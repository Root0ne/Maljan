"""A call a guard answers with no tool run is filed as the guard's answer.

The repeat guard's answers are filed as repeats of the entry that holds the
answer. The other guards' answers were filed nowhere: a call whose argument
names its own parameter, and a call made after the conversation's room ran
out, were told something and left no entry and no event, so a later reader
could not see that the model asked or what it was told. Each is now an entry
whose ``repeated_of`` is its own id: every reader that leaves a repeat out of
the tool results leaves it out, and its chain holds no answer, so nothing can
cite it.
"""

from __future__ import annotations

from typing import Any

from langchain_core.tools import StructuredTool

from maljan.agents.base_agent import earlier_chunks_block
from maljan.agents.evidence_recorder import (
    EvidenceRecorder,
    RepeatGuard,
    record_tools,
    seeded_repeat_guard,
)
from maljan.agents.judge_agent import question_evidence
from maljan.llm import context_window as cw
from maljan.pipeline.nodes import evidence_summary
from maljan.pipeline.run_state import _lines as run_state_lines
from maljan.pipeline.validation import EntryTexts
from maljan.reporting.models import (
    EvidenceIndexRow,
    FileHashes,
    MalwareReport,
    SampleIdentity,
)
from maljan.reporting.renderers.markdown import MarkdownRenderer
from maljan.schemas.evidence import (
    EvidenceCounter,
    LedgerEntry,
    answers_held,
    apply_budget,
    is_guard_answer,
    repeat_holders,
)


class _Sink:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    def __call__(self, event_type: str, data: dict[str, Any]) -> None:
        self.events.append((event_type, data))

    def of(self, event_type: str) -> list[dict[str, Any]]:
        return [data for name, data in self.events if name == event_type]


class _Corpus:
    def __init__(self) -> None:
        self.remembered: list[str] = []

    def remember(self, entry_id: str, tool: str, output: str) -> None:
        self.remembered.append(entry_id)


def _strings_tool(ran: list[dict[str, Any]]) -> StructuredTool:
    def strings(pattern: str | None = None, offset: int = 0) -> str:
        """List printable runs."""
        ran.append({"pattern": pattern, "offset": offset})
        return '{"strings": ["kernel32.dll"]}'

    return StructuredTool.from_function(func=strings, name="strings")


def _recorded(
    ran: list[dict[str, Any]], budget: Any = None
) -> tuple[StructuredTool, EvidenceRecorder, _Sink, _Corpus]:
    sink, corpus = _Sink(), _Corpus()
    recorder = EvidenceRecorder("static", counter=EvidenceCounter(), sink=sink, corpus=corpus)
    (tool,) = record_tools([_strings_tool(ran)], recorder, RepeatGuard(), context_budget=budget)
    return tool, recorder, sink, corpus


def _out_of_room(*, line_fits: bool) -> cw.ContextBudget:
    window = 1_000_000 if line_fits else 9_000
    budget = cw.ContextBudget(cw.WindowFact(window, cw.PROBED, "props"), reply_tokens=8192)
    budget.note_no_room("static")
    if not line_fits:
        budget.charge(10_000_000, "static")
    return budget


class TestTheCallIsFiled:
    def test_a_self_named_argument_leaves_the_guard_s_answer_and_its_events(self) -> None:
        ran: list[dict[str, Any]] = []
        tool, recorder, sink, corpus = _recorded(ran)

        answer = tool.invoke({"pattern": '"pattern"', "offset": 400})

        assert ran == []
        (entry,) = recorder.entries
        assert is_guard_answer(entry)
        assert entry.repeated_of == entry.id
        assert entry.tool == "strings" and entry.args == {"pattern": '"pattern"', "offset": 400}
        assert entry.output == answer and entry.error == answer
        assert not entry.ok and entry.duration_ms == 0 and entry.structured is None
        assert entry.id not in answer, "the model is never shown the entry's id"
        assert corpus.remembered == [], "nothing a tool said is remembered for grounding"
        started, finished = sink.of("tool_call_started"), sink.of("tool_call_finished")
        assert len(started) == 1 and len(finished) == 1
        assert finished[0]["evidence_id"] == entry.id

    def test_a_call_after_the_room_ran_out_leaves_the_guard_s_answer(self) -> None:
        ran: list[dict[str, Any]] = []
        tool, recorder, _sink, _corpus = _recorded(ran, _out_of_room(line_fits=True))

        answer = tool.invoke({"pattern": "kernel32"})

        assert ran == []
        assert answer == cw.TOOL_PHASE_ENDED_NOTICE
        (entry,) = recorder.entries
        assert is_guard_answer(entry) and entry.output == answer

    def test_a_call_told_nothing_is_filed_with_nothing_said(self) -> None:
        tool, recorder, _sink, _corpus = _recorded([], _out_of_room(line_fits=False))

        answer = tool.invoke({"pattern": "kernel32"})

        assert answer == ""
        (entry,) = recorder.entries
        assert is_guard_answer(entry) and entry.output == "" and entry.error is None

    def test_an_ordinary_call_is_untouched(self) -> None:
        ran: list[dict[str, Any]] = []
        tool, recorder, _sink, corpus = _recorded(ran)

        answer = tool.invoke({"pattern": "kernel32"})

        (entry,) = recorder.entries
        assert answer.startswith(f"[{entry.id}]")
        assert not is_guard_answer(entry) and entry.repeated_of is None and entry.ok
        assert corpus.remembered == [entry.id]


def _ledger() -> list[LedgerEntry]:
    return [
        LedgerEntry(id="ev_0001", tool="strings", output="kernel32.dll"),
        LedgerEntry(id="ev_0002", tool="strings", ok=False, error="boom"),
        LedgerEntry(id="ev_0003", tool="strings", output="a note", repeated_of="ev_0001"),
        LedgerEntry(
            id="ev_0004",
            tool="strings",
            args={"pattern": '"pattern"'},
            ok=False,
            error="strings was not run",
            output="strings was not run",
            repeated_of="ev_0004",
        ),
    ]


class TestItIsNoToolResult:
    def test_the_summary_counts_it_apart(self) -> None:
        summary = evidence_summary(_ledger())

        assert summary["entries"] == 4
        assert (summary["ok"], summary["failed"], summary["repeats"]) == (1, 1, 1)
        assert summary["guard_answers"] == 1
        assert [row["entry_id"] for row in summary["failures"]] == ["ev_0002"]

    def test_a_ledger_without_one_keeps_its_summary_shape(self) -> None:
        assert "guard_answers" not in evidence_summary(_ledger()[:3])

    def test_nothing_can_cite_it(self) -> None:
        ledger = _ledger()

        assert repeat_holders(ledger)["ev_0004"] == ""
        texts = EntryTexts.from_ledger(ledger)
        assert not texts.has_text("ev_0004")
        assert texts.holds("ev_0003", "kernel32.dll")
        assert "ev_0004" not in question_evidence(ledger)

    def test_a_later_chunk_is_not_told_of_it_and_does_not_seed_from_it(self) -> None:
        ledger = _ledger()

        assert "ev_0004" not in earlier_chunks_block(ledger)
        guard = seeded_repeat_guard(ledger)
        assert guard.answered_by("strings", {"pattern": '"pattern"'}) is None
        assert guard.answered_by("strings", {}) == "ev_0001"

    def test_it_costs_no_evidence_budget(self) -> None:
        ledger = _ledger()

        apply_budget(ledger, budget_bytes=len("kernel32.dll") + len("boom"))

        assert ledger[3].output == "strings was not run" and not ledger[3].truncated

    def test_it_is_not_what_an_agent_gathered(self) -> None:
        ledger = _ledger()

        assert answers_held(ledger)
        assert not answers_held(ledger[3:])
        assert not answers_held([])

    def test_the_run_state_block_does_not_list_it_as_a_failed_tool(self) -> None:
        state = {"evidence_ledger": _ledger()[3:]}

        lines = run_state_lines(state, None, None)

        assert not any(line.startswith("tools failed") for line in lines)


class TestTheReportSaysWhatTheGuardAnswered:
    def _report(self, evidence: dict[str, Any], rows: list[EvidenceIndexRow]) -> str:
        report = MalwareReport(
            identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
            run_summary={"evidence": evidence},
            evidence_index=rows,
        )
        return MarkdownRenderer().render(report)

    def test_the_bounds_line_and_the_index_name_it(self) -> None:
        text = self._report(
            {"entries": 2, "ok": 1, "failed": 0, "trimmed": 0, "guard_answers": 1},
            [
                EvidenceIndexRow(id="ev_0001", tool="strings"),
                EvidenceIndexRow(id="ev_0002", tool="strings", ok=False, repeated_of="ev_0002"),
            ],
        )

        assert (
            "**Evidence bounds:** 2 ledger entries, 1 ok, 0 failed, 1 answered by a guard "
            "with no tool run, 0 trimmed to the budget." in text
        )
        assert "Evidence: 2 tool call(s), 1 answered by a guard with no tool run (see §13)." in text
        assert "| ev_0002 | - | - | strings | guard's answer, not run |" in text


class TestADelegatedAnswer:
    def test_its_evidence_holds_what_the_tools_said_and_not_the_guard_s_answer(self) -> None:
        from unittest.mock import MagicMock, patch

        from maljan.agents.base_agent import BaseAnalyst

        class _Analyst(BaseAnalyst):
            def analyze(self, data: str) -> str:  # pragma: no cover - unused
                return ""

            def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
                return ""

        analyst = _Analyst(llm=MagicMock(), name="static")
        seen: list[str] = []

        def _loop(_messages: Any) -> str:
            analyst._evidence_entries.extend([_ledger()[0], _ledger()[3]])
            return "CLAIM: c"

        def _gate(isr: Any, evidence: str) -> Any:
            seen.append(evidence)
            return isr

        with (
            patch.object(analyst, "_try_initialize_mcp", lambda: False),
            patch.object(analyst, "_system_prompt", lambda _data: "system"),
            patch.object(analyst, "execute_tool_loop", _loop),
            patch.object(analyst, "_apply_consistency_gate", _gate),
            patch.object(analyst, "_validate_isr", lambda isr, _evidence: isr),
        ):
            analyst.answer_task("look at the strings")

        assert seen == ["look at the strings\nkernel32.dll"]

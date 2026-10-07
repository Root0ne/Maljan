"""Every tool call leaves a ledger entry and its events, the repeat guard's included.

A later chunk's calls that an earlier chunk had made are answered from the
earlier entry without running, and a third identical call is refused with a
notice. Both used to be told to the model and written nowhere: a reverser's
second chunk made nine calls, all answered this way, and the ledger, the event
feed, the report's limitations section and its evidence index showed none of
them. Each is now filed as a repeat of the entry that holds its answer.
"""

from __future__ import annotations

from typing import Any

from langchain_core.tools import StructuredTool
from pydantic import BaseModel

from maljan.agents.base_agent import earlier_chunks_block
from maljan.agents.evidence_recorder import (
    EvidenceRecorder,
    RepeatGuard,
    record_tools,
    seeded_repeat_guard,
)
from maljan.agents.function_map import keeps_for_the_map
from maljan.pipeline.nodes import evidence_summary
from maljan.pipeline.validation import decompiled_functions
from maljan.reporting.models import (
    EvidenceIndexRow,
    FileHashes,
    MalwareReport,
    SampleIdentity,
)
from maljan.reporting.renderers.markdown import MarkdownRenderer
from maljan.schemas.evidence import EvidenceCounter, LedgerEntry

LISTING = "int FUN_00401000(void)\n{ return decode(0x10); }"


class _Args(BaseModel):
    address: str = ""


class _Sink:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    def __call__(self, event_type: str, data: dict[str, Any]) -> None:
        self.events.append((event_type, data))

    def of(self, event_type: str) -> list[dict[str, Any]]:
        return [data for name, data in self.events if name == event_type]


def _decompiler(calls: list[str]) -> StructuredTool:
    def _run(address: str = "") -> str:
        calls.append(address)
        return LISTING

    return StructuredTool.from_function(
        func=_run,
        name="decompile_function",
        description="Decompile one function.",
        args_schema=_Args,
        infer_schema=False,
    )


def _earlier(entry_id: str = "ev_0003", address: str = "0x401000") -> LedgerEntry:
    return LedgerEntry(
        id=entry_id,
        agent="reverser",
        tool="decompile_function",
        args={"address": address},
        output=LISTING,
    )


class TestALaterChunkCallIsFiledAsARepeat:
    def test_the_earlier_chunk_s_call_leaves_an_entry_and_its_events(self) -> None:
        sink = _Sink()
        recorder = EvidenceRecorder("reverser", counter=EvidenceCounter(), sink=sink)
        calls: list[str] = []
        wrapped = record_tools([_decompiler(calls)], recorder, seeded_repeat_guard([_earlier()]))[0]

        answer = wrapped.invoke({"address": "0x401000"})

        assert calls == [], "the tool is not run again"
        assert answer.startswith("[ev_0003]"), "the model cites the earlier entry"
        assert len(recorder.entries) == 1
        entry = recorder.entries[0]
        assert entry.repeated_of == "ev_0003"
        assert entry.ok and entry.duration_ms == 0 and entry.structured is None
        assert entry.id not in answer, "the repeat's own id is never handed to the model"
        assert "earlier chunk" in entry.output and LISTING not in entry.output
        started, finished = sink.of("tool_call_started"), sink.of("tool_call_finished")
        assert len(started) == 1 and len(finished) == 1
        assert finished[0]["evidence_id"] == entry.id
        assert finished[0]["repeated_of"] == "ev_0003"

    def test_nine_calls_answered_from_earlier_entries_are_nine_entries(self) -> None:
        earlier = [_earlier(f"ev_{n:04d}", f"0x40{n:04x}") for n in range(1, 10)]
        recorder = EvidenceRecorder("reverser", counter=EvidenceCounter())
        calls: list[str] = []
        wrapped = record_tools([_decompiler(calls)], recorder, seeded_repeat_guard(earlier))[0]

        for entry in earlier:
            wrapped.invoke(dict(entry.args))

        assert calls == []
        assert [e.repeated_of for e in recorder.entries] == [e.id for e in earlier]

    def test_a_refused_identical_call_names_the_entry_that_answered_it(self) -> None:
        recorder = EvidenceRecorder("reverser", counter=EvidenceCounter())
        calls: list[str] = []
        wrapped = record_tools([_decompiler(calls)], recorder, RepeatGuard())[0]

        for _ in range(3):
            notice = wrapped.invoke({"address": "0x401000"})

        assert len(calls) == 2
        assert recorder.entries[2].repeated_of == recorder.entries[0].id
        assert recorder.entries[2].output == notice


class TestARepeatIsReadAsARepeat:
    def test_a_later_chunk_is_not_told_of_it_and_does_not_seed_from_it(self) -> None:
        first = _earlier("ev_0003")
        repeat = LedgerEntry(
            id="ev_0009",
            tool="decompile_function",
            args={"address": "0x401000"},
            output="a note",
            repeated_of="ev_0003",
        )

        block = earlier_chunks_block([first, repeat])
        guard = seeded_repeat_guard([first, repeat])

        assert "ev_0003" in block and "ev_0009" not in block
        assert guard.recorded_answer("decompile_function", {"address": "0x401000"}) == (
            "ev_0003",
            LISTING,
        )

    def test_it_decompiled_nothing_of_its_own(self) -> None:
        repeat = LedgerEntry(
            id="ev_0009",
            tool="decompile_function",
            args={"address": "0x402000"},
            output="a note",
            repeated_of="ev_0003",
        )

        assert decompiled_functions([repeat]) == []
        assert not keeps_for_the_map(repeat)

    def test_the_summary_counts_repeats_apart_from_the_calls_that_ran(self) -> None:
        ledger = [
            _earlier("ev_0001"),
            LedgerEntry(id="ev_0002", tool="strings", ok=False, error="boom"),
            LedgerEntry(id="ev_0003", tool="decompile_function", repeated_of="ev_0001"),
            LedgerEntry(id="ev_0004", tool="strings", ok=False, repeated_of="ev_0002"),
        ]

        summary = evidence_summary(ledger)

        assert summary["entries"] == 4
        assert (summary["ok"], summary["failed"], summary["repeats"]) == (1, 1, 2)
        assert [row["tool"] for row in summary["failures"]] == ["strings"]
        assert summary["failures"][0]["count"] == 1

    def test_a_ledger_without_repeats_keeps_its_summary_shape(self) -> None:
        assert "repeats" not in evidence_summary([_earlier("ev_0001")])


class TestARepeatCostsNoBudget:
    def test_a_later_answer_fits_however_many_repeats_came_before(self) -> None:
        from maljan.schemas.evidence import apply_budget

        first = LedgerEntry(id="ev_0001", tool="strings", output="a" * 40)
        repeats = [
            LedgerEntry(id=f"ev_{n:04d}", tool="strings", output="n" * 30, repeated_of="ev_0001")
            for n in range(2, 8)
        ]
        later = LedgerEntry(id="ev_0008", tool="pe_info", output="b" * 50)

        trimmed, spent = apply_budget([first, *repeats, later], budget_bytes=100)

        assert (trimmed, spent) == (0, 90)
        assert later.output == "b" * 50 and not later.truncated
        assert all(r.output and not r.truncated for r in repeats)


class TestTheReportSaysWhatWasRepeated:
    def _report(self, evidence: dict[str, Any], rows: list[EvidenceIndexRow]) -> str:
        report = MalwareReport(
            identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
            run_summary={"evidence": evidence},
            evidence_index=rows,
        )
        return MarkdownRenderer().render(report)

    def test_the_bounds_line_and_the_index_name_the_repeats(self) -> None:
        text = self._report(
            {"entries": 3, "ok": 2, "failed": 0, "trimmed": 0, "repeats": 1},
            [
                EvidenceIndexRow(id="ev_0001", tool="decompile_function"),
                EvidenceIndexRow(id="ev_0002", tool="strings"),
                EvidenceIndexRow(id="ev_0003", tool="decompile_function", repeated_of="ev_0001"),
            ],
        )

        assert (
            "**Evidence bounds:** 3 ledger entries, 2 ok, 0 failed, 1 answered from an "
            "earlier entry without running, 0 trimmed to the budget." in text
        )
        assert "Evidence: 3 tool call(s), 1 answered from an earlier entry (see §13)." in text
        assert "| ev_0003 | - | - | decompile_function | repeat of ev_0001 |" in text

    def test_a_run_with_no_repeat_reads_as_before(self) -> None:
        text = self._report(
            {"entries": 2, "ok": 2, "failed": 0, "trimmed": 0},
            [EvidenceIndexRow(id="ev_0001", tool="strings")],
        )

        assert (
            "**Evidence bounds:** 2 ledger entries, 2 ok, 0 failed, 0 trimmed to the budget."
            in text
        )
        assert "repeat of" not in text

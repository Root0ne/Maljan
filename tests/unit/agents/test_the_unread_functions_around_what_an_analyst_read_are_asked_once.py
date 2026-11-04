"""The unread functions around the routines an analyst read are listed to it, once (T-558).

An analyst reading code stopped on its own with the routine that reads its
configuration file, the one that writes it and the cipher wrapper of its
channel unread. Each was a callee of a routine it had read, and the function
map listed it as named and not read. Before the answer stands, the platform
now lists those functions in one question:

- every routine a listing of the analyst holds counts, whether or not a claim
  names it; a listing at an address inside a function reads that function;
- the unread callees of those routines are listed, and so are the unread
  functions on the path from a stated start down to them;
- the list is ranked by distance from where the code starts (the entry point
  and exports any format header states, the threads the function index
  states), a further caller counting one call, so a shared helper comes last;
- at most :data:`CALLEES_SHOWN` are listed, and the question says how many
  there are and that the rest are not;
- it carries addresses and counts only, never a name or a string the sample
  or a tool wrote;
- it is asked once per analyst and job, only where the turn after the loop can
  carry the analyst's tools; the analyst reads what it chooses, and the loop's
  record and an answered row say what it read;
- an analyst that reads no code is not asked and nothing is said; where the
  platform cannot tell, it says why once;
- an answer with nothing unread sends exactly what it sent before.

Every address, name and sentence here is made up for the test.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from langchain_core.messages import AIMessage

from maljan.agents.base_agent import BaseAnalyst
from maljan.agents.callees_question import (
    CALLEES_SHOWN,
    NOT_RUN_NO_LISTING,
    STARTS_CLAIMED,
    STARTS_NONE,
    STARTS_STATED,
    UNREAD_CALLEES_CODE,
    CalleesFound,
    callees_asked_record,
    callees_to_read,
    reads_code,
    unread_callees_violation,
)
from maljan.analysis.run_summary import RunSummaryBuilder
from maljan.core.config import Settings
from maljan.core.declared_reading import declarations, facts_record
from maljan.pipeline.validation import AnswerCheckInputs, analyst_answer_checks
from maljan.schemas.evidence import LedgerEntry
from maljan.schemas.isr_models import AgentISR, ClaimEvidence

BASE = 0x180000000
START = BASE + 0x1000  # the export and entry point
GATE = BASE + 0x1800  # called by the start; never read; calls the outer routine
OUTER = BASE + 0x2000  # read
STEP = BASE + 0x3000  # a step the outer routine calls; calls two more
SIDE = BASE + 0x4000  # another step it calls; calls nothing
HELPER = BASE + 0x9000  # called from six places
OTHERS = [BASE + 0xA000 + 0x100 * i for i in range(5)]
SECRET = "EvilConfigName"


def _fun(address: int) -> str:
    return f"FUN_{address:x}"


def _listing(address: int, *calls: int) -> str:
    body = "".join(f"  {_fun(c)}();\n" for c in calls)
    return f'\nundefined8 {_fun(address)}(void)\n\n{{\n  x = "{SECRET}";\n{body}  return 0;\n}}\n'


def _batch(entry: str, listings: dict[int, str], facts: Any = None, **kw: Any) -> LedgerEntry:
    return LedgerEntry(
        id=entry,
        tool=kw.pop("tool", "batch_decompile"),
        args={"functions": ",".join(hex(a) for a in listings)},
        output=json.dumps({hex(a): text for a, text in listings.items()}),
        **({"source": kw.pop("source", "provider:x"), "facts": facts} if facts is not None else kw),
    )


def _decompile(entry: str, address: int, *calls: int) -> LedgerEntry:
    return LedgerEntry(
        id=entry,
        tool="decompile_function",
        args={"address": f"{address:x}"},
        output=_listing(address, *calls),
    )


def _index(*, threads: bool = False, entry: bool = False) -> LedgerEntry:
    others = {
        hex(START): [hex(GATE)],
        hex(GATE): [hex(OUTER)],
        hex(OUTER): [hex(STEP), hex(SIDE), hex(HELPER)],
        hex(STEP): [hex(BASE + 0x5000), hex(BASE + 0x6000)],
        **{hex(o): [hex(HELPER)] for o in OTHERS},
    }
    data: dict[str, Any] = {
        "tool": "function_index",
        "image_base": hex(BASE),
        "rows": (
            [{"function": hex(START), "offset": "0x1000", "entry_point": True, "callees": []}]
            if entry
            else []
        ),
        "other_callees": others,
    }
    if threads:
        data["thread_starts"] = [
            {"starter": hex(START), "started": hex(OUTER), "through": "CreateThread"}
        ]
    return LedgerEntry(
        id="ev_0025",
        tool="function_index",
        args={"path": "/x/s.dll", "carved_path": ""},
        output=json.dumps(data),
    )


def _header(tool: str = "pe_info", entry_point: Any = 0x1000) -> LedgerEntry:
    data = {
        "image_base": hex(BASE),
        "entry_point": entry_point,
        "export_rows": [{"name": SECRET, "ordinal": 1, "rva": "0x1000"}],
    }
    return LedgerEntry(
        id="ev_0004",
        tool=tool,
        args={"path": "/x/s.dll", "carved_path": ""},
        output=json.dumps(data),
        source="pack",
        facts={"v": 1, "kind": "format_info"},
    )


def _claim(text: str, evidence: str = "[ev_0003]") -> ClaimEvidence:
    return ClaimEvidence(claim=text, evidence_ref=evidence, confidence=0.8)


def _shipped() -> tuple[Any, Any, Any]:
    held = declarations(Settings())
    return (
        facts_record("provider:ghidra", "batch_decompile", declared=held),
        facts_record("pack", "function_index", declared=held),
        facts_record("pack", "pe_info", declared=held),
    )


OWN = [
    _batch("ev_0003", {START: _listing(START, GATE), OUTER: _listing(OUTER, STEP, SIDE, HELPER)})
]
PACK = [_header(), _index()]
CLAIMS = [_claim("The loader decrypts its settings.", "[ev_0004]")]


def _addresses(found: CalleesFound) -> list[int]:
    return [c.address for c in found.ranked]


class TestWhatIsListed:
    def test_the_functions_around_what_was_read_are_ranked_by_the_main_path(self) -> None:
        found = callees_to_read(CLAIMS, OWN, PACK)

        # The gate is on the path from the start to the routine read; the
        # steps are its callees; the helper, called from six places, is last.
        assert _addresses(found) == [GATE, STEP, SIDE, HELPER]
        assert found.starts == STARTS_STATED
        gate, step = found.ranked[0], found.ranked[1]
        assert gate.on_path and gate.callers == (START,) and gate.depth == 1
        assert (step.callers, step.depth, step.start, step.called_from, step.calls) == (
            (OUTER,),
            3,
            START,
            1,
            2,
        )
        assert found.ranked[-1].distance() == 3 + 5

    def test_a_routine_no_claim_names_still_has_its_callees_listed(self) -> None:
        assert _addresses(callees_to_read([], OWN, PACK)) == [GATE, STEP, SIDE, HELPER]

    def test_a_thread_the_index_states_is_a_start(self) -> None:
        found = callees_to_read(CLAIMS, OWN, [_index(threads=True)])

        assert found.starts == STARTS_STATED
        step = found.ranked[0]
        assert (step.address, step.depth, step.start) == (STEP, 1, OUTER)

    def test_any_format_header_states_its_entry_point_and_exports(self) -> None:
        header = _header(tool="elf_info", entry_point="0x1000")

        found = callees_to_read(CLAIMS, OWN, [header, _index()])

        assert found.starts == STARTS_STATED
        assert found.ranked[0].start == START

    def test_with_no_start_stated_the_read_routine_a_claim_calls_main_stands_in(self) -> None:
        claims = [_claim(f"{START:#x} calls {OUTER:#x}, the main dispatcher of commands.")]

        found = callees_to_read(claims, OWN, [_index()])

        assert found.starts == STARTS_CLAIMED
        # Only the address nearest the word is the claim's central routine.
        step = next(c for c in found.ranked if c.address == STEP)
        assert (step.depth, step.start) == (1, OUTER)

    def test_with_no_start_at_all_the_list_is_given_unranked_by_path(self) -> None:
        found = callees_to_read(CLAIMS, OWN, [])

        assert found.starts == STARTS_NONE
        assert set(_addresses(found)) == {GATE, STEP, SIDE, HELPER}
        assert all(c.depth is None for c in found.ranked)

    def test_a_read_callee_is_not_listed(self) -> None:
        found = callees_to_read(CLAIMS, [*OWN, _decompile("ev_0005", STEP)], PACK)

        # Read now, its own callees are what is unread around it.
        assert _addresses(found) == [GATE, SIDE, BASE + 0x5000, BASE + 0x6000, HELPER]

    def test_a_listing_inside_a_function_reads_that_function(self) -> None:
        inside = LedgerEntry(
            id="ev_0006",
            tool="disassemble",
            args={"address": hex(STEP + 0x40)},
            output="0x180003040  mov eax, 1\n0x180003045  ret\n",
        )

        found = callees_to_read(CLAIMS, [*OWN, inside], PACK)

        assert STEP not in _addresses(found)

    def test_an_analyst_that_listed_no_code_is_not_read_at_all(self) -> None:
        with patch("maljan.agents.callees_question.build_function_map") as built:
            found = callees_to_read(CLAIMS, [], PACK)

        assert found.ranked == () and found.not_run == NOT_RUN_NO_LISTING
        assert not found.says_why()
        built.assert_not_called()

    def test_the_order_is_the_same_whatever_order_the_pack_is_in(self) -> None:
        assert callees_to_read(CLAIMS, OWN, PACK) == callees_to_read(
            CLAIMS, OWN, list(reversed(PACK))
        )


class TestTheQuestion:
    def test_it_lists_each_with_its_reason_and_forces_nothing(self) -> None:
        violation = unread_callees_violation(callees_to_read(CLAIMS, OWN, PACK))

        assert violation is not None
        assert violation.code == UNREAD_CALLEES_CODE and violation.advisory
        assert (
            f"{STEP:#x} (called by {OUTER:#x}; 3 call(s) from the start {START:#x}; "
            "1 caller(s); calls 2)"
        ) in violation.message
        assert f"{GATE:#x} (called by {START:#x}; on the path from a start" in violation.message
        assert "leave them unread and change nothing" in violation.message
        assert "This is asked once." in violation.message

    def test_it_carries_no_text_the_sample_or_a_tool_wrote(self) -> None:
        violation = unread_callees_violation(callees_to_read(CLAIMS, OWN, PACK))

        assert violation is not None
        assert SECRET not in violation.message and "FUN_" not in violation.message

    def test_a_longer_list_is_bounded_and_says_so(self) -> None:
        many = [BASE + 0x20000 + 0x10 * i for i in range(CALLEES_SHOWN + 3)]
        own = [_batch("ev_0003", {OUTER: _listing(OUTER, *many)})]

        found = callees_to_read(CLAIMS, own, [])
        violation = unread_callees_violation(found)

        assert len(found.ranked) == CALLEES_SHOWN + 3
        assert violation is not None
        assert (
            f"The first {CALLEES_SHOWN} of {CALLEES_SHOWN + 3} are listed (the question lists "
            f"at most {CALLEES_SHOWN}); the other 3 are not."
        ) in violation.message
        assert hex(many[CALLEES_SHOWN]) not in violation.message

    def test_nothing_unread_is_no_question(self) -> None:
        assert unread_callees_violation(callees_to_read(CLAIMS, [], PACK)) is None


class TestTheShippedDeclarations:
    def test_the_shipped_decompiler_index_and_header_are_read_by_their_declared_kinds(
        self,
    ) -> None:
        batch, index, header = _shipped()
        assert batch is not None and index is not None and header is not None
        own = [
            _batch(
                "ev_0003",
                {START: _listing(START, GATE), OUTER: _listing(OUTER, STEP, SIDE, HELPER)},
                batch,
                source="provider:ghidra",
            )
        ]
        shipped_index = _index().model_copy(update={"source": "pack", "facts": index})
        shipped_header = _header().model_copy(update={"facts": header})

        found = callees_to_read(CLAIMS, own, [shipped_header, shipped_index])

        assert _addresses(found) == [GATE, STEP, SIDE, HELPER]
        assert found.starts == STARTS_STATED

    def test_the_shipped_reverser_is_served_the_provider_s_decompiler(self) -> None:
        # The seeded reverser reads code through the static provider's tools,
        # whose batch decompile the shipped declarations call a decompile.
        reverser = Settings().agents.definitions["reverser"]
        batch, _index_facts, _header_facts = _shipped()

        assert "provider" in [ref.kind for ref in reverser.tools]
        assert batch is not None and batch["kind"] == "decompile_batch"


def _inputs() -> AnswerCheckInputs:
    return AnswerCheckInputs(
        attck=None,
        ledger_ids=["ev_0003"],
        sample={"file_type": "pe", "platform": "windows"},
        items=None,
        decompiled=[],
        image_bases=(),
        techniques=False,
        alignment=None,
        alignment_threshold=0.3,
        alignment_margin=0.4,
    )


class TestTheComposition:
    def test_the_question_is_one_of_the_answer_s_checks_only_when_handed_a_list(self) -> None:
        isr = AgentISR(agent_id="a", domain="code", claims=CLAIMS)

        def _codes(callees: Any) -> list[str]:
            with patch("maljan.pipeline.validation.validate_isr", return_value=[]):
                found = analyst_answer_checks(
                    isr,
                    _inputs(),
                    whole_answer=[],
                    unread=[],
                    functions=[],
                    weak_alignment_challenges=False,
                    callees=callees,
                )
            return [v.code for v in found]

        assert UNREAD_CALLEES_CODE in _codes(callees_to_read(CLAIMS, OWN, PACK))
        assert UNREAD_CALLEES_CODE not in _codes(None)
        assert UNREAD_CALLEES_CODE not in _codes(CalleesFound())


FIRST = (
    f"CLAIM 1: {START:#x} is the export, and it calls {GATE:#x}.\n"
    "EVIDENCE: [ev_0003]\nCONFIDENCE: 0.8\nTECHNIQUE: NONE\n---\n"
    f"CLAIM 2: {OUTER:#x} decrypts the configuration.\n"
    "EVIDENCE: [ev_0003]\nCONFIDENCE: 0.8\nTECHNIQUE: NONE\n---\n"
)
RETRY = (
    f"CLAIM 3: {STEP:#x} reads the settings file.\n"
    "EVIDENCE: [ev_0007]\nCONFIDENCE: 0.8\nTECHNIQUE: NONE\n---\n"
)
HOST_ANSWER = (
    "CLAIM 1: The host resolves.\nEVIDENCE: [ev_0003]\nCONFIDENCE: 0.8\nTECHNIQUE: NONE\n---\n"
)


class _Analyst(BaseAnalyst):
    def __init__(self, replies: list[str], entries: list[LedgerEntry]) -> None:
        super().__init__(llm=MagicMock(), name="my_code_reader")
        self._evidence_entries = list(entries)
        self._replies = list(replies)
        self.seen_turns: list[list[Any]] = []
        self.pack_entries = list(PACK)
        self.read_on_retry: LedgerEntry | None = None
        self._budget_records = [{"steps_used": 3}]

    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        return ""

    def _invoke_llm_with_timeout(self, messages: list, timeout: float, **_: Any) -> str:
        self.seen_turns.append(list(messages))
        # What the analyst's own tools would file when it reads a function.
        if self.read_on_retry is not None:
            self._evidence_entries.append(self.read_on_retry)
            self.read_on_retry = None
        text = self._replies.pop(0)
        self._record_usage(AIMessage(content=text))
        return text


@pytest.fixture
def tools() -> Iterator[None]:
    """The turn after the loop carries the analyst's tools, its loop answered by the fake."""
    with (
        patch.object(BaseAnalyst, "_turns_carry_tools", return_value=True),
        patch.object(
            BaseAnalyst,
            "_answer_after_loop",
            lambda self, messages, timeout, **kw: self._invoke_llm_with_timeout(
                kw.get("plain") or messages, timeout
            ),
        ),
    ):
        yield


def _events(analyst: _Analyst, first: str = FIRST) -> list[tuple[str, dict[str, Any]]]:
    recorded: list[tuple[str, dict[str, Any]]] = []
    isr = analyst._text_to_isr(first, 0)
    with (
        patch("maljan.agents.base_agent.validity_check_available", return_value=True),
        patch.object(BaseAnalyst, "_fits_the_window", return_value=True),
        patch.object(
            BaseAnalyst,
            "_event_sink",
            lambda _self: lambda kind, data: recorded.append((kind, data)),
        ),
    ):
        analyst.result = analyst._validate_isr(isr, "evidence")  # type: ignore[attr-defined]
    return recorded


def _notes(recorded: list[tuple[str, dict[str, Any]]]) -> list[dict[str, Any]]:
    return [d for kind, d in recorded if kind == "agent_message"]


@pytest.mark.usefixtures("tools")
class TestTheValidationTurn:
    def test_it_is_asked_once_and_what_the_analyst_read_is_recorded(self) -> None:
        analyst = _Analyst([RETRY], list(OWN))
        analyst.read_on_retry = _decompile("ev_0007", STEP, BASE + 0x5000, BASE + 0x6000)

        recorded = _events(analyst)

        (turns,) = analyst.seen_turns
        question = str(turns[-1].content)
        assert UNREAD_CALLEES_CODE in question
        assert f"{STEP:#x}" in question and f"{HELPER:#x}" in question
        assert any(f"{STEP:#x}" in c.claim for c in analyst.result.claims)
        record = analyst._budget_records[-1]["callees_question"]
        assert record == {
            "listed": 4,
            "shown": [hex(GATE), hex(STEP), hex(SIDE), hex(HELPER)],
            "shown_at_most": CALLEES_SHOWN,
            "read_after": [hex(STEP)],
        }
        (row,) = [v for v in analyst.validation_findings if v.code == UNREAD_CALLEES_CODE]
        assert row.answered
        assert "read 1 of those listed" in row.message and "left 3 unread" in row.message
        states = [
            d["state"]
            for kind, d in recorded
            if kind == "validation_feedback" and d["code"] == UNREAD_CALLEES_CODE
        ]
        assert states == ["retried", "answered"]

    def test_a_later_turn_of_the_same_job_is_not_asked_again(self) -> None:
        analyst = _Analyst([RETRY], list(OWN))
        _events(analyst)
        analyst._replies = []

        _events(analyst)

        assert len(analyst.seen_turns) == 1

    def test_another_job_is_asked_again(self) -> None:
        analyst = _Analyst([RETRY, RETRY], list(OWN))
        _events(analyst)
        analyst._job_id = "another job"

        _events(analyst)

        assert len(analyst.seen_turns) == 2

    def test_it_rides_the_turn_another_question_already_takes(self) -> None:
        own = [*OWN, _decompile("ev_0006", BASE + 0x7000)]
        analyst = _Analyst([RETRY], own)

        _events(analyst)

        (turns,) = analyst.seen_turns
        question = str(turns[-1].content)
        assert UNREAD_CALLEES_CODE in question and "isr.decompiled_not_described" in question

    def test_an_answer_with_nothing_unread_sends_nothing_new(self) -> None:
        own = [
            _batch("ev_0003", {START: _listing(START, OUTER), OUTER: _listing(OUTER)}),
        ]
        analyst = _Analyst([], own)
        analyst.pack_entries = [_header()]

        recorded = _events(analyst)

        assert analyst.seen_turns == []
        assert "callees_question" not in analyst._budget_records[-1]
        assert _notes(recorded) == []

    def test_a_check_that_raises_says_so_and_asks_nothing(self) -> None:
        analyst = _Analyst([], list(OWN))
        with patch("maljan.agents.base_agent.callees_to_read", side_effect=RuntimeError("x")):
            recorded = _events(analyst)

        assert analyst.seen_turns == []
        (said,) = _notes(recorded)
        assert said["text"].endswith("the check could not run (RuntimeError).")


class TestATurnWithoutTools:
    def test_a_turn_that_cannot_carry_tools_is_not_asked_and_says_why(self) -> None:
        analyst = _Analyst([], list(OWN))

        recorded = _events(analyst)

        assert analyst.seen_turns == []
        (said,) = _notes(recorded)
        assert "carries no tools (the agent has no tools" in said["text"]
        assert "not_run" in analyst._budget_records[-1]["callees_question"]

    def test_too_few_steps_left_is_not_asked_and_says_why(self) -> None:
        analyst = _Analyst([], list(OWN))
        analyst._last_loop_steps_known = True
        analyst._last_loop_steps_left = 2
        with patch.object(BaseAnalyst, "_turns_carry_tools", return_value=True):
            recorded = _events(analyst)

        assert analyst.seen_turns == []
        (said,) = _notes(recorded)
        assert "2 step(s) of its loop were left" in said["text"]


class TestTheRecord:
    def test_the_record_lists_what_was_asked_and_what_was_read(self) -> None:
        found = callees_to_read(CLAIMS, OWN, PACK)

        record, answered = callees_asked_record(found, [*OWN, _decompile("ev_0007", SIDE)], PACK)

        assert record["read_after"] == [hex(SIDE)]
        assert answered is not None and answered.answered

    def test_nothing_asked_is_no_record(self) -> None:
        assert callees_asked_record(CalleesFound(), OWN, PACK) == ({}, None)

    def test_the_run_summary_carries_it_per_agent(self) -> None:
        row = {"listed": 3, "shown": ["0x1"], "shown_at_most": 12, "read_after": []}
        builder = RunSummaryBuilder(start_time=0.0)

        builder.set_budget({"my_code_reader": [{"steps_used": 3, "callees_question": row}]})

        assert builder._budget is not None
        assert builder._budget["my_code_reader"]["callees_question"] == [row]


def _acme(tool: str, kind: str) -> Any:
    """A server nobody shipped, declaring ``tool`` of ``kind`` in the operator's settings."""
    settings = Settings.model_validate(
        {
            "mcp": {
                "servers": {
                    "acme": {
                        "command": "x",
                        "tool_facts": {
                            tool: {
                                "kind": kind,
                                "effects": {"network": False, "third_party": "no"},
                            }
                        },
                    }
                }
            }
        }
    )
    return facts_record("mcp:acme", tool, declared=declarations(settings))


def _served(tool: str, facts: Any, source: str = "mcp:acme") -> LedgerEntry:
    listings = {START: _listing(START, GATE), OUTER: _listing(OUTER, STEP, SIDE, HELPER)}
    return LedgerEntry(
        id="ev_0003",
        tool=tool,
        args={"functions": ",".join(hex(a) for a in listings)},
        output=json.dumps({hex(a): text for a, text in listings.items()}),
        source=source,
        facts=facts,
    )


class TestAnyAnalystAndAnyTool:
    @pytest.mark.usefixtures("tools")
    def test_a_user_s_analyst_with_a_declared_decompiler_of_its_own_is_asked(self) -> None:
        facts = _acme("lift_routines", "decompile_batch")
        assert facts is not None and facts["kind"] == "decompile_batch"
        analyst = _Analyst([RETRY], [_served("lift_routines", facts)])

        recorded = _events(analyst)

        (turns,) = analyst.seen_turns
        assert UNREAD_CALLEES_CODE in str(turns[-1].content)
        assert {d["agent"] for kind, d in recorded if kind == "validation_feedback"} == {
            "my_code_reader"
        }

    @pytest.mark.usefixtures("tools")
    def test_an_undeclared_server_s_decompiler_is_read_by_what_its_name_says(self) -> None:
        analyst = _Analyst([RETRY], [_served("decompile_many", None, source="mcp:unknown")])

        _events(analyst)

        (turns,) = analyst.seen_turns
        assert UNREAD_CALLEES_CODE in str(turns[-1].content)

    def test_an_undeclared_tool_nothing_says_lists_code_is_named_in_the_note(self) -> None:
        analyst = _Analyst([], [_served("lift_all", None, source="mcp:unknown")])

        recorded = _events(analyst)

        assert analyst.seen_turns == []
        (said,) = _notes(recorded)
        assert said["speaker"] == "my_code_reader" and said["kind"] == "system"
        assert "1 undeclared tool(s) it called (lift_all)" in said["text"]
        assert "not_run" in analyst._budget_records[-1]["callees_question"]

    def test_an_analyst_that_reads_no_code_is_not_asked_and_nothing_is_said(self) -> None:
        lookup = LedgerEntry(
            id="ev_0003",
            tool="resolve_host",
            args={"host": "example.test"},
            output="{}",
            source="mcp:acme",
            facts=_acme("resolve_host", "dns"),
        )
        analyst = _Analyst([], [lookup])
        analyst.name = "my_network_reader"
        analyst.pack_entries = []

        recorded = _events(analyst, HOST_ANSWER)

        assert analyst.seen_turns == []
        assert _notes(recorded) == []
        assert "callees_question" not in analyst._budget_records[-1]

    def test_why_it_was_not_asked_is_said_once_per_job(self) -> None:
        analyst = _Analyst([], [_served("lift_all", None, source="mcp:unknown")])

        first = _events(analyst)
        second = _events(analyst)

        assert len(_notes(first)) == 1
        assert _notes(second) == []


class TestTheSeam:
    def test_whether_an_analyst_reads_code_is_decided_in_one_place(self) -> None:
        assert reads_code(None, OWN) == (True, "")
        assert reads_code(None, []) == (False, NOT_RUN_NO_LISTING)

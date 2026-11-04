"""The unread callees of the routines an analyst describes are listed to it, once (T-558).

A reverser stopped on its own with the routine that reads its configuration
file, the one that writes it and the cipher wrapper of its channel unread. Each
was a callee of a routine its claims described, and the function map listed
it as named and not read. Before the answer stands, the platform now lists
those callees in one question:

- a routine is described when a claim names its address or cites the entry
  that lists it; only the callees of described routines are listed;
- the list is ranked by distance from where the code starts (the entry point
  and exports a PE header answer states, the threads the function index
  states), a further caller counting one call, so a shared helper comes last;
- at most :data:`CALLEES_SHOWN` are listed, and the question says how many
  there are and that the rest are not;
- it carries addresses and counts only, never a name or a string the sample
  or a tool wrote;
- it is asked once per analyst and job; the analyst reads what it chooses,
  and the loop's record and an answered row say what it read;
- an answer with nothing unread sends exactly what it sent before.

Every address, name and sentence here is made up for the test.
"""

from __future__ import annotations

import json
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
OUTER = BASE + 0x2000  # called by the start; described
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


def _batch(entry: str, listings: dict[int, str], facts: Any = None) -> LedgerEntry:
    return LedgerEntry(
        id=entry,
        tool="batch_decompile",
        args={"functions": ",".join(hex(a) for a in listings)},
        output=json.dumps({hex(a): text for a, text in listings.items()}),
        **({"source": "provider:ghidra", "facts": facts} if facts is not None else {}),
    )


def _decompile(entry: str, address: int, *calls: int) -> LedgerEntry:
    return LedgerEntry(
        id=entry,
        tool="decompile_function",
        args={"address": f"{address:x}"},
        output=_listing(address, *calls),
    )


def _index(facts: Any = None, *, threads: bool = False) -> LedgerEntry:
    others = {
        hex(START): [hex(OUTER)],
        hex(OUTER): [hex(STEP), hex(SIDE), hex(HELPER)],
        hex(STEP): [hex(BASE + 0x5000), hex(BASE + 0x6000)],
        **{hex(o): [hex(HELPER)] for o in OTHERS},
    }
    data: dict[str, Any] = {
        "tool": "function_index",
        "image_base": hex(BASE),
        "rows": [],
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
        **({"source": "pack", "facts": facts} if facts is not None else {}),
    )


def _header(facts: Any = None) -> LedgerEntry:
    data = {
        "image_base": hex(BASE),
        "entry_point": 0x1000,
        "export_rows": [{"name": SECRET, "ordinal": 1, "rva": "0x1000"}],
    }
    return LedgerEntry(
        id="ev_0004",
        tool="pe_info",
        args={"path": "/x/s.dll", "carved_path": ""},
        output=json.dumps(data),
        **({"source": "pack", "facts": facts} if facts is not None else {}),
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
    _batch("ev_0003", {START: _listing(START, OUTER), OUTER: _listing(OUTER, STEP, SIDE, HELPER)})
]
PACK = [_header(), _index()]
DESCRIBED = [_claim(f"{OUTER:#x} decrypts the configuration.")]


class TestWhatIsListed:
    def test_the_callees_of_a_described_routine_are_ranked_by_the_main_path(self) -> None:
        found = callees_to_read(DESCRIBED, OWN, PACK)

        assert [c.address for c in found.ranked] == [STEP, SIDE, HELPER]
        assert found.starts == STARTS_STATED
        step = found.ranked[0]
        assert (step.callers, step.depth, step.start, step.called_from, step.calls) == (
            (OUTER,),
            2,
            START,
            1,
            2,
        )
        # Six functions call the helper: five more than one, five calls further.
        assert found.ranked[-1].distance() == 2 + 5

    def test_a_routine_no_claim_describes_has_its_callees_left_out(self) -> None:
        # The start is read and named, by a claim citing no listing; the outer
        # routine it calls is read, so nothing the start calls is unread.
        found = callees_to_read([_claim(f"{START:#x} is the export.", "[ev_0004]")], OWN, PACK)

        assert found.ranked == ()

    def test_a_cited_listing_describes_every_routine_it_holds(self) -> None:
        found = callees_to_read([_claim("The loader decrypts its settings.")], OWN, PACK)

        assert [c.address for c in found.ranked] == [STEP, SIDE, HELPER]

    def test_a_thread_the_index_states_is_a_start(self) -> None:
        found = callees_to_read(DESCRIBED, OWN, [_index(threads=True)])

        assert found.starts == STARTS_STATED
        assert (found.ranked[0].depth, found.ranked[0].start) == (1, OUTER)

    def test_with_no_start_stated_the_routine_a_claim_calls_main_stands_in(self) -> None:
        claims = [_claim(f"{OUTER:#x} is the main dispatcher of commands.")]

        found = callees_to_read(claims, OWN, [_index()])

        assert found.starts == STARTS_CLAIMED
        assert (found.ranked[0].depth, found.ranked[0].start) == (1, OUTER)

    def test_with_no_start_at_all_the_list_is_still_given_unranked_by_path(self) -> None:
        found = callees_to_read(DESCRIBED, OWN, [])

        assert found.starts == STARTS_NONE
        assert {c.address for c in found.ranked} == {STEP, SIDE, HELPER}
        assert all(c.depth is None for c in found.ranked)

    def test_a_read_callee_is_not_listed(self) -> None:
        own = [*OWN, _decompile("ev_0005", STEP)]

        found = callees_to_read(DESCRIBED, own, PACK)

        assert [c.address for c in found.ranked] == [SIDE, HELPER]

    def test_an_analyst_that_listed_no_code_is_not_read_at_all(self) -> None:
        with patch("maljan.agents.callees_question.build_function_map") as built:
            found = callees_to_read(DESCRIBED, [], PACK)

        assert found.ranked == ()
        built.assert_not_called()

    def test_the_order_is_the_same_whatever_order_the_pack_is_in(self) -> None:
        one = callees_to_read(DESCRIBED, OWN, PACK)
        two = callees_to_read(DESCRIBED, OWN, list(reversed(PACK)))

        assert one == two


class TestTheQuestion:
    def test_it_lists_each_with_its_reason_and_forces_nothing(self) -> None:
        violation = unread_callees_violation(callees_to_read(DESCRIBED, OWN, PACK))

        assert violation is not None
        assert violation.code == UNREAD_CALLEES_CODE
        assert (
            f"{STEP:#x} (called by {OUTER:#x}; 2 call(s) from the start {START:#x}; "
            "1 caller(s); calls 2)"
        ) in violation.message
        assert "leave them unread and change nothing" in violation.message
        assert "This is asked once." in violation.message

    def test_it_carries_no_text_the_sample_or_a_tool_wrote(self) -> None:
        violation = unread_callees_violation(callees_to_read(DESCRIBED, OWN, PACK))

        assert violation is not None
        assert SECRET not in violation.message
        assert "FUN_" not in violation.message

    def test_a_longer_list_is_bounded_and_says_so(self) -> None:
        many = [BASE + 0x20000 + 0x10 * i for i in range(CALLEES_SHOWN + 3)]
        own = [_batch("ev_0003", {OUTER: _listing(OUTER, *many)})]

        found = callees_to_read(DESCRIBED, own, [])
        violation = unread_callees_violation(found)

        assert len(found.ranked) == CALLEES_SHOWN + 3
        assert violation is not None
        assert (
            f"The first {CALLEES_SHOWN} of {CALLEES_SHOWN + 3} are listed (the question lists "
            f"at most {CALLEES_SHOWN}); the other 3 are not."
        ) in violation.message
        assert hex(many[CALLEES_SHOWN]) not in violation.message

    def test_nothing_unread_is_no_question(self) -> None:
        assert unread_callees_violation(callees_to_read(DESCRIBED, [], PACK)) is None


class TestTheShippedDeclarations:
    def test_the_shipped_decompiler_index_and_header_are_read_by_their_declared_kinds(
        self,
    ) -> None:
        batch, index, header = _shipped()
        assert batch is not None and index is not None and header is not None
        own = [
            _batch(
                "ev_0003",
                {START: _listing(START, OUTER), OUTER: _listing(OUTER, STEP, SIDE, HELPER)},
                batch,
            )
        ]

        found = callees_to_read(DESCRIBED, own, [_header(header), _index(index)])

        assert [c.address for c in found.ranked] == [STEP, SIDE, HELPER]
        assert found.starts == STARTS_STATED

    def test_the_shipped_reverser_is_served_the_provider_s_decompiler(self) -> None:
        # The seeded reverser reads code through the static provider's tools,
        # whose batch decompile the shipped declarations call a decompile.
        reverser = Settings().agents.definitions["reverser"]
        batch, _index_facts, _header_facts = _shipped()

        assert "provider" in [ref.kind for ref in reverser.tools]
        assert batch is not None and batch["kind"] == "decompile_batch"


def _inputs(entries: list[Any], pack: list[Any]) -> AnswerCheckInputs:
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
        entries=entries,
        pack=pack,
    )


class TestTheComposition:
    def test_the_question_is_one_of_the_answer_s_checks_only_when_asked_for(self) -> None:
        isr = AgentISR(agent_id="reverser", domain="code", claims=DESCRIBED)

        def _codes(asked: bool) -> list[str]:
            with patch("maljan.pipeline.validation.validate_isr", return_value=[]):
                found = analyst_answer_checks(
                    isr,
                    _inputs(OWN, PACK),
                    whole_answer=[],
                    unread=[],
                    functions=[],
                    weak_alignment_challenges=False,
                    callees_question=asked,
                )
            return [v.code for v in found]

        assert UNREAD_CALLEES_CODE in _codes(True)
        assert UNREAD_CALLEES_CODE not in _codes(False)

    def test_a_check_that_raises_asks_nothing_and_keeps_the_others(self) -> None:
        isr = AgentISR(agent_id="reverser", domain="code", claims=DESCRIBED)
        with (
            patch("maljan.pipeline.validation.validate_isr", return_value=[]),
            patch(
                "maljan.agents.callees_question.callees_to_read",
                side_effect=RuntimeError("x"),
            ),
        ):
            found = analyst_answer_checks(
                isr,
                _inputs(OWN, PACK),
                whole_answer=[],
                unread=[],
                functions=[],
                weak_alignment_challenges=False,
                callees_question=True,
            )

        assert found == []


FIRST = (
    f"CLAIM 1: {START:#x} is the export, and it calls {OUTER:#x}.\n"
    "EVIDENCE: [ev_0003]\nCONFIDENCE: 0.8\nTECHNIQUE: NONE\n---\n"
    f"CLAIM 2: {OUTER:#x} decrypts the configuration.\n"
    "EVIDENCE: [ev_0003]\nCONFIDENCE: 0.8\nTECHNIQUE: NONE\n---\n"
)
RETRY = (
    f"CLAIM 3: {STEP:#x} reads the settings file.\n"
    "EVIDENCE: [ev_0007]\nCONFIDENCE: 0.8\nTECHNIQUE: NONE\n---\n"
)


class _Analyst(BaseAnalyst):
    def __init__(self, replies: list[str], entries: list[LedgerEntry]) -> None:
        super().__init__(llm=MagicMock(), name="reverser")
        self._evidence_entries = list(entries)
        self._replies = list(replies)
        self.seen_turns: list[list[Any]] = []
        self.pack_entries = list(PACK)
        self.read_on_retry: LedgerEntry | None = None

    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        return ""

    def _invoke_llm_with_timeout(self, messages: list, timeout: float, **_: Any) -> str:
        self.seen_turns.append(list(messages))
        # What the analyst's own tools would file when it reads a callee.
        if self.read_on_retry is not None:
            self._evidence_entries.append(self.read_on_retry)
            self.read_on_retry = None
        text = self._replies.pop(0)
        self._record_usage(AIMessage(content=text))
        return text


def _check(analyst: _Analyst, first: str = FIRST) -> AgentISR:
    isr = analyst._text_to_isr(first, 0)
    with (
        patch("maljan.agents.base_agent.validity_check_available", return_value=True),
        patch.object(BaseAnalyst, "_fits_the_window", return_value=True),
    ):
        return analyst._validate_isr(isr, "evidence")


@pytest.fixture
def one_loop(monkeypatch: pytest.MonkeyPatch) -> Any:
    def _give(analyst: _Analyst) -> _Analyst:
        analyst._budget_records = [{"steps_used": 3}]
        return analyst

    return _give


class TestTheValidationTurn:
    def test_it_is_asked_once_and_what_the_analyst_read_is_recorded(self, one_loop: Any) -> None:
        analyst = one_loop(_Analyst([RETRY], list(OWN)))
        analyst.read_on_retry = _decompile("ev_0007", STEP, BASE + 0x5000, BASE + 0x6000)

        result = _check(analyst)

        (turns,) = analyst.seen_turns
        question = str(turns[-1].content)
        assert UNREAD_CALLEES_CODE in question
        assert f"{STEP:#x}" in question and f"{HELPER:#x}" in question
        assert any(f"{STEP:#x}" in c.claim for c in result.claims)
        record = analyst._budget_records[-1]["callees_question"]
        assert record == {
            "listed": 3,
            "shown": [hex(STEP), hex(SIDE), hex(HELPER)],
            "shown_at_most": CALLEES_SHOWN,
            "read_after": [hex(STEP)],
        }
        (row,) = [v for v in analyst.validation_findings if v.code == UNREAD_CALLEES_CODE]
        assert row.answered
        assert "read 1 of those listed" in row.message and "left 2 unread" in row.message

    def test_a_later_turn_of_the_same_job_is_not_asked_again(self, one_loop: Any) -> None:
        analyst = one_loop(_Analyst([RETRY], list(OWN)))
        _check(analyst)
        analyst._replies = []

        _check(analyst)

        assert len(analyst.seen_turns) == 1

    def test_another_job_is_asked_again(self, one_loop: Any) -> None:
        analyst = one_loop(_Analyst([RETRY, RETRY], list(OWN)))
        _check(analyst)
        analyst._job_id = "another job"

        _check(analyst)

        assert len(analyst.seen_turns) == 2

    def test_it_rides_the_turn_another_question_already_takes(self, one_loop: Any) -> None:
        # A decompiled routine no claim names is asked about in the same turn:
        # one model call carries both questions.
        own = [*OWN, _decompile("ev_0006", BASE + 0x7000)]
        analyst = one_loop(_Analyst([RETRY], own))

        _check(analyst)

        (turns,) = analyst.seen_turns
        question = str(turns[-1].content)
        assert UNREAD_CALLEES_CODE in question and "isr.decompiled_not_described" in question

    def test_an_answer_with_nothing_unread_sends_nothing_new(self, one_loop: Any) -> None:
        own = [
            *OWN,
            _decompile("ev_0005", STEP),
            _decompile("ev_0006", SIDE),
            _decompile("ev_0007", HELPER),
        ]
        first = FIRST + (
            f"CLAIM 3: {STEP:#x}, {SIDE:#x} and {HELPER:#x} copy and free buffers.\n"
            "EVIDENCE: [ev_0005]\nCONFIDENCE: 0.8\nTECHNIQUE: NONE\n---\n"
        )
        analyst = one_loop(_Analyst([], own))
        # No index: what the read callees call is not stated, so nothing is unread.
        analyst.pack_entries = [_header()]

        _check(analyst, first)

        assert analyst.seen_turns == []
        assert "callees_question" not in analyst._budget_records[-1]


class TestTheRecord:
    def test_the_record_lists_what_was_asked_and_what_was_read(self) -> None:
        record, answered = callees_asked_record(
            DESCRIBED, OWN, [*OWN, _decompile("ev_0007", SIDE)], PACK
        )

        assert record["read_after"] == [hex(SIDE)]
        assert answered is not None and answered.answered

    def test_nothing_asked_is_no_record(self) -> None:
        assert callees_asked_record(DESCRIBED, [], [], PACK) == ({}, None)

    def test_the_run_summary_carries_it_per_agent(self) -> None:
        row = {"listed": 3, "shown": ["0x1"], "shown_at_most": 12, "read_after": []}
        builder = RunSummaryBuilder(start_time=0.0)

        builder.set_budget({"reverser": [{"steps_used": 3, "callees_question": row}]})

        assert builder._budget is not None
        assert builder._budget["reverser"]["callees_question"] == [row]


def _events(analyst: _Analyst, first: str = FIRST) -> list[tuple[str, dict[str, Any]]]:
    recorded: list[tuple[str, dict[str, Any]]] = []
    with patch.object(
        BaseAnalyst, "_event_sink", lambda _self: lambda kind, data: recorded.append((kind, data))
    ):
        _check(analyst, first)
    return recorded


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
    listings = {START: _listing(START, OUTER), OUTER: _listing(OUTER, STEP, SIDE, HELPER)}
    return LedgerEntry(
        id="ev_0003",
        tool=tool,
        args={"functions": ",".join(hex(a) for a in listings)},
        output=json.dumps({hex(a): text for a, text in listings.items()}),
        source=source,
        facts=facts,
    )


HOST_ANSWER = (
    "CLAIM 1: The host resolves.\nEVIDENCE: [ev_0003]\nCONFIDENCE: 0.8\nTECHNIQUE: NONE\n---\n"
)


class TestAnyAnalystAndAnyTool:
    def test_a_user_s_analyst_with_a_declared_decompiler_of_its_own_is_asked(
        self, one_loop: Any
    ) -> None:
        facts = _acme("lift_routines", "decompile_batch")
        assert facts is not None and facts["kind"] == "decompile_batch"
        analyst = one_loop(_Analyst([RETRY], [_served("lift_routines", facts)]))
        analyst.name = "my_code_reader"

        recorded = _events(analyst)

        (turns,) = analyst.seen_turns
        assert UNREAD_CALLEES_CODE in str(turns[-1].content)
        states = [
            d["state"]
            for kind, d in recorded
            if kind == "validation_feedback" and d["code"] == UNREAD_CALLEES_CODE
        ]
        assert states == ["retried", "answered"]
        assert {d["agent"] for kind, d in recorded if kind == "validation_feedback"} == {
            "my_code_reader"
        }

    def test_an_undeclared_server_s_decompiler_is_read_by_what_its_name_says(
        self, one_loop: Any
    ) -> None:
        entry = _served("decompile_many", None, source="mcp:unknown")
        analyst = one_loop(_Analyst([RETRY], [entry]))
        analyst.name = "my_code_reader"

        _events(analyst)

        (turns,) = analyst.seen_turns
        assert UNREAD_CALLEES_CODE in str(turns[-1].content)

    def test_an_undeclared_tool_nothing_says_lists_code_is_named_in_the_event(
        self, one_loop: Any
    ) -> None:
        analyst = one_loop(_Analyst([], [_served("lift_all", None, source="mcp:unknown")]))
        analyst.name = "my_code_reader"

        recorded = _events(analyst)

        assert analyst.seen_turns == []
        (said,) = [d for kind, d in recorded if kind == "agent_message"]
        assert said["speaker"] == "my_code_reader" and said["kind"] == "system"
        assert "1 undeclared tool(s) it called (lift_all)" in said["text"]
        assert "not_run" in analyst._budget_records[-1]["callees_question"]

    def test_an_analyst_with_no_code_reading_source_is_not_asked_and_told_why(
        self, one_loop: Any
    ) -> None:
        lookup = LedgerEntry(
            id="ev_0003",
            tool="resolve_host",
            args={"host": "example.test"},
            output="{}",
            source="mcp:acme",
            facts=_acme("resolve_host", "dns"),
        )
        analyst = one_loop(_Analyst([], [lookup]))
        analyst.name = "my_network_reader"
        analyst.pack_entries = []

        recorded = _events(analyst, HOST_ANSWER)

        assert analyst.seen_turns == []
        (said,) = [d for kind, d in recorded if kind == "agent_message"]
        assert said["text"].endswith(f"{NOT_RUN_NO_LISTING}.")
        assert analyst._budget_records[-1]["callees_question"] == {"not_run": NOT_RUN_NO_LISTING}

    def test_why_it_was_not_asked_is_said_once_per_job(self, one_loop: Any) -> None:
        analyst = one_loop(_Analyst([], [_served("lift_all", None, source="mcp:unknown")]))

        first = _events(analyst)
        second = _events(analyst)

        assert len([k for k, _d in first if k == "agent_message"]) == 1
        assert [k for k, _d in second if k == "agent_message"] == []


class TestTheSeam:
    def test_whether_an_analyst_reads_code_is_decided_in_one_place(self) -> None:
        assert reads_code(None, OWN) == (True, "")
        assert reads_code(None, []) == (False, NOT_RUN_NO_LISTING)

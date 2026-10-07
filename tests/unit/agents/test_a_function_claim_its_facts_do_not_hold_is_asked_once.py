"""A claim naming a call its function's facts do not hold is asked about once, in the turn.

The question goes through the validation turn every other question goes through.
The analyst corrects, keeps or withdraws the claim and its answer stands: a
correction leaves no finding, a kept claim stays with the finding recorded, and a
withdrawal is kept although the answer has one claim block fewer. A question no
time was left for is recorded as not asked. The run record says how many claims
were checked and asked about, and the judge's note shows a kept one's finding.

Every address, name and sentence here is made up for the test.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock, patch

from langchain_core.messages import AIMessage

from maljan.agents.base_agent import BaseAnalyst
from maljan.agents.function_map import function_artefacts
from maljan.pipeline.function_claims import FUNCTION_CLAIM_UNHELD_CODE
from maljan.pipeline.validation import FUNCTION_CHECK_HEAD, technique_check_note
from maljan.schemas.evidence import LedgerEntry
from maljan.schemas.isr_models import AgentISR

BASE = 0x140000000
MAIN = 0x2340
HELPER = 0x2A10
MAIN_VA = f"0x{BASE + MAIN:x}"


def _cells(key: str, values: Any) -> list[dict[str, Any]]:
    return [{key: value, "sources": ["this entry"]} for value in values]


def _index() -> LedgerEntry:
    rows = [
        {
            "function": hex(BASE + MAIN),
            "offset": hex(MAIN),
            "direct": 1,
            "imports": _cells("name", ["CreateMutexW"]),
            "resolved": [],
            "decoded_strings": [],
            "plain_strings": [],
            "capa": [],
            "callers": [],
            "callees": [hex(BASE + HELPER)],
            "indirect": {"artefacts": 1, "through": 1},
        },
        {
            "function": hex(BASE + HELPER),
            "offset": hex(HELPER),
            "direct": 1,
            "imports": _cells("name", ["GetTickCount"]),
            "resolved": [],
            "decoded_strings": [],
            "plain_strings": [],
            "capa": [],
            "callers": [hex(BASE + MAIN)],
            "callees": [],
            "indirect": {"artefacts": 0, "through": 0},
        },
    ]
    data = {
        "tool": "function_index",
        "image_base": hex(BASE),
        "functions_known": 2,
        "undecoded_functions": 0,
        "undecoded": [],
        "calls_unnamed": {},
        "rows": rows,
    }
    return LedgerEntry(
        id="ev_0002",
        agent="pipeline",
        tool="function_index",
        output=json.dumps(data),
        structured=data,
    )


LISTING = LedgerEntry(
    id="ev_0007",
    agent="reverser",
    tool="decompile_function",
    args={"address": f"{BASE + MAIN:x}"},
    output=f"\nundefined8 FUN_{BASE + MAIN:x}(void)\n\n{{\n  FUN_{BASE + HELPER:x}();\n}}\n",
)


def _block(n: int, sentence: str) -> str:
    return f"CLAIM {n}: {sentence}\nEVIDENCE: [ev_0007]\nCONFIDENCE: 0.8\nTECHNIQUE: NONE\n---\n"


GUARD = _block(1, f"{MAIN_VA} creates the single-instance guard with CreateMutexW.")
WRONG = _block(2, f"{MAIN_VA} waits with SleepEx between beacons.")
FIXED = _block(2, f"{MAIN_VA} reads the clock with GetTickCount between beacons.")


class _Analyst(BaseAnalyst):
    def __init__(self, replies: list[str]) -> None:
        super().__init__(llm=MagicMock(), name="reverser")
        self._evidence_entries = [LISTING]
        index = _index()
        self.pack_function_artefacts = function_artefacts([index])
        self.pack_entries = [index]
        self._replies = list(replies)
        self.seen_turns: list[list[Any]] = []
        self._budget_records = [{"agent": "reverser"}]

    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        return ""

    def _invoke_llm_with_timeout(self, messages: list, timeout: float, **_: Any) -> str:
        self.seen_turns.append(list(messages))
        text = self._replies.pop(0)
        self._record_usage(AIMessage(content=text))
        return text


def _check(analyst: _Analyst, first: str = GUARD + WRONG) -> AgentISR:
    isr = analyst._text_to_isr(first, 0)
    with (
        patch("maljan.agents.base_agent.validity_check_available", return_value=True),
        patch.object(BaseAnalyst, "_fits_the_window", return_value=True),
    ):
        return analyst._validate_isr(isr, "evidence")


def _left(analyst: _Analyst) -> list[Any]:
    return [v for v in analyst.validation_findings if v.code == FUNCTION_CLAIM_UNHELD_CODE]


class TestTheTurn:
    def test_the_question_is_asked_once_and_a_correction_stands(self) -> None:
        analyst = _Analyst([GUARD + FIXED])

        result = _check(analyst)

        (turns,) = analyst.seen_turns
        question = str(turns[-1].content)
        assert FUNCTION_CLAIM_UNHELD_CODE in question
        assert "claim 2 (" in question and '"SleepEx"' in question
        assert "GetTickCount" in result.claims[1].claim
        assert _left(analyst) == []

    def test_a_kept_claim_stays_with_the_finding_recorded(self) -> None:
        analyst = _Analyst([GUARD + WRONG])

        result = _check(analyst)

        assert len(analyst.seen_turns) == 1
        assert "SleepEx" in result.claims[1].claim
        (left,) = _left(analyst)
        assert left.asked and '"SleepEx"' in left.message

    def test_a_withdrawal_stands_with_one_claim_block_fewer(self) -> None:
        analyst = _Analyst([GUARD])

        result = _check(analyst)

        # One turn: the withdrawn claim is the answer, not a dropped one to ask about.
        assert len(analyst.seen_turns) == 1
        assert [c.claim for c in result.claims] == [
            f"{MAIN_VA} creates the single-instance guard with CreateMutexW."
        ]
        assert _left(analyst) == []

    def test_a_retry_that_drops_another_claim_keeps_the_first_answer(self) -> None:
        analyst = _Analyst([WRONG.replace("CLAIM 2", "CLAIM 1")])

        result = _check(analyst)

        assert len(result.claims) == 2

    def test_a_question_no_time_was_left_for_is_recorded_as_not_asked(self) -> None:
        analyst = _Analyst([])
        with (
            patch.object(BaseAnalyst, "_seconds_the_last_loop_left", return_value=1.0),
            patch.object(BaseAnalyst, "seconds_an_answer_needs", return_value=60.0),
        ):
            _check(analyst)

        assert analyst.seen_turns == []
        (left,) = _left(analyst)
        assert not left.asked and "Not asked" in left.message

    def test_the_loop_s_record_counts_the_claims_checked_and_asked(self) -> None:
        analyst = _Analyst([GUARD + FIXED])

        _check(analyst)

        assert analyst._budget_records[-1]["function_claims"] == {"checked": 2, "asked": 1}

    def test_an_answer_naming_what_the_facts_hold_is_not_asked(self) -> None:
        analyst = _Analyst([])

        _check(analyst, GUARD + FIXED)

        assert analyst.seen_turns == []
        assert analyst._budget_records[-1]["function_claims"] == {"checked": 2, "asked": 0}


class TestWhatTheRunShows:
    def test_the_judge_s_note_shows_a_kept_finding_as_it_was_asked(self) -> None:
        analyst = _Analyst([GUARD + WRONG])
        _check(analyst)
        (left,) = _left(analyst)

        note = technique_check_note({"reverser": [left.to_dict()]})

        assert note.startswith(FUNCTION_CHECK_HEAD)
        assert f"- {FUNCTION_CLAIM_UNHELD_CODE}: " in note
        assert "TECHNIQUE CHECK" not in note

    def test_the_run_summary_keeps_each_loop_s_record(self) -> None:
        from maljan.analysis.run_summary import RunSummaryBuilder

        builder = RunSummaryBuilder(start_time=0.0).set_budget(
            {
                "reverser": [
                    {"steps_used": 3, "function_claims": {"checked": 2, "asked": 1}},
                    {"steps_used": 1},
                ]
            }
        )

        assert builder._budget is not None
        assert builder._budget["reverser"]["function_claims"] == [{"checked": 2, "asked": 1}]

    def test_a_loop_with_no_function_claims_adds_nothing_to_the_summary(self) -> None:
        from maljan.analysis.run_summary import RunSummaryBuilder

        builder = RunSummaryBuilder(start_time=0.0).set_budget({"static": [{"steps_used": 1}]})

        assert builder._budget is not None
        assert "function_claims" not in builder._budget["static"]


IMPORTS = LedgerEntry(
    id="ev_0001",
    agent="pipeline",
    tool="pe_imports",
    output="ws2_32.dll: connect, send\nkernel32.dll: CreateMutexW",
)


def _cited(n: int, sentence: str, evidence: str) -> str:
    return f"CLAIM {n}: {sentence}\nEVIDENCE: {evidence}\nCONFIDENCE: 0.8\nTECHNIQUE: NONE\n---\n"


LIBRARY = _cited(3, "The sample imports ws2_32.dll for networking.", "[ev_0001]")
SECOND_GUARD = _cited(
    4, f"{MAIN_VA} creates a guard named with CreateMutexW before anything else.", "[ev_0007]"
)
KEPT = GUARD + SECOND_GUARD.replace("CLAIM 4", "CLAIM 2")


class TestOneRuleForEveryAskedClaim:
    def _analyst(self, reply: str) -> _Analyst:
        analyst = _Analyst([reply])
        analyst.pack_entries = [*analyst.pack_entries, IMPORTS]
        analyst._evidence_entries = [LISTING, IMPORTS]
        return analyst

    def test_a_retry_withdrawing_the_claims_both_questions_asked_about_is_kept(self) -> None:
        analyst = self._analyst(KEPT)

        result = _check(analyst, GUARD + WRONG + LIBRARY + SECOND_GUARD)

        assert len(analyst.seen_turns) == 1
        question = str(analyst.seen_turns[-1][-1].content)
        assert FUNCTION_CLAIM_UNHELD_CODE in question and "isr.library_only_claims" in question
        assert len(result.claims) == 2

    def test_with_no_function_question_the_library_rule_is_as_it_was(self) -> None:
        analyst = self._analyst(KEPT)

        result = _check(
            analyst,
            GUARD
            + LIBRARY.replace("CLAIM 3", "CLAIM 2")
            + _cited(
                3,
                f"{MAIN_VA} creates a guard named with CreateMutexW before anything else.",
                "[ev_0007]",
            ),
        )

        question = str(analyst.seen_turns[-1][-1].content)
        assert FUNCTION_CLAIM_UNHELD_CODE not in question
        assert len(result.claims) == 2

    def test_a_retry_dropping_a_claim_nobody_asked_about_keeps_the_first_answer(self) -> None:
        analyst = self._analyst(GUARD)

        result = _check(analyst, GUARD + WRONG + LIBRARY + SECOND_GUARD)

        assert len(result.claims) == 4

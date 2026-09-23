"""The validation turn after a loop gets what that loop left, or is not asked.

It used to be handed the loop's whole budget again — after a first loop that
ended at its time cap, 1,500 s more; after a second loop run under what the
stage had left, that whole remainder again — so the question about an answer's
format could double an analyst's time. It now gets what the loop it follows
left, and when that cannot hold an answer at the pace the loop measured, it is
not asked: what it would have asked is recorded, and the loop's budget record
says why.
"""

from __future__ import annotations

import time
from typing import Any
from unittest.mock import patch

from maljan.agents.base_agent import BaseAnalyst, BudgetCeiling, TurnPace
from maljan.pipeline.validation import UNPARSED_ANSWER_CODE

PROSE = "The sample downloads a payload and runs it from memory."
GOOD = "CLAIM: runs from memory\nEVIDENCE: fexecve [ev_0004]\nCONFIDENCE: 0.8\nTECHNIQUE: NONE\n"


class _Analyst(BaseAnalyst):
    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        return ""


def _analyst(turn_seconds: float) -> tuple[_Analyst, list[float]]:
    analyst = _Analyst(llm=object(), name="static")  # type: ignore[arg-type]
    pace = TurnPace()
    pace.current = "qwen"
    pace.turns["qwen"] = [turn_seconds]
    analyst._last_pace = pace
    analyst._note_budget({"stage": "analysis", "cap": "time"})
    given: list[float] = []

    def _answer(messages: list, timeout: float) -> str:
        given.append(timeout)
        return GOOD

    analyst._invoke_llm_with_timeout = _answer  # type: ignore[method-assign]
    return analyst, given


def _validated(analyst: _Analyst) -> Any:
    first = analyst._text_to_isr(PROSE, revision_round=0)
    with patch("maljan.agents.base_agent.validity_check_available", return_value=True):
        return analyst._validate_isr(first, "evidence")


class TestAfterTheFirstLoop:
    def test_the_turn_is_given_what_the_loop_left(self) -> None:
        analyst, given = _analyst(turn_seconds=10.0)
        analyst._last_loop_deadline = time.monotonic() + 400.0

        isr = _validated(analyst)

        assert isr.claims
        (timeout,) = given
        assert 390.0 < timeout <= 400.0, "not a fresh copy of the loop's budget"

    def test_a_loop_that_left_too_little_is_not_asked_and_it_is_recorded(self) -> None:
        analyst, given = _analyst(turn_seconds=140.0)
        analyst._last_loop_deadline = time.monotonic() + 100.0

        isr = _validated(analyst)

        assert given == []
        assert isr.claims == []
        assert isr.unparsed_answer == PROSE
        assert UNPARSED_ANSWER_CODE in {v.code for v in analyst.validation_findings}
        (record,) = analyst.drain_budget_records()
        assert record["validation"].startswith("not asked: 100s of the loop's time were left")
        assert "an answer needs 210s" in record["validation"]


class TestAfterTheSecondLoop:
    def test_the_turn_keeps_to_what_the_second_loop_left_not_its_ceiling(self) -> None:
        analyst, given = _analyst(turn_seconds=10.0)
        analyst._budget_ceiling = BudgetCeiling(40, 600.0)
        analyst._last_loop_deadline = time.monotonic() + 120.0

        _validated(analyst)

        (timeout,) = given
        assert timeout <= 120.0 < 600.0

    def test_a_second_loop_that_used_its_time_is_not_asked(self) -> None:
        analyst, given = _analyst(turn_seconds=10.0)
        analyst._budget_ceiling = BudgetCeiling(40, 600.0)
        analyst._last_loop_deadline = time.monotonic() - 1.0

        _validated(analyst)

        assert given == []


def test_the_summary_carries_the_turns_not_asked() -> None:
    from maljan.analysis.run_summary import RunSummaryBuilder

    summary = (
        RunSummaryBuilder(start_time=0.0)
        .set_budget({"static": [{"cap": "time", "validation": "not asked: 3s …"}]})
        .build()
        .to_dict()
    )

    assert summary["budget"]["static"]["validation_not_asked"] == ["not asked: 3s …"]

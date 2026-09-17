"""``by_code`` counts every correction, not only the ones that failed.

The second live run reported ``retries: 1`` and ``by_code: {}`` in the same
block, while the log said "retrying after 1 violation(s): verdict.not_json".
Both numbers were right about their own question and the pair was useless: a
violation the retry fixes leaves no trace in the unresolved list, which was the
only thing ``by_code`` was ever built from.

Every producer now counts what it was *shown* — analysts, judge, narrative and
composer — and the unresolved leftovers are added on top.
"""

from __future__ import annotations

from typing import Any

import pytest

from maljan.pipeline.validation import (
    ValidationTally,
    Violation,
    retry_with_feedback,
    retry_with_feedback_sync,
    validation_metrics,
)


def _violation(code: str = "verdict.not_json") -> Violation:
    return Violation(code=code, message="that was not a JSON bundle.")


class TestTheMetric:
    def test_a_fixed_violation_is_still_counted(self) -> None:
        metrics = validation_metrics(1, [], {"verdict.not_json": 1})
        assert metrics == {
            "retries": 1,
            "by_code": {"verdict.not_json": 1},
            "unresolved": [],
            "not_run": [],
        }

    def test_an_unresolved_one_is_added_on_top(self) -> None:
        metrics = validation_metrics(2, [("judge", _violation())], {"verdict.not_json": 1})
        assert metrics["by_code"] == {"verdict.not_json": 2}
        assert metrics["unresolved"] == [
            {"agent": "judge", "code": "verdict.not_json", "message": _violation().message}
        ]

    def test_codes_from_different_producers_are_kept_apart(self) -> None:
        metrics = validation_metrics(
            3,
            [("static", _violation("attck.unknown_id"))],
            {"narrative.schema": 2, "composer.schema": 1},
        )
        assert metrics["by_code"] == {
            "attck.unknown_id": 1,
            "composer.schema": 1,
            "narrative.schema": 2,
        }

    def test_it_is_unchanged_when_nothing_was_fed_back(self) -> None:
        assert validation_metrics(0, [])["by_code"] == {}


class TestTheTally:
    def test_it_counts_each_code(self) -> None:
        tally = ValidationTally()
        tally.count([_violation(), _violation(), _violation("stix.unknown_technique")])
        assert tally.by_code == {"verdict.not_json": 2, "stix.unknown_technique": 1}

    def test_merging_adds(self) -> None:
        left, right = ValidationTally(retries=1), ValidationTally(retries=2)
        left.count([_violation()])
        right.count([_violation(), _violation("composer.schema")])
        left.merge(right)
        assert left.retries == 3
        assert left.by_code == {"verdict.not_json": 2, "composer.schema": 1}


class TestTheRetryLoopReportsWhatItFedBack:
    def test_the_sync_loop_announces_before_it_asks_again(self) -> None:
        tally = ValidationTally()
        answers = iter(["bad", "good"])
        seen: list[str] = []

        def _run(turns: list[Any]) -> str:
            value = next(answers)
            seen.append(value)
            return value

        def _validate(parsed: str) -> list[Violation]:
            return [] if parsed == "good" else [_violation()]

        parsed, violations, retries = retry_with_feedback_sync(
            _run, [], [_validate], parse=lambda a: str(a), on_feedback=tally.count
        )

        assert (parsed, violations, retries) == ("good", [], 1)
        assert tally.by_code == {"verdict.not_json": 1}
        assert seen == ["bad", "good"]

    @pytest.mark.asyncio
    async def test_the_async_loop_does_the_same(self) -> None:
        tally = ValidationTally()
        answers = iter(["bad", "good"])

        async def _run(turns: list[Any]) -> str:
            return next(answers)

        def _validate(parsed: str) -> list[Violation]:
            return [] if parsed == "good" else [_violation("narrative.schema")]

        await retry_with_feedback(
            _run, [], [_validate], parse=lambda a: str(a), on_feedback=tally.count
        )
        assert tally.by_code == {"narrative.schema": 1}

    @pytest.mark.asyncio
    async def test_an_answer_that_was_right_first_time_feeds_back_nothing(self) -> None:
        tally = ValidationTally()

        async def _run(turns: list[Any]) -> str:
            return "good"

        await retry_with_feedback(
            _run, [], [lambda p: []], parse=lambda a: str(a), on_feedback=tally.count
        )
        assert tally.by_code == {}

    def test_a_tally_that_raises_does_not_break_the_loop(self) -> None:
        answers = iter(["bad", "good"])

        def _run(turns: list[Any]) -> str:
            return next(answers)

        def _explode(violations: Any) -> None:
            raise RuntimeError("the tally is broken")

        parsed, _violations, retries = retry_with_feedback_sync(
            _run,
            [],
            [lambda p: [] if p == "good" else [_violation()]],
            parse=lambda a: str(a),
            on_feedback=_explode,
        )
        assert (parsed, retries) == ("good", 1)


class TestTheReportRoundIsFoldedIn:
    def test_its_codes_are_added_to_the_summary_block(self) -> None:
        from maljan.pipeline.nodes import _amended_validation

        tally = ValidationTally(retries=2)
        tally.count([_violation("composer.schema"), _violation("narrative.schema")])
        block = _amended_validation(
            {"validation": {"retries": 1, "by_code": {"verdict.not_json": 1}, "unresolved": []}},
            tally,
        )

        assert block == {
            "retries": 3,
            "by_code": {
                "composer.schema": 1,
                "narrative.schema": 1,
                "verdict.not_json": 1,
            },
            "unresolved": [],
            "not_run": [],
        }

    def test_a_clean_report_round_amends_nothing(self) -> None:
        from maljan.pipeline.nodes import _amended_validation

        summary = {"validation": {"retries": 1, "by_code": {}, "unresolved": []}}
        assert _amended_validation(summary, ValidationTally()) is None

    def test_there_is_nothing_to_amend_without_a_summary(self) -> None:
        from maljan.pipeline.nodes import _amended_validation

        tally = ValidationTally(retries=1)
        tally.count([_violation("composer.schema")])
        assert _amended_validation(None, tally) is None


class TestTheProducersHandItOver:
    def test_the_analyst_drains_what_it_was_shown(self) -> None:
        from maljan.agents.base_agent import BaseAnalyst

        class _Analyst(BaseAnalyst):
            def analyze(self, data: str) -> str:  # pragma: no cover - unused
                return ""

            def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
                return ""

        analyst = _Analyst.__new__(_Analyst)
        analyst.validation_findings = []
        analyst.validation_retries = 2
        analyst.validation_fed_back = {"attck.unknown_id": 3}

        rows, retries, fed_back = analyst.drain_validation_findings()

        assert (rows, retries, fed_back) == ([], 2, {"attck.unknown_id": 3})
        # Drained, not read: a second call must not re-emit the same counts.
        assert analyst.drain_validation_findings() == ([], 0, {})

    def test_the_judge_verdict_carries_it(self) -> None:
        from maljan.agents.judge_agent import JudgeVerdict
        from maljan.schemas.stix_models import Bundle

        verdict = JudgeVerdict(bundle=Bundle(objects=[]), violations=[], retries=1)
        assert verdict.fed_back == {}

        counted = JudgeVerdict(
            bundle=Bundle(objects=[]),
            violations=[],
            retries=1,
            fed_back={"verdict.not_json": 1},
        )
        assert counted.fed_back == {"verdict.not_json": 1}


class TestADrainOnTheWrongContract:
    """The three values were unpacked inside a broad except that returned an
    empty update, so an agent still on the old two-value drain lost its
    findings, its retries and its feedback counts without a word."""

    class _Agent:
        def __init__(self, drained: Any) -> None:
            self._drained = drained

        def drain_validation_findings(self) -> Any:
            return self._drained

    def test_the_right_shape_is_read(self) -> None:
        from maljan.pipeline.nodes import _validation_update

        update = _validation_update(
            self._Agent(([{"code": "attck.unknown_id", "message": "m", "path": ""}], 1, {"a": 2})),
            "static",
        )

        assert update["validation_retries"] == 1
        assert update["validation_fed_back"] == {"a": 2}
        assert update["validation_findings"]["static"]

    def test_the_old_two_value_shape_is_said_out_loud(self, caplog: Any) -> None:
        import logging

        from maljan.pipeline.nodes import _validation_update

        with caplog.at_level(logging.ERROR, logger="maljan"):
            assert _validation_update(self._Agent(([], 1)), "static") == {}

        assert "drained 2 value(s), not three" in caplog.text

    def test_a_stub_that_drains_nothing_real_is_not_an_error(self, caplog: Any) -> None:
        import logging

        from maljan.pipeline.nodes import _validation_update

        with caplog.at_level(logging.ERROR, logger="maljan"):
            assert _validation_update(self._Agent(object()), "static") == {}

        assert caplog.text == ""

    def test_an_agent_with_no_drain_at_all_is_skipped(self) -> None:
        from maljan.pipeline.nodes import _validation_update

        assert _validation_update(object(), "static") == {}

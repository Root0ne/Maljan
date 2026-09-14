"""A verdict with no assessment is asked for one, and says so if it never comes.

The judge decides severity, malware category, family and its own confidence;
nothing downstream computes them. A bundle that omits ``x_maljan_assessment``
therefore produces a report whose severity reads "not assessed" — and until
now that happened silently, with the run summary showing a clean validation
block beside it.

It is a violation now: fed back once, in the words the judge can act on, and
recorded unresolved when the retry omits it too.
"""

from __future__ import annotations

from maljan.pipeline.validation import ASSESSMENT_MISSING_CODE, assessment_violations
from maljan.schemas.judgement import FamilyVerdict, JudgeAssessment, SeverityVerdict
from maljan.schemas.stix_models import Bundle


def _assessment(**overrides: object) -> JudgeAssessment:
    fields: dict[str, object] = {
        "severity": SeverityVerdict(rating="High", rationale="it injects into a remote process"),
        "malware_category": "loader",
        "family": FamilyVerdict(name="AsyncRAT", confidence=0.7, evidence_ids=["ev_0004"]),
        "confidence": 0.8,
    }
    fields.update(overrides)
    return JudgeAssessment(**fields)  # type: ignore[arg-type]


class TestTheAssessmentIsRequired:
    def test_a_bundle_without_one_is_a_violation(self) -> None:
        violations = assessment_violations(Bundle(objects=[]))
        assert [v.code for v in violations] == [ASSESSMENT_MISSING_CODE]

    def test_the_message_says_what_to_add_and_where(self) -> None:
        message = assessment_violations(Bundle(objects=[]))[0].message
        assert message.startswith("Add x_maljan_assessment")
        for field in (
            "severity",
            "rating",
            "rationale",
            "malware_category",
            "family",
            "name",
            "evidence_ids",
            "confidence",
        ):
            assert field in message

    def test_a_complete_assessment_passes(self) -> None:
        bundle = Bundle(objects=[], x_maljan_assessment=_assessment())
        assert assessment_violations(bundle) == []

    def test_an_assessment_that_says_nothing_at_all_is_missing(self) -> None:
        """Every field optional means an empty object parses; it is still nothing."""
        bundle = Bundle(objects=[], x_maljan_assessment=JudgeAssessment())
        assert [v.code for v in assessment_violations(bundle)] == [ASSESSMENT_MISSING_CODE]

    def test_a_partial_assessment_is_accepted(self) -> None:
        """The judge may abstain on a field it cannot support; that is not a fault."""
        bundle = Bundle(
            objects=[], x_maljan_assessment=_assessment(family=None, malware_category=None)
        )
        assert assessment_violations(bundle) == []


class TestTheJudgeAsksOnce:
    def test_a_first_answer_without_one_earns_a_feedback_turn(self) -> None:
        import asyncio
        from unittest.mock import MagicMock

        from maljan.agents.judge_agent import JudgeAgent

        answers = [
            '{"type": "bundle", "objects": []}',
            (
                '{"type": "bundle", "objects": [], "x_maljan_assessment": '
                '{"severity": {"rating": "High", "rationale": "it injects"}, '
                '"malware_category": "loader", "confidence": 0.8}}'
            ),
        ]

        class _LLM:
            async def ainvoke(self, turns: object) -> object:
                return MagicMock(content=answers.pop(0))

        judge = JudgeAgent.__new__(JudgeAgent)
        judge.llm = _LLM()
        judge.logger = MagicMock()
        judge.token_ledger = None
        judge.truncation_ledger = None

        verdict = asyncio.run(judge.give_verdict(reports={"static": "nothing"}, history=[]))

        assert verdict.retries == 1
        assert verdict.fed_back == {ASSESSMENT_MISSING_CODE: 1}
        assert verdict.violations == []
        assert verdict.bundle.x_maljan_assessment is not None
        assert verdict.bundle.x_maljan_assessment.confidence == 0.8

    def test_a_second_answer_without_one_is_recorded_unresolved(self) -> None:
        import asyncio
        from unittest.mock import MagicMock

        from maljan.agents.judge_agent import JudgeAgent

        class _LLM:
            async def ainvoke(self, turns: object) -> object:
                return MagicMock(content='{"type": "bundle", "objects": []}')

        judge = JudgeAgent.__new__(JudgeAgent)
        judge.llm = _LLM()
        judge.logger = MagicMock()
        judge.token_ledger = None
        judge.truncation_ledger = None

        verdict = asyncio.run(judge.give_verdict(reports={"static": "nothing"}, history=[]))

        assert verdict.retries == 1
        assert [v.code for v in verdict.violations] == [ASSESSMENT_MISSING_CODE]
        assert verdict.bundle.x_maljan_assessment is None

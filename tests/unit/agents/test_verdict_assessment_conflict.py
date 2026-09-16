"""A verdict and the judge's own severity may not say different things.

A live run returned Malware at 0.6 confidence with its own severity rated
Informational and a rationale reading "there is no evidence of malicious
functionality". Both fields are the judge's and both reached the report, which
printed them side by side with nothing saying they disagree.

It is one feedback turn now, naming both fields and asking which was meant.
Neither field is ever rewritten: a contradiction that survives the turn is
recorded, because choosing one of the two for the judge would be the silent
override this layer exists to replace.
"""

from __future__ import annotations

from maljan.pipeline.validation import (
    ASSESSMENT_CONFLICT_CODE,
    assessment_conflict_violations,
)
from maljan.schemas.judgement import JudgeAssessment, SeverityVerdict
from maljan.schemas.stix_models import AttackPattern, Bundle, Malware


def _malware_bundle(rating: str) -> Bundle:
    return Bundle(
        objects=[Malware(id=f"malware--{'a' * 8}-0000-4000-8000-{'b' * 12}", name="loader")],
        x_maljan_assessment=JudgeAssessment(
            severity=SeverityVerdict(rating=rating, rationale="stated by the judge")
        ),
    )


def _empty_bundle(rating: str) -> Bundle:
    return Bundle(
        objects=[],
        x_maljan_assessment=JudgeAssessment(
            severity=SeverityVerdict(rating=rating, rationale="stated by the judge")
        ),
    )


class TestTheTwoDirections:
    def test_malware_rated_informational_is_a_conflict(self) -> None:
        violations = assessment_conflict_violations(_malware_bundle("Informational"))

        assert [v.code for v in violations] == [ASSESSMENT_CONFLICT_CODE]
        assert violations[0].path == "x_maljan_assessment.severity.rating"

    def test_benign_rated_high_or_critical_is_a_conflict(self) -> None:
        for rating in ("High", "Critical"):
            violations = assessment_conflict_violations(_empty_bundle(rating))
            assert [v.code for v in violations] == [ASSESSMENT_CONFLICT_CODE], rating

    def test_the_message_names_both_fields_and_asks_for_one_answer(self) -> None:
        message = assessment_conflict_violations(_malware_bundle("Informational"))[0].message

        assert "Malware" in message and "Informational" in message
        assert "x_maljan_assessment.severity.rating" in message
        assert "Reconcile them" in message


class TestWhatIsNotAConflict:
    def test_a_rating_that_matches_the_verdict_passes(self) -> None:
        assert assessment_conflict_violations(_malware_bundle("High")) == []
        assert assessment_conflict_violations(_empty_bundle("Informational")) == []

    def test_a_suspicious_bundle_is_free_to_be_rated_anything(self) -> None:
        """Suspicious is the verdict for an unsettled run, and every rating is
        a defensible reading of one."""
        for rating in ("Critical", "High", "Medium", "Low", "Informational"):
            bundle = Bundle(
                objects=[
                    AttackPattern(
                        id=f"attack-pattern--{'a' * 8}-0000-4000-8000-{'c' * 12}",
                        name="T1055",
                    )
                ],
                x_maljan_assessment=JudgeAssessment(
                    severity=SeverityVerdict(rating=rating, rationale="stated")
                ),
            )
            assert assessment_conflict_violations(bundle) == [], rating

    def test_a_bundle_with_no_assessment_is_left_to_the_other_validator(self) -> None:
        """``verdict.assessment_missing`` already covers that, and two
        violations about one absence is one feedback turn wasted."""
        assert assessment_conflict_violations(Bundle(objects=[])) == []

    def test_a_judge_that_abstained_on_severity_is_not_in_conflict(self) -> None:
        bundle = Bundle(
            objects=[],
            x_maljan_assessment=JudgeAssessment(malware_category="loader", confidence=0.4),
        )
        assert assessment_conflict_violations(bundle) == []


class TestTheJudgeIsAskedOnce:
    def test_the_conflict_earns_a_feedback_turn_and_neither_field_is_rewritten(self) -> None:
        import asyncio
        from unittest.mock import MagicMock

        from maljan.agents.judge_agent import JudgeAgent

        conflicting = (
            '{"type": "bundle", "objects": [{"type": "malware", '
            '"id": "malware--aaaaaaaa-0000-4000-8000-bbbbbbbbbbbb", "name": "loader"}], '
            '"x_maljan_assessment": {"severity": {"rating": "Informational", '
            '"rationale": "no evidence of malicious functionality"}, '
            '"malware_category": "loader", "confidence": 0.6}}'
        )
        answers = [conflicting, conflicting]

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
        assert verdict.fed_back.get(ASSESSMENT_CONFLICT_CODE) == 1
        assert [v.code for v in verdict.violations] == [ASSESSMENT_CONFLICT_CODE]
        rating = verdict.bundle.x_maljan_assessment.severity.rating
        assert rating == "Informational", "the judge's own rating is recorded, never corrected"

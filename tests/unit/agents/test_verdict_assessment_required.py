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


def _examined() -> dict:
    """One analyst with one claim, so the run is not one nobody examined.

    A verdict over an empty bundle and no claims is its own violation
    (``verdict.unsupported_benign``), and this file is about the assessment
    block rather than about that.
    """
    from maljan.schemas.isr_models import AgentISR, ClaimEvidence

    return {
        "static": AgentISR(
            agent_id="static",
            domain="static",
            claims=[
                ClaimEvidence(claim="the binary is packed", evidence_ref="ev_0001", confidence=0.5)
            ],
        )
    }


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
        # Where the parser reads it: a top-level property of the bundle. A
        # block nested inside ``objects`` is discarded by the schema, which is
        # the failure this violation exists to fix.
        assert "top level of the bundle" in message
        assert 'sibling of "objects" and not inside it' in message
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

        # The corrected answer names a malware object as well as the block.
        # A bundle with no objects reads as Benign, and a Benign verdict rated
        # High is a conflict of its own (``verdict.assessment_conflict``) —
        # a second finding this test is not about.
        answers = [
            '{"type": "bundle", "objects": []}',
            (
                '{"type": "bundle", "objects": [{"type": "malware", '
                '"id": "malware--aaaaaaaa-0000-4000-8000-bbbbbbbbbbbb", "name": "loader"}], '
                '"x_maljan_assessment": '
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

        verdict = asyncio.run(
            judge.give_verdict(reports={"static": "nothing"}, history=[], isr_reports=_examined())
        )

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

        verdict = asyncio.run(
            judge.give_verdict(reports={"static": "nothing"}, history=[], isr_reports=_examined())
        )

        assert verdict.retries == 1
        assert [v.code for v in verdict.violations] == [ASSESSMENT_MISSING_CODE]
        assert verdict.bundle.x_maljan_assessment is None


class TestThePromptAndTheFeedbackAgree:
    def test_both_put_the_block_at_the_top_level(self) -> None:
        from maljan.agents.judge_agent import JUDGE_VERDICT_SYSTEM
        from maljan.pipeline.validation import ASSESSMENT_MISSING_MESSAGE

        assert "top-level" in JUDGE_VERDICT_SYSTEM
        assert "top level of the bundle" in ASSESSMENT_MISSING_MESSAGE

    def test_the_prompt_counts_the_fields_it_lists(self) -> None:
        """``confidence`` joined severity, malware_category and family."""
        from maljan.agents.judge_agent import JUDGE_VERDICT_SYSTEM

        assert "Omit any of the four you cannot support" in JUDGE_VERDICT_SYSTEM
        assert "Omit any of the three" not in JUDGE_VERDICT_SYSTEM

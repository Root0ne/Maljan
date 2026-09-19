"""The report's confidence is the judge's, and nobody else's.

Live run 2: one static analyst produced a single claim at 0.50, the dynamic and
network analysts were skipped for want of a sandbox report, and the report's
front page said 0.167 beside a "Malware" verdict — the mean of 0.5, 0 and 0.
Excluding the analysts that never ran fixed the arithmetic and left the wrong
author: the number still belonged to the analysts' own claims and was printed
as the verdict's confidence.

The judge decides the verdict and says how sure it is of it. That number is the
verdict's; when the judge gives none the report says "not assessed", which is a
different fact from zero and from an average of something else.

A number is published only *with* a verdict the judge stated and this pipeline
could read. PuTTY's `1.0` was real and was about the judge's own assessment; the
verdict printed beside it was the object set's, and the two together read as
certainty about a decision the judge had not made.

``mean_claim_confidence`` stays, for the one reader that wants it as what it is:
the analysts' confidence in their own claims.
"""

from __future__ import annotations

from maljan.pipeline.nodes import _overall_confidence, mean_claim_confidence
from maljan.schemas.isr_models import AgentISR, ClaimEvidence
from maljan.schemas.judgement import JudgeAssessment, SeverityVerdict


def _isr(agent: str, *confidences: float) -> AgentISR:
    return AgentISR(
        agent_id=agent,
        domain=agent,
        claims=[
            ClaimEvidence(
                claim="it writes itself into the startup folder",
                evidence_ref="ev_0002",
                confidence=c,
            )
            for c in confidences
        ],
    )


class TestTheAnalystMean:
    def test_a_skipped_analyst_is_excluded_not_counted_as_zero(self) -> None:
        isrs = {
            "static": _isr("static", 0.5),
            "dynamic": _isr("dynamic"),
            "network": _isr("network"),
        }
        assert mean_claim_confidence(isrs) == 0.5

    def test_the_run_that_worked_is_unchanged(self) -> None:
        isrs = {
            "static": _isr("static", 0.95),
            "dynamic": _isr("dynamic", 1.0),
            "network": _isr("network", 1.0),
        }
        assert round(mean_claim_confidence(isrs) or 0.0, 4) == 0.9833

    def test_no_analyst_with_claims_is_no_answer(self) -> None:
        assert mean_claim_confidence({"static": _isr("static")}) is None
        assert mean_claim_confidence({}) is None

    def test_it_reads_a_plain_sequence_too(self) -> None:
        assert mean_claim_confidence([_isr("static", 0.4), _isr("network")]) == 0.4


class TestWhoDecides:
    def test_the_judge_when_it_gave_a_number(self) -> None:
        assessment = JudgeAssessment(
            verdict="Malware",
            severity=SeverityVerdict(rating="High", rationale="it injects"),
            confidence=0.9,
        )
        assert _overall_confidence(assessment) == 0.9

    def test_nothing_when_the_judge_abstained(self) -> None:
        assert (
            _overall_confidence(JudgeAssessment(verdict="Malware", malware_category="loader"))
            is None
        )

    def test_nothing_when_there_is_no_assessment_at_all(self) -> None:
        assert _overall_confidence(None) is None

    def test_nothing_when_the_judge_never_answered(self) -> None:
        assessment = JudgeAssessment(verdict="Malware", confidence=0.9)
        assert _overall_confidence(assessment, judged=False) is None

    def test_nothing_when_the_judge_stated_no_verdict_for_the_number(self) -> None:
        """The verdict is then the object set's fail-safe, and the number is not about it."""
        assert _overall_confidence(JudgeAssessment(confidence=1.0)) is None

    def test_nothing_when_the_word_it_stated_cannot_be_read(self) -> None:
        assert _overall_confidence(JudgeAssessment(verdict="Malicious", confidence=0.95)) is None

    def test_a_judge_confidence_of_zero_is_still_the_judge_speaking(self) -> None:
        assert _overall_confidence(JudgeAssessment(verdict="Benign", confidence=0.0)) == 0.0

    def test_a_confidence_that_is_not_a_number_is_not_assessed(self) -> None:
        class _Odd:
            verdict = "Malware"
            confidence = "very"

        assert _overall_confidence(_Odd()) is None

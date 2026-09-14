"""The report's confidence is the judge's, or the analysts' who had something to say.

Live run 2: one static analyst produced a single claim at 0.50, the dynamic and
network analysts were skipped for want of a sandbox report, and the report's
front page said 0.167 beside a "Malware" verdict — the mean of 0.5, 0 and 0.
An analyst that had nothing to read is not a vote of no confidence, and run 1's
0.98 was only right because all three of its analysts happened to run.

The judge decides the verdict, so the judge's own confidence is the verdict's
confidence. Failing that, the mean over the analysts that produced claims.
Failing that, zero — which says the run reached no confidence rather than
naming one.
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
            severity=SeverityVerdict(rating="High", rationale="it injects"), confidence=0.9
        )
        isrs = {"static": _isr("static", 0.5), "dynamic": _isr("dynamic")}
        assert _overall_confidence(assessment, isrs) == 0.9

    def test_the_analysts_when_the_judge_abstained(self) -> None:
        assessment = JudgeAssessment(malware_category="loader")
        isrs = {"static": _isr("static", 0.5), "dynamic": _isr("dynamic")}
        assert _overall_confidence(assessment, isrs) == 0.5

    def test_the_analysts_when_there_is_no_assessment_at_all(self) -> None:
        assert _overall_confidence(None, {"static": _isr("static", 0.8)}) == 0.8

    def test_zero_when_nobody_answered(self) -> None:
        assert _overall_confidence(None, {"static": _isr("static")}) == 0.0

    def test_a_judge_confidence_of_zero_is_still_the_judge_speaking(self) -> None:
        assessment = JudgeAssessment(confidence=0.0)
        assert _overall_confidence(assessment, {"static": _isr("static", 0.9)}) == 0.0

"""A run nobody performed is not a result.

Two live runs, one shape. A hosted endpoint answered 402 to every call: every
analyst failed, the judge raised, and the job still finished as "completed"
with verdict Suspicious, confidence 0.0, no evidence and an empty error
message. A second run got as far as a judge that emitted no malware object over
a run with no evidence at all, and the bundle heuristic read that as Benign at
0.10 — a false negative with a number on it.

Neither is a degraded analysis. The first has no analysis to report and fails;
the second reports Suspicious and says why.
"""

from __future__ import annotations

from typing import Any

from maljan.pipeline.outcome import (
    INCONCLUSIVE_REASON,
    absent_analysis_message,
    nothing_was_analysed,
    verdict_for_run,
)
from maljan.schemas.isr_models import AgentISR, ClaimEvidence


def _isr(claims: int = 1) -> AgentISR:
    return AgentISR(
        agent_id="static",
        domain="static",
        claims=[
            ClaimEvidence(claim=f"claim {n}", evidence_ref=f"ev_000{n}", confidence=0.5)
            for n in range(claims)
        ],
    )


class TestAnEmptyRunIsNeverBenign:
    def test_no_evidence_and_no_claims_is_inconclusive(self) -> None:
        decision, reason = verdict_for_run("Benign", evidence_entries=[], isr_reports={})

        assert decision == "Suspicious"
        assert reason == INCONCLUSIVE_REASON

    def test_a_claim_is_enough_to_leave_the_verdict_alone(self) -> None:
        """A judge that examined a claim and found nothing malicious meant it."""
        decision, reason = verdict_for_run(
            "Benign", evidence_entries=[], isr_reports={"static": _isr()}
        )

        assert (decision, reason) == ("Benign", "")

    def test_a_tool_call_is_enough_on_its_own(self) -> None:
        decision, reason = verdict_for_run(
            "Benign", evidence_entries=[object()], isr_reports={"static": _isr(claims=0)}
        )

        assert (decision, reason) == ("Benign", "")

    def test_every_other_verdict_passes_through_untouched(self) -> None:
        for verdict in ("Malware", "Suspicious"):
            assert verdict_for_run(verdict, evidence_entries=[], isr_reports={}) == (verdict, "")

    def test_the_two_signals_are_read_together(self) -> None:
        assert nothing_was_analysed([], {}) is True
        assert nothing_was_analysed([], {"static": _isr(claims=0)}) is True
        assert nothing_was_analysed([object()], {}) is False
        assert nothing_was_analysed([], {"static": _isr()}) is False


class TestARunWithNoAnalysisAtAll:
    def _state(self, **fields: Any) -> dict[str, Any]:
        return {
            "reports": {"static": "[ERROR] static analyst failed (APIStatusError)"},
            "isr_reports": {},
            "judge_report": "[ERROR] Judge failed (APIStatusError): Error code: 402 - payment",
            **fields,
        }

    def test_every_analyst_failed_and_the_judge_never_answered(self) -> None:
        message = absent_analysis_message(self._state())

        assert message.startswith("no analysis was produced")
        assert "APIStatusError" in message
        assert "402" in message, "the operator reads the provider's status, not a verdict"

    def test_the_message_carries_none_of_the_providers_body(self) -> None:
        """Only the class and the status: a body can quote back a credential."""
        state = self._state(
            judge_report=(
                "[ERROR] Judge failed (APIStatusError): Error code: 401 - "
                "{'error': {'message': 'invalid api key sk-live-abcdef'}}"
            )
        )

        assert "sk-live-abcdef" not in absent_analysis_message(state)

    def test_one_analyst_that_answered_keeps_the_degraded_path(self) -> None:
        state = self._state(reports={"static": "The sample is packed and resolves imports."})

        assert absent_analysis_message(state) == ""

    def test_a_claim_without_prose_also_keeps_the_degraded_path(self) -> None:
        state = self._state(isr_reports={"static": _isr()})

        assert absent_analysis_message(state) == ""

    def test_a_judge_that_answered_is_an_analysis_however_thin(self) -> None:
        state = self._state(judge_report="Analyzed negotiation history and expert reports.")

        assert absent_analysis_message(state) == ""

    def test_a_revised_report_counts_as_an_answer(self) -> None:
        state = self._state(revised_reports={"static": "Revised: the sample is packed."})

        assert absent_analysis_message(state) == ""


class TestTheWorkerFailsSuchAJob:
    def test_the_absent_run_is_its_own_error_class(self) -> None:
        """The worker raises rather than branching, so the one failure path
        marks the job, records the message and persists no report."""
        from app.worker.analysis_worker import AbsentAnalysisError

        assert issubclass(AbsentAnalysisError, Exception)
        error = AbsentAnalysisError("no analysis was produced: ... (APIStatusError 402)")
        assert f"{type(error).__name__}: {error}".startswith("AbsentAnalysisError: ")


class TestWhatTheReaderIsTold:
    def _inconclusive_report(self) -> Any:
        from maljan.reporting.models import FileHashes, MalwareReport, SampleIdentity

        return MalwareReport(
            identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64), file_type="pe"),
            verdict="Suspicious",
            overall_confidence=0.1,
            degraded_mode=True,
            degradation_reasons=[INCONCLUSIVE_REASON],
        )

    def test_the_deterministic_summary_says_inconclusive_rather_than_classified(self) -> None:
        from maljan.reporting.builder import MalwareReportBuilder

        report = MalwareReportBuilder.apply_fallback_narrative(self._inconclusive_report())

        assert "inconclusive" in report.executive_summary.lower()
        assert "classified as" not in report.executive_summary.lower()

    def test_an_ordinary_run_keeps_the_summary_it_had(self) -> None:
        from maljan.reporting.builder import MalwareReportBuilder
        from maljan.reporting.models import FileHashes, MalwareReport, SampleIdentity

        report = MalwareReportBuilder.apply_fallback_narrative(
            MalwareReport(
                identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64), file_type="pe"),
                verdict="Malware",
                overall_confidence=0.8,
            )
        )

        assert report.executive_summary.startswith("Sample classified as malware")

    def test_the_header_carries_the_reason(self) -> None:
        """The degraded banner is where a reader meets it, not a JSON field."""
        from maljan.reporting.renderers.markdown import MarkdownRenderer

        markdown = MarkdownRenderer().render(self._inconclusive_report())

        assert INCONCLUSIVE_REASON in markdown

    def test_the_judge_is_told_that_an_empty_run_is_not_benign(self) -> None:
        from maljan.agents.judge_agent import JUDGE_VERDICT_SYSTEM

        assert "Benign is a finding, not a default" in JUDGE_VERDICT_SYSTEM
        assert "an empty report is not a clean sample" in JUDGE_VERDICT_SYSTEM

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

import pytest

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

    def test_a_verdict_stage_that_never_ran_is_also_a_non_answer(self) -> None:
        """The question is whether there is a verdict, not whether one failed.

        A verdict stage carrying a ``when`` that declines never enters the
        judge node, so nothing writes the failure string and nothing writes a
        decision — and such a run used to take the ordinary completion path
        and publish a report for an analysis nobody performed.
        """
        state = {"reports": {"static": "[ERROR] static analyst failed"}, "isr_reports": {}}

        message = absent_analysis_message(state)

        assert message.startswith("no analysis was produced")
        assert "no verdict was produced" in message

    def test_a_blank_judge_report_is_a_non_answer_too(self) -> None:
        state = self._state(judge_report="   ")

        assert absent_analysis_message(state).startswith("no analysis was produced")

    def test_a_decision_without_a_judge_report_still_counts_as_an_answer(self) -> None:
        """A verdict is a verdict whichever field of the state carries it."""
        state = self._state(judge_report="", final_decision="Suspicious")

        assert absent_analysis_message(state) == ""

    def test_a_report_stage_that_raised_keeps_its_own_message(self) -> None:
        """That run fails too, through the check that knows what raised."""
        state = self._state(report_error="ValueError: boom")

        assert absent_analysis_message(state) == ""

    def test_a_revised_report_counts_as_an_answer(self) -> None:
        state = self._state(revised_reports={"static": "Revised: the sample is packed."})

        assert absent_analysis_message(state) == ""


class TestTheEvidenceTheVerdictStageCouldNotSee:
    """The evidence-only static provider's passes land after the verdict.

    capa and YARA have no tool loop, so ``report_node`` collects their bundle
    and writes their ledger entries there — after ``verdict_for_run`` has
    already read an empty ledger. The verdict stays where the judge's answer
    put it; the sentence stops claiming nothing was analysed.
    """

    def test_a_run_that_did_record_evidence_gets_the_narrower_sentence(self) -> None:
        from maljan.pipeline.outcome import NO_CLAIMS_REASON, corrected_reasons

        corrected = corrected_reasons([INCONCLUSIVE_REASON, "analyst failures: static"], [object()])

        assert corrected == [NO_CLAIMS_REASON, "analyst failures: static"]

    def test_a_run_with_no_evidence_keeps_the_sentence_it_had(self) -> None:
        from maljan.pipeline.outcome import corrected_reasons

        assert corrected_reasons([INCONCLUSIVE_REASON], []) == [INCONCLUSIVE_REASON]

    def test_the_report_reads_either_sentence_as_inconclusive(self) -> None:
        from maljan.pipeline.outcome import NO_CLAIMS_REASON
        from maljan.reporting.builder import MalwareReportBuilder
        from maljan.reporting.models import FileHashes, MalwareReport, SampleIdentity

        report = MalwareReportBuilder.apply_fallback_narrative(
            MalwareReport(
                identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64), file_type="pe"),
                verdict="Suspicious",
                degraded_mode=True,
                degradation_reasons=[NO_CLAIMS_REASON],
            )
        )

        assert "inconclusive" in report.executive_summary.lower()


class TestTheWorkerFailsSuchAJob:
    def test_the_raise_sits_above_everything_that_persists_a_report(self) -> None:
        """The claim worth pinning is the order.

        A report written before the check would be a published result for a
        run nobody performed, which is the whole finding. Read off the module
        source because exercising ``run_analysis`` needs a database, Redis and
        a sample.
        """
        import inspect

        from app.worker import analysis_worker

        source = inspect.getsource(analysis_worker.run_analysis)
        raised = source.index("raise AbsentAnalysisError")

        assert raised < source.index("from app.models.report import"), (
            "no report model is even imported first"
        )
        assert raised < source.index('"phase_change", {"phase": "reporting"}')
        assert raised < source.index('status="completed"')

    def test_the_failure_path_writes_the_reason_to_the_job_row(self) -> None:
        """Through a session of its own, and as a reason rather than a message.

        The row is written by ``mark_job_failed``, which opens a new session:
        the one the run was writing through is the one a terminated backend
        leaves unusable. What it writes is ``failure_reason`` — the class of
        the exception and the error id — because ``job.error_message`` is
        published on ``JobResponse``.
        """
        import inspect

        from app.worker import analysis_worker

        source = inspect.getsource(analysis_worker.run_analysis)
        handler = source[source.index("\n    except Exception as exc:") :]

        assert "failure_reason(" in handler, "the row carries a reason, not a message"
        assert "mark_job_failed(" in handler, "and it is written on a session of its own"
        assert "db." not in handler.split("finally:")[0], (
            "the failure path must not reach for the run's own session"
        )

    def test_the_reason_carries_the_class_and_the_id_and_nothing_else(self) -> None:
        from app.worker.analysis_worker import AbsentAnalysisError, failure_reason

        assert failure_reason(ValueError("/srv/samples/x.exe is missing"), "abc") == (
            "ValueError (error id abc)"
        )
        # The exceptions whose sentence this module wrote itself.
        absent = AbsentAnalysisError("no analysis was produced: ... (APIStatusError 402)")
        assert failure_reason(absent, "abc").startswith("no analysis was produced")
        assert failure_reason(absent, "abc").endswith("(error id abc)")

    def test_a_sentence_this_module_wrote_reaches_the_operator_whole(self) -> None:
        """The two attached-report refusals are answers, not stack traces."""
        from app.worker.analysis_worker import StatedFailure, failure_reason

        stated = StatedFailure("The attached sandbox report does not belong to this sample.")
        assert failure_reason(stated, "abc") == (
            "The attached sandbox report does not belong to this sample. (error id abc)"
        )

    def test_the_absent_run_is_its_own_error_class(self) -> None:
        """Its own class so the handler above cannot be reached by accident."""
        from app.worker.analysis_worker import AbsentAnalysisError, StatedFailure

        assert issubclass(AbsentAnalysisError, StatedFailure)
        assert issubclass(StatedFailure, Exception)
        error = AbsentAnalysisError("no analysis was produced: ... (APIStatusError 402)")
        assert f"{type(error).__name__}: {error}".startswith("AbsentAnalysisError: ")

    def test_every_worded_refusal_in_the_module_is_a_stated_failure(self) -> None:
        """A sentence raised as a bare exception would be swallowed by its class.

        Read off the source: a ``raise`` whose argument is a sentence — more
        than three words of prose — belongs to the class that keeps sentences,
        or to one of its subclasses. Neither edge of the older form is left:
        it matched the name ``StatedFailure`` literally, so a correct raise of
        ``AbsentAnalysisError`` would have failed it, and it keyed on a
        trailing full stop, so a sentence without one walked past.
        """
        import ast
        import inspect

        from app.worker import analysis_worker
        from app.worker.analysis_worker import StatedFailure

        def keeps_its_message(name: str) -> bool:
            raised = getattr(analysis_worker, name, None)
            return isinstance(raised, type) and issubclass(raised, StatedFailure)

        tree = ast.parse(inspect.getsource(analysis_worker))
        # An exception class's own body is about how it is built, not about how
        # a job ended.
        for node in list(ast.walk(tree)):
            if isinstance(node, ast.ClassDef):
                node.body = []
        inspected: list[str] = []
        worded: list[str] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Raise) or not isinstance(node.exc, ast.Call):
                continue
            if not node.exc.args:
                continue
            first = node.exc.args[0]
            # Only a message written at the raise: a message computed elsewhere
            # — ``RuntimeError(report_error or "…")`` carries a pipeline
            # exception's own words — is exactly what must *not* be promoted
            # into a class that publishes it.
            if not isinstance(first, ast.Constant | ast.JoinedStr):
                continue
            raised = getattr(node.exc.func, "id", "") or getattr(node.exc.func, "attr", "")
            said = " ".join(
                part.value
                for part in ast.walk(first)
                if isinstance(part, ast.Constant) and isinstance(part.value, str)
            ).strip()
            if len(said.split()) <= 3:
                # A word or two is a diagnosis for the log, not a sentence for
                # an operator; those travel as their class name and the id.
                continue
            inspected.append(f"{raised}: {said[:40]}")
            if not keeps_its_message(raised):
                worded.append(f"{raised}: {said[:60]}")
        # A guard that inspected nothing passes for the wrong reason.
        assert inspected, "no worded raise was found in the module at all"
        assert worded == [], worded

    def test_the_guard_sees_a_subclass_and_a_sentence_without_a_full_stop(self) -> None:
        """The two edges the older form of the guard had, pinned.

        Checked against a sample of source rather than by reading the guard
        twice: ``AbsentAnalysisError`` is a correct worded raise and must pass,
        and a bare ``RuntimeError`` with an unpunctuated sentence must not.
        """
        import ast

        from app.worker.analysis_worker import AbsentAnalysisError, StatedFailure

        sample = ast.parse(
            'raise AbsentAnalysisError("no analysis was produced by this run")\n'
            'raise RuntimeError("the configured provider refused every request")\n'
        )
        by_name = {"AbsentAnalysisError": AbsentAnalysisError, "RuntimeError": RuntimeError}
        verdicts = {}
        for node in ast.walk(sample):
            if isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call):
                name = getattr(node.exc.func, "id", "")
                raised = by_name[name]
                verdicts[name] = issubclass(raised, StatedFailure)
        assert verdicts == {"AbsentAnalysisError": True, "RuntimeError": False}


class TestWhatAStatedFailureMaySay:
    """The class publishes its message, so it marks one it cannot vouch for.

    Marked rather than refused: raising here would replace the failure being
    reported with a failure about reporting it, inside whatever ``except``
    built it. The job says the class name in that case, exactly as it does for
    every other exception, and the sentence goes to the log under the error id.
    """

    def test_a_path_is_not_an_authored_sentence(self) -> None:
        from app.worker.analysis_worker import StatedFailure, failure_reason

        stated = StatedFailure("the sample at /srv/maljan/data/samples/aa/sample.exe was refused")
        assert stated.publishable is False
        assert failure_reason(stated, "abc") == "StatedFailure (error id abc)"

    def test_a_secret_shaped_value_is_not_either(self) -> None:
        from app.worker.analysis_worker import StatedFailure, failure_reason
        from tests.credential_shapes import prefixed_key

        secret = prefixed_key("sk-")
        stated = StatedFailure(f"the provider refused the call: api_key={secret}")
        assert stated.publishable is False
        assert secret not in failure_reason(stated, "abc")

    def test_a_drivers_own_words_are_not_promoted_into_one(self) -> None:
        """``StatedFailure(str(exc))`` is the shape the contract exists against."""
        from app.worker.analysis_worker import StatedFailure, failure_reason

        driver_error = OSError("could not open /etc/maljan/credentials.toml")
        stated = StatedFailure(str(driver_error))
        assert stated.publishable is False
        assert "/etc/maljan" not in failure_reason(stated, "abc")

    def test_the_sentence_still_reaches_the_log_under_the_error_id(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        import logging

        from app.worker.analysis_worker import StatedFailure, failure_reason

        stated = StatedFailure("the sample at /srv/maljan/data/samples/aa/sample.exe was refused")
        with caplog.at_level(logging.ERROR):
            failure_reason(stated, "abc123")

        said = " ".join(record.getMessage() for record in caplog.records)
        assert "abc123" in said
        assert "/srv/maljan" in said, "the operator's own log keeps what the API may not"

    def test_the_sentences_this_module_raises_are_accepted(self) -> None:
        from app.worker.analysis_worker import AbsentAnalysisError, StatedFailure

        assert StatedFailure(
            "The attached sandbox report does not belong to this sample."
        ).publishable
        assert StatedFailure(
            "A sandbox report is attached to this job, but the configured "
            "sandbox provider ('mock') cannot accept an uploaded report."
        ).publishable
        assert AbsentAnalysisError(
            "no analysis was produced: every analyst failed and the judge did "
            "not answer (APIStatusError 402)"
        ).publishable

    def test_every_sentence_this_module_raises_is_publishable(self) -> None:
        """The check CI performs so a job never has to.

        Walks each ``raise`` of a ``StatedFailure`` in the module, rebuilds the
        sentence as it is written — an f-string's placeholders stand in for the
        values they interpolate — and asserts the publisher's scrubber would
        leave it alone. A worded refusal added later with a path in it fails
        here rather than in somebody's run.
        """
        import ast
        import inspect

        from app.worker import analysis_worker
        from app.worker.analysis_worker import StatedFailure, is_publishable

        def written(node: ast.expr) -> str:
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                return node.value
            if isinstance(node, ast.JoinedStr):
                # ``{provider!r}`` stands for whatever it interpolates; what is
                # under test is the sentence around it.
                return "".join(
                    part.value if isinstance(part, ast.Constant) else "'placeholder'"
                    for part in node.values
                )
            return ""

        source = inspect.getsource(analysis_worker)
        checked: list[str] = []
        for node in ast.walk(ast.parse(source)):
            if not isinstance(node, ast.Raise) or not isinstance(node.exc, ast.Call):
                continue
            name = getattr(node.exc.func, "id", "")
            raised = getattr(analysis_worker, name, None)
            if not (isinstance(raised, type) and issubclass(raised, StatedFailure)):
                continue
            if not node.exc.args:
                continue
            sentence = written(node.exc.args[0])
            if not sentence:
                # Not written at the raise — ``AbsentAnalysisError(absent)``
                # carries a sentence ``pipeline.outcome`` composed, which its
                # own tests cover.
                continue
            checked.append(sentence)
            assert is_publishable(sentence), sentence
        assert checked, "no worded StatedFailure was found to check"


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

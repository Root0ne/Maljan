"""A verdict nothing decided carries no confidence.

When the judge's body raises, the pipeline writes a conservative "Suspicious"
verdict of its own so a run — or a whole batch evaluation — is not lost. That
part is right. What was wrong is what the report then said about it: with no
judge assessment to read, the confidence fell through to the mean of the
analysts' confidence in their *own claims* (0.92 on the run that prompted
this), and the front page printed that number beside a decision none of them
made. The comment at the failure site still claimed the report node capped it,
which it has not done since the cap was removed.

Three things hold now. The judge node records that it fell back, and with what
class of failure. The report carries ``overall_confidence`` ``None`` for such a
run and says on its front page that no confidence was assessed. And the run
summary carries the note under ``verdict.fallback``, the code the judge agent
already uses when its answer was not the verdict it was asked for.

The same answer covers the judge that did answer and put no number on what it
said: there is one author of a verdict's confidence, and when that author
abstains the report says so rather than borrowing a number from somebody else.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock

from maljan.core.token_ledger import TokenLedger
from maljan.core.truncation_ledger import TruncationLedger
from maljan.pipeline.nodes import _overall_confidence, make_judge_node, with_verdict_fallback
from maljan.schemas.evidence import EvidenceCounter
from maljan.schemas.isr_models import AgentISR, ClaimEvidence
from tests.stages import paper_profile
from tests.unit.pipeline.test_evidence_ledger_channel import _JudgeContainer


class _Container(_JudgeContainer):
    def server_degradation_reasons(self) -> list[str]:
        return []

    def server_rests(self) -> list[dict]:
        return []

    def active_profile(self) -> Any:
        return paper_profile(["static"])

    def get_token_ledger(self) -> TokenLedger:
        return TokenLedger()

    def get_truncation_ledger(self) -> TruncationLedger:
        return TruncationLedger()


def _confident_analysts() -> dict[str, AgentISR]:
    """Analysts that are very sure of their own claims, which is not a verdict."""
    claim = ClaimEvidence(
        claim="Allocates and writes memory in a remote process",
        evidence_ref="[ev_0001] capa: inject code",
        confidence=0.92,
        technique_id="T1055",
    )
    return {"static": AgentISR(agent_id="static", domain="static", claims=[claim])}


def _state() -> dict[str, Any]:
    return {
        "iteration_count": 1,
        "reports": {"static": "static findings"},
        "isr_reports": _confident_analysts(),
        "evidence_ledger": [],
        "sandbox_report": {"signatures": []},
        "sample_path": None,
        "triage_facts": {"degradation_reasons": []},
        "validation_findings": {},
        "validation_not_run": [],
    }


def _judge_that_raises() -> dict[str, Any]:
    container = _Container(EvidenceCounter())
    judge = container.get_judge_agent(role="judge")
    judge.give_verdict = AsyncMock(side_effect=TimeoutError("waited 1800s for 127.0.0.1:8080"))
    return asyncio.run(make_judge_node(container)(_state()))


class TestTheJudgeNodeRecordsThatItFellBack:
    def test_the_fallback_names_the_class_of_the_failure(self) -> None:
        update = _judge_that_raises()

        assert update["final_decision"] == "Suspicious"
        fallback = update["verdict_fallback"]
        assert fallback["decision"] == "Suspicious"
        assert "TimeoutError" in fallback["failure"]

    def test_the_failure_travels_without_its_message(self) -> None:
        """The host and port in the exception's text reach the log, not a reader."""
        update = _judge_that_raises()

        assert "127.0.0.1" not in update["verdict_fallback"]["failure"]
        assert "127.0.0.1" not in update["judge_report"]

    def test_the_run_is_degraded(self) -> None:
        update = _judge_that_raises()

        assert update["degraded_mode"] is True
        assert any("judge failed" in reason for reason in update["degradation_reasons"])


class TestAJudgeThatAnsweredClearsTheChannel:
    def test_the_judged_path_writes_the_channel_empty(self) -> None:
        """A channel only ever set would suppress the next run's confidence.

        The verdict stage runs once today, so nothing reads a stale value —
        which is exactly why it is worth writing now rather than after a
        retry is added.
        """
        from unittest.mock import AsyncMock

        from maljan.agents.judge_agent import JudgeVerdict
        from maljan.schemas.stix_models import Bundle

        container = _Container(EvidenceCounter())
        judge = container.get_judge_agent(role="judge")
        judge.give_verdict = AsyncMock(
            return_value=JudgeVerdict(
                bundle=Bundle(objects=[]), violations=[], retries=0, fed_back={}
            )
        )
        update = asyncio.run(make_judge_node(container)(_state()))

        assert update["verdict_fallback"] is None


class TestNothingDerivesAConfidenceForIt:
    def test_an_unjudged_verdict_has_none(self) -> None:
        assert _overall_confidence(None, judged=False) is None

    def test_a_judge_that_answered_without_a_number_gives_none_either(self) -> None:
        """The analysts' mean is not a second answer, on any path.

        It belongs to their own claims — 0.92 on the run that prompted this —
        and a verdict none of them reached is not something they were 92% sure
        of.
        """
        assert _overall_confidence(None, judged=True) is None


class TestTheSummaryCarriesTheNote:
    def test_the_note_is_filed_under_verdict_fallback(self) -> None:
        block = with_verdict_fallback(None, "TimeoutError")

        assert block["by_code"]["verdict.fallback"] == 1
        row = block["unresolved"][0]
        assert row["code"] == "verdict.fallback"
        assert "TimeoutError" in row["message"]
        assert "did not answer" in row["message"]

    def test_it_is_added_to_what_the_run_was_already_told(self) -> None:
        existing = {
            "retries": 2,
            "by_code": {"attck.unknown_id": 1},
            "unresolved": [{"agent": "static", "code": "attck.unknown_id", "message": "no id"}],
            "not_run": ["attck.unknown_id"],
        }
        block = with_verdict_fallback(existing, "ConnectionError")

        assert block["retries"] == 2
        assert block["by_code"] == {"attck.unknown_id": 1, "verdict.fallback": 1}
        assert [row["code"] for row in block["unresolved"]] == [
            "attck.unknown_id",
            "verdict.fallback",
        ]
        assert block["not_run"] == ["attck.unknown_id"]
        # The caller's own dict is not the one that was changed.
        assert "verdict.fallback" not in existing["by_code"]


def _report_container() -> Any:
    from unittest.mock import MagicMock

    from maljan.pipeline.validation import ValidationTally

    container = MagicMock()
    # The report round's own tally is merged into the summary's validation
    # block, so it has to be a real one: a mock's ``retries`` would turn the
    # count this asserts on into a mock and hide whatever it is worth.
    container.get_narrative_agent.return_value.validation_tally = ValidationTally()
    container.get_report_composer.return_value.validation_tally = ValidationTally()
    container.is_mock = True
    container.config.reporting.enabled = True
    container.config.llm.parallel_analysts = True
    container.config.negotiation.max_iterations = 3
    container.analyst_keys.return_value = ["static"]
    container.agent_role.side_effect = lambda name: name
    container.active_profile.return_value = paper_profile(["static"])
    return container


def _report_state(fallback: dict[str, Any] | None) -> dict[str, Any]:
    state = _state()
    state.update(
        {
            "file_hash": "deadbeef",
            "file_name": "sample.exe",
            "platform": "windows",
            "file_type": "pe",
            "final_decision": "Suspicious",
            "stix_output": {},
            "run_summary": None,
            "degraded_mode": True,
            "degradation_reasons": ["judge failed (TimeoutError)"],
            "verdict_fallback": fallback,
            "discussion_history": [],
        }
    )
    return state


def _run_report(fallback: dict[str, Any] | None) -> dict[str, Any]:
    from maljan.pipeline.nodes import make_report_node

    update = asyncio.run(make_report_node(_report_container())(_report_state(fallback)))
    assert update.get("report_error") is None
    return update


def _reported(fallback: dict[str, Any] | None) -> tuple[dict[str, Any], str]:
    update = _run_report(fallback)
    return update["malware_report"], update["malware_report_markdown"]


class TestTheReportSaysTheJudgeDidNotAnswer:
    def test_the_confidence_is_none_and_the_header_says_so(self) -> None:
        report, markdown = _reported({"decision": "Suspicious", "failure": "TimeoutError"})

        assert report["overall_confidence"] is None
        assert "(not assessed) · **Severity:**" in markdown
        assert "NO CONFIDENCE ASSESSED" in markdown
        # The number that used to be printed here belongs to the analysts'
        # claims, and it is still on the record where it means something.
        assert "0.92" not in markdown.split("## ")[0]

    def test_the_stored_summary_carries_the_note(self) -> None:
        """The state channel, which is the summary the API stores and serves.

        The report's own copy travels inside ``malware_report``; the column the
        SUMMARY tab's Run record reads is ``analysis_reports.run_summary``, and
        the worker fills that from ``result["run_summary"]``. Asserting on the
        report's copy alone left the stored one silent: an operator whose judge
        raised read "No producer needed a correction turn."
        """
        update = _run_report({"decision": "Suspicious", "failure": "TimeoutError"})

        for where, summary in (
            ("the stored summary", update["run_summary"]),
            ("the report's own copy", update["malware_report"]["run_summary"]),
        ):
            validation = summary["validation"]
            assert validation["by_code"]["verdict.fallback"] == 1, where
            assert validation["retries"] == 0, where
            row = validation["unresolved"][0]
            assert row["agent"] == "judge", where
            assert "TimeoutError" in row["message"], where

    def test_a_judged_run_stores_no_note_and_no_empty_block(self) -> None:
        """The amendment writes only what it changed, so the column is untouched."""
        update = _run_report(None)

        assert "validation" not in (update.get("run_summary") or {})

    def test_a_run_whose_judge_answered_says_nothing_about_a_fallback(self) -> None:
        """This judge answered and assessed no confidence, so there is none to print.

        The analysts' 0.92 used to fill the gap. It is the confidence they put
        on their own claims and it is still on the record where it means that;
        the front page of a verdict nobody put a number on says so instead.
        """
        report, markdown = _reported(None)

        assert report["overall_confidence"] is None
        assert "(not assessed) · **Severity:**" in markdown
        assert "NO CONFIDENCE ASSESSED" in markdown
        assert "verdict.fallback" not in str(report["run_summary"].get("validation") or {})


class TestAJudgeThatAnsweredWithNoVerdict:
    """The same rule for a judge that answered with text, or not at all.

    Its body did not raise, so nothing wrote the fallback channel — and the
    verdict the pipeline then reported carried the analysts' confidence in
    their own claims, exactly as a judge that raised used to.
    """

    @staticmethod
    def _extracted_verdict() -> dict[str, Any]:
        """A judge that answered JSON that was not a bundle.

        Nothing is wrong with the answer's syntax, so no code says "fallback"
        on its own; the bundle the pipeline built out of the text is what says
        so, and that is what the node has to read. Keyed off the codes instead,
        the report printed the analysts' own confidence beside a verdict no
        judge expressed.
        """
        from unittest.mock import AsyncMock

        from maljan.agents.judge_agent import JudgeVerdict
        from maljan.schemas.stix_models import Bundle

        container = _Container(EvidenceCounter())
        judge = container.get_judge_agent(role="judge")
        judge.give_verdict = AsyncMock(
            return_value=JudgeVerdict(
                bundle=Bundle.model_validate(
                    {
                        "objects": [],
                        "x_maljan_fallback_verdict": {
                            "decision": "Suspicious",
                            "source": "extracted",
                        },
                    }
                ),
                violations=[],
                retries=0,
                fed_back={},
            )
        )
        return asyncio.run(make_judge_node(container)(_state()))

    def test_a_verdict_extracted_from_text_is_a_fallback_too(self) -> None:
        update = self._extracted_verdict()

        fallback = update["verdict_fallback"]
        assert fallback["decision"] == "Suspicious"
        assert fallback["failure"] == "verdict.fallback"

    def test_whether_the_judge_recorded_it_is_read_from_what_it_recorded(self) -> None:
        """This judge recorded nothing, so the report node writes the note.

        Hard-coded, the flag said the row was already there and the summary
        ended up with nothing to say about a verdict no judge expressed.
        """
        update = self._extracted_verdict()

        assert update["verdict_fallback"]["recorded"] is False

    def test_and_then_the_summary_carries_it(self) -> None:
        update = _run_report(
            {"decision": "Suspicious", "failure": "verdict.fallback", "recorded": False}
        )

        validation = update["run_summary"]["validation"]
        assert validation["by_code"]["verdict.fallback"] == 1

    def test_the_report_gives_it_no_confidence(self) -> None:
        report, markdown = _reported(
            {"decision": "Suspicious", "failure": "verdict.fallback", "recorded": True}
        )

        assert report["overall_confidence"] is None
        assert "0.92" not in markdown.split("## ")[0]

    @staticmethod
    def _timed_out_verdict(claims: bool) -> dict[str, Any]:
        from unittest.mock import AsyncMock

        from maljan.agents.judge_agent import (
            VERDICT_TIMEOUT_CODE,
            VERDICT_TIMEOUT_REASON,
            JudgeVerdict,
        )
        from maljan.pipeline.validation import Violation
        from maljan.schemas.stix_models import Bundle

        container = _Container(EvidenceCounter())
        judge = container.get_judge_agent(role="judge")
        bundle = Bundle.model_validate(
            {
                "objects": [],
                "x_maljan_fallback_verdict": {"decision": "Suspicious", "source": "pipeline"},
            }
        )
        judge.give_verdict = AsyncMock(
            return_value=JudgeVerdict(
                bundle=bundle,
                violations=[Violation(code=VERDICT_TIMEOUT_CODE, message=VERDICT_TIMEOUT_REASON)],
                retries=0,
                fed_back={},
            )
        )
        state = _state()
        if not claims:
            state["isr_reports"] = {
                "static": AgentISR(agent_id="static", domain="static", claims=[])
            }
            state["reports"] = {"static": "Nothing was established."}
        return asyncio.run(make_judge_node(container)(state))

    def test_a_silent_run_whose_judge_timed_out_is_not_malware(self) -> None:
        """The audit's case: signed, reputation-clean, no claim, no technique."""
        update = self._timed_out_verdict(claims=False)

        assert update["final_decision"] != "Malware"
        assert update["final_decision"] == "Suspicious"

    def test_the_fallback_channel_is_written(self) -> None:
        update = self._timed_out_verdict(claims=True)

        fallback = update["verdict_fallback"]
        assert fallback["decision"] == "Suspicious"
        assert fallback["failure"] == "verdict.timeout"
        assert fallback["recorded"] is True

    def test_the_summary_carries_the_timeout_once(self) -> None:
        update = self._timed_out_verdict(claims=True)

        validation = update["run_summary"]["validation"]
        codes = [row["code"] for row in validation["unresolved"]]
        assert codes.count("verdict.timeout") == 1
        assert "verdict.fallback" not in codes

    def test_the_report_carries_no_confidence_for_it(self) -> None:
        report, markdown = _reported(
            {"decision": "Suspicious", "failure": "verdict.timeout", "recorded": True}
        )

        assert report["overall_confidence"] is None
        assert "NO CONFIDENCE ASSESSED" in markdown

    def test_the_note_the_judge_already_recorded_is_not_written_again(self) -> None:
        update = _run_report(
            {"decision": "Suspicious", "failure": "verdict.timeout", "recorded": True}
        )

        assert "validation" not in (update.get("run_summary") or {})

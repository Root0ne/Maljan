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
run and says the judge did not answer. And the run summary carries the note
under ``verdict.fallback``, the code the judge agent already uses when its
answer was not the verdict it was asked for.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock

import pytest

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


class TestNothingDerivesAConfidenceForIt:
    def test_an_unjudged_verdict_has_none(self) -> None:
        assert _overall_confidence(None, _confident_analysts(), judged=False) is None

    def test_a_judged_run_still_falls_back_to_the_analysts(self) -> None:
        """The behaviour for a judge that answered without a confidence is unchanged."""
        assert _overall_confidence(None, _confident_analysts(), judged=True) == pytest.approx(0.92)


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

    container = MagicMock()
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


def _reported(fallback: dict[str, Any] | None) -> tuple[dict[str, Any], str]:
    from maljan.pipeline.nodes import make_report_node

    update = asyncio.run(make_report_node(_report_container())(_report_state(fallback)))
    assert update.get("report_error") is None
    return update["malware_report"], update["malware_report_markdown"]


class TestTheReportSaysTheJudgeDidNotAnswer:
    def test_the_confidence_is_none_and_the_header_says_so(self) -> None:
        report, markdown = _reported({"decision": "Suspicious", "failure": "TimeoutError"})

        assert report["overall_confidence"] is None
        assert "**Overall Confidence**: not assessed" in markdown
        assert "The judge did not answer" in markdown
        # The number that used to be printed here belongs to the analysts'
        # claims, and it is still on the record where it means something.
        assert "0.92" not in markdown.split("## ")[0]

    def test_the_stored_summary_carries_the_note(self) -> None:
        report, _ = _reported({"decision": "Suspicious", "failure": "TimeoutError"})

        validation = report["run_summary"]["validation"]
        assert validation["by_code"]["verdict.fallback"] == 1
        assert validation["unresolved"][0]["agent"] == "judge"

    def test_a_run_whose_judge_answered_is_untouched(self) -> None:
        report, markdown = _reported(None)

        assert report["overall_confidence"] == pytest.approx(0.92)
        assert "**Overall Confidence**: 0.92" in markdown
        assert "The judge did not answer" not in markdown
        assert "verdict.fallback" not in str(report["run_summary"].get("validation") or {})

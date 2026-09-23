"""No consensus is recorded among analysts who said nothing.

A run whose static analyst timed out and whose two others were skipped went to
the mediator with nothing to compare. The mediator wrote "no analyst provided a
substantive report … agreement_confidence: 1.0", and the run recorded
"Consensus reached (confidence=1.00)", a termination reason of `consensus` and
a final confidence of 1.000 — agreement among nobody. With fewer than two
analysts that produced claims, consensus is not applicable: the mediator still
speaks, and no agreement value is recorded anywhere, neither 1.0 nor 0.0.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from langchain_core.messages import AIMessage
from langchain_core.runnables import RunnableLambda

from maljan.agents.judge_agent import JudgeAgent
from maljan.analysis.run_summary import RunSummaryBuilder
from maljan.pipeline.mediation_models import MediatorVerdict
from maljan.pipeline.nodes import make_negotiation_node
from maljan.pipeline.routing import ConsensusRouter
from maljan.pipeline.state import AgentArgument
from maljan.schemas.isr_models import AgentISR, ClaimEvidence

SAID_BY_THE_MEDIATOR = (
    "- no input from static analyst\n- no input from dynamic analyst\n"
    "No analyst provided a substantive report.\nagreement_confidence: 1.0"
)


def _isr(name: str, claims: int) -> AgentISR:
    return AgentISR(
        agent_id=name,
        domain=name,
        claims=[
            ClaimEvidence(
                claim=f"claim {i}", evidence_ref=f"[ev_000{i + 1}] imports", confidence=0.7
            )
            for i in range(claims)
        ],
    )


class _Model:
    """A model that says what the mediator said on the run, in both shapes."""

    async def ainvoke(self, _messages: Any, **_kw: Any) -> AIMessage:
        return AIMessage(content=SAID_BY_THE_MEDIATOR)

    def with_structured_output(self, _schema: Any) -> Any:
        return RunnableLambda(
            lambda _in: MediatorVerdict(
                contradictions=[], resolution_summary="all agree", confidence=1.0
            )
        )


def _mediate(reports: dict[str, str], isrs: dict[str, AgentISR], *, structured: bool):
    judge = JudgeAgent(llm=_Model())  # type: ignore[arg-type]
    with patch.object(judge, "_supports_structured_output", return_value=structured):
        return asyncio.run(judge.mediate(reports, [], isr_reports=isrs))


@pytest.mark.parametrize("structured", [True, False], ids=["model", "fallback"])
class TestTheMediatorRecordsNoAgreement:
    def test_nobody_produced_a_claim(self, structured: bool) -> None:
        argument, is_consensus = _mediate(
            {"static": "[ERROR] timed out", "dynamic": ""},
            {"static": _isr("static", 0), "dynamic": _isr("dynamic", 0)},
            structured=structured,
        )

        assert is_consensus is None
        assert argument.confidence_score is None
        assert "Confidence:" not in argument.finding
        # The mediator's own words stay whole; the platform's sentence is apart.
        assert argument.finding == SAID_BY_THE_MEDIATOR
        assert "Consensus: not applicable" not in argument.finding
        assert argument.note == "Consensus: not applicable — 0 of 2 analyst(s) produced claims."

    def test_one_analyst_produced_claims(self, structured: bool) -> None:
        argument, is_consensus = _mediate(
            {"static": "found things", "dynamic": ""},
            {"static": _isr("static", 3), "dynamic": _isr("dynamic", 0)},
            structured=structured,
        )

        assert is_consensus is None
        assert argument.confidence_score is None

    def test_two_analysts_that_produced_claims_are_measured(self, structured: bool) -> None:
        argument, is_consensus = _mediate(
            {"static": "found things", "dynamic": "saw things"},
            {"static": _isr("static", 2), "dynamic": _isr("dynamic", 1)},
            structured=structured,
        )

        assert is_consensus is True
        assert argument.confidence_score == 1.0


def _container(mediated: tuple[AgentArgument, bool | None] | BaseException) -> Any:
    container = MagicMock()
    container.is_mock = False
    container.agent_registry.list_agents.return_value = ["static", "dynamic"]
    container.analyst_keys.return_value = ["static", "dynamic"]
    judge = MagicMock()
    if isinstance(mediated, BaseException):
        judge.mediate = AsyncMock(side_effect=mediated)
    else:
        judge.mediate = AsyncMock(return_value=mediated)
    container.get_judge_agent.return_value = judge
    return container


SILENT_STATE: dict[str, Any] = {
    "iteration_count": 0,
    "reports": {"static": "[ERROR] timed out", "dynamic": ""},
    "isr_reports": {"static": _isr("static", 0), "dynamic": _isr("dynamic", 0)},
}


class TestTheNegotiationRecordsNothing:
    def test_the_round_appends_no_confidence(self) -> None:
        argument = AgentArgument(agent_name="Mediator", finding="nothing", confidence_score=None)
        result = asyncio.run(make_negotiation_node(_container((argument, None)))(SILENT_STATE))

        assert result["consensus_applicable"] is False
        assert result["is_consensus"] is None
        assert result["confidence_history"] == []

    def test_a_failed_mediation_among_the_silent_records_no_zero(self) -> None:
        result = asyncio.run(
            make_negotiation_node(_container(RuntimeError("went away")))(SILENT_STATE)
        )

        assert result["consensus_applicable"] is False
        assert result["is_consensus"] is None
        assert result["confidence_history"] == []
        assert result["discussion_history"][0].status == "failed"

    def test_the_mock_mediator_records_nothing_either(self) -> None:
        container = _container((AgentArgument(agent_name="Mediator", finding="x"), True))
        container.is_mock = True

        result = asyncio.run(make_negotiation_node(container)(SILENT_STATE))

        assert result["consensus_applicable"] is False
        assert result["is_consensus"] is None
        assert result["confidence_history"] == []

    def test_two_analysts_that_produced_claims_are_still_measured(self) -> None:
        argument = AgentArgument(agent_name="Mediator", finding="agree", confidence_score=0.9)
        state = {
            **SILENT_STATE,
            "isr_reports": {"static": _isr("static", 2), "dynamic": _isr("dynamic", 1)},
        }
        with patch("maljan.pipeline.nodes.detect_sycophancy", return_value=False):
            result = asyncio.run(make_negotiation_node(_container((argument, True)))(state))

        assert result["consensus_applicable"] is True
        assert result["is_consensus"] is True
        assert result["confidence_history"] == [pytest.approx(0.7)]

    def test_the_router_hands_the_analysts_to_the_judge(self) -> None:
        from maljan.core.config import Settings

        state = {
            "iteration_count": 1,
            "is_consensus": None,
            "consensus_applicable": False,
            "confidence_history": [],
            "discussion_history": [AgentArgument(agent_name="Mediator", finding="nothing")],
        }

        assert ConsensusRouter(Settings()).should_continue(state) == "judge"


def _summary() -> Any:
    return (
        RunSummaryBuilder(start_time=0.0)
        .set_negotiation(
            {
                "iteration_count": 1,
                "is_consensus": None,
                "consensus_applicable": False,
                "confidence_history": [],
                "discussion_history": [],
            },
            max_iterations=3,
        )
        .build()
    )


class TestNoSurfacePrintsAnAgreement:
    def test_the_run_summary_has_no_final_confidence(self) -> None:
        negotiation = _summary().to_dict()["negotiation"]

        assert negotiation["termination_reason"] == "not_applicable"
        assert "final_confidence" not in negotiation
        assert "converged_early" not in negotiation
        assert negotiation["confidence_history"] == []

    def test_the_run_summary_markdown_says_not_applicable(self) -> None:
        text = _summary().to_markdown()

        assert "Final confidence" not in text
        assert "not applicable" in text

    def test_the_report_prints_no_final_confidence(self) -> None:
        text = _appendix_text(_summary().to_dict())

        assert "Final confidence" not in text
        assert "`consensus`" not in text
        assert "not applicable" in text

    def test_the_verdict_section_states_no_agreement(self) -> None:
        from maljan.reporting.models import MalwareReport
        from maljan.reporting.renderers.markdown import MarkdownRenderer

        report = MalwareReport.model_validate(
            {"identity": {"hashes": {"sha256": "0" * 64}}, "run_summary": _summary().to_dict()}
        )
        text = MarkdownRenderer().render(report)
        agreement = [line for line in text.splitlines() if "**Analyst agreement:**" in line]

        assert len(agreement) == 1
        assert "not applicable" in agreement[0]
        assert "not_applicable" not in agreement[0]
        assert "consensus after" not in agreement[0]

    def test_the_report_s_negotiation_block_does_not_borrow_the_verdict_s_confidence(
        self,
    ) -> None:
        from maljan.reporting.builder import MalwareReportBuilder

        negotiation = _summary().to_dict()["negotiation"]
        summary = MalwareReportBuilder._negotiation_summary({"negotiation": negotiation}, 0.85)

        assert "final_confidence" not in summary
        assert summary["termination_reason"] == "not_applicable"


def _appendix_text(run_summary: dict) -> str:
    """The report's run-summary appendix for a report carrying ``run_summary``."""
    from maljan.reporting.models import MalwareReport
    from maljan.reporting.renderers.markdown import MarkdownRenderer

    report = MalwareReport.model_validate(
        {"identity": {"hashes": {"sha256": "0" * 64}}, "run_summary": run_summary}
    )
    return MarkdownRenderer()._appendix_run(report)

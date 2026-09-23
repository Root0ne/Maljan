"""Fault-isolation contract for the mediator negotiation node.

Live trace 2026-06-04 (Ghidra+LLM static-only validation on a local 35B): the
judge's ReAct tool loop re-raises a bare ``asyncio.TimeoutError``, and under
concurrent analyst load the openai client can raise a transient
``APIConnectionError``. Either one used to escape the negotiation node's
``except (AnalystError, LLMError)`` clause and abort the whole LangGraph run —
which, in a batch eval, silently drops the entire sample. The node now isolates
*any* mediation failure: it degrades to "no consensus" and carries the current
ISRs forward so the run still returns a scoreable result.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from maljan.pipeline.nodes import make_negotiation_node
from maljan.schemas.isr_models import AgentISR, ClaimEvidence


def _claiming(name: str) -> AgentISR:
    return AgentISR(
        agent_id=name,
        domain=name,
        claims=[ClaimEvidence(claim="c", evidence_ref="[ev_0001] x", confidence=0.6)],
    )


def _container_with_failing_judge(exc: BaseException) -> Any:
    """ServiceContainer stub whose mediate() raises ``exc``."""
    container = MagicMock()
    container.is_mock = False
    container.agent_registry.list_agents.return_value = ["static", "dynamic"]
    container.analyst_keys.return_value = ["static", "dynamic"]
    judge = MagicMock()
    judge.mediate = AsyncMock(side_effect=exc)
    container.get_judge_agent.return_value = judge
    return container


def _run_node(container: Any) -> dict[str, Any]:
    node_fn = make_negotiation_node(container)
    # Two analysts that produced claims, so consensus applies and a failed
    # round is a "no consensus"; the sycophancy detector is held dormant so the
    # test exercises only the mediation try/except path.
    state = {
        "iteration_count": 1,
        "reports": {"static": "finding", "dynamic": "finding"},
        "isr_reports": {"static": _claiming("static"), "dynamic": _claiming("dynamic")},
    }
    with patch("maljan.pipeline.nodes.detect_sycophancy", return_value=False):
        return asyncio.run(node_fn(state))


@pytest.mark.parametrize(
    "exc",
    [
        TimeoutError(),  # bare asyncio timeout re-raised by execute_tool_loop
        RuntimeError("Connection error."),  # stands in for openai APIConnectionError
        ValueError("unexpected mediator bug"),  # any other failure
    ],
)
def test_negotiation_isolates_mediation_failure(exc: BaseException) -> None:
    """A failed mediation round degrades gracefully instead of propagating."""
    result = _run_node(_container_with_failing_judge(exc))

    # No agreement was measured: consensus is neither reached nor refused,
    # and no number stands in for the one the mediator never stated.
    assert result["is_consensus"] is None
    assert result["iteration_count"] == 2  # iteration advanced, loop not aborted
    assert result["confidence_history"] == []
    argument = result["discussion_history"][0]
    assert argument.finding.startswith("[ERROR] Mediation")
    assert argument.confidence_score is None
    assert argument.status in ("failed", "timeout")


def test_a_failed_mediation_publishes_no_agreement_anywhere() -> None:
    """The run summary, the report projection and the router read the failure, not a 0.0."""
    from maljan.analysis.run_summary import MEDIATION_FAILED, RunSummaryBuilder
    from maljan.pipeline.routing import ConsensusRouter
    from maljan.reporting.builder import MalwareReportBuilder

    result = _run_node(_container_with_failing_judge(RuntimeError("Connection error.")))
    state = {**result, "consensus_applicable": result.get("consensus_applicable", True)}

    summary = (
        RunSummaryBuilder(start_time=0.0).set_negotiation(state, max_iterations=3).build().to_dict()
    )
    negotiation = summary["negotiation"]
    assert negotiation["termination_reason"] == MEDIATION_FAILED
    assert "final_confidence" not in negotiation
    assert negotiation["confidence_history"] == []

    projected = MalwareReportBuilder._negotiation_summary(summary, overall_confidence=0.9)
    assert "final_confidence" not in projected
    assert projected["termination_reason"] == MEDIATION_FAILED

    from maljan.core.config import get_settings

    assert ConsensusRouter(get_settings()).should_continue(state) == "judge"


def test_negotiation_labels_timeout_distinctly() -> None:
    """TimeoutError is reported as 'timed out' (operator-facing diagnostics)."""
    result = _run_node(_container_with_failing_judge(TimeoutError()))
    assert "timed out" in result["discussion_history"][0].finding


def test_negotiation_success_path_unaffected() -> None:
    """A successful mediation still returns consensus + the judge's argument."""
    from maljan.pipeline.state import AgentArgument

    container = MagicMock()
    container.is_mock = False
    container.agent_registry.list_agents.return_value = ["static", "dynamic"]
    container.analyst_keys.return_value = ["static", "dynamic"]
    judge = MagicMock()
    arg = AgentArgument(agent_name="Mediator", finding="all agree", confidence_score=0.9)
    judge.mediate = AsyncMock(return_value=(arg, True))
    container.get_judge_agent.return_value = judge

    result = _run_node(container)
    assert result["is_consensus"] is True
    assert result["discussion_history"][0].finding == "all agree"

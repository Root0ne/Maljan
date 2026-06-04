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
from unittest.mock import AsyncMock, MagicMock

import pytest

from maljan.pipeline.nodes import make_negotiation_node


def _container_with_failing_judge(exc: BaseException) -> Any:
    """ServiceContainer stub whose mediate() raises ``exc``."""
    container = MagicMock()
    container.is_mock = False
    container.agent_registry.list_agents.return_value = ["static"]
    judge = MagicMock()
    judge.mediate = AsyncMock(side_effect=exc)
    container.get_judge_agent.return_value = judge
    return container


def _run_node(container: Any) -> dict[str, Any]:
    node_fn = make_negotiation_node(container)
    # iteration>=1 + empty isr_reports keeps the sycophancy detector dormant so
    # the test exercises only the mediation try/except path.
    state = {"iteration_count": 1, "reports": {"static": "finding"}, "isr_reports": {}}
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

    assert result["is_consensus"] is False
    assert result["iteration_count"] == 2  # iteration advanced, loop not aborted
    assert result["confidence_history"] == [0.0]
    finding = result["discussion_history"][0].finding
    assert finding.startswith("[ERROR] Mediation")


def test_negotiation_labels_timeout_distinctly() -> None:
    """TimeoutError is reported as 'timed out' (operator-facing diagnostics)."""
    result = _run_node(_container_with_failing_judge(TimeoutError()))
    assert "timed out" in result["discussion_history"][0].finding


def test_negotiation_success_path_unaffected() -> None:
    """A successful mediation still returns consensus + the judge's argument."""
    from maljan.pipeline.state import AgentArgument

    container = MagicMock()
    container.is_mock = False
    container.agent_registry.list_agents.return_value = ["static"]
    judge = MagicMock()
    arg = AgentArgument(agent_name="Mediator", finding="all agree", confidence_score=0.9)
    judge.mediate = AsyncMock(return_value=(arg, True))
    container.get_judge_agent.return_value = judge

    result = _run_node(container)
    assert result["is_consensus"] is True
    assert result["discussion_history"][0].finding == "all agree"

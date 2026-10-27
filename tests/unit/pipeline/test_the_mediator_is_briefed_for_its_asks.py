"""The debate node hands the mediator what an ask hands on, and drains what an ask left.

The judge may ask the reverser and the static analyst (T-415d). A callee is
briefed from its caller, as a stage briefs an analyst: the pack, the run state,
the ids it may cite and the sample's paths. The node gives the mediator those
before each mediation, and after it writes what the callee's checks said under
the judge's name, as a stage writes a lead's asks under the lead's.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

from maljan.agents.judge_agent import JudgeAgent
from maljan.pipeline.nodes import brief_the_mediator, make_negotiation_node
from maljan.pipeline.state import AgentArgument
from maljan.pipeline.validation import Violation
from maljan.schemas.isr_models import AgentISR, ClaimEvidence


def _isr(name: str) -> AgentISR:
    return AgentISR(
        agent_id=name,
        domain=name,
        claims=[ClaimEvidence(claim="claim", evidence_ref="[ev_0001] imports", confidence=0.7)],
    )


STATE: dict[str, Any] = {
    "iteration_count": 1,
    "reports": {"static": "found things", "dynamic": "saw things"},
    "isr_reports": {"static": _isr("static"), "dynamic": _isr("dynamic")},
    "file_type": "PE32",
    "platform": "windows",
    "static_sample_path": "/mirror/s.bin",
    "static_sample_paths": {"ghidra": "/ghidra/s.bin"},
}


def test_the_mediator_carries_the_paths_and_the_round_an_ask_hands_on() -> None:
    judge = JudgeAgent(llm=MagicMock())

    with patch("maljan.pipeline.nodes.brief_agent") as briefed:
        brief_the_mediator(judge, STATE, MagicMock(), 1)

    briefed.assert_called_once()
    assert judge.sample_path_choices["by_provider"] == {"ghidra": "/ghidra/s.bin"}
    assert judge.sample_path_choices["static"] == "/mirror/s.bin"
    assert judge._analysis_file_path == "/mirror/s.bin"
    assert judge.current_round == 1


def _container(judge: Any) -> Any:
    container = MagicMock()
    container.is_mock = False
    container.agent_registry.list_agents.return_value = ["static", "dynamic"]
    container.analyst_keys.return_value = ["static", "dynamic"]
    container.get_judge_agent.return_value = judge
    container.drain_all_judge_evidence.return_value = []
    container.drain_all_judge_budget_records.return_value = []
    return container


def _mediated() -> tuple[AgentArgument, bool]:
    return AgentArgument(agent_name="Mediator", finding="ok", confidence_score=0.9), True


def test_the_node_briefs_the_mediator_before_it_mediates() -> None:
    judge = JudgeAgent(llm=MagicMock())
    seen: dict[str, Any] = {}

    async def _mediate(**_kw: Any) -> tuple[AgentArgument, bool]:
        seen["round"] = judge.current_round
        seen["choices"] = dict(judge.sample_path_choices)
        return _mediated()

    judge.mediate = _mediate  # type: ignore[method-assign]
    with (
        patch("maljan.pipeline.nodes.detect_sycophancy", return_value=False),
        patch("maljan.pipeline.nodes.brief_agent"),
    ):
        asyncio.run(make_negotiation_node(_container(judge))(STATE))

    assert seen["round"] == 1
    assert seen["choices"]["static"] == "/mirror/s.bin"


def test_what_an_asked_agent_s_checks_said_is_written_under_the_judge() -> None:
    judge = JudgeAgent(llm=MagicMock())

    async def _mediate(**_kw: Any) -> tuple[AgentArgument, bool]:
        # What ``delegation._hand_over_the_record`` folds onto the caller.
        judge.validation_findings.append(
            Violation(code="ungrounded", message="reverser: a claim cites nothing", path="c1")
        )
        judge.validation_retries += 1
        return _mediated()

    judge.mediate = AsyncMock(side_effect=_mediate)
    with (
        patch("maljan.pipeline.nodes.detect_sycophancy", return_value=False),
        patch("maljan.pipeline.nodes.brief_agent"),
    ):
        result = asyncio.run(make_negotiation_node(_container(judge))(STATE))

    (row,) = result["validation_findings"]["judge"]
    assert row["message"] == "reverser: a claim cites nothing"
    assert result["validation_retries"] == 1
    assert judge.validation_findings == []


def test_a_mediation_with_no_ask_writes_no_validation_row() -> None:
    judge = JudgeAgent(llm=MagicMock())
    judge.mediate = AsyncMock(return_value=_mediated())
    with (
        patch("maljan.pipeline.nodes.detect_sycophancy", return_value=False),
        patch("maljan.pipeline.nodes.brief_agent"),
    ):
        result = asyncio.run(make_negotiation_node(_container(judge))(STATE))

    assert "validation_findings" not in result
    assert "validation_retries" not in result

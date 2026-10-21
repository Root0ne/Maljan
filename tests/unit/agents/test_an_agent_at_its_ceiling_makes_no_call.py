"""Past its own ceiling an agent makes no model call, and its role ends the way it ends without one.

An analyst stopped mid-loop keeps the latest report among its own turns, read
as written, or none, and sends neither a salvage nor a nudge. A judge stopped
before its verdict gets the pipeline's fallback verdict, as a timed-out judge
does, with the ceiling's sentence as its reason. A mediator stopped in its
round leaves the round unmediated, its note in the ceiling's words.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any
from unittest.mock import AsyncMock

import pytest
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult

from maljan.agents.judge_agent import VERDICT_AGENT_CEILING_CODE, JudgeAgent
from maljan.core.spend import AgentCeilingStop, SpendMeter
from maljan.core.token_ledger import TokenLedger
from maljan.llm.agent_ceiling import attach_agent_ceiling
from maljan.llm.generation_rate import model_name_of
from maljan.pipeline.mediation_models import MEDIATOR_NO_ANSWER, mediator_no_answer_note
from maljan.pipeline.nodes import make_judge_node, stopped_before_answer_reason
from maljan.pipeline.outcome import decide_from_bundle
from maljan.schemas.evidence import EvidenceCounter
from tests.unit.agents.test_a_loop_has_no_default_limit import (
    REPORT,
    USAGE,
    _analyst,
    _Model,
    _run,
)
from tests.unit.pipeline.test_a_fallback_verdict_assesses_nothing import _Container, _state

_SAID = "agent judge reached its spend ceiling of 0.01 USD (llm.agents.judge.max_spend_usd)"


def _ledger_for(model: Any, agent: str, usd: float) -> TokenLedger:
    """A job whose only ceiling is ``agent``'s, at one USD per million tokens either way."""
    name = model_name_of(model)
    meter = SpendMeter(
        None, {name: {"input_usd_per_mtok": 1.0, "output_usd_per_mtok": 1.0}}, table={}
    )
    meter.set_agent_ceiling(agent, usd)
    return TokenLedger(spend=meter)


class _ReportsAsItGoes(_Model):
    """Writes its report beside each lookup it asks for."""

    def _generate(
        self, messages: Any, stop: Any = None, run_manager: Any = None, **kw: Any
    ) -> ChatResult:
        result = super()._generate(messages, stop, run_manager, **kw)
        turn = result.generations[0].message
        if getattr(turn, "tool_calls", None):
            turn = AIMessage(content=REPORT, tool_calls=turn.tool_calls, usage_metadata=USAGE)
        return ChatResult(generations=[ChatGeneration(message=turn)])


class TestAnAnalystStoppedMidLoop:
    def test_it_sends_no_salvage_or_nudge_and_has_no_answer(self) -> None:
        # Each turn costs 0.011 USD: the second one crosses 0.02.
        model = _Model(calls=12, seen=[])
        ledger = _ledger_for(model, "static", 0.02)
        attach_agent_ceiling(model, ledger, "static")
        agent = _analyst(model, ledger)

        answer = _run(agent)

        assert len(model.seen) == 2
        assert REPORT not in (answer or "")
        assert ledger.spend.agents_stopped() == frozenset({"static"})

    def test_its_latest_report_turn_stands_as_written(self) -> None:
        model = _ReportsAsItGoes(calls=12, seen=[])
        ledger = _ledger_for(model, "static", 0.02)
        attach_agent_ceiling(model, ledger, "static")
        agent = _analyst(model, ledger)

        answer = _run(agent)

        assert len(model.seen) == 2
        assert "it reads its own strings" in answer

    def test_the_run_says_it_stopped_and_keeps_its_evidence(self) -> None:
        ledger = [{"agent": "static", "id": "ev_0001"}, {"agent": "static", "id": "ev_0002"}]
        assert stopped_before_answer_reason("static", ledger) == (
            "static stopped at its own ceiling before writing an answer; "
            "its 2 evidence entries are kept"
        )


class _Refuses:
    """A model whose every call its agent's ceiling refuses."""

    def __init__(self, said: str = _SAID) -> None:
        self.said = said

    async def ainvoke(self, *_a: Any, **_k: Any) -> Any:
        raise AgentCeilingStop(f"a call of judge-model was not made: {self.said}", "judge")


class TestAJudgeStoppedBeforeItsVerdict:
    @pytest.mark.asyncio
    async def test_the_verdict_is_the_pipeline_s_and_says_why(self) -> None:
        verdict = await JudgeAgent(llm=_Refuses()).give_verdict(  # type: ignore[arg-type]
            reports={"static": "static findings"}, history=[]
        )

        assert verdict.bundle.x_maljan_fallback_verdict is not None
        assert decide_from_bundle(verdict.bundle) == "Suspicious"
        (row,) = [v for v in verdict.violations if v.code == "verdict.agent_ceiling"]
        assert _SAID in row.message
        assert verdict.retries == 0

    def test_the_judge_node_names_the_agent_and_its_ceiling(self) -> None:
        meter = SpendMeter(None, {}, table={})
        meter.set_agent_ceiling("judge", 0.01)
        meter.note_agent_call("judge", {"input_tokens": 1, "output_tokens": 1, "cost": 0.02}, "m")
        said, _ = meter.agent_refusal("judge")
        ledger = TokenLedger(spend=meter)

        class _StoppedJudge(_Container):
            def get_token_ledger(self) -> TokenLedger:
                return ledger

        container = _StoppedJudge(EvidenceCounter())
        verdict = asyncio.run(
            JudgeAgent(llm=_Refuses(said)).give_verdict(  # type: ignore[arg-type]
                reports={"static": "static findings"}, history=[]
            )
        )
        judge = container.get_judge_agent(role="judge")
        judge.give_verdict = AsyncMock(return_value=verdict)

        update = asyncio.run(make_judge_node(container)(_state()))

        assert update["degraded_mode"] is True
        assert any(
            reason.startswith("The agent judge reached its spend ceiling of 0.01 USD")
            for reason in update["degradation_reasons"]
        )
        assert update["verdict_fallback"]["failure"] == VERDICT_AGENT_CEILING_CODE


class TestAMediatorStoppedInItsRound:
    def test_the_round_is_not_mediated_and_says_why(self) -> None:
        said = "agent mediator reached its spend ceiling of 0.01 USD"
        judge = JudgeAgent(llm=_Refuses(said))  # type: ignore[arg-type]
        judge.logger = logging.getLogger("test.mediator_ceiling")

        argument, consensus = asyncio.run(
            judge.mediate({"static": "found things", "dynamic": "saw things"}, [])
        )

        assert consensus is None
        assert argument.status == MEDIATOR_NO_ANSWER
        assert argument.note == mediator_no_answer_note(
            f"a call of judge-model was not made: {said}"
        )

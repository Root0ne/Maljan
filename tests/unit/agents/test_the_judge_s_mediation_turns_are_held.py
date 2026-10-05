"""The judge's mediation turns are held to what the spend pays for, as an analyst's are.

The mediation loop handed the bare model to the ReAct executor, which bound the
tools itself; nothing could set a turn's cap, so every mediation turn was
admitted only at its whole cap. A 2.00 USD DeepSeek run refused one with 0.12
USD spendable for exactly that ("its model takes no cap of its own per call").
The model is now
bound to its tools before the executor sees it, and each turn's held cap is
set on that binding.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import patch

import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import StructuredTool
from pydantic import BaseModel

from maljan.agents.base_agent import model_held_per_turn
from maljan.agents.judge_agent import JudgeAgent, judge_output_cap
from maljan.core.cancellation import JobCancelled
from maljan.core.config import Settings
from maljan.core.spend import SpendMeter
from maljan.core.token_ledger import TokenLedger
from maljan.llm.generation_rate import model_name_of

USAGE = {"input_tokens": 1_000, "output_tokens": 500, "total_tokens": 1_500}


class _Judge(BaseChatModel):
    """Asks one lookup, then answers; records the cap each call was sent with."""

    caps: list = []

    def bind_tools(self, tools: Any, **_: Any) -> Any:
        return self.bind(tools=[{"type": "function", "function": {"name": t.name}} for t in tools])

    def _generate(
        self, messages: Any, stop: Any = None, run_manager: Any = None, **kwargs: Any
    ) -> ChatResult:
        self.caps.append(kwargs.get("max_tokens"))
        asked = any(isinstance(m, AIMessage) and m.tool_calls for m in messages)
        if asked or (
            isinstance(messages[-1], HumanMessage) and "Do NOT call" in str(messages[-1].content)
        ):
            turn = AIMessage(content="agreement 0.5", usage_metadata=USAGE)
        else:
            turn = AIMessage(
                content="",
                tool_calls=[{"name": "lookup", "args": {"what": "T1055"}, "id": "c1"}],
                usage_metadata=USAGE,
            )
        return ChatResult(generations=[ChatGeneration(message=turn)])

    @property
    def _llm_type(self) -> str:
        return "judge-stub"


class _What(BaseModel):
    what: str = ""


def _lookup() -> StructuredTool:
    def lookup(what: str = "") -> str:
        return f"{what} is a technique"

    return StructuredTool.from_function(
        func=lookup, name="lookup", description="Look it up.", args_schema=_What
    )


def _run(model: _Judge, ledger: TokenLedger) -> tuple[JudgeAgent, str]:
    judge = JudgeAgent(llm=model)
    judge.tools = [_lookup()]
    judge.token_ledger = ledger
    cfg = Settings(_env_file=None)
    with (
        patch("maljan.agents.base_agent.get_settings", lambda: cfg),
        patch("maljan.agents.judge_agent.get_settings", lambda: cfg),
    ):
        answer = asyncio.run(judge.execute_tool_loop([("system", "s"), ("human", "mediate")]))
    return judge, answer


def test_a_mediation_turn_whose_whole_cap_does_not_fit_is_sent_held() -> None:
    model = _Judge(caps=[])
    cfg = Settings(_env_file=None)
    with patch("maljan.agents.judge_agent.get_settings", lambda: cfg):
        cap = int(judge_output_cap().tokens)
    price = 10.0  # USD per million output tokens
    # What is left pays for half the whole cap, and far more than one answer.
    ceiling = cap * price / 1e6 / 2
    meter = SpendMeter(
        ceiling,
        {model_name_of(model): {"input_usd_per_mtok": 0.0, "output_usd_per_mtok": price}},
        table={},
    )
    meter.settle({"input_tokens": 0, "output_tokens": 100}, model_name_of(model))

    _judge, answer = _run(model, TokenLedger(spend=meter))

    assert "agreement" in answer
    loop_caps = [c for c in model.caps if c is not None]
    assert loop_caps, "a mediation turn was sent with a held cap"
    assert all(100 <= c < cap for c in loop_caps), (loop_caps, cap)
    held = meter.snapshot()["held_calls"]
    assert any("the mediation turn call" in said and "held to" in said for said in held)
    assert not any("was not made" in said for said in held)
    assert meter.committed() == meter.spent()


def test_a_model_that_cannot_be_bound_ahead_is_admitted_at_its_whole_cap() -> None:
    class _Unbindable(_Judge):
        def bind_tools(self, tools: Any, **_: Any) -> Any:
            return self

    model = _Unbindable(caps=[])
    loop_model, binding = model_held_per_turn(model, [_lookup()])
    assert loop_model is model and binding is None


def test_a_cancelled_mediation_releases_its_loop_s_reservation() -> None:
    """Cancelled after its second turn was admitted and reserved, before it was sent."""
    model = _Judge(caps=[])
    meter = SpendMeter(
        10.0,
        {model_name_of(model): {"input_usd_per_mtok": 0.0, "output_usd_per_mtok": 10.0}},
        table={},
    )
    meter.settle({"input_tokens": 0, "output_tokens": 100}, model_name_of(model))
    turns = {"seen": 0}

    def _cancel_on_the_second_turn(self: Any, conversation: Any, asked: Any) -> None:
        turns["seen"] += 1
        if turns["seen"] == 2:
            assert meter._reserved, "the second turn is reserved"
            raise JobCancelled("the operator cancelled the job; stopped before a model call")

    with (
        patch.object(JudgeAgent, "_publish_questions", _cancel_on_the_second_turn),
        pytest.raises(JobCancelled),
    ):
        _run(model, TokenLedger(spend=meter))

    # The turn reserved when the job was cancelled is released, and the loop's
    # running count goes to the ledger with the turn that was answered.
    assert turns["seen"] == 2
    assert meter._reserved == {}
    assert meter._in_flight == {}
    assert meter.committed() == meter.spent()

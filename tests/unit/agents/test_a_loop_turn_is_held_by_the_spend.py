"""A tool loop's turn is sent with its output cap held to what the spend pays for.

The spend ceiling used to refuse a turn whose whole output cap would pass what
was left, and never lower a turn's cap. A loop's turns are now held like any
other call: the held cap is set on the loop's own model binding before each
turn, the turn's worst case is reserved while it runs, and the reservation is
released once the loop counts the turn.
"""

from __future__ import annotations

from typing import Any

from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.outputs import ChatGeneration, ChatResult

from maljan.core.spend import SpendMeter
from maljan.core.token_ledger import TokenLedger
from maljan.llm.generation_rate import model_name_of
from tests.unit.agents.test_a_loop_has_no_default_limit import (
    REPORT,
    TASK,
    USAGE,
    _analyst,
    _Model,
    _run,
)


class _Binding(_Model):
    """The scripted model, bound the way a provider binds tools, recording each call's cap."""

    caps: list = []

    def bind_tools(self, tools: Any, **kwargs: Any) -> Any:
        return self.bind(tools=[{"type": "function", "function": {"name": t.name}} for t in tools])

    def _generate(
        self, messages: Any, stop: Any = None, run_manager: Any = None, **kwargs: Any
    ) -> ChatResult:
        self.caps.append(kwargs.get("max_tokens"))
        sent = list(messages)
        last = sent[-1]
        if isinstance(last, HumanMessage) and TASK not in str(last.content):
            return ChatResult(
                generations=[
                    ChatGeneration(message=AIMessage(content=REPORT, usage_metadata=USAGE))
                ]
            )
        return super()._generate(messages, stop, run_manager, **kwargs)


def test_each_turn_is_sent_at_its_held_cap_and_released_after() -> None:
    model = _Binding(calls=2, seen=[], caps=[])
    name = model_name_of(model)
    meter = SpendMeter(
        # A turn's whole 16,384-token cap would cost 0.16 USD: it cannot fit.
        0.10,
        {name: {"input_usd_per_mtok": 1.0, "output_usd_per_mtok": 10.0}},
        table={},
    )
    # One answer of 1,000 tokens measured: the smallest answer a turn can give.
    meter.settle({"input_tokens": 0, "output_tokens": 1_000}, name)
    agent = _analyst(model, TokenLedger(spend=meter))

    answer = _run(agent)

    assert "it reads its own strings" in answer
    loop_caps = [cap for cap in model.caps[:3]]
    assert all(isinstance(cap, int) and cap > 1_000 for cap in loop_caps), loop_caps
    held = meter.snapshot()["held_calls"]
    assert any("the loop turn call" in said and "held to" in said for said in held)
    # Nothing is left reserved once the loop is over.
    assert meter.committed() == meter.spent()

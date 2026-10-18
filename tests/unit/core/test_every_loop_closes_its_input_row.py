"""Every tool loop closes its row on the input meter, however it ended, agreeing with the ledger.

A loop that finished, one the hard cap stopped, one that raised an analyst
error and a judge loop that failed each close their row with the very turns
the token ledger recorded on that exit path, so the provider-reported input on
the row equals the agent's input tokens in the ledger (``run_summary.tokens``).
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import MagicMock

import pytest
from langchain_core.tools import StructuredTool
from tests.unit.core.test_every_model_call_is_counted import (
    _Analyst,
    _cut_off,
    _judge,
    _peek_tool,
    _Scripted,
    _scripted_analyst,
    _slow,
    _Tooling,
)

from maljan.agents import base_agent
from maljan.core.exceptions import AnalystError
from maljan.core.input_meter import InputMeter
from maljan.core.token_ledger import TokenLedger


def _metered(agent: Any) -> InputMeter:
    meter = InputMeter()
    agent._container = MagicMock()
    agent._container.input_meter = meter
    return meter


def _agrees(meter: InputMeter, ledger: TokenLedger, agent: str) -> None:
    rows = [row for row in meter.rows() if row["agent"] == agent]
    assert rows, "the loop measured its requests"
    tally = ledger.snapshot()["agents"][agent]
    assert sum(row.get("input_tokens", 0) for row in rows) == tally["input_tokens"]
    assert sum(row["reported_requests"] for row in rows) == tally["llm_calls"]


def test_a_loop_that_finished() -> None:
    agent, _llm, ledger = _scripted_analyst(["tool", "CLAIM: x\nEVIDENCE: ev_0001"])
    meter = _metered(agent)

    agent.execute_tool_loop([("system", "s"), ("human", "h")])

    _agrees(meter, ledger, "static")


def test_a_loop_the_hard_cap_stopped(monkeypatch: pytest.MonkeyPatch) -> None:
    llm, ledger = _Tooling(asked=[]), TokenLedger()
    agent = _Analyst(
        llm=llm,
        name="static",
        tools=[StructuredTool.from_function(func=_slow, name="slow", description="s")],
    )
    agent.token_ledger = ledger
    meter = _metered(agent)
    agent._model_label = lambda: "openai/static-model"
    monkeypatch.setattr(base_agent, "_run_coro_blocking", _cut_off)

    with pytest.raises(TimeoutError):
        agent.execute_tool_loop([("system", "s"), ("human", "h")])

    _agrees(meter, ledger, "static")


def test_a_loop_that_raised_an_analyst_error() -> None:
    agent, _llm, ledger = _scripted_analyst(["tool", "tool", AnalystError("gave up")])
    meter = _metered(agent)

    with pytest.raises(AnalystError):
        agent.execute_tool_loop([("system", "s"), ("human", "h")])

    _agrees(meter, ledger, "static")


def test_a_judge_loop_that_failed() -> None:
    llm = _Scripted(script=["tool", "tool", RuntimeError("the server broke")], served=[])
    ledger = TokenLedger()
    judge = _judge(llm, ledger)  # type: ignore[arg-type]
    judge.tools = [_peek_tool()]
    meter = _metered(judge)

    with pytest.raises(RuntimeError):
        asyncio.run(judge.execute_tool_loop([("system", "s"), ("human", "h")]))

    _agrees(meter, ledger, "judge")

"""A model call's whole-call deadline is that call failing, never the loop's clock.

With no loop clock the only time bound on a turn is its own whole-call
deadline (``ModelCallDeadline``). It is a ``TimeoutError`` so a model list
moves on from it, and it used to be taken for the loop's hard cap: a lone
model that ran past it on its fourth turn aborted the analyst with "exceeded
hard cap of none" and three tool rounds of evidence unwritten. It ends the
tool phase now, and the salvage writes the answer from what was gathered, the
record naming the model call deadline.
"""

from __future__ import annotations

import logging
from typing import Any
from unittest.mock import patch

import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import StructuredTool
from pydantic import BaseModel

from maljan.agents.base_agent import BaseAnalyst, _run_coro_blocking
from maljan.core.exceptions import AnalystError
from maljan.core.token_ledger import TokenLedger
from maljan.llm.generation_rate import ModelCallDeadline

REPORT = "CLAIM: it reads its own strings\nEVIDENCE: ev_0001\nCONFIDENCE: 0.6\nTECHNIQUE: NONE"


class _Model(BaseChatModel):
    """Asks for a lookup, and on call ``dies_on`` runs past its deadline."""

    dies_on: int = 4
    calls: int = 0

    def _generate(
        self, messages: Any, stop: Any = None, run_manager: Any = None, **_: Any
    ) -> ChatResult:
        self.calls += 1
        last = messages[-1]
        if isinstance(last, HumanMessage) and "look at it" not in str(last.content):
            return ChatResult(generations=[ChatGeneration(message=AIMessage(content=REPORT))])
        if self.calls == self.dies_on:
            raise ModelCallDeadline("the model request did not finish within its 1800 s deadline")
        turn = AIMessage(
            content="",
            tool_calls=[
                {"name": "lookup", "args": {"what": f"w{self.calls}"}, "id": f"c{self.calls}"}
            ],
        )
        return ChatResult(generations=[ChatGeneration(message=turn)])

    @property
    def _llm_type(self) -> str:
        return "deadline-stub"

    def bind_tools(self, tools: Any, **_: Any) -> Any:
        return self


class _What(BaseModel):
    what: str = ""


class _Analyst(BaseAnalyst):
    def analyze(self, data: str) -> str:  # pragma: no cover - not exercised
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover
        return ""


def _analyst(model: _Model) -> _Analyst:
    def lookup(what: str = "") -> str:
        return f"answer for {what}"

    agent = _Analyst(llm=model, name="static")
    agent.logger = logging.getLogger("test.call_deadline")
    agent.tools = [
        StructuredTool.from_function(func=lookup, name="lookup", description="L", args_schema=_What)
    ]
    agent.token_ledger = TokenLedger()
    return agent


def _run(agent: _Analyst) -> str:
    with patch("maljan.agents.base_agent.loop_limits", return_value=(None, None)):
        return agent.execute_tool_loop([("system", "s"), ("human", "look at it")])


class TestInALoopWithNoClock:
    def test_the_loop_ends_its_tool_phase_and_writes_its_answer(self) -> None:
        agent = _analyst(_Model(dies_on=4))

        answer = _run(agent)

        assert "it reads its own strings" in answer, "the salvage wrote from what was gathered"
        (record,) = agent.drain_budget_records()
        assert record["cap"] == "time"
        assert record["detail"].startswith("model call deadline: ")
        assert record["max_steps"] is None and record["timeout_s"] is None

    def test_with_nothing_gathered_the_analyst_fails_naming_the_deadline(self) -> None:
        agent = _analyst(_Model(dies_on=1))

        with pytest.raises(AnalystError, match="model call deadline"):
            _run(agent)
        (record,) = agent.drain_budget_records()
        assert record["cap"] == "time"
        assert record["detail"].startswith("model call deadline: ")


class TestTheRunnerHandsTheCallsOwnTimeoutOn:
    def test_a_coroutine_s_own_timeout_is_not_the_wait_running_out(self) -> None:
        async def raises() -> None:
            raise ModelCallDeadline("its own")

        with pytest.raises(ModelCallDeadline, match="its own"):
            _run_coro_blocking(raises(), None, label="test")

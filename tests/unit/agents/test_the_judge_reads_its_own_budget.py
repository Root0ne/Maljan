"""The judge's tool loop reads its budget the way every agent's loop does.

It read the deployment-wide ``react_agent_timeout`` and ``react_agent_max_steps``
directly, so the override map's ``judge`` entry never reached it. It goes
through ``loop_limits("judge")`` now: the definition, then the deprecated
maps, then the deployment's values — and ``None``, no limit, when none of them
is set.
"""

from __future__ import annotations

import asyncio
import sys
from typing import Any
from unittest.mock import MagicMock, patch

from langchain_core.messages import AIMessage
from langchain_core.tools import StructuredTool

from maljan.agents.judge_agent import JudgeAgent
from maljan.core.config import Settings


def _recursion_limit_of_the_judge(cfg: Settings) -> tuple[int, Any]:
    captured: dict[str, Any] = {}

    class _Executor:
        async def astream(self, inputs, config, stream_mode="values"):  # type: ignore[no-untyped-def]
            captured["limit"] = config.get("recursion_limit")
            yield {"messages": [*inputs["messages"], AIMessage(content="agreement 0.8")]}

    def lookup(what: str = "") -> str:
        """Look it up."""
        return what

    judge = JudgeAgent(llm=MagicMock())
    judge.tools = [StructuredTool.from_function(func=lookup, name="lookup")]
    with (
        patch("maljan.agents.base_agent.get_settings", lambda: cfg),
        patch("maljan.agents.judge_agent.get_settings", lambda: cfg),
        patch("langgraph.prebuilt.create_react_agent", return_value=_Executor()),
    ):
        asyncio.run(judge.execute_tool_loop([("system", "s"), ("human", "h")]))
    (record,) = judge.drain_budget_records()
    return captured["limit"], record


class TestTheJudgesLoopBudget:
    def test_no_limit_by_default(self) -> None:
        limit, record = _recursion_limit_of_the_judge(Settings(_env_file=None))
        assert limit == sys.maxsize
        assert record["max_steps"] is None and record["timeout_s"] is None

    def test_the_deployment_s_value_reaches_it(self) -> None:
        cfg = Settings(_env_file=None, react_agent_max_steps=7, react_agent_timeout=300)
        limit, record = _recursion_limit_of_the_judge(cfg)
        assert limit == 7
        assert record["max_steps"] == 7 and record["timeout_s"] == 300.0

    def test_the_override_map_entry_reaches_it(self) -> None:
        cfg = Settings(
            _env_file=None,
            react_agent_max_steps_overrides={"judge": 9},
            react_agent_timeout_overrides={"judge": 450},
        )
        limit, record = _recursion_limit_of_the_judge(cfg)
        assert limit == 9
        assert record["max_steps"] == 9 and record["timeout_s"] == 450.0

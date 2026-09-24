"""The size of the tool definitions a loop sends is on the record, not only in the budget.

The context budget counts every tool definition with every request, and a run
whose per-turn answer cap shrank could not say by how much of it was the
definitions: the figure was never written down. It is now, per loop in the
budget record, per agent in the run summary, and on every ``budget_tick``.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import StructuredTool

from maljan.agents.base_agent import BaseAnalyst, LoopBudget
from maljan.analysis.run_summary import RunSummaryBuilder
from maljan.llm.context_window import tool_definition_chars
from maljan.pipeline.events import BUDGET_TICK, emit_budget_tick
from maljan.pipeline.nodes import _budget_update


class _Scripted(BaseChatModel):
    script: list[Any]

    def _generate(self, messages: Any, stop: Any = None, run_manager: Any = None, **_: Any):
        answer = self.script.pop(0) if self.script else AIMessage(content="")
        return ChatResult(generations=[ChatGeneration(message=answer)])

    @property
    def _llm_type(self) -> str:
        return "scripted"

    def bind_tools(self, tools: Any, **_: Any) -> Any:
        return self


class _Analyst(BaseAnalyst):
    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *a: Any, **k: Any) -> str:  # pragma: no cover - unused
        return ""


def _peek(path: str) -> dict[str, Any]:
    """Read the first bytes of a file the analyst names."""
    return {"x": 1}


def _agent(events: list[tuple[str, dict]]) -> _Analyst:
    tool = StructuredTool.from_function(func=_peek, name="peek", description="Peek at a file.")
    call = AIMessage(content="", tool_calls=[{"name": "peek", "args": {"path": "/s"}, "id": "1"}])
    agent = _Analyst(
        llm=_Scripted(script=[call, AIMessage(content="CLAIM: x\nEVIDENCE: ev_0001")]),
        name="static",
        tools=[tool],
    )
    agent.pipeline_stage = "analysis"
    container = MagicMock()
    container.event_sink = lambda kind, payload: events.append((kind, payload))
    agent._container = container
    return agent


class TestTheLoop:
    def test_the_record_and_every_tick_carry_the_definitions_it_sent(self) -> None:
        events: list[tuple[str, dict]] = []
        agent = _agent(events)
        expected = tool_definition_chars(agent.pinned_tools())
        assert expected > 0

        agent.execute_tool_loop([("system", "s"), ("human", "h")])

        (record,) = _budget_update(agent, "static")["budget_records"]["static"]
        assert record["tool_definition_chars"] == agent._tool_definition_chars
        assert record["tool_definition_chars"] >= expected
        ticks = [payload for kind, payload in events if kind == BUDGET_TICK]
        assert ticks
        assert {tick["tool_definition_chars"] for tick in ticks} == {
            record["tool_definition_chars"]
        }

    def test_a_record_written_outside_a_loop_says_none_were_sent(self) -> None:
        agent = _agent([])
        agent._record_budget(LoopBudget(max_steps=4, timeout=1.0), [], None)
        (record,) = agent.drain_budget_records()
        assert record["tool_definition_chars"] == 0


class TestTheTick:
    def test_the_tick_has_the_field(self) -> None:
        events: list[tuple[str, dict]] = []
        emit_budget_tick(
            lambda kind, payload: events.append((kind, payload)),
            agent="static",
            stage="analysis",
            steps_used=1,
            max_steps=40,
            elapsed_s=1.0,
            timeout_s=10.0,
            prompt_chars=100,
            ledger_entries=0,
            tool_definition_chars=4321,
        )
        assert events[0][1]["tool_definition_chars"] == 4321


class TestTheRunSummary:
    def test_the_summary_keeps_each_agent_s_largest_figure(self) -> None:
        summary = (
            RunSummaryBuilder(start_time=0.0)
            .set_budget(
                {
                    "static": [
                        {"steps_used": 3, "max_steps": 40, "tool_definition_chars": 21_000},
                        {"steps_used": 2, "max_steps": 40, "tool_definition_chars": 19_500},
                    ],
                    "judge": [{"steps_used": 1, "max_steps": 40}],
                }
            )
            .build()
            .to_dict()
        )
        assert summary["budget"]["static"]["tool_definition_chars"] == 21_000
        assert summary["budget"]["judge"]["tool_definition_chars"] == 0

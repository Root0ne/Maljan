"""The tool loop meters itself, names the cap that ended it, and the summary sums the meter.

Driven through a real loop with a scripted model: a loop that answers ticks
and records no cap, one that spends its steps says so, and ticks come every
few steps rather than every turn.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import StructuredTool

from maljan.analysis.run_summary import RunSummaryBuilder
from maljan.pipeline.events import (
    BUDGET_TICK,
    STAGE_ENDED_AT_CAP,
    emit_budget_tick,
    emit_stage_ended_at_cap,
)
from maljan.pipeline.nodes import _budget_update


class TestTheBudgetEvents:
    def test_a_tick_carries_the_meter_s_fields(self) -> None:
        events: list[tuple[str, dict]] = []
        emit_budget_tick(
            lambda k, p: events.append((k, p)),
            agent="static",
            stage="analysis",
            steps_used=7,
            max_steps=40,
            elapsed_s=12.34,
            timeout_s=1500,
            prompt_chars=9000,
            ledger_entries=3,
        )
        assert events == [
            (
                BUDGET_TICK,
                {
                    "agent": "static",
                    "stage": "analysis",
                    "steps_used": 7,
                    "max_steps": 40,
                    "elapsed_s": 12.3,
                    "timeout_s": 1500.0,
                    "prompt_chars": 9000,
                    "ledger_entries": 3,
                    "final": False,
                },
            )
        ]

    def test_a_cap_names_itself(self) -> None:
        events: list[tuple[str, dict]] = []
        emit_stage_ended_at_cap(
            lambda k, p: events.append((k, p)), stage="analysis", agent="static", cap="steps"
        )
        assert events == [
            (STAGE_ENDED_AT_CAP, {"stage": "analysis", "agent": "static", "cap": "steps"})
        ]


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


def _call(n: int) -> AIMessage:
    """A tool round; the argument varies so the repeat guard leaves the loop alone."""
    return AIMessage(
        content="", tool_calls=[{"name": "peek", "args": {"path": f"/s{n}"}, "id": str(n)}]
    )


class TestTheLoopMetersItself:
    def _agent(self, script: list[Any], events: list[tuple[str, dict]]) -> Any:
        from maljan.agents.base_agent import BaseAnalyst

        class _Analyst(BaseAnalyst):
            def analyze(self, data: str) -> str:  # pragma: no cover - unused
                return ""

            def revise(self, *a: Any, **k: Any) -> str:  # pragma: no cover - unused
                return ""

        def peek(path: str) -> dict[str, Any]:
            """Peek."""
            return {"x": 1}

        agent = _Analyst(
            llm=_Scripted(script=script),
            name="static",
            tools=[StructuredTool.from_function(func=peek, name="peek", description="p")],
        )
        agent.pipeline_stage = "analysis"
        container = MagicMock()
        container.event_sink = lambda k, p: events.append((k, p))
        agent._container = container
        return agent

    def test_a_loop_that_answers_records_no_cap_and_a_final_tick(self, monkeypatch) -> None:
        events: list[tuple[str, dict]] = []
        agent = self._agent([_call(1), AIMessage(content="CLAIM: x\nEVIDENCE: ev_0001")], events)
        agent.execute_tool_loop([("system", "s"), ("human", "h")])
        ticks = [p for k, p in events if k == BUDGET_TICK]
        assert ticks and ticks[-1]["final"] is True
        assert ticks[-1]["steps_used"] == 3 and ticks[-1]["ledger_entries"] == 1
        assert ticks[-1]["max_steps"] == 40
        assert not [p for k, p in events if k == STAGE_ENDED_AT_CAP]
        (record,) = _budget_update(agent, "static")["budget_records"]["static"]
        assert record["cap"] is None and record["steps_used"] == 3
        assert _budget_update(agent, "static") == {}

    def test_a_loop_that_hits_its_step_cap_says_so(self, monkeypatch) -> None:
        from maljan.core.config import Settings, get_settings

        cfg = get_settings()
        monkeypatch.setitem(cfg.react_agent_max_steps_overrides, "static", 4)
        events: list[tuple[str, dict]] = []
        agent = self._agent([_call(1), _call(2), _call(3), _call(4)], events)
        agent.execute_tool_loop([("system", "s"), ("human", "h")])
        caps = [p for k, p in events if k == STAGE_ENDED_AT_CAP]
        assert caps and caps[0]["cap"] == "steps" and caps[0]["agent"] == "static"
        (record,) = _budget_update(agent, "static")["budget_records"]["static"]
        assert record["cap"] == "steps" and record["max_steps"] == 4
        assert isinstance(cfg, Settings)

    def test_ticks_come_every_few_steps(self, monkeypatch) -> None:
        from maljan.core.config import get_settings

        monkeypatch.setitem(get_settings().react_agent_max_steps_overrides, "static", 40)
        events: list[tuple[str, dict]] = []
        script = [_call(n) for n in range(1, 7)] + [AIMessage(content="CLAIM: x")]
        agent = self._agent(script, events)
        agent.execute_tool_loop([("system", "s"), ("human", "h")])
        ticks = [p for k, p in events if k == BUDGET_TICK]
        # Six tool rounds are twelve steps: a tick at five and ten, then the final one.
        assert [t["final"] for t in ticks] == [False, False, True]
        assert ticks[0]["steps_used"] >= 5


class TestTheRunSummarySumsTheMeter:
    def test_per_agent_totals_and_the_distinct_caps(self) -> None:
        summary = (
            RunSummaryBuilder(start_time=0.0)
            .set_budget(
                {
                    "static": [
                        {"steps_used": 12, "max_steps": 40, "elapsed_s": 30.0, "timeout_s": 1500},
                        {
                            "steps_used": 40,
                            "max_steps": 40,
                            "elapsed_s": 100.0,
                            "timeout_s": 1500,
                            "delegated_steps": 6,
                            "cap": "steps",
                        },
                        {"steps_used": 3, "max_steps": 40, "elapsed_s": 5.0, "cap": "steps"},
                    ],
                    "network": [],
                }
            )
            .build()
            .to_dict()
        )
        assert summary["budget"] == {
            "static": {
                "loops": 3,
                "steps_used": 55,
                "max_steps": 40,
                "elapsed_s": 135.0,
                "timeout_s": 1500.0,
                "delegated_steps": 6,
                "caps": ["steps"],
            }
        }

    def test_no_records_is_none(self) -> None:
        assert RunSummaryBuilder(start_time=0.0).set_budget({}).build().to_dict()["budget"] is None

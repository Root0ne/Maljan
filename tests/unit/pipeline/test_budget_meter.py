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

    def test_a_loop_cut_off_at_its_wall_clock_records_what_it_spent(self) -> None:
        """The one run the meter exists to explain, and it used to read as zero.

        A loop that does not come back from its thread has no conversation to
        hand the record; the refresher counted the turns before every model
        turn, so the budget itself is where the last figure is.
        """
        from maljan.agents.base_agent import LoopBudget

        events: list[tuple[str, dict]] = []
        agent = self._agent([AIMessage(content="CLAIM: x")], events)
        budget = LoopBudget(max_steps=40, timeout=1500.0)
        budget.own_steps = 31
        budget.note_delegated(4)

        agent._record_budget(budget, [], "time", detail="the loop exceeded its hard cap")

        (record,) = _budget_update(agent, "static")["budget_records"]["static"]
        assert record["steps_used"] == 35, "its own turns and what it delegated"
        assert record["cap"] == "time" and record["max_steps"] == 40
        assert [p["cap"] for k, p in events if k == STAGE_ENDED_AT_CAP] == ["time"]

    def test_the_meter_s_rows_are_this_agent_s_and_not_the_class_s(self) -> None:
        """A stand-in built without ``__init__`` must not drain another one's rows."""
        from maljan.agents.base_agent import BudgetMeter, LoopBudget

        class _StandIn(BudgetMeter):
            name = "stand-in"
            logger = MagicMock()
            pipeline_stage = "analysis"
            _container = None

        one, two = _StandIn(), _StandIn()
        one._record_budget(LoopBudget(max_steps=4, timeout=1.0), [], None)

        assert len(one.drain_budget_records()) == 1
        assert two.drain_budget_records() == []

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
        # A tick before the last one counts the calls made so far rather than
        # publishing a zero that means "nobody asked".
        assert ticks[0]["ledger_entries"] > 0


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


class TestEveryPathThatDrainsALedgerDrainsTheMeter:
    """Rows written on one path and drained on another are rows nobody sees."""

    def test_a_callee_s_rows_travel_with_its_ledger(self) -> None:
        from maljan.agents.base_agent import BudgetMeter, LoopBudget
        from maljan.agents.delegation import _hand_over_the_record

        class _Agent(BudgetMeter):
            def __init__(self, name: str) -> None:
                self.name = name
                self.logger = MagicMock()
                self.pipeline_stage = "analysis"
                self._container = None
                self._budget_records: list[dict[str, Any]] = []
                self._evidence_entries: list[Any] = []
                self.validation_findings: list[Any] = []
                self.validation_retries = 0
                self.validation_fed_back: dict[str, int] = {}
                self.validation_not_run: list[str] = []

            def drain_evidence_entries(self) -> list[Any]:
                entries, self._evidence_entries = self._evidence_entries, []
                return entries

            def drain_validation_findings(self):
                return [], 0, {}

            def drain_validation_not_run(self) -> list[str]:
                return []

        caller, callee = _Agent("boss"), _Agent("helper")
        callee._record_budget(LoopBudget(max_steps=8, timeout=60.0), [], "steps")

        _hand_over_the_record(caller, callee)

        (row,) = caller.drain_budget_records()
        assert row["cap"] == "steps" and row["agent"] == "helper"
        assert callee.drain_budget_records() == [], "the callee keeps nothing"

    def test_a_caller_that_has_already_finished_is_given_no_rows(self) -> None:
        from maljan.agents.base_agent import BudgetMeter, LoopBudget
        from maljan.agents.delegation import _hand_over_the_record

        class _Agent(BudgetMeter):
            def __init__(self, name: str) -> None:
                self.name = name
                self.logger = MagicMock()
                self.pipeline_stage = "analysis"
                self._container = None
                self._budget_records: list[dict[str, Any]] = []
                self._evidence_entries: list[Any] = []

            def drain_evidence_entries(self) -> list[Any]:
                return []

            def drain_validation_findings(self):
                return [], 0, {}

            def drain_validation_not_run(self) -> list[str]:
                return []

        caller, callee = _Agent("boss"), _Agent("helper")
        callee._record_budget(LoopBudget(max_steps=8, timeout=60.0), [], None)

        _hand_over_the_record(caller, callee, still_running=False)

        assert caller.drain_budget_records() == []
        assert callee.drain_budget_records() == [], "the callee is drained either way"

    def test_a_row_is_filed_under_the_agent_that_ran_the_loop(self) -> None:
        """A lead hands over what its specialists spent; the summary keeps them apart."""
        from maljan.agents.base_agent import BudgetMeter, LoopBudget

        class _Agent(BudgetMeter):
            def __init__(self) -> None:
                self.name = "lead"
                self.logger = MagicMock()
                self.pipeline_stage = "lead"
                self._container = None
                self._budget_records: list[dict[str, Any]] = []

        lead = _Agent()
        lead._record_budget(LoopBudget(max_steps=40, timeout=100.0), [], None)
        lead._note_budget({"stage": "lead", "cap": "steps", "agent": "static"})

        rows = _budget_update(lead, "lead")["budget_records"]

        assert set(rows) == {"lead", "static"}
        assert [row["cap"] for row in rows["static"]] == ["steps"]
        assert [row["cap"] for row in rows["lead"]] == [None]

    def test_the_judge_notes_its_turns_so_a_timed_out_loop_is_not_zero(self) -> None:
        """Its loop has no run-state block to refresh, so nothing else counted."""
        from langchain_core.messages import AIMessage, HumanMessage

        from maljan.agents.base_agent import LoopBudget, _steps_this_loop_spent

        budget = LoopBudget(max_steps=10, timeout=600.0)
        budget.note_turns([HumanMessage(content="h"), AIMessage(content="a")])

        assert budget.own_steps > 0
        assert _steps_this_loop_spent(budget, []) == budget.own_steps

    def test_the_judge_meters_its_own_loop_and_the_container_drains_it(self) -> None:
        from maljan.agents.base_agent import BudgetMeter, LoopBudget
        from maljan.agents.judge_agent import JudgeAgent
        from maljan.pipeline.nodes import _judge_budget

        judge = JudgeAgent(llm=MagicMock())
        assert isinstance(judge, BudgetMeter), "the judge runs the analysts' meter"
        judge._record_budget(LoopBudget(max_steps=10, timeout=600.0), [], "time")

        container = MagicMock()
        container.drain_all_judge_budget_records.return_value = judge.drain_budget_records()

        update = _judge_budget(container)

        assert [row["cap"] for row in update["budget_records"]["judge"]] == ["time"]
        assert judge.drain_budget_records() == []

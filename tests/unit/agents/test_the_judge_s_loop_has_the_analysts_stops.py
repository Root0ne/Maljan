"""The judge's tool loop, unbounded by default, ends by the analysts' own stops.

With no step or time limit the mediation loop has to end the way an
analyst's does: at the repeat guard when it re-asks the same lookup, and at the
spend ceiling when its own turns cost it. A lone model stamps no model name on
its answers, so the loop's running turns are priced under the judge's own
label — priced as "" they cost nothing and the ceiling never tripped.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import patch

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import StructuredTool
from pydantic import BaseModel

from maljan.agents.judge_agent import JudgeAgent
from maljan.core.config import Settings
from maljan.core.spend import SpendMeter
from maljan.core.token_ledger import TokenLedger
from maljan.llm.generation_rate import model_name_of

USAGE = {"input_tokens": 10_000, "output_tokens": 1_000, "total_tokens": 11_000}


class _Judge(BaseChatModel):
    """Asks for a lookup on every turn: the same one (``same``) or a new one each time."""

    same: bool = True
    turns: int = 0

    def _generate(
        self, messages: Any, stop: Any = None, run_manager: Any = None, **_: Any
    ) -> ChatResult:
        self.turns += 1
        if isinstance(messages[-1], HumanMessage) and "Do NOT call" in str(messages[-1].content):
            return ChatResult(
                generations=[ChatGeneration(message=AIMessage(content="agreement 0.5"))]
            )
        what = "T1055" if self.same else f"T{1000 + self.turns}"
        turn = AIMessage(
            content="",
            tool_calls=[{"name": "lookup", "args": {"what": what}, "id": f"c{self.turns}"}],
            usage_metadata=USAGE,
        )
        return ChatResult(generations=[ChatGeneration(message=turn)])

    @property
    def _llm_type(self) -> str:
        return "judge-stub"

    def bind_tools(self, tools: Any, **_: Any) -> Any:
        return self


class _What(BaseModel):
    what: str = ""


def _lookup() -> StructuredTool:
    def lookup(what: str = "") -> str:
        return f"{what} is a technique"

    return StructuredTool.from_function(
        func=lookup, name="lookup", description="Look it up.", args_schema=_What
    )


def _run(model: _Judge, ledger: TokenLedger | None = None) -> tuple[JudgeAgent, str]:
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


class TestTheJudgesLoopWithNoLimit:
    def test_ends_at_the_repeat_guard(self) -> None:
        model = _Judge(same=True)

        judge, _answer = _run(model)

        (record,) = judge.drain_budget_records()
        assert record["cap"] == "repeats"
        assert record["max_steps"] is None
        assert model.turns < 12, "the guard ended it, not the window"

    def test_its_running_turns_trip_the_spend_ceiling(self) -> None:
        model = _Judge(same=False)
        meter = SpendMeter(
            0.05,
            {model_name_of(model): {"input_usd_per_mtok": 1.0, "output_usd_per_mtok": 10.0}},
            table={},
        )

        judge, _answer = _run(model, TokenLedger(spend=meter))

        (record,) = judge.drain_budget_records()
        assert record["cap"] == "spend"
        # Ended at the trip, or before it: a turn whose worst case would pass
        # what is left is not sent, and the ceiling records why.
        snapshot = meter.snapshot()
        assert snapshot is not None
        assert meter.reached() or snapshot.get("held_calls")
        assert model.turns < 12

    def test_a_turn_that_fits_the_ceiling_runs_and_the_running_cost_trips_it(self) -> None:
        model = _Judge(same=False)
        meter = SpendMeter(
            0.05,
            {model_name_of(model): {"input_usd_per_mtok": 1.0, "output_usd_per_mtok": 10.0}},
            table={},
        )
        # Worst cases always fit, so only the running turns can end it.
        meter.worst_case = lambda *a, **k: 0.0  # type: ignore[method-assign]

        judge, _answer = _run(model, TokenLedger(spend=meter))

        (record,) = judge.drain_budget_records()
        assert record["cap"] == "spend"
        assert meter.reached() is True, "the judge's own running turns tripped it"

    def test_an_unstamped_turn_is_priced_under_the_label_it_is_given(self) -> None:
        meter = SpendMeter(
            0.01,
            {"judge-model": {"input_usd_per_mtok": 1.0, "output_usd_per_mtok": 10.0}},
            table={},
        )
        turn = AIMessage(content="", usage_metadata=USAGE)
        meter.note_loop("k", [turn])
        assert meter.spent() == 0.0, "no label, no price"
        meter.note_loop("k", [turn], "judge-model")
        assert meter.spent() > 0.01 and meter.reached() is True

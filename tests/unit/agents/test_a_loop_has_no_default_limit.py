"""A tool loop has no step or time limit unless an operator sets one.

The deployment used to hand every loop ten steps and 180 seconds, the lead
forty and 1,800, and every ask twelve and 300: a paid run's second static
server ended at nine of its ten steps with more to read. ``None`` is no limit
now, end to end, and a loop ends by its model answering or by one of the stops
that are not a count — the repeat guard, the conversation's room, the
operator's spend ceiling — with the arq job timeout as the last resort. These
tests drive the real loop over each of them with no limit set, and one that
takes more than ten steps because nothing stops it.
"""

from __future__ import annotations

import logging
import sys
from typing import Any
from unittest.mock import patch

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import StructuredTool
from pydantic import BaseModel

from maljan.agents.base_agent import (
    NO_LIMIT,
    BaseAnalyst,
    BudgetCeiling,
    LoopBudget,
    hard_cap,
    limit_text,
    loop_limits,
    model_turns_left,
    recursion_limit,
)
from maljan.core.spend import SpendMeter
from maljan.core.token_ledger import TokenLedger
from maljan.llm.generation_rate import model_name_of
from maljan.pipeline.run_state import budget_line, render_run_state
from tests.unit.agents.test_no_room_ends_the_loop import (
    _a_budget_that_runs_out,
    _loop_turns,
)
from tests.unit.agents.test_no_room_ends_the_loop import (
    _run as _run_out_of_room,
)

TASK = "look at it"
REPORT = "CLAIM: it reads its own strings\nEVIDENCE: ev_0001\nCONFIDENCE: 0.6\nTECHNIQUE: NONE"
USAGE = {"input_tokens": 10_000, "output_tokens": 1_000, "total_tokens": 11_000}


class _Model(BaseChatModel):
    """Asks for ``calls`` distinct lookups (or the same one, ``same``), then answers.

    Told to stop — a human turn that is not the task, or one that says no tool
    can be called — it writes the report.
    Every turn carries provider-reported usage, so a spend meter can price it.
    """

    calls: int = 12
    same: bool = False
    seen: list = []

    def _generate(
        self, messages: Any, stop: Any = None, run_manager: Any = None, **_: Any
    ) -> ChatResult:
        sent = list(messages)
        self.seen.append(sent)
        last = sent[-1]
        told = str(last.content)
        if isinstance(last, HumanMessage) and (TASK not in told or "no tool can be" in told):
            turn = AIMessage(content=REPORT, usage_metadata=USAGE)
        else:
            made = sum(1 for m in sent if isinstance(m, AIMessage) and m.tool_calls)
            if made < self.calls:
                what = "w" if self.same else f"w{made}"
                turn = AIMessage(
                    content="",
                    tool_calls=[{"name": "lookup", "args": {"what": what}, "id": f"c{made}"}],
                    usage_metadata=USAGE,
                )
            else:
                turn = AIMessage(content=REPORT, usage_metadata=USAGE)
        return ChatResult(generations=[ChatGeneration(message=turn)])

    @property
    def _llm_type(self) -> str:
        return "scripted"

    def bind_tools(self, tools: Any, **_: Any) -> Any:
        return self


class _What(BaseModel):
    what: str = ""


def _lookup() -> StructuredTool:
    def lookup(what: str = "") -> str:
        return f"answer for {what}"

    return StructuredTool.from_function(
        func=lookup, name="lookup", description="Look it up.", args_schema=_What
    )


class _Analyst(BaseAnalyst):
    def analyze(self, data: str) -> str:  # pragma: no cover - not exercised
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover
        return ""


def _analyst(model: _Model, ledger: TokenLedger | None = None) -> _Analyst:
    agent = _Analyst(llm=model, name="static")
    agent.logger = logging.getLogger("test.no_default_limit")
    agent.tools = [_lookup()]
    agent.token_ledger = ledger if ledger is not None else TokenLedger()
    return agent


def _run(agent: _Analyst) -> str:
    with patch("maljan.agents.base_agent.loop_limits", return_value=(None, None)):
        return agent.execute_tool_loop([("system", "s"), ("human", TASK)])


def _records(agent: _Analyst) -> list[dict[str, Any]]:
    return list(agent.drain_budget_records())


class TestTheDefaultsAreNone:
    def test_loop_limits_reads_none_from_a_deployment_that_set_none(self) -> None:
        from maljan.core.config import Settings

        cfg = Settings(_env_file=None)
        with patch("maljan.agents.base_agent.get_settings", lambda: cfg):
            for agent in ("static", "dynamic", "network", "judge", "lead", "static_r2"):
                assert loop_limits(agent) == (None, None), agent

    def test_an_operator_s_value_still_wins(self) -> None:
        from maljan.core.config import Settings

        cfg = Settings(
            _env_file=None, react_agent_timeout=240, react_agent_max_steps_overrides={"judge": 7}
        )
        with patch("maljan.agents.base_agent.get_settings", lambda: cfg):
            assert loop_limits("judge") == (240, 7)
            assert loop_limits("static") == (240, None)

    def test_no_limit_is_an_unbounded_graph_and_no_hard_cap(self) -> None:
        assert recursion_limit(None) == sys.maxsize
        assert recursion_limit(12) == 12
        assert hard_cap(None) is None
        assert hard_cap(None, BudgetCeiling(None, None)) is None
        assert hard_cap(None, BudgetCeiling(4, 50.0, wall=50.0)) == 50.0
        assert limit_text(None, "s") == "none" and limit_text(180, "s") == "180s"

    def test_a_budget_with_no_limit_counts_nothing_down(self) -> None:
        budget = LoopBudget(None, None)
        assert budget.steps_left() is None and budget.seconds_left() is None
        assert budget.turns_left([]) is None and budget.deadline() is None
        assert budget.stated_turns([]) is NO_LIMIT and budget.stated_seconds() is NO_LIMIT
        assert model_turns_left(None, [AIMessage(content="x")]) is None


class TestTheRunStateSaysSoInWords:
    def test_no_limit_is_words_never_a_number(self) -> None:
        assert budget_line(NO_LIMIT, NO_LIMIT) == "budget remaining: no step limit, no time limit"
        assert budget_line(7, NO_LIMIT) == "budget remaining: 7 model turns, no time limit"
        assert budget_line(NO_LIMIT, 90.4) == "budget remaining: no step limit, 90 s"
        assert budget_line(None, None) == ""

    def test_the_rendered_block_carries_it(self) -> None:
        block = render_run_state({}, steps_left=NO_LIMIT, seconds_left=NO_LIMIT)
        assert block == "budget remaining: no step limit, no time limit"
        assert str(sys.maxsize) not in block


class TestALoopWithNoLimit:
    def test_runs_past_ten_steps_when_nothing_stops_it(self) -> None:
        agent = _analyst(_Model(calls=12, seen=[]))

        answer = _run(agent)

        (record,) = _records(agent)
        assert record["cap"] is None
        assert record["max_steps"] is None and record["timeout_s"] is None
        assert record["steps_used"] > 10, "twelve tool rounds are twenty-five steps"
        assert "it reads its own strings" in answer

    def test_ends_on_the_repeat_guard(self) -> None:
        agent = _analyst(_Model(calls=10_000, same=True, seen=[]))

        answer = _run(agent)

        (record,) = _records(agent)
        assert record["cap"] == "repeats"
        assert "it reads its own strings" in answer, "the salvage wrote up what it had"

    def test_ends_where_the_room_does(self) -> None:
        agent, model, _container, ran, ledger, answer = _run_out_of_room(
            _a_budget_that_runs_out(),
            max_steps=None,  # type: ignore[arg-type]
        )

        assert ledger.snapshot()["tool_output_no_room"] == 1
        assert len(ran) == 4
        assert len(_loop_turns(model)) < 10
        (record,) = _records(agent)
        assert record["cap"] == "no_room" and record["max_steps"] is None
        assert "reads its own strings" in answer

    def test_ends_at_the_spend_ceiling_and_writes_its_answer(self) -> None:
        model = _Model(calls=10_000, seen=[])
        name = model_name_of(model)
        # 10,000 input and 1,000 output tokens a turn at 1 USD and 10 USD per
        # million: two cents a turn, so a five-cent ceiling is met at the third.
        meter = SpendMeter(
            0.05,
            {name: {"input_usd_per_mtok": 1.0, "output_usd_per_mtok": 10.0}},
            table={},
        )
        # Every turn's worst case fits, so the running turns are what trip it.
        meter.worst_case = lambda *a, **k: 0.0  # type: ignore[method-assign]
        agent = _analyst(model, TokenLedger(spend=meter))

        answer = _run(agent)

        (record,) = _records(agent)
        assert record["cap"] == "spend"
        assert "it reads its own strings" in answer, "the salvage answered from what it had"
        loop_turns = [s for s in model.seen if TASK in str(s[-1].content) or len(s) > 2]
        assert len(loop_turns) < 10, "the ceiling ended the tool phase"
        assert meter.snapshot()["reached"] is True
        assert "spend ceiling of 0.0500 USD was reached" in meter.reason()

    def test_a_loop_that_would_start_past_the_ceiling_is_not_started(self) -> None:
        model = _Model(calls=10_000, seen=[])
        meter = SpendMeter(
            0.01,
            {model_name_of(model): {"input_usd_per_mtok": 1.0, "output_usd_per_mtok": 10.0}},
            table={},
        )
        meter.settle(USAGE, model_name_of(model))
        agent = _analyst(model, TokenLedger(spend=meter))

        answer = _run(agent)

        assert model.seen == [], "no call: past the ceiling only the verdict and report run"
        assert answer == ""
        (record,) = _records(agent)
        assert record["cap"] == "spend"

    def test_a_chunk_is_not_started_past_the_ceiling(self) -> None:
        from maljan.loaders.binary_chunker import ChunkStrategy, TextChunk

        model = _Model(calls=10_000, seen=[])
        meter = SpendMeter(
            0.01,
            {model_name_of(model): {"input_usd_per_mtok": 1.0, "output_usd_per_mtok": 10.0}},
            table={},
        )
        meter.settle(USAGE, model_name_of(model))
        agent = _analyst(model, TokenLedger(spend=meter))
        chunks = [
            TextChunk(
                index=i,
                total=2,
                strategy=ChunkStrategy.SLIDING_WINDOW,
                content="data",
                char_count=4,
                token_estimate=1,
                domain="static",
            )
            for i in range(2)
        ]
        import pytest

        from maljan.core.exceptions import AnalystError

        with pytest.raises(AnalystError, match="not started, the spend ceiling is reached"):
            agent.safe_analyze_isr_chunked(chunks)
        assert model.seen == []


class TestATurnPastTheWorstCase:
    def test_is_not_sent_and_the_loop_says_why(self) -> None:
        model = _Model(calls=10_000, seen=[])
        meter = SpendMeter(
            0.05,
            {model_name_of(model): {"input_usd_per_mtok": 1.0, "output_usd_per_mtok": 10.0}},
            table={},
        )
        meter.worst_case = lambda *a, **k: 1.0  # type: ignore[method-assign]
        agent = _analyst(model, TokenLedger(spend=meter))

        _run(agent)

        assert model.seen == [], "the first turn's worst case passes the ceiling"
        (record,) = _records(agent)
        assert record["cap"] == "spend"
        assert "loop turn call" in meter.snapshot()["held_calls"][0]

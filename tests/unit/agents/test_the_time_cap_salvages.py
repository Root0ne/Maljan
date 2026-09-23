"""The time budget ends a tool phase early enough to write the answer.

A 27B model on Ollama took about a hundred seconds a turn. Its static analyst
reached the 1,500 s budget at step 28 of 40 and was aborted: everything it had
gathered, including a correct reading of the sample's single-instance mutex,
went with it, because the step cap and a full window end the tool phase and
salvage, and the clock did neither. Thirty seconds of grace are a tenth of one
such turn.

Driven through the real loop with a stand-in model whose turns take a measured
time: the loop reads its own pace, ends the tool phase while what is left still
holds a turn and the final answer, writes the salvage from what was gathered
before the budget runs out, and records the cap as ``time``.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections.abc import Iterator
from typing import Any
from unittest.mock import patch

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import StructuredTool
from pydantic import BaseModel

from maljan.agents.base_agent import BaseAnalyst
from maljan.analysis.run_summary import RunSummaryBuilder
from maljan.llm import context_window as cw

TASK = "look at it"
CLAIM = (
    "CLAIM: the sample checks a mutex so only one copy runs\n"
    "EVIDENCE: ev_0001\nCONFIDENCE: 0.6\nTECHNIQUE: NONE"
)

# The stand-in's pace, and the budget: eight turns' worth of seconds.
TURN_SECONDS = 1.0
BUDGET_SECONDS = 8


class _SlowModel(BaseChatModel):
    """Asks for one more tool on every loop turn, each turn taking ``turn`` seconds.

    ``slow_turn`` makes that one turn take far longer than any before it, which
    is the case the reserve cannot see coming. Told to stop, it answers with
    the claim at its ordinary pace.
    """

    turn: float = TURN_SECONDS
    slow_turn: int = -1
    calls: list[list[BaseMessage]] = []

    def _generate(self, *_a: Any, **_k: Any) -> ChatResult:  # pragma: no cover
        raise NotImplementedError

    async def _agenerate(
        self, messages: Any, stop: Any = None, run_manager: Any = None, **_: Any
    ) -> ChatResult:
        sent = list(messages)
        self.calls.append(sent)
        told_to_stop = isinstance(sent[-1], HumanMessage) and TASK not in str(sent[-1].content)
        turn = sum(1 for message in sent if isinstance(message, AIMessage))
        await asyncio.sleep(self.turn * (30 if turn == self.slow_turn else 1))
        if told_to_stop:
            return ChatResult(generations=[ChatGeneration(message=AIMessage(content=CLAIM))])
        asked = AIMessage(
            content="Let me read a few more strings.",
            tool_calls=[{"name": "strings", "args": {"offset": turn}, "id": f"call_{turn}"}],
        )
        return ChatResult(generations=[ChatGeneration(message=asked)])

    @property
    def _llm_type(self) -> str:
        return "slow"

    def bind_tools(self, tools: Any, **_: Any) -> Any:
        return self


class _Container:
    def __init__(self) -> None:
        self.budget = cw.ContextBudget(
            cw.WindowFact(1_000_000, cw.PROBED, "test"), reply_tokens=8192
        )
        self.events: list[tuple[str, dict[str, Any]]] = []
        self.config = None

    def event_sink(self, event_type: str, data: dict[str, Any]) -> None:
        self.events.append((event_type, dict(data)))

    def get_context_budget(self) -> Any:
        return self.budget

    def get_server_registry(self) -> Any:
        return None


class _Analyst(BaseAnalyst):
    def analyze(self, data: str) -> str:  # pragma: no cover - not exercised
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover
        return ""


class _Offset(BaseModel):
    offset: int = 0


def _strings_tool() -> Any:
    async def _strings(offset: int = 0) -> str:
        return f"CreateMutexW at offset {offset}"

    return StructuredTool.from_function(
        coroutine=_strings,
        name="strings",
        description="strings",
        args_schema=_Offset,
        infer_schema=False,
    )


@contextlib.contextmanager
def _settings() -> Iterator[None]:
    with (
        patch("maljan.agents.base_agent.get_settings") as settings,
        # The salvage's floor is a minute in production; the stand-in's pace
        # is a second, so its floor is scaled with it.
        patch("maljan.agents.base_agent._SYNTHESIS_MIN_SECONDS", 1),
    ):
        cfg = settings.return_value
        cfg.react_agent_timeout = BUDGET_SECONDS
        cfg.react_agent_timeout_overrides = {}
        cfg.react_agent_max_steps = 80
        cfg.react_agent_max_steps_overrides = {}
        cfg.react_agent_tool_call_budget = 100
        cfg.llm.provider = "openai"
        cfg.llm.agents = {}
        cfg.llm.openai.context_size = 0
        cfg.reporting.evidence_budget_bytes = 0
        yield


def _run(model: _SlowModel) -> tuple[_Analyst, _Container, str, float]:
    agent = _Analyst(llm=model, name="static")
    agent.logger = logging.getLogger("test.time_cap")
    container = _Container()
    agent._container = container
    agent.tools = [_strings_tool()]
    started = time.monotonic()
    with _settings():
        answer = agent.execute_tool_loop([("system", "read the sample"), ("human", TASK)])
    return agent, container, answer, time.monotonic() - started


def _salvage_calls(model: _SlowModel) -> list[list[BaseMessage]]:
    return [
        sent
        for sent in model.calls
        if isinstance(sent[-1], HumanMessage) and TASK not in str(sent[-1].content)
    ]


class TestTheClockEndsTheToolPhaseInTime:
    def test_the_salvage_is_written_before_the_budget_runs_out(self) -> None:
        model = _SlowModel(calls=[])
        agent, container, answer, elapsed = _run(model)

        assert "only one copy runs" in answer, "the salvage wrote the answer"
        assert elapsed < BUDGET_SECONDS, f"{elapsed:.1f}s against a {BUDGET_SECONDS}s budget"
        salvage = _salvage_calls(model)
        assert len(salvage) >= 1
        gathered = [m for m in salvage[0] if isinstance(m, ToolMessage)]
        assert gathered, "the salvage was written from what was gathered"

    def test_the_loop_stops_while_a_turn_and_the_answer_still_fit(self) -> None:
        model = _SlowModel(calls=[])
        _agent, _container, _answer, _elapsed = _run(model)

        loop_turns = len(model.calls) - len(_salvage_calls(model))
        # Eight seconds hold eight one-second turns; the loop keeps the last
        # two and a half for one more turn and the final answer.
        assert 2 <= loop_turns < BUDGET_SECONDS

    def test_the_record_the_event_and_the_summary_say_time(self) -> None:
        model = _SlowModel(calls=[])
        agent, container, _answer, _elapsed = _run(model)

        records = agent.drain_budget_records()
        assert [row["cap"] for row in records] == ["time"]
        events = [data for kind, data in container.events if kind == "stage_ended_at_cap"]
        assert [data["cap"] for data in events] == ["time"]
        assert "kept for the final answer" in str(events[0].get("detail", ""))
        summary = RunSummaryBuilder(0.0).set_budget({"static": records}).build()
        assert summary.budget is not None
        assert summary.budget["static"]["caps"] == ["time"]


class TestATurnLongerThanAnySeen:
    def test_the_budget_reached_mid_turn_keeps_what_was_gathered(self) -> None:
        # The third turn takes thirty times as long as the two before it: the
        # budget runs out inside it. The analyst is not aborted and its record
        # says ``time``; the gathered evidence is not thrown away.
        model = _SlowModel(calls=[], slow_turn=2)
        agent, container, answer, elapsed = _run(model)

        assert elapsed < BUDGET_SECONDS + 5
        records = agent.drain_budget_records()
        assert [row["cap"] for row in records] == ["time"]
        assert len(agent.drain_evidence_entries()) >= 2, "the calls it made are kept"

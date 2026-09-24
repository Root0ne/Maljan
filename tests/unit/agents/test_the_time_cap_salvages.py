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
before the budget runs out, and records the cap as ``time``. The final answer
is sent a transcript a hosted provider accepts, the answer after it is given
only what the final-answer turn left, and a model list's switch is not counted
as the pace of the model that answered.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections.abc import Iterator
from typing import Any
from unittest.mock import patch

import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import StructuredTool
from pydantic import BaseModel

from maljan.agents.base_agent import FINAL_ANSWER_NUDGE, BaseAnalyst
from maljan.analysis.run_summary import RunSummaryBuilder
from maljan.llm import context_window as cw

TASK = "look at it"
CLAIM = (
    "CLAIM: the sample checks a mutex so only one copy runs\n"
    "EVIDENCE: ev_0001\nCONFIDENCE: 0.6\nTECHNIQUE: NONE"
)
PROSE = "The sample seems to check something before it runs."

# The stand-in's pace, and the budget: eight turns' worth of seconds.
TURN_SECONDS = 1.0
BUDGET_SECONDS = 8


class UnansweredToolCall(ValueError):
    """What Anthropic, OpenAI and Gemini answer a transcript with a call nothing answered."""


def _refuse_unanswered_calls(sent: list[BaseMessage]) -> None:
    """What reaches the wire, through the OpenAI client's own message formatter."""
    from langchain_openai.chat_models.base import _convert_message_to_dict

    wire = [_convert_message_to_dict(message) for message in sent]
    answered = {m.get("tool_call_id") for m in wire if m.get("role") == "tool"}
    for message in wire:
        for call in message.get("tool_calls") or []:
            if call.get("id") not in answered:
                raise UnansweredToolCall(f"HTTP 400: tool call {call.get('id')} has no result")


class _SlowModel(BaseChatModel):
    """Asks for one more tool on every loop turn, each turn taking ``turn`` seconds.

    Every call is checked the way a hosted provider checks it: a transcript
    with a tool call nothing answered is refused. ``slow_turn`` makes that
    one turn take thirty times as long; ``stall_from`` makes every turn from
    there on never answer. Told to write its final answer it answers
    ``salvage`` at its ordinary pace, synchronously or not; the final-answer
    nudge takes ``nudge_seconds``.
    """

    turn: float = TURN_SECONDS
    slow_turn: int = -1
    stall_from: int = -1
    salvage: str = CLAIM
    nudge_seconds: float = TURN_SECONDS
    calls: list[list[BaseMessage]] = []

    def _answer(self, messages: Any) -> tuple[float, AIMessage]:
        sent = list(messages)
        self.calls.append(sent)
        _refuse_unanswered_calls(sent)
        last = str(sent[-1].content) if isinstance(sent[-1], HumanMessage) else ""
        if last == FINAL_ANSWER_NUDGE:
            return self.nudge_seconds, AIMessage(content=CLAIM)
        if isinstance(sent[-1], HumanMessage) and TASK not in last:
            return self.turn, AIMessage(content=self.salvage)
        turn = sum(1 for message in sent if isinstance(message, AIMessage))
        if 0 <= self.stall_from <= turn:
            seconds = 1_000.0
        else:
            seconds = self.turn * (30 if turn == self.slow_turn else 1)
        # Shaped as the OpenAI client returns a tool-calling answer: the call
        # in ``tool_calls`` and again, raw, in ``additional_kwargs``.
        asked = AIMessage(
            content="Let me read a few more strings.",
            tool_calls=[{"name": "strings", "args": {"offset": turn}, "id": f"call_{turn}"}],
            additional_kwargs={
                "tool_calls": [
                    {
                        "id": f"call_{turn}",
                        "type": "function",
                        "function": {"name": "strings", "arguments": f'{{"offset": {turn}}}'},
                    }
                ]
            },
        )
        return seconds, asked

    def _generate(
        self, messages: Any, stop: Any = None, run_manager: Any = None, **_: Any
    ) -> ChatResult:
        seconds, message = self._answer(messages)
        time.sleep(seconds)
        return ChatResult(generations=[ChatGeneration(message=message)])

    async def _agenerate(
        self, messages: Any, stop: Any = None, run_manager: Any = None, **_: Any
    ) -> ChatResult:
        seconds, message = self._answer(messages)
        await asyncio.sleep(seconds)
        return ChatResult(generations=[ChatGeneration(message=message)])

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
def _settings(budget: int) -> Iterator[None]:
    with (
        patch("maljan.agents.base_agent.get_settings") as settings,
        # The salvage's floor is a minute in production; the stand-in's pace
        # is a second, so its floor is scaled with it.
        patch("maljan.agents.base_agent._SYNTHESIS_MIN_SECONDS", 1),
    ):
        cfg = settings.return_value
        cfg.react_agent_timeout = budget
        cfg.react_agent_timeout_overrides = {}
        cfg.react_agent_max_steps = 80
        cfg.react_agent_max_steps_overrides = {}
        cfg.react_agent_tool_call_budget = 100
        cfg.llm.provider = "openai"
        cfg.llm.agents = {}
        cfg.llm.openai.context_size = 0
        cfg.reporting.evidence_budget_bytes = 0
        yield


def _run(llm: Any, budget: int = BUDGET_SECONDS) -> tuple[_Analyst, _Container, str, float]:
    agent = _Analyst(llm=llm, name="static")
    agent.logger = logging.getLogger("test.time_cap")
    container = _Container()
    agent._container = container
    agent.tools = [_strings_tool()]
    started = time.monotonic()
    with _settings(budget):
        answer = agent.execute_tool_loop([("system", "read the sample"), ("human", TASK)])
    return agent, container, answer, time.monotonic() - started


def _final_answer_calls(model: _SlowModel) -> list[list[BaseMessage]]:
    return [
        sent
        for sent in model.calls
        if isinstance(sent[-1], HumanMessage) and TASK not in str(sent[-1].content)
    ]


def _cap_details(container: _Container) -> list[str]:
    return [
        str(data.get("detail", ""))
        for kind, data in container.events
        if kind == "stage_ended_at_cap"
    ]


class TestTheClockEndsTheToolPhaseInTime:
    def test_the_salvage_is_written_before_the_budget_runs_out(self) -> None:
        model = _SlowModel(calls=[])
        agent, container, answer, elapsed = _run(model)

        assert "only one copy runs" in answer, "the salvage wrote the answer"
        assert elapsed < BUDGET_SECONDS, f"{elapsed:.1f}s against a {BUDGET_SECONDS}s budget"
        salvage = _final_answer_calls(model)
        assert salvage, "the final-answer turn ran"
        gathered = [m for m in salvage[0] if isinstance(m, ToolMessage)]
        assert gathered, "the salvage was written from what was gathered"

    def test_the_loop_stops_while_a_turn_and_the_answer_still_fit(self) -> None:
        model = _SlowModel(calls=[])
        _run(model)

        loop_turns = len(model.calls) - len(_final_answer_calls(model))
        # Eight seconds hold eight one-second turns; the loop keeps the last
        # two and a half for one more turn and the final answer.
        assert 2 <= loop_turns < BUDGET_SECONDS

    def test_the_record_the_event_and_the_summary_say_time(self) -> None:
        agent, container, _answer, _elapsed = _run(_SlowModel(calls=[]))

        records = agent.drain_budget_records()
        assert [row["cap"] for row in records] == ["time"]
        details = _cap_details(container)
        assert len(details) == 1
        assert "kept for the final answer" in details[0]
        summary = RunSummaryBuilder(0.0).set_budget({"static": records}).build()
        assert summary.budget is not None
        assert summary.budget["static"]["caps"] == ["time"]


class TestTheFinalAnswerIsSentATranscriptAProviderAccepts:
    def test_the_last_turn_s_unrun_calls_go_and_its_text_stays(self) -> None:
        model = _SlowModel(calls=[])
        _agent, container, answer, _elapsed = _run(model)

        assert "only one copy runs" in answer, "the provider accepted the final-answer turn"
        sent = _final_answer_calls(model)[0]
        assert "Let me read a few more strings." in [str(m.content) for m in sent]
        assert "tool call(s) of the last turn were not run" in _cap_details(container)[0]


class TestTheAnswerAfterTheFinalTurnGetsOnlyWhatIsLeft:
    def test_the_nudge_is_given_what_the_salvage_left_and_no_more(self) -> None:
        # The salvage writes prose, so the nudge asks once more; the nudge's
        # answer would take five seconds. Handed the loop's own elapsed time it
        # got a second full remainder and the two ran past the budget.
        model = _SlowModel(calls=[], salvage=PROSE, nudge_seconds=5.0)
        _agent, _container, _answer, elapsed = _run(model)

        assert _final_answer_calls(model), "the final-answer turn ran"
        assert elapsed < BUDGET_SECONDS + 0.5, f"{elapsed:.1f}s against {BUDGET_SECONDS}s"


class TestAModelListSwitchIsNotThePaceOfTheModelThatAnswered:
    def _list(self) -> tuple[Any, _SlowModel, _SlowModel]:
        from maljan.llm.fallback import FallbackChatModel

        primary = _SlowModel(calls=[], stall_from=3)
        secondary = _SlowModel(calls=[])
        return (
            FallbackChatModel(
                models=[primary, secondary], labels=["primary", "secondary"], agent="static"
            ),
            primary,
            secondary,
        )

    def test_the_phase_runs_on_at_the_new_model_s_own_pace(self) -> None:
        llm, _primary, secondary = self._list()
        agent, container, answer, elapsed = _run(llm, budget=16)

        tool_calls = len(agent.drain_evidence_entries())
        # The stall costs half of what was left; the new model's one-second
        # turns then fill most of the rest, where counting the stall as its
        # pace ended the phase on the first turn after the switch.
        assert tool_calls >= 6, f"{tool_calls} tool calls kept"
        assert "only one copy runs" in answer
        assert elapsed < 16
        detail = _cap_details(container)[0]
        assert "the longest turn of secondary" in detail
        assert secondary.calls, "the new model wrote the rest"


class TestATurnLongerThanAnySeen:
    def test_the_budget_reached_mid_turn_keeps_what_was_gathered(self) -> None:
        # The third turn takes thirty times as long as the two before it: the
        # budget runs out inside it. The analyst is not aborted and its record
        # says ``time``; the gathered evidence is not thrown away.
        model = _SlowModel(calls=[], slow_turn=2)
        agent, _container, _answer, elapsed = _run(model)

        assert elapsed < BUDGET_SECONDS + 5
        records = agent.drain_budget_records()
        assert [row["cap"] for row in records] == ["time"]
        assert len(agent.drain_evidence_entries()) >= 2, "the calls it made are kept"


class TestTheReserve:
    """The pace's arithmetic, on the slow run's own numbers."""

    @staticmethod
    def _pace(turns: list[float], rate: float | None, model: str = "slow") -> Any:
        from maljan.agents.base_agent import TurnPace

        pace = TurnPace(lambda: rate)
        pace.turns[model] = list(turns)
        pace.current = model
        return pace

    def test_the_longest_turn_sets_it_where_no_rate_is_known(self) -> None:
        pace = self._pace([69, 70, 117, 240, 94], rate=None)

        assert pace.reserve() == 240 * 1.5
        assert pace.leaves_no_room_for(599) and not pace.leaves_no_room_for(601)

    def test_a_measured_rate_sizes_it_for_the_final_answer(self) -> None:
        from maljan.agents.base_agent import FINAL_ANSWER_EXPECTED_TOKENS

        pace = self._pace([100, 117], rate=3.8)

        assert pace.reserve() == FINAL_ANSWER_EXPECTED_TOKENS / 3.8 * 1.5

    def test_the_longest_turn_is_the_floor(self) -> None:
        # A thousand tokens at 3.8 a second is about 263 s; a 300 s turn is longer.
        pace = self._pace([69, 300], rate=3.8)

        assert pace.reserve() == 300 * 1.5

    def test_a_switch_turn_is_not_measured_and_nothing_is_decided_before_a_turn(self) -> None:
        from maljan.agents.base_agent import TurnPace
        from maljan.llm.fallback import FALLBACK_KEY, MODEL_KEY

        pace = TurnPace()
        switched = AIMessage(
            content="x", response_metadata={MODEL_KEY: "second", FALLBACK_KEY: "first: stalled"}
        )
        pace.note({"messages": [switched]})

        assert pace.current == "second"
        assert pace.turns == {}
        assert not pace.leaves_no_room_for(0.0)


class TestABudgetThatRanOutEmpty:
    def test_it_is_not_called_the_hard_cap(self) -> None:
        agent = _Analyst(llm=_SlowModel(calls=[], stall_from=0), name="static")
        agent.logger = logging.getLogger("test.time_cap")
        container = _Container()
        agent._container = container
        agent.tools = [_strings_tool()]
        with _settings(3), pytest.raises(TimeoutError):
            agent.execute_tool_loop([("system", "read the sample"), ("human", TASK)])

        details = _cap_details(container)
        assert details == ["the loop reached its 3s budget with nothing gathered"]

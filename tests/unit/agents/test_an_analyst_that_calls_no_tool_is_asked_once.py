"""An analyst with tools that answers without calling one is told so and asked once.

Four of seven analysts in two local runs answered in one turn with
``tool_calls=0``: offered 18 to 38 tools, they wrote their claims from the
triage pack. The platform now states the fact and the tools the analyst has,
and asks once, in the same conversation, whether it wants to call any before
its answer stands. The model decides: whatever it answers after the question
stands. The question is held to the same step, time and spend checks as the
final-answer question, and the loop's budget record, then the run summary's
``nudge``, say that it was asked and what followed.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any
from unittest.mock import patch

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import StructuredTool
from pydantic import BaseModel

from maljan.agents.base_agent import BaseAnalyst, BudgetCeiling, TurnPace
from maljan.agents.prompt_fragments import no_tool_call_question
from maljan.analysis.run_summary import RunSummaryBuilder, tool_asks_of
from maljan.core.spend import SpendCeilingStop
from maljan.llm.generation_rate import ModelCallDeadline

TASK = "look at it"
FIRST = "CLAIM: it reads its own strings\nEVIDENCE: pack\nCONFIDENCE: 0.6\nTECHNIQUE: NONE"
AFTER = "CLAIM: it decodes a table\nEVIDENCE: ev_0001\nCONFIDENCE: 0.7\nTECHNIQUE: NONE"
REPLY = "No tool call is needed; my answer above stands."


def _asked(sent: list[Any]) -> bool:
    return any(
        isinstance(m, HumanMessage) and "without calling any tool" in str(m.content) for m in sent
    )


class _Model(BaseChatModel):
    """Answers without a tool first; after the question, does what ``then`` says.

    ``then`` is ``"call"`` (one lookup, then an answer), ``"answer"`` (an
    answer with no call), ``"keep"`` (the one word KEEP), ``"reply"`` (a
    sentence that is not a report), ``"deadline"`` (the call's deadline),
    ``"full"`` (the server's full-window refusal) or ``"slow"`` (an answer
    slower than the loop's clock). ``first_calls`` makes it call a tool on its
    first turn instead.
    """

    then: str = "answer"
    first_calls: bool = False
    seen: list = []

    def _generate(
        self, messages: Any, stop: Any = None, run_manager: Any = None, **_: Any
    ) -> ChatResult:
        sent = list(messages)
        self.seen.append(sent)
        called = any(isinstance(m, ToolMessage) for m in sent)
        if self.first_calls and not called:
            turn = AIMessage(
                content="", tool_calls=[{"name": "lookup", "args": {"what": "a"}, "id": "c0"}]
            )
        elif _asked(sent) and self.then == "keep":
            turn = AIMessage(content=" keep. ")
        elif _asked(sent) and self.then == "marked_keep":
            turn = AIMessage(content="**KEEP**")
        elif _asked(sent) and self.then == "blocking":
            time.sleep(6)
            turn = AIMessage(content=AFTER)
        elif _asked(sent) and self.then == "reply":
            turn = AIMessage(content=REPLY)
        elif _asked(sent) and self.then == "deadline":
            raise ModelCallDeadline("the model request did not finish within its 5 s deadline")
        elif _asked(sent) and self.then == "full":
            raise _full_window()
        elif _asked(sent) and self.then == "call" and not called:
            turn = AIMessage(
                content="", tool_calls=[{"name": "lookup", "args": {"what": "b"}, "id": "c1"}]
            )
        elif _asked(sent) or called:
            turn = AIMessage(content=AFTER)
        else:
            turn = AIMessage(content=FIRST)
        return ChatResult(generations=[ChatGeneration(message=turn)])

    async def _agenerate(
        self, messages: Any, stop: Any = None, run_manager: Any = None, **kw: Any
    ) -> ChatResult:
        if self.then == "blocking":
            # A call that blocks its thread: cancelling the await does not end it.
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(
                None, lambda: self._generate(messages, stop, run_manager, **kw)
            )
        if self.then == "slow" and _asked(list(messages)):
            self.seen.append(list(messages))
            await asyncio.sleep(30)
        return self._generate(messages, stop, run_manager, **kw)

    @property
    def _llm_type(self) -> str:
        return "scripted"

    def bind_tools(self, tools: Any, **_: Any) -> Any:
        return self


def _full_window() -> Exception:
    import httpx
    from openai import BadRequestError

    request = httpx.Request("POST", "http://127.0.0.1:8080/v1/chat/completions")
    return BadRequestError(
        "the request exceeds the available context size",
        response=httpx.Response(400, request=request),
        body=None,
    )


class _What(BaseModel):
    what: str = ""


def _tool(name: str, ran: list[str]) -> StructuredTool:
    def _run(what: str = "") -> str:
        ran.append(what)
        return f"answer for {what}"

    return StructuredTool.from_function(
        func=_run, name=name, description="Look it up.", args_schema=_What, infer_schema=False
    )


class _Analyst(BaseAnalyst):
    def analyze(self, data: str) -> str:  # pragma: no cover - not exercised
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover
        return ""


def _analyst(model: _Model, ran: list[str]) -> _Analyst:
    model.seen = []
    agent = _Analyst(llm=model, name="triage")
    agent.logger = logging.getLogger("test.no_tool_call")
    agent.tools = [_tool("lookup", ran), _tool("strings", ran)]
    return agent


def _run(agent: _Analyst, limits: tuple[Any, Any] = (None, None)) -> str:
    with patch("maljan.agents.base_agent.loop_limits", return_value=limits):
        return agent.execute_tool_loop([("system", "s"), ("human", TASK)])


def _ask_record(agent: _Analyst) -> Any:
    rows = agent.drain_budget_records()
    return rows[-1].get("tool_ask") if rows else None


class TestTheQuestion:
    def test_it_states_the_fact_and_names_every_tool(self) -> None:
        text = no_tool_call_question(["strings", "lookup"])

        assert "without calling any tool" in text
        assert "lookup, strings" in text
        assert "reply with the single word KEEP" in text
        assert "your answer above stands as written" in text

    def test_it_is_asked_once_in_the_same_conversation_after_the_first_answer(self) -> None:
        ran: list[str] = []
        model = _Model(then="answer")
        agent = _analyst(model, ran)

        _run(agent)

        asked = [sent for sent in model.seen if _asked(sent)]
        assert len(model.seen) == 2
        assert len(asked) == 1
        conversation = asked[0]
        assert any(isinstance(m, AIMessage) and m.content == FIRST for m in conversation)
        question = [m for m in conversation if isinstance(m, HumanMessage)][-1]
        assert no_tool_call_question(["lookup", "strings"]) in str(question.content)


class TestTheModelDecides:
    def test_a_model_that_calls_a_tool_after_the_question_gets_it(self) -> None:
        ran: list[str] = []
        agent = _analyst(_Model(then="call"), ran)

        answer = _run(agent)

        assert ran == ["b"]
        assert answer.strip() == AFTER
        assert _ask_record(agent) == {"tool_calls_after": 1, "followed": "called_tools"}

    def test_a_model_that_calls_none_answers_again_and_that_answer_stands(self) -> None:
        ran: list[str] = []
        agent = _analyst(_Model(then="answer"), ran)

        answer = _run(agent)

        assert ran == []
        assert answer.strip() == AFTER
        assert _ask_record(agent) == {"tool_calls_after": 0, "followed": "answered_without_tools"}


class TestWhenItIsNotAsked:
    def test_a_loop_that_called_a_tool_is_not_asked(self) -> None:
        ran: list[str] = []
        model = _Model(first_calls=True)
        agent = _analyst(model, ran)

        _run(agent)

        assert not any(_asked(sent) for sent in model.seen)
        assert _ask_record(agent) is None

    def test_it_is_asked_once_per_analyst_not_once_per_loop(self) -> None:
        ran: list[str] = []
        model = _Model(then="answer")
        agent = _analyst(model, ran)

        _run(agent)
        model.seen = []
        _run(agent)

        assert not any(_asked(sent) for sent in model.seen)

    def test_an_analyst_that_called_tools_in_an_earlier_loop_is_not_asked(self) -> None:
        ran: list[str] = []
        model = _Model(first_calls=True)
        agent = _analyst(model, ran)
        _run(agent)

        model.first_calls = False
        model.seen = []
        _run(agent)

        assert not any(_asked(sent) for sent in model.seen)

    def test_no_turn_left_asks_nothing(self) -> None:
        ran: list[str] = []
        model = _Model(then="answer")
        agent = _analyst(model, ran)

        answer = _run(agent, limits=(None, 1))

        assert not any(_asked(sent) for sent in model.seen)
        assert answer.strip() == FIRST

    def test_no_time_left_asks_nothing(self) -> None:
        ran: list[str] = []
        model = _Model(then="answer")
        agent = _analyst(model, ran)

        with patch("maljan.agents.base_agent.LoopBudget.seconds_left", return_value=0.5):
            answer = _run(agent, limits=(60, None))

        assert not any(_asked(sent) for sent in model.seen)
        assert answer.strip() == FIRST

    def test_a_spend_ceiling_that_refuses_the_question_asks_nothing(self) -> None:
        ran: list[str] = []
        model = _Model(then="answer")
        agent = _analyst(model, ran)

        with patch.object(_Analyst, "_spend_refuses", return_value=True):
            answer = _run(agent)

        assert not any(_asked(sent) for sent in model.seen)
        assert answer.strip() == FIRST


class TestTheRunSummarySaysSo:
    def test_the_nudge_records_the_question_and_what_followed(self) -> None:
        records = {
            "triage": [
                {
                    "cap": None,
                    "tool_ask": {"tool_calls_after": 0, "followed": "answered_without_tools"},
                }
            ],
            "static": [{"cap": None}],
            "network": [
                {"cap": None},
                {"cap": None, "tool_ask": {"tool_calls_after": 3, "followed": "called_tools"}},
            ],
        }

        asks = tool_asks_of(records)
        summary = (
            RunSummaryBuilder(start_time=0.0).set_nudge({}, no_tool_call=asks).build().to_dict()
        )

        assert summary["nudge"] == {
            "no_tool_call": {
                "triage": [{"tool_calls_after": 0, "followed": "answered_without_tools"}],
                "network": [{"tool_calls_after": 3, "followed": "called_tools"}],
            }
        }

    def test_the_retry_modes_stay_beside_it(self) -> None:
        summary = (
            RunSummaryBuilder(start_time=0.0)
            .set_nudge({"static": "tool_choice_none"}, no_tool_call={})
            .build()
            .to_dict()
        )
        assert summary["nudge"] == {"retry_mode": {"static": "tool_choice_none"}}

    def test_a_run_with_neither_has_no_nudge(self) -> None:
        assert RunSummaryBuilder(start_time=0.0).set_nudge({}).build().to_dict()["nudge"] is None


class TestKeep:
    def test_the_one_word_keeps_the_first_answer_as_written(self) -> None:
        ran: list[str] = []
        agent = _analyst(_Model(then="keep"), ran)

        answer = _run(agent)

        assert answer.strip() == FIRST
        assert _ask_record(agent) == {"tool_calls_after": 0, "followed": "kept_first_answer"}

    def test_any_other_reply_stands_as_before(self) -> None:
        ran: list[str] = []
        agent = _analyst(_Model(then="reply"), ran)

        answer = _run(agent)

        assert FIRST not in answer
        assert REPLY in answer


class TestAWholeAnswerMustFit:
    def test_two_steps_are_needed_for_one_whole_turn(self) -> None:
        ran: list[str] = []
        model = _Model(then="answer")
        agent = _analyst(model, ran)

        answer = _run(agent, limits=(None, 2))

        assert not any(_asked(sent) for sent in model.seen)
        assert answer.strip() == FIRST

    def test_the_final_answer_reserve_must_be_left(self) -> None:
        ran: list[str] = []
        model = _Model(then="answer")
        agent = _analyst(model, ran)

        answer = _run(agent, limits=(30, None))

        assert not any(_asked(sent) for sent in model.seen)
        assert answer.strip() == FIRST

    def test_the_conversation_and_a_whole_answer_must_fit_the_window(self) -> None:
        ran: list[str] = []
        model = _Model(then="answer")
        agent = _analyst(model, ran)

        with patch.object(BaseAnalyst, "_fits_the_window", return_value=False):
            answer = _run(agent)

        assert not any(_asked(sent) for sent in model.seen)
        assert answer.strip() == FIRST


class TestNoAnswerLeavesTheFirstStanding:
    def _no_answer(self, agent: _Analyst) -> dict[str, Any]:
        record = _ask_record(agent)
        assert record is not None
        assert record["followed"] == "no_answer"
        assert record["why"]
        return record

    def test_the_spend_ceiling(self) -> None:
        ran: list[str] = []
        agent = _analyst(_Model(then="answer"), ran)
        admits = iter([None])

        def _admit(*_a: Any, **_k: Any) -> Any:
            try:
                return next(admits)
            except StopIteration:
                raise SpendCeilingStop("the job's spend ceiling is reached") from None

        with patch.object(_Analyst, "_spend_admits", side_effect=_admit):
            answer = _run(agent)

        assert answer.strip() == FIRST
        assert "spend ceiling" in self._no_answer(agent)["why"]

    def test_a_call_s_deadline(self) -> None:
        ran: list[str] = []
        agent = _analyst(_Model(then="deadline"), ran)

        answer = _run(agent)

        assert answer.strip() == FIRST
        assert "deadline" in self._no_answer(agent)["why"]

    def test_the_loop_s_clock(self) -> None:
        ran: list[str] = []
        agent = _analyst(_Model(then="slow"), ran)

        with patch.object(TurnPace, "reserve", return_value=0.1):
            answer = _run(agent, limits=(3, None))

        assert answer.strip() == FIRST
        assert "time" in self._no_answer(agent)["why"]

    def test_a_full_window(self) -> None:
        ran: list[str] = []
        agent = _analyst(_Model(then="full"), ran)

        answer = _run(agent)

        assert answer.strip() == FIRST
        assert "context window full" in self._no_answer(agent)["why"]


def test_calls_made_answering_another_agent_s_ask_do_not_count() -> None:
    ran: list[str] = []
    model = _Model(first_calls=True)
    agent = _analyst(model, ran)
    agent._budget_ceiling = BudgetCeiling(None, None)
    _run(agent)

    agent._budget_ceiling = None
    model.first_calls = False
    model.seen = []
    _run(agent)

    assert any(_asked(sent) for sent in model.seen)


def test_markdown_around_the_one_word_still_keeps_the_first_answer() -> None:
    ran: list[str] = []
    agent = _analyst(_Model(then="marked_keep"), ran)

    answer = _run(agent)

    assert answer.strip() == FIRST
    assert _ask_record(agent)["followed"] == "kept_first_answer"


def test_the_loop_s_clock_with_a_call_that_blocks_its_thread() -> None:
    ran: list[str] = []
    agent = _analyst(_Model(then="blocking"), ran)

    with patch.object(TurnPace, "reserve", return_value=0.1):
        answer = _run(agent, limits=(3, None))

    assert answer.strip() == FIRST
    record = _ask_record(agent)
    assert record["followed"] == "no_answer"
    assert "clock" in record["why"] or "time" in record["why"]


def test_the_loop_s_own_clock_ending_the_question_s_pass_leaves_the_first_answer() -> None:
    """The pass's own timeout did not fire first: the loop's clock ended it."""
    ran: list[str] = []
    agent = _analyst(_Model(then="slow"), ran)

    with patch("maljan.agents.base_agent.LoopBudget.seconds_left", return_value=None):
        answer = _run(agent, limits=(3, None))

    assert answer.strip() == FIRST
    record = _ask_record(agent)
    assert record["followed"] == "no_answer"
    assert "clock" in record["why"]

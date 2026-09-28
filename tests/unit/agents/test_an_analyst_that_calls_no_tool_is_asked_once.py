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

import logging
from typing import Any
from unittest.mock import patch

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import StructuredTool
from pydantic import BaseModel

from maljan.agents.base_agent import BaseAnalyst
from maljan.agents.prompt_fragments import no_tool_call_question
from maljan.analysis.run_summary import RunSummaryBuilder, tool_asks_of

TASK = "look at it"
FIRST = "CLAIM: it reads its own strings\nEVIDENCE: pack\nCONFIDENCE: 0.6\nTECHNIQUE: NONE"
AFTER = "CLAIM: it decodes a table\nEVIDENCE: ev_0001\nCONFIDENCE: 0.7\nTECHNIQUE: NONE"


def _asked(sent: list[Any]) -> bool:
    return any(
        isinstance(m, HumanMessage) and "without calling any tool" in str(m.content) for m in sent
    )


class _Model(BaseChatModel):
    """Answers without a tool first; after the question, does what ``then`` says.

    ``then`` is ``"call"`` (one lookup, then an answer) or ``"answer"`` (an
    answer with no call). ``first_calls`` makes it call a tool on its first
    turn instead.
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
        elif _asked(sent) and self.then == "call" and not called:
            turn = AIMessage(
                content="", tool_calls=[{"name": "lookup", "args": {"what": "b"}, "id": "c1"}]
            )
        elif _asked(sent) or called:
            turn = AIMessage(content=AFTER)
        else:
            turn = AIMessage(content=FIRST)
        return ChatResult(generations=[ChatGeneration(message=turn)])

    @property
    def _llm_type(self) -> str:
        return "scripted"

    def bind_tools(self, tools: Any, **_: Any) -> Any:
        return self


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
        assert "the answer you write next is the one that stands" in text

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

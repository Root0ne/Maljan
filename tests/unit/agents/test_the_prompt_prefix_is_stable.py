"""Each turn's request is the previous turn's, plus new turns, plus the current run state.

A provider's prefix cache (and a local server's reuse of what it has already
read) holds only while the front of a request is byte-identical to the front of
the one before it. The run-state block counts its budget down on every turn of
a tool loop, so it travels last: take it off a turn's request and what is left
is, byte for byte, the front of the next turn's request.

Checked on the serialized form a provider receives (OpenAI chat messages), for
every loop that sends the run state: an analyst's tool loop, the judge's tool
loop, and the retries the composer and the analyst's validation send.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from collections.abc import Iterator
from typing import Any
from unittest.mock import patch

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, HumanMessage, convert_to_openai_messages
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import StructuredTool
from pydantic import BaseModel

from maljan.agents.base_agent import BaseAnalyst
from maljan.agents.judge_agent import JudgeAgent
from maljan.pipeline.run_state import RUN_STATE_BEGIN, is_run_state_turn
from maljan.pipeline.triage_pack import PACK_HEADING
from maljan.pipeline.validation import Violation, retry_with_feedback

FACTS = f"{PACK_HEADING}\n[ev_0001] identity: pe windows"
RUN_STATE = "sample: c\nledger: 1 entries (ev_0001), 1 from the triage pack"
REPORT = "CLAIM: it reads a file\nEVIDENCE: ev_0002\nCONFIDENCE: 0.6\nTECHNIQUE: T1005\n"


class _Scripted(BaseChatModel):
    """Calls ``lookup`` for its first ``calls`` turns, then answers; records every request."""

    calls: int = 3
    answer: str = REPORT
    seen: list = []

    def _generate(
        self, messages: Any, stop: Any = None, run_manager: Any = None, **_: Any
    ) -> ChatResult:
        sent = list(messages)
        self.seen.append(sent)
        made = sum(1 for m in sent if isinstance(m, AIMessage) and m.tool_calls)
        if made < self.calls:
            turn = AIMessage(
                content="",
                tool_calls=[{"name": "lookup", "args": {"what": f"w{made}"}, "id": f"c{made}"}],
            )
        else:
            turn = AIMessage(content=self.answer)
        return ChatResult(generations=[ChatGeneration(message=turn)])

    @property
    def _llm_type(self) -> str:
        return "scripted"

    def bind_tools(self, tools: Any, **_: Any) -> Any:
        return self


class _What(BaseModel):
    what: str = ""


def _lookup_tool() -> StructuredTool:
    def _lookup(what: str = "") -> str:
        return f"answer for {what}"

    return StructuredTool.from_function(
        func=_lookup, name="lookup", description="Look it up.", args_schema=_What
    )


def _wire(messages: list[Any]) -> list[str]:
    """The request as a provider receives it, one serialized message per entry."""
    return [json.dumps(m, sort_keys=True) for m in convert_to_openai_messages(messages)]


def _without_the_trailing_block(messages: list[Any]) -> list[Any]:
    if messages and isinstance(messages[-1], HumanMessage):
        if is_run_state_turn(messages[-1].content):
            return messages[:-1]
    return messages


def _assert_each_request_extends_the_last(requests: list[list[Any]]) -> None:
    assert len(requests) >= 2, "a loop of one turn proves nothing about the next"
    for earlier, later in zip(requests, requests[1:], strict=False):
        head = _wire(_without_the_trailing_block(earlier))
        assert _wire(later)[: len(head)] == head
        assert len(_wire(later)) > len(head)


class _Analyst(BaseAnalyst):
    def __init__(self, llm: Any) -> None:
        super().__init__(llm=llm, name="static")

    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        return ""


class TestAnAnalystsToolLoop:
    def _run(self) -> list[list[Any]]:
        model = _Scripted(seen=[])
        agent = _Analyst(model)
        agent.facts_block = FACTS
        agent.run_state_block = RUN_STATE
        agent.tools = [_lookup_tool()]
        agent.execute_tool_loop([("system", "You are a static analyst."), ("human", "Analyse.")])
        return model.seen

    def test_every_turn_ends_on_the_current_block(self) -> None:
        requests = self._run()
        assert len(requests) == 4
        budgets = []
        for request in requests:
            assert is_run_state_turn(request[-1].content)
            assert sum(RUN_STATE_BEGIN in str(m.content) for m in request) == 1
            budgets.append(str(request[-1].content).split("budget remaining: ")[1].split(",")[0])
        # The line the block exists for still counts down, turn by turn.
        assert len(set(budgets)) == len(budgets)

    def test_each_request_is_the_last_one_plus_new_turns(self) -> None:
        _assert_each_request_extends_the_last(self._run())

    def test_the_system_turn_is_the_one_its_author_wrote(self) -> None:
        for request in self._run():
            assert request[0].content == "You are a static analyst."


@contextlib.contextmanager
def _judge_settings() -> Iterator[None]:
    with patch("maljan.agents.judge_agent.get_settings") as settings:
        cfg = settings.return_value
        cfg.react_agent_timeout = 600
        cfg.react_agent_max_steps = 40
        cfg.llm.provider = "openai"
        cfg.llm.agents = {}
        cfg.llm.openai.context_size = 0
        yield


class TestTheJudgesToolLoop:
    def test_each_request_is_the_last_one_plus_new_turns(self) -> None:
        from maljan.agents.judge_agent import _standing_blocks

        model = _Scripted(seen=[], answer="agreement_confidence: 0.8")
        judge = JudgeAgent(llm=model)
        judge.tools = [_lookup_tool()]
        human = f"{_standing_blocks(RUN_STATE, FACTS)}Expert Reports:\nstatic: text"
        with _judge_settings():
            asyncio.run(judge.execute_tool_loop([("system", "You mediate."), ("human", human)]))
        assert len(model.seen) == 4
        _assert_each_request_extends_the_last(model.seen)


class TestTheRetries:
    def test_a_composer_retry_extends_the_first_request(self) -> None:
        """The composer's retry is ``retry_with_feedback`` over its first request."""
        from langchain_core.messages import SystemMessage

        from maljan.pipeline.run_state import with_run_state

        first = [
            SystemMessage(content="You write one report section."),
            HumanMessage(content=f"{with_run_state('', RUN_STATE)}\n\n{FACTS}\n\nWrite it."),
        ]
        requests: list[list[Any]] = []

        async def _run(turns: list[Any]) -> Any:
            requests.append(list(turns))
            return AIMessage(content='{"text": "x"}')

        told = iter([[Violation(code="composer.schema", message="fix it")], []])
        asyncio.run(
            retry_with_feedback(_run, first, [lambda _p: next(told, [])], parse=lambda a: a.content)
        )
        assert len(requests) == 2
        _assert_each_request_extends_the_last(requests)

    def test_an_analysts_validation_retry_extends_the_framed_request(self) -> None:
        """Framed once, the block stays where it was put while the retry adds turns."""
        from maljan.agents.base_agent import frame_messages, prompt_to_messages

        framed = frame_messages(
            prompt_to_messages([("system", "You are a static analyst."), ("human", "evidence")]),
            facts_block=FACTS,
            run_state=RUN_STATE,
        )
        assert is_run_state_turn(framed[-1].content)
        requests: list[list[Any]] = []

        async def _run(turns: list[Any]) -> Any:
            requests.append(list(turns))
            return AIMessage(content=REPORT)

        told = iter([[Violation(code="isr.ungrounded_technique", message="cite")], []])
        asyncio.run(
            retry_with_feedback(
                _run, framed, [lambda _p: next(told, [])], parse=lambda a: a.content
            )
        )
        assert len(requests) == 2
        assert _wire(requests[1])[: len(requests[0])] == _wire(requests[0])

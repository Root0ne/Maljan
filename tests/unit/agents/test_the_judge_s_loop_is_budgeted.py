"""The judge's tool loop is sized against the window the way the analysts' is.

The judge's loop sent nothing to the context budget. Its answers were capped
against whatever conversation happened to be live, and by the time the judge
mediates, the analysts have finished and forgotten theirs, so every reputation
answer got the widest cap the window allows and nothing could say the room was
gone. A few large answers overflow a 32,768-token window, and a server that
refused the request failed the judge.

Driven through langgraph's own executor and the MCP toolkit's guardrail, with a
stand-in server that refuses, in llama's words, any request whose prompt and
reply would reach the window, counting the tool definitions it was sent.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import math
from collections.abc import Iterator
from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import openai
import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import StructuredTool
from pydantic import BaseModel

from maljan.agents.base_agent import _message_chars
from maljan.agents.judge_agent import JudgeAgent
from maljan.agents.mcp_client import MCPLangChainToolkit
from maljan.llm import context_window as cw

WINDOW = 32_768
REPLY = 8_192
REASONING = "Contradictions: none that the lookups support.\nagreement_confidence: 0.8"


class _Server(BaseChatModel):
    """A judge model behind a server with a real window.

    Asks for one more reputation lookup on every loop turn. A request is
    measured the way the server counts it — every message plus the tool
    definitions it was sent — at ``chars_per_token``, and refused with llama's
    sentence when it and the reply would reach the window. Told to stop, it
    writes its reasoning.
    """

    chars_per_token: float = 3.0
    definitions: int = 0
    largest: int = 0
    refused: int = 0

    def _generate(
        self, messages: Any, stop: Any = None, run_manager: Any = None, **_: Any
    ) -> ChatResult:
        sent = list(messages)
        weight = sum(_message_chars(m) for m in sent)
        if not _told_to_stop(sent):
            weight += self.definitions
        tokens = math.ceil(weight / self.chars_per_token)
        if tokens + REPLY >= WINDOW - 1:
            self.refused += 1
            request = httpx.Request("POST", "http://127.0.0.1:8080/v1/chat/completions")
            raise openai.InternalServerError(
                "Error code: 500 - {'error': {'message': 'context shift is disabled'}}",
                response=httpx.Response(500, request=request),
                body=None,
            )
        self.largest = max(self.largest, tokens)
        if _told_to_stop(sent):
            return ChatResult(generations=[ChatGeneration(message=AIMessage(content=REASONING))])
        turn = sum(1 for message in sent if isinstance(message, AIMessage))
        asked = AIMessage(
            content="Let me look this indicator up.",
            tool_calls=[
                {"name": "reputation", "args": {"indicator": f"i{turn}"}, "id": f"call_{turn}"}
            ],
        )
        return ChatResult(generations=[ChatGeneration(message=asked)])

    @property
    def _llm_type(self) -> str:
        return "server"

    def bind_tools(self, tools: Any, **_: Any) -> Any:
        self.definitions = cw.tool_definition_chars(tools)
        return self


def _told_to_stop(sent: list[BaseMessage]) -> bool:
    return isinstance(sent[-1], HumanMessage) and "Do NOT call any more tools" in str(
        sent[-1].content
    )


class _Container:
    def __init__(self, budget: Any) -> None:
        self.budget = budget
        self.events: list[tuple[str, dict[str, Any]]] = []
        self.config = None

    def event_sink(self, event_type: str, data: dict[str, Any]) -> None:
        self.events.append((event_type, dict(data)))

    def get_context_budget(self) -> Any:
        return self.budget

    def get_server_registry(self) -> Any:
        return None


class _Indicator(BaseModel):
    indicator: str = ""


def _a_large_reputation_answer(indicator: str) -> str:
    """A VirusTotal-shaped answer, tens of thousands of characters whole."""
    return json.dumps(
        {
            "id": indicator,
            "last_analysis_stats": {"malicious": 52, "undetected": 23},
            "detections": [
                {"engine": f"engine_{index}", "result": f"Trojan.Win64.Generic.{index:06d}"}
                for index in range(600)
            ],
        }
    )


def _judge(budget: Any, model: _Server) -> JudgeAgent:
    judge = JudgeAgent(llm=model)
    judge._container = _Container(budget)
    toolkit = MCPLangChainToolkit(context_budget=budget)

    async def _reputation(indicator: str = "") -> str:
        return await asyncio.to_thread(
            toolkit._apply_output_guardrail, _a_large_reputation_answer(indicator)
        )

    judge.tools = [
        StructuredTool.from_function(
            coroutine=_reputation,
            name="reputation",
            description="Look an indicator up.",
            args_schema=_Indicator,
            infer_schema=False,
        )
    ]
    return judge


@contextlib.contextmanager
def _settings() -> Iterator[None]:
    with patch("maljan.agents.judge_agent.get_settings") as settings:
        cfg = settings.return_value
        cfg.react_agent_timeout = 600
        cfg.react_agent_max_steps = 40
        cfg.llm.provider = "openai"
        cfg.llm.agents = {}
        cfg.llm.openai.context_size = 0
        yield


def _budget() -> cw.ContextBudget:
    return cw.ContextBudget(cw.WindowFact(WINDOW, cw.PROBED, "props"), reply_tokens=REPLY)


PROMPT = [("system", "You mediate. " + "s" * 3_000), ("human", "Expert reports: " + "r" * 10_000)]


def _loop(judge: JudgeAgent) -> str:
    with _settings():
        return asyncio.run(judge.execute_tool_loop(PROMPT))


class TestTheJudgeNeverReachesTheWindow:
    def test_several_large_lookups_end_on_the_budget_not_on_the_server(self) -> None:
        model = _Server(chars_per_token=3.0)
        judge = _judge(_budget(), model)

        reasoning = _loop(judge)

        assert model.refused == 0, "no request reached the window"
        assert model.largest + REPLY < WINDOW
        assert len(judge.drain_evidence_entries()) >= 2, "several lookups were made"
        records = judge.drain_budget_records()
        assert [row["cap"] for row in records] == ["no_room"]
        assert reasoning == REASONING, "the reasoning was written from what was gathered"

    def test_its_conversation_is_counted_under_its_own_name(self) -> None:
        budget = _budget()
        model = _Server(chars_per_token=3.0)
        judge = _judge(budget, model)
        seen: list[int] = []
        original = budget.note_conversation

        def _noted(agent: str, chars: int) -> None:
            if agent == "judge":
                seen.append(chars)
            original(agent, chars)

        with patch.object(budget, "note_conversation", _noted):
            _loop(judge)

        assert seen, "the judge's conversation reached the budget"
        assert seen[0] >= 13_000 + model.definitions, "its tool definitions are counted"
        assert budget.held_chars("judge") == 0, "and forgotten once the loop is over"


class TestAGenuineOverflowAfterGathering:
    def test_it_ends_the_tool_phase_and_the_verdict_is_still_reached(self) -> None:
        # Content that tokenises worse than the budget's three characters a
        # token, and no usage from the server: only the server can see it.
        model = _Server(chars_per_token=2.4)
        judge = _judge(_budget(), model)

        extracted: list[str] = []

        async def _extract(prompt: Any, reasoning: str) -> Any:
            extracted.append(reasoning)
            return judge._fallback_mediate(reasoning)

        with (
            _settings(),
            patch.object(judge, "_initialize_mcp_client", AsyncMock()),
            patch.object(judge, "_extract_mediator_verdict", _extract),
        ):
            argument, _consensus = asyncio.run(judge.mediate({"static": "r" * 10_000}, []))

        assert model.refused >= 1, "the server did refuse"
        records = judge.drain_budget_records()
        assert records[-1]["cap"] == "no_room"
        ended = [d for kind, d in judge._container.events if kind == "stage_ended_at_cap"]
        assert "reported its context window full" in ended[-1]["detail"]
        assert extracted == [REASONING], "the verdict was read from the salvaged reasoning"
        assert argument.confidence_score == pytest.approx(0.8)

    def test_an_overflow_before_anything_was_gathered_still_fails_the_judge(self) -> None:
        model = _Server(chars_per_token=0.5)
        judge = _judge(_budget(), model)

        with pytest.raises(openai.InternalServerError):
            _loop(judge)

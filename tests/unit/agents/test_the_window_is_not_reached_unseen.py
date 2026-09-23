"""A conversation cannot reach the served window while the budget says there is room.

A live static analyst on a 32,768-token window reached step 36 of 40 with the
budget holding 61,762 characters of conversation — 20,587 tokens at three
characters a token, inside the 24,576 the reply reserve leaves — and llama
answered HTTP 500 "context shift is disabled": prompt and reply together had
reached the window. The run said ``tool_output_no_room 0``, and the analyst's
work was lost with the exception.

What the count missed is what every request carries besides the messages: the
definitions of the loop's tools. That analyst had 35 of them; the two in-repo
servers it drew 29 from list 30 tools that serialise to 19,306 characters, so
more than a quarter of the tool budget was spent before the first message and
never counted. Counted now, the same conversation has no room; and where the
server reports what a request really weighed, that figure bounds the count from
below, so a characters-per-token figure that flatters the content cannot hide
the rest.

When a server says the window is full anyway, that is the conversation out of
room, not a crash: the tool phase ends with ``no_room`` and the salvage writes
the answer from what was gathered.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from collections.abc import Iterator
from typing import Any
from unittest.mock import patch

import httpx
import openai
import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.tools import StructuredTool
from pydantic import BaseModel, Field

from maljan.agents.base_agent import BaseAnalyst, LoopBudget
from maljan.agents.mcp_client import MCPLangChainToolkit
from maljan.llm import context_window as cw

# The recorded run: the window llama served and the reply reserve it was given.
WINDOW = 32_768
REPLY = 8_192
# What the budget held at the last tick before llama refused, step 36 of 40.
HELD_AT_STEP_36 = 61_762
# The sentence llama answered with.
CONTEXT_SHIFT = "Error code: 500 - {'error': {'code': 500, 'message': 'context shift is disabled'}}"

TASK = "look at it"
CLAIM = (
    "CLAIM: the sample reads its own strings\nEVIDENCE: ev_0001\nCONFIDENCE: 0.6\nTECHNIQUE: NONE"
)


def _budget() -> cw.ContextBudget:
    return cw.ContextBudget(cw.WindowFact(WINDOW, cw.PROBED, "props"), reply_tokens=REPLY)


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


class _Analyst(BaseAnalyst):
    def analyze(self, data: str) -> str:  # pragma: no cover - not exercised
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover
        return ""


def _analyst(budget: Any, llm: Any = None) -> _Analyst:
    agent = _Analyst(llm=llm, name="static")
    agent.logger = logging.getLogger("test.window")
    agent._container = _Container(budget)
    return agent


def _described_tools(count: int, description_chars: int) -> list[Any]:
    """``count`` tools whose definitions weigh what a sidecar's do.

    The analysis sidecar's descriptions run to several hundred characters each
    and its arguments carry their own; what is sized here is the definition the
    provider sends, not what the tool does.
    """

    class _Args(BaseModel):
        path: str = Field("", description="The file to read, as staged for this job.")
        offset: int = Field(0, description="Where to start, for a paged answer.")

    return [
        StructuredTool.from_function(
            func=lambda path="", offset=0: "",
            name=f"tool_{index}",
            description="d" * description_chars,
            args_schema=_Args,
            infer_schema=False,
        )
        for index in range(count)
    ]


def _conversation_of(chars: int) -> list[BaseMessage]:
    """A conversation the budget measures at exactly ``chars`` characters."""
    return [SystemMessage(content="s" * 4_000), HumanMessage(content="h" * (chars - 4_000))]


class TestTheToolDefinitionsAreCounted:
    def test_the_recorded_conversation_had_room_by_the_old_count(self) -> None:
        """The arithmetic the run was sized with, reproduced: the cap was not zero."""
        budget = _budget()
        budget.note_conversation("static", HELD_AT_STEP_36)

        assert budget.cap_without_recording("static") > 0
        assert HELD_AT_STEP_36 < budget.tool_budget_chars()

    def test_with_its_tools_counted_the_same_conversation_has_no_room(self) -> None:
        budget = _budget()
        agent = _analyst(budget)
        # 35 tools, about 600 characters of definition each: the order of the
        # 19,306 characters the two in-repo servers' 30 tools serialise to.
        agent._tool_definition_chars = cw.tool_definition_chars(_described_tools(35, 400))
        assert agent._tool_definition_chars > 19_000

        refresh = agent._run_state_refresher(40, 1500.0, 0.0, LoopBudget(40, 1500.0))
        refresh({"messages": _conversation_of(HELD_AT_STEP_36)})

        assert budget.held_chars("static") == HELD_AT_STEP_36 + agent._tool_definition_chars
        assert budget.cap_without_recording("static") == 0, "no room: the tool phase ends"

    def test_the_count_is_what_the_provider_sends(self) -> None:
        from langchain_core.utils.function_calling import convert_to_openai_tool

        tools = _described_tools(3, 50)
        expected = sum(
            len(json.dumps(convert_to_openai_tool(t), ensure_ascii=False)) for t in tools
        )
        assert cw.tool_definition_chars(tools) == expected

    def test_a_tool_that_cannot_be_described_costs_nothing_rather_than_failing(self) -> None:
        assert cw.tool_definition_chars([object()]) == 0


class TestWhatTheServerReportedBoundsTheCount:
    def test_a_reported_prompt_larger_than_the_measure_wins(self) -> None:
        """Strings of opcode noise tokenise worse than three characters a token.

        The server's own count for the last request is the truth about
        everything before the model's last turn; only what came after it is
        estimated.
        """
        budget = _budget()
        agent = _analyst(budget)
        reported = 25_000  # prompt tokens a server counted for the last request
        turn = AIMessage(
            content="Let me look for specific patterns.",
            tool_calls=[{"name": "strings", "args": {"pattern": "mutex"}, "id": "call_1"}],
            usage_metadata={"input_tokens": reported, "output_tokens": 40, "total_tokens": 25_040},
        )
        answer = ToolMessage(content="[ev_0030]\n" + "r" * 160, tool_call_id="call_1")
        messages = [*_conversation_of(HELD_AT_STEP_36 - 400), turn, answer]

        refresh = agent._run_state_refresher(40, 1500.0, 0.0, LoopBudget(40, 1500.0))
        refresh({"messages": messages})

        from maljan.agents.base_agent import _message_chars

        after = _message_chars(turn) + _message_chars(answer)
        assert budget.held_chars("static") == reported * cw.CHARS_PER_TOKEN + after
        assert budget.cap_without_recording("static") == 0

    def test_a_reported_prompt_smaller_than_the_measure_does_not_lower_it(self) -> None:
        budget = _budget()
        agent = _analyst(budget)
        turn = AIMessage(
            content="ok",
            usage_metadata={"input_tokens": 10, "output_tokens": 1, "total_tokens": 11},
        )
        messages = [*_conversation_of(30_000), turn]

        refresh = agent._run_state_refresher(40, 1500.0, 0.0, LoopBudget(40, 1500.0))
        refresh({"messages": messages})

        assert budget.held_chars("static") >= 30_000


class TestAServerThatSaysTheWindowIsFull:
    @pytest.mark.parametrize(
        "said",
        [
            CONTEXT_SHIFT,
            "the request exceeds the available context size, try increasing it",
            "This model's maximum context length is 32768 tokens",
        ],
    )
    def test_the_wordings_are_recognised(self, said: str) -> None:
        assert cw.window_reported_full(said) is True

    def test_an_unrelated_failure_is_not(self) -> None:
        assert cw.window_reported_full("Error code: 500 - {'error': 'model crashed'}") is False

    def test_the_tool_phase_ends_with_no_room_and_the_salvage_is_written(self) -> None:
        model = _RefusesAtTheFourthTurn(calls=[])
        agent, container, answer = _run(model)

        records = agent.drain_budget_records()
        assert [row["cap"] for row in records] == ["no_room"]
        ended = [data for kind, data in container.events if kind == "stage_ended_at_cap"]
        assert [data["cap"] for data in ended] == ["no_room"]
        assert "window" in ended[0]["detail"]
        salvage = [sent for sent in model.calls if _told_to_stop(sent)]
        assert salvage, "the salvage ran"
        assert sum(isinstance(m, ToolMessage) for m in salvage[0]) == 3, "over what was gathered"
        assert "the sample reads its own strings" in answer

    def test_any_other_failure_still_fails_the_analyst(self) -> None:
        from maljan.core.exceptions import AnalystError

        model = _RefusesAtTheFourthTurn(
            calls=[], said="Error code: 500 - {'error': 'model crashed'}"
        )
        with pytest.raises(AnalystError):
            _run(model)


def _told_to_stop(sent: list[BaseMessage]) -> bool:
    return isinstance(sent[-1], HumanMessage) and TASK not in str(sent[-1].content)


class _RefusesAtTheFourthTurn(BaseChatModel):
    """Asks for a tool on each loop turn; the server refuses the fourth."""

    said: str = CONTEXT_SHIFT
    calls: list[list[BaseMessage]] = []

    def _generate(
        self, messages: Any, stop: Any = None, run_manager: Any = None, **_: Any
    ) -> ChatResult:
        sent = list(messages)
        self.calls.append(sent)
        if _told_to_stop(sent):
            return ChatResult(generations=[ChatGeneration(message=AIMessage(content=CLAIM))])
        turn = sum(1 for message in sent if isinstance(message, AIMessage))
        if turn == 3:
            request = httpx.Request("POST", "http://127.0.0.1:8080/v1/chat/completions")
            raise openai.InternalServerError(
                self.said, response=httpx.Response(500, request=request), body=None
            )
        asked = AIMessage(
            content="Let me look for specific patterns.",
            tool_calls=[{"name": "strings", "args": {"offset": turn}, "id": f"call_{turn}"}],
        )
        return ChatResult(generations=[ChatGeneration(message=asked)])

    @property
    def _llm_type(self) -> str:
        return "refuses"

    def bind_tools(self, tools: Any, **_: Any) -> Any:
        return self


class _Offset(BaseModel):
    offset: int = 0


@contextlib.contextmanager
def _settings() -> Iterator[None]:
    with patch("maljan.agents.base_agent.get_settings") as settings:
        cfg = settings.return_value
        cfg.react_agent_timeout = 600
        cfg.react_agent_timeout_overrides = {}
        cfg.react_agent_max_steps = 40
        cfg.react_agent_max_steps_overrides = {}
        cfg.react_agent_tool_call_budget = 20
        cfg.llm.provider = "openai"
        cfg.llm.agents = {}
        cfg.llm.openai.context_size = 0
        cfg.reporting.evidence_budget_bytes = 0
        yield


def _run(model: BaseChatModel) -> tuple[_Analyst, _Container, str]:
    budget = _budget()
    agent = _analyst(budget, llm=model)
    toolkit = MCPLangChainToolkit(context_budget=budget)

    async def _strings(offset: int = 0) -> str:
        return await asyncio.to_thread(toolkit._apply_output_guardrail, "row\n" * 300)

    agent.tools = [
        StructuredTool.from_function(
            coroutine=_strings,
            name="strings",
            description="strings",
            args_schema=_Offset,
            infer_schema=False,
        )
    ]
    with _settings():
        answer = agent.execute_tool_loop([("system", "s"), ("human", TASK)])
    container = agent._container
    assert isinstance(container, _Container)
    return agent, container, answer

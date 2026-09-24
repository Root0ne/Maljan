"""DeepSeek's reasoning is kept on its assistant turn and sent back with it.

DeepSeek's thinking-mode guide: on a request that carries tools, the
``reasoning_content`` of every earlier assistant turn has to be passed back in
every later request, or the API answers 400. ``langchain-openai`` reads the
field out of no answer and writes it into no request. Under
``compat: deepseek`` the provider's chat class does both, exactly as returned;
every other dialect's body is left as langchain builds it.

Through a stand-in transport: the bodies read are the bodies the SDK would
have sent, and no request leaves the process.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import patch

import httpx
import pytest
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.tools import StructuredTool
from pydantic import BaseModel

from maljan.agents.base_agent import BaseAnalyst, nudge_turns
from maljan.core.config import Settings
from maljan.llm.openai_provider import OpenAIProvider, forget_standard_only
from maljan.pipeline.run_state import RUN_STATE_END, without_run_state_tail

HOSTED = "https://api.deepseek.com"
LOCAL = "http://127.0.0.1:8080/v1"
THOUGHT = "The user wants a lookup first.\n  Then an answer — keep “this” exactly."
REPORT = "CLAIM: it reads a file\nEVIDENCE: ev_0001\nCONFIDENCE: 0.6\nTECHNIQUE: T1005\n"


@pytest.fixture(autouse=True)
def _forget() -> Any:
    forget_standard_only()
    yield
    forget_standard_only()


class _DeepSeek:
    """Calls ``lookup`` until it has ``calls`` answers, thinking before each turn."""

    def __init__(self, calls: int = 1) -> None:
        self.calls = calls
        self.bodies: list[dict[str, Any]] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        self.bodies.append(body)
        done = sum(1 for m in body["messages"] if m.get("role") == "tool")
        message: dict[str, Any] = {
            "role": "assistant",
            "content": "" if done < self.calls else REPORT,
            "reasoning_content": f"{THOUGHT} ({done})",
        }
        if done < self.calls:
            message["content"] = None
            message["tool_calls"] = [
                {
                    "id": f"call_{done}",
                    "type": "function",
                    "function": {"name": "lookup", "arguments": json.dumps({"what": f"w{done}"})},
                }
            ]
        return httpx.Response(
            200,
            json={
                "id": f"r{len(self.bodies)}",
                "object": "chat.completion",
                "created": 0,
                "model": "deepseek-flash",
                "choices": [
                    {
                        "index": 0,
                        "message": message,
                        "finish_reason": "tool_calls" if done < self.calls else "stop",
                    }
                ],
                "usage": {
                    "prompt_tokens": 50,
                    "completion_tokens": 20,
                    "completion_tokens_details": {"reasoning_tokens": 12},
                },
            },
        )


def _model(wire: _DeepSeek, *, base_url: str | None = HOSTED, compat: str = "deepseek") -> Any:
    settings = Settings(
        _env_file=None,
        llm={"openai": {"api_key": "sk-test", "base_url": base_url, "compat": compat}},
    )
    transport = httpx.MockTransport(wire)
    return OpenAIProvider(settings).build_model(
        "deepseek-flash",
        0.0,
        max_tokens=64,
        http_client=httpx.Client(transport=transport),
        http_async_client=httpx.AsyncClient(transport=transport),
    )


class _What(BaseModel):
    what: str = ""


def _lookup() -> StructuredTool:
    return StructuredTool.from_function(
        func=lambda what="": f"answer for {what}",
        name="lookup",
        description="Look it up.",
        args_schema=_What,
    )


def _two_turns(model: Any) -> tuple[AIMessage, list[Any]]:
    bound = model.bind_tools([_lookup()])
    opening = [SystemMessage(content="sys"), HumanMessage(content="task")]
    first = bound.invoke(opening)
    call = first.tool_calls[0]
    bound.invoke([*opening, first, ToolMessage(content="answer", tool_call_id=call["id"])])
    return first, opening


class TestTheReasoningGoesBack:
    def test_it_is_kept_on_the_answer_exactly_as_returned(self) -> None:
        wire = _DeepSeek()
        first, _ = _two_turns(_model(wire))
        assert first.additional_kwargs["reasoning_content"] == f"{THOUGHT} (0)"
        # What the model wrote is what the message says.
        assert first.content == ""
        assert first.tool_calls[0]["name"] == "lookup"

    def test_the_second_request_carries_it_on_the_assistant_turn(self) -> None:
        wire = _DeepSeek()
        _two_turns(_model(wire))
        assistant = [m for m in wire.bodies[1]["messages"] if m["role"] == "assistant"]
        assert len(assistant) == 1
        assert assistant[0]["reasoning_content"] == f"{THOUGHT} (0)"
        assert assistant[0]["tool_calls"][0]["function"]["name"] == "lookup"
        # Only the assistant turn: no other message gains the field.
        others = [m for m in wire.bodies[1]["messages"] if m["role"] != "assistant"]
        assert all("reasoning_content" not in m for m in others)

    @pytest.mark.parametrize(
        ("base_url", "compat"),
        [(HOSTED, "auto"), (HOSTED, "standard"), (LOCAL, "llama_cpp"), (LOCAL, "auto")],
    )
    def test_no_other_dialect_sends_it(self, base_url: str, compat: str) -> None:
        wire = _DeepSeek()
        _two_turns(_model(wire, base_url=base_url, compat=compat))
        assistant = [m for m in wire.bodies[1]["messages"] if m["role"] == "assistant"]
        assert "reasoning_content" not in assistant[0]

    def test_the_reasoning_is_counted_where_the_provider_reports_it(self) -> None:
        from maljan.core.token_ledger import turn_usage

        first, _ = _two_turns(_model(_DeepSeek()))
        usage = turn_usage(first)
        assert usage is not None and usage["reasoning_tokens"] == 12

    def test_a_turn_the_nudge_rebuilds_keeps_its_reasoning(self) -> None:
        turn = AIMessage(
            content="Let me look.",
            additional_kwargs={"reasoning_content": THOUGHT, "tool_calls": [{"id": "x"}]},
            invalid_tool_calls=[{"name": "lookup", "args": "{", "id": "x", "error": "bad"}],
        )
        sendable, changed = nudge_turns([turn])
        assert changed
        assert sendable[0].additional_kwargs == {"reasoning_content": THOUGHT}


class _Analyst(BaseAnalyst):
    def __init__(self, llm: Any) -> None:
        super().__init__(llm=llm, name="static")

    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        return ""


class TestThroughTheAnalystsLoop:
    def test_every_later_request_carries_every_earlier_turn_s_reasoning_and_its_front(
        self,
    ) -> None:
        """The loop's real executor, the real provider model, three thinking turns."""
        wire = _DeepSeek(calls=2)
        agent = _Analyst(_model(wire))
        agent.run_state_block = "sample: c"
        agent.tools = [_lookup()]
        agent.execute_tool_loop([("system", "You are a static analyst."), ("human", "Analyse.")])
        assert len(wire.bodies) == 3
        last = wire.bodies[-1]["messages"]
        thoughts = [m.get("reasoning_content") for m in last if m["role"] == "assistant"]
        assert thoughts == [f"{THOUGHT} (0)", f"{THOUGHT} (1)"]
        # The run state ends the last message; without it, the request is the
        # next one's front, byte for byte, reasoning included.
        for earlier, later in zip(wire.bodies, wire.bodies[1:], strict=False):
            head = [dict(m) for m in earlier["messages"]]
            assert head[-1]["content"].endswith(RUN_STATE_END)
            head[-1]["content"] = without_run_state_tail(head[-1]["content"])
            assert later["messages"][: len(head)] == head
            roles = [m["role"] for m in later["messages"]]
            assert all(
                not (a == "user" and b == "user") for a, b in zip(roles, roles[1:], strict=False)
            )


class TestOnlyWhereItIsAskedFor:
    def test_a_request_without_tools_is_sent_without_it(self) -> None:
        """The guide: not needed without tools, and ignored if sent."""
        wire = _DeepSeek()
        model = _model(wire)
        said = AIMessage(content="an answer", additional_kwargs={"reasoning_content": THOUGHT})
        model.invoke([HumanMessage(content="task"), said, HumanMessage(content="and now?")])
        body = wire.bodies[0]
        assert "tools" not in body
        assert all("reasoning_content" not in m for m in body["messages"])

    def test_a_turn_that_does_not_line_up_is_said_rather_than_sent_silently(self) -> None:
        from maljan.llm import openai_provider

        model = _model(_DeepSeek())
        parent = type(model).__mro__[1]
        said = AIMessage(content="x", additional_kwargs={"reasoning_content": THOUGHT})

        def _one_message(*_a: Any, **_k: Any) -> dict[str, Any]:
            return {"messages": [{"role": "user", "content": "t"}], "tools": [1]}

        with (
            patch.object(parent, "_get_request_payload", _one_message),
            patch.object(openai_provider, "logger") as logger,
        ):
            payload = model._get_request_payload([HumanMessage(content="t"), said])
        assert logger.warning.called
        assert "reasoning_content" not in payload["messages"][0]


class TestTheCapBoundForOneCall:
    def test_it_reaches_deepseek_as_max_tokens(self) -> None:
        wire = _DeepSeek(calls=0)
        _model(wire).bind(max_tokens=7).invoke([HumanMessage(content="task")])
        assert wire.bodies[0]["max_tokens"] == 7
        assert wire.bodies[0]["max_completion_tokens"] == 7

    def test_the_model_s_own_cap_still_does(self) -> None:
        wire = _DeepSeek(calls=0)
        _model(wire).invoke([HumanMessage(content="task")])
        assert wire.bodies[0]["max_tokens"] == 64


class TestTheWindowCountsWhatIsSentBack:
    def test_a_turn_s_reasoning_is_part_of_its_size(self) -> None:
        from maljan.agents.base_agent import _message_chars

        bare = AIMessage(content="answer")
        thinking = AIMessage(content="answer", additional_kwargs={"reasoning_content": THOUGHT})
        assert _message_chars(thinking) == _message_chars(bare) + len(THOUGHT)

"""No request the platform sends carries a tool call without its reply.

A DeepSeek revision loop was refused with 400, "An assistant message with
'tool_calls' must be followed by tool messages responding to each
'tool_call_id'", and the analyst was lost for the round. A turn can hold a call
no tool ran — one whose arguments were cut mid-string sits in
``invalid_tool_calls``, which langgraph's tool node does not run and
langchain-openai still writes into the turn's ``tool_calls`` — so the next
request carried an unanswered id. Every OpenAI-compatible request now sends
such a call with a reply saying it was not run; the call itself stays in the
turn as the model wrote it.

Through a stand-in transport that refuses a malformed history the way DeepSeek
does: no request leaves the process.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.tools import StructuredTool
from pydantic import BaseModel

from maljan.agents.base_agent import BaseAnalyst
from maljan.core.config import Settings
from maljan.llm.openai_provider import (
    NO_REPLY_RECORDED,
    OpenAIProvider,
    answered_tool_calls,
    forget_standard_only,
)

HOSTED = "https://api.deepseek.com"
LOCAL = "http://127.0.0.1:8080/v1"
REPORT = "CLAIM: it reads a file\nEVIDENCE: [ev_0001]\nCONFIDENCE: 0.6\nTECHNIQUE: T1005\n"
REFUSAL = (
    "An assistant message with 'tool_calls' must be followed by tool messages "
    "responding to each 'tool_call_id'."
)


@pytest.fixture(autouse=True)
def _forget() -> Any:
    forget_standard_only()
    yield
    forget_standard_only()


def unanswered_ids(messages: list[dict[str, Any]]) -> list[str]:
    """Each call id no tool message right after its turn answers, as the server checks."""
    missing: list[str] = []
    for index, message in enumerate(messages):
        if message.get("role") != "assistant" or not message.get("tool_calls"):
            continue
        answered: set[str] = set()
        for later in messages[index + 1 :]:
            if later.get("role") != "tool":
                break
            answered.add(str(later.get("tool_call_id")))
        missing += [str(c["id"]) for c in message["tool_calls"] if str(c["id"]) not in answered]
    return missing


class _Strict:
    """A DeepSeek-shaped server: one turn with a whole call and a cut one, then a report."""

    def __init__(self) -> None:
        self.bodies: list[dict[str, Any]] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        self.bodies.append(body)
        if unanswered_ids(body["messages"]):
            return httpx.Response(
                400, json={"error": {"message": REFUSAL, "type": "invalid_request_error"}}
            )
        first = not any(m.get("role") == "tool" for m in body["messages"])
        message: dict[str, Any] = {
            "role": "assistant",
            "content": None if first else REPORT,
            "reasoning_content": "thinking",
        }
        if first:
            message["tool_calls"] = [
                {
                    "id": "call_whole",
                    "type": "function",
                    "function": {"name": "lookup", "arguments": json.dumps({"what": "a"})},
                },
                {
                    "id": "call_cut",
                    "type": "function",
                    # Cut inside the string: the repair refuses to guess its end.
                    "function": {"name": "lookup", "arguments": '{"what": "b'},
                },
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
                        "finish_reason": "tool_calls" if first else "stop",
                    }
                ],
                "usage": {"prompt_tokens": 50, "completion_tokens": 20},
            },
        )


def _model(wire: _Strict, *, base_url: str = HOSTED, compat: str = "deepseek") -> Any:
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


class _Analyst(BaseAnalyst):
    def __init__(self, llm: Any) -> None:
        super().__init__(llm=llm, name="static")

    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        return ""


@pytest.mark.parametrize(
    ("base_url", "compat"), [(HOSTED, "deepseek"), (HOSTED, "standard"), (LOCAL, "llama_cpp")]
)
def test_a_loop_whose_turn_holds_a_cut_call_sends_a_well_formed_history(
    base_url: str, compat: str
) -> None:
    wire = _Strict()
    agent = _Analyst(_model(wire, base_url=base_url, compat=compat))
    agent.run_state_block = "sample: c"
    agent.tools = [_lookup()]
    answer = agent.execute_tool_loop([("system", "You are a static analyst."), ("human", "Go.")])
    assert "CLAIM: it reads a file" in answer
    assert len(wire.bodies) == 2
    assert all(unanswered_ids(body["messages"]) == [] for body in wire.bodies)
    last = wire.bodies[-1]["messages"]
    turn = next(m for m in last if m["role"] == "assistant")
    # The model's turn is sent as it wrote it: both calls, cut arguments included.
    assert [c["id"] for c in turn["tool_calls"]] == ["call_whole", "call_cut"]
    replies = [m for m in last if m["role"] == "tool"]
    assert [r["tool_call_id"] for r in replies] == ["call_whole", "call_cut"]
    assert replies[1]["content"] == NO_REPLY_RECORDED
    if compat == "deepseek":
        assert turn["reasoning_content"] == "thinking"


def test_a_history_with_a_dangling_call_is_completed_on_the_deepseek_serializer() -> None:
    from langchain_core.messages import AIMessage, ToolMessage

    wire = _Strict()
    model = _model(wire).bind_tools([_lookup()])
    turn = AIMessage(
        content="",
        tool_calls=[
            {"name": "lookup", "args": {"what": "a"}, "id": "one", "type": "tool_call"},
            {"name": "lookup", "args": {"what": "b"}, "id": "two", "type": "tool_call"},
        ],
        additional_kwargs={"reasoning_content": "earlier"},
    )
    model.invoke(
        [
            SystemMessage(content="sys"),
            HumanMessage(content="task"),
            turn,
            ToolMessage(content="a's answer", tool_call_id="one"),
            HumanMessage(content="Write your report now."),
        ]
    )
    sent = wire.bodies[0]["messages"]
    assert unanswered_ids(sent) == []
    assert [m["role"] for m in sent] == ["system", "user", "assistant", "tool", "tool", "user"]
    assert sent[2]["reasoning_content"] == "earlier"
    assert sent[4] == {"role": "tool", "tool_call_id": "two", "content": NO_REPLY_RECORDED}


def _call(call_id: str) -> dict[str, Any]:
    return {"id": call_id, "type": "function", "function": {"name": "f", "arguments": "{}"}}


def test_a_well_formed_history_is_sent_as_it_was() -> None:
    messages = [
        {"role": "user", "content": "t"},
        {"role": "assistant", "content": None, "tool_calls": [_call("a"), _call("b")]},
        {"role": "tool", "tool_call_id": "a", "content": "1"},
        {"role": "tool", "tool_call_id": "b", "content": "2"},
    ]
    assert answered_tool_calls(messages) == (messages, 0)


def test_replies_are_put_in_call_order_and_one_that_answers_nothing_stays() -> None:
    messages = [
        {"role": "assistant", "content": None, "tool_calls": [_call("a"), _call("b")]},
        {"role": "tool", "tool_call_id": "b", "content": "2"},
        {"role": "tool", "tool_call_id": "z", "content": "stray"},
        {"role": "user", "content": "next"},
    ]
    out, written = answered_tool_calls(messages)
    assert written == 1
    assert [m.get("tool_call_id") for m in out[1:4]] == ["a", "b", "z"]
    assert out[1]["content"] == NO_REPLY_RECORDED
    assert out[-1] == {"role": "user", "content": "next"}

"""A DeepSeek answer read as a stream is the answer that was read whole.

DeepSeek streams ``delta.content`` and ``delta.reasoning_content``, tool calls
under ``delta.tool_calls[].index`` (one call's arguments split over several
chunks), a finish reason, and — with ``stream_options.include_usage`` — usage
that is null on every chunk but the last, which carries
``prompt_cache_hit_tokens`` and ``completion_tokens_details.reasoning_tokens``.
Read through the provider, the joined answer keeps all of it, and its
reasoning is sent back on the next request that carries tools.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from langchain_core.messages import HumanMessage, ToolMessage
from langchain_core.tools import StructuredTool

from maljan.core.config import Settings
from maljan.core.token_ledger import turn_usage
from maljan.llm.openai_provider import OpenAIProvider, forget_standard_only


@pytest.fixture(autouse=True)
def _forget() -> Any:
    forget_standard_only()
    yield
    forget_standard_only()


def _chunk(delta: dict[str, Any] | None, finish: str | None = None, **extra: Any) -> str:
    body: dict[str, Any] = {
        "id": "chatcmpl-1",
        "object": "chat.completion.chunk",
        "created": 0,
        "model": "deepseek-chat",
        "choices": [] if delta is None else [{"index": 0, "delta": delta, "finish_reason": finish}],
        "usage": None,
    }
    body.update(extra)
    return f"data: {json.dumps(body)}\n\n"


def _call(index: int, arguments: str, **head: Any) -> dict[str, Any]:
    function: dict[str, Any] = {"arguments": arguments}
    if "name" in head:
        function["name"] = head.pop("name")
    return {"tool_calls": [{"index": index, **head, "function": function}]}


USAGE = {
    "prompt_tokens": 1000,
    "completion_tokens": 300,
    "total_tokens": 1300,
    "prompt_cache_hit_tokens": 800,
    "prompt_cache_miss_tokens": 200,
    "completion_tokens_details": {"reasoning_tokens": 120},
}

STREAM = "".join(
    [
        _chunk({"role": "assistant", "content": None, "reasoning_content": "Think "}),
        _chunk({"reasoning_content": "more."}),
        _chunk({"content": "Calling."}),
        _chunk(_call(0, '{"q":', id="call_0", type="function", name="lookup")),
        _chunk(_call(0, ' "x"')),
        _chunk(_call(0, "}")),
        _chunk(
            _call(1, '{"url": "https://example.com/a"}', id="call_1", type="function", name="fetch")
        ),
        _chunk(_call(2, '{"q": "cut', id="call_2", type="function", name="lookup")),
        _chunk({}, "length"),
        _chunk(None, usage=USAGE),
        "data: [DONE]\n\n",
    ]
)

SECOND = "".join(
    [
        _chunk({"role": "assistant", "content": "Done."}),
        _chunk({}, "stop"),
        _chunk(None, usage=USAGE),
        "data: [DONE]\n\n",
    ]
)


def _tools() -> list[Any]:
    def lookup(q: str) -> str:
        """Look a value up."""
        return q

    def fetch(url: str) -> str:
        """Fetch a page."""
        return url

    return [
        StructuredTool.from_function(func=lookup, name="lookup"),
        StructuredTool.from_function(func=fetch, name="fetch"),
    ]


def _model(answers: list[str], bodies: list[dict[str, Any]]) -> Any:
    def _handle(request: httpx.Request) -> httpx.Response:
        bodies.append(json.loads(request.content))
        return httpx.Response(
            200,
            content=answers[len(bodies) - 1].encode(),
            headers={"content-type": "text/event-stream"},
        )

    settings = Settings(
        _env_file=None,
        llm={
            "openai": {
                "api_key": "not-a-key",
                "base_url": "https://api.deepseek.com",
                "compat": "deepseek",
            }
        },
    )
    model = OpenAIProvider(settings).build_model(
        "deepseek-chat",
        0.0,
        max_tokens=512,
        http_client=httpx.Client(transport=httpx.MockTransport(_handle)),
    )
    return model.bind_tools(_tools())


def test_the_streamed_answer_keeps_what_the_whole_one_had() -> None:
    bodies: list[dict[str, Any]] = []
    answer = _model([STREAM], bodies).invoke([HumanMessage(content="go")])

    assert bodies[0]["stream"] is True
    assert bodies[0]["stream_options"] == {"include_usage": True}
    assert answer.content == "Calling."
    assert answer.additional_kwargs["reasoning_content"] == "Think more."
    assert [(c["id"], c["name"], c["args"]) for c in answer.tool_calls] == [
        ("call_0", "lookup", {"q": "x"}),
        ("call_1", "fetch", {"url": "https://example.com/a"}),
    ]
    assert [c["id"] for c in answer.invalid_tool_calls] == ["call_2"]
    assert answer.response_metadata["finish_reason"] == "length"
    assert answer.usage_metadata["input_tokens"] == 1000
    assert answer.usage_metadata["output_tokens"] == 300


def test_its_usage_reads_the_cache_hits_and_the_reasoning() -> None:
    answer = _model([STREAM], []).invoke([HumanMessage(content="go")])

    usage = turn_usage(answer)

    assert usage is not None
    assert usage["cached_input_tokens"] == 800
    assert usage["reasoning_tokens"] == 120
    assert usage["sent_at"] > 0


def test_its_reasoning_is_sent_back_on_the_next_request_with_tools() -> None:
    bodies: list[dict[str, Any]] = []
    model = _model([STREAM, SECOND], bodies)
    first = model.invoke([HumanMessage(content="go")])

    model.invoke(
        [
            HumanMessage(content="go"),
            first,
            ToolMessage(content="x", tool_call_id="call_0"),
            ToolMessage(content="page", tool_call_id="call_1"),
        ]
    )

    assistant = [m for m in bodies[1]["messages"] if m.get("role") == "assistant"]
    assert [m.get("reasoning_content") for m in assistant] == ["Think more."]
    assert bodies[1]["stream"] is True

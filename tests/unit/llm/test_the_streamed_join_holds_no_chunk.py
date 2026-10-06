"""A streamed answer is joined as it arrives, holding no chunk, into the same answer as before.

Adding the chunks together rebuilt the joined text and reasoning on every
chunk, the square of the answer's length, and the call held every chunk until
the end. The join now keeps the text, the reasoning and each tool call's
arguments as pieces, joined once, and adds the rest of each chunk as it comes.
The answer is compared, field for field, with the join it replaced (kept here
as the reference) over every shape the streamed paths carry: llama.cpp's
running usage and per-chunk timings, DeepSeek's reasoning pieces and closing
usage, parallel, split, malformed and argument-less tool calls, and the finish
reason.
"""

from __future__ import annotations

import copy
import json
import time
from typing import Any

import pytest
from langchain_core.messages import AIMessageChunk

from maljan.core.config import Settings
from maljan.llm.openai_provider import (
    REASONING_CONTENT_KEY,
    OpenAIProvider,
    _Join,
    forget_standard_only,
)


@pytest.fixture(autouse=True)
def _forget() -> Any:
    forget_standard_only()
    yield
    forget_standard_only()


def _reference(chunks: list[Any], *, keep_reasoning: bool) -> Any:
    """The join this one replaced, as it was."""
    from langchain_core.messages import AIMessage
    from langchain_core.output_parsers.openai_tools import make_invalid_tool_call, parse_tool_call
    from langchain_core.outputs import ChatGeneration, ChatResult

    last_usage = max(
        (i for i, c in enumerate(chunks) if getattr(c.message, "usage_metadata", None)),
        default=None,
    )
    for index, chunk in enumerate(chunks):
        if index != last_usage and getattr(chunk.message, "usage_metadata", None):
            chunk.message.usage_metadata = None
    for key in ("token_usage", "timings"):
        last = max(
            (i for i, c in enumerate(chunks) if key in (c.generation_info or {})), default=None
        )
        for index, chunk in enumerate(chunks):
            info = chunk.generation_info
            if index != last and info and key in info:
                chunk.generation_info = {k: v for k, v in info.items() if k != key} or None
    for chunk in chunks:
        if not keep_reasoning:
            chunk.message.additional_kwargs.pop(REASONING_CONTENT_KEY, None)
        chunk.message.response_metadata = {
            **(chunk.generation_info or {}),
            **chunk.message.response_metadata,
        }
    joined = chunks[0]
    for chunk in chunks[1:]:
        joined += chunk
    merged = joined.message
    tool_calls: list[Any] = []
    invalid: list[Any] = []
    for piece in getattr(merged, "tool_call_chunks", None) or []:
        raw = {
            "id": piece.get("id"),
            "type": "function",
            "function": {"name": piece.get("name") or "", "arguments": piece.get("args") or ""},
        }
        try:
            parsed = parse_tool_call(raw, return_id=True)
        except Exception as exc:  # noqa: BLE001
            invalid.append(make_invalid_tool_call(raw, str(exc)))
            continue
        if parsed is not None:
            tool_calls.append(parsed)
    message = AIMessage(
        content=merged.content,
        additional_kwargs=dict(merged.additional_kwargs),
        response_metadata=dict(merged.response_metadata),
        id=merged.id,
        tool_calls=tool_calls,
        invalid_tool_calls=invalid,
        usage_metadata=merged.usage_metadata,
    )
    return ChatResult(
        generations=[ChatGeneration(message=message, generation_info=joined.generation_info)]
    )


def _raw(delta: dict[str, Any] | None, finish: str | None = None, **extra: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "id": "chatcmpl-1",
        "object": "chat.completion.chunk",
        "created": 0,
        "model": "m",
        "choices": [] if delta is None else [{"index": 0, "delta": delta, "finish_reason": finish}],
    }
    body.update(extra)
    return body


def _call(index: int, arguments: str, **head: Any) -> dict[str, Any]:
    function: dict[str, Any] = {"arguments": arguments}
    if "name" in head:
        function["name"] = head.pop("name")
    return {"tool_calls": [{"index": index, **head, "function": function}]}


def _usage(n: int, **more: Any) -> dict[str, Any]:
    return {"prompt_tokens": 120, "completion_tokens": n, "total_tokens": 120 + n, **more}


_TIMINGS = {"prompt_n": 120, "prompt_ms": 400.0, "predicted_n": 3, "predicted_ms": 1500.0}

SHAPES: dict[str, tuple[str, list[dict[str, Any]]]] = {
    "llama text, running usage and timings on every chunk": (
        "llama_cpp",
        [
            _raw({"role": "assistant", "content": None}, usage=_usage(1)),
            *[
                _raw({"content": piece}, usage=_usage(n), timings={**_TIMINGS, "predicted_n": n})
                for n, piece in enumerate(["do", "n", "e"], start=2)
            ],
            _raw({}, "stop"),
            _raw(None, usage=_usage(3), timings=_TIMINGS),
        ],
    ),
    "llama reasoning left out": (
        "llama_cpp",
        [
            _raw({"role": "assistant", "content": None, "reasoning_content": "think "}),
            _raw({"reasoning_content": "more"}),
            _raw({"content": "answer"}),
            _raw({}, "stop"),
            _raw(None, usage=_usage(4)),
        ],
    ),
    "llama tool calls: parallel, malformed, no arguments": (
        "llama_cpp",
        [
            _raw({"role": "assistant", "content": None}),
            _raw(_call(0, '{"q": ', id="call-1", type="function", name="lookup")),
            _raw(_call(0, '"x"}')),
            _raw(_call(1, "{not json}", id="call-2", type="function", name="fetch")),
            _raw(_call(2, "", id="call-3", type="function", name="ping")),
            _raw({}, "tool_calls"),
            _raw(None, usage=_usage(9)),
        ],
    ),
    "deepseek reasoning, split calls, length, closing usage": (
        "deepseek",
        [
            _raw({"role": "assistant", "content": None, "reasoning_content": "Think "}, usage=None),
            _raw({"reasoning_content": "more."}, usage=None),
            _raw({"content": "Calling."}, usage=None),
            _raw(_call(0, '{"q":', id="call_0", type="function", name="lookup"), usage=None),
            _raw(_call(0, ' "x"'), usage=None),
            _raw(_call(0, "}"), usage=None),
            _raw(
                _call(1, '{"url": "https://example.com/a"}', id="call_1", name="fetch"),
                usage=None,
            ),
            _raw(_call(2, '{"q": "cut', id="call_2", type="function", name="lookup"), usage=None),
            _raw({}, "length", usage=None),
            _raw(
                None,
                usage=_usage(
                    300,
                    prompt_cache_hit_tokens=80,
                    completion_tokens_details={"reasoning_tokens": 120},
                ),
            ),
        ],
    ),
    "content only, no usage": (
        "deepseek",
        [_raw({"role": "assistant", "content": ""}), _raw({"content": "a"}), _raw({}, "stop")],
    ),
}


def _model(compat: str) -> Any:
    base_url = "http://127.0.0.1:8080/v1" if compat == "llama_cpp" else "https://api.deepseek.com"
    settings = Settings(
        _env_file=None,
        llm={"openai": {"api_key": "not-a-key", "base_url": base_url, "compat": compat}},
    )
    return OpenAIProvider(settings).build_model("m", 0.0, max_tokens=512)


def _chunks(compat: str, raws: list[dict[str, Any]]) -> list[Any]:
    model = _model(compat)
    out = []
    for raw in raws:
        chunk = model._convert_chunk_to_generation_chunk(copy.deepcopy(raw), AIMessageChunk, {})
        if chunk is not None:
            out.append(chunk)
    return out


@pytest.mark.parametrize("name", sorted(SHAPES))
def test_the_join_is_the_join_it_replaced(name: str) -> None:
    compat, raws = SHAPES[name]
    keep = compat == "deepseek"
    join = _Join(keep_reasoning=keep)
    for chunk in _chunks(compat, raws):
        join.add(chunk)
    got = join.result()
    want = _reference(_chunks(compat, raws), keep_reasoning=keep)

    got_message, want_message = got.generations[0].message, want.generations[0].message
    assert got_message.content == want_message.content
    assert got_message.additional_kwargs == want_message.additional_kwargs
    assert got_message.response_metadata == want_message.response_metadata
    assert got_message.tool_calls == want_message.tool_calls
    assert got_message.invalid_tool_calls == want_message.invalid_tool_calls
    assert got_message.usage_metadata == want_message.usage_metadata
    assert got_message.id == want_message.id
    assert got.generations[0].generation_info == want.generations[0].generation_info


def _stream_chunks(count: int) -> list[Any]:
    model = _model("deepseek")
    raws = [_raw({"role": "assistant", "content": "", "reasoning_content": "r"})]
    raws += [_raw({"content": "four", "reasoning_content": "four"}) for _ in range(count)]
    raws += [_raw({}, "stop"), _raw(None, usage=_usage(count))]
    return [model._convert_chunk_to_generation_chunk(raw, AIMessageChunk, {}) for raw in raws]


def _seconds_to_join(count: int) -> float:
    chunks = _stream_chunks(count)
    join = _Join(keep_reasoning=True)
    started = time.process_time()
    for chunk in chunks:
        join.add(chunk)
    result = join.result()
    elapsed = time.process_time() - started
    assert len(result.generations[0].message.content) == 4 * count
    return elapsed


def test_four_times_the_chunks_cost_about_four_times_the_time() -> None:
    short = _seconds_to_join(5_000)
    long = _seconds_to_join(20_000)

    assert long < short * 4 * 2.5


def test_a_chunk_is_not_held_once_joined() -> None:
    import gc
    import weakref

    chunks = _stream_chunks(50)
    seen = weakref.ref(chunks[10])
    join = _Join(keep_reasoning=True)
    for chunk in chunks:
        join.add(chunk)
    del chunks, chunk
    gc.collect()

    assert seen() is None
    assert json.dumps(join.result().generations[0].message.content)


def _ollama_parts(count: int = 3) -> list[dict[str, Any]]:
    parts: list[dict[str, Any]] = [
        {"model": "m", "message": {"role": "assistant", "content": "", "thinking": "Think "}},
        {"model": "m", "message": {"role": "assistant", "content": "", "thinking": "more."}},
    ]
    parts += [
        {"model": "m", "message": {"role": "assistant", "content": f"piece {n} "}}
        for n in range(count)
    ]
    parts.append(
        {
            "model": "m",
            "message": {
                "role": "assistant",
                "content": "",
                "tool_calls": [{"function": {"name": "lookup", "arguments": {"q": "x"}}}],
            },
        }
    )
    parts.append(
        {
            "model": "m",
            "message": {"role": "assistant", "content": ""},
            "done": True,
            "done_reason": "stop",
            "prompt_eval_count": 12,
            "eval_count": 7,
        }
    )
    return parts


def _ollama(parts: list[dict[str, Any]]) -> Any:
    from maljan.llm.ollama_provider import OllamaProvider

    model = OllamaProvider(Settings(_env_file=None)).build_model("m", 0.0, reasoning=True)

    def _sync(*_args: Any, **_kwargs: Any) -> Any:
        yield from copy.deepcopy(parts)

    async def _async(*_args: Any, **_kwargs: Any) -> Any:
        for part in copy.deepcopy(parts):
            yield part

    object.__setattr__(model, "_create_chat_stream", _sync)
    object.__setattr__(model, "_acreate_chat_stream", _async)
    return model


def _same_chunk(got: Any, want: Any) -> None:
    assert got.text == want.text
    assert got.message.content == want.message.content
    assert got.message.additional_kwargs == want.message.additional_kwargs

    # Ollama's client names each call with a fresh random id.
    def _calls(chunk: Any) -> list[Any]:
        return [{**call, "id": None} for call in chunk.message.tool_calls]

    assert _calls(got) == _calls(want)
    assert got.message.usage_metadata == want.message.usage_metadata
    assert got.generation_info == want.generation_info


def test_an_ollama_answer_is_joined_as_chat_ollama_joins_it() -> None:
    from langchain_ollama import ChatOllama

    model = _ollama(_ollama_parts())
    got = model._chat_stream_with_aggregation([], None, None)
    want = ChatOllama._chat_stream_with_aggregation(model, [], None, None)

    assert got.message.additional_kwargs["reasoning_content"] == "Think more."
    assert [call["name"] for call in got.message.tool_calls] == ["lookup"]
    _same_chunk(got, want)


@pytest.mark.asyncio
async def test_an_async_ollama_answer_is_joined_as_chat_ollama_joins_it() -> None:
    from langchain_ollama import ChatOllama

    model = _ollama(_ollama_parts())
    got = await model._achat_stream_with_aggregation([], None, None)
    want = await ChatOllama._achat_stream_with_aggregation(model, [], None, None)

    _same_chunk(got, want)


def test_four_times_an_ollama_answer_costs_about_four_times_the_time() -> None:
    def _seconds(count: int) -> float:
        model = _ollama(_ollama_parts(count))
        started = time.process_time()
        model._chat_stream_with_aggregation([], None, None)
        return time.process_time() - started

    short = _seconds(4_000)
    long = _seconds(16_000)

    assert long < short * 4 * 2.5


def _as_sent(chunk: Any) -> Any:
    return (copy.deepcopy(chunk.message.model_dump()), copy.deepcopy(chunk.generation_info))


@pytest.mark.parametrize("name", sorted(SHAPES))
def test_a_chunk_the_callbacks_were_handed_is_left_as_sent(name: str) -> None:
    compat, raws = SHAPES[name]
    chunks = _chunks(compat, raws)
    sent = [_as_sent(chunk) for chunk in chunks]
    join = _Join(keep_reasoning=compat == "deepseek")
    for chunk in chunks:
        join.add(chunk)
    join.result()

    assert [_as_sent(chunk) for chunk in chunks] == sent


def test_an_ollama_chunk_the_callbacks_were_handed_is_left_as_sent() -> None:
    from langchain_core.outputs import ChatGenerationChunk

    from maljan.llm.ollama_provider import _OllamaJoin

    chunks = [
        ChatGenerationChunk(
            message=AIMessageChunk(content="", additional_kwargs={"reasoning_content": "Think "})
        ),
        ChatGenerationChunk(message=AIMessageChunk(content="piece ")),
        ChatGenerationChunk(message=AIMessageChunk(content="two"), generation_info={"done": True}),
    ]
    sent = [_as_sent(chunk) for chunk in chunks]
    join = _OllamaJoin()
    for chunk in chunks:
        join.add(chunk)
    got = join.result().message

    assert [_as_sent(chunk) for chunk in chunks] == sent
    assert got.content == "piece two"
    assert got.additional_kwargs["reasoning_content"] == "Think "


def _content_chunks(contents: list[Any]) -> list[Any]:
    from langchain_core.outputs import ChatGenerationChunk

    return [
        ChatGenerationChunk(message=AIMessageChunk(content=copy.deepcopy(content), id="run-1"))
        for content in contents
    ]


_LIST_PIECE = [{"type": "text", "text": "listed"}]
CONTENT_SHAPES: dict[str, list[Any]] = {
    "text, then a list, then text": ["one ", "two ", _LIST_PIECE, " three", " four"],
    "a list first, then text": [_LIST_PIECE, "after ", "more"],
    "text between two lists": ["a", _LIST_PIECE, "b", "c", [{"type": "text", "text": "x"}], "d"],
    "text only": ["a", "b", "c"],
}


@pytest.mark.parametrize("name", sorted(CONTENT_SHAPES))
def test_text_pieces_keep_their_place_beside_content_that_is_not_a_string(name: str) -> None:
    contents = CONTENT_SHAPES[name]
    join = _Join()
    for chunk in _content_chunks(contents):
        join.add(chunk)
    got = join.result().generations[0].message.content
    want = _reference(_content_chunks(contents), keep_reasoning=False)

    assert got == want.generations[0].message.content


@pytest.mark.parametrize("name", sorted(CONTENT_SHAPES))
def test_an_ollama_join_keeps_text_beside_content_that_is_not_a_string(name: str) -> None:
    from maljan.llm.ollama_provider import _OllamaJoin

    join = _OllamaJoin()
    for chunk in _content_chunks(CONTENT_SHAPES[name]):
        join.add(chunk)
    want = _content_chunks(CONTENT_SHAPES[name])
    joined = want[0]
    for chunk in want[1:]:
        joined += chunk

    assert join.result().message.content == joined.message.content

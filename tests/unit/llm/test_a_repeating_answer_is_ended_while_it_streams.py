"""A streamed answer that repeats its claims past the margin is ended while it streams.

The repeated-claims check used to read only the finished answer, so a model
writing the same claims again ran to its output cap first. Read while the
answer streams, the same rule ends the call once the margin is crossed: no
further piece is read, the stream is closed, and the answer is everything the
model wrote up to there. The caller's check on the finished answer then reads
it as it reads any other.

Synthetic streams only: a llama.cpp server, DeepSeek and Ollama, each answering
with claims written again and again for as long as they are read.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Iterator
from typing import Any

import httpx
import pytest
from langchain_core.messages import HumanMessage

from maljan.core.config import Settings
from maljan.llm.openai_provider import OpenAIProvider, forget_standard_only
from maljan.llm.stream_watch import current_rule, watched, watching
from maljan.pipeline.validation import claims_repeated

FIRST = (
    "CLAIM: it reads its configuration from the resource section\n"
    "EVIDENCE: ev_0003\nCONFIDENCE: 0.7\nTECHNIQUE: T1027\n\n"
)
SECOND = (
    "CLAIM: it resolves its imports by hash\n"
    "EVIDENCE: ev_0004\nCONFIDENCE: 0.8\nTECHNIQUE: T1027.007\n\n"
)
# What one model wrote before it began writing its claims again.
WRITTEN = FIRST + SECOND
# How long a runaway answer runs here when nothing ends it: finite, so a
# stream that is not ended fails its test rather than hanging it.
RUNAWAY_LINES = 2000


def _lines(text: str) -> list[str]:
    return text.splitlines(keepends=True)


def _runaway_pieces() -> Iterator[str]:
    """The two claims, then both again, line by line, for as long as they are read."""
    yield from _lines(WRITTEN)
    while True:
        yield from _lines(WRITTEN)


def _rule(margin: int | None = None) -> Any:
    def _stop(text: str) -> str | None:
        found = claims_repeated(text, margin)
        return None if found is None else f"{found.repeated} repeated claims"

    return _stop


@pytest.fixture(autouse=True)
def _forget() -> Any:
    forget_standard_only()
    yield
    forget_standard_only()


def _sse(body: dict[str, Any]) -> bytes:
    return f"data: {json.dumps(body)}\n\n".encode()


def _chunk(delta: dict[str, Any], **extra: Any) -> bytes:
    return _sse(
        {
            "id": "chatcmpl-1",
            "object": "chat.completion.chunk",
            "created": 0,
            "model": "m",
            "choices": [{"index": 0, "delta": delta, "finish_reason": None}],
            **extra,
        }
    )


class _Server:
    """An OpenAI-compatible server streaming the runaway answer, counting what was read."""

    def __init__(self, *, reasoning: bool = False, limit: int = RUNAWAY_LINES) -> None:
        self.read = 0
        self.bodies: list[dict[str, Any]] = []
        self.reasoning = reasoning
        self.limit = limit
        self.closed = False

    def _parts(self) -> Iterator[bytes]:
        opening: dict[str, Any] = {"role": "assistant", "content": ""}
        if self.reasoning:
            opening["reasoning_content"] = "First the configuration."
        yield _chunk(opening)
        try:
            for index, line in enumerate(_runaway_pieces()):
                if index >= self.limit:
                    break
                self.read += 1
                yield _chunk({"content": line})
            closing = {
                "id": "chatcmpl-1",
                "object": "chat.completion.chunk",
                "created": 0,
                "model": "m",
                "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
            }
            yield _sse(closing)
            yield b"data: [DONE]\n\n"
        finally:
            self.closed = True

    def sync(self, request: httpx.Request) -> httpx.Response:
        self.bodies.append(json.loads(request.content))
        return httpx.Response(
            200, content=self._parts(), headers={"content-type": "text/event-stream"}
        )

    def asynchronous(self, request: httpx.Request) -> httpx.Response:
        self.bodies.append(json.loads(request.content))
        parts = self._parts()

        async def _body() -> AsyncIterator[bytes]:
            for part in parts:
                yield part

        return httpx.Response(200, content=_body(), headers={"content-type": "text/event-stream"})


def _settings(base_url: str, compat: str) -> Settings:
    return Settings(
        _env_file=None,
        llm={"openai": {"api_key": "not-a-key", "base_url": base_url, "compat": compat}},
    )


_ENDPOINTS = [
    pytest.param("http://127.0.0.1:8080/v1", "llama_cpp", id="llama.cpp"),
    pytest.param("https://api.deepseek.com", "deepseek", id="deepseek"),
]


def _model(server: _Server, base_url: str, compat: str) -> Any:
    return OpenAIProvider(_settings(base_url, compat)).build_model(
        "m",
        0.0,
        max_tokens=512,
        http_client=httpx.Client(transport=httpx.MockTransport(server.sync)),
        http_async_client=httpx.AsyncClient(transport=httpx.MockTransport(server.asynchronous)),
    )


def _assert_ended_after_the_margin(content: str, server: _Server) -> None:
    # Everything written before the repetition is in the answer, and the
    # answer goes on only to the line on which the margin was crossed.
    assert content.startswith(WRITTEN)
    found = claims_repeated(content)
    assert found is not None
    assert claims_repeated(content[: content.rstrip("\n").rfind("\n") + 1]) is None
    # The call was ended: the transport reads a little ahead of the answer
    # (its buffer, the reader thread's queue), never the whole runaway.
    assert server.read < RUNAWAY_LINES // 10


class TestTheOpenAICompatibleStreams:
    @pytest.mark.parametrize(("base_url", "compat"), _ENDPOINTS)
    def test_a_sync_call_is_ended_once_the_margin_is_crossed(
        self, base_url: str, compat: str
    ) -> None:
        server = _Server()
        with watching(_rule()):
            answer = _model(server, base_url, compat).invoke([HumanMessage(content="go")])

        _assert_ended_after_the_margin(str(answer.content), server)

    @pytest.mark.parametrize(("base_url", "compat"), _ENDPOINTS)
    @pytest.mark.asyncio
    async def test_an_async_call_is_ended_once_the_margin_is_crossed(
        self, base_url: str, compat: str
    ) -> None:
        server = _Server()
        with watching(_rule()):
            answer = await _model(server, base_url, compat).ainvoke([HumanMessage(content="go")])

        _assert_ended_after_the_margin(str(answer.content), server)

    @pytest.mark.parametrize(("base_url", "compat"), _ENDPOINTS)
    def test_the_operator_s_margin_is_the_one_read(self, base_url: str, compat: str) -> None:
        server = _Server()
        with watching(_rule(0)):
            answer = _model(server, base_url, compat).invoke([HumanMessage(content="go")])

        content = str(answer.content)
        assert content.startswith(WRITTEN)
        found = claims_repeated(content, 0)
        assert found is not None and found.repeated == 1

    @pytest.mark.parametrize(("base_url", "compat"), _ENDPOINTS)
    def test_without_a_rule_the_answer_is_read_to_its_end(self, base_url: str, compat: str) -> None:
        server = _Server(limit=40)
        answer = _model(server, base_url, compat).invoke([HumanMessage(content="go")])

        assert server.read == 40
        assert answer.response_metadata["finish_reason"] == "stop"

    @pytest.mark.parametrize(("base_url", "compat"), _ENDPOINTS)
    def test_an_answer_within_the_margin_is_read_to_its_end(
        self, base_url: str, compat: str
    ) -> None:
        # The answer written twice is within the derived margin.
        server = _Server(limit=len(_lines(WRITTEN)) * 2)
        with watching(_rule()):
            answer = _model(server, base_url, compat).invoke([HumanMessage(content="go")])

        assert str(answer.content) == WRITTEN * 2
        assert answer.response_metadata["finish_reason"] == "stop"


class TestDeepSeekStreams:
    def test_a_deepseek_request_is_streamed_with_its_usage(self) -> None:
        server = _Server(limit=4)
        _model(server, "https://api.deepseek.com", "deepseek").invoke([HumanMessage(content="go")])

        assert server.bodies[0]["stream"] is True
        assert server.bodies[0]["stream_options"] == {"include_usage": True}

    def test_its_reasoning_is_kept_on_the_streamed_answer(self) -> None:
        server = _Server(reasoning=True, limit=4)
        answer = _model(server, "https://api.deepseek.com", "deepseek").invoke(
            [HumanMessage(content="go")]
        )

        assert answer.additional_kwargs["reasoning_content"] == "First the configuration."

    def test_a_llama_cpp_answer_still_leaves_its_reasoning_out(self) -> None:
        server = _Server(reasoning=True, limit=4)
        answer = _model(server, "http://127.0.0.1:8080/v1", "llama_cpp").invoke(
            [HumanMessage(content="go")]
        )

        assert "reasoning_content" not in answer.additional_kwargs

    def test_another_hosted_api_is_still_read_whole(self) -> None:
        seen: list[dict[str, Any]] = []

        def _handle(request: httpx.Request) -> httpx.Response:
            seen.append(json.loads(request.content))
            return httpx.Response(
                200,
                json={
                    "id": "chatcmpl-1",
                    "object": "chat.completion",
                    "created": 0,
                    "model": "m",
                    "choices": [
                        {
                            "index": 0,
                            "message": {"role": "assistant", "content": WRITTEN},
                            "finish_reason": "stop",
                        }
                    ],
                },
            )

        model = OpenAIProvider(_settings("https://api.example.org/v1", "auto")).build_model(
            "m", 0.0, http_client=httpx.Client(transport=httpx.MockTransport(_handle))
        )
        with watching(_rule()):
            assert model.invoke([HumanMessage(content="go")]).content == WRITTEN
        assert not seen[0].get("stream")


class _OllamaParts:
    """What an Ollama server streams for the runaway answer, counting what was read."""

    def __init__(self) -> None:
        self.read = 0

    def parts(self) -> Iterator[dict[str, Any]]:
        for index, line in enumerate(_runaway_pieces()):
            if index >= RUNAWAY_LINES:
                break
            self.read += 1
            yield {"model": "m", "message": {"role": "assistant", "content": line}, "done": False}


def _ollama(parts: _OllamaParts) -> Any:
    from maljan.llm.ollama_provider import OllamaProvider

    model = OllamaProvider(Settings(_env_file=None)).build_model("m", 0.0, max_tokens=512)

    def _sync(*_args: Any, **_kwargs: Any) -> Iterator[dict[str, Any]]:
        yield from parts.parts()

    async def _async(*_args: Any, **_kwargs: Any) -> AsyncIterator[dict[str, Any]]:
        for part in parts.parts():
            yield part

    object.__setattr__(model, "_create_chat_stream", _sync)
    object.__setattr__(model, "_acreate_chat_stream", _async)
    return model


class TestOllamaStreams:
    def test_a_sync_call_is_ended_once_the_margin_is_crossed(self) -> None:
        parts = _OllamaParts()
        with watching(_rule()):
            answer = _ollama(parts).invoke([HumanMessage(content="go")])

        content = str(answer.content)
        assert content.startswith(WRITTEN)
        assert claims_repeated(content) is not None
        assert parts.read < RUNAWAY_LINES // 10

    @pytest.mark.asyncio
    async def test_an_async_call_is_ended_once_the_margin_is_crossed(self) -> None:
        parts = _OllamaParts()
        with watching(_rule()):
            answer = await _ollama(parts).ainvoke([HumanMessage(content="go")])

        content = str(answer.content)
        assert content.startswith(WRITTEN)
        assert claims_repeated(content) is not None
        assert parts.read < RUNAWAY_LINES // 10


class TestTheRuleIsTheCaller_s:
    def test_no_rule_outside_a_watched_block(self) -> None:
        assert current_rule() is None
        with watching(_rule()):
            assert current_rule() is not None
        assert current_rule() is None

    def test_a_rule_that_fails_never_ends_an_answer(self) -> None:
        def _broken(_text: str) -> str | None:
            raise ValueError("unreadable")

        class _Piece:
            def __init__(self, text: str) -> None:
                self.content = text

        with watching(_broken):
            read = list(watched(iter([_Piece("a\n"), _Piece("b\n")])))
        assert len(read) == 2

    def test_the_rule_reaches_a_task_started_inside_the_block(self) -> None:
        async def _inside() -> bool:
            return current_rule() is not None

        async def _outer() -> bool:
            with watching(_rule()):
                return await asyncio.create_task(_inside())

        assert asyncio.run(_outer()) is True

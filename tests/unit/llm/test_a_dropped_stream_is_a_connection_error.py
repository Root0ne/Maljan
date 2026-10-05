"""A connection that drops while an answer streams is the connection error a whole answer's is.

The SDK reads a whole answer inside its request and states a transport failure
as ``openai.APIConnectionError``, which the analyst's loop replays and
``retry_on_connection_error`` retries. A streamed answer is read after the
request returned, so the same failure came out as the transport's own class
and neither retry saw it. On every streamed path (llama.cpp, DeepSeek, Ollama)
a transport failure that is not a timeout is raised as
``openai.APIConnectionError``, the failure as its cause. A timeout keeps its
own reading (the call's deadline).
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Iterator
from typing import Any

import httpx
import openai
import pytest
from langchain_core.messages import HumanMessage

from maljan.core.config import Settings
from maljan.llm.generation_rate import as_connection_error
from maljan.llm.openai_provider import OpenAIProvider, forget_standard_only


@pytest.fixture(autouse=True)
def _forget() -> Any:
    forget_standard_only()
    yield
    forget_standard_only()


def _chunk(text: str) -> bytes:
    body = {
        "id": "chatcmpl-1",
        "object": "chat.completion.chunk",
        "created": 0,
        "model": "m",
        "choices": [{"index": 0, "delta": {"content": text}, "finish_reason": None}],
    }
    return f"data: {json.dumps(body)}\n\n".encode()


def _dropping(request: httpx.Request) -> Iterator[bytes]:
    yield _chunk("CLAIM: it reads a file\n")
    raise httpx.RemoteProtocolError("peer closed connection", request=request)


def _settings(base_url: str, compat: str) -> Settings:
    return Settings(
        _env_file=None,
        llm={"openai": {"api_key": "not-a-key", "base_url": base_url, "compat": compat}},
    )


def _model(base_url: str, compat: str) -> Any:
    def _sync(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, content=_dropping(request), headers={"content-type": "text/event-stream"}
        )

    def _async(request: httpx.Request) -> httpx.Response:
        parts = _dropping(request)

        async def _body() -> AsyncIterator[bytes]:
            for part in parts:
                yield part

        return httpx.Response(200, content=_body(), headers={"content-type": "text/event-stream"})

    return OpenAIProvider(_settings(base_url, compat)).build_model(
        "m",
        0.0,
        max_tokens=512,
        http_client=httpx.Client(transport=httpx.MockTransport(_sync)),
        http_async_client=httpx.AsyncClient(transport=httpx.MockTransport(_async)),
    )


_ENDPOINTS = [
    pytest.param("http://127.0.0.1:8080/v1", "llama_cpp", id="llama.cpp"),
    pytest.param("https://api.deepseek.com", "deepseek", id="deepseek"),
]


def _assert_connection_error(error: BaseException) -> None:
    assert isinstance(error, openai.APIConnectionError)
    assert not isinstance(error, openai.APITimeoutError)
    causes = []
    current: BaseException | None = error
    while current is not None:
        causes.append(type(current).__name__)
        current = current.__cause__
    assert "RemoteProtocolError" in causes


class TestTheOpenAICompatibleStreams:
    @pytest.mark.parametrize(("base_url", "compat"), _ENDPOINTS)
    def test_a_sync_drop_mid_stream(self, base_url: str, compat: str) -> None:
        with pytest.raises(openai.APIConnectionError) as caught:
            _model(base_url, compat).invoke([HumanMessage(content="go")])
        _assert_connection_error(caught.value)

    @pytest.mark.parametrize(("base_url", "compat"), _ENDPOINTS)
    @pytest.mark.asyncio
    async def test_an_async_drop_mid_stream(self, base_url: str, compat: str) -> None:
        with pytest.raises(openai.APIConnectionError) as caught:
            await _model(base_url, compat).ainvoke([HumanMessage(content="go")])
        _assert_connection_error(caught.value)


def _ollama(failure: BaseException) -> Any:
    from maljan.llm.ollama_provider import OllamaProvider

    model = OllamaProvider(Settings(_env_file=None)).build_model("m", 0.0, max_tokens=512)

    def _sync(*_args: Any, **_kwargs: Any) -> Iterator[dict[str, Any]]:
        yield {"model": "m", "message": {"role": "assistant", "content": "CLAIM: x\n"}}
        raise failure

    async def _async(*_args: Any, **_kwargs: Any) -> AsyncIterator[dict[str, Any]]:
        yield {"model": "m", "message": {"role": "assistant", "content": "CLAIM: x\n"}}
        raise failure

    object.__setattr__(model, "_create_chat_stream", _sync)
    object.__setattr__(model, "_acreate_chat_stream", _async)
    return model


class TestOllama:
    def test_a_sync_drop_mid_stream(self) -> None:
        with pytest.raises(openai.APIConnectionError) as caught:
            _ollama(httpx.RemoteProtocolError("peer closed connection")).invoke(
                [HumanMessage(content="go")]
            )
        _assert_connection_error(caught.value)

    @pytest.mark.asyncio
    async def test_an_async_drop_mid_stream(self) -> None:
        with pytest.raises(openai.APIConnectionError) as caught:
            await _ollama(httpx.RemoteProtocolError("peer closed connection")).ainvoke(
                [HumanMessage(content="go")]
            )
        _assert_connection_error(caught.value)


class TestWhatIsAConnectionError:
    @pytest.mark.parametrize(
        "failure",
        [
            httpx.RemoteProtocolError("closed"),
            httpx.ReadError("reset"),
            httpx.WriteError("broken"),
            httpx.ConnectError("refused"),
            ConnectionResetError("reset by peer"),
        ],
        ids=["remote-protocol", "read", "write", "connect", "reset"],
    )
    def test_a_transport_failure_becomes_one(self, failure: BaseException) -> None:
        error = as_connection_error(failure)

        assert isinstance(error, openai.APIConnectionError)
        assert error.__cause__ is None  # the caller raises it from the failure

    @pytest.mark.parametrize(
        "failure",
        [httpx.ReadTimeout("slow"), TimeoutError("slow"), ValueError("not a transport")],
        ids=["read-timeout", "timeout", "other"],
    )
    def test_a_timeout_or_another_error_is_left_as_it_is(self, failure: BaseException) -> None:
        assert as_connection_error(failure) is failure

    def test_the_httpx2_fork_s_failure_too(self) -> None:
        httpx2 = pytest.importorskip("httpx2")

        assert isinstance(
            as_connection_error(httpx2.RemoteProtocolError("closed")), openai.APIConnectionError
        )
        assert isinstance(as_connection_error(httpx2.ReadTimeout("slow")), httpx2.ReadTimeout)

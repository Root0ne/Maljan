"""The settings probe reads the window an asynchronous answer reports.

The API asks on its own loop through an ``httpx.AsyncClient``, whose answers
stream asynchronously. The body used to be read with the synchronous reader,
which refuses such a stream; the error was swallowed by the probe's catch-all
and the console showed the fallback window for a model whose server lists its
own. The worker's synchronous probe was never affected.

The transport here answers with a stream that is asynchronous only, which is
what a real connection hands the async client. A plain ``content=`` body is
both kinds at once and would pass with the bug in place.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest

from maljan.llm import context_window as cw
from maljan.llm import model_output_limits

MODEL = "deepseek-flash"
WINDOW = 1_048_576
MODEL_LIST = {
    "object": "list",
    "data": [
        {"id": MODEL, "context_window": WINDOW, "max_output_tokens": 393_216},
    ],
}


class _AsyncOnly(httpx.AsyncByteStream):
    """A body that can only be read asynchronously, in the chunks given."""

    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self._chunks:
            yield chunk

    async def aclose(self) -> None:
        self.closed = True


def _in_chunks(payload: bytes, size: int = 7) -> list[bytes]:
    return [payload[i : i + size] for i in range(0, len(payload), size)]


@pytest.fixture(autouse=True)
def _nothing_learned() -> Any:
    cw.forget_learned_windows()
    model_output_limits.forget_learned()
    yield
    cw.forget_learned_windows()
    model_output_limits.forget_learned()


def _awaited(handler: Any) -> Any:
    real = httpx.AsyncClient

    def stub(**_kwargs: Any) -> httpx.AsyncClient:
        return real(transport=httpx.MockTransport(handler))

    async def ask() -> Any:
        return await cw.aprobe_window(
            "openai", endpoint="https://api.example.test/v1", model=MODEL, api_key="k"
        )

    try:
        httpx.AsyncClient = stub  # type: ignore[assignment,misc]
        return asyncio.run(ask())
    finally:
        httpx.AsyncClient = real  # type: ignore[misc]


def test_the_served_model_list_is_read_from_an_async_stream() -> None:
    body = json.dumps(MODEL_LIST).encode()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == cw.MODEL_LIST_PATH:
            return httpx.Response(200, stream=_AsyncOnly(_in_chunks(body)))
        return httpx.Response(404, stream=_AsyncOnly([b"{}"]))

    fact = _awaited(handler)

    assert fact is not None
    assert fact.tokens == WINDOW
    assert fact.source == cw.PROBED


def test_an_async_answer_past_the_bound_is_abandoned_and_closed() -> None:
    stream = _AsyncOnly([b"x" * 4096] * ((cw.MAX_METADATA_BYTES // 4096) + 2))

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == cw.MODEL_LIST_PATH:
            return httpx.Response(200, stream=stream)
        return httpx.Response(404, stream=_AsyncOnly([b"{}"]))

    assert _awaited(handler) is None
    assert stream.closed


def test_the_sync_probe_reads_the_same_answer() -> None:
    """The worker's path, for the same list, answers the same window."""
    body = json.dumps(MODEL_LIST).encode()
    real = httpx.Client

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == cw.MODEL_LIST_PATH:
            return httpx.Response(200, content=body)
        return httpx.Response(404, json={})

    def stub(**_kwargs: Any) -> httpx.Client:
        return real(transport=httpx.MockTransport(handler))

    try:
        httpx.Client = stub  # type: ignore[assignment,misc]
        fact = cw.probe_window(
            "openai", endpoint="https://api.example.test/v1", model=MODEL, api_key="k"
        )
    finally:
        httpx.Client = real  # type: ignore[misc]

    assert fact is not None
    assert fact.tokens == WINDOW

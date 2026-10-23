"""Ghidra's HTTP calls are held to the breaker and call cap every tool server has.

No Ghidra runs here: each request is answered in-process.
"""

from __future__ import annotations

import asyncio

import httpx

from maljan.providers.server_guard import ServerGuard
from maljan.providers.static.ghidra.http_client import GhidraHTTPClient

PARAMS: list[dict[str, str]] = []


def _client(handler, guard) -> GhidraHTTPClient:
    client = GhidraHTTPClient(base_url="http://ghidra.invalid", guard=guard)
    client._http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return client


async def _call(client: GhidraHTTPClient) -> str:
    return await client._call_endpoint("/list_functions", "GET", PARAMS, {})


def test_unanswered_calls_open_the_breaker_and_the_next_is_not_sent() -> None:
    sent: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request.url.path)
        raise httpx.ConnectError("refused", request=request)

    guard = ServerGuard("ghidra", failures_to_open=2, cooldown_seconds=600.0)
    client = _client(handler, guard)

    async def run() -> tuple[str, str]:
        first = await _call(client)
        await _call(client)
        return first, await _call(client)

    first, resting = asyncio.run(run())
    assert "request_failed" in first
    assert len(sent) == 2
    assert "resting" in resting


def test_an_error_status_is_an_answer_and_never_opens_the_breaker() -> None:
    sent: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request.url.path)
        return httpx.Response(500, text="boom")

    guard = ServerGuard("ghidra", failures_to_open=1, cooldown_seconds=600.0)
    client = _client(handler, guard)

    async def run() -> list[str]:
        return [await _call(client) for _ in range(3)]

    answers = asyncio.run(run())
    assert all("http_status" in a for a in answers)
    assert len(sent) == 3


def test_without_a_guard_every_call_is_sent() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    client = _client(handler, None)
    assert "ok" in asyncio.run(_call(client))

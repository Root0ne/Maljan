"""Each rule of the server guard holds for Ghidra's HTTP calls.

The breaker counts a call its caller's budget cut off, lets one trial through
after the cooldown, ignores a call that never left the queue, and the cap holds
the call past it. No Ghidra runs here: each request is answered in-process.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx

from maljan.providers.base import StaticJobContext
from maljan.providers.server_guard import ServerGuard
from maljan.providers.static.ghidra.http_client import GhidraHTTPClient


def _client(handler: Any, guard: Any) -> GhidraHTTPClient:
    client = GhidraHTTPClient(base_url="http://ghidra.invalid", guard=guard)
    client._http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return client


async def _call(client: GhidraHTTPClient) -> str:
    return await client._call_endpoint("/list_functions", "GET", [], {})


async def _cut_off(client: GhidraHTTPClient) -> None:
    try:
        await asyncio.wait_for(_call(client), timeout=0.05)
    except TimeoutError:
        pass


def test_a_call_cut_off_by_its_caller_s_budget_counts_and_the_third_is_refused() -> None:
    sent: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request.url.path)
        await asyncio.sleep(3600)
        return httpx.Response(200, text="late")

    guard = ServerGuard("ghidra", failures_to_open=2, cooldown_seconds=600.0)
    client = _client(handler, guard)

    async def run() -> str:
        await _cut_off(client)
        await _cut_off(client)
        return await _call(client)

    resting = asyncio.run(run())
    assert len(sent) == 2
    assert "resting" in resting


def test_a_long_running_tool_cut_off_is_no_verdict_on_the_server() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(3600)
        return httpx.Response(200, text="late")

    guard = ServerGuard("ghidra", failures_to_open=1, cooldown_seconds=600.0)
    guard.declare({"list_functions": {"long_running": True}})
    client = _client(handler, guard)

    async def run() -> None:
        await _cut_off(client)
        await _cut_off(client)

    asyncio.run(run())
    assert guard.admit("list_functions") == (None, False)


def test_the_trial_after_the_cooldown_is_sent_and_its_failure_starts_a_new_rest() -> None:
    now = [0.0]
    sent: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request.url.path)
        raise httpx.ConnectError("refused", request=request)

    guard = ServerGuard("ghidra", failures_to_open=1, cooldown_seconds=60.0, clock=lambda: now[0])
    client = _client(handler, guard)

    async def run() -> tuple[str, str]:
        await _call(client)
        during = await _call(client)
        now[0] = 61.0
        await _call(client)
        return during, await _call(client)

    during, after_trial = asyncio.run(run())
    assert "resting" in during
    assert len(sent) == 2
    assert "resting" in after_trial


def test_a_call_cancelled_while_it_waits_for_a_slot_is_not_counted() -> None:
    gate: list[asyncio.Event] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        await gate[0].wait()
        return httpx.Response(200, text="ok")

    guard = ServerGuard(
        "ghidra", failures_to_open=1, cooldown_seconds=600.0, max_concurrent_calls=1
    )
    client = _client(handler, guard)

    async def run() -> str:
        gate.append(asyncio.Event())
        first = asyncio.ensure_future(_call(client))
        await asyncio.sleep(0.05)
        second = asyncio.ensure_future(_call(client))
        await asyncio.sleep(0.05)
        second.cancel()
        await asyncio.gather(second, return_exceptions=True)
        gate[0].set()
        await first
        return await _call(client)

    assert "ok" in asyncio.run(run())


def test_the_cap_holds_the_fifth_concurrent_call() -> None:
    state = {"running": 0, "peak": 0}
    gate: list[asyncio.Event] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        state["running"] += 1
        state["peak"] = max(state["peak"], state["running"])
        await gate[0].wait()
        state["running"] -= 1
        return httpx.Response(200, text="ok")

    guard = ServerGuard("ghidra", max_concurrent_calls=4)
    client = _client(handler, guard)

    async def run() -> int:
        gate.append(asyncio.Event())
        calls = [asyncio.ensure_future(_call(client)) for _ in range(5)]
        await asyncio.sleep(0.1)
        held = state["running"]
        gate[0].set()
        await asyncio.gather(*calls)
        return held

    assert asyncio.run(run()) == 4
    assert state["peak"] == 4


def test_the_provider_builds_a_guard_with_settings_and_none_without(monkeypatch: Any) -> None:
    from maljan.core.config import Settings
    from maljan.providers.static.ghidra import GhidraStaticProvider
    from maljan.providers.static.ghidra import http_client as ghidra_http_client
    from maljan.providers.static.ghidra import provider as ghidra_provider

    built: list[Any] = []
    rests: list[dict[str, Any]] = []

    class _Fake:
        def __init__(self, **kwargs: Any) -> None:
            built.append(kwargs["guard"])

        async def initialize(self) -> None:
            return None

        def get_tools(self) -> list[Any]:
            return []

    monkeypatch.setattr(ghidra_http_client, "GhidraHTTPClient", _Fake)
    cfg = Settings(_env_file=None)  # type: ignore[call-arg]
    cfg.static.ghidra.enabled = True
    cfg.static.ghidra.transport = "http"

    monkeypatch.setattr(ghidra_provider, "get_settings_or_none", lambda: cfg)
    GhidraStaticProvider.from_settings(cfg).open(StaticJobContext(on_server_rest=rests.append))
    assert isinstance(built[0], ServerGuard)
    for _ in range(3):
        built[0].failed("x")
    assert len(rests) == 1

    monkeypatch.setattr(ghidra_provider, "get_settings_or_none", lambda: None)
    GhidraStaticProvider.from_settings(cfg).open(StaticJobContext())
    assert built[1] is None

"""One attach implementation, one allow-list, one collision rule."""

from __future__ import annotations

import asyncio
import logging
from unittest.mock import AsyncMock, MagicMock

import pytest

from maljan.core.config import MCPServerConfig, Settings
from maljan.providers.errors import ProviderConfigurationError
from maljan.providers.servers import ServerHandle, ServerRegistry


class _T:
    """A stand-in LangChain tool: the registry only reads and rewrites ``name``."""

    def __init__(self, name: str) -> None:
        self.name = name

    def model_copy(self, *, update: dict) -> _T:
        return _T(update.get("name", self.name))


def _toolkit(names: list[str]) -> MagicMock:
    instance = MagicMock()
    instance.initialize = AsyncMock(return_value=None)
    instance.get_tools = MagicMock(return_value=[_T(n) for n in names])
    instance.cleanup = AsyncMock(return_value=None)
    return instance


def _run_async_stub(coro, label):
    """Skip the real event-loop hop, and close the coroutine so it is never
    reported as "never awaited" — ``initialize()`` on an ``AsyncMock`` returns
    a real coroutine object whether or not anything runs it.
    """
    coro.close()


@pytest.fixture()
def patched(monkeypatch):
    """Attach without a live MCP server, and without a real event loop hop."""
    made: list[MagicMock] = []

    def factory(*args, **kwargs):
        made.append(_toolkit(factory.names))
        return made[-1]

    factory.names = ["alpha", "beta"]
    monkeypatch.setattr("maljan.agents.mcp_client.MCPLangChainToolkit", factory)
    monkeypatch.setattr("maljan.providers.servers._run_async", _run_async_stub)
    return factory, made


def test_a_disabled_server_attaches_nothing(patched):
    handle = ServerHandle("x", MCPServerConfig(enabled=False, command="mcp"))
    handle.open("job-1")
    assert handle.tools() == [] and handle.is_open is False


def test_none_keeps_every_tool_and_an_empty_list_keeps_none(patched):
    keep_all = ServerHandle("x", MCPServerConfig(enabled=True, command="mcp", tools=None))
    keep_all.open("job-1")
    assert [t.name for t in keep_all.tools()] == ["alpha", "beta"]

    keep_none = ServerHandle("y", MCPServerConfig(enabled=True, command="mcp", tools=[]))
    keep_none.open("job-1")
    assert keep_none.tools() == []
    assert keep_none.all_tool_names() == ["alpha", "beta"], "the manifest is still readable"


def test_an_allow_list_narrows_and_ignores_names_the_server_does_not_offer(patched):
    handle = ServerHandle("x", MCPServerConfig(enabled=True, command="mcp", tools=["beta", "nope"]))
    handle.open("job-1")
    assert [t.name for t in handle.tools()] == ["beta"]


def test_reopening_for_the_same_job_is_a_no_op_and_a_new_job_reattaches(patched):
    _, made = patched
    handle = ServerHandle("x", MCPServerConfig(enabled=True, command="mcp"))
    handle.open("job-1")
    handle.open("job-1")
    assert len(made) == 1
    handle.open("job-2")
    assert len(made) == 2
    made[0].cleanup.assert_called_once()


def test_close_is_idempotent_and_drops_the_tools(patched):
    handle = ServerHandle("x", MCPServerConfig(enabled=True, command="mcp"))
    handle.open("job-1")
    handle.close()
    handle.close()
    assert handle.tools() == [] and handle.is_open is False


def test_a_cwd_outside_the_repository_is_refused():
    handle = ServerHandle("x", MCPServerConfig(enabled=True, command="mcp", cwd="../../etc"))
    with pytest.raises(ProviderConfigurationError) as exc:
        handle.open("job-1")
    assert "cwd" in str(exc.value) and "x" in str(exc.value)


def test_for_agent_returns_only_enabled_servers_bound_to_that_role():
    cfg = Settings(_env_file=None)
    registry = ServerRegistry(cfg)
    assert [h.name for h in registry.for_agent("network")] == ["network"]
    assert [h.name for h in registry.for_agent("judge")] == ["threatintel"]
    assert registry.for_agent("static") == []
    cfg.mcp.servers["threatintel"].enabled = False
    assert ServerRegistry(cfg).for_agent("judge") == []


def test_get_names_the_servers_that_exist():
    registry = ServerRegistry(Settings(_env_file=None))
    assert registry.get("network").name == "network"
    with pytest.raises(ProviderConfigurationError) as exc:
        registry.get("nope")
    assert "network" in str(exc.value) and "threatintel" in str(exc.value)


def test_a_collision_prefixes_the_later_server_and_the_first_keeps_its_name(patched, monkeypatch):
    cfg = Settings(_env_file=None)
    cfg.mcp.servers["network"].agents = ["network"]
    cfg.mcp.servers["zzz"] = MCPServerConfig(enabled=True, command="mcp", agents=["network"])
    registry = ServerRegistry(cfg)
    tools, reasons = registry.tools_for("network", "job-1")
    assert reasons == []
    assert [t.name for t in tools] == ["alpha", "beta", "zzz__alpha", "zzz__beta"]


def test_a_server_that_cannot_open_degrades_and_names_itself(patched, monkeypatch):
    cfg = Settings(_env_file=None)
    cfg.mcp.servers["broken"] = MCPServerConfig(enabled=True, command="mcp", agents=["network"])
    registry = ServerRegistry(cfg)
    real_open = ServerHandle.open

    def flaky(self, job_id, **kwargs):
        if self.name == "broken":
            raise RuntimeError("no such file")
        return real_open(self, job_id, **kwargs)

    monkeypatch.setattr(ServerHandle, "open", flaky)
    tools, reasons = registry.tools_for("network", "job-1")
    assert reasons == ["mcp server 'broken' unavailable"]
    assert [t.name for t in tools] == ["alpha", "beta"]


def test_the_reasons_accumulate_on_the_registry_for_the_run_summary(patched, monkeypatch):
    cfg = Settings(_env_file=None)
    cfg.mcp.servers["broken"] = MCPServerConfig(enabled=True, command="mcp", agents=["network"])
    registry = ServerRegistry(cfg)
    monkeypatch.setattr(
        ServerHandle, "open", lambda self, job_id, **kw: (_ for _ in ()).throw(RuntimeError("x"))
    )
    registry.tools_for("network", "job-1")
    registry.tools_for("network", "job-1")
    assert registry.degradation_reasons == [
        "mcp server 'network' unavailable",
        "mcp server 'broken' unavailable",
    ], "built-ins are attached first, so they are also reported first"


def test_close_all_closes_every_opened_handle(patched):
    _, made = patched
    registry = ServerRegistry(Settings(_env_file=None))
    registry.tools_for("network", "job-1")
    skipped = registry.close_all()
    assert made[0].cleanup.await_count + made[0].cleanup.call_count >= 1
    assert skipped == []


def test_close_all_skips_a_handle_opened_asynchronously_and_reports_it(patched):
    """Regression (F6): a judge-opened handle's exit stack was wound on the
    graph loop; the registry's synchronous close_all() must not try to unwind
    it through the shared agent loop (anyio's cross-loop cancel-scope error),
    it must skip it and hand it back so the caller closes it the right way."""
    handle = ServerHandle("threatintel", MCPServerConfig(enabled=True, command="mcp"))
    asyncio.run(handle.aopen("job-1"))
    assert handle.is_open is True

    registry = ServerRegistry(Settings(_env_file=None))
    registry._handles["threatintel"] = handle
    skipped = registry.close_all()

    assert skipped == [handle]
    assert handle.is_open is True, "still attached: only aclose() may release it"

    asyncio.run(handle.aclose())
    assert handle.is_open is False


# ---------------------------------------------------------------------------
# Fix round 1: a toolkit that starts (a socket, a subprocess) but never
# finishes ``initialize`` must not be left dangling, an allow-list entry the
# server does not offer must say so, and ``_resolve_cwd`` gets its positive
# and its other negative cases alongside the one the brief already covers.
# ---------------------------------------------------------------------------


def test_a_failed_initialize_closes_the_partial_toolkit_and_a_later_open_works(monkeypatch):
    """``initialize`` can fail after the transport is partly up; nothing else holds a
    reference to that toolkit, so ``open`` itself must tear it down before re-raising.
    """
    constructed: list[MagicMock] = []

    def failing_factory(*args, **kwargs):
        instance = MagicMock()
        instance.initialize = AsyncMock(side_effect=RuntimeError("handshake failed"))
        instance.get_tools = MagicMock(return_value=[_T("alpha")])
        instance.cleanup = AsyncMock(return_value=None)
        constructed.append(instance)
        return instance

    monkeypatch.setattr("maljan.agents.mcp_client.MCPLangChainToolkit", failing_factory)

    handle = ServerHandle("x", MCPServerConfig(enabled=True, command="mcp"))
    with pytest.raises(RuntimeError, match="handshake failed"):
        handle.open("job-1")

    assert handle.is_open is False
    assert handle._toolkit is None
    constructed[0].cleanup.assert_called_once()

    def working_factory(*args, **kwargs):
        instance = MagicMock()
        instance.initialize = AsyncMock(return_value=None)
        instance.get_tools = MagicMock(return_value=[_T("alpha")])
        instance.cleanup = AsyncMock(return_value=None)
        constructed.append(instance)
        return instance

    monkeypatch.setattr("maljan.agents.mcp_client.MCPLangChainToolkit", working_factory)
    handle.open("job-2")
    assert handle.is_open is True
    assert [t.name for t in handle.tools()] == ["alpha"]


@pytest.mark.asyncio
async def test_aopen_closes_the_partial_toolkit_when_wait_for_cancels_it(monkeypatch):
    """``asyncio.wait_for`` cancelling ``aopen`` mid-``initialize`` must still tear
    the partly spawned toolkit down — the same guarantee the synchronous ``open``
    gives its own caller, now for a caller (``handshake_tools``) that awaits on its
    own loop instead of handing the coroutine to ``_run_async``.
    """
    instance = MagicMock()

    async def hang() -> None:
        await asyncio.sleep(100)

    instance.initialize = hang
    instance.get_tools = MagicMock(return_value=[])
    instance.cleanup = AsyncMock(return_value=None)

    monkeypatch.setattr("maljan.agents.mcp_client.MCPLangChainToolkit", lambda *a, **kw: instance)

    handle = ServerHandle("x", MCPServerConfig(enabled=True, command="mcp"))
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(handle.aopen("job-1"), timeout=0.05)

    instance.cleanup.assert_called_once()
    assert handle.is_open is False
    assert handle._toolkit is None


def test_an_allow_listed_name_the_server_does_not_offer_logs_one_warning(patched, caplog):
    factory, _ = patched
    factory.names = ["alpha"]
    handle = ServerHandle(
        "x", MCPServerConfig(enabled=True, command="mcp", tools=["alpha", "nope", "also-missing"])
    )
    with caplog.at_level(logging.WARNING, logger="maljan"):
        handle.open("job-1")

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    matches = [r for r in warnings if "nope" in r.getMessage() and "also-missing" in r.getMessage()]
    assert len(matches) == 1, f"expected exactly one warning naming the misses, got {warnings}"
    assert "x" in matches[0].getMessage()


def test_a_relative_cwd_inside_the_repository_resolves(tmp_path, monkeypatch):
    monkeypatch.setattr("maljan.core.paths.get_project_root", lambda *a, **k: tmp_path)
    (tmp_path / "sub").mkdir()
    handle = ServerHandle("x", MCPServerConfig(enabled=True, command="mcp", cwd="sub"))
    assert handle._resolve_cwd() == str((tmp_path / "sub").resolve())


def test_an_existing_absolute_cwd_resolves(tmp_path):
    handle = ServerHandle("x", MCPServerConfig(enabled=True, command="mcp", cwd=str(tmp_path)))
    assert handle._resolve_cwd() == str(tmp_path.resolve())


def test_an_absolute_cwd_that_does_not_exist_is_refused(tmp_path):
    missing = tmp_path / "does-not-exist"
    handle = ServerHandle("x", MCPServerConfig(enabled=True, command="mcp", cwd=str(missing)))
    with pytest.raises(ProviderConfigurationError) as exc:
        handle.open("job-1")
    assert "cwd" in str(exc.value) and "x" in str(exc.value)


def test_a_symlink_escaping_the_repository_root_is_refused(tmp_path, monkeypatch):
    """``_resolve_cwd`` takes no root argument, so the root is faked by pointing
    ``get_project_root`` (imported locally inside the method, so patchable here)
    at a throwaway directory rather than the real repository.
    """
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "escape").symlink_to(outside)
    monkeypatch.setattr("maljan.core.paths.get_project_root", lambda *a, **k: root)

    handle = ServerHandle("x", MCPServerConfig(enabled=True, command="mcp", cwd="escape"))
    with pytest.raises(ProviderConfigurationError) as exc:
        handle.open("job-1")
    assert "cwd" in str(exc.value) and "x" in str(exc.value)


# ---------------------------------------------------------------------------
# One session per loop (fix wave 2b).
#
# The teardown Critical had a twin at call time. The mediator judge attaches
# its servers inside `run_on_agent_loop`, so the handle binds to the shared
# agent loop; a judge running on the graph loop asking the registry for the
# same server key used to be handed that same handle, and with it a
# `ClientSession` whose anyio scopes belong to somebody else's loop. Awaiting
# it from the graph loop is the same shape of unresumable park.
#
# Before the tool-server registry existed, every `JudgeAgent` built its own
# `MCPLangChainToolkit` and its own subprocess, so no session was ever shared
# across loops. These tests hold the registry to that property.
# ---------------------------------------------------------------------------


class _LoopBoundToolkit:
    """A toolkit that only answers on the loop that initialised it."""

    def __init__(self) -> None:
        self.loop: asyncio.AbstractEventLoop | None = None
        self.closed_on: asyncio.AbstractEventLoop | None = None

    async def initialize(self) -> None:
        self.loop = asyncio.get_running_loop()

    def get_tools(self) -> list:
        return [_T("check_ip_reputation")]

    async def call(self) -> str:
        """A tool call, with the check a real session makes implicitly."""
        if asyncio.get_running_loop() is not self.loop:
            raise RuntimeError("session used from a loop other than the one that opened it")
        return "ok"

    async def cleanup(self) -> None:
        self.closed_on = asyncio.get_running_loop()


def _registry_with_fake_toolkits(monkeypatch, made: list) -> ServerRegistry:
    """A registry whose handles build `_LoopBoundToolkit`s instead of children."""

    def factory(*args, **kwargs):
        made.append(_LoopBoundToolkit())
        return made[-1]

    monkeypatch.setattr("maljan.agents.mcp_client.MCPLangChainToolkit", factory)
    return ServerRegistry(Settings(_env_file=None))


def _serve(loop: asyncio.AbstractEventLoop, name: str):
    """Run `loop` forever on its own thread, and wait until it is running."""
    import threading

    running = threading.Event()

    def target() -> None:
        asyncio.set_event_loop(loop)
        loop.call_soon(running.set)
        loop.run_forever()

    thread = threading.Thread(target=target, daemon=True, name=name)
    thread.start()
    assert running.wait(60), f"{name} never started"
    return thread


def test_two_live_loops_get_two_handles_for_one_server(monkeypatch):
    made: list = []
    registry = _registry_with_fake_toolkits(monkeypatch, made)

    first, second = asyncio.new_event_loop(), asyncio.new_event_loop()
    threads = [_serve(first, "loop-a"), _serve(second, "loop-b")]
    try:
        tools_a, reasons_a = asyncio.run_coroutine_threadsafe(
            registry.atools_for("judge", "job-1"), first
        ).result(timeout=60)
        tools_b, reasons_b = asyncio.run_coroutine_threadsafe(
            registry.atools_for("judge", "job-1"), second
        ).result(timeout=60)

        # Same tool set and no degradation either way: the second caller is
        # not a fallback, it is an equal attach.
        assert [t.name for t in tools_a] == [t.name for t in tools_b]
        assert reasons_a == [] and reasons_b == []

        assert len(made) == 2, "the second loop must get a session of its own"
        assert made[0].loop is first
        assert made[1].loop is second

        # And a call from each loop reaches the session that loop opened.
        for loop, toolkit in ((first, made[0]), (second, made[1])):
            assert asyncio.run_coroutine_threadsafe(toolkit.call(), loop).result(timeout=60) == "ok"

        # Teardown closes both, each on its own loop, inside the budget.
        skipped = registry.close_all()
        assert {handle.name for handle in skipped} == {"threatintel"}
        for loop in (first, second):

            async def release(handles=skipped) -> None:
                for handle in handles:
                    await asyncio.wait_for(handle.aclose(), timeout=20)

            asyncio.run_coroutine_threadsafe(release(), loop).result(timeout=60)

        assert made[0].closed_on is first
        assert made[1].closed_on is second
    finally:
        for loop, thread in zip((first, second), threads, strict=True):
            loop.call_soon_threadsafe(loop.stop)
            thread.join(timeout=30)


def test_one_loop_keeps_sharing_a_single_handle(monkeypatch):
    """The default profile is unchanged: one loop, one handle, one child."""
    made: list = []
    registry = _registry_with_fake_toolkits(monkeypatch, made)

    loop = asyncio.new_event_loop()
    thread = _serve(loop, "loop-only")
    try:

        async def attach_twice() -> None:
            await registry.atools_for("judge", "job-1")
            await registry.atools_for("judge", "job-1")

        asyncio.run_coroutine_threadsafe(attach_twice(), loop).result(timeout=60)
        assert len(made) == 1
        assert registry._loop_handles == {}
    finally:
        loop.call_soon_threadsafe(loop.stop)
        thread.join(timeout=30)

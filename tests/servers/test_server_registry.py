"""One attach implementation, one allow-list, one collision rule."""

from __future__ import annotations

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


@pytest.fixture()
def patched(monkeypatch):
    """Attach without a live MCP server, and without a real event loop hop."""
    made: list[MagicMock] = []

    def factory(*args, **kwargs):
        made.append(_toolkit(factory.names))
        return made[-1]

    factory.names = ["alpha", "beta"]
    monkeypatch.setattr("maljan.agents.mcp_client.MCPLangChainToolkit", factory)
    monkeypatch.setattr("maljan.providers.servers._run_async", lambda coro, label: None)
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
    registry.close_all()
    assert made[0].cleanup.await_count + made[0].cleanup.call_count >= 1

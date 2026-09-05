"""A server bound to static or dynamic is appended, never substituted."""

from __future__ import annotations

import pytest

from maljan.core.config import MCPServerConfig, Settings


class _T:
    def __init__(self, name: str) -> None:
        self.name = name

    def model_copy(self, *, update: dict) -> _T:
        return _T(update.get("name", self.name))


def _container(monkeypatch, **servers):
    from maljan.core.container import ServiceContainer

    cfg = Settings(_env_file=None)
    for key, entry in servers.items():
        cfg.mcp.servers[key] = entry
    return ServiceContainer(config=cfg, mock=True)


def _wired(container, name: str):
    """An analyst with this container behind it, without building an LLM.

    ``container.get_agent`` needs a real model and refuses in mock mode; these
    tests only need the ``_container`` back-reference the registry helper reads.
    """
    from unittest.mock import MagicMock

    agent = container.agent_registry.create(name, MagicMock())
    agent._container = container
    return agent


def test_the_provider_tools_come_first_and_the_bound_server_after(monkeypatch):
    container = _container(
        monkeypatch,
        extra=MCPServerConfig(enabled=True, command="mcp", agents=["static"], tools=["helper"]),
    )
    registry = container.get_server_registry()
    monkeypatch.setattr(registry, "tools_for", lambda role, job_id, **kw: ([_T("helper")], []))
    agent = _wired(container, "static")
    monkeypatch.setattr(type(agent), "_provider", lambda self: _StubProvider())
    agent._initialize_mcp_client()
    assert [t.name for t in agent.tools] == ["ghidra_tool", "helper"]


class _StubProvider:
    id = "ghidra"

    class capabilities:  # noqa: N801 — a stand-in for the frozen dataclass
        provides_tools = True
        degrade_on_failure = False

    server_name = ""

    def open(self, job):
        return None

    def get_tools(self):
        return [_T("ghidra_tool")]

    def select_tools(self, tools, categories=None):
        return list(tools)


def test_the_server_the_provider_already_owns_is_not_attached_twice(monkeypatch):
    container = _container(
        monkeypatch,
        mine=MCPServerConfig(enabled=True, command="mcp", agents=["static"]),
    )
    registry = container.get_server_registry()
    asked: list[str] = []

    def spy(role, job_id, *, exclude=None, **kw):
        asked.append(exclude or "")
        return [], []

    monkeypatch.setattr(registry, "tools_for", spy)
    agent = _wired(container, "static")

    provider = _StubProvider()
    provider.server_name = "mine"
    monkeypatch.setattr(type(agent), "_provider", lambda self: provider)
    agent._initialize_mcp_client()
    assert asked == ["mine"]


def test_a_failed_bound_server_degrades_a_static_run_that_would_otherwise_fail(monkeypatch):
    """Ghidra's loud failure is untouched; a registry server never fails a job."""
    container = _container(
        monkeypatch,
        broken=MCPServerConfig(enabled=True, command="nope", agents=["static"]),
    )
    registry = container.get_server_registry()
    monkeypatch.setattr(
        registry,
        "tools_for",
        lambda role, job_id, **kw: ([], ["mcp server 'broken' unavailable"]),
    )
    agent = _wired(container, "static")
    monkeypatch.setattr(type(agent), "_provider", lambda self: _StubProvider())
    agent._initialize_mcp_client()
    assert [t.name for t in agent.tools] == ["ghidra_tool"]
    assert container.server_degradation_reasons() == []  # the registry itself never failed
    assert agent.degradation_reasons == ["mcp server 'broken' unavailable"]


@pytest.mark.parametrize("role", ["dynamic"])
def test_the_dynamic_analyst_appends_after_the_sandbox_tools(monkeypatch, role):
    container = _container(
        monkeypatch,
        extra=MCPServerConfig(enabled=True, command="mcp", agents=["dynamic"]),
    )
    registry = container.get_server_registry()
    monkeypatch.setattr(registry, "tools_for", lambda r, job_id, **kw: ([_T("extra")], []))
    agent = _wired(container, "dynamic")
    agent._initialize_mcp_client()
    assert [t.name for t in agent.tools][-1] == "extra"

"""A server bound to static or dynamic is appended, never substituted.

Both halves of an agent's tool set run here: the servers bound to its role by
``MCPServerConfig.agents``, and the servers its own definition names by
``ToolRef``. Stubbing only the first would let the reference half be deleted
with these assertions still passing, which is the failure the two halves were
introduced to prevent.
"""

from __future__ import annotations

import pytest

from maljan.core.config import MCPServerConfig, Settings, ToolRef


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


def _serve_refs(registry, monkeypatch, by_server: dict[str, str]) -> None:
    """Answer ``tools_for_ref`` with one named tool per referenced server."""

    def _ref(ref, job_id, **kw):
        name = by_server.get(str(ref.server))
        if name is None:
            return [], [f"agent tool '{ref.server}.{ref.name}' unavailable"]
        return [_T(name)], []

    monkeypatch.setattr(registry, "tools_for_ref", _ref)


def test_the_provider_tools_come_first_then_the_bound_server_then_the_references(monkeypatch):
    container = _container(
        monkeypatch,
        extra=MCPServerConfig(enabled=True, command="mcp", agents=["static"], tools=["helper"]),
    )
    registry = container.get_server_registry()
    monkeypatch.setattr(registry, "tools_for", lambda role, job_id, **kw: ([_T("helper")], []))
    _serve_refs(registry, monkeypatch, {"analysis": "pe_info", "knowledge": "attck_lookup"})
    agent = _wired(container, "static")
    monkeypatch.setattr(type(agent), "_provider", lambda self: _StubProvider())
    agent._initialize_mcp_client()
    # The provider opens its own tools, the role binding comes next, and the
    # definition's references last — the order the settings probe reports.
    assert [t.name for t in agent.tools] == ["ghidra_tool", "helper", "pe_info", "attck_lookup"]


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
    asked_refs: list[str] = []

    def _ref(ref, job_id, **kw):
        asked_refs.append(str(ref.server))
        return [], []

    monkeypatch.setattr(registry, "tools_for_ref", _ref)
    # The definition names the very server the provider owns, which is the
    # second way the same tools could arrive twice.
    definitions = container.config.agents.definitions
    definitions["static"] = definitions["static"].model_copy(
        update={"tools": [ToolRef(kind="mcp", server="mine")]}
    )
    agent = _wired(container, "static")

    provider = _StubProvider()
    provider.server_name = "mine"
    monkeypatch.setattr(type(agent), "_provider", lambda self: provider)
    agent._initialize_mcp_client()
    assert asked == ["mine"]
    assert asked_refs == [], "a reference to the provider's own server is skipped too"


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
    _serve_refs(registry, monkeypatch, {"analysis": "pe_info", "knowledge": "attck_lookup"})
    agent = _wired(container, "static")
    monkeypatch.setattr(type(agent), "_provider", lambda self: _StubProvider())
    agent._initialize_mcp_client()
    # The bound server failed; the provider's tools and the definition's
    # references are unaffected, which is what "degrades" has to mean.
    assert [t.name for t in agent.tools] == ["ghidra_tool", "pe_info", "attck_lookup"]
    assert container.server_degradation_reasons() == []  # the registry itself never failed
    assert agent.degradation_reasons == ["mcp server 'broken' unavailable"]


def test_a_reference_that_cannot_be_served_degrades_the_same_way(monkeypatch):
    container = _container(monkeypatch)
    registry = container.get_server_registry()
    monkeypatch.setattr(registry, "tools_for", lambda role, job_id, **kw: ([], []))
    _serve_refs(registry, monkeypatch, {"analysis": "pe_info"})
    agent = _wired(container, "static")
    monkeypatch.setattr(type(agent), "_provider", lambda self: _StubProvider())
    agent._initialize_mcp_client()
    assert [t.name for t in agent.tools] == ["ghidra_tool", "pe_info"]
    assert agent.degradation_reasons == ["agent tool 'knowledge.None' unavailable"]


@pytest.mark.parametrize("role", ["dynamic"])
def test_the_dynamic_analyst_appends_after_the_sandbox_tools(monkeypatch, role):
    container = _container(
        monkeypatch,
        extra=MCPServerConfig(enabled=True, command="mcp", agents=["dynamic"]),
    )
    container.sandbox_report = {"behavior": {"processes": [{"pid": 1}]}}
    registry = container.get_server_registry()
    monkeypatch.setattr(registry, "tools_for", lambda r, job_id, **kw: ([_T("extra")], []))
    _serve_refs(registry, monkeypatch, {"knowledge": "attck_lookup"})
    agent = _wired(container, "dynamic")
    agent._initialize_mcp_client()
    names = [t.name for t in agent.tools]
    # The in-process sandbox tools its definition references come first, then
    # the role-bound server, then the referenced ones.
    assert "sandbox_processes" in names
    assert names.index("extra") > names.index("sandbox_processes")
    assert names[-1] == "attck_lookup"

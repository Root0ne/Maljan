"""The connection test launches the same server a job launches."""

from __future__ import annotations

import pytest
from app.services.settings_probes import PROBES, handshake_tools, probe_mcp, run_mcp_probe


class _Handle:
    """Records what it was asked to attach, and answers with a manifest."""

    made: list = []

    def __init__(self, name, config):
        self.name = name
        self.config = config
        _Handle.made.append(self)
        self.closed = False

    async def aopen(self, job_id, **kw):
        return None

    async def aclose(self):
        self.closed = True

    def all_tool_names(self):
        return ["open_file", "analyze", "list_imports"]


@pytest.fixture(autouse=True)
def _no_live_server(monkeypatch):
    _Handle.made = []
    monkeypatch.setattr("app.services.settings_probes.ServerHandle", _Handle)


@pytest.mark.asyncio
async def test_the_probe_reports_the_manifest_and_names_it_in_the_detail():
    result = await probe_mcp({"name": "r2custom", "entry": {"enabled": True, "command": "r2mcp"}})
    assert result.ok is True
    assert result.tools == ["open_file", "analyze", "list_imports"]
    assert "3 tools" in result.detail and "open_file" in result.detail


@pytest.mark.asyncio
async def test_the_probe_forces_the_server_on_and_ignores_the_stored_allow_list():
    """A probe exists to read the manifest, so it must not be narrowed by it."""
    await probe_mcp({"name": "x", "entry": {"enabled": False, "command": "mcp", "tools": []}})
    assert _Handle.made[-1].config.enabled is True
    assert _Handle.made[-1].config.tools is None


@pytest.mark.asyncio
async def test_a_hanging_server_is_killed_and_reported(monkeypatch):
    import asyncio

    async def hang(self, job_id, **kw):
        await asyncio.sleep(30)

    monkeypatch.setattr(_Handle, "aopen", hang)
    monkeypatch.setattr("app.services.settings_probes.PROBE_BUDGET_SECONDS", 0.05)
    result = await probe_mcp({"name": "x", "entry": {"enabled": True, "command": "mcp"}})
    assert result.ok is False and "no MCP handshake" in result.detail
    assert _Handle.made[-1].closed is True, "the child is killed, not left running"


@pytest.mark.asyncio
async def test_a_missing_binary_names_itself(monkeypatch):
    async def boom(self, job_id, **kw):
        raise FileNotFoundError("r2mcp")

    # Through monkeypatch, not a direct class assignment: a bare assignment
    # would outlive this test and take down every later one that opens a
    # handle, since ``_Handle`` is one module-level class shared by them all.
    monkeypatch.setattr(_Handle, "aopen", boom)
    result = await probe_mcp({"name": "x", "entry": {"enabled": True, "command": "r2mcp"}})
    assert result.ok is False and "r2mcp" in result.detail


@pytest.mark.asyncio
async def test_run_mcp_probe_layers_staged_values_over_the_stored_map():
    result = await run_mcp_probe(
        "r2custom",
        {"core.mcp.servers": {"r2custom": {"enabled": True, "command": "staged"}}},
        {"core.mcp.servers": {"r2custom": {"enabled": True, "command": "stored"}}},
    )
    assert result.ok is True
    assert _Handle.made[-1].config.command == "staged"


@pytest.mark.asyncio
async def test_an_unknown_server_is_a_legible_failure():
    result = await run_mcp_probe("nope", {}, {})
    assert result.ok is False and "nope" in result.detail


def test_the_probe_is_registered_under_its_own_name():
    assert "mcp" in PROBES


@pytest.mark.asyncio
async def test_the_r2_probe_speaks_the_same_handshake(monkeypatch):
    from app.services.settings_probes import probe_r2

    result = await probe_r2({"binary_path": "r2mcp"})
    assert result.ok is True and result.tools == ["open_file", "analyze", "list_imports"]
    assert _Handle.made[-1].config.command == "r2mcp"
    assert handshake_tools is not None

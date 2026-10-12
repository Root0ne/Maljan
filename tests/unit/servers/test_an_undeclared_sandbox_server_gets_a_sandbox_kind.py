"""An undeclared live sandbox server is proposed sandbox kinds; an accepted one runs as built in.

An invented MCP server, served in memory through the real client: one tool
answers its run's processes under keys of its own (``process_id``,
``parent_id``, ``image``, ``cmdline``) and says so in its ``outputSchema``; one
answers its connections laid out as a flow table, with no ``outputSchema``, so
only a harmless probe call shows the answer's shape; one answers the files the
run dropped.

* The connection test proposes the sandbox kinds from the rows' keys (the
  sandbox report shape test), with the process id as the place a run root is
  read from.
* Accepted, the processes tool's answer is a sandbox's: its entry reads as a
  ``run`` root per process, it is drawn as the built-in sandbox's processes
  are, and it is counted among the sandbox's entries rather than as a look at
  the file.
* Not accepted, nothing changes.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, suppress
from typing import Any

import mcp.types as types
import pytest
from mcp.server.lowlevel import Server
from mcp.shared.memory import create_client_server_memory_streams

from maljan.agents.evidence_recorder import EvidenceRecorder, record_tools
from maljan.analysis.evidence_roots import PROCESS_ROOT, READING_RUN, reading_of, run_roots
from maljan.core import declared_reading
from maljan.core.config import Settings, get_settings, install_settings
from maljan.reporting import tool_kinds
from maljan.reporting.ledger_report import build_sections

SERVER = "livebox"
PROCESSES = {
    "procs": [
        {"process_id": 3100, "parent_id": 880, "image": "dropper.exe", "cmdline": "dropper.exe -x"},
        {"process_id": 3144, "parent_id": 3100, "image": "cmd.exe", "cmdline": "cmd /c whoami"},
    ]
}
FLOWS = {"tcp": [{"dst": "203.0.113.20", "dport": 8443}], "udp": []}
DROPPED = {"written": [{"sha256": "ab" * 32, "path": "C:\\t\\x.dll", "size": 100}]}
CALLS: list[str] = []

_PROCESS_TOOL = types.Tool(
    name="run_processes",
    description="The processes of the current run.",
    inputSchema={"type": "object", "properties": {"run": {"type": "string"}}},
    outputSchema={
        "type": "object",
        "properties": {
            "procs": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "process_id": {"type": "integer"},
                        "parent_id": {"type": "integer"},
                        "image": {"type": "string"},
                        "cmdline": {"type": "string"},
                    },
                },
            }
        },
    },
    annotations=types.ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
_FLOW_TOOL = types.Tool(
    name="run_connections",
    description="The connections of the current run.",
    inputSchema={"type": "object"},
    annotations=types.ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
_DROPPED_TOOL = types.Tool(
    name="run_dropped",
    description="What the current run wrote to disk.",
    inputSchema={"type": "object"},
    outputSchema={
        "type": "object",
        "properties": {
            "written": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "sha256": {"type": "string"},
                        "path": {"type": "string"},
                        "size": {"type": "integer"},
                    },
                },
            }
        },
    },
    annotations=types.ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
_ANSWERS = {"run_processes": PROCESSES, "run_connections": FLOWS, "run_dropped": DROPPED}


def _server() -> Server:
    server: Server = Server(SERVER)

    @server.list_tools()
    async def _list() -> list[types.Tool]:
        return [_PROCESS_TOOL, _FLOW_TOOL, _DROPPED_TOOL]

    @server.call_tool(validate_input=False)
    async def _call(name: str, arguments: dict[str, Any]) -> types.CallToolResult:
        CALLS.append(name)
        answer = _ANSWERS.get(name, {})
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=json.dumps(answer))],
            structuredContent=answer,
        )

    return server


def _in_memory(server: Server) -> Any:
    def _client(_params: Any) -> Any:
        @asynccontextmanager
        async def _streams() -> AsyncIterator[Any]:
            async with create_client_server_memory_streams() as (client, served):
                task = asyncio.create_task(
                    server.run(served[0], served[1], server.create_initialization_options())
                )
                try:
                    yield client
                finally:
                    task.cancel()
                    with suppress(BaseException):
                        await task

        return _streams()

    return _client


@pytest.fixture(autouse=True)
def _served(monkeypatch: pytest.MonkeyPatch) -> None:
    CALLS.clear()
    monkeypatch.setattr("maljan.agents.mcp_client.stdio_client", _in_memory(_server()))


@pytest.fixture
def installed() -> Iterator[Any]:
    previous = get_settings()

    def _install(settings: Settings) -> Settings:
        install_settings(settings)
        declared_reading.forget()
        return settings

    yield _install
    install_settings(previous)
    declared_reading.forget()


def _probe(confirmed: list[str] | None = None) -> Any:
    from app.services.settings_probes import probe_mcp

    entry = {"enabled": True, "command": "livebox-server"}
    return asyncio.run(
        probe_mcp({"name": SERVER, "entry": entry, "confirmed_calls": list(confirmed or [])})
    )


def _settings(tool_facts: dict[str, Any] | None) -> Settings:
    block: dict[str, Any] = {"enabled": True, "command": "livebox-server", "agents": ["dynamic"]}
    if tool_facts is not None:
        block["tool_facts"] = tool_facts
    return Settings.model_validate({"mcp": {"servers": {SERVER: block}}})


def _entry(settings: Settings, tool: str) -> Any:
    async def _run() -> Any:
        from maljan.providers.servers import ServerRegistry

        registry = ServerRegistry(settings)
        tools, _reasons = await registry.atools_for("dynamic", "job-1")
        try:
            recorder = EvidenceRecorder("dynamic")
            recorded = {t.name: t for t in record_tools(tools, recorder)}
            await recorded[tool].ainvoke({})
            return recorder.entries[0]
        finally:
            for handle in registry.still_open():
                await handle.aclose()

    return asyncio.run(_run())


def test_the_probe_proposes_sandbox_kinds_from_the_rows_keys() -> None:
    proposals = _probe(confirmed=["run_connections"]).details["proposals"]["tools"]
    processes = proposals["run_processes"]
    assert processes["facts"]["kind"] == "sandbox_processes"
    assert processes["facts"]["rows"] == "/procs/*"
    assert processes["facts"]["places"] == {"pid": "/process_id"}
    assert processes["facts"]["values"] == {"name": "/image", "command_line": "/cmdline"}
    kind = processes["fields"]["kind"]
    assert kind["confidence"] in ("medium", "low")
    assert any("shape test" in said for said in kind["evidence"])
    # Seen only through the confirmed harmless call: a flow table.
    flows = proposals["run_connections"]["facts"]
    assert flows["kind"] == "sandbox_network"
    assert flows["reader"] == "flow_table"
    assert proposals["run_dropped"]["facts"]["kind"] == "sandbox_dropped_files"


def test_an_accepted_sandbox_kind_gives_run_roots_and_a_sandbox_s_reading(installed: Any) -> None:
    proposals = _probe(confirmed=["run_connections"]).details["proposals"]["tools"]
    accepted = {name: json.loads(json.dumps(held["facts"])) for name, held in proposals.items()}
    settings = installed(_settings(accepted))
    entry = _entry(settings, "run_processes")
    assert entry.facts["kind"] == "sandbox_processes"
    roots = run_roots([entry]).entries[entry.id.lower()].roots
    assert sorted(roots) == sorted(PROCESS_ROOT.format(pid=pid) for pid in (3100, 3144))
    assert reading_of(entry.tool, roots) == READING_RUN
    # Counted among the sandbox's entries, as the built-in sandbox tools are.
    assert tool_kinds.is_of(entry, "evidence_bundles.SANDBOX_TOOL_PREFIXES")
    drawn = [s for s in build_sections([entry]) if s.key == "sandbox_processes"]
    assert drawn
    rows = drawn[0].model_dump()["rows"]
    assert ["3100", "", "dropper.exe", "dropper.exe -x"] in rows

    flow = _entry(settings, "run_connections")
    flow_roots = run_roots([flow]).entries[flow.id.lower()].roots
    assert any(str(root).startswith("flow") or "203.0.113.20" in str(root) for root in flow_roots)
    assert reading_of(flow.tool, flow_roots) == READING_RUN


def test_without_acceptance_the_sandbox_server_stays_undeclared(installed: Any) -> None:
    settings = installed(_settings(None))
    entry = _entry(settings, "run_processes")
    assert entry.facts == {"v": 1}
    assert not tool_kinds.is_of(entry, "evidence_bundles.SANDBOX_TOOL_PREFIXES")
    roots = run_roots([entry]).entries[entry.id.lower()].roots
    assert not any(str(root).startswith(PROCESS_ROOT.split("{", 1)[0]) for root in roots)

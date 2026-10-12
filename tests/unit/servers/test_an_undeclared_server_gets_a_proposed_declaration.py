"""A tool server nobody declared gets a proposed declaration, which only an operator applies.

An invented MCP server, served in memory through the real client, with no
declaration but a rich MCP schema: a rule scanner whose ``inputSchema`` takes a
``file_path`` and a ``sha256``, whose ``outputSchema`` has rows and technique
tags, whose annotations give a title and say it only reads; a hash lookup
whose answer holds engine counts; a section lister with no ``outputSchema``
that answers a missing file in prose; and a ``capabilities`` manifest whose
cell for the scanner carries its own budget, long-running flag and facts.

* The connection test proposes the right kinds and fields, each with the
  schema part or answer it was read from and how sure the reading is.
* The harmless calls the operator may ask for send a path that does not
  exist and the digest of empty input, never a sample, and the lister's
  answer proposes an error pattern.
* Accepting the proposal gives the same run as a hand-written declaration.
* Without acceptance nothing changes: the entries store the facts of an
  undeclared tool, as before.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, suppress
from typing import Any

import mcp.types as types
import pytest
from mcp.server.lowlevel import Server
from mcp.shared.memory import create_client_server_memory_streams

from maljan.agents.evidence_recorder import EvidenceRecorder, record_tools
from maljan.core import declared_reading
from maljan.core.config import MCPServerConfig, Settings, get_settings, install_settings
from maljan.core.tool_declarations import ToolFacts
from maljan.pipeline.evidence_summary import asserted_techniques, asserting_source
from maljan.providers.servers import ServerRegistry
from maljan.reporting.ledger_report import build_sections

SERVER = "invented"
RULE_ANSWER = {
    "matches": [
        {"rule": "demo_rule", "tags": ["attack.t1055"], "strings": [{"offset": 1024}]},
    ]
}
LOOKUP_ANSWER = {"stats": {"malicious": 3, "total": 70}, "permalink": "https://example.invalid/r"}
# What the server was called with, per tool, so the test can see no call
# named anything but the probe's harmless values.
CALLS: list[tuple[str, dict[str, Any]]] = []

_RULE_TOOL = types.Tool(
    name="scan_rules",
    description=(
        "Matches the server's rules against the file at file_path and lists each match "
        "with its ATT&CK tags."
    ),
    inputSchema={
        "type": "object",
        "properties": {
            "file_path": {"type": "string", "description": "Path to the file to scan."},
            "sha256": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
        },
        "required": ["file_path"],
    },
    outputSchema={
        "type": "object",
        "properties": {
            "matches": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "rule": {"type": "string"},
                        "tags": {"type": "array", "items": {"type": "string"}},
                        "strings": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {"offset": {"type": "integer"}},
                            },
                        },
                    },
                },
            }
        },
    },
    annotations=types.ToolAnnotations(title="Rule scanner", readOnlyHint=True),
)
_LOOKUP_TOOL = types.Tool(
    name="query_hash",
    description="Looks a file's hash up.",
    inputSchema={
        "type": "object",
        "properties": {"hash": {"type": "string"}},
        "required": ["hash"],
    },
    outputSchema={
        "type": "object",
        "properties": {
            "stats": {
                "type": "object",
                "properties": {"malicious": {"type": "integer"}, "total": {"type": "integer"}},
            },
            "permalink": {"type": "string"},
        },
    },
    annotations=types.ToolAnnotations(readOnlyHint=True, openWorldHint=True),
)
_LISTER_TOOL = types.Tool(
    name="section_list",
    description="Lists the sections of the file.",
    inputSchema={
        "type": "object",
        "properties": {"path": {"type": "string"}},
        "required": ["path"],
    },
    annotations=types.ToolAnnotations(readOnlyHint=True, openWorldHint=False),
)
# Says nothing about what it does: it may write, so it is never called.
_UNANNOTATED_TOOL = types.Tool(
    name="submit_url",
    description="Sends a URL on.",
    inputSchema={
        "type": "object",
        "properties": {"url": {"type": "string"}},
        "required": ["url"],
    },
)
_WRITER_TOOL = types.Tool(
    name="write_note",
    description="Writes a note next to the file.",
    inputSchema={
        "type": "object",
        "properties": {"path": {"type": "string"}},
        "required": ["path"],
    },
    annotations=types.ToolAnnotations(destructiveHint=True),
)
_CAPABILITIES_TOOL = types.Tool(
    name="capabilities", description="What this server can do.", inputSchema={"type": "object"}
)
MANIFEST = {
    "server": SERVER,
    "version": "1.0",
    "tools": [
        {
            "name": "scan_rules",
            "available": True,
            "timeout_s": 120,
            "long_running": True,
            "facts": "matches rules",
        }
    ],
}


def _text(text: str) -> types.CallToolResult:
    return types.CallToolResult(content=[types.TextContent(type="text", text=text)])


def _structured(answer: dict[str, Any]) -> types.CallToolResult:
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=json.dumps(answer))],
        structuredContent=answer,
    )


def _server(tools: list[types.Tool] | None = None) -> Server:
    server: Server = Server(SERVER)
    listed = tools or [
        _RULE_TOOL,
        _LOOKUP_TOOL,
        _LISTER_TOOL,
        _WRITER_TOOL,
        _UNANNOTATED_TOOL,
        _CAPABILITIES_TOOL,
    ]

    @server.list_tools()
    async def _list() -> list[types.Tool]:
        return listed

    @server.call_tool(validate_input=False)
    async def _call(name: str, arguments: dict[str, Any]) -> types.CallToolResult:
        CALLS.append((name, dict(arguments)))
        if name == "capabilities":
            return _text(json.dumps(MANIFEST))
        if name == "scan_rules":
            return _structured(RULE_ANSWER)
        if name == "query_hash":
            return _structured(LOOKUP_ANSWER)
        if name == "section_list":
            return _text(f"cannot open {arguments.get('path')}: no such file")
        return _text("written")

    return server


def _in_memory(server: Server) -> Any:
    """A stand-in for the stdio transport that serves ``server`` in this process."""

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
    """Install a settings object for the entries' writer, and put the process's back."""
    previous = get_settings()

    def _install(settings: Settings) -> Settings:
        install_settings(settings)
        declared_reading.forget()
        return settings

    yield _install
    install_settings(previous)
    declared_reading.forget()


def _probe(*, confirmed: list[str] | None = None, **entry_over: Any) -> Any:
    from app.services.settings_probes import probe_mcp

    entry = {"enabled": True, "command": "invented-server", **entry_over}
    return asyncio.run(
        probe_mcp({"name": SERVER, "entry": entry, "confirmed_calls": list(confirmed or [])})
    )


# ---------------------------------------------------------------------------
# The proposal
# ---------------------------------------------------------------------------


def test_the_probe_proposes_the_kinds_and_fields_with_their_evidence() -> None:
    result = _probe()
    assert result.ok is True
    proposals = result.details["proposals"]
    assert set(proposals["tools"]) == {
        "scan_rules",
        "query_hash",
        "section_list",
        "write_note",
        "submit_url",
    }
    # Nothing is called unless the operator confirms.
    assert [name for name, _args in CALLS] == ["capabilities"]
    assert "probed" not in proposals

    scan = proposals["tools"]["scan_rules"]
    assert scan["facts"] == {
        "kind": "signature_rules",
        "arguments": {"hash": "sha256", "path": "file_path"},
        "rows": "/matches/*",
        "places": {"offset": "/strings/*/offset"},
        "values": {"rule": "/rule"},
        "techniques": [{"path": "/**2/tags", "format": "sigma_tag"}],
        "asserts_techniques": True,
        "long_running": True,
        "timeout_seconds": 120.0,
        "display_name": "Rule scanner",
    }
    fields = scan["fields"]
    assert fields["arguments"]["evidence"] == [
        "inputSchema.properties.sha256 (name)",
        "inputSchema.properties.file_path (name)",
    ]
    assert fields["rows"]["evidence"] == ["outputSchema.matches (a list of objects)"]
    assert fields["techniques"]["evidence"] == ["outputSchema.matches[].tags"]
    assert fields["timeout_seconds"] == {
        "value": 120.0,
        "evidence": ["capabilities manifest timeout_s"],
        "confidence": "high",
    }
    assert fields["long_running"]["evidence"] == ["capabilities manifest long_running"]
    # A field brings only what makes it validate; never a kind.
    assert fields["places"]["requires"] == ["rows"]
    assert fields["asserts_techniques"]["requires"] == ["techniques"]
    assert "requires" not in fields["display_name"]
    # A guess about what a technique id means is the operator's to confirm.
    assert fields["asserts_techniques"]["confidence"] == "low"
    for held in fields.values():
        assert held["confidence"] in ("high", "medium", "low")
        assert held["evidence"]

    lookup = proposals["tools"]["query_hash"]["facts"]
    assert lookup["kind"] == "reputation"
    assert lookup["arguments"] == {"hash": "hash"}
    assert lookup["reputation"] == {
        "malicious": "/stats/malicious",
        "stats": "/stats",
        "total": "/stats/total",
        "link": ["/permalink"],
    }
    # Nothing names a kind for the lister: it is proposed none.
    assert proposals["tools"]["section_list"]["facts"] == {"arguments": {"path": "path"}}
    assert "error_patterns" not in proposals["server"]


def test_each_proposed_declaration_validates_as_a_saved_one() -> None:
    proposals = _probe().details["proposals"]
    tool_facts = {name: held["facts"] for name, held in proposals["tools"].items()}
    saved = MCPServerConfig.model_validate({"command": "invented-server", "tool_facts": tool_facts})
    assert set(saved.tool_facts) == set(tool_facts)


def test_the_probe_lists_the_calls_it_would_make_and_makes_none() -> None:
    proposals = _probe().details["proposals"]
    planned = {call["tool"]: call for call in proposals["planned"]}
    # Only the tools their own server marks read-only; never the destructive
    # writer, never the unannotated submitter.
    assert set(planned) == {"scan_rules", "query_hash", "section_list"}
    assert planned["query_hash"]["arguments"] == {"hash": hashlib.sha256(b"").hexdigest()}
    assert planned["query_hash"]["remote"] is True
    assert planned["section_list"]["remote"] is False
    assert all(call["credential"] is False for call in planned.values())
    assert [name for name, _args in CALLS] == ["capabilities"]


def test_only_the_confirmed_calls_are_made_and_never_name_a_sample() -> None:
    result = _probe(
        confirmed=["scan_rules", "query_hash", "section_list", "write_note", "submit_url"]
    )
    proposals = result.details["proposals"]
    assert proposals["probed"] == {
        "scan_rules": "called",
        "query_hash": "called",
        "section_list": "called",
    }
    called = {name: args for name, args in CALLS if name != "capabilities"}
    # A confirmation does not make an unplanned tool callable.
    assert set(called) == {"scan_rules", "query_hash", "section_list"}
    for name in ("scan_rules", "section_list"):
        (path,) = called[name].values()
        assert path.startswith("/nonexistent-maljan-probe/")
    assert called["query_hash"] == {"hash": hashlib.sha256(b"").hexdigest()}

    patterns = proposals["server"]["error_patterns"]
    assert patterns["confidence"] == "medium"
    assert patterns["evidence"] == ["probe answer of section_list to a path that does not exist"]
    (pattern,) = patterns["value"]
    assert pattern == {"match": r"cannot open .+: no such file", "tools": ["section_list"]}
    saved = MCPServerConfig.model_validate(
        {"command": "invented-server", "error_patterns": patterns["value"]}
    )
    assert saved.error_patterns[0].matches(
        "section_list", "cannot open /srv/elsewhere.bin: no such file"
    )


def test_a_confirmed_subset_calls_that_subset() -> None:
    _probe(confirmed=["section_list"])
    assert [name for name, _args in CALLS if name != "capabilities"] == ["section_list"]


def test_confirmed_calls_go_without_the_server_s_credentials_unless_it_needs_one() -> None:
    from pydantic import SecretStr

    from app.services.settings_probes import _needs_credential, _without_credentials

    token = "-".join(["runtime", "built", "value"])
    config = MCPServerConfig(
        command="invented-server",
        auth_token=SecretStr(token),
        env={"PLAIN": "1", "HIDDEN": "2"},
        env_allow=["PLAIN_TOO", "HIDDEN_TOO"],
        variable_names=["PLAIN", "PLAIN_TOO"],
    )
    stripped = _without_credentials(config)
    assert stripped.auth_token.get_secret_value() == ""
    assert stripped.env == {"PLAIN": "1"}
    assert stripped.env_allow == ["PLAIN_TOO"]
    needing = config.model_copy(update={"required_env_allow": ["HIDDEN_TOO"]})
    assert _needs_credential(needing) and _without_credentials(needing) is needing

    proposals = _probe(required_env_allow=["HIDDEN_TOO"]).details["proposals"]
    assert all(call["credential"] is True for call in proposals["planned"])


def test_a_declared_tool_gets_no_proposal_and_no_call() -> None:
    result = _probe(
        confirmed=["scan_rules"],
        tool_facts={"scan_rules": {"kind": "signature_rules_of_mine"}},
    )
    assert "scan_rules" not in result.details["proposals"]["tools"]
    assert "scan_rules" not in {name for name, _args in CALLS}


def test_a_proposal_that_cannot_be_built_never_fails_the_connection_test(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _broken(*_args: Any, **_kw: Any) -> Any:
        raise RuntimeError("no proposals")

    monkeypatch.setattr("maljan.core.declaration_proposals.propose", _broken)
    monkeypatch.setattr("maljan.core.declaration_proposals.plan_calls", _broken)
    result = _probe(confirmed=["section_list"])
    assert result.ok is True
    assert "proposals" not in (result.details or {})
    assert [name for name, _args in CALLS] == ["capabilities"]


# ---------------------------------------------------------------------------
# Accepting it, and not accepting it
# ---------------------------------------------------------------------------

# What an operator writes by hand for the scanner, from the server's docs.
HAND_WRITTEN = {
    "kind": "signature_rules",
    "asserts_techniques": True,
    "rows": "/matches/*",
    "places": {"offset": "/strings/*/offset"},
    "values": {"rule": "/rule"},
    "techniques": [{"path": "/**2/tags", "format": "sigma_tag"}],
    "arguments": {"path": "file_path", "hash": "sha256"},
    "long_running": True,
    "timeout_seconds": 120,
    "display_name": "Rule scanner",
}


def _settings(tool_facts: dict[str, Any] | None) -> Settings:
    block: dict[str, Any] = {"enabled": True, "command": "invented-server", "agents": ["static"]}
    if tool_facts is not None:
        block["tool_facts"] = tool_facts
    return Settings.model_validate({"mcp": {"servers": {SERVER: block}}})


def _scan_entry(settings: Settings) -> Any:
    async def _run() -> Any:
        registry = ServerRegistry(settings)
        tools, _reasons = await registry.atools_for("static", "job-1")
        try:
            recorder = EvidenceRecorder("static")
            recorded = {tool.name: tool for tool in record_tools(tools, recorder)}
            await recorded["scan_rules"].ainvoke({"file_path": "sample.bin"})
            return recorder.entries[0]
        finally:
            for handle in registry.still_open():
                await handle.aclose()

    return asyncio.run(_run())


def test_accepting_the_proposal_runs_as_a_hand_written_declaration(installed: Any) -> None:
    proposals = _probe().details["proposals"]
    # The console sends the accepted facts as JSON, through the settings path.
    accepted = json.loads(json.dumps(proposals["tools"]["scan_rules"]["facts"]))
    assert ToolFacts.model_validate(accepted) == ToolFacts.model_validate(HAND_WRITTEN)

    by_proposal = _scan_entry(installed(_settings({"scan_rules": accepted})))
    by_hand = _scan_entry(installed(_settings({"scan_rules": HAND_WRITTEN})))
    assert by_proposal.facts == by_hand.facts
    assert by_proposal.facts["kind"] == "signature_rules"
    assert asserted_techniques(by_proposal) == asserted_techniques(by_hand) == {"T1055"}
    assert asserting_source(by_proposal) == asserting_source(by_hand) == "scan_rules"

    def _drawn(entry: Any) -> list[Any]:
        return [s.model_dump() for s in build_sections([entry])]

    assert _drawn(by_proposal) == _drawn(by_hand)


def test_without_acceptance_the_tool_stays_undeclared(installed: Any) -> None:
    settings = installed(_settings(None))
    before = _scan_entry(settings)
    _probe(confirmed=["scan_rules", "query_hash", "section_list"])
    after = _scan_entry(settings)
    assert before.facts == after.facts == {"v": 1}
    assert asserted_techniques(after) == set()
    assert settings.mcp.servers[SERVER].tool_facts == {}


def _lister_call(settings: Settings) -> tuple[Any, list[Any]]:
    """One ``section_list`` call recorded through the registry, and the tools offered."""

    async def _run() -> tuple[Any, list[Any]]:
        registry = ServerRegistry(settings)
        tools, _reasons = await registry.atools_for("static", "job-1")
        try:
            recorder = EvidenceRecorder("static")
            recorded = {tool.name: tool for tool in record_tools(tools, recorder)}
            await recorded["section_list"].ainvoke({"path": "sample.bin"})
            return recorder.entries[0], list(tools)
        finally:
            for handle in registry.still_open():
                await handle.aclose()

    return asyncio.run(_run())


def _what_an_undeclared_tool_gets(entry: Any, tools: list[Any]) -> dict[str, Any]:
    """The readings an undeclared tool gets, and the composer section its cited output reaches."""
    from types import SimpleNamespace

    from maljan.agents.network_analyst import _undeclared_tools_in
    from maljan.core.undeclared_tools import entry_code_kind, entry_is_strings_source
    from maljan.reporting import tool_kinds
    from maljan.reporting.evidence_bundles import bundle_for
    from maljan.reporting.models import (
        EvidenceIndexRow,
        FileHashes,
        MalwareReport,
        SampleIdentity,
    )

    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        technical_evidence={"static": [entry.to_captured().model_dump()]},
        evidence_index=[
            EvidenceIndexRow(
                id=entry.id,
                agent=entry.agent,
                tool=entry.tool,
                source=entry.source,
                facts=entry.facts,
            )
        ],
    )
    isr = {
        "static": SimpleNamespace(
            agent_id="static",
            claims=[
                SimpleNamespace(
                    claim="The sample persists through a scheduled task.",
                    evidence_ref=entry.id,
                    confidence=0.8,
                )
            ],
        )
    }
    return {
        "read_as_undeclared": tool_kinds.facts_of(entry) is None,
        "code_kind": entry_code_kind(entry),
        "strings": entry_is_strings_source(entry),
        "undeclared_offered": _undeclared_tools_in(tools),
        "reaches": [
            o["tool"] for o in bundle_for("persistence_detail", report, None, isr)["tool_outputs"]
        ],
    }


@pytest.mark.parametrize(
    "accepted",
    [
        # What accepting only the proposed display name stages.
        {"section_list": {"display_name": "Sections"}},
        # An operator who typed the word a proposal once offered for no kind.
        {"section_list": {"kind": "unclassified"}},
        {"section_list": {"kind": "unclassified", "timeout_seconds": 30}},
    ],
)
def test_accepting_a_field_without_a_kind_keeps_what_an_undeclared_tool_gets(
    installed: Any, accepted: dict[str, Any]
) -> None:
    from maljan.core.undeclared_tools import declares_a_kind

    undeclared_entry, undeclared_tools = _lister_call(installed(_settings(None)))
    before = _what_an_undeclared_tool_gets(undeclared_entry, undeclared_tools)
    assert before["reaches"] == ["section_list"] and before["read_as_undeclared"]

    settings = installed(_settings(accepted))
    assert not declares_a_kind(settings.mcp.servers[SERVER].tool_facts["section_list"])
    entry, tools = _lister_call(settings)
    assert _what_an_undeclared_tool_gets(entry, tools) == before


def test_a_run_s_handle_keeps_no_tool_definitions() -> None:
    async def _run() -> list[Any]:
        registry = ServerRegistry(_settings(None))
        await registry.atools_for("static", "job-1")
        try:
            return [handle.tool_definitions() for handle in registry.still_open()]
        finally:
            for handle in registry.still_open():
                await handle.aclose()

    held = asyncio.run(_run())
    assert held and all(definitions == [] for definitions in held)


def test_no_run_module_reads_a_proposal() -> None:
    """Proposals reach the console and nothing else: only the settings probe imports them."""
    import re
    from pathlib import Path

    import maljan

    imports = re.compile(r"^\s*(?:from|import)\s+maljan\.core\.declaration_proposals\b", re.M)
    root = Path(maljan.__file__).parent
    readers = sorted(
        str(path.relative_to(root))
        for path in root.rglob("*.py")
        if imports.search(path.read_text(encoding="utf-8"))
    )
    assert readers == []
    api = Path(__file__).resolve().parents[3] / "apps" / "api" / "app"
    api_readers = sorted(
        str(path.relative_to(api))
        for path in api.rglob("*.py")
        if imports.search(path.read_text(encoding="utf-8"))
    )
    assert api_readers == ["services/settings_probes.py"]


def test_a_tool_declared_without_a_kind_is_still_introduced_by_the_server_s_own_words() -> None:
    from langchain_core.tools import StructuredTool

    from maljan.providers.servers import _own_words

    tools = [
        StructuredTool.from_function(
            func=lambda: "", name="section_list", description="Lists sections.", args_schema=None
        )
    ]

    class _Handle:
        name = SERVER
        server_instructions = "served words"

        def __init__(self, tool_facts: dict[str, Any]) -> None:
            self.config = MCPServerConfig(command="invented-server", tool_facts=tool_facts)

    assert _own_words(_Handle({}), tools)
    assert _own_words(_Handle({"section_list": {"display_name": "Sections"}}), tools)
    assert _own_words(_Handle({"section_list": {"kind": "listing_strings"}}), tools) == ""

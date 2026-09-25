"""The all-tools team an operator imports is one the settings API accepts and the run resolves.

``docs/examples/profiles/all-tools.json`` is a settings import document: three
static analysts on three tools in one stage (the sidecars, radare2 and the
Qu1cksc0pe server), a reverser on Ghidra after them, then detonation, network,
debate, verdict and report. These load it through the validation
``POST /api/v1/settings/import`` runs, build the settings a job would run on,
and resolve every agent the way a job does, with stub tool servers and a stub
Ghidra on the loopback: no model is called and nothing is analysed.
"""

from __future__ import annotations

import asyncio
import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from langchain_core.tools import StructuredTool

from app.services.agent_map import (
    AGENT_DEFINITIONS_KEY,
    AGENT_PROFILES_KEY,
    validate_agent_map,
)
from maljan.agents.composition import aresolve_agent, reachable_agents, reads_static_provider
from maljan.agents.prompts import REVERSER_PROMPT
from maljan.core.settings_overrides import build_settings
from maljan.providers.static.ghidra import GHIDRA_GUIDANCE, GHIDRA_WORKFLOW
from maljan.providers.static.r2 import R2StaticProvider

DOCUMENT = Path(__file__).resolve().parents[2] / "docs" / "examples" / "profiles" / "all-tools.json"
TEAM = "all_tools"

GHIDRA_SCHEMA = {
    "tools": [
        {
            "path": "/load_program",
            "method": "POST",
            "params": [{"name": "file", "type": "string", "required": True}],
        },
        {
            "path": "/decompile_function",
            "method": "GET",
            "params": [{"name": "address", "type": "string", "required": True}],
        },
        {"path": "/get_xrefs_to", "method": "GET", "params": []},
    ]
}


class _Ghidra(BaseHTTPRequestHandler):
    paths: list[str] = []

    def do_GET(self) -> None:  # noqa: N802 - the stdlib's name
        type(self).paths.append(self.path)
        body = json.dumps(GHIDRA_SCHEMA).encode()
        self.send_response(200 if self.path == "/mcp/schema" else 404)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: Any) -> None:
        return None


@pytest.fixture
def ghidra_url() -> Iterator[str]:
    handler = type("Handler", (_Ghidra,), {"paths": []})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _document() -> dict[str, Any]:
    return json.loads(DOCUMENT.read_text(encoding="utf-8"))


# What an operator's store already holds for the run: the Qu1cksc0pe server
# the team names, the three providers and the global provider switched to
# none, so each static analyst is on a tool of its own. Stub commands: the
# tool servers are never started here.
STORED: dict[str, Any] = {
    "core.mcp.servers": {
        "qu1cksc0pe": {
            "enabled": True,
            "transport": "stdio",
            "command": "qu1cksc0pe-mcp",
            "label": "Qu1cksc0pe",
        },
    },
    "core.static.provider": "none",
}


def _settings(ghidra_url: str) -> Any:
    changes = _document()["values"]
    validated = validate_agent_map(dict(changes), STORED)
    merged = {**STORED, **validated, "core.agents.profile": TEAM}
    core = {key.removeprefix("core."): value for key, value in merged.items()}
    core["static.ghidra"] = {
        "enabled": True,
        "transport": "http",
        "url": ghidra_url,
        "auth_token": "tok",
    }
    settings = build_settings(core)
    for name in ("analysis", "knowledge", "virustotal", "network", "threatintel"):
        settings.mcp.servers[name].enabled = True
        # The stub servers offer tools of their own names; no allow-list of
        # the real servers' tool names applies to them.
        settings.mcp.servers[name].tools = None
    return settings


class _Toolkit:
    """A tool server that answers the handshake with two tools named after itself."""

    def __init__(self, name: str) -> None:
        self._tools = [
            StructuredTool.from_function(
                func=lambda: "ok", name=f"{name}_{verb}", description=f"{name} {verb}"
            )
            for verb in ("read", "search")
        ]

    async def initialize(self) -> None:
        return None

    def get_tools(self) -> list[Any]:
        return list(self._tools)

    async def cleanup(self) -> None:
        return None


class _Container:
    """The part of ``ServiceContainer`` resolution reads, with real providers and registry."""

    mock = True
    sandbox_report = None

    def __init__(self, settings: Any) -> None:
        from maljan.core.truncation_ledger import TruncationLedger
        from maljan.llm.context_window import budget_for_settings
        from maljan.providers.servers import ServerRegistry

        self.config = settings
        self._providers: dict[str, Any] = {}
        self._ledger = TruncationLedger()
        self._budget = budget_for_settings(settings, ["static"], probe=False)
        self._registry = ServerRegistry(settings, truncation_ledger=self._ledger)

    def get_static_provider(self, provider_id: str | None = None) -> Any:
        from maljan.providers.registry import get_static_provider

        wanted = str(provider_id or self.config.static.provider)
        if wanted not in self._providers:
            cfg = self.config
            if wanted != str(cfg.static.provider):
                cfg = cfg.model_copy(deep=True)
                cfg.static.provider = wanted
            self._providers[wanted] = get_static_provider(cfg)
        return self._providers[wanted]

    def get_sandbox_provider(self) -> Any:
        return None

    def get_server_registry(self) -> Any:
        return self._registry

    def get_context_budget(self) -> Any:
        return self._budget

    def get_truncation_ledger(self) -> Any:
        return self._ledger

    def job_key(self) -> str:
        return "job-under-test"

    def close(self) -> None:
        for provider in self._providers.values():
            provider.close()


@pytest.fixture
def container(ghidra_url: str, monkeypatch: pytest.MonkeyPatch) -> Iterator[_Container]:
    from maljan.providers.servers import ServerHandle

    monkeypatch.setattr(ServerHandle, "_build_toolkit", lambda self, *a, **k: _Toolkit(self.name))
    built = _Container(_settings(ghidra_url))
    try:
        yield built
    finally:
        built.close()


def _resolve(container: _Container, key: str) -> Any:
    """Resolve on one loop and close what it opened on the same loop, as a job does."""

    async def _run() -> Any:
        try:
            return await aresolve_agent(key, container, "job-under-test")
        finally:
            for handle in container.get_server_registry().still_open():
                await handle.aclose()

    return asyncio.run(_run())


def _servers(resolved: Any) -> set[str]:
    return {str(tool.name).split("_")[0] for tool in resolved.tools}


class TestTheDocument:
    def test_it_is_an_import_document(self) -> None:
        document = _document()
        assert document["format"] == "maljan-settings/1"
        assert set(document["values"]) == {AGENT_DEFINITIONS_KEY, AGENT_PROFILES_KEY}

    def test_the_settings_api_accepts_it(self) -> None:
        validated = validate_agent_map(dict(_document()["values"]), STORED)
        assert TEAM in validated[AGENT_PROFILES_KEY]
        for key in ("static_r2", "static_qu1cksc0pe", "reverser_ghidra"):
            assert key in validated[AGENT_DEFINITIONS_KEY]

    def test_the_stages_are_the_team_the_run_needs(self, ghidra_url: str) -> None:
        team = _settings(ghidra_url).agents.profiles[TEAM]
        assert [stage.key for stage in team.stages] == [
            "triage_pack",
            "triage",
            "static",
            "reversing",
            "dynamic",
            "network",
            "debate",
            "verdict",
            "report",
        ]
        by_key = {stage.key: stage for stage in team.stages}
        assert by_key["static"].agents == ["static", "static_r2", "static_qu1cksc0pe"]
        assert by_key["reversing"].agents == ["reverser_ghidra"]
        assert by_key["reversing"].inject_upstream == "findings"
        assert by_key["network"].when == "has_pcap or has_sandbox_report"

    def test_the_reverser_is_the_seeded_one_on_ghidra(self, ghidra_url: str) -> None:
        """The document carries the seeded prompt verbatim, so the two cannot drift."""
        definitions = _settings(ghidra_url).agents.definitions
        assert definitions["reverser_ghidra"].prompt == REVERSER_PROMPT
        assert definitions["reverser_ghidra"].static_provider == "ghidra"

    def test_every_provider_the_run_opens_is_mirrored_for(self, ghidra_url: str) -> None:
        settings = _settings(ghidra_url)
        team = settings.agents.profiles[TEAM]
        named = [agent for stage in team.stages for agent in stage.agents]
        opens = {
            key
            for key in reachable_agents(settings, named)
            if reads_static_provider(settings.agents.definitions.get(key))
        }
        assert opens == {"static", "static_r2", "reverser_ghidra"}


class TestEveryAgentResolves:
    def test_the_static_analyst_reads_the_sidecars(self, container: _Container) -> None:
        resolved = _resolve(container, "static")
        assert _servers(resolved) == {"analysis", "knowledge", "virustotal"}
        assert resolved.static_provider_id == "none"
        assert resolved.degradation_reasons == ()

    def test_the_r2_clone_reads_r2_and_two_sidecars(self, container: _Container) -> None:
        resolved = _resolve(container, "static_r2")
        assert _servers(resolved) == {"analysis", "knowledge"}
        assert resolved.static_provider_id == "r2"
        # The class opens r2 when it runs; resolution describes it as expected.
        assert R2StaticProvider.R2_PROMPT_FRAGMENT.split(" through")[0] in resolved.prompt
        assert "load_program" not in resolved.prompt

    def test_the_qu1cksc0pe_analyst_reads_its_server_only(self, container: _Container) -> None:
        resolved = _resolve(container, "static_qu1cksc0pe")
        assert {tool.name for tool in resolved.tools} == {
            "qu1cksc0pe_read",
            "qu1cksc0pe_search",
        }
        assert resolved.degradation_reasons == ()

    def test_the_reverser_gets_ghidra_s_tools_and_its_workflow(self, container: _Container) -> None:
        resolved = _resolve(container, "reverser_ghidra")
        names = {tool.name for tool in resolved.tools}
        assert {"load_program", "decompile_function", "get_xrefs_to"} <= names
        assert {"knowledge_read", "virustotal_read"} <= names
        assert resolved.static_provider_id == "ghidra"
        assert resolved.prompt.startswith(REVERSER_PROMPT)
        assert GHIDRA_WORKFLOW in resolved.prompt
        assert GHIDRA_GUIDANCE in resolved.prompt
        assert resolved.degradation_reasons == ()

    def test_the_reverser_on_r2_would_get_r2_s_workflow_instead(
        self, container: _Container
    ) -> None:
        container.config.agents.definitions["reverser_ghidra"].static_provider = "r2"
        r2 = container.get_static_provider("r2")
        r2.get_tools = lambda: [  # type: ignore[method-assign]
            StructuredTool.from_function(func=lambda: "ok", name="open_file", description="o")
        ]
        r2.open = lambda job: None  # type: ignore[method-assign]
        resolved = _resolve(container, "reverser_ghidra")
        assert "open_file" in {tool.name for tool in resolved.tools}
        assert R2StaticProvider.R2_PROMPT_FRAGMENT in resolved.prompt
        assert GHIDRA_WORKFLOW not in resolved.prompt

    @pytest.mark.parametrize(
        ("key", "servers"),
        [
            ("triage", {"analysis", "knowledge", "virustotal"}),
            ("network", {"network", "knowledge", "virustotal"}),
            ("dynamic", {"sandbox", "knowledge"}),
            ("judge", {"knowledge", "virustotal", "threatintel"}),
        ],
    )
    def test_the_rest_of_the_team_keeps_its_seeded_tools(
        self, container: _Container, key: str, servers: set[str]
    ) -> None:
        resolved = _resolve(container, key)
        assert _servers(resolved) == servers

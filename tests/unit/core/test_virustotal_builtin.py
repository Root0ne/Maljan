"""The VirusTotal built-in: what it is seeded as, and what it is bound to.

Two claims are worth a test rather than a reading of the seed. The tick list
is one: the lookups are read-only and are on, the submit tools upload the
sample to VirusTotal and are off, and a later edit that quietly adds one to the
default list is a disclosure nobody asked for. The other is that the server
ships disabled and without a credential, so a deployment that never registers
dials nothing.
"""

from __future__ import annotations

import json
from pathlib import Path

from maljan.core import virustotal
from maljan.core.config import (
    BUILTIN_SERVER_KEYS,
    RESERVED_SERVER_KEYS,
    Settings,
    ToolRef,
)

GOLDEN = (
    Path(__file__).resolve().parents[2] / "fixtures" / "golden" / "mcp_tools" / "virustotal.json"
)


def _golden() -> dict:
    return json.loads(GOLDEN.read_text(encoding="utf-8"))


class TestTheSeed:
    def test_it_is_the_http_endpoint_and_starts_disabled(self) -> None:
        server = Settings(_env_file=None).mcp.servers[virustotal.SERVER_KEY]
        assert server.enabled is False
        assert server.transport == "streamable-http"
        assert server.url == virustotal.MCP_ENDPOINT
        assert server.label == virustotal.SERVER_LABEL
        assert server.command == "" and server.args == []
        assert server.auth_token.get_secret_value() == ""
        # Bound by the definitions' own references, never by role.
        assert server.agents == []

    def test_only_the_read_only_lookups_are_ticked(self) -> None:
        server = Settings(_env_file=None).mcp.servers[virustotal.SERVER_KEY]
        assert server.tools == list(virustotal.LOOKUP_TOOLS)
        assert not set(server.tools or []) & set(virustotal.SUBMIT_TOOLS)

    def test_the_key_is_a_built_in_and_reserved(self) -> None:
        assert virustotal.SERVER_KEY in BUILTIN_SERVER_KEYS
        assert virustotal.SERVER_KEY in RESERVED_SERVER_KEYS

    def test_the_network_analyst_the_judge_and_triage_reference_it(self) -> None:
        definitions = Settings(_env_file=None).agents.definitions
        ref = ToolRef(kind="mcp", server=virustotal.SERVER_KEY)
        for key in ("network", "judge", "triage"):
            assert ref in definitions[key].tools, key

    def test_the_threat_intel_sidecar_is_left_exactly_as_it_was(self) -> None:
        """The VT REST sidecar keeps its key, its keys and its binding.

        ``virustotal`` supersedes the VirusTotal half of ``threatintel`` when
        an operator enables it, and supersede is not replace: a deployment
        that has an API key and no agent token keeps working unchanged.
        """
        intel = Settings(_env_file=None).mcp.servers["threatintel"]
        assert intel.enabled is True
        assert intel.env_allow == ["VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY"]
        assert intel.agents == ["judge"]


class TestTheGoldenManifest:
    def test_it_names_a_unique_sorted_tool_set(self) -> None:
        tools = _golden()["tools"]
        assert tools == sorted(set(tools)) and tools

    def test_every_ticked_lookup_is_a_tool_the_server_offers(self) -> None:
        """The default tick list is a subset of the real manifest.

        A ticked name the server does not offer is a tool the agent silently
        never gets, which is exactly the failure a tick list is meant to make
        visible.
        """
        assert set(virustotal.LOOKUP_TOOLS) <= set(_golden()["tools"])

    def test_the_local_upload_tool_is_absent_over_http(self) -> None:
        """``submit_local_file`` is stdio-only, and the fixture must say so.

        The remote server cannot open this host's filesystem. Documenting the
        stdio install as the way to reach that tool only holds while the HTTP
        manifest really lacks it.
        """
        assert "submit_local_file" not in _golden()["tools"]
        assert "submit_local_file" in virustotal.SUBMIT_TOOLS


class TestTheStdioAlternative:
    def test_an_installed_vt_mcp_is_launched_directly(self) -> None:
        command, args = virustotal.stdio_command(lambda name: "/usr/local/bin/vt-mcp")
        assert command == virustotal.STDIO_COMMAND
        assert args == []

    def test_without_it_the_pinned_uvx_invocation_is_used(self) -> None:
        command, args = virustotal.stdio_command(lambda name: None)
        assert command == "uvx"
        assert args == ["--python", "3.12", f"vt-mcp=={virustotal.VT_MCP_VERSION}"]

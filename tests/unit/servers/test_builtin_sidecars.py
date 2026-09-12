"""The two tool sidecars' manifests are the contract an agent calls them by.

``test_builtin_tool_sets`` pins the older sidecars by tool name, because that
is what the move-into-settings claim rested on. These two are pinned by
argument names as well: an argument silently renamed is a tool that stops
working for every agent at once, with nothing anywhere to say why. Regenerate
with ``uv run python scripts/goldens/capture_builtin_tool_sets.py``.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
GOLDEN = ROOT / "tests" / "fixtures" / "golden" / "mcp_tools"

TOOL_SIDECARS = ["analysis", "knowledge"]

_INTERPRETER_MISSING = not sys.executable or not shutil.which(sys.executable)


def _golden(name: str) -> dict:
    return json.loads((GOLDEN / f"{name}.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("name", TOOL_SIDECARS)
def test_the_golden_pins_arguments_and_not_only_names(name: str) -> None:
    payload = _golden(name)
    assert payload["tools"], f"{name} golden is empty"
    assert payload["tools"] == sorted(set(payload["tools"]))
    assert set(payload["arguments"]) == set(payload["tools"]), (
        "every pinned tool must have its argument names pinned too"
    )


def test_the_analysis_golden_carries_the_tools_the_static_analyst_needs() -> None:
    """Named rather than counted: a count moves whenever anything is added,
    and says nothing about whether the capability an analyst depends on is
    still there."""
    tools = set(_golden("analysis")["tools"])
    assert {
        "identify_file",
        "hashes",
        "signing_info",
        "strings",
        "iocs_from_file",
        "pe_info",
        "elf_info",
        "macho_info",
        "apk_info",
        "archive_list",
        "document_info",
        "carve_payloads",
        "yara_scan",
        "sigma_match",
        "capa",
    } <= tools


def test_the_analysis_golden_carries_the_whole_sample_delivery_convention() -> None:
    tools = set(_golden("analysis")["tools"])
    assert {"put_sample", "put_sample_begin", "put_sample_chunk", "put_sample_finish"} <= tools

    arguments = _golden("analysis")["arguments"]
    assert set(arguments["put_sample"]) == {"filename", "content_b64", "sha256"}
    assert set(arguments["put_sample_begin"]) == {"filename", "sha256", "size"}
    assert set(arguments["put_sample_chunk"]) == {"upload_id", "seq", "content_b64"}
    assert set(arguments["put_sample_finish"]) == {"upload_id"}


def test_the_knowledge_golden_carries_the_reference_lookups() -> None:
    tools = set(_golden("knowledge")["tools"])
    assert tools == {
        "resolve_technique",
        "attck_lookup",
        "attck_validate",
        "api_capability",
        "lolbin_lookup",
        "family_lookup",
        "similar_cases",
    }


def test_the_network_golden_gained_the_whole_capture_view() -> None:
    """``pcap_summary`` joined the three packet-level tools on the existing
    sidecar rather than moving them somewhere new."""
    tools = set(_golden("network")["tools"])
    assert "pcap_summary" in tools
    assert {"read_pcap_summary", "extract_dns", "extract_http"} <= tools


@pytest.mark.skipif(
    _INTERPRETER_MISSING, reason="no python interpreter available to launch the sidecar"
)
@pytest.mark.parametrize("name", TOOL_SIDECARS)
def test_the_live_sidecar_offers_exactly_the_pinned_manifest(name: str) -> None:
    """A real stdio handshake. Neither sidecar reaches the network to answer
    ``initialize`` or ``tools/list``, so a failure here is a real signal that
    the manifest moved."""
    from scripts.goldens.capture_builtin_tool_sets import SIDECARS, enumerate_stdio_manifest

    from maljan.agents.subprocess_env import child_env

    subdir, allow = SIDECARS[name]
    live = asyncio.run(
        asyncio.wait_for(
            enumerate_stdio_manifest(
                sys.executable,
                [str(ROOT / subdir / "server.py")],
                str(ROOT / subdir),
                child_env(allow=allow),
            ),
            timeout=60.0,
        )
    )

    payload = _golden(name)
    assert sorted(live) == payload["tools"]
    assert {name: sorted(args) for name, args in live.items()} == payload["arguments"]


@pytest.mark.parametrize("name", TOOL_SIDECARS)
def test_the_sidecar_is_registered_as_a_built_in_with_the_launch_parameters_it_needs(
    name: str,
) -> None:
    from maljan.core.config import BUILTIN_SERVER_KEYS, RESERVED_SERVER_KEYS, Settings

    assert name in BUILTIN_SERVER_KEYS
    assert name in RESERVED_SERVER_KEYS
    server = Settings(_env_file=None).mcp.servers[name]
    assert server.enabled is True
    assert server.transport == "stdio"
    assert server.command == sys.executable
    assert server.args == [f"services/{name}-mcp/server.py"]
    assert server.cwd == f"services/{name}-mcp"
    assert server.tools is None, "a built-in exposes its whole manifest"
    assert server.agents == [], (
        "a tool sidecar binds through the definitions' tool references only, "
        "so a definition that drops the reference really loses the tools"
    )


def test_only_the_analysis_sidecar_is_allowed_to_see_the_staging_directory() -> None:
    """The staging variables say where uploads land and how long they are
    kept, and no other built-in has any business reading either."""
    from maljan.core.config import Settings

    servers = Settings(_env_file=None).mcp.servers
    assert servers["analysis"].env_allow == ["MALJAN_STAGING_DIR", "MALJAN_STAGING_TTL_HOURS"]
    assert servers["knowledge"].env_allow == []

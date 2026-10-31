"""A capability reference resolves, and a save passes, before any server was listed.

A settings database cloned from a deployment keeps no declaration its servers
served (``core.served_declarations``), and a server bound to the judge by its
own ``agents`` list still serves the reputation capability. Before the fix,
every save on such a database was refused ("references capability
'reputation', which no tool server declares a tool of") and every
capability reference resolved to no server at run time.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from maljan.agents.composition import capability_servers, mcp_refs_for, servers_bound_to
from maljan.core import served_declarations
from maljan.core.settings_overrides import build_settings, unknown_reference_refusals

ENTRY = {"provider": "openai", "model": "m"}
LOOKING_UP = ("static", "network", "judge", "triage", "android_static", "reverser")
# The stored rows of a cloned database: the built-in servers as saved, the
# threat-intel sidecar still bound to the judge alone.
CLONED = {
    "mcp.servers": {
        "threatintel": {"enabled": True, "agents": ["judge"]},
        "virustotal": {"enabled": False},
    },
    "llm.agents": {"static": ENTRY},
}


@pytest.fixture
def nothing_listed() -> Iterator[None]:
    """No server's tools were ever listed, as on a fresh or cloned database."""
    served_declarations._UNSAVED.clear()
    served_declarations.forget_served()
    yield


def test_a_save_on_a_cloned_database_is_not_refused(nothing_listed: None) -> None:
    merged = {**CLONED, "llm.agents": {"static": ENTRY, "judge": ENTRY}}
    assert unknown_reference_refusals(merged, CLONED) == {}


def test_a_capability_no_block_names_is_not_refused_before_its_server_is_listed(
    nothing_listed: None,
) -> None:
    clone = {
        "role": "generic",
        "prompt": "p",
        "tools": [{"kind": "capability", "capability": "function_index"}],
    }
    merged = {**CLONED, "agents.definitions": {"mine": clone}}
    assert unknown_reference_refusals(merged, CLONED) == {}


def test_a_capability_reaches_the_reputation_server_bound_to_the_judge(
    nothing_listed: None,
) -> None:
    settings = build_settings(CLONED)
    assert capability_servers(settings, "reputation") == ["threatintel", "virustotal"]
    for key in LOOKING_UP:
        refs = [str(ref.server) for ref in mcp_refs_for(settings, key)]
        assert refs.count("threatintel") == 1, key
        assert "threatintel" in servers_bound_to(settings, key), key


def test_the_threat_intel_sidecar_is_reached_once_its_tools_are_listed_too() -> None:
    # The default test state: every own server listed and kept.
    settings = build_settings(CLONED)
    assert capability_servers(settings, "reputation") == ["threatintel", "virustotal"]
    assert unknown_reference_refusals({**CLONED, "llm.agents": {"judge": ENTRY}}, CLONED) == {}

"""The built-in agents reach reputation by capability, and a stored settings row still loads.

``ToolRef(kind="capability", capability="reputation")`` stands for every
built-in server that says it serves reputation (its block's roles, or a tool it
declares), referenced as a reference by key is, whether or not its own
``agents`` list binds it to someone. With the shipped servers that is the
threat-intel sidecar and VirusTotal's own server, so the default profile
resolves to the servers the definitions named by key before, and the sidecar
beside them. A built-in row stored with that earlier list is its seed of an
earlier release and loads as the seed.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from maljan.agents.composition import capability_servers, mcp_refs_for
from maljan.core.config import FORMER_SEED_TOOLS, Settings, ToolRef, _builtin_definitions

LOOKING_UP = ("static", "network", "judge", "triage", "android_static", "reverser")


def _former(key: str) -> list[dict[str, Any]]:
    """Built-in ``key``'s tool list as the release before this one stored it."""
    return [
        FORMER_SEED_TOOLS[f"capability:{ref.capability}"]
        if ref.kind == "capability"
        else ref.model_dump()
        for ref in _builtin_definitions()[key].tools
    ]


def test_the_default_profile_resolves_to_the_servers_it_always_did_and_the_sidecar() -> None:
    settings = Settings(_env_file=None)
    for key in LOOKING_UP:
        resolved = [ref.model_dump() for ref in mcp_refs_for(settings, key)]
        former = [r for r in _former(key) if r["kind"] == "mcp"]
        assert [r for r in resolved if r["server"] != "threatintel"] == former, key
        assert {"kind": "mcp", "server": "threatintel", "name": None} in resolved, key


def test_the_capability_counts_a_built_in_its_seed_binds_by_its_own_agents_list() -> None:
    settings = Settings(_env_file=None)
    # The threat-intel sidecar declares a lookup and its seed binds it to the judge.
    assert settings.mcp.servers["threatintel"].agents == ["judge"]
    assert capability_servers(settings, "reputation") == ["threatintel", "virustotal"]
    assert capability_servers(settings, "no_such_kind") == []


def test_a_server_row_stored_with_a_lookup_s_former_kind_is_still_reached() -> None:
    """A row saved while the lookups declared ``file_reputation`` keeps its lookup."""
    from maljan.core.declared_reading import declarations
    from maljan.core.reputation import pack_lookups

    settings = Settings.model_validate(
        {
            "mcp": {
                "servers": {
                    "virustotal": {
                        "tool_facts": {
                            "get_file_report": {
                                "kind": "file_reputation",
                                "arguments": {"hash": "hash"},
                            }
                        }
                    }
                }
            }
        }
    )
    assert "virustotal" in capability_servers(settings, "reputation")
    lookups = pack_lookups(settings.mcp.servers, declarations(settings))
    assert ("virustotal", "get_file_report") in {(lk.server, lk.tool) for lk in lookups}


@pytest.mark.parametrize("key", LOOKING_UP)
def test_a_built_in_row_stored_with_the_former_list_loads_as_the_seed(key: str) -> None:
    seed = _builtin_definitions()[key]
    stored = {**seed.model_dump(), "tools": _former(key)}
    settings = Settings(_env_file=None, agents={"definitions": {key: stored}})
    assert settings.agents.definitions[key].tools == seed.tools


def test_the_settings_api_reads_the_former_list_as_the_seed() -> None:
    from app.services.agent_map import staged_definitions

    seed = _builtin_definitions()["static"]
    staged = staged_definitions({"static": {**seed.model_dump(), "tools": _former("static")}})
    assert staged["static"]["tools"] == [ref.model_dump() for ref in seed.tools]


def test_a_built_in_row_with_another_list_is_still_refused() -> None:
    seed = _builtin_definitions()["static"]
    stored = {**seed.model_dump(), "tools": [{"kind": "mcp", "server": "knowledge"}]}
    with pytest.raises(ValidationError, match="built in; clone it to change it"):
        Settings(_env_file=None, agents={"definitions": {"static": stored}})


def test_an_operator_clone_naming_the_server_by_key_keeps_its_list() -> None:
    clone = {
        "role": "static",
        "label": "Mine",
        "tools": [{"kind": "mcp", "server": "virustotal"}, {"kind": "mcp", "server": "analysis"}],
    }
    settings = Settings(_env_file=None, agents={"definitions": {"mine": clone}})
    assert [r.server for r in settings.agents.definitions["mine"].tools] == [
        "virustotal",
        "analysis",
    ]


def test_a_capability_reference_names_a_kind_and_nothing_else() -> None:
    assert ToolRef(kind="capability", capability="reputation").model_dump() == {
        "kind": "capability",
        "server": None,
        "name": None,
        "capability": "reputation",
    }
    # Every other kind dumps as it always did.
    assert ToolRef(kind="mcp", server="analysis").model_dump() == {
        "kind": "mcp",
        "server": "analysis",
        "name": None,
    }
    for bad in (
        {"kind": "capability"},
        {"kind": "capability", "capability": "Not A Word"},
        {"kind": "capability", "capability": "reputation", "server": "virustotal"},
        {"kind": "mcp", "server": "analysis", "capability": "reputation"},
    ):
        with pytest.raises(ValidationError):
            ToolRef.model_validate(bad)


def test_a_server_named_by_key_and_by_capability_is_attached_once() -> None:
    settings = Settings(_env_file=None)
    definition = settings.agents.definitions["static"].model_copy(
        update={
            "tools": [
                ToolRef(kind="mcp", server="virustotal"),
                ToolRef(kind="capability", capability="reputation"),
            ]
        }
    )
    settings.agents.definitions["mine"] = definition
    assert [str(r.server) for r in mcp_refs_for(settings, "mine")] == ["virustotal", "threatintel"]


# The stored server rows the capability must resolve as dev 2c2522b2 resolved
# them, with the threat-intel sidecar beside them wherever a definition
# references the capability: every definition's servers (``servers_bound_to``)
# and server references (``mcp_refs_for``).
_STORED_ROWS: dict[str, dict[str, Any]] = {
    "default": {},
    "vt_enabled": {"mcp": {"servers": {"virustotal": {"enabled": True}}}},
    "vt_empty_agents": {"mcp": {"servers": {"virustotal": {"enabled": True, "agents": []}}}},
    # A non-empty list, which leaves out every agent but the one it names.
    "vt_judge": {"mcp": {"servers": {"virustotal": {"enabled": True, "agents": ["judge"]}}}},
    "vt_dynamic": {"mcp": {"servers": {"virustotal": {"enabled": True, "agents": ["dynamic"]}}}},
    "vt_ticked": {
        "mcp": {"servers": {"virustotal": {"enabled": True, "tools": ["get_file_report"]}}}
    },
    "ti_none": {
        "mcp": {"servers": {"threatintel": {"agents": []}, "virustotal": {"enabled": True}}}
    },
}


@pytest.mark.parametrize("case", sorted(_STORED_ROWS))
def test_every_agent_under_every_team_resolves_as_dev_resolved_it(case: str) -> None:
    """The servers and server references of every definition under every seeded team.

    The golden was written on dev 2c2522b2, where the built-ins named VirusTotal
    by key; a capability reference reaches what that did, and the threat-intel
    sidecar its seed binds to the judge.
    """
    import json
    from pathlib import Path

    from maljan.agents.composition import servers_bound_to

    golden = Path(__file__).resolve().parents[2] / "fixtures" / "golden" / "agents"
    dev = json.loads((golden / "servers_bound_to_stored_reputation_rows.json").read_text())
    resolved: dict[str, Any] = {}
    for profile in sorted(Settings.model_validate(_STORED_ROWS[case]).agents.profiles):
        settings = Settings.model_validate(_STORED_ROWS[case])
        settings.agents.profile = profile
        resolved[profile] = {
            key: [
                sorted(servers_bound_to(settings, key)),
                [r.model_dump() for r in mcp_refs_for(settings, key)],
            ]
            for key in sorted(settings.agents.definitions)
        }
    assert resolved == dev[case]


def test_the_capability_path_honours_the_server_s_tick_list(monkeypatch: Any) -> None:
    """A capability reference attaches the server's ticked tools, as a reference by key did."""
    from langchain_core.tools import StructuredTool

    from maljan.providers.servers import ServerRegistry

    settings = Settings.model_validate(
        {"mcp": {"servers": {"virustotal": {"enabled": True, "tools": ["get_file_report"]}}}}
    )
    registry = ServerRegistry(settings)
    handle = registry.get("virustotal")
    handle._all_tools = [
        StructuredTool.from_function(func=lambda: "x", name=n, description=n)
        for n in ("get_file_report", "get_ip_report", "submit_file")
    ]
    monkeypatch.setattr(handle, "open", lambda *_a, **_k: None)
    monkeypatch.setattr(registry, "_handle_for", lambda held, _loop: held)
    (ref,) = [r for r in mcp_refs_for(settings, "static") if r.server == "virustotal"]
    assert ref == ToolRef(kind="mcp", server="virustotal")
    tools, _reasons = registry.tools_for_ref(ref, "job")
    assert [t.name for t in tools] == ["get_file_report"]


def test_a_stored_lookup_with_no_rank_keeps_the_shipped_order() -> None:
    """An edited VirusTotal row written before ranks keeps VirusTotal ahead of the sidecar."""
    from maljan.core.declared_reading import declarations
    from maljan.core.reputation import pack_lookups

    settings = Settings.model_validate(
        {
            "mcp": {
                "servers": {
                    "virustotal": {
                        "enabled": True,
                        "tool_facts": {
                            "get_file_report": {
                                "kind": "file_reputation",
                                "arguments": {"hash": "hash"},
                                "display_name": "VT (edited)",
                            }
                        },
                    }
                }
            }
        }
    )
    lookups = pack_lookups(settings.mcp.servers, declarations(settings))
    assert [(lk.server, lk.tool, lk.rank) for lk in lookups] == [
        ("virustotal", "get_file_report", 10),
        ("threatintel", "check_hash", 20),
    ]


def test_an_operator_lookup_with_no_rank_takes_the_default() -> None:
    from maljan.core.declared_reading import declarations
    from maljan.core.reputation import DEFAULT_RANK, pack_lookups

    settings = Settings.model_validate(
        {
            "mcp": {
                "servers": {
                    "mine": {
                        "command": "x",
                        "tool_facts": {"ask": {"kind": "reputation", "arguments": {"hash": "h"}}},
                    }
                }
            }
        }
    )
    held = declarations(settings)
    ranks = {lk.server: lk.rank for lk in pack_lookups(settings.mcp.servers, held)}
    assert ranks["mine"] == DEFAULT_RANK

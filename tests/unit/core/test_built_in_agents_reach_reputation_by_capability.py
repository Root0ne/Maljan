"""The built-in agents reach reputation by capability, and a stored settings row still loads.

``ToolRef(kind="capability", capability="reputation")`` stands for every
server that declares a reputation lookup, except a built-in whose seed binds it
by its own ``agents`` list. With the shipped servers that is VirusTotal's own server alone,
which the definitions named by key before, so the default profile resolves to
the same servers it always did. A built-in row stored with that earlier list
is its seed of an earlier release and loads as the seed.
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


def test_the_default_profile_resolves_to_the_servers_it_always_did() -> None:
    settings = Settings(_env_file=None)
    for key in LOOKING_UP:
        resolved = [ref.model_dump() for ref in mcp_refs_for(settings, key)]
        assert resolved == [r for r in _former(key) if r["kind"] == "mcp"], key


def test_the_capability_skips_a_built_in_its_seed_binds_by_its_own_agents_list() -> None:
    settings = Settings(_env_file=None)
    # The threat-intel sidecar declares a lookup and its seed binds it to the judge.
    assert settings.mcp.servers["threatintel"].agents == ["judge"]
    assert capability_servers(settings, "reputation") == ["virustotal"]
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
    assert [str(r.server) for r in mcp_refs_for(settings, "mine")] == ["virustotal"]


# The stored server rows the capability must resolve as dev 2c2522b2 resolved
# them, and dev's answer: every definition's servers (``servers_bound_to``) and
# server references (``mcp_refs_for``), written on that tree.
_STORED_ROWS: dict[str, dict[str, Any]] = {
    "vt_judge": {"mcp": {"servers": {"virustotal": {"enabled": True, "agents": ["judge"]}}}},
    "vt_dynamic": {"mcp": {"servers": {"virustotal": {"enabled": True, "agents": ["dynamic"]}}}},
    "ti_none": {
        "mcp": {"servers": {"threatintel": {"agents": []}, "virustotal": {"enabled": True}}}
    },
    "default": {},
}


@pytest.mark.parametrize("case", sorted(_STORED_ROWS))
def test_a_stored_server_row_with_an_agents_list_resolves_as_dev_resolved_it(case: str) -> None:
    import json
    from pathlib import Path

    from maljan.agents.composition import servers_bound_to

    golden = Path(__file__).resolve().parents[2] / "fixtures" / "golden" / "agents"
    dev = json.loads((golden / "servers_bound_to_stored_reputation_rows.json").read_text())
    settings = Settings.model_validate(_STORED_ROWS[case])
    resolved = {
        key: [
            sorted(servers_bound_to(settings, key)),
            [str(r.server) for r in mcp_refs_for(settings, key)],
        ]
        for key in sorted(settings.agents.definitions)
    }
    assert resolved == dev[case]


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

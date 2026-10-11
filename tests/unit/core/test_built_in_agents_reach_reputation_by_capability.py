"""The built-in agents reach reputation by capability, and a stored settings row still loads.

``ToolRef(kind="capability", capability="reputation")`` stands for every
server that declares a reputation lookup and leaves its binding to the
definitions. With the shipped servers that is VirusTotal's own server alone,
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


def test_the_capability_names_only_the_servers_that_leave_binding_to_the_definitions() -> None:
    settings = Settings(_env_file=None)
    # The threat-intel sidecar declares a lookup and binds itself to the judge.
    assert settings.mcp.servers["threatintel"].agents == ["judge"]
    assert capability_servers(settings, "reputation") == ["virustotal"]
    assert capability_servers(settings, "no_such_kind") == []


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

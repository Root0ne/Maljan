"""PATCH-time validation of the agent maps, keyed per definition and per profile.

The model validates too — that is what stops a bad value from ever reaching a
job — but a model error is one message about a whole map. The editor draws a
card per definition, so it needs an error per definition, which is what this
layer produces, exactly as ``server_map.py`` does for servers.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_API = Path(__file__).resolve().parents[2] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

from app.services.agent_map import (  # noqa: E402
    AGENT_DEFINITIONS_KEY,
    AGENT_PROFILE_KEY,
    AGENT_PROFILES_KEY,
    AgentMapError,
    effective_definitions,
    effective_profiles,
    validate_agent_map,
)

BUILTIN_STATIC = {
    "role": "static",
    "label": "Static analyst",
    "prompt": None,
    "tools": [],
    "static_provider": None,
    "enabled": True,
}


def _defs(**extra):
    return {AGENT_DEFINITIONS_KEY: {**extra}}


def test_a_valid_definition_round_trips_with_the_built_ins_reseeded():
    out = validate_agent_map(
        _defs(strings={"role": "generic", "prompt": "read strings"}), stored={}
    )
    definitions = out[AGENT_DEFINITIONS_KEY]
    assert set(definitions) == {"static", "dynamic", "network", "judge", "strings"}
    assert definitions["strings"]["role"] == "generic"


def test_a_bad_key_is_reported_under_that_key():
    with pytest.raises(AgentMapError) as exc:
        validate_agent_map(_defs(**{"Bad Name": {"role": "generic", "prompt": "p"}}), stored={})
    assert "Bad Name" in exc.value.errors
    assert "lowercase" in exc.value.errors["Bad Name"]


def test_a_generic_agent_without_a_prompt_is_reported_on_its_prompt_field():
    with pytest.raises(AgentMapError) as exc:
        validate_agent_map(_defs(strings={"role": "generic", "prompt": ""}), stored={})
    assert exc.value.errors["strings.prompt"] == "a generic agent needs a prompt"


def test_an_edited_built_in_says_to_clone_it():
    with pytest.raises(AgentMapError) as exc:
        validate_agent_map(_defs(static={**BUILTIN_STATIC, "prompt": "mine"}), stored={})
    assert exc.value.errors["static"] == "'static' is built in; clone it to change it"


def test_a_disabled_built_in_analyst_is_allowed():
    out = validate_agent_map(
        {
            AGENT_DEFINITIONS_KEY: {"dynamic": {"role": "dynamic", "enabled": False}},
            AGENT_PROFILES_KEY: {"lean": {"analysts": ["static", "network"]}},
            AGENT_PROFILE_KEY: "lean",
        },
        stored={},
    )
    assert out[AGENT_DEFINITIONS_KEY]["dynamic"]["enabled"] is False


def test_an_unknown_static_provider_is_reported_on_its_field():
    with pytest.raises(AgentMapError) as exc:
        validate_agent_map(
            _defs(static_r2={"role": "static", "static_provider": "idapro"}), stored={}
        )
    assert "idapro" in exc.value.errors["static_r2.static_provider"]


def test_a_tool_reference_to_an_unknown_server_is_reported_on_its_field():
    with pytest.raises(AgentMapError) as exc:
        validate_agent_map(
            _defs(
                strings={
                    "role": "generic",
                    "prompt": "p",
                    "tools": [{"kind": "mcp", "server": "ghost"}],
                }
            ),
            stored={},
        )
    assert "ghost" in exc.value.errors["strings.tools"]


def test_a_named_tool_outside_the_servers_allow_list_is_refused():
    stored = {
        "core.mcp.servers": {
            "mine": {"enabled": True, "transport": "stdio", "command": "x", "tools": ["grep"]}
        }
    }
    with pytest.raises(AgentMapError) as exc:
        validate_agent_map(
            _defs(
                strings={
                    "role": "generic",
                    "prompt": "p",
                    "tools": [{"kind": "mcp", "server": "mine", "name": "rm"}],
                }
            ),
            stored=stored,
        )
    assert "'rm' is not allowed on server 'mine'" in exc.value.errors["strings.tools"]


def test_a_profile_naming_a_missing_analyst_is_reported_under_the_profile():
    with pytest.raises(AgentMapError) as exc:
        validate_agent_map(
            {AGENT_PROFILES_KEY: {"two": {"analysts": ["static", "ghost"]}}}, stored={}
        )
    assert "ghost" in exc.value.errors["two"]


def test_the_default_profile_may_not_be_edited():
    with pytest.raises(AgentMapError) as exc:
        validate_agent_map({AGENT_PROFILES_KEY: {"default": {"analysts": ["network"]}}}, stored={})
    assert exc.value.errors["default"] == "'default' is built in; clone it to change it"


def test_the_active_profile_must_exist_in_the_map_being_saved():
    with pytest.raises(AgentMapError) as exc:
        validate_agent_map({AGENT_PROFILE_KEY: "ghost"}, stored={})
    assert "ghost" in exc.value.errors[AGENT_PROFILE_KEY]


def test_a_profile_and_the_definition_it_uses_may_be_saved_in_one_patch():
    out = validate_agent_map(
        {
            AGENT_DEFINITIONS_KEY: {"strings": {"role": "generic", "prompt": "p"}},
            AGENT_PROFILES_KEY: {"wide": {"analysts": ["static", "strings"]}},
            AGENT_PROFILE_KEY: "wide",
        },
        stored={},
    )
    assert out[AGENT_PROFILE_KEY] == "wide"


def test_a_definition_stored_earlier_still_counts_when_only_a_profile_is_patched():
    stored = {AGENT_DEFINITIONS_KEY: {"strings": {"role": "generic", "prompt": "p"}}}
    out = validate_agent_map(
        {AGENT_PROFILES_KEY: {"wide": {"analysts": ["strings"]}}}, stored=stored
    )
    assert out[AGENT_PROFILES_KEY]["wide"]["analysts"] == ["strings"]


def test_an_explicit_null_clears_a_map_back_to_the_built_ins():
    """Identical to sub-project B's null semantics for the server map."""
    stored = {AGENT_DEFINITIONS_KEY: {"strings": {"role": "generic", "prompt": "p"}}}
    out = validate_agent_map({AGENT_DEFINITIONS_KEY: None}, stored=stored)
    assert out[AGENT_DEFINITIONS_KEY] is None
    assert set(effective_definitions({})) == {"static", "dynamic", "network", "judge"}


def test_clearing_the_definitions_that_a_stored_profile_uses_is_refused():
    stored = {
        AGENT_DEFINITIONS_KEY: {"strings": {"role": "generic", "prompt": "p"}},
        AGENT_PROFILES_KEY: {"wide": {"analysts": ["strings"]}},
    }
    with pytest.raises(AgentMapError) as exc:
        validate_agent_map({AGENT_DEFINITIONS_KEY: None}, stored=stored)
    assert "strings" in exc.value.errors["wide"]


def test_the_effective_maps_layer_stored_over_seeded():
    assert set(effective_profiles({})) == {"default"}
    assert set(effective_profiles({AGENT_PROFILES_KEY: {"lean": {"analysts": ["network"]}}})) == {
        "default",
        "lean",
    }


def test_the_catalog_resolves_the_two_new_choice_sources():
    from app.services.settings_catalog_api import resolved_catalog

    entries = {
        e.key: e
        for e in resolved_catalog(
            ["network"], profiles=["default", "lean"], agents=["static", "strings"]
        )
    }
    assert entries["core.agents.profile"].choices == ["default", "lean"]
    assert entries["core.mcp.servers"].editor == "server_map"
    assert entries["core.agents.definitions"].editor == "agent_definitions"
    assert entries["core.agents.profiles"].editor == "profiles"


def test_a_server_binding_offers_the_effective_definition_keys():
    from app.services.settings_catalog_api import resolved_catalog

    entries = {
        e.key: e for e in resolved_catalog([], profiles=["default"], agents=["static", "strings"])
    }
    catalog_entry = entries["core.static.generic.server"]
    assert catalog_entry.choices_from == "mcp_servers"
    # ``agent_roles`` is consumed by the definitions editor rather than by a
    # leaf, so the source is asserted through the resolver's own table.
    from app.services.settings_catalog_api import _choice_sources

    assert _choice_sources([], ["default"], ["static", "strings"])["agent_roles"] == [
        "static",
        "strings",
    ]

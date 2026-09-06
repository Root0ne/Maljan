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
from pydantic import ValidationError

from maljan.core.config import Settings

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
    assert f"{AGENT_DEFINITIONS_KEY}.Bad Name" in exc.value.errors
    assert "lowercase" in exc.value.errors[f"{AGENT_DEFINITIONS_KEY}.Bad Name"]


def test_a_generic_agent_without_a_prompt_is_reported_on_its_prompt_field():
    with pytest.raises(AgentMapError) as exc:
        validate_agent_map(_defs(strings={"role": "generic", "prompt": ""}), stored={})
    assert (
        exc.value.errors[f"{AGENT_DEFINITIONS_KEY}.strings.prompt"]
        == "a generic agent needs a prompt"
    )


def test_an_edited_built_in_says_to_clone_it():
    with pytest.raises(AgentMapError) as exc:
        validate_agent_map(_defs(static={**BUILTIN_STATIC, "prompt": "mine"}), stored={})
    assert (
        exc.value.errors[f"{AGENT_DEFINITIONS_KEY}.static"]
        == "'static' is built in; clone it to change it"
    )


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
    assert "idapro" in exc.value.errors[f"{AGENT_DEFINITIONS_KEY}.static_r2.static_provider"]


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
    assert "ghost" in exc.value.errors[f"{AGENT_DEFINITIONS_KEY}.strings.tools"]


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
    assert (
        "'rm' is not allowed on server 'mine'"
        in exc.value.errors[f"{AGENT_DEFINITIONS_KEY}.strings.tools"]
    )


def test_a_provider_tool_reference_on_a_built_in_role_is_refused():
    """Identical to the ``Settings``-level rule: only a generic agent may

    carry a ``provider`` tool reference; a built-in role opens its own
    provider's tools itself.
    """
    with pytest.raises(AgentMapError) as exc:
        validate_agent_map(
            _defs(strings={"role": "static", "tools": [{"kind": "provider"}]}), stored={}
        )
    assert exc.value.errors[f"{AGENT_DEFINITIONS_KEY}.strings"] == (
        "'strings': provider tool references are only valid on generic "
        "definitions; built-in roles open their provider themselves"
    )


def test_a_disabled_built_in_profile_member_is_allowed_while_another_profile_is_active():
    """The exemption ``AgentsConfig`` gives a built-in profile: disabling a

    member of ``default`` is harmless as long as ``default`` itself is not
    the profile that would run.
    """
    out = validate_agent_map(
        {
            AGENT_DEFINITIONS_KEY: {"network": {"role": "network", "enabled": False}},
            AGENT_PROFILES_KEY: {
                "default": {"label": "Default", "analysts": ["static", "dynamic", "network"]},
                "lean": {"analysts": ["static", "dynamic"]},
            },
            AGENT_PROFILE_KEY: "lean",
        },
        stored={},
    )
    assert out[AGENT_PROFILE_KEY] == "lean"


def test_a_disabled_built_in_profile_member_is_refused_once_that_profile_is_active():
    with pytest.raises(AgentMapError) as exc:
        validate_agent_map(
            {
                AGENT_DEFINITIONS_KEY: {"network": {"role": "network", "enabled": False}},
                AGENT_PROFILES_KEY: {
                    "default": {
                        "label": "Default",
                        "analysts": ["static", "dynamic", "network"],
                    },
                    "lean": {"analysts": ["static", "dynamic"]},
                },
                AGENT_PROFILE_KEY: "default",
            },
            stored={},
        )
    assert "network" in exc.value.errors[f"{AGENT_PROFILES_KEY}.default"]


def test_a_profile_naming_a_missing_analyst_is_reported_under_the_profile():
    with pytest.raises(AgentMapError) as exc:
        validate_agent_map(
            {AGENT_PROFILES_KEY: {"two": {"analysts": ["static", "ghost"]}}}, stored={}
        )
    assert "ghost" in exc.value.errors[f"{AGENT_PROFILES_KEY}.two"]


def test_the_default_profile_may_not_be_edited():
    with pytest.raises(AgentMapError) as exc:
        validate_agent_map({AGENT_PROFILES_KEY: {"default": {"analysts": ["network"]}}}, stored={})
    assert (
        exc.value.errors[f"{AGENT_PROFILES_KEY}.default"]
        == "'default' is built in; clone it to change it"
    )


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
    assert "strings" in exc.value.errors[f"{AGENT_PROFILES_KEY}.wide"]


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


def _settings_from_changes(changes: dict, stored: dict) -> Settings:
    """The ``Settings``-level equivalent of one ``validate_agent_map`` call.

    Built from the same two inputs the API layer sees, so a payload can be
    run through both without hand-translating it twice.
    """
    agents_kwargs: dict = {}
    definitions = changes.get(AGENT_DEFINITIONS_KEY, stored.get(AGENT_DEFINITIONS_KEY))
    if definitions is not None:
        agents_kwargs["definitions"] = definitions
    profiles = changes.get(AGENT_PROFILES_KEY, stored.get(AGENT_PROFILES_KEY))
    if profiles is not None:
        agents_kwargs["profiles"] = profiles
    profile = changes.get(AGENT_PROFILE_KEY, stored.get(AGENT_PROFILE_KEY))
    if profile is not None:
        agents_kwargs["profile"] = profile

    settings_kwargs: dict = {"_env_file": None, "agents": agents_kwargs}
    servers = stored.get("core.mcp.servers")
    if isinstance(servers, dict):
        settings_kwargs["mcp"] = {"servers": servers}
    return Settings(**settings_kwargs)


def _api_accepts(changes: dict, stored: dict) -> bool:
    try:
        validate_agent_map(changes, stored)
        return True
    except AgentMapError:
        return False


def _settings_accepts(changes: dict, stored: dict) -> bool:
    try:
        _settings_from_changes(changes, stored)
        return True
    except ValidationError:
        return False


_SYMMETRY_CASES = [
    ("valid new generic definition", _defs(strings={"role": "generic", "prompt": "p"}), {}),
    ("non-slug key", _defs(**{"Bad Name": {"role": "generic", "prompt": "p"}}), {}),
    ("generic without a prompt", _defs(strings={"role": "generic", "prompt": ""}), {}),
    ("an edited built-in", _defs(static={**BUILTIN_STATIC, "prompt": "mine"}), {}),
    (
        "a disabled built-in analyst behind a custom active profile",
        {
            AGENT_DEFINITIONS_KEY: {"dynamic": {"role": "dynamic", "enabled": False}},
            AGENT_PROFILES_KEY: {"lean": {"analysts": ["static", "network"]}},
            AGENT_PROFILE_KEY: "lean",
        },
        {},
    ),
    (
        "an unknown static provider",
        _defs(static_r2={"role": "static", "static_provider": "idapro"}),
        {},
    ),
    (
        "a tool reference to an unknown server",
        _defs(
            strings={
                "role": "generic",
                "prompt": "p",
                "tools": [{"kind": "mcp", "server": "ghost"}],
            }
        ),
        {},
    ),
    (
        "a named tool outside the server's allow list",
        _defs(
            strings={
                "role": "generic",
                "prompt": "p",
                "tools": [{"kind": "mcp", "server": "mine", "name": "rm"}],
            }
        ),
        {
            "core.mcp.servers": {
                "mine": {
                    "enabled": True,
                    "transport": "stdio",
                    "command": "x",
                    "tools": ["grep"],
                }
            }
        },
    ),
    (
        "a second definition with the judge role",
        _defs(judge_2={"role": "judge", "prompt": "p"}),
        {},
    ),
    (
        "a provider tool reference on a built-in role",
        _defs(strings={"role": "static", "tools": [{"kind": "provider"}]}),
        {},
    ),
    (
        "a profile naming a missing analyst",
        {AGENT_PROFILES_KEY: {"two": {"analysts": ["static", "ghost"]}}},
        {},
    ),
    (
        "an edited default profile",
        {AGENT_PROFILES_KEY: {"default": {"analysts": ["network"]}}},
        {},
    ),
    ("an unknown active profile", {AGENT_PROFILE_KEY: "ghost"}, {}),
    (
        "a disabled built-in member, inactive default profile",
        {
            AGENT_DEFINITIONS_KEY: {"network": {"role": "network", "enabled": False}},
            AGENT_PROFILES_KEY: {
                "default": {"label": "Default", "analysts": ["static", "dynamic", "network"]},
                "lean": {"analysts": ["static", "dynamic"]},
            },
            AGENT_PROFILE_KEY: "lean",
        },
        {},
    ),
    (
        "a disabled built-in member, active default profile",
        {
            AGENT_DEFINITIONS_KEY: {"network": {"role": "network", "enabled": False}},
            AGENT_PROFILES_KEY: {
                "default": {"label": "Default", "analysts": ["static", "dynamic", "network"]},
                "lean": {"analysts": ["static", "dynamic"]},
            },
            AGENT_PROFILE_KEY: "default",
        },
        {},
    ),
]


@pytest.mark.parametrize(
    "label,changes,stored", _SYMMETRY_CASES, ids=[c[0] for c in _SYMMETRY_CASES]
)
def test_the_api_layer_and_settings_agree_on_accept_or_reject(label, changes, stored):
    """A payload the API accepts must be one ``Settings`` would also accept, and

    vice versa -- otherwise the two layers have quietly drifted and an
    operator sees a PATCH succeed only to have a job fail to build ``Settings``
    from it later, or a PATCH refused for a reason ``Settings`` does not share.
    """
    assert _api_accepts(changes, stored) == _settings_accepts(changes, stored), label


def test_a_cloned_judge_is_refused_with_the_rule_that_names_it():
    with pytest.raises(AgentMapError) as exc:
        validate_agent_map(_defs(judge_2={"role": "judge", "prompt": "p"}), stored={})
    assert (
        exc.value.errors[f"{AGENT_DEFINITIONS_KEY}.judge_2"]
        == "'judge_2': only the built-in judge may have role judge"
    )

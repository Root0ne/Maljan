"""What an operator may write into ``agents.definitions`` and ``agents.profiles``.

Every rule in spec §3.2 gets an accepting case and a rejecting one. The
accepting cases matter as much as the rejections: a validator that refuses
everything would also keep the default profile byte-identical.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from maljan.core.config import (
    AGENT_KEY_PATTERN,
    BUILTIN_AGENTS,
    BUILTIN_PROFILES,
    SERVER_KEY_PATTERN,
    Settings,
    ToolRef,
)

DEFAULT_AGENTS = {
    "profile": "default",
    "profiles": {
        "default": {"label": "Default", "analysts": ["static", "dynamic", "network"]},
    },
    "definitions": {
        "static": {
            "role": "static",
            "label": "Static analyst",
            "prompt": None,
            "tools": [],
            "static_provider": None,
            "enabled": True,
        },
        "dynamic": {
            "role": "dynamic",
            "label": "Dynamic analyst",
            "prompt": None,
            "tools": [],
            "static_provider": None,
            "enabled": True,
        },
        "network": {
            "role": "network",
            "label": "Network analyst",
            "prompt": None,
            "tools": [],
            "static_provider": None,
            "enabled": True,
        },
        "judge": {
            "role": "judge",
            "label": "Judge",
            "prompt": None,
            "tools": [],
            "static_provider": None,
            "enabled": True,
        },
    },
}


def _settings(**agents) -> Settings:
    return Settings(_env_file=None, agents=agents)


# ── seeding and the pinned default ─────────────────────────────────────


def test_the_key_pattern_is_the_one_the_server_map_already_uses():
    assert AGENT_KEY_PATTERN == SERVER_KEY_PATTERN


def test_the_default_settings_dump_is_exactly_the_pinned_dict():
    assert Settings(_env_file=None).agents.model_dump() == DEFAULT_AGENTS


def test_a_stored_map_holding_only_a_custom_agent_gets_the_built_ins_back():
    cfg = _settings(definitions={"strings": {"role": "generic", "prompt": "look at strings"}})
    assert set(cfg.agents.definitions) == {*BUILTIN_AGENTS, "strings"}
    assert set(cfg.agents.profiles) == set(BUILTIN_PROFILES)
    assert cfg.agents.definitions["static"].role == "static"


def test_disabling_a_built_in_analyst_is_kept_not_reseeded_away():
    cfg = _settings(
        definitions={"dynamic": {"role": "dynamic", "enabled": False}},
        profiles={"lean": {"analysts": ["static", "network"]}},
        profile="lean",
    )
    assert cfg.agents.definitions["dynamic"].enabled is False


# ── keys ───────────────────────────────────────────────────────────────


def test_a_slug_key_is_accepted():
    cfg = _settings(definitions={"static_r2": {"role": "static"}})
    assert "static_r2" in cfg.agents.definitions


@pytest.mark.parametrize("key", ["Static", "9lives", "a" * 33, "has space"])
def test_a_non_slug_key_is_refused(key):
    with pytest.raises(ValidationError, match="lowercase"):
        _settings(definitions={key: {"role": "generic", "prompt": "p"}})


# ── the active profile ─────────────────────────────────────────────────


def test_naming_an_existing_profile_is_accepted():
    cfg = _settings(profiles={"lean": {"analysts": ["network"]}}, profile="lean")
    assert cfg.agents.profile == "lean"


def test_naming_a_profile_that_does_not_exist_is_refused():
    with pytest.raises(ValidationError, match="unknown profile 'ghost'"):
        _settings(profile="ghost")


# ── built-ins are read-only except ``enabled`` ─────────────────────────


def test_a_built_in_may_be_disabled():
    cfg = _settings(
        definitions={"network": {"role": "network", "enabled": False}},
        profiles={"lean": {"analysts": ["static"]}},
        profile="lean",
    )
    assert cfg.agents.definitions["network"].enabled is False


def test_a_built_in_with_an_edited_prompt_is_refused():
    with pytest.raises(ValidationError, match="'static' is built in; clone it to change it"):
        _settings(definitions={"static": {"role": "static", "prompt": "mine"}})


def test_the_default_profile_may_not_be_edited():
    with pytest.raises(ValidationError, match="'default' is built in; clone it to change it"):
        _settings(profiles={"default": {"analysts": ["network"]}})


def test_a_clone_of_a_built_in_may_carry_its_own_prompt():
    cfg = _settings(
        definitions={"static_r2": {"role": "static", "prompt": "mine", "static_provider": "r2"}},
        profiles={"two": {"analysts": ["static", "static_r2"]}},
        profile="two",
    )
    assert cfg.agents.definitions["static_r2"].prompt == "mine"


# ── the analyst list ───────────────────────────────────────────────────


def test_a_profile_of_enabled_non_judge_analysts_is_accepted():
    cfg = _settings(profiles={"two": {"analysts": ["static", "network"]}}, profile="two")
    assert cfg.agents.profiles["two"].analysts == ["static", "network"]


def test_a_profile_naming_an_unknown_definition_is_refused():
    with pytest.raises(ValidationError, match="'two' lists unknown analyst 'ghost'"):
        _settings(profiles={"two": {"analysts": ["static", "ghost"]}})


def test_a_profile_naming_a_disabled_definition_is_refused():
    with pytest.raises(ValidationError, match="'two' lists disabled analyst 'dynamic'"):
        _settings(
            definitions={"dynamic": {"role": "dynamic", "enabled": False}},
            profiles={"two": {"analysts": ["static", "dynamic"]}},
        )


def test_a_profile_naming_the_judge_is_refused():
    with pytest.raises(ValidationError, match="the judge cannot be an analyst"):
        _settings(profiles={"two": {"analysts": ["static", "judge"]}})


def test_a_profile_repeating_an_analyst_is_refused():
    with pytest.raises(ValidationError, match="lists 'static' twice"):
        _settings(profiles={"two": {"analysts": ["static", "static"]}})


def test_an_empty_profile_is_refused():
    with pytest.raises(ValidationError, match="needs at least one analyst"):
        _settings(profiles={"empty": {"analysts": []}})


# ── prompts ────────────────────────────────────────────────────────────


def test_a_generic_agent_with_a_prompt_is_accepted():
    cfg = _settings(definitions={"strings": {"role": "generic", "prompt": "read strings"}})
    assert cfg.agents.definitions["strings"].prompt == "read strings"


@pytest.mark.parametrize("prompt", [None, "", "   "])
def test_a_generic_agent_without_a_prompt_is_refused(prompt):
    with pytest.raises(ValidationError, match="a generic agent needs a prompt"):
        _settings(definitions={"strings": {"role": "generic", "prompt": prompt}})


# ── tool references ────────────────────────────────────────────────────


def test_a_reference_to_a_whole_server_is_accepted():
    cfg = _settings(
        definitions={
            "strings": {
                "role": "generic",
                "prompt": "p",
                "tools": [{"kind": "mcp", "server": "network"}],
            }
        }
    )
    assert cfg.agents.definitions["strings"].tools[0].server == "network"


def test_a_reference_to_an_unknown_server_is_refused():
    with pytest.raises(ValidationError, match="'strings' references unknown mcp server 'ghost'"):
        _settings(
            definitions={
                "strings": {
                    "role": "generic",
                    "prompt": "p",
                    "tools": [{"kind": "mcp", "server": "ghost"}],
                }
            }
        )


def test_a_named_tool_outside_the_servers_allow_list_is_refused():
    with pytest.raises(ValidationError, match="'read_pcap' is not allowed on server 'narrow'"):
        Settings(
            _env_file=None,
            mcp={
                "servers": {"narrow": {"enabled": True, "command": "x", "tools": ["extract_dns"]}}
            },
            agents={
                "definitions": {
                    "strings": {
                        "role": "generic",
                        "prompt": "p",
                        "tools": [{"kind": "mcp", "server": "narrow", "name": "read_pcap"}],
                    }
                }
            },
        )


def test_a_named_tool_on_a_server_that_exposes_everything_is_left_to_resolution():
    """``tools: null`` means "the whole manifest", which is not known at save time."""
    cfg = _settings(
        definitions={
            "strings": {
                "role": "generic",
                "prompt": "p",
                "tools": [{"kind": "mcp", "server": "network", "name": "whatever_it_offers"}],
            }
        }
    )
    assert cfg.agents.definitions["strings"].tools[0].name == "whatever_it_offers"


def test_an_mcp_reference_without_a_server_is_refused():
    with pytest.raises(ValidationError, match="an mcp tool reference needs a server"):
        ToolRef(kind="mcp")


def test_a_provider_reference_carrying_a_server_is_refused():
    with pytest.raises(ValidationError, match="a provider tool reference names no server"):
        ToolRef(kind="provider", server="network")


def test_a_bare_provider_reference_is_accepted():
    assert ToolRef(kind="provider").server is None


# ── static providers ───────────────────────────────────────────────────


def test_a_registered_static_provider_is_accepted():
    cfg = _settings(definitions={"static_r2": {"role": "static", "static_provider": "r2"}})
    assert cfg.agents.definitions["static_r2"].static_provider == "r2"


def test_an_unregistered_static_provider_is_refused():
    with pytest.raises(ValidationError, match="unknown static provider 'idapro'"):
        _settings(definitions={"static_r2": {"role": "static", "static_provider": "idapro"}})


# ── the server binding vocabulary ──────────────────────────────────────


def test_a_server_may_be_bound_to_a_custom_definition_key():
    cfg = Settings(
        _env_file=None,
        mcp={"servers": {"mine": {"enabled": True, "command": "x", "agents": ["strings"]}}},
        agents={"definitions": {"strings": {"role": "generic", "prompt": "p"}}},
    )
    assert cfg.mcp.servers["mine"].agents == ["strings"]


def test_a_server_bound_to_a_definition_that_does_not_exist_is_refused():
    with pytest.raises(ValidationError, match="server 'mine' is bound to unknown agent 'ghost'"):
        Settings(
            _env_file=None,
            mcp={"servers": {"mine": {"enabled": True, "command": "x", "agents": ["ghost"]}}},
        )


def test_the_deprecated_agent_role_alias_is_still_a_type():
    """Sub-project B imports ``AgentRole``; it must keep importing."""
    from maljan.core.config import AgentRole

    assert AgentRole is str


# ── annotations ────────────────────────────────────────────────────────


def test_every_new_leaf_is_annotated_and_grouped():
    from maljan.core.settings_annotations import ANNOTATIONS, GROUP_ORDER

    for key in ("agents.profile", "agents.profiles", "agents.definitions"):
        assert key in ANNOTATIONS, key
    assert ANNOTATIONS["agents.profile"]["choices_from"] == "profiles"
    assert ANNOTATIONS["agents.profile"]["order"] == -1
    assert ANNOTATIONS["agents.profiles"]["editor"] == "profiles"
    assert ANNOTATIONS["agents.definitions"]["editor"] == "agent_definitions"
    assert dict(GROUP_ORDER)["agents"] == "Agents"

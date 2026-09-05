"""The container answers "which analysts" and "which class" from the profile.

The first test is the byte-identity one: with the default profile the
container hands back the same three classes under the same three names it
always did. The rest are the new capability — a clone runs its built-in class
under its own key, a generic definition runs ``ConfigurableAnalyst``, and two
static providers in one profile really are two provider objects.
"""

from __future__ import annotations

import pytest

from maljan.agents.configurable_analyst import ConfigurableAnalyst
from maljan.agents.dynamic_analyst import DynamicAnalyst
from maljan.agents.network_analyst import NetworkAnalyst
from maljan.agents.static_analyst import StaticAnalyst
from maljan.core.config import Settings
from maljan.core.container import ServiceContainer


def _container(**agents) -> ServiceContainer:
    cfg = Settings(_env_file=None, agents=agents) if agents else Settings(_env_file=None)
    return ServiceContainer(cfg, mock=True)


def test_the_default_profile_gives_todays_three_agents_unchanged():
    container = _container()
    assert container.analyst_keys() == ["static", "dynamic", "network"]
    assert [type(container.get_agent(k)) for k in container.analyst_keys()] == [
        StaticAnalyst,
        DynamicAnalyst,
        NetworkAnalyst,
    ]
    assert [container.get_agent(k).name for k in container.analyst_keys()] == [
        "static",
        "dynamic",
        "network",
    ]


def test_the_active_profile_is_the_object_not_its_name():
    container = _container()
    assert container.active_profile().analysts == ["static", "dynamic", "network"]


def test_a_clone_runs_its_built_in_class_under_its_own_key():
    container = _container(
        definitions={"static_r2": {"role": "static", "static_provider": "r2"}},
        profiles={"two": {"analysts": ["static", "static_r2"]}},
        profile="two",
    )
    agent = container.get_agent("static_r2")
    assert isinstance(agent, StaticAnalyst)
    assert agent.name == "static_r2"
    assert agent._resolved.static_provider_id == "r2"
    assert container.agent_role("static_r2") == "static"


def test_a_generic_definition_runs_the_configurable_analyst():
    container = _container(
        definitions={"strings": {"role": "generic", "prompt": "read strings"}},
        profiles={"one": {"analysts": ["strings"]}},
        profile="one",
    )
    agent = container.get_agent("strings")
    assert isinstance(agent, ConfigurableAnalyst)
    assert agent.name == "strings"
    assert agent._resolved.prompt == "read strings"
    assert container.agent_role("strings") == "generic"


def test_two_provider_ids_give_two_provider_instances_and_each_is_cached():
    container = _container()
    ghidra_a = container.get_static_provider("ghidra")
    ghidra_b = container.get_static_provider("ghidra")
    r2 = container.get_static_provider("r2")
    assert ghidra_a is ghidra_b
    assert ghidra_a is not r2
    assert r2.id == "r2"


def test_the_no_argument_call_still_returns_the_globally_configured_provider():
    container = _container()
    assert container.get_static_provider() is container.get_static_provider("ghidra")
    assert container.get_static_provider().id == "ghidra"


def test_every_agent_gets_the_ledgers_and_a_way_back_to_the_container():
    container = _container(
        definitions={"strings": {"role": "generic", "prompt": "p"}},
        profiles={"one": {"analysts": ["strings"]}},
        profile="one",
    )
    for key in ("static", "strings"):
        agent = container.get_agent(key)
        assert agent._container is container
        assert agent.token_ledger is container.get_token_ledger()
        assert agent.truncation_ledger is container.get_truncation_ledger()


def test_an_agent_is_built_once_and_cached():
    container = _container()
    assert container.get_agent("static") is container.get_agent("static")


def test_an_unknown_key_says_what_is_available():
    container = _container()
    with pytest.raises(KeyError, match="No agent definition named 'ghost'"):
        container.get_agent("ghost")


def test_a_reduced_profile_is_the_only_thing_the_container_reports():
    container = _container(profiles={"lean": {"analysts": ["network"]}}, profile="lean")
    assert container.analyst_keys() == ["network"]

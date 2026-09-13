# tests/unit/servers/test_agent_parity.py
"""The four ways "which agents exist" is answered must give one answer.

Spec §8 item 4. The class registry, the seeded definitions, the catalog's
``agent_roles`` choices and the job schema's profile validation each hold a
piece of the same fact; a drift between any two of them is a wrong dropdown or
a job that fails minutes after it was accepted.
"""

from __future__ import annotations

from maljan.agents.registry import AgentRegistry
from maljan.core.config import (
    BUILTIN_AGENTS,
    BUILTIN_PROFILES,
    JUDGE_AGENT_KEY,
    REPORTER_AGENT_KEY,
    Settings,
)


def test_the_built_in_definitions_are_the_registered_classes_plus_the_two_that_are_not_analysts():
    registered = set(AgentRegistry().list_agents(include_disabled=True))
    assert set(BUILTIN_AGENTS) == registered | {JUDGE_AGENT_KEY, REPORTER_AGENT_KEY}


def test_every_built_in_definition_names_its_own_role():
    definitions = Settings(_env_file=None).agents.definitions
    for key in BUILTIN_AGENTS:
        # The reporter is the one key that is not its role: ``report`` is what
        # the stage kind is called and ``reporter`` is who runs it, and naming
        # both the same would make the definition map read as a stage list.
        expected = "report" if key == REPORTER_AGENT_KEY else key
        assert definitions[key].role == expected


def test_the_default_profile_is_every_built_in_analyst_and_neither_of_the_others():
    profile = Settings(_env_file=None).agents.profiles["default"]
    analysis_agents = set(profile.analysis_agents)
    assert analysis_agents == set(BUILTIN_AGENTS) - {JUDGE_AGENT_KEY, REPORTER_AGENT_KEY}
    assert profile.analysis_agents == ["static", "dynamic", "network"]
    # The team is the paper's pipeline written as the four stages it always
    # was: the analysts, the debate over them, the verdict and the report.
    assert [(s.key, s.kind) for s in profile.stages] == [
        ("analysis", "analysis"),
        ("debate", "debate"),
        ("verdict", "verdict"),
        ("report", "report"),
    ]
    assert profile.stage("verdict").agents == [JUDGE_AGENT_KEY]
    assert profile.stage("report").agents == [REPORTER_AGENT_KEY]
    # ``measurement`` is the second built-in: the same three analysts with
    # every tool server withheld, which is the baseline the tool sidecars are
    # measured against.
    assert BUILTIN_PROFILES == ("default", "measurement", "mobile", "deep_static")
    baseline = Settings(_env_file=None).agents.profiles["measurement"]
    assert baseline.analysis_agents == profile.analysis_agents
    assert baseline.static_provider == "none"
    assert baseline.exclude_sandbox_tools is True


def test_agent_roles_resolves_to_the_effective_definition_keys():
    from app.services.settings_catalog_api import _choice_sources

    sources = _choice_sources([], ["default"], ["static", "dynamic", "network", "judge", "x"])
    assert sources["agent_roles"] == ["static", "dynamic", "network", "judge", "x"]
    assert sources["profiles"] == ["default"]


def test_the_job_schemas_profile_accepts_exactly_the_effective_profile_keys():
    from app.services.agent_map import AGENT_PROFILES_KEY, effective_profiles

    assert set(effective_profiles({})) == set(BUILTIN_PROFILES)
    stored = {AGENT_PROFILES_KEY: {"lean": {"analysts": ["network"]}}}
    assert set(effective_profiles(stored)) == {*BUILTIN_PROFILES, "lean"}


def test_a_definition_key_and_a_server_key_obey_the_same_rule():
    from maljan.core.config import AGENT_KEY_PATTERN, SERVER_KEY_PATTERN

    assert AGENT_KEY_PATTERN == SERVER_KEY_PATTERN

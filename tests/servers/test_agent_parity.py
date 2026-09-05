# tests/servers/test_agent_parity.py
"""The four ways "which agents exist" is answered must give one answer.

Spec §8 item 4. The class registry, the seeded definitions, the catalog's
``agent_roles`` choices and the job schema's profile validation each hold a
piece of the same fact; a drift between any two of them is a wrong dropdown or
a job that fails minutes after it was accepted.
"""

from __future__ import annotations

import sys
from pathlib import Path

_API = Path(__file__).resolve().parents[2] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

from maljan.agents.registry import AgentRegistry  # noqa: E402
from maljan.core.config import BUILTIN_AGENTS, BUILTIN_PROFILES, Settings  # noqa: E402


def test_the_built_in_definitions_are_the_registered_classes_plus_the_judge():
    registered = set(AgentRegistry().list_agents(include_disabled=True))
    assert set(BUILTIN_AGENTS) == registered | {"judge"}


def test_every_built_in_definition_names_its_own_role():
    definitions = Settings(_env_file=None).agents.definitions
    for key in BUILTIN_AGENTS:
        assert definitions[key].role == key


def test_the_default_profile_is_every_built_in_analyst_and_not_the_judge():
    profile = Settings(_env_file=None).agents.profiles["default"]
    assert set(profile.analysts) == set(BUILTIN_AGENTS) - {"judge"}
    assert profile.analysts == ["static", "dynamic", "network"]
    assert BUILTIN_PROFILES == ("default",)


def test_agent_roles_resolves_to_the_effective_definition_keys():
    from app.services.settings_catalog_api import _choice_sources

    sources = _choice_sources([], ["default"], ["static", "dynamic", "network", "judge", "x"])
    assert sources["agent_roles"] == ["static", "dynamic", "network", "judge", "x"]
    assert sources["profiles"] == ["default"]


def test_the_job_schemas_profile_accepts_exactly_the_effective_profile_keys():
    from app.services.agent_map import AGENT_PROFILES_KEY, effective_profiles

    assert set(effective_profiles({})) == set(BUILTIN_PROFILES)
    stored = {AGENT_PROFILES_KEY: {"lean": {"analysts": ["network"]}}}
    assert set(effective_profiles(stored)) == {"default", "lean"}


def test_a_definition_key_and_a_server_key_obey_the_same_rule():
    from maljan.core.config import AGENT_KEY_PATTERN, SERVER_KEY_PATTERN

    assert AGENT_KEY_PATTERN == SERVER_KEY_PATTERN

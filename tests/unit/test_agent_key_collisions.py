"""A stored agent whose name the product later seeded must still load.

Seeding `triage`, `android_static`, `reverser`, `mobile` and `deep_static` took
five names that were legal for an operator's own agent or team the day before.
The identity check refuses a stored built-in that does not match its seed, and
it refuses it on every construction of ``Settings`` — at boot, in the worker,
in a script. Without the rename, an operator who had used one of those names
upgrades into a service that will not start and cannot be repaired from a
console that needs the configuration to load.

So what is pinned here is that the configuration loads, that the operator's
agent survives with its own fields, and that every reference to it moved with
it. A reference left behind is worse than the crash: a per-agent model choice
or a timeout that silently stops applying.
"""

from __future__ import annotations

import pytest

from maljan.core.agent_key_migration import free_key, rename_colliding_agent_keys
from maljan.core.config import BUILTIN_PROFILES, Settings, seeded_generic_agents


def _settings(**over):
    return Settings(_env_file=None, **over)


class TestAStoredAgentUnderASeededName:
    def test_the_configuration_still_loads(self) -> None:
        cfg = _settings(agents={"definitions": {"reverser": {"role": "generic", "prompt": "mine"}}})
        assert "reverser_custom" in cfg.agents.definitions
        assert cfg.agents.definitions["reverser_custom"].prompt == "mine"

    def test_the_seed_is_there_beside_it(self) -> None:
        cfg = _settings(agents={"definitions": {"reverser": {"role": "generic", "prompt": "mine"}}})
        assert cfg.agents.definitions["reverser"].label == "Reverser"
        assert cfg.agents.definitions["reverser"].prompt != "mine"

    def test_the_operator_s_agent_keeps_its_own_fields(self) -> None:
        """Renamed before the seed's defaults are merged in, not after.

        Merged first, the operator's agent would come out of this carrying the
        seed's tools and label — an agent they never configured, running tools
        they never gave it.
        """
        cfg = _settings(agents={"definitions": {"triage": {"role": "generic", "prompt": "mine"}}})
        assert cfg.agents.definitions["triage_custom"].tools == []
        assert cfg.agents.definitions["triage_custom"].label == ""

    @pytest.mark.parametrize("key", seeded_generic_agents())
    def test_every_seeded_generic_name_is_handled(self, key: str) -> None:
        cfg = _settings(agents={"definitions": {key: {"role": "generic", "prompt": "mine"}}})
        assert f"{key}_custom" in cfg.agents.definitions

    def test_a_second_collision_gets_a_counter(self) -> None:
        cfg = _settings(
            agents={
                "definitions": {
                    "reverser": {"role": "generic", "prompt": "mine"},
                    "reverser_custom": {"role": "generic", "prompt": "also mine"},
                }
            }
        )
        assert cfg.agents.definitions["reverser_custom"].prompt == "also mine"
        assert cfg.agents.definitions["reverser_custom_2"].prompt == "mine"

    def test_a_stored_entry_that_is_the_seed_is_left_alone(self) -> None:
        """A document that already carries the seed is not a collision.

        The console writes the whole map back, and an export/import round trip
        carries the seeded entries with it. Renaming those would produce a
        duplicate of every built-in on every save.
        """
        seed = Settings(_env_file=None).agents.definitions["reverser"].model_dump()
        cfg = _settings(agents={"definitions": {"reverser": seed}})
        assert "reverser_custom" not in cfg.agents.definitions

    def test_a_disabled_built_in_is_not_a_collision(self) -> None:
        """Disabling a built-in analyst is the operator's one lever on it, and
        the identity check forgives it. The rename must forgive it too, or
        every deployment that has ever switched an analyst off would grow a
        duplicate of it on the next load."""
        cfg = _settings(
            agents={
                "definitions": {"dynamic": {"role": "dynamic", "enabled": False}},
                "profiles": {"lean": {"analysts": ["static", "network"]}},
                "profile": "lean",
            }
        )
        assert "dynamic_custom" not in cfg.agents.definitions
        assert cfg.agents.definitions["dynamic"].enabled is False


class TestAStoredTeamUnderASeededName:
    def test_the_configuration_still_loads(self) -> None:
        cfg = _settings(agents={"profiles": {"mobile": {"label": "Mine", "analysts": ["static"]}}})
        assert cfg.agents.profiles["mobile_custom"].label == "Mine"
        assert set(BUILTIN_PROFILES) <= set(cfg.agents.profiles)

    def test_the_active_team_follows_its_rename(self) -> None:
        cfg = _settings(
            agents={
                "profiles": {"deep_static": {"label": "Mine", "analysts": ["static"]}},
                "profile": "deep_static",
            }
        )
        assert cfg.agents.profile == "deep_static_custom"

    def test_the_seeded_team_is_there_beside_it(self) -> None:
        cfg = _settings(agents={"profiles": {"mobile": {"label": "Mine", "analysts": ["static"]}}})
        assert [s.key for s in cfg.agents.profiles["mobile"].stages][0] == "triage"


class TestEveryReferenceMovesWithTheRename:
    def _cfg(self):
        return _settings(
            agents={
                "definitions": {"reverser": {"role": "generic", "prompt": "mine"}},
                "profiles": {"team": {"label": "Team", "analysts": ["reverser"]}},
                "profile": "team",
            },
            llm={"agents": {"reverser": {"provider": "openai", "model": "gpt-x"}}},
            react_agent_timeout_overrides={"reverser": 900},
            react_agent_max_steps_overrides={"reverser": 12},
        )

    def test_the_team_that_named_it_names_the_new_key(self) -> None:
        stages = self._cfg().agents.profiles["team"].stages
        assert stages[0].agents == ["reverser_custom"]

    def test_the_per_agent_model_entry_follows(self) -> None:
        assert "reverser_custom" in self._cfg().llm.agents
        assert self._cfg().llm.agents["reverser_custom"].model == "gpt-x"

    def test_both_react_override_maps_follow(self) -> None:
        cfg = self._cfg()
        assert cfg.react_agent_timeout_overrides["reverser_custom"] == 900
        assert cfg.react_agent_max_steps_overrides["reverser_custom"] == 12
        assert "reverser" not in cfg.react_agent_timeout_overrides

    def test_a_server_binding_follows(self) -> None:
        cfg = _settings(
            agents={"definitions": {"reverser": {"role": "generic", "prompt": "mine"}}},
            mcp={
                "servers": {
                    "mine": {
                        "enabled": True,
                        "transport": "stdio",
                        "command": "x",
                        "agents": ["reverser"],
                    }
                }
            },
        )
        assert cfg.mcp.servers["mine"].agents == ["reverser_custom"]


class TestThePassItself:
    def test_it_is_idempotent(self) -> None:
        document = {"agents": {"definitions": {"reverser": {"role": "generic", "prompt": "mine"}}}}
        once, first = rename_colliding_agent_keys(document)
        twice, second = rename_colliding_agent_keys(once)
        assert first.definitions == {"reverser": "reverser_custom"}
        assert not second
        assert twice == once

    def test_a_document_with_no_collision_is_returned_unchanged(self) -> None:
        document = {"agents": {"definitions": {"strings": {"role": "generic", "prompt": "p"}}}}
        out, renames = rename_colliding_agent_keys(document)
        assert out == document
        assert not renames

    def test_a_document_that_is_not_a_mapping_is_left_alone(self) -> None:
        out, renames = rename_colliding_agent_keys("nonsense")
        assert out == "nonsense"
        assert not renames

    def test_a_free_key_stays_inside_the_key_length_limit(self) -> None:
        long_key = "a" * 32
        assert len(free_key(long_key, set())) <= 32
        assert len(free_key(long_key, {f"{'a' * 25}_custom"})) <= 32


class TestTheRewriteLeavesAnAbsentFieldAbsent:
    """Three optional list fields, none of which accepts ``None``.

    The rewrite that follows a rename touches every stored team and every
    stored server, not only the ones that named the renamed agent. Writing the
    key in with a ``None`` value turned a document that would have validated
    into one that will not — the very failure the rename exists to prevent, and
    on exactly the operator it was written for, since the rewrite only runs
    when something was renamed.
    """

    CUSTOM = {"role": "generic", "prompt": "mine"}

    def test_a_team_with_a_debate_stage_still_loads(self) -> None:
        """A debate stage carries no agents. That is how the seeded teams
        themselves write one, so a custom team modelled on a built-in hits it."""
        cfg = _settings(
            agents={
                "definitions": {"reverser": self.CUSTOM},
                "profiles": {
                    "myteam": {
                        "stages": [
                            {"key": "a", "kind": "analysis", "agents": ["reverser"]},
                            {"key": "d", "kind": "debate", "depends_on": ["a"]},
                            {
                                "key": "v",
                                "kind": "verdict",
                                "agents": ["judge"],
                                "depends_on": ["d"],
                            },
                        ]
                    }
                },
            }
        )
        stages = {s.key: s.agents for s in cfg.agents.profiles["myteam"].stages}
        assert stages == {"a": ["reverser_custom"], "d": [], "v": ["judge"]}

    def test_a_team_that_omits_analysts_still_loads(self) -> None:
        """`analysts` is inert once a team carries stages, so omitting it is
        the modern shape and the one the console writes."""
        cfg = _settings(
            agents={
                "definitions": {"reverser": self.CUSTOM},
                "profiles": {
                    "myteam": {
                        "stages": [
                            {"key": "a", "kind": "analysis", "agents": ["reverser"]},
                            {
                                "key": "v",
                                "kind": "verdict",
                                "agents": ["judge"],
                                "depends_on": ["a"],
                            },
                        ]
                    }
                },
            }
        )
        assert cfg.agents.profiles["myteam"].analysts == []

    def test_a_server_without_an_agent_binding_still_loads(self) -> None:
        """A server with no agent restriction is the default and the common
        case, and one such server anywhere in the store was enough."""
        cfg = _settings(
            agents={"definitions": {"reverser": self.CUSTOM}},
            mcp={"servers": {"srv": {"transport": "stdio", "command": "x"}}},
        )
        assert cfg.mcp.servers["srv"].agents == []

    def test_a_team_that_names_no_renamed_agent_is_the_same_object(self) -> None:
        """The rewrite must not touch what it has no business touching."""
        from maljan.core.agent_key_migration import rename_colliding_agent_keys

        untouched = {"label": "Other", "stages": [{"key": "a", "agents": ["static"]}]}
        document = {
            "agents": {
                "definitions": {"reverser": self.CUSTOM},
                "profiles": {"other": untouched},
            }
        }
        out, renames = rename_colliding_agent_keys(document)
        assert renames.definitions == {"reverser": "reverser_custom"}
        assert out["agents"]["profiles"]["other"] == untouched

    def test_a_server_that_names_no_renamed_agent_is_the_same_object(self) -> None:
        from maljan.core.agent_key_migration import rename_colliding_agent_keys

        untouched = {"transport": "stdio", "command": "x", "agents": ["static"]}
        document = {
            "agents": {"definitions": {"reverser": self.CUSTOM}},
            "mcp": {"servers": {"srv": dict(untouched), "bare": {"command": "y"}}},
        }
        out, _ = rename_colliding_agent_keys(document)
        assert out["mcp"]["servers"]["srv"] == untouched
        assert out["mcp"]["servers"]["bare"] == {"command": "y"}


class TestSetIfList:
    def test_it_leaves_an_absent_field_absent(self) -> None:
        from maljan.core.agent_key_migration import set_if_list

        assert set_if_list({"key": "d"}, "agents", {"a": "b"}) == {"key": "d"}

    def test_it_leaves_a_field_that_is_not_a_list_alone(self) -> None:
        from maljan.core.agent_key_migration import set_if_list

        assert set_if_list({"agents": None}, "agents", {"a": "b"}) == {"agents": None}

    def test_it_rewrites_a_list_that_names_a_renamed_key(self) -> None:
        from maljan.core.agent_key_migration import set_if_list

        assert set_if_list({"agents": ["a", "z"]}, "agents", {"a": "b"}) == {"agents": ["b", "z"]}

    def test_it_returns_the_mapping_itself_when_nothing_changes(self) -> None:
        from maljan.core.agent_key_migration import set_if_list

        mapping = {"agents": ["z"]}
        assert set_if_list(mapping, "agents", {"a": "b"}) is mapping

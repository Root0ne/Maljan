"""A team is a validated pipeline, and a stored analyst list is one too.

Two things are pinned here. The rules a stage list must satisfy before it can
be stored — because a team that cannot run is a team that fails minutes into a
job rather than at the moment it was saved — and the conversion, because every
profile in every operator database is still written as a list of analysts and
must come out running exactly what it ran before.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from maljan.core.config import (
    DebateOptions,
    ProfileDefinition,
    Settings,
    StageDefinition,
    stages_from_analysts,
)


def _settings(**agents: object) -> Settings:
    return Settings(_env_file=None, agents=agents)


def _stage(**over: object) -> dict:
    return {"key": "analysis", "kind": "analysis", "agents": ["static"], **over}


def _verdict(depends_on: list[str]) -> dict:
    return {"key": "verdict", "kind": "verdict", "agents": ["judge"], "depends_on": depends_on}


class TestTheConversion:
    def test_a_stored_analyst_list_becomes_the_four_stages(self) -> None:
        profile = ProfileDefinition.model_validate({"analysts": ["static", "network"]})
        assert [(s.key, s.kind) for s in profile.stages] == [
            ("analysis", "analysis"),
            ("debate", "debate"),
            ("verdict", "verdict"),
            ("report", "report"),
        ]
        assert profile.stage("analysis").agents == ["static", "network"]
        assert profile.analysis_agents == ["static", "network"]

    def test_the_conversion_is_the_helper_the_migration_also_speaks(self) -> None:
        written = ProfileDefinition(
            label="hand",
            stages=stages_from_analysts(["static", "network"]),
        )
        converted = ProfileDefinition.model_validate(
            {"label": "hand", "analysts": ["static", "network"]}
        )
        assert converted.model_dump()["stages"] == written.model_dump()["stages"]

    def test_the_seeded_teams_are_the_hand_written_stage_form(self) -> None:
        """``default`` and ``measurement`` are the paper's pipeline, both of them."""
        settings = Settings(_env_file=None)
        expected = stages_from_analysts(
            ["static", "dynamic", "network"],
            parallel=False,
            max_rounds=settings.negotiation.max_iterations,
            consensus_threshold=settings.negotiation.consensus_threshold,
        )
        for name in ("default", "measurement"):
            dumped = settings.agents.profiles[name].model_dump()["stages"]
            assert dumped == [s.model_dump() for s in expected], name

    def test_a_converted_team_inherits_the_two_global_keys(self) -> None:
        settings = Settings(
            _env_file=None,
            llm={"parallel_analysts": True},
            negotiation={"max_iterations": 9, "consensus_threshold": 0.55},
        )
        profile = settings.agents.profiles["default"]
        assert profile.stage("analysis").mode == "parallel"
        assert profile.stage("debate").debate == DebateOptions(
            max_rounds=9, consensus_threshold=0.55, sycophancy_check=True
        )

    def test_a_team_written_as_stages_ignores_the_global_analyst_mode(self) -> None:
        settings = Settings(
            _env_file=None,
            llm={"parallel_analysts": True},
            agents={
                "profiles": {
                    "own": {
                        "stages": [
                            _stage(mode="sequential"),
                            _verdict(["analysis"]),
                        ]
                    }
                }
            },
        )
        assert settings.agents.profiles["own"].stage("analysis").mode == "sequential"

    def test_explicit_stages_win_over_a_stored_analyst_list(self) -> None:
        profile = ProfileDefinition.model_validate(
            {"analysts": ["static", "dynamic"], "stages": [_stage(), _verdict(["analysis"])]}
        )
        assert profile.analysis_agents == ["static"]
        # The list is kept: it is what the migration's downgrade reads.
        assert profile.analysts == ["static", "dynamic"]


class TestTheRulesAStageListMustSatisfy:
    def test_a_team_needs_exactly_one_verdict_stage(self) -> None:
        with pytest.raises(ValidationError, match="exactly one verdict stage; found none"):
            ProfileDefinition.model_validate({"stages": [_stage()]})
        with pytest.raises(ValidationError, match="exactly one verdict stage"):
            ProfileDefinition.model_validate(
                {
                    "stages": [
                        _stage(),
                        _verdict(["analysis"]),
                        {"key": "v2", "kind": "verdict", "agents": ["judge"]},
                    ]
                }
            )

    def test_the_report_stage_is_last_and_there_is_at_most_one(self) -> None:
        with pytest.raises(ValidationError, match="report stage is the last stage"):
            ProfileDefinition.model_validate(
                {
                    "stages": [
                        _stage(),
                        {
                            "key": "report",
                            "kind": "report",
                            "agents": ["reporter"],
                            "depends_on": ["analysis"],
                        },
                        _verdict(["analysis"]),
                    ]
                }
            )

    def test_a_stage_may_only_depend_on_a_stage_declared_before_it(self) -> None:
        """The rule that makes a cycle unrepresentable rather than detectable."""
        with pytest.raises(ValidationError, match="which is declared after it"):
            ProfileDefinition.model_validate(
                {
                    "stages": [
                        _stage(depends_on=["late"]),
                        {"key": "late", "kind": "analysis", "agents": ["network"]},
                        _verdict(["late"]),
                    ]
                }
            )

    def test_a_self_dependency_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="depends on itself"):
            ProfileDefinition.model_validate(
                {"stages": [_stage(depends_on=["analysis"]), _verdict(["analysis"])]}
            )

    def test_an_unknown_dependency_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="depends on unknown stage 'ghost'"):
            ProfileDefinition.model_validate(
                {"stages": [_stage(depends_on=["ghost"]), _verdict(["analysis"])]}
            )

    def test_a_duplicate_stage_key_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="'analysis' is declared twice"):
            ProfileDefinition.model_validate(
                {"stages": [_stage(), _stage(agents=["network"]), _verdict(["analysis"])]}
            )

    def test_an_analysis_stage_needs_an_agent(self) -> None:
        with pytest.raises(ValidationError, match="analysis stage with no agent"):
            ProfileDefinition.model_validate(
                {"stages": [_stage(agents=[]), _verdict(["analysis"])]}
            )

    def test_a_debate_needs_an_analysis_stage_upstream_of_it(self) -> None:
        with pytest.raises(ValidationError, match="debates nothing"):
            ProfileDefinition.model_validate(
                {
                    "stages": [
                        {"key": "debate", "kind": "debate"},
                        _stage(),
                        _verdict(["analysis"]),
                    ]
                }
            )

    def test_a_debate_reaches_its_analysis_stage_through_another_stage(self) -> None:
        """Upstream means transitively upstream, not only one hop back."""
        profile = ProfileDefinition.model_validate(
            {
                "stages": [
                    _stage(),
                    {
                        "key": "second",
                        "kind": "analysis",
                        "agents": ["network"],
                        "depends_on": ["analysis"],
                    },
                    {"key": "debate", "kind": "debate", "depends_on": ["second"]},
                    _verdict(["debate"]),
                ]
            }
        )
        assert profile.stage("debate").kind == "debate"

    def test_a_condition_that_does_not_parse_is_a_settings_error(self) -> None:
        with pytest.raises(ValidationError, match="unknown name 'bogus'"):
            StageDefinition(key="a", kind="analysis", agents=["static"], when="bogus == 1")

    def test_an_agent_belongs_to_one_stage(self) -> None:
        with pytest.raises(ValidationError, match="an agent belongs to one stage"):
            ProfileDefinition.model_validate(
                {
                    "stages": [
                        _stage(),
                        {"key": "again", "kind": "analysis", "agents": ["static"]},
                        _verdict(["again"]),
                    ]
                }
            )


class TestTheRulesThatNeedTheDefinitionMap:
    def test_a_verdict_stage_names_a_judge_definition(self) -> None:
        with pytest.raises(ValidationError, match="is not a judge definition"):
            _settings(
                profiles={
                    "own": {
                        "stages": [
                            _stage(),
                            {
                                "key": "verdict",
                                "kind": "verdict",
                                "agents": ["static"],
                                "depends_on": ["analysis"],
                            },
                        ]
                    }
                }
            )

    def test_a_report_stage_is_run_by_the_reporter(self) -> None:
        with pytest.raises(ValidationError, match="a report stage is run by 'reporter'"):
            _settings(
                profiles={
                    "own": {
                        "stages": [
                            _stage(),
                            _verdict(["analysis"]),
                            {
                                "key": "report",
                                "kind": "report",
                                "agents": ["judge"],
                                "depends_on": ["verdict"],
                            },
                        ]
                    }
                }
            )

    def test_a_debate_stage_names_no_agent(self) -> None:
        with pytest.raises(ValidationError, match="a debate stage names no agent"):
            _settings(
                profiles={
                    "own": {
                        "stages": [
                            _stage(),
                            {
                                "key": "debate",
                                "kind": "debate",
                                "agents": ["network"],
                                "depends_on": ["analysis"],
                            },
                            _verdict(["debate"]),
                        ]
                    }
                }
            )


class TestTheBuiltInTeamsStayTheArchitecture:
    def test_the_debate_options_of_a_built_in_may_be_tuned(self) -> None:
        stages = [
            s.model_dump() for s in Settings(_env_file=None).agents.profiles["default"].stages
        ]
        stages[1]["debate"] = {
            "max_rounds": 2,
            "consensus_threshold": 0.6,
            "sycophancy_check": False,
        }
        settings = _settings(profiles={"default": {"label": "Default", "stages": stages}})
        assert settings.agents.profiles["default"].stage("debate").debate.max_rounds == 2

    def test_the_built_in_tool_switch_of_a_built_in_may_be_flipped(self) -> None:
        stages = [
            s.model_dump() for s in Settings(_env_file=None).agents.profiles["default"].stages
        ]
        stages[0]["builtin_tools"] = False
        settings = _settings(profiles={"default": {"label": "Default", "stages": stages}})
        assert settings.agents.profiles["default"].stage("analysis").builtin_tools is False

    def test_anything_else_about_a_built_in_s_stages_is_refused(self) -> None:
        stages = [
            s.model_dump() for s in Settings(_env_file=None).agents.profiles["default"].stages
        ]
        stages[0]["agents"] = ["static"]
        with pytest.raises(ValidationError, match="'default' is built in; clone it to change it"):
            _settings(profiles={"default": {"label": "Default", "stages": stages}})


class TestADebateNeedsSomewhereToHandOver:
    """A conditional edge has one destination per branch, so a debate has one.

    Refused when the team is saved rather than only when the graph is built:
    the builder still raises, but by then the sample has been uploaded and
    detonated and every job under that team fails.
    """

    def _team(self, downstream: list[dict]) -> dict:
        return {
            "own": {
                "stages": [
                    _stage(),
                    {"key": "d", "kind": "debate", "depends_on": ["analysis"]},
                    *downstream,
                ]
            }
        }

    def test_a_debate_feeding_a_parallel_stage_of_two_agents_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="hands over to 2 nodes"):
            _settings(
                profiles=self._team(
                    [
                        {
                            "key": "wide",
                            "kind": "analysis",
                            "agents": ["dynamic", "network"],
                            "mode": "parallel",
                            "depends_on": ["d"],
                        },
                        {
                            "key": "v",
                            "kind": "verdict",
                            "agents": ["judge"],
                            "depends_on": ["wide"],
                        },
                    ]
                )
            )

    def test_a_debate_feeding_two_stages_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="hands over to 2 nodes \\(one, two\\)"):
            _settings(
                profiles=self._team(
                    [
                        {
                            "key": "one",
                            "kind": "analysis",
                            "agents": ["dynamic"],
                            "depends_on": ["d"],
                        },
                        {
                            "key": "two",
                            "kind": "analysis",
                            "agents": ["network"],
                            "depends_on": ["d"],
                        },
                        {
                            "key": "v",
                            "kind": "verdict",
                            "agents": ["judge"],
                            "depends_on": ["one", "two"],
                        },
                    ]
                )
            )

    def test_the_message_says_what_a_parallel_stage_has_to_do_with_it(self) -> None:
        with pytest.raises(
            ValidationError,
            match="not to a parallel analysis stage with more than one agent",
        ):
            _settings(
                profiles=self._team(
                    [
                        {
                            "key": "wide",
                            "kind": "analysis",
                            "agents": ["dynamic", "network"],
                            "mode": "parallel",
                            "depends_on": ["d"],
                        },
                        {
                            "key": "v",
                            "kind": "verdict",
                            "agents": ["judge"],
                            "depends_on": ["wide"],
                        },
                    ]
                )
            )

    def test_a_debate_feeding_a_sequential_stage_of_two_agents_is_fine(self) -> None:
        """A chain starts at one node however many agents it holds."""
        settings = _settings(
            profiles=self._team(
                [
                    {
                        "key": "chain",
                        "kind": "analysis",
                        "agents": ["dynamic", "network"],
                        "depends_on": ["d"],
                    },
                    {"key": "v", "kind": "verdict", "agents": ["judge"], "depends_on": ["chain"]},
                ]
            )
        )
        assert settings.agents.profiles["own"].stage("d").kind == "debate"

    def test_a_debate_feeding_one_parallel_agent_is_fine(self) -> None:
        settings = _settings(
            profiles=self._team(
                [
                    {
                        "key": "solo",
                        "kind": "analysis",
                        "agents": ["dynamic"],
                        "mode": "parallel",
                        "depends_on": ["d"],
                    },
                    {"key": "v", "kind": "verdict", "agents": ["judge"], "depends_on": ["solo"]},
                ]
            )
        )
        assert settings.agents.profiles["own"].stage("solo").mode == "parallel"


class TestAMigratedTeamAndAFreshOneAgree:
    """A team the migration wrote stages for keeps following the global keys.

    Without the marker the migration froze whatever those two keys said on the
    day it ran, and an operator who migrated on a hosted API and later moved
    back to the single-slot local model kept running analysts in parallel.
    """

    def _globals(self) -> dict:
        return {"llm": {"parallel_analysts": True}, "negotiation": {"max_iterations": 9}}

    def test_the_two_produce_the_same_stages(self) -> None:
        fresh = Settings(
            _env_file=None,
            **self._globals(),
            agents={"profiles": {"lean": {"label": "Lean", "analysts": ["static"]}}},
        ).agents.profiles["lean"]

        migrated_doc = {
            "label": "Lean",
            "analysts": ["static"],
            "derived_from_analysts": True,
            "stages": [s.model_dump() for s in stages_from_analysts(["static"])],
        }
        migrated = Settings(
            _env_file=None,
            **self._globals(),
            agents={"profiles": {"lean": migrated_doc}},
        ).agents.profiles["lean"]

        assert migrated.model_dump()["stages"] == fresh.model_dump()["stages"]
        assert migrated.stage("analysis").mode == "parallel"
        assert migrated.stage("debate").debate.max_rounds == 9

    def test_a_team_the_operator_has_edited_keeps_its_edit(self) -> None:
        """The console clears the marker on the first stage edit."""
        written = [s.model_dump() for s in stages_from_analysts(["static"])]
        written[0]["mode"] = "sequential"
        edited = Settings(
            _env_file=None,
            **self._globals(),
            agents={
                "profiles": {
                    "lean": {
                        "label": "Lean",
                        "analysts": ["static"],
                        "derived_from_analysts": False,
                        "stages": written,
                    }
                }
            },
        ).agents.profiles["lean"]
        assert edited.stage("analysis").mode == "sequential"

    def test_the_marker_is_not_what_makes_a_built_in_look_edited(self) -> None:
        """A built-in whose stages the migration wrote out is the same built-in."""
        seed = Settings(_env_file=None).agents.profiles["default"]
        stored = seed.model_dump()
        stored.pop("derived_from_analysts", None)
        settings = _settings(profiles={"default": stored})
        assert settings.agents.profiles["default"].analysis_agents == seed.analysis_agents


class TestTheDerivedMarkerIsCheckedNotTrusted:
    """The marker travels in the document, so it arrives from anywhere.

    A team with the marker and stages an operator wrote by hand used to have
    those stages replaced on the next load, with no error and no log line —
    reachable from an imported document, a script's PATCH, or an export edited
    in a text editor. The console was the only thing clearing the marker.
    """

    def _hand_written(self) -> dict:
        return {
            "mine": {
                "analysts": ["static", "dynamic", "network"],
                "derived_from_analysts": True,
                "stages": [
                    {"key": "triage", "kind": "analysis", "agents": ["static"]},
                    {"key": "deb", "kind": "debate", "depends_on": ["triage"]},
                    {"key": "v", "kind": "verdict", "agents": ["judge"], "depends_on": ["deb"]},
                    {"key": "r", "kind": "report", "agents": ["reporter"], "depends_on": ["v"]},
                ],
            }
        }

    def test_a_flagged_team_with_hand_written_stages_loads_as_written(self) -> None:
        profile = _settings(profiles=self._hand_written(), profile="mine").agents.profiles["mine"]
        assert [s.key for s in profile.stages] == ["triage", "deb", "v", "r"]
        assert profile.derived_from_analysts is False

    def test_the_flag_is_cleared_rather_than_left_to_bite_on_the_next_load(self) -> None:
        """Loading the corrected document twice must be the same as once."""
        first = _settings(profiles=self._hand_written(), profile="mine").agents.profiles["mine"]
        again = _settings(profiles={"mine": first.model_dump()}, profile="mine").agents.profiles[
            "mine"
        ]
        assert [s.key for s in again.stages] == ["triage", "deb", "v", "r"]

    def test_a_flagged_untouched_team_still_follows_the_globals(self) -> None:
        untouched = {
            "lean": {
                "analysts": ["static"],
                "derived_from_analysts": True,
                "stages": [s.model_dump() for s in stages_from_analysts(["static"])],
            }
        }
        profile = Settings(
            _env_file=None,
            llm={"parallel_analysts": True},
            negotiation={"max_iterations": 9},
            agents={"profiles": untouched, "profile": "lean"},
        ).agents.profiles["lean"]
        assert profile.derived_from_analysts is True
        assert profile.stage("analysis").mode == "parallel"
        assert profile.stage("debate").debate.max_rounds == 9

    def test_one_edited_stage_is_enough_to_stop_the_derivation(self) -> None:
        for field, value in (
            ("when", 'platform == "windows"'),
            ("builtin_tools", False),
            ("inject_upstream", "full"),
            ("label", "Renamed"),
        ):
            stages = [s.model_dump() for s in stages_from_analysts(["static"])]
            stages[0][field] = value
            profile = _settings(
                profiles={
                    "lean": {
                        "analysts": ["static"],
                        "derived_from_analysts": True,
                        "stages": stages,
                    }
                },
                profile="lean",
            ).agents.profiles["lean"]
            assert profile.derived_from_analysts is False, field
            assert getattr(profile.stage("analysis"), field) == value

    def test_a_stage_added_or_removed_stops_it_too(self) -> None:
        stages = [s.model_dump() for s in stages_from_analysts(["static"])]
        shorter = [s for s in stages if s["key"] != "report"]
        profile = _settings(
            profiles={
                "lean": {
                    "analysts": ["static"],
                    "derived_from_analysts": True,
                    "stages": shorter,
                }
            },
            profile="lean",
        ).agents.profiles["lean"]
        assert profile.derived_from_analysts is False
        assert [s.key for s in profile.stages] == ["analysis", "debate", "verdict"]

    def test_the_marker_means_nothing_without_an_analyst_list_to_derive_from(self) -> None:
        profile = _settings(
            profiles={
                "lean": {
                    "derived_from_analysts": True,
                    "stages": [_stage(), _verdict(["analysis"])],
                }
            },
            profile="lean",
        ).agents.profiles["lean"]
        assert profile.derived_from_analysts is False

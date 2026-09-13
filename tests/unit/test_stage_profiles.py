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

"""A team is checked before it is saved, in the words save refuses it with.

Three promises are pinned here. Every refusal the settings model makes about a
team is a lint error, word for word, so the editor's preview and the save
cannot disagree. A warning is a team that saves. And the lint reports: it
never changes the team it reads.
"""

from __future__ import annotations

import copy
from typing import Any

import pytest
from pydantic import ValidationError

from maljan.core.config import (
    AgentDefinition,
    AgentsConfig,
    Settings,
    StageDefinition,
    _builtin_definitions,
)
from maljan.core.team_layout import layout_team
from maljan.core.team_lint import lint_team, lint_teams

TEAM = "mine"


def _team(*stages: dict[str, Any]) -> dict[str, Any]:
    return {"label": "Mine", "stages": list(stages)}


def _triage() -> dict[str, Any]:
    return {"key": "triage_pack", "kind": "triage"}


def _analysis(key: str = "a", agents: list[str] | None = None, **over: Any) -> dict[str, Any]:
    return {"key": key, "kind": "analysis", "agents": agents or ["static"], **over}


def _debate(depends_on: list[str], key: str = "d", **over: Any) -> dict[str, Any]:
    return {"key": key, "kind": "debate", "depends_on": depends_on, **over}


def _verdict(depends_on: list[str], key: str = "v", **over: Any) -> dict[str, Any]:
    return {"key": key, "kind": "verdict", "agents": ["judge"], "depends_on": depends_on, **over}


def _report(depends_on: list[str], key: str = "r", **over: Any) -> dict[str, Any]:
    return {"key": key, "kind": "report", "agents": ["reporter"], "depends_on": depends_on, **over}


def _good() -> dict[str, Any]:
    return _team(
        _triage(),
        _analysis(depends_on=["triage_pack"]),
        _debate(["a"]),
        _verdict(["d"]),
        _report(["v"]),
    )


def _definitions(**changes: Any) -> dict[str, AgentDefinition]:
    """The seeded agent map with ``changes`` merged in, as the settings model merges them."""
    out = dict(_builtin_definitions())
    for key, change in changes.items():
        seed = out.get(key)
        merged = {**seed.model_dump(), **change} if seed is not None else change
        out[key] = AgentDefinition.model_validate(merged)
    return out


def _errors(name: str, entry: Any, **kwargs: Any) -> list[str]:
    kwargs.setdefault("definitions", _definitions())
    return [f.message for f in lint_team(name, entry, **kwargs) if f.severity == "error"]


def _warnings(entry: Any, **kwargs: Any) -> list[tuple[str, str | None]]:
    kwargs.setdefault("definitions", _definitions())
    return [(f.code, f.stage) for f in lint_team(TEAM, entry, **kwargs) if f.severity == "warning"]


# One defect per team, each one a rule the settings model refuses. Every rule
# ``stage_list_problems``, ``stage_member_problems``, the condition check, the
# built-in identity check and the field validation can raise has a row here;
# ``test_the_corpus_reaches_every_rule`` fails when a new rule has none.
CORPUS: dict[str, tuple[str, dict[str, Any], dict[str, Any]]] = {
    "no_stages": (TEAM, _team(), {}),
    "duplicate_key": (
        TEAM,
        _team(_analysis(), _analysis(agents=["dynamic"]), _verdict(["a"])),
        {},
    ),
    "self_dependency": (TEAM, _team(_analysis(depends_on=["a"]), _verdict(["a"])), {}),
    "dangling_dependency": (TEAM, _team(_analysis(depends_on=["zzz"]), _verdict(["a"])), {}),
    "later_dependency": (TEAM, _team(_analysis(depends_on=["v"]), _verdict(["a"])), {}),
    "agent_in_two_stages": (
        TEAM,
        _team(_analysis(), _analysis("b", depends_on=["a"]), _verdict(["b"])),
        {},
    ),
    "no_agents": (TEAM, _team({"key": "a", "kind": "analysis"}, _verdict(["a"])), {}),
    "triage_agents": (
        TEAM,
        _team({**_triage(), "agents": ["static"]}, _analysis(), _verdict(["a"])),
        {},
    ),
    "triage_key": (
        TEAM,
        _team({"key": "static_analyst", "kind": "triage"}, _analysis(), _verdict(["a"])),
        {},
    ),
    "debate_upstream": (
        TEAM,
        _team(_triage(), _debate(["triage_pack"]), _analysis(depends_on=["d"]), _verdict(["a"])),
        {},
    ),
    "debate_handover": (
        TEAM,
        _team(
            _analysis(),
            _debate(["a"]),
            _analysis("one", ["dynamic"], depends_on=["d"]),
            _analysis("two", ["network"], depends_on=["d"]),
            _verdict(["one", "two"]),
        ),
        {},
    ),
    "verdict_count": (TEAM, _team(_analysis(), _debate(["a"])), {}),
    "report_count": (
        TEAM,
        _team(_analysis(), _verdict(["a"]), _report(["v"]), _report(["v"], key="r2")),
        {},
    ),
    "report_not_last": (
        TEAM,
        _team(_analysis(), {"key": "r", "kind": "report", "agents": ["reporter"]}, _verdict(["a"])),
        {},
    ),
    "condition": (TEAM, _team(_analysis(when="verdict == 'Malware'"), _verdict(["a"])), {}),
    "field": (TEAM, _team(_analysis(key="Bad Key"), _verdict(["Bad Key"])), {}),
    "field_kind": (TEAM, _team(_analysis(kind="judge"), _verdict(["a"])), {}),
    "field_team": (TEAM, {"label": 3, "stages": _good()["stages"]}, {}),
    "unknown_agent": (TEAM, _team(_analysis(agents=["ghost"]), _verdict(["a"])), {}),
    "agent_role": (TEAM, _team(_analysis(agents=["judge"]), _verdict(["a"])), {}),
    "disabled_agent": (
        TEAM,
        _team(_analysis(agents=["network"]), _verdict(["a"])),
        {"network": {"role": "network", "enabled": False}},
    ),
    "verdict_judge": (TEAM, _team(_analysis(), _verdict(["a"], agents=[])), {}),
    "verdict_not_a_judge": (TEAM, _team(_analysis(), _verdict(["a"], agents=["dynamic"])), {}),
    "report_reporter": (
        TEAM,
        _team(_analysis(), _verdict(["a"]), _report(["v"], agents=["judge"])),
        {},
    ),
    "debate_agents": (
        TEAM,
        _team(_analysis(), _debate(["a"], agents=["dynamic"]), _verdict(["d"])),
        {},
    ),
    "builtin": ("default", {**_good(), "label": "Not the seed"}, {}),
    "team_key": ("Bad Team", _good(), {}),
}

CODES = {
    "no_stages",
    "duplicate_key",
    "self_dependency",
    "dangling_dependency",
    "later_dependency",
    "agent_in_two_stages",
    "no_agents",
    "triage_agents",
    "triage_key",
    "debate_upstream",
    "debate_handover",
    "verdict_count",
    "report_count",
    "report_not_last",
    "condition",
    "field",
    "unknown_agent",
    "agent_role",
    "disabled_agent",
    "verdict_judge",
    "report_reporter",
    "debate_agents",
    "builtin",
    "team_key",
}


def _model_refusal(name: str, entry: dict[str, Any], definitions: dict[str, Any]) -> list[str]:
    """What the settings model says when it refuses ``entry``, prefix removed."""
    with pytest.raises(ValidationError) as exc:
        AgentsConfig.model_validate(
            {"profiles": {name: entry}, "definitions": definitions, "profile": "default"}
        )
    return [str(err["msg"]).removeprefix("Value error, ") for err in exc.value.errors()]


class TestEveryRefusalIsAFinding:
    @pytest.mark.parametrize("case", sorted(CORPUS))
    def test_the_model_refusal_is_a_lint_error_word_for_word(self, case: str) -> None:
        name, entry, changes = CORPUS[case]
        refusals = _model_refusal(name, entry, changes)
        errors = _errors(name, entry, definitions=_definitions(**changes))
        assert refusals
        for refusal in refusals:
            assert refusal in errors, f"{case}: save says {refusal!r}, lint says {errors}"

    @pytest.mark.parametrize("case", sorted(CORPUS))
    def test_the_save_path_refuses_with_the_lint_error_at_the_lint_path(self, case: str) -> None:
        from app.services.agent_map import (
            AGENT_DEFINITIONS_KEY,
            AGENT_PROFILES_KEY,
            AgentMapError,
            finding_path,
            validate_agent_map,
        )

        name, entry, changes = CORPUS[case]
        patch: dict[str, Any] = {AGENT_PROFILES_KEY: {name: entry}}
        if changes:
            patch[AGENT_DEFINITIONS_KEY] = changes
        with pytest.raises(AgentMapError) as exc:
            validate_agent_map(patch, stored={})
        definitions = _definitions(**changes)
        found = {
            (finding_path(f), f.message)
            for f in lint_team(name, entry, definitions=definitions)
            if f.severity == "error"
        }
        for path, message in exc.value.errors.items():
            assert (path, message) in found, f"{case}: {path}: {message}"

    def test_the_corpus_reaches_every_rule(self) -> None:
        hit: set[str] = set()
        for name, entry, changes in CORPUS.values():
            for finding in lint_team(name, entry, definitions=_definitions(**changes)):
                hit.add(finding.code)
        assert CODES <= hit, CODES - hit

    def test_a_disabled_member_of_a_built_in_is_refused_only_while_it_runs(self) -> None:
        definitions = _definitions(network={"role": "network", "enabled": False})
        entry = Settings(_env_file=None).agents.profiles["default"].model_dump(mode="json")
        assert _errors("default", entry, definitions=definitions, active="mobile") == []
        running = _errors("default", entry, definitions=definitions, active="default")
        assert any("'network' is disabled" in m for m in running)
        assert "'default' is built in; clone it to change it" not in running


class TestWhatTheLintReports:
    def test_the_seeded_teams_are_clean(self) -> None:
        settings = Settings(_env_file=None)
        profiles = {k: v.model_dump(mode="json") for k, v in settings.agents.profiles.items()}
        assert lint_teams(profiles, definitions=settings.agents.definitions) == []

    def test_every_problem_is_reported_at_once_on_its_own_stage(self) -> None:
        entry = _team(
            _analysis(agents=["ghost"]),
            {"key": "b", "kind": "analysis", "depends_on": ["zzz"]},
            _verdict(["a"], when="verdict == 1"),
        )
        located = {
            (f.code, f.stage, f.field)
            for f in lint_team(TEAM, entry, definitions=_definitions())
            if f.severity == "error"
        }
        assert ("unknown_agent", "a", "agents") in located
        assert ("no_agents", "b", "agents") in located
        assert ("dangling_dependency", "b", "depends_on") in located
        assert ("condition", "v", "when") in located

    def test_a_cycle_is_named_on_every_stage_in_it(self) -> None:
        entry = _team(
            _analysis(depends_on=["b"]),
            _analysis("b", ["dynamic"], depends_on=["a"]),
            _verdict(["b"]),
        )
        cycle = [f for f in lint_team(TEAM, entry, definitions=_definitions()) if f.code == "cycle"]
        assert {f.stage for f in cycle} == {"a", "b"}
        assert "a → b → a" in cycle[0].message

    def test_a_stage_with_a_bad_key_does_not_hide_the_rest_of_the_team(self) -> None:
        entry = _team(_analysis(key="Bad Key"), _analysis("b", agents=["ghost"]), _verdict(["b"]))
        codes = {f.code for f in lint_team(TEAM, entry, definitions=_definitions())}
        assert {"field", "unknown_agent"} <= codes

    def test_a_stored_analyst_list_is_linted_as_the_stages_it_becomes(self) -> None:
        assert _errors(TEAM, {"analysts": ["static", "ghost"]})

    def test_a_team_that_is_not_an_object_is_one_error(self) -> None:
        assert _errors(TEAM, ["not", "a", "team"]) == ["a profile entry must be an object"]

    def test_the_lint_never_changes_the_team_it_reads(self) -> None:
        for name, entry, changes in CORPUS.values():
            before = copy.deepcopy(entry)
            lint_team(name, entry, definitions=_definitions(**changes))
            assert entry == before


class TestWarnings:
    def test_a_stage_the_verdict_does_not_wait_for_is_a_warning(self) -> None:
        entry = _team(
            _triage(),
            _analysis(depends_on=["triage_pack"]),
            _analysis("side", ["dynamic"], depends_on=["triage_pack"]),
            _verdict(["a"]),
        )
        assert ("unreachable", "side") in _warnings(entry)

    def test_a_stage_after_the_verdict_is_a_warning(self) -> None:
        entry = _team(
            _analysis(), _verdict(["a"]), _analysis("late", ["dynamic"], depends_on=["v"])
        )
        assert ("after_verdict", "late") in _warnings(entry)

    def test_a_root_the_triage_pack_adopts_is_upstream_of_it(self) -> None:
        """The builder starts a root after the pack; the lint reads the same rule."""
        entry = _team(_triage(), _analysis(), _verdict(["a"]))
        assert _warnings(entry) == []

    def test_a_condition_false_for_every_sample_is_a_warning(self) -> None:
        entry = _team(_analysis(when="1 == 2"), _verdict(["a"]))
        assert ("never_runs", "a") in _warnings(entry)

    def test_a_condition_over_the_sample_is_not_guessed_at(self) -> None:
        entry = _team(_analysis(when='file_type == "nothing-ever"'), _verdict(["a"]))
        assert _warnings(entry) == []

    def test_a_condition_on_a_stage_the_team_lacks_is_a_warning(self) -> None:
        entry = _team(_analysis(when="stages.ghost.ran"), _verdict(["a"]))
        assert ("condition_unknown_stage", "a") in _warnings(entry)

    def test_a_condition_on_a_stage_that_has_not_run_yet_is_a_warning(self) -> None:
        entry = _team(
            _triage(),
            _analysis(depends_on=["triage_pack"]),
            _analysis(
                "b", ["dynamic"], depends_on=["triage_pack"], when="stages.a.claim_count > 0"
            ),
            _verdict(["a", "b"]),
        )
        assert ("condition_not_upstream", "b") in _warnings(entry)

    def test_a_condition_on_an_upstream_stage_is_fine(self) -> None:
        entry = _team(
            _analysis(),
            _analysis("b", ["dynamic"], depends_on=["a"], when="stages.a.claim_count > 0"),
            _verdict(["b"]),
        )
        assert _warnings(entry) == []

    def test_an_enabled_agent_no_team_names_is_a_warning(self) -> None:
        definitions = _definitions(
            spare={"role": "generic", "label": "Spare", "prompt": "Look.", "tools": []}
        )
        settings = Settings(_env_file=None)
        profiles = {k: v.model_dump(mode="json") for k, v in settings.agents.profiles.items()}
        unused = [
            f.agent
            for f in lint_teams(profiles, definitions=definitions)
            if f.code == "unused_agent"
        ]
        assert unused == ["spare"]

    def test_an_agent_only_asked_by_another_agent_is_in_use(self) -> None:
        definitions = _definitions(
            spare={"role": "generic", "label": "Spare", "prompt": "Look.", "tools": []},
            asker={
                "role": "generic",
                "label": "Asker",
                "prompt": "Ask.",
                "tools": [{"kind": "agent", "agent": "spare"}],
            },
        )
        profiles = {TEAM: _team(_analysis(agents=["asker"]), _verdict(["a"]))}
        unused = [
            f.agent
            for f in lint_teams(profiles, definitions=definitions)
            if f.code == "unused_agent"
        ]
        assert "spare" not in unused
        assert "asker" not in unused

    def test_a_warning_never_blocks_a_save(self) -> None:
        from app.services.agent_map import AGENT_PROFILES_KEY, validate_agent_map

        entry = _team(
            _analysis(when="1 == 2"),
            _verdict(["a"]),
            _analysis("late", ["dynamic"], depends_on=["v"]),
        )
        assert _warnings(entry)
        out = validate_agent_map({AGENT_PROFILES_KEY: {TEAM: entry}}, stored={})
        assert TEAM in out[AGENT_PROFILES_KEY]


def _stages(*raw: dict[str, Any]) -> list[StageDefinition]:
    return [StageDefinition.model_validate(stage) for stage in raw]


class TestTheLayout:
    def test_a_chain_is_one_column_in_run_order(self) -> None:
        layout = layout_team(_stages(*_good()["stages"]))
        assert [(n.key, n.row, n.column) for n in layout.nodes] == [
            ("triage_pack", 0, 0),
            ("a", 1, 0),
            ("d", 2, 0),
            ("v", 3, 0),
            ("r", 4, 0),
        ]
        assert layout.columns == 1

    def test_stages_that_run_side_by_side_share_a_row(self) -> None:
        layout = layout_team(
            _stages(
                _triage(),
                _analysis(depends_on=["triage_pack"]),
                _analysis("b", ["dynamic"], depends_on=["triage_pack"]),
                _verdict(["a", "b"]),
            )
        )
        rows = {n.key: (n.row, n.column) for n in layout.nodes}
        assert rows == {"triage_pack": (0, 0), "a": (1, 0), "b": (1, 1), "v": (2, 0)}
        assert layout.columns == 2

    def test_the_triage_pack_adoption_is_an_implicit_edge(self) -> None:
        profile = Settings(_env_file=None).agents.profiles["default"]
        layout = layout_team(list(profile.stages))
        implicit = [(e.source, e.target) for e in layout.edges if e.implicit]
        assert implicit == [("triage_pack", "analysis")]

    def test_an_edge_to_a_later_stage_is_drawn_illegal_and_moves_nothing(self) -> None:
        stages = [
            StageDefinition.model_construct(
                key="a",
                kind="analysis",
                agents=["static"],
                depends_on=["v"],
                when="",
                label="",
                mode="sequential",
                inject_upstream="findings",
            ),
            *_stages(_verdict(["a"])),
        ]
        layout = layout_team(stages)
        assert [(e.source, e.target, e.legal) for e in layout.edges] == [
            ("a", "v", True),
            ("v", "a", False),
        ]
        assert [n.row for n in layout.nodes] == [0, 1]

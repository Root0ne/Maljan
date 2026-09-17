"""A team of stages becomes the graph the team describes, and nothing else.

The default profile's graph is pinned separately by ``test_graph_snapshot``.
This is the other half: a team that is *not* the default — a triage stage, a
platform-conditional stage, a parallel stage with a barrier, two independent
analysis stages feeding one debate — builds the topology it says it does, and a
stage whose condition is false is still in the graph and still records why it
did not run.
"""

from __future__ import annotations

from typing import Any

from maljan.core.config import Settings, StageDefinition
from maljan.core.container import ServiceContainer
from maljan.pipeline.builder import build_graph
from maljan.pipeline.nodes import make_stage_agent_node, stage_context, stage_rollup


def _shape(container: ServiceContainer) -> dict[str, Any]:
    compiled = build_graph(container)
    drawn = compiled.get_graph()
    conditional: dict[str, dict[str, str]] = {}
    for source, branches in compiled.builder.branches.items():
        for spec in branches.values():
            conditional[source] = dict(spec.ends or {})
    return {
        "nodes": sorted(drawn.nodes),
        "edges": sorted(f"{e.source}->{e.target}" for e in drawn.edges),
        "conditional": conditional,
    }


def _settings(stages: list[dict], **definitions: dict) -> Settings:
    return Settings(
        _env_file=None,
        agents={
            "definitions": definitions,
            "profiles": {"team": {"label": "Team", "stages": stages}},
            "profile": "team",
        },
    )


def _container(stages: list[dict], **definitions: dict) -> ServiceContainer:
    return ServiceContainer(_settings(stages, **definitions), mock=True)


ANALYST = {"role": "generic", "prompt": "look"}
_STAGE_MODEL = StageDefinition


class TestATeamBuildsTheTopologyItDescribes:
    def test_a_conditional_stage_is_a_node_whatever_the_sample_is(self) -> None:
        """triage → static(when apk) → dynamic → verdict → report.

        The APK stage's condition is false for a PE, and the graph is the same
        graph: the topology is a property of the team, not of the sample, so a
        run can be drawn and compared before the sample arrives.
        """
        stages = [
            {"key": "triage", "kind": "analysis", "agents": ["static"]},
            {
                "key": "apk",
                "kind": "analysis",
                "agents": ["apkscan"],
                "depends_on": ["triage"],
                "when": 'extension == "apk"',
            },
            {"key": "detonate", "kind": "analysis", "agents": ["dynamic"], "depends_on": ["apk"]},
            {"key": "verdict", "kind": "verdict", "agents": ["judge"], "depends_on": ["detonate"]},
            {"key": "report", "kind": "report", "agents": ["reporter"], "depends_on": ["verdict"]},
        ]
        shape = _shape(_container(stages, apkscan=ANALYST))
        assert shape["nodes"] == sorted(
            [
                "__start__",
                "__end__",
                "static_analyst",
                "apkscan_analyst",
                "dynamic_analyst",
                "judge",
                "report",
            ]
        )
        assert shape["edges"] == sorted(
            [
                "__start__->static_analyst",
                "static_analyst->apkscan_analyst",
                "apkscan_analyst->dynamic_analyst",
                "dynamic_analyst->judge",
                "judge->report",
                "report->__end__",
            ]
        )
        assert shape["conditional"] == {}

    def test_a_parallel_stage_feeding_two_stages_gets_a_barrier(self) -> None:
        stages = [
            {
                "key": "wide",
                "kind": "analysis",
                "agents": ["static", "network"],
                "mode": "parallel",
            },
            {"key": "left", "kind": "analysis", "agents": ["dynamic"], "depends_on": ["wide"]},
            {"key": "right", "kind": "analysis", "agents": ["strings"], "depends_on": ["wide"]},
            {
                "key": "verdict",
                "kind": "verdict",
                "agents": ["judge"],
                "depends_on": ["left", "right"],
            },
        ]
        shape = _shape(_container(stages, strings=ANALYST))
        assert "wide__join" in shape["nodes"]
        assert "static_analyst->wide__join" in shape["edges"]
        assert "network_analyst->wide__join" in shape["edges"]
        assert "wide__join->dynamic_analyst" in shape["edges"]
        assert "wide__join->strings_analyst" in shape["edges"]

    def test_a_parallel_stage_with_one_downstream_node_needs_no_barrier(self) -> None:
        """LangGraph already waits for every predecessor; a barrier would be a
        node in every transcript that stands for nothing."""
        stages = [
            {
                "key": "wide",
                "kind": "analysis",
                "agents": ["static", "network"],
                "mode": "parallel",
            },
            {"key": "verdict", "kind": "verdict", "agents": ["judge"], "depends_on": ["wide"]},
        ]
        shape = _shape(_container(stages))
        assert not any(node.endswith("__join") for node in shape["nodes"])
        assert "static_analyst->judge" in shape["edges"]
        assert "network_analyst->judge" in shape["edges"]

    def test_two_independent_analysis_stages_feed_one_debate(self) -> None:
        stages = [
            {"key": "one", "kind": "analysis", "agents": ["static"]},
            {"key": "two", "kind": "analysis", "agents": ["network"]},
            {"key": "debate", "kind": "debate", "depends_on": ["one", "two"]},
            {"key": "verdict", "kind": "verdict", "agents": ["judge"], "depends_on": ["debate"]},
        ]
        shape = _shape(_container(stages))
        assert "__start__->static_analyst" in shape["edges"]
        assert "__start__->network_analyst" in shape["edges"]
        assert "static_analyst->negotiation" in shape["edges"]
        assert "network_analyst->negotiation" in shape["edges"]
        assert shape["conditional"] == {"negotiation": {"revision": "revision", "judge": "judge"}}

    def test_two_debates_take_the_stage_prefix_so_neither_loses_its_nodes(self) -> None:
        stages = [
            {"key": "one", "kind": "analysis", "agents": ["static"]},
            {"key": "argue", "kind": "debate", "depends_on": ["one"]},
            {"key": "two", "kind": "analysis", "agents": ["network"], "depends_on": ["argue"]},
            {"key": "argue_again", "kind": "debate", "depends_on": ["two"]},
            {
                "key": "verdict",
                "kind": "verdict",
                "agents": ["judge"],
                "depends_on": ["argue_again"],
            },
        ]
        shape = _shape(_container(stages))
        for node in (
            "argue__negotiation",
            "argue__revision",
            "argue_again__negotiation",
            "argue_again__revision",
        ):
            assert node in shape["nodes"], node
        assert shape["conditional"]["argue__negotiation"]["judge"] == "network_analyst"
        assert shape["conditional"]["argue_again__negotiation"]["judge"] == "judge"

    def test_reporting_disabled_drops_the_report_stage_and_ends_at_the_judge(self) -> None:
        settings = _settings(
            [
                {"key": "one", "kind": "analysis", "agents": ["static"]},
                {"key": "verdict", "kind": "verdict", "agents": ["judge"], "depends_on": ["one"]},
                {
                    "key": "report",
                    "kind": "report",
                    "agents": ["reporter"],
                    "depends_on": ["verdict"],
                },
            ]
        )
        settings.reporting.enabled = False
        shape = _shape(ServiceContainer(settings, mock=True))
        assert "report" not in shape["nodes"]
        assert "judge->__end__" in shape["edges"]


class TestAStageThatDeclinesToRunSaysSo:
    def _node(self, when: str, container: ServiceContainer) -> Any:
        stage = container.active_profile().stage("apk")
        assert stage.when == when
        return make_stage_agent_node(stage, "apkscan", container)

    def _team(self) -> ServiceContainer:
        stages = [
            {"key": "triage", "kind": "analysis", "agents": ["static"]},
            {
                "key": "apk",
                "kind": "analysis",
                "agents": ["apkscan"],
                "depends_on": ["triage"],
                "when": 'extension == "apk"',
            },
            {"key": "verdict", "kind": "verdict", "agents": ["judge"], "depends_on": ["apk"]},
        ]
        return _container(stages, apkscan=ANALYST)

    def test_the_node_records_a_skip_with_its_reason_and_produces_nothing(self) -> None:
        container = self._team()
        events: list[tuple[str, dict]] = []
        container.event_sink = lambda t, d: events.append((t, d))
        update = self._node('extension == "apk"', container)(
            {"file_hash": "abc", "file_name": "evil.exe", "platform": "windows"}
        )
        assert update == {
            "stage_results": {
                "apk": {
                    "ran": False,
                    "reason": 'condition not met: extension == "apk"',
                    "claim_count": 0,
                    "technique_ids": [],
                    "finding_count": 0,
                    "agents": [],
                    "failure": False,
                    "kind": "analysis",
                    "mode": "sequential",
                    "duration_ms": 0,
                }
            }
        }
        assert (
            "stage_skipped",
            {"stage": "apk", "kind": "analysis", "reason": 'condition not met: extension == "apk"'},
        ) in events

    def test_the_same_node_runs_when_the_condition_holds(self) -> None:
        container = self._team()
        update = self._node('extension == "apk"', container)(
            {"file_hash": "abc", "file_name": "evil.apk", "platform": "android"}
        )
        assert update["stage_results"]["apk"]["ran"] is True
        assert update["reports"]["apkscan"].startswith("MOCK")

    def test_the_rollup_names_every_stage_including_the_one_that_declined(self) -> None:
        container = self._team()
        state = {
            "stage_results": {
                "triage": {"ran": True, "agents": ["static"], "duration_ms": 12},
                "apk": {"ran": False, "reason": "condition not met", "agents": []},
            }
        }
        rows = stage_rollup(container, state)  # type: ignore[arg-type]
        assert [(r["key"], r["kind"], r["ran"]) for r in rows] == [
            ("triage", "analysis", True),
            ("apk", "analysis", False),
            ("verdict", "verdict", False),
        ]
        assert rows[1]["reason"] == "condition not met"
        # A stage nothing reported is not the same finding as a skipped one.
        assert rows[2]["reason"] == "stage did not report"
        assert rows[2]["agents"] == ["judge"]


class TestTheConditionContext:
    def test_it_is_built_from_the_state_the_nodes_read(self) -> None:
        ctx = stage_context(
            {
                "file_hash": "abc",
                "file_name": "evil.APK",
                "file_type": "Android package",
                "platform": "android",
                "sandbox_report": {
                    "target": {"size": 4096, "type": "application/vnd.android.package-archive"},
                    "network": {"dns": [{"request": "c2.example"}]},
                },
            }  # type: ignore[arg-type]
        )
        assert ctx.extension == "apk"
        assert ctx.platform == "android"
        assert ctx.size == 4096
        assert ctx.mime == "application/vnd.android.package-archive"
        assert ctx.has_pcap is True
        assert ctx.has_sandbox_report is True

    def test_a_run_with_no_sandbox_report_says_so_rather_than_guessing(self) -> None:
        ctx = stage_context({"file_hash": "abc", "file_name": "x"})  # type: ignore[arg-type]
        assert ctx.has_sandbox_report is False
        assert ctx.has_pcap is False
        assert ctx.size == 0


class TestTheRunRecordsWhatEachStageDid:
    """``stage_results`` is written by every node and read by the report.

    The reducer is the part worth pinning: a parallel stage is several nodes
    and each of them writes the stage it belongs to, so a shallow merge would
    keep whichever agent LangGraph finished last and lose the rest.
    """

    def test_two_agents_of_one_stage_add_up_rather_than_overwrite(self) -> None:
        from maljan.pipeline.state import _merge_stage_results

        left = {
            "wide": {
                "ran": True,
                "reason": "",
                "claim_count": 2,
                "technique_ids": ["T1055"],
                "finding_count": 0,
                "agents": ["static"],
                "kind": "analysis",
                "duration_ms": 100,
            }
        }
        right = {
            "wide": {
                "ran": True,
                "reason": "",
                "claim_count": 3,
                "technique_ids": ["T1055", "T1071"],
                "finding_count": 1,
                "agents": ["network"],
                "kind": "analysis",
                "duration_ms": 250,
            }
        }
        merged = _merge_stage_results(left, right)["wide"]
        assert merged["claim_count"] == 5
        assert merged["finding_count"] == 1
        assert merged["duration_ms"] == 350
        assert merged["agents"] == ["static", "network"]
        assert merged["technique_ids"] == ["T1055", "T1071"]

    def test_a_stage_that_ran_anywhere_counts_as_having_run(self) -> None:
        from maljan.pipeline.state import _merge_stage_results

        merged = _merge_stage_results(
            {"wide": {"ran": False, "reason": "no data for this agent"}},
            {"wide": {"ran": True}},
        )
        assert merged["wide"]["ran"] is True

    def test_a_stage_nothing_wrote_before_is_taken_as_it_arrives(self) -> None:
        from maljan.pipeline.state import _merge_stage_results

        merged = _merge_stage_results({}, {"deep": {"ran": True, "agents": ["x"]}})
        assert merged == {"deep": {"ran": True, "agents": ["x"]}}


class TestTheConsoleEvents:
    def _events(self, when: str, state: dict[str, Any]) -> list[tuple[str, dict]]:
        stages = [
            {"key": "triage", "kind": "analysis", "agents": ["static"], "when": when},
            {"key": "verdict", "kind": "verdict", "agents": ["judge"], "depends_on": ["triage"]},
        ]
        container = _container(stages)
        events: list[tuple[str, dict]] = []
        container.event_sink = lambda t, d: events.append((t, d))
        stage = container.active_profile().stage("triage")
        make_stage_agent_node(stage, "static", container)(state)  # type: ignore[arg-type]
        return events

    def test_a_stage_that_runs_announces_itself(self) -> None:
        events = self._events("", {"file_hash": "abc", "file_name": "x.exe"})
        assert (
            "stage_started",
            {"stage": "triage", "kind": "analysis", "agents": ["static"]},
        ) in events
        assert not [e for e in events if e[0] == "stage_skipped"]

    def test_a_stage_that_declines_announces_the_reason(self) -> None:
        events = self._events('platform == "linux"', {"file_hash": "abc", "platform": "windows"})
        ((kind, payload),) = [e for e in events if e[0] == "stage_skipped"]
        assert kind == "stage_skipped"
        assert payload["stage"] == "triage"
        assert payload["reason"] == 'condition not met: platform == "linux"'
        assert not [e for e in events if e[0] == "stage_started"]


class TestTheBuilderIsStillTheBackstop:
    """The settings model refuses a fan-out debate; the builder refuses it too.

    A stored document can reach the builder without passing through the model
    that would have caught it — an import from an older export, a row written
    by hand — and a graph that silently routes a debate to one of two stages is
    worse than one that will not build.
    """

    def test_a_debate_feeding_two_nodes_will_not_build(self) -> None:
        import pytest

        from maljan.core.config import ProfileDefinition

        stages = [
            {"key": "a", "kind": "analysis", "agents": ["static"]},
            {"key": "d", "kind": "debate", "depends_on": ["a"]},
            {
                "key": "wide",
                "kind": "analysis",
                "agents": ["dynamic", "network"],
                "mode": "parallel",
                "depends_on": ["d"],
            },
            {"key": "v", "kind": "verdict", "agents": ["judge"], "depends_on": ["wide"]},
        ]
        container = _container(
            [
                {"key": "a", "kind": "analysis", "agents": ["static"]},
                {"key": "d", "kind": "debate", "depends_on": ["a"]},
                {"key": "v", "kind": "verdict", "agents": ["judge"], "depends_on": ["d"]},
            ]
        )
        # Past the model's own refusal, which is what an out-of-band document
        # does: build the profile without validation and hand it to the builder.
        unchecked = ProfileDefinition.model_construct(
            label="Team",
            stages=[_STAGE_MODEL.model_validate(s) for s in stages],
            analysts=[],
        )
        container.active_profile = lambda: unchecked  # type: ignore[method-assign]
        with pytest.raises(RuntimeError, match="a debate hands over to exactly one stage"):
            build_graph(container)

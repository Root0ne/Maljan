"""Every stage says when it started and when it ended, once each, in order.

The console draws a run from these. A stage that announces itself three times
because it has three analysts, or one that never announces an end because the
node that would have done it was dropped with the report stage, is a live view
an operator cannot read.

The whole graph is run here in mock mode rather than one node at a time,
because what is being pinned is the *wiring*: which node the builder made
responsible for closing which stage.
"""

from __future__ import annotations

import asyncio
from typing import Any

from maljan.core.config import Settings
from maljan.core.container import ServiceContainer
from maljan.pipeline.builder import build_graph


def _state(**over: Any) -> dict[str, Any]:
    state: dict[str, Any] = {
        "file_hash": "abc123",
        "file_name": "evil.exe",
        "sample_path": None,
        "sandbox_report": None,
        "file_type": None,
        "platform": "windows",
        "static_sample_path": None,
        "static_sample_paths": {},
        "reports": {},
        "revised_reports": {},
        "isr_reports": {},
        "discussion_history": [],
        "sycophancy_detected": False,
        "confidence_history": [],
        "iteration_count": 0,
        "is_consensus": False,
        "final_decision": None,
        "judge_report": None,
        "stix_output": None,
        "run_summary": None,
        "stage_results": {},
    }
    state.update(over)
    return state


def _run(settings: Settings, **over: Any) -> tuple[list[tuple[str, dict]], dict[str, Any]]:
    container = ServiceContainer(settings, mock=True)
    events: list[tuple[str, dict]] = []
    container.event_sink = lambda kind, payload: events.append((kind, payload))
    final = asyncio.run(build_graph(container).ainvoke(_state(**over)))
    return events, final


def _stage_events(events: list[tuple[str, dict]]) -> list[tuple[str, str]]:
    return [(kind, payload["stage"]) for kind, payload in events if kind.startswith("stage_")]


class TestTheDefaultTeam:
    """The triage pack leads and, with no sample on disk here, declines and says so."""

    def test_each_stage_starts_once_and_ends_once_in_order(self) -> None:
        events, _ = _run(Settings(_env_file=None))
        assert _stage_events(events) == [
            ("stage_skipped", "triage_pack"),
            ("stage_started", "analysis"),
            ("stage_finished", "analysis"),
            ("stage_started", "debate"),
            ("stage_finished", "debate"),
            ("stage_started", "verdict"),
            ("stage_finished", "verdict"),
            ("stage_started", "report"),
            ("stage_finished", "report"),
        ]

    def test_a_three_analyst_stage_announces_itself_once_not_three_times(self) -> None:
        events, _ = _run(Settings(_env_file=None))
        started = [p for k, p in events if k == "stage_started" and p["stage"] == "analysis"]
        assert len(started) == 1
        assert started[0]["agents"] == ["static", "dynamic", "network"]

    def test_the_parallel_team_terminates_every_stage_too(self) -> None:
        """A fan-out has no last node of its own; the next stage closes it."""
        events, _ = _run(Settings(_env_file=None, llm={"parallel_analysts": True}))
        assert _stage_events(events) == [
            ("stage_skipped", "triage_pack"),
            ("stage_started", "analysis"),
            ("stage_finished", "analysis"),
            ("stage_started", "debate"),
            ("stage_finished", "debate"),
            ("stage_started", "verdict"),
            ("stage_finished", "verdict"),
            ("stage_started", "report"),
            ("stage_finished", "report"),
        ]

    def test_reporting_disabled_still_terminates_every_stage_that_runs(self) -> None:
        """The report node used to be the only source of ``stage_finished``.

        With reporting off it is dropped from the plan, so the live view got
        starts with no ends for the whole run.
        """
        settings = Settings(_env_file=None)
        settings.reporting.enabled = False
        events, _ = _run(settings)
        assert _stage_events(events) == [
            ("stage_skipped", "triage_pack"),
            ("stage_started", "analysis"),
            ("stage_finished", "analysis"),
            ("stage_started", "debate"),
            ("stage_finished", "debate"),
            ("stage_started", "verdict"),
            ("stage_finished", "verdict"),
        ]

    def test_a_finish_carries_the_stage_s_duration_and_members(self) -> None:
        events, _ = _run(Settings(_env_file=None))
        (finished,) = [p for k, p in events if k == "stage_finished" and p["stage"] == "analysis"]
        assert finished["kind"] == "analysis"
        assert finished["ran"] is True
        assert finished["agents"] == ["static", "dynamic", "network"]
        assert isinstance(finished["duration_ms"], int)


def _conditional_team(when: str) -> Settings:
    return Settings(
        _env_file=None,
        agents={
            "definitions": {"apkscan": {"role": "generic", "prompt": "unpack it"}},
            "profiles": {
                "team": {
                    "label": "Team",
                    "stages": [
                        {"key": "triage", "kind": "analysis", "agents": ["static"]},
                        {
                            "key": "apk",
                            "kind": "analysis",
                            "agents": ["apkscan"],
                            "depends_on": ["triage"],
                            "when": when,
                        },
                        {
                            "key": "verdict",
                            "kind": "verdict",
                            "agents": ["judge"],
                            "depends_on": ["apk"],
                        },
                    ],
                }
            },
            "profile": "team",
        },
    )


class TestAStageThatDeclines:
    def test_it_is_announced_skipped_once_and_never_finished(self) -> None:
        events, _ = _run(_conditional_team('extension == "apk"'))
        assert _stage_events(events) == [
            ("stage_started", "triage"),
            ("stage_finished", "triage"),
            ("stage_skipped", "apk"),
            ("stage_started", "verdict"),
            ("stage_finished", "verdict"),
        ]
        (skipped,) = [p for k, p in events if k == "stage_skipped"]
        assert skipped["reason"] == 'condition not met: extension == "apk"'

    def test_the_same_team_runs_the_stage_when_the_condition_holds(self) -> None:
        events, _ = _run(_conditional_team('extension == "apk"'), file_name="evil.apk")
        assert ("stage_started", "apk") in _stage_events(events)
        assert ("stage_skipped", "apk") not in _stage_events(events)


class TestADebateWithNothingUpstreamThatRan:
    """Finding 8: the agents of a skipped stage must not reach the debate."""

    def _team(self) -> Settings:
        return Settings(
            _env_file=None,
            agents={
                "profiles": {
                    "team": {
                        "label": "Team",
                        "stages": [
                            {
                                "key": "triage",
                                "kind": "analysis",
                                "agents": ["static", "network"],
                                "when": 'platform == "linux"',
                            },
                            {"key": "debate", "kind": "debate", "depends_on": ["triage"]},
                            {
                                "key": "verdict",
                                "kind": "verdict",
                                "agents": ["judge"],
                                "depends_on": ["debate"],
                            },
                        ],
                    }
                },
                "profile": "team",
            },
        )

    def test_the_debate_skips_itself_with_a_reason(self) -> None:
        events, final = _run(self._team())
        assert _stage_events(events) == [
            ("stage_skipped", "triage"),
            ("stage_skipped", "debate"),
            ("stage_started", "verdict"),
            ("stage_finished", "verdict"),
        ]
        reasons = {p["stage"]: p["reason"] for k, p in events if k == "stage_skipped"}
        assert reasons["debate"] == "no analysis stage upstream of it ran"
        assert final["stage_results"]["debate"]["ran"] is False

    def test_it_hands_over_rather_than_looping(self) -> None:
        _, final = _run(self._team())
        # Nothing ran, so no agreement was measured; the router hands over on
        # that rather than on a consensus nobody reached.
        assert final["consensus_applicable"] is False
        assert final["is_consensus"] is None
        assert final["final_decision"] is not None


class TestALedgerEntrySaysWhichStageMadeTheCall:
    """``LedgerEntry.stage`` was the constant ``"analysis"`` for two producers.

    The analyst nodes set it from their stage; the judge's mediation and
    verdict calls, and the report's own capa/YARA rows, still said "analysis",
    which sends a reader of the evidence endpoint looking for an analyst that
    never made the call.
    """

    def test_the_judge_records_the_stage_the_node_put_it_in(self) -> None:
        from maljan.agents.evidence_recorder import EvidenceRecorder
        from maljan.agents.judge_agent import JudgeAgent

        judge = JudgeAgent.__new__(JudgeAgent)
        # The default, for a judge nobody staged — a script, a test, the CLI.
        assert getattr(judge, "pipeline_stage", "analysis") == "analysis"

        judge.pipeline_stage = "verdict"
        recorder = EvidenceRecorder("judge", stage=str(judge.pipeline_stage))
        assert recorder.stage == "verdict"

    def test_the_verdict_node_stages_its_judge_before_it_rules(self) -> None:
        """Set before anything else the node does, so a verdict that fails
        half way still has its tool calls filed under the verdict stage."""
        from unittest.mock import MagicMock

        from maljan.pipeline.nodes import make_judge_node

        settings = Settings(_env_file=None)
        stage = settings.agents.profiles["default"].stage("verdict")
        judge = MagicMock()
        container = MagicMock()
        container.is_mock = False
        container.event_sink = None
        container.config = settings
        container.active_profile.return_value = settings.agents.profiles["default"]
        container.get_judge_agent.return_value = judge
        container.drain_all_judge_evidence.return_value = []
        # The verdict itself is not what is under test: whatever it does, the
        # judge has already been told which stage it is running as.
        container.get_evidence_counter.side_effect = RuntimeError("no verdict here")

        out = asyncio.run(make_judge_node(container, stage=stage)(_state()))
        assert judge.pipeline_stage == "verdict"
        assert out["final_decision"] == "Suspicious"

    def test_the_debate_node_stages_its_mediator_as_the_debate(self) -> None:
        from unittest.mock import MagicMock

        from maljan.pipeline.nodes import make_negotiation_node

        settings = Settings(_env_file=None)
        stage = settings.agents.profiles["default"].stage("debate")
        judge = MagicMock()
        container = MagicMock()
        container.is_mock = False
        container.event_sink = None
        container.config = settings
        container.active_profile.return_value = settings.agents.profiles["default"]
        container.analyst_keys.return_value = ["static"]
        container.get_judge_agent.return_value = judge
        container.drain_all_judge_evidence.return_value = []

        asyncio.run(
            make_negotiation_node(container, stage=stage)(
                _state(stage_results={"analysis": {"ran": True, "agents": ["static"]}})
            )
        )
        assert judge.pipeline_stage == "debate"

    def test_the_report_s_own_rows_carry_the_report_stage(self) -> None:
        from maljan.providers.base import StaticEvidenceBundle
        from maljan.providers.static.capa_yara import ledger_entries
        from maljan.schemas.evidence import EvidenceCounter

        bundle = StaticEvidenceBundle(
            yara_matches=[{"rule": "ransom_note", "strings": [], "technique": "T1486"}]
        )
        (entry,) = ledger_entries(bundle, EvidenceCounter(), "report")
        assert entry.stage == "report"

    def test_those_rows_default_to_analysis_outside_a_staged_run(self) -> None:
        from maljan.providers.base import StaticEvidenceBundle
        from maljan.providers.static.capa_yara import ledger_entries
        from maljan.schemas.evidence import EvidenceCounter

        bundle = StaticEvidenceBundle(
            yara_matches=[{"rule": "ransom_note", "strings": [], "technique": "T1486"}]
        )
        (entry,) = ledger_entries(bundle, EvidenceCounter())
        assert entry.stage == "analysis"

    def test_an_analyst_s_own_entries_still_carry_their_stage(self) -> None:
        from maljan.agents.evidence_recorder import EvidenceRecorder

        assert EvidenceRecorder("static", stage="triage").stage == "triage"


class TestAStageNothingRunsAfter:
    """The two shapes with no node of their own to close them.

    ``topology._finisher`` gives a stage with a single terminal node — a
    sequential chain, a barrier, the judge, the report — that node as its
    finisher, and a stage with several gets the single node of the stage that
    follows. A stage nothing depends on has no such node, so every one of its
    own nodes is a finisher: a fan-out of three analysts announced the stage
    finished three times, and a debate that loops announced it once per node
    it left through. The console draws one row per stage from these events.
    """

    def _fan_out(self) -> Settings:
        return Settings(
            _env_file=None,
            agents={
                "profiles": {
                    "team": {
                        "label": "Team",
                        "stages": [
                            {
                                "key": "analysis",
                                "kind": "analysis",
                                "agents": ["static"],
                            },
                            {
                                "key": "verdict",
                                "kind": "verdict",
                                "agents": ["judge"],
                                "depends_on": ["analysis"],
                            },
                            {
                                "key": "sweep",
                                "kind": "analysis",
                                "mode": "parallel",
                                "agents": ["dynamic", "network"],
                                "depends_on": ["verdict"],
                            },
                        ],
                    }
                },
                "profile": "team",
            },
        )

    def test_a_terminal_fan_out_announces_its_end_exactly_once(self) -> None:
        events, _ = _run(self._fan_out())
        finished = [p for k, p in events if k == "stage_finished" and p["stage"] == "sweep"]
        assert len(finished) == 1
        assert finished[0]["agents"] == ["dynamic", "network"]

    def test_every_stage_of_that_team_is_announced_once(self) -> None:
        events, _ = _run(self._fan_out())
        assert _stage_events(events) == [
            ("stage_started", "analysis"),
            ("stage_finished", "analysis"),
            ("stage_started", "verdict"),
            ("stage_finished", "verdict"),
            ("stage_started", "sweep"),
            ("stage_finished", "sweep"),
        ]

    def _terminal_debate(self) -> Settings:
        return Settings(
            _env_file=None,
            agents={
                "profiles": {
                    "team": {
                        "label": "Team",
                        "stages": [
                            {
                                "key": "analysis",
                                "kind": "analysis",
                                "agents": ["static", "dynamic"],
                            },
                            {
                                "key": "verdict",
                                "kind": "verdict",
                                "agents": ["judge"],
                                "depends_on": ["analysis"],
                            },
                            {
                                "key": "debate",
                                "kind": "debate",
                                "depends_on": ["verdict"],
                            },
                        ],
                    }
                },
                "profile": "team",
            },
        )

    def test_a_terminal_debate_announces_its_end_exactly_once(self) -> None:
        events, _ = _run(self._terminal_debate())
        finished = [p for k, p in events if k == "stage_finished" and p["stage"] == "debate"]
        assert len(finished) == 1

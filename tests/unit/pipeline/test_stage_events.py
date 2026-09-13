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
    def test_each_stage_starts_once_and_ends_once_in_order(self) -> None:
        events, _ = _run(Settings(_env_file=None))
        assert _stage_events(events) == [
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
        assert final["is_consensus"] is True
        assert final["final_decision"] is not None

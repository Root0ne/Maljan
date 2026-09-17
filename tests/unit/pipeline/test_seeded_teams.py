"""The teams that ship: mobile and deep_static, built and run in mock mode.

A seeded team is a claim the product makes about itself, so what is pinned
here is that each one is a legal profile, that it builds a graph, and that its
conditional stages decline on the samples they are meant to decline on. A
condition that never fires is a stage nobody ever gets, and a condition that
always fires is a team with no shape.
"""

from __future__ import annotations

import asyncio
from typing import Any

from maljan.core.config import BUILTIN_PROFILES, Settings
from maljan.core.container import ServiceContainer
from maljan.pipeline.builder import build_graph


def _settings(profile: str) -> Settings:
    settings = Settings(_env_file=None)
    settings.agents.profile = profile
    return settings


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


def _run(profile: str, **over: Any) -> tuple[list[tuple[str, dict]], dict[str, Any]]:
    container = ServiceContainer(_settings(profile), mock=True)
    events: list[tuple[str, dict]] = []
    container.event_sink = lambda kind, payload: events.append((kind, payload))
    final = asyncio.run(build_graph(container).ainvoke(_state(**over)))
    return events, final


class TestTheSeededTeams:
    def test_they_are_seeded_as_built_ins(self) -> None:
        assert "mobile" in BUILTIN_PROFILES
        assert "deep_static" in BUILTIN_PROFILES
        profiles = Settings(_env_file=None).agents.profiles
        assert set(BUILTIN_PROFILES) <= set(profiles)

    def test_each_one_builds_a_graph(self) -> None:
        for profile in ("mobile", "deep_static"):
            container = ServiceContainer(_settings(profile), mock=True)
            nodes = set(build_graph(container).get_graph().nodes)
            assert "triage_analyst" in nodes
            assert "judge" in nodes
            assert "report" in nodes

    def test_their_agents_are_seeded_definitions(self) -> None:
        definitions = Settings(_env_file=None).agents.definitions
        for key in ("triage", "android_static", "reverser"):
            assert definitions[key].role == "generic"
            assert definitions[key].prompt

    def test_no_seeded_prompt_names_a_windows_artefact(self) -> None:
        """The prompts are format-neutral; the sample's own fragment is not.

        A seeded prompt that said "PE" or "registry" would put a Windows
        assumption in front of every APK the mobile team is for.
        """
        definitions = Settings(_env_file=None).agents.definitions
        forbidden = ("windows", "registry", "\bpe \b", ".exe", "dll")
        for key in ("triage", "android_static", "reverser"):
            prompt = (definitions[key].prompt or "").lower()
            for word in forbidden:
                assert word not in prompt, f"{key} prompt names {word!r}"


class TestTheMobileTeam:
    def test_the_android_stage_declines_on_a_pe(self) -> None:
        events, final = _run("mobile", file_name="evil.exe", file_type="pe")
        skipped = {p["stage"] for k, p in events if k == "stage_skipped"}
        assert "android_static" in skipped
        assert final["stage_results"]["android_static"]["ran"] is False
        assert 'file_type in ("apk", "dex")' in final["stage_results"]["android_static"]["reason"]

    def test_the_android_stage_runs_on_an_apk(self) -> None:
        events, _ = _run("mobile", file_name="app.apk", file_type="apk")
        started = {p["stage"] for k, p in events if k == "stage_started"}
        assert "android_static" in started

    def test_detonation_declines_when_no_sandbox_reported(self) -> None:
        _, final = _run("mobile", file_name="app.apk", file_type="apk")
        assert final["stage_results"]["dynamic"]["ran"] is False

    def test_a_declining_stage_does_not_stop_the_verdict(self) -> None:
        _, final = _run("mobile", file_name="evil.exe", file_type="pe")
        assert final["final_decision"] is not None

    def test_every_stage_of_it_is_announced_exactly_once(self) -> None:
        events, _ = _run("mobile", file_name="app.apk", file_type="apk")
        announced: dict[str, int] = {}
        for kind, payload in events:
            if kind.startswith("stage_"):
                announced[f"{kind}:{payload['stage']}"] = (
                    announced.get(f"{kind}:{payload['stage']}", 0) + 1
                )
        assert all(count == 1 for count in announced.values()), announced


class TestTheDeepStaticTeam:
    def test_the_network_stage_declines_without_a_capture_or_a_sandbox(self) -> None:
        _, final = _run("deep_static", file_name="evil.exe", file_type="pe")
        assert final["stage_results"]["network"]["ran"] is False

    def test_reversing_runs_after_the_static_stage_it_reads(self) -> None:
        events, final = _run("deep_static", file_name="evil.exe", file_type="pe")
        order = [p["stage"] for k, p in events if k == "stage_started"]
        assert order.index("static") < order.index("reversing")
        assert final["stage_results"]["reversing"]["ran"] is True

    def test_the_reverser_is_handed_the_static_stage_s_findings(self) -> None:
        profile = Settings(_env_file=None).agents.profiles["deep_static"]
        reversing = profile.stage("reversing")
        assert reversing is not None
        assert reversing.depends_on == ["static"]
        assert reversing.inject_upstream == "findings"

    def test_it_reaches_a_verdict_and_a_report(self) -> None:
        _, final = _run("deep_static", file_name="evil.exe", file_type="pe")
        assert final["final_decision"] is not None
        assert final["stage_results"]["report"]["ran"] is True


class TestTheTeamLeadTeam:
    def test_it_is_seeded_and_builds_one_analyst_node(self) -> None:
        assert "team_lead" in BUILTIN_PROFILES
        container = ServiceContainer(_settings("team_lead"), mock=True)
        nodes = set(build_graph(container).get_graph().nodes)
        assert "lead_analyst" in nodes
        assert "judge" in nodes and "report" in nodes
        assert not any(node.startswith(("static_", "dynamic_", "network_")) for node in nodes)

    def test_it_runs_end_to_end_in_mock_mode(self) -> None:
        events, final = _run("team_lead", file_name="evil.exe", file_type="pe")
        started = [p["stage"] for k, p in events if k == "stage_started"]
        assert started[0] == "lead"
        assert final["stage_results"]["lead"]["ran"] is True
        assert final["stage_results"]["lead"]["agents"] == ["lead"]
        assert final["final_decision"] is not None

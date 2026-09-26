"""``llm.parallel_analysts`` is auto, true or false, and a stage's own mode wins.

``auto`` decides per job from the models the analysts call: a hosted API runs
them in parallel; Ollama, or an OpenAI-compatible server at a local address,
runs them one after another unless its ``/props`` reported more than one slot.
Nothing here puts a request on the network: the slot count is noted the way
the window probe notes it, and every resolution is made with ``probe=False``.
"""

from __future__ import annotations

from typing import Any

import pytest

from maljan.core.config import Settings
from maljan.llm import context_window
from maljan.pipeline.analyst_mode import (
    AnalystMode,
    analyst_mode_of,
    mock_mode,
    resolve_analyst_mode,
    with_resolved_modes,
)

LOCAL = "http://127.0.0.1:8080/v1"


@pytest.fixture(autouse=True)
def _nothing_learned() -> Any:
    context_window.forget_learned_windows()
    yield
    context_window.forget_learned_windows()


def _settings(**llm: Any) -> Settings:
    return Settings(_env_file=None, llm=llm)


def _slots(endpoint: str, count: int) -> None:
    """What the window probe notes when a llama.cpp ``/props`` answers."""
    root = endpoint[: -len("/v1")] if endpoint.endswith("/v1") else endpoint
    context_window._note_slots(root + context_window.LLAMA_PROPS_PATH, count)


class TestTheSetting:
    def test_auto_is_the_default(self) -> None:
        assert Settings(_env_file=None).llm.parallel_analysts == "auto"

    @pytest.mark.parametrize(("stored", "read"), [(True, "true"), (False, "false")])
    def test_a_stored_boolean_keeps_its_meaning(self, stored: bool, read: str) -> None:
        assert _settings(parallel_analysts=stored).llm.parallel_analysts == read

    @pytest.mark.parametrize("value", ["auto", "true", "false", "TRUE"])
    def test_the_three_words_are_read(self, value: str) -> None:
        assert _settings(parallel_analysts=value).llm.parallel_analysts == value.lower()

    def test_anything_else_is_refused(self) -> None:
        with pytest.raises(ValueError):
            _settings(parallel_analysts="sometimes")


class TestTheResolution:
    def test_an_explicit_true_is_parallel_whatever_serves_the_model(self) -> None:
        mode = resolve_analyst_mode(
            _settings(parallel_analysts=True, provider="ollama"), ["static"], probe=False
        )
        assert mode.parallel is True
        assert mode.reason == "llm.parallel_analysts is true"

    def test_an_explicit_false_is_sequential_on_a_hosted_api(self) -> None:
        mode = resolve_analyst_mode(_settings(parallel_analysts=False), ["static"], probe=False)
        assert mode.parallel is False
        assert mode.setting == "false"

    def test_auto_on_a_hosted_api_is_parallel(self) -> None:
        mode = resolve_analyst_mode(
            _settings(openai={"base_url": "https://api.deepseek.com", "model": "deepseek-flash"}),
            ["static", "dynamic", "network"],
            probe=False,
        )
        assert mode.parallel is True
        assert mode.setting == "auto"
        assert "hosted API at https://api.deepseek.com" in mode.reason

    def test_auto_on_ollama_is_sequential(self) -> None:
        mode = resolve_analyst_mode(_settings(provider="ollama"), ["static"], probe=False)
        assert mode.parallel is False
        assert "Ollama" in mode.reason

    def test_auto_on_a_local_server_that_reported_no_slots_is_sequential(self) -> None:
        mode = resolve_analyst_mode(_settings(openai={"base_url": LOCAL}), ["static"], probe=False)
        assert mode.parallel is False
        assert "reported no slot count" in mode.reason

    def test_auto_on_a_local_server_with_one_slot_is_sequential(self) -> None:
        _slots(LOCAL, 1)
        mode = resolve_analyst_mode(_settings(openai={"base_url": LOCAL}), ["static"], probe=False)
        assert mode.parallel is False
        assert "reports one slot" in mode.reason

    def test_auto_on_a_local_server_with_several_slots_is_parallel(self) -> None:
        _slots(LOCAL, 4)
        mode = resolve_analyst_mode(_settings(openai={"base_url": LOCAL}), ["static"], probe=False)
        assert mode.parallel is True
        assert "reports 4 slots" in mode.reason

    def test_one_single_slot_model_makes_the_whole_job_sequential(self) -> None:
        settings = _settings(
            openai={"base_url": "https://api.deepseek.com"},
            agents={"network": {"provider": "openai", "model": "qwen", "base_url": LOCAL}},
        )
        mode = resolve_analyst_mode(settings, ["static", "network"], probe=False)
        assert mode.parallel is False
        assert "openai/qwen" in mode.reason

    def test_the_slot_count_is_read_from_the_props_answer(self) -> None:
        assert context_window.slots_from_llama_props({"total_slots": 3}) == 3
        assert context_window.slots_from_llama_props({"total_slots": True}) == 0
        assert context_window.slots_from_llama_props({}) == 0

    def test_a_mock_job_on_auto_runs_its_analysts_one_after_another(self) -> None:
        mode = mock_mode(Settings(_env_file=None))
        assert mode.parallel is False
        assert "mock run" in mode.reason
        assert mock_mode(_settings(parallel_analysts=True)).parallel is True


def _profile(stages: list[dict]) -> Any:
    settings = Settings(
        _env_file=None,
        agents={"profiles": {"team": {"label": "Team", "stages": stages}}, "profile": "team"},
    )
    return settings.agents.profiles["team"]


PARALLEL = AnalystMode(True, "auto", "resolved for the test")
SEQUENTIAL = AnalystMode(False, "auto", "resolved for the test")


class TestTheStageOverride:
    STAGES = [
        {"key": "first", "kind": "analysis", "agents": ["static", "dynamic"]},
        {
            "key": "second",
            "kind": "analysis",
            "agents": ["network", "triage"],
            "depends_on": ["first"],
            "mode": "sequential",
        },
        {"key": "verdict", "kind": "verdict", "agents": ["judge"], "depends_on": ["second"]},
        {"key": "report", "kind": "report", "agents": ["reporter"], "depends_on": ["verdict"]},
    ]

    def test_a_stage_with_no_mode_follows_the_job(self) -> None:
        profile = _profile(self.STAGES)
        assert with_resolved_modes(profile, PARALLEL).stage("first").mode == "parallel"
        assert with_resolved_modes(profile, SEQUENTIAL).stage("first").mode == "sequential"

    def test_a_stage_the_operator_set_keeps_its_mode(self) -> None:
        profile = _profile(self.STAGES)
        assert with_resolved_modes(profile, PARALLEL).stage("second").mode == "sequential"

    def test_the_stored_profile_is_not_changed(self) -> None:
        profile = _profile(self.STAGES)
        with_resolved_modes(profile, PARALLEL)
        assert profile.stage("first").mode is None

    def test_a_stage_a_debate_hands_over_to_stays_one_node(self) -> None:
        """A debate hands over to one node; two agents in parallel would be two."""
        profile = _profile(
            [
                {"key": "first", "kind": "analysis", "agents": ["static"]},
                {"key": "argue", "kind": "debate", "depends_on": ["first"]},
                {
                    "key": "after",
                    "kind": "analysis",
                    "agents": ["dynamic", "network"],
                    "depends_on": ["argue"],
                },
                {"key": "verdict", "kind": "verdict", "agents": ["judge"], "depends_on": ["after"]},
                {
                    "key": "report",
                    "kind": "report",
                    "agents": ["reporter"],
                    "depends_on": ["verdict"],
                },
            ]
        )
        resolved = with_resolved_modes(profile, PARALLEL)
        assert resolved.stage("first").mode == "parallel"
        assert resolved.stage("after").mode == "sequential"


class TestTheContainer:
    def test_the_job_s_mode_reaches_the_graph(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from maljan.core.container import ServiceContainer
        from maljan.pipeline.builder import build_graph

        for parallel in (False, True):
            container = ServiceContainer(Settings(_env_file=None), mock=True)
            monkeypatch.setattr(
                container, "analyst_mode", lambda p=parallel: PARALLEL if p else SEQUENTIAL
            )
            edges = {(e.source, e.target) for e in build_graph(container).get_graph().edges}
            fanned = {("triage_pack", f"{a}_analyst") for a in ("static", "dynamic", "network")}
            assert (fanned <= edges) is parallel
            assert analyst_mode_of(container).parallel is parallel

    def test_a_mock_container_resolves_once_and_says_why(self) -> None:
        from maljan.core.container import ServiceContainer

        container = ServiceContainer(Settings(_env_file=None), mock=True)
        first = container.analyst_mode()
        assert first is container.analyst_mode()
        assert first.parallel is False
        assert {s.mode for s in container.active_profile().stages if s.kind == "analysis"} == {
            "sequential"
        }

    def test_a_stand_in_container_is_read_from_its_settings(self) -> None:
        class _StandIn:
            config = _settings(parallel_analysts=True)

        assert analyst_mode_of(_StandIn()).parallel is True

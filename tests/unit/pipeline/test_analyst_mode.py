"""``llm.parallel_analysts`` is auto, true or false, and a stage's own mode wins.

``auto`` decides per job from the models the analysts call: a host that
resolves only to public addresses runs them in parallel; Ollama, or an
OpenAI-compatible server whose host is local (a literal, a name only a local
resolver answers, or a name that resolves to a local address), runs them one
after another unless its ``/props`` reported more than one slot; a host that
does not resolve runs them one after another. Nothing here puts a request on
the network: names resolve from a table, the slot count is noted the way the
window probe notes it, and every resolution is made with ``probe=False``.
"""

from __future__ import annotations

from typing import Any

import pytest

from maljan.core.config import Settings
from maljan.llm import context_window
from maljan.pipeline import analyst_mode as analyst_mode_module
from maljan.pipeline.analyst_mode import (
    AnalystMode,
    analyst_mode_of,
    mock_mode,
    resolve_analyst_mode,
    revision_mode,
    stage_modes,
    stage_sentences,
    with_resolved_modes,
)

LOCAL = "http://127.0.0.1:8080/v1"
DOCKER_HOST = "http://host.docker.internal:8080/v1"
COMPOSE = "http://llama:8080/v1"
HOSTED = "https://api.deepseek.com"
UNRESOLVABLE = "http://nowhere-known:8080/v1"

# What the names here resolve to: a compose service on a bridge network, and a
# vendor API. Anything else does not resolve.
RESOLVES = {"llama": ["172.18.0.5"], "api.deepseek.com": ["104.18.26.90", "2606:4700::6812:1a5a"]}


@pytest.fixture(autouse=True)
def _nothing_learned(monkeypatch: pytest.MonkeyPatch) -> Any:
    context_window.forget_learned_windows()
    monkeypatch.setattr(analyst_mode_module, "_addresses", lambda host: RESOLVES.get(host, []))
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

    def test_auto_on_a_host_that_resolves_to_public_addresses_is_parallel(self) -> None:
        mode = resolve_analyst_mode(
            _settings(openai={"base_url": HOSTED, "model": "deepseek-flash"}),
            ["static", "dynamic", "network"],
            probe=False,
        )
        assert mode.parallel is True
        assert mode.setting == "auto"
        assert "a hosted API (api.deepseek.com resolves only to public addresses)" in mode.reason

    def test_auto_on_the_docker_host_name_is_sequential(self) -> None:
        mode = resolve_analyst_mode(
            _settings(openai={"base_url": DOCKER_HOST}), ["static"], probe=False
        )
        assert mode.parallel is False
        assert "host.docker.internal is a name only a local resolver answers" in mode.reason
        assert "reported no slot count" in mode.reason

    def test_auto_on_the_docker_host_name_with_one_slot_is_sequential(self) -> None:
        _slots(DOCKER_HOST, 1)
        mode = resolve_analyst_mode(
            _settings(openai={"base_url": DOCKER_HOST}), ["static"], probe=False
        )
        assert mode.parallel is False
        assert "whose /props reports one slot" in mode.reason

    def test_auto_on_a_compose_name_that_resolves_to_a_private_address_is_sequential(
        self,
    ) -> None:
        mode = resolve_analyst_mode(
            _settings(openai={"base_url": COMPOSE}), ["static"], probe=False
        )
        assert mode.parallel is False
        assert "llama resolves to 172.18.0.5" in mode.reason

    def test_auto_on_a_multi_slot_compose_server_is_parallel(self) -> None:
        _slots(COMPOSE, 4)
        mode = resolve_analyst_mode(
            _settings(openai={"base_url": COMPOSE}), ["static"], probe=False
        )
        assert mode.parallel is True
        assert "whose /props reports 4 slots" in mode.reason

    def test_auto_on_a_name_that_does_not_resolve_is_sequential(self) -> None:
        mode = resolve_analyst_mode(
            _settings(openai={"base_url": UNRESOLVABLE}), ["static"], probe=False
        )
        assert mode.parallel is False
        assert "could not be told whether it is hosted" in mode.reason

    def test_a_shared_range_address_is_local(self) -> None:
        kind, fact = analyst_mode_module.locality("http://100.101.2.3:8080/v1")
        assert kind == "local" and "shared-range" in fact

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
            openai={"base_url": HOSTED},
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
        rows = {(r["stage"], r["round"]): r for r in stage_modes(profile, resolved, PARALLEL)}
        assert rows[("first", "analysis")] == {
            "stage": "first",
            "round": "analysis",
            "mode": "parallel",
            "from": "job",
        }
        assert rows[("after", "analysis")]["from"] == "debate handover"
        assert rows[("after", "analysis")]["mode"] == "sequential"


class TestWhatEachStageRan:
    STAGES = [
        {
            "key": "pinned",
            "kind": "analysis",
            "agents": ["static", "dynamic"],
            "mode": "sequential",
        },
        {"key": "argue", "kind": "debate", "depends_on": ["pinned"]},
        {"key": "verdict", "kind": "verdict", "agents": ["judge"], "depends_on": ["argue"]},
        {"key": "report", "kind": "report", "agents": ["reporter"], "depends_on": ["verdict"]},
    ]

    def test_a_pinned_stage_and_its_revision_round_are_recorded_as_they_ran(self) -> None:
        profile = _profile(self.STAGES)
        resolved = with_resolved_modes(profile, PARALLEL)
        rows = stage_modes(profile, resolved, PARALLEL)
        assert rows == (
            {"stage": "pinned", "round": "analysis", "mode": "sequential", "from": "stage"},
            {
                "stage": "argue",
                "round": "revision",
                "mode": "sequential",
                "from": "the stages it revises",
            },
        )
        assert stage_sentences(rows)[0] == (
            "Stage 'pinned' runs its agents one after another (set on the stage)."
        )

    def test_the_revision_round_follows_the_stages_it_revises(self) -> None:
        profile = _profile(self.STAGES)
        resolved = with_resolved_modes(profile, PARALLEL)
        assert revision_mode(resolved, resolved.stage("argue"), PARALLEL) == (
            False,
            "the stages it revises",
        )
        fanned = _profile([{**self.STAGES[0], "mode": None}, *self.STAGES[1:]])
        fanned = with_resolved_modes(fanned, PARALLEL)
        assert revision_mode(fanned, fanned.stage("argue"), PARALLEL)[0] is True
        # With no stage to read, the job's mode.
        assert revision_mode(fanned, None, SEQUENTIAL) == (False, "job")


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
        record = first.to_dict()
        assert record["stages"][0] == {
            "stage": "analysis",
            "round": "analysis",
            "mode": "sequential",
            "from": "job",
        }
        # The resolved profile is worked out once per job.
        assert container.active_profile() is container.active_profile()
        assert {s.mode for s in container.active_profile().stages if s.kind == "analysis"} == {
            "sequential"
        }

    def test_a_stand_in_container_is_read_from_its_settings(self) -> None:
        class _StandIn:
            config = _settings(parallel_analysts=True)

        assert analyst_mode_of(_StandIn()).parallel is True

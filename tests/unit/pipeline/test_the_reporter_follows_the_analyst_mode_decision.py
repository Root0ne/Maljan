"""The composer's sections run at once as far as the reporter's server serves them.

``llm.parallel_analysts`` already says whether a job's models serve concurrent
requests: ``true``/``false`` as set, ``auto`` decided from each model's
endpoint (a hosted API serves them; Ollama, or a local server that reported
one slot or none, does not). The report composer asks the same question of
the reporter's own models — its agent entry and fallbacks, or the global
judge model — and adds no setting of its own. Names resolve from a table here
and every resolution is made with ``probe=False``: nothing goes on the network.
"""

from __future__ import annotations

from typing import Any

import pytest

from maljan.core.config import Settings
from maljan.llm import context_window
from maljan.pipeline import analyst_mode as analyst_mode_module
from maljan.pipeline.analyst_mode import resolve_analyst_mode, resolve_reporter_mode

LOCAL = "http://127.0.0.1:8080/v1"
HOSTED = "https://api.deepseek.com"
RESOLVES = {"api.deepseek.com": ["104.18.26.90"]}


@pytest.fixture(autouse=True)
def _nothing_learned(monkeypatch: pytest.MonkeyPatch) -> Any:
    context_window.forget_learned_windows()
    monkeypatch.setattr(analyst_mode_module, "_addresses", lambda host: RESOLVES.get(host, []))
    yield
    context_window.forget_learned_windows()


def _settings(**llm: Any) -> Settings:
    return Settings(_env_file=None, llm=llm)


def _slots(endpoint: str, count: int) -> None:
    root = endpoint[: -len("/v1")] if endpoint.endswith("/v1") else endpoint
    context_window._note_slots(root + context_window.LLAMA_PROPS_PATH, count)


class TestTheReporterMode:
    def test_false_runs_them_one_after_another_on_a_hosted_api(self) -> None:
        mode = resolve_reporter_mode(
            _settings(parallel_analysts=False, openai={"base_url": HOSTED}), probe=False
        )
        assert mode.at_once == 1 and mode.parallel is False
        assert mode.reason == "llm.parallel_analysts is false"

    def test_true_on_a_hosted_api_runs_every_section_at_once(self) -> None:
        mode = resolve_reporter_mode(
            _settings(parallel_analysts=True, openai={"base_url": HOSTED}), probe=False
        )
        assert mode.at_once is None and mode.parallel is True

    def test_true_never_takes_a_single_slot_server_past_its_one_slot(self) -> None:
        _slots(LOCAL, 1)
        mode = resolve_reporter_mode(
            _settings(parallel_analysts=True, openai={"base_url": LOCAL}), probe=False
        )
        assert mode.at_once == 1
        assert "reports one slot" in mode.reason

    def test_true_on_ollama_runs_them_one_after_another(self) -> None:
        mode = resolve_reporter_mode(
            _settings(parallel_analysts=True, provider="ollama"), probe=False
        )
        assert mode.at_once == 1

    def test_auto_on_a_hosted_api_runs_the_sections_at_once(self) -> None:
        mode = resolve_reporter_mode(_settings(openai={"base_url": HOSTED}), probe=False)
        assert mode.parallel is True
        assert mode.at_once is None
        assert "api.deepseek.com resolves only to public addresses" in mode.reason

    def test_auto_on_a_single_slot_local_server_runs_them_one_after_another(self) -> None:
        _slots(LOCAL, 1)
        mode = resolve_reporter_mode(_settings(openai={"base_url": LOCAL}), probe=False)
        assert mode.parallel is False
        assert "reports one slot" in mode.reason

    def test_auto_on_a_multi_slot_local_server_runs_as_many_as_it_has_slots(self) -> None:
        _slots(LOCAL, 4)
        mode = resolve_reporter_mode(_settings(openai={"base_url": LOCAL}), probe=False)
        assert mode.parallel is True
        assert mode.at_once == 4

    def test_auto_on_ollama_runs_them_one_after_another(self) -> None:
        mode = resolve_reporter_mode(_settings(provider="ollama"), probe=False)
        assert mode.parallel is False
        assert "Ollama" in mode.reason

    def test_the_reporter_s_own_model_decides_not_the_analysts(self) -> None:
        settings = _settings(
            openai={"base_url": HOSTED},
            agents={"reporter": {"provider": "openai", "model": "qwen", "base_url": LOCAL}},
        )
        assert resolve_analyst_mode(settings, ["static"], probe=False).parallel is True
        mode = resolve_reporter_mode(settings, probe=False)
        assert mode.parallel is False
        assert "127.0.0.1" in mode.reason

    def test_settings_that_cannot_be_read_run_them_one_after_another(self) -> None:
        mode = resolve_reporter_mode(object(), probe=False)
        assert mode.parallel is False


class _Composer:
    """Records how the report node asks for the sections."""

    def __init__(self) -> None:
        from maljan.pipeline.validation import ValidationTally

        self.llm = None
        self.validation_tally = ValidationTally()
        self.degradations: list[str] = []
        self.asked: list[tuple[bool, Any]] = []

    async def compose(self, report: Any, isr_reports: Any = None, **kwargs: Any) -> None:
        self.asked.append((kwargs["concurrent"], kwargs["at_once"]))


class TestTheReportNodeAsks:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("at_once", [None, 1, 2])
    async def test_the_node_passes_the_reporter_s_mode_to_the_composer(
        self, at_once: int | None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from unittest.mock import MagicMock

        from maljan.pipeline.analyst_mode import ReporterMode

        monkeypatch.setattr(
            analyst_mode_module,
            "resolve_reporter_mode",
            lambda settings: ReporterMode(at_once, "auto", "a stated reason"),
        )

        from maljan.pipeline.nodes import make_report_node
        from tests.stages import paper_profile
        from tests.unit.pipeline.test_what_is_served_is_the_final_report import _state

        composer = _Composer()
        fake = MagicMock()
        fake.agent_registry.list_agents.return_value = ["static"]
        fake.analyst_keys.return_value = ["static"]
        fake.agent_role.side_effect = lambda n: n
        fake.is_mock = False
        fake.config.reporting.enabled = True
        fake.config.llm.parallel_analysts = "auto"
        fake.config.negotiation.max_iterations = 3
        fake.active_profile.return_value = paper_profile(["static"], parallel=False)
        fake.get_narrative_agent.return_value = None
        fake.get_report_composer.return_value = composer
        fake.get_static_provider.return_value.capabilities.provides_evidence = False
        stage = next(step for step in fake.active_profile().stages if step.kind == "report")

        await make_report_node(fake, stage=stage, announces=False)(_state())  # type: ignore[arg-type]

        assert composer.asked == [(at_once != 1, at_once)]

"""The mediator and the function summariser each read an ``llm.agents`` entry of their own.

``llm.agents.mediator`` decides the model the negotiation mediator calls and
``llm.agents.summarizer`` the one the function summariser calls, through the
per-agent path every other entry takes: provider, model, endpoint,
temperature, fallbacks and a per-model effort. Everything that follows an
agent's model follows theirs — the output cap and its log line, the label the
ledger records each call under, the build line. With no entry each runs on the
global expert model as before (``test_the_mediator_and_summarizer_send_what_they_sent``),
and a judge entry does not move the mediator.
"""

from __future__ import annotations

import logging
from typing import Any

import pytest

from .provider_bodies import _history, _payload
from .role_entry_bodies import (
    container,
    deepseek_settings,
    mediator_model,
    summarizer_model,
)

LOCAL = "http://127.0.0.1:9/v1"
# The global expert model of ``deepseek_settings``, as a ledger row names it.
EXPERT_LABEL = "openai/deepseek-flash @ https://api.deepseek.com"


def _body(model: Any) -> dict[str, Any]:
    return dict(_payload(model, _history()))


@pytest.fixture
def lines(caplog: pytest.LogCaptureFixture) -> Any:
    from maljan.core.logger import logger

    logger.addHandler(caplog.handler)
    caplog.set_level(logging.DEBUG)
    yield lambda: [r.getMessage() for r in caplog.records]
    logger.removeHandler(caplog.handler)


class TestTheMediatorsEntry:
    def test_its_entry_decides_its_model_and_its_effort(self) -> None:
        settings = deepseek_settings(
            mediator={"provider": "openai", "model": "deepseek-reasoner", "effort": "high"}
        )

        body = _body(mediator_model(settings))

        assert body["model"] == "deepseek-reasoner"
        assert body["reasoning_effort"] == "high"

    def test_with_no_entry_it_inherits_the_global_effort_and_not_the_judges(self) -> None:
        body = _body(mediator_model(deepseek_settings()))

        assert body["model"] == "deepseek-flash"
        assert body["reasoning_effort"] == "max"

    def test_its_fallbacks_are_built_and_named(self) -> None:
        settings = deepseek_settings(
            mediator={
                "provider": "openai",
                "model": "deepseek-reasoner",
                "fallbacks": [{"provider": "openai", "model": "deepseek-pro", "effort": "low"}],
            }
        )

        llm = mediator_model(settings)

        assert [m.model_name for m in llm.models] == ["deepseek-reasoner", "deepseek-pro"]
        assert _body(llm.models[1])["reasoning_effort"] == "low"

    def test_its_output_cap_is_derived_from_its_own_model(self, lines: Any) -> None:
        from maljan.llm.context_window import output_cap_for

        settings = deepseek_settings(
            mediator={"provider": "openai", "model": "local-model", "base_url": LOCAL}
        )
        cap = output_cap_for(settings, "expert_max_tokens", "mediator", probe=False)

        body = _body(mediator_model(settings))

        assert body["max_completion_tokens"] == cap.tokens
        assert f"Output cap for mediator: {cap.sentence}." in lines()

    def test_its_calls_are_recorded_under_its_own_model(self) -> None:
        from maljan.core.model_assignments import model_label_for

        settings = deepseek_settings(
            mediator={"provider": "openai", "model": "local-model", "base_url": LOCAL}
        )

        judge = container(settings).get_judge_agent(role="expert")

        assert judge._model_label() == model_label_for(settings, "mediator")
        assert judge._model_label() == "openai/local-model @ http://127.0.0.1:9"

    def test_with_no_entry_its_calls_are_recorded_under_the_expert_model(self) -> None:
        judge = container(deepseek_settings()).get_judge_agent(role="expert")

        assert judge._model_label() == EXPERT_LABEL

    def test_the_build_line_names_its_entry_and_its_effort(self, lines: Any) -> None:
        mediator_model(
            deepseek_settings(
                mediator={"provider": "openai", "model": "deepseek-reasoner", "effort": "high"}
            )
        )

        built = [line for line in lines() if "Building" in line]
        assert "Building dedicated LLM for agent 'mediator': openai/deepseek-reasoner" in built[-1]
        assert "effort=high from llm.agents.mediator.effort" in built[-1]

    def test_with_no_entry_the_build_line_is_the_expert_roles(self, lines: Any) -> None:
        mediator_model(deepseek_settings())

        built = [line for line in lines() if "Building" in line]
        assert built[-1].startswith("Building openai/deepseek-flash (role=expert, temp=0.1")


class TestTheRunsWindow:
    """A role with an entry of its own is one of the models the run's window is learned for."""

    def _agents(self, settings: Any, monkeypatch: pytest.MonkeyPatch) -> list[str]:
        from maljan.llm import context_window

        asked: list[list[str]] = []
        real = context_window.budget_for_settings

        def _budget(cfg: Any, agents: list[str], **kwargs: Any) -> Any:
            asked.append(list(agents))
            return real(cfg, agents, **kwargs)

        monkeypatch.setattr(context_window, "budget_for_settings", _budget)
        container(settings).get_context_budget()
        return asked[0]

    def test_a_mediator_entry_is_asked_about(self, monkeypatch: pytest.MonkeyPatch) -> None:
        settings = deepseek_settings(mediator={"provider": "openai", "model": "deepseek-lite"})

        assert "mediator" in self._agents(settings, monkeypatch)

    def test_with_no_entry_the_run_asks_what_it_asked(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = deepseek_settings()
        settings.preprocessing.use_function_summarizer = True

        assert self._agents(settings, monkeypatch) == ["static", "dynamic", "network", "judge"]


class TestTheSummarizersEntry:
    def test_its_entry_decides_its_model_and_its_effort(self) -> None:
        settings = deepseek_settings(
            summarizer={"provider": "openai", "model": "deepseek-lite", "effort": "low"}
        )

        body = _body(summarizer_model(settings))

        assert body["model"] == "deepseek-lite"
        assert body["reasoning_effort"] == "low"

    def test_its_body_carries_no_argument_a_provider_does_not_read(self) -> None:
        for settings in (
            deepseek_settings(),
            deepseek_settings(summarizer={"provider": "openai", "model": "deepseek-lite"}),
        ):
            body = _body(summarizer_model(settings))
            assert "provider_override" not in body
            assert "model_override" not in body

    def test_an_entry_is_built_with_no_output_cap_as_the_role_always_was(self) -> None:
        settings = deepseek_settings(summarizer={"provider": "openai", "model": "deepseek-lite"})

        body = _body(summarizer_model(settings))

        assert "max_completion_tokens" not in body
        assert "max_tokens" not in body.get("extra_body", {})

    def test_its_label_is_the_model_it_calls(self) -> None:
        plain = deepseek_settings()
        own = deepseek_settings(
            summarizer={"provider": "openai", "model": "local-model", "base_url": LOCAL}
        )

        assert container(plain)._summarizer_model_label() == EXPERT_LABEL
        assert container(own)._summarizer_model_label() == "openai/local-model @ http://127.0.0.1:9"

    def test_the_line_it_starts_with_names_the_model_it_calls(self, lines: Any) -> None:
        settings = deepseek_settings()
        settings.preprocessing.use_function_summarizer = True

        container(settings).get_function_summarizer()

        said = [line for line in lines() if line.startswith("FunctionSummarizer initialized")]
        assert set(said) == {f"FunctionSummarizer initialized ({EXPERT_LABEL}, max_words=150)."}

    def test_the_build_line_names_its_entry(self, lines: Any) -> None:
        summarizer_model(
            deepseek_settings(summarizer={"provider": "openai", "model": "deepseek-lite"})
        )

        built = [line for line in lines() if "Building" in line]
        assert "Building dedicated LLM for agent 'summarizer': openai/deepseek-lite" in built[-1]
        assert "effort=max from llm.openai.reasoning_effort" in built[-1]


class TestTheRetiredSummarizerSettings:
    def test_the_settings_no_longer_carry_them(self) -> None:
        from maljan.core.config import PreprocessingConfig
        from maljan.core.settings_annotations import ANNOTATIONS

        for name in ("summarizer_provider", "summarizer_model"):
            assert name not in PreprocessingConfig.model_fields
            assert f"preprocessing.{name}" not in ANNOTATIONS

    def test_a_stored_value_is_ignored_when_the_settings_are_built(self) -> None:
        from maljan.core.settings_overrides import build_settings

        settings = build_settings(
            {
                "preprocessing.summarizer_provider": "openai",
                "preprocessing.summarizer_model": "gpt-x",
                "preprocessing.summarizer_max_words": 90,
            }
        )

        assert settings.preprocessing.summarizer_max_words == 90
        assert "summarizer" not in settings.llm.agents

"""A report section's output budget is the model's reply room, not a constant.

A fixed 900 tokens dropped a section of a live report: the model reasoned past
it and the answer was cut. The budget is now what an analyst's reply is given
on the same model — the deployment's generation cap, at most a quarter of the
context window that model serves — and the run summary says how it was
reached. An operator's own positive value is used as it always was.
"""

from __future__ import annotations

import inspect
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from langchain_core.language_models.fake_chat_models import FakeMessagesListChatModel

from maljan.analysis.run_summary import generation_lines
from maljan.core.config import Settings
from maljan.core.container import ServiceContainer
from maljan.llm.context_window import WindowFact
from maljan.llm.generation_rate import GenerationRates
from maljan.reporting.composer import ReportComposer


def _composer(window: int, **llm: int) -> Any:
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    settings.llm.provider = "openai"
    settings.reporting.composer_enabled = True
    for name, value in llm.items():
        setattr(settings.llm, name, value)
    container = ServiceContainer(settings, mock=False)
    registry = MagicMock()
    registry.build_model_for_agent.return_value = FakeMessagesListChatModel(responses=[])
    container._llm_registry = registry  # type: ignore[assignment]
    fact = WindowFact(window, "probed", "the server's /props")
    with patch("maljan.llm.context_window.learn_window", return_value=fact):
        composer = container.get_report_composer()
    built = registry.build_model_for_agent.call_args.kwargs["max_tokens_for"]("openai")
    return composer, built


class TestTheDefault:
    def test_the_setting_ships_at_zero(self) -> None:
        assert Settings(_env_file=None).reporting.composer_section_max_tokens == 0  # type: ignore[call-arg]

    def test_the_composer_carries_no_fixed_budget(self) -> None:
        default = inspect.signature(ReportComposer).parameters["section_max_tokens"].default
        assert default == 0


class TestTheDerivation:
    def test_a_large_window_gives_the_generation_cap(self) -> None:
        composer, built = _composer(32768, judge_max_tokens=8192, expert_max_tokens=8192)

        assert composer.output_cap == 8192
        assert built == 8192

    def test_a_small_window_gives_a_quarter_of_it(self) -> None:
        composer, built = _composer(16384, judge_max_tokens=8192, expert_max_tokens=8192)

        assert composer.output_cap == 4096
        assert built == 4096

    def test_the_larger_generation_cap_is_the_one_that_holds(self) -> None:
        composer, _built = _composer(131072, judge_max_tokens=4096, expert_max_tokens=12000)

        assert composer.output_cap == 12000

    def test_no_generation_cap_takes_the_default_reply_room(self) -> None:
        composer, _built = _composer(131072, judge_max_tokens=0, expert_max_tokens=0)

        assert composer.output_cap == 8192

    def test_the_derivation_is_said(self) -> None:
        composer, _built = _composer(16384, judge_max_tokens=8192, expert_max_tokens=8192)

        assert composer.budget_note.startswith("4096 tokens — ")
        assert "16384-token context window (probed)" in composer.budget_note
        assert "8192 tokens" in composer.budget_note

    def test_the_run_summary_prints_it_beside_the_wait(self) -> None:
        composer, _built = _composer(16384, judge_max_tokens=8192, expert_max_tokens=8192)
        rates = GenerationRates()
        rates.observe("model", 1000, 100.0, "test")
        rates.call_timeout(
            "composer:section", "model", 120, composer.output_cap, budget=composer.budget_note
        )

        lines = generation_lines(rates.snapshot())

        assert any(
            line.startswith("Output budget of `composer:section`: 4096 tokens") for line in lines
        )
        assert any("4096 tokens at 10.00 tokens/s" in line for line in lines)


class TestAnOperatorsOwnBudget:
    @pytest.mark.parametrize("thinking_off", [True, False])
    def test_a_positive_value_is_used_as_it_always_was(self, thinking_off: bool) -> None:
        settings = Settings(_env_file=None)  # type: ignore[call-arg]
        settings.llm.provider = "openai"
        settings.llm.openai.disable_thinking = thinking_off
        settings.llm.judge_max_tokens = 8192
        settings.reporting.composer_enabled = True
        settings.reporting.composer_section_max_tokens = 900
        container = ServiceContainer(settings, mock=False)
        registry = MagicMock()
        registry.build_model_for_agent.return_value = FakeMessagesListChatModel(responses=[])
        container._llm_registry = registry  # type: ignore[assignment]

        with patch("maljan.llm.context_window.learn_window") as learned:
            composer = container.get_report_composer()

        expected = 900 if thinking_off else 900 + 8192
        assert composer.output_cap == expected
        assert "composer_section_max_tokens is set to 900" in composer.budget_note
        learned.assert_not_called()

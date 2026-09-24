"""An analyst's and the judge's output cap: the operator's, or derived from the window.

``llm.expert_max_tokens`` and ``llm.judge_max_tokens`` shipped as a fixed
8,192 whatever the model served. They ship at 0 now, which derives each from
the window the agent's model serves: a quarter of it, with no fixed figure
above it, and the smaller of that and the model's own maximum output where its
provider declares one. The reply reserve and the composer's section budget
follow the same rule. A window nobody reported keeps the documented fallback
and says so. A value above 0 is the operator's and is used as set; the
derivation is printed in the run summary beside the timeouts it sizes.
"""

from __future__ import annotations

from maljan.core.config import LLMConfig, Settings
from maljan.llm import model_output_limits
from maljan.llm.context_window import (
    DEFAULT_REPLY_TOKENS,
    WindowFact,
    derived_reply,
    output_cap_for,
    reply_reserve_tokens,
)
from maljan.llm.generation_rate import GenerationRates


def _settings(window: int = 0, **caps: int) -> Settings:
    settings = Settings(llm=LLMConfig(provider="openai", **caps))
    settings.llm.openai.context_size = window
    return settings


class TestTheShippedDefault:
    def test_both_caps_ship_derived(self) -> None:
        assert LLMConfig().expert_max_tokens == 0
        assert LLMConfig().judge_max_tokens == 0


class TestTheDerivation:
    def test_a_quarter_of_the_window(self) -> None:
        cap = output_cap_for(_settings(16384), "expert_max_tokens", "static")

        assert cap.tokens == 4096
        assert "a quarter (4096) of the model's 16384-token context window" in cap.sentence

    def test_no_fixed_figure_bounds_it_from_above(self) -> None:
        cap = output_cap_for(_settings(131072), "judge_max_tokens", "judge", role="judge")

        assert cap.tokens == 32768

    def test_the_model_s_declared_maximum_output_bounds_it(self) -> None:
        model_output_limits.note_from_model_list(
            {"data": [{"id": "big-model", "top_provider": {"max_completion_tokens": 16000}}]},
            "big-model",
        )
        try:
            window = WindowFact(131072, "probed", "the served model list reported 131,072")
            tokens, said = derived_reply(window, 0, "big-model", "llm.judge_max_tokens")
        finally:
            model_output_limits.forget_learned()

        assert tokens == 16000
        assert "the model's declared maximum output of 16000" in said

    def test_an_unknown_window_keeps_the_documented_fallback_and_says_so(self) -> None:
        window = WindowFact(8192, "fallback", "nothing answered")

        tokens, said = derived_reply(window, 0, "", "llm.expert_max_tokens")

        assert tokens == DEFAULT_REPLY_TOKENS
        assert "the documented fallback: no window was learned" in said

    def test_the_reply_reserve_follows_the_same_rule(self) -> None:
        assert reply_reserve_tokens(131072) == 32768
        assert reply_reserve_tokens(131072, 8192) == 8192
        assert reply_reserve_tokens(131072, 0, 16000) == 16000

    def test_an_operator_value_is_used_as_set(self) -> None:
        cap = output_cap_for(_settings(16384, expert_max_tokens=6000), "expert_max_tokens")

        assert cap.tokens == 6000
        assert "llm.expert_max_tokens is set to 6000" in cap.sentence


class TestItIsPrinted:
    def test_the_generation_record_carries_each_cap_and_its_derivation(self) -> None:
        rates = GenerationRates()
        cap = output_cap_for(_settings(16384), "expert_max_tokens", "static")

        rates.note_output_cap("static", cap.tokens, cap.sentence)

        assert rates.snapshot()["output_caps"] == {
            "static": {"tokens": 4096, "derivation": cap.sentence}
        }

    def test_a_record_with_no_cap_noted_carries_no_key(self) -> None:
        assert "output_caps" not in GenerationRates().snapshot()

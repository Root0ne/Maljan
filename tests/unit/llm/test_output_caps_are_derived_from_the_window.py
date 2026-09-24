"""An analyst's and the judge's output cap: the operator's, or derived from the window.

``llm.expert_max_tokens`` and ``llm.judge_max_tokens`` shipped as a fixed
8,192 whatever the model served. They ship at 0 now, which derives each from
the window the agent's model serves — a quarter of it, at most 8,192 — the
rule the reply reserve and the composer's section budget already follow. A
value above 0 is the operator's and is used as set; the derivation is printed
in the run summary beside the timeouts it sizes.
"""

from __future__ import annotations

from maljan.core.config import LLMConfig, Settings
from maljan.llm.context_window import DEFAULT_REPLY_TOKENS, output_cap_for
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
        assert "a quarter of the model's 16384-token context window" in cap.sentence

    def test_never_more_than_the_shipped_reply_room(self) -> None:
        cap = output_cap_for(_settings(131072), "judge_max_tokens", "judge", role="judge")

        assert cap.tokens == DEFAULT_REPLY_TOKENS

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

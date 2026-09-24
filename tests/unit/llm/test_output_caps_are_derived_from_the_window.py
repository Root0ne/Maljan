"""An analyst's and the judge's output cap: the operator's, or derived — three cases.

``llm.expert_max_tokens`` and ``llm.judge_max_tokens`` shipped as a fixed
8,192 whatever the model served. They ship at 0 now, which derives each:

1. the model's maximum output is declared (a model list entry, or a vendored
   ``max_output`` row with the vendor's page as its source): the smaller of it
   and a quarter of the window;
2. a runtime we run serves it (llama.cpp or Ollama on loopback, or a server the
   window probe read from a runtime's own description): a quarter of the window,
   since no API limits output;
3. a hosted API declares no maximum: the documented fallback of 8,192, which a
   quarter of a hosted model's window is routinely past.

A value above 0 is the operator's and is used as set, and every case records
its derivation.
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


def _settings(
    window: int = 0, *, model: str = "local-model", base_url: str | None = None, **caps: int
) -> Settings:
    settings = Settings(llm=LLMConfig(provider="openai", **caps))
    settings.llm.openai.context_size = window
    settings.llm.openai.expert_model = model
    settings.llm.openai.judge_model = model
    settings.llm.openai.base_url = base_url
    return settings


LOCAL = "http://127.0.0.1:8080/v1"


class TestTheShippedDefault:
    def test_both_caps_ship_derived(self) -> None:
        assert LLMConfig().expert_max_tokens == 0
        assert LLMConfig().judge_max_tokens == 0


class TestAFreshInstallOnTheDefaultModels:
    """gpt-4o and gpt-4o-mini, the shipped defaults, declare 16,384 output tokens."""

    def test_no_max_tokens_above_the_model_s_limit_is_ever_sent(self) -> None:
        settings = Settings(llm=LLMConfig(provider="openai"))
        for model in (settings.llm.openai.expert_model, settings.llm.openai.judge_model):
            assert model in ("gpt-4o", "gpt-4o-mini")
            for setting, agent, role in (
                ("expert_max_tokens", "static", "expert"),
                ("judge_max_tokens", "judge", "judge"),
            ):
                cap = output_cap_for(settings, setting, agent, role=role)
                assert 0 < cap.tokens <= 16384, (model, cap)
                assert "declared maximum output of 16384" in cap.sentence

    def test_every_max_output_row_names_the_vendor_page_it_came_from(self) -> None:
        import json

        from maljan.core.paths import resolve_data
        from maljan.llm.context_window import TABLE_PATH

        with open(resolve_data(TABLE_PATH), encoding="utf-8") as handle:
            rows = json.load(handle)["max_output"]
        listed = {k: v for k, v in rows.items() if not k.startswith("_")}
        assert listed
        for model, row in listed.items():
            assert isinstance(row["tokens"], int) and row["tokens"] > 0, model
            assert row["source"].startswith("https://"), model


class TestTheThreeCases:
    def test_a_declared_maximum_bounds_the_quarter(self) -> None:
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

    def test_a_llama_server_that_answered_props_on_loopback_gets_a_quarter(self) -> None:
        from unittest.mock import patch

        for window, expected in ((32768, 8192), (131072, 32768)):
            fact = WindowFact(window, "probed", f"llama.cpp /props reported {window:,} tokens")
            with patch("maljan.llm.context_window.learn_window", return_value=fact):
                cap = output_cap_for(
                    _settings(window, base_url=LOCAL), "expert_max_tokens", "static"
                )

            assert cap.tokens == expected
            assert "served by a runtime with no API output limit" in cap.sentence

    def test_a_loopback_proxy_with_no_runtime_answer_takes_the_hosted_fallback(self) -> None:
        """A gateway on localhost:4000 forwarding to a hosted API has that API's limit."""
        cap = output_cap_for(
            _settings(131072, base_url="http://localhost:4000/v1"), "expert_max_tokens", "static"
        )

        assert cap.tokens == DEFAULT_REPLY_TOKENS
        assert "the documented fallback of 8192" in cap.sentence
        assert "declares no maximum output" in cap.sentence

    def test_a_loopback_proxy_to_a_model_that_declares_its_maximum_takes_it(self) -> None:
        cap = output_cap_for(
            _settings(128000, model="gpt-4o", base_url="http://127.0.0.1:4000/v1"),
            "expert_max_tokens",
            "static",
        )

        assert cap.tokens == 16384
        assert "declared maximum output of 16384" in cap.sentence

    def test_a_server_the_probe_read_from_llama_props_is_local_wherever_it_is(self) -> None:
        window = WindowFact(131072, "probed", "llama.cpp /props reported 131,072 tokens")

        tokens, said = derived_reply(window, 0, "local-model", "llm.expert_max_tokens", local=True)

        assert tokens == 32768

    def test_a_hosted_api_that_declares_no_maximum_takes_the_documented_fallback(self) -> None:
        cap = output_cap_for(
            _settings(200000, base_url="https://api.example.com/v1"),
            "judge_max_tokens",
            "judge",
            role="judge",
        )

        assert cap.tokens == DEFAULT_REPLY_TOKENS
        assert "the documented fallback of 8192" in cap.sentence
        assert "declares no maximum output" in cap.sentence

    def test_an_unknown_window_keeps_the_documented_fallback_and_says_so(self) -> None:
        window = WindowFact(8192, "fallback", "nothing answered")

        tokens, said = derived_reply(window, 0, "", "llm.expert_max_tokens")

        assert tokens == DEFAULT_REPLY_TOKENS
        assert "the documented fallback: no window was learned" in said

    def test_the_reply_reserve_follows_the_same_bounds(self) -> None:
        assert reply_reserve_tokens(131072) == 32768
        assert reply_reserve_tokens(131072, 8192) == 8192
        assert reply_reserve_tokens(131072, 0, 16000) == 16000

    def test_an_operator_value_is_used_as_set(self) -> None:
        cap = output_cap_for(
            _settings(16384, model="gpt-4o", expert_max_tokens=6000), "expert_max_tokens"
        )

        assert cap.tokens == 6000
        assert "llm.expert_max_tokens is set to 6000" in cap.sentence


class TestItIsPrinted:
    def test_the_generation_record_carries_each_cap_and_its_derivation(self) -> None:
        rates = GenerationRates()
        cap = output_cap_for(_settings(16384, model="gpt-4o"), "expert_max_tokens", "static")

        rates.note_output_cap("static", cap.tokens, cap.sentence)

        assert rates.snapshot()["output_caps"] == {
            "static": {"tokens": 4096, "derivation": cap.sentence}
        }

    def test_a_record_with_no_cap_noted_carries_no_key(self) -> None:
        assert "output_caps" not in GenerationRates().snapshot()

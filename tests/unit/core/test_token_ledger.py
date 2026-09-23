"""What a run spent on its models, in the providers' own figures and nothing else."""

from __future__ import annotations

from maljan.analysis.run_summary import RunSummaryBuilder, TokenUsageMetrics, tokens_sentence
from maljan.core.token_ledger import (
    TokenLedger,
    estimate_tokens,
    record_response_usage,
    turn_usage,
)


class _Resp:
    """Minimal langchain-response stand-in."""

    def __init__(
        self,
        content: str,
        usage: dict | None = None,
        metadata: dict | None = None,
    ) -> None:
        self.content = content
        if usage is not None:
            self.usage_metadata = usage
        self.response_metadata = metadata or {}


def _usage(inp: int, out: int) -> dict:
    return {"input_tokens": inp, "output_tokens": out, "total_tokens": inp + out}


class TestTheLedgerAddsWhatWasReported:
    def test_reported_usage_is_summed(self) -> None:
        led = TokenLedger()
        led.add({"input_tokens": 100, "output_tokens": 40})
        led.add({"input_tokens": 50, "output_tokens": 10})
        assert (led.input_tokens, led.output_tokens, led.total_tokens, led.calls) == (
            150,
            50,
            200,
            2,
        )

    def test_a_call_that_reported_nothing_is_counted_and_adds_no_tokens(self) -> None:
        led = TokenLedger()
        led.add(None, agent="static")
        snap = led.snapshot()
        assert snap["llm_calls"] == 1
        assert snap["unreported_calls"] == 1
        assert snap["input_tokens"] == 0 and snap["output_tokens"] == 0

    def test_per_agent_and_per_model(self) -> None:
        led = TokenLedger()
        led.add({"input_tokens": 7, "output_tokens": 3}, agent="static", model="openai/qwen")
        led.add(None, agent="static", model="ollama/gemma")
        led.add({"input_tokens": 1, "output_tokens": 1}, agent="judge", model="openai/qwen")
        static = led.snapshot()["agents"]["static"]
        assert static["llm_calls"] == 2
        assert static["unreported_calls"] == 1
        assert static["input_tokens"] == 7
        assert static["models"] == {"ollama/gemma": 1, "openai/qwen": 1}

    def test_a_cost_appears_only_where_it_was_reported(self) -> None:
        led = TokenLedger()
        led.add({"input_tokens": 1, "output_tokens": 1, "cost": 0.002}, agent="static")
        led.add({"input_tokens": 1, "output_tokens": 1}, agent="judge")
        snap = led.snapshot()
        assert snap["cost"] == 0.002 and snap["cost_calls"] == 1
        assert "cost" not in snap["agents"]["judge"]

    def test_a_fallback_is_kept_with_its_reason(self) -> None:
        led = TokenLedger()
        led.add(None, agent="static", model="ollama/gemma", fallback="openai/qwen: timed out")
        assert led.snapshot()["fallbacks"] == [
            {"agent": "static", "model": "ollama/gemma", "reason": "openai/qwen: timed out"}
        ]


class TestOneAnswer:
    def test_usage_metadata_is_what_is_recorded(self) -> None:
        led = TokenLedger()
        record_response_usage(led, _Resp("hi", _usage(120, 30)), agent="static", model="m")
        assert (led.input_tokens, led.output_tokens) == (120, 30)
        assert led.snapshot()["unreported_calls"] == 0

    def test_an_answer_without_usage_is_not_estimated(self) -> None:
        led = TokenLedger()
        record_response_usage(led, _Resp("y" * 400), agent="static")
        snap = led.snapshot()
        assert snap["unreported_calls"] == 1
        assert snap["input_tokens"] == 0 and snap["output_tokens"] == 0

    def test_a_router_reported_cost_is_read(self) -> None:
        answer = _Resp("hi", _usage(5, 5), {"token_usage": {"cost": 0.0125}})
        assert turn_usage(answer) == {"input_tokens": 5, "output_tokens": 5, "cost": 0.0125}

    def test_the_model_an_answer_names_wins_over_the_one_asked(self) -> None:
        led = TokenLedger()
        answer = _Resp(
            "hi",
            _usage(1, 1),
            {"maljan_model": "ollama/gemma", "maljan_fallback": "openai/qwen: timed out"},
        )
        record_response_usage(led, answer, agent="static", model="openai/qwen")
        snap = led.snapshot()
        assert snap["agents"]["static"]["models"] == {"ollama/gemma": 1}
        assert snap["fallbacks"][0]["reason"] == "openai/qwen: timed out"

    def test_none_ledger_is_noop(self) -> None:
        record_response_usage(None, _Resp("hi"))

    def test_malformed_response_never_raises(self) -> None:
        led = TokenLedger()
        record_response_usage(led, object())
        assert led.calls == 1
        assert led.snapshot()["unreported_calls"] == 1


class TestEstimateTokensStaysForCeilings:
    def test_empty(self) -> None:
        assert estimate_tokens("") == 0

    def test_roughly_quarter_chars(self) -> None:
        assert estimate_tokens("a" * 400) == 100
        assert estimate_tokens("abc") == 1


class TestTheSentence:
    def test_counts_and_the_calls_that_reported_nothing(self) -> None:
        text = tokens_sentence(
            {"llm_calls": 3, "unreported_calls": 1, "input_tokens": 1200, "output_tokens": 80}
        )
        assert text == "Tokens: 1,200 in and 80 out over 3 model calls; not reported for 1 of them."

    def test_nothing_reported_is_said_in_words(self) -> None:
        text = tokens_sentence({"llm_calls": 2, "unreported_calls": 2})
        assert text == "Tokens: not reported by the provider for any of 2 model calls."

    def test_a_reported_cost_is_named_with_its_unit_and_its_calls(self) -> None:
        text = tokens_sentence(
            {"llm_calls": 1, "input_tokens": 1, "output_tokens": 1, "cost": 0.5, "cost_calls": 1}
        )
        assert text is not None
        assert "a cost of 0.5000 USD as the provider reported it for 1 call." in text

    def test_a_summary_stored_with_estimates_prints_no_count(self) -> None:
        """The shape a run stored before this release carries, as it is read back."""
        stored = {
            "input_tokens": 120000,
            "output_tokens": 9000,
            "total_tokens": 129000,
            "llm_calls": 40,
            "estimated_calls": 40,
        }
        text = tokens_sentence(stored)
        assert text == (
            "Tokens: this run was recorded with estimates mixed into its 40 model calls, "
            "so no count is shown."
        )
        assert "120,000" not in text

    def test_the_served_markdown_of_an_old_run_prints_no_estimate(self) -> None:
        from maljan.reporting.renderers.markdown import MarkdownRenderer

        text = MarkdownRenderer()._section_run_summary(
            {"tokens": {"llm_calls": 40, "estimated_calls": 3, "input_tokens": 120000}}
        )
        assert "120,000" not in text and "no count is shown" in text

    def test_no_calls_no_sentence(self) -> None:
        assert tokens_sentence({"llm_calls": 0}) is None


class TestRunSummaryIntegration:
    def test_set_token_usage_populates_metrics_and_models(self) -> None:
        led = TokenLedger()
        led.add(_usage(100, 40), agent="static", model="openai/qwen")
        led.add(None, agent="static", model="ollama/gemma", fallback="openai/qwen: timed out")
        summary = (
            RunSummaryBuilder(start_time=0.0)
            .set_sample("abc", "x.exe")
            .set_verdict("Malware", 3)
            .set_token_usage(led.snapshot())
            .build()
        )
        assert isinstance(summary.tokens, TokenUsageMetrics)
        assert summary.tokens.total_tokens == 140
        assert summary.tokens.unreported_calls == 1
        d = summary.to_dict()
        assert d["tokens"]["per_agent"]["static"]["llm_calls"] == 2
        assert d["tokens"]["sentence"].startswith("Tokens: 100 in and 40 out over 2 model calls")
        assert d["models"]["static"]["turns"] == {"ollama/gemma": 1, "openai/qwen": 1}
        assert d["models"]["static"]["fallbacks"] == [
            {"model": "ollama/gemma", "reason": "openai/qwen: timed out"}
        ]
        markdown = summary.to_markdown()
        assert "## Token Usage" in markdown and "## Model Fallbacks" in markdown

    def test_an_agent_whose_calls_reported_nothing_shows_no_zero_count(self) -> None:
        led = TokenLedger()
        led.add(_usage(10, 2), agent="static", model="m")
        led.add(None, agent="reporter")
        summary = (
            RunSummaryBuilder(start_time=0.0)
            .set_sample("abc", None)
            .set_verdict("Benign", 0)
            .set_token_usage(led.snapshot())
            .build()
        )
        row = next(
            line for line in summary.to_markdown().splitlines() if line.startswith("| reporter")
        )
        assert row == "| reporter | 1 | not reported | not reported | 1 | — |"

    def test_no_usage_leaves_tokens_none(self) -> None:
        summary = (
            RunSummaryBuilder(start_time=0.0)
            .set_sample("abc", None)
            .set_verdict("Benign", 0)
            .set_token_usage(TokenLedger().snapshot())
            .build()
        )
        assert summary.tokens is None
        assert summary.to_dict()["tokens"] is None
        assert summary.to_dict()["models"] is None
        assert "## Token Usage" not in summary.to_markdown()

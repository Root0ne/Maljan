"""Unit tests for the per-run token ledger (findings-log §4 Item 1)."""

from __future__ import annotations

from maljan.analysis.run_summary import RunSummaryBuilder, TokenUsageMetrics
from maljan.core.token_ledger import TokenLedger, estimate_tokens, record_response_usage


class _Resp:
    """Minimal langchain-response stand-in."""

    def __init__(self, content: str, usage: dict | None = None) -> None:
        self.content = content
        if usage is not None:
            self.usage_metadata = usage


class TestTokenLedger:
    def test_add_accumulates(self) -> None:
        led = TokenLedger()
        led.add(100, 40)
        led.add(50, 10)
        assert led.input_tokens == 150
        assert led.output_tokens == 50
        assert led.total_tokens == 200
        assert led.calls == 2
        assert led.estimated_calls == 0

    def test_estimated_flag_counted(self) -> None:
        led = TokenLedger()
        led.add(10, 5, estimated=True)
        assert led.estimated_calls == 1

    def test_snapshot_shape(self) -> None:
        led = TokenLedger()
        led.add(7, 3)
        snap = led.snapshot()
        assert snap == {
            "input_tokens": 7,
            "output_tokens": 3,
            "total_tokens": 10,
            "llm_calls": 1,
            "estimated_calls": 0,
        }

    def test_negative_clamped(self) -> None:
        led = TokenLedger()
        led.add(-5, -1)
        assert led.input_tokens == 0
        assert led.output_tokens == 0


class TestRecordResponseUsage:
    def test_prefers_usage_metadata(self) -> None:
        led = TokenLedger()
        record_response_usage(
            led, _Resp("hi", {"input_tokens": 120, "output_tokens": 30, "total_tokens": 150})
        )
        assert led.input_tokens == 120
        assert led.output_tokens == 30
        assert led.estimated_calls == 0

    def test_falls_back_to_estimate(self) -> None:
        led = TokenLedger()
        prompt = "x" * 400  # ~100 tokens
        record_response_usage(led, _Resp("y" * 40), prompt_text=prompt)
        assert led.estimated_calls == 1
        assert led.input_tokens == estimate_tokens(prompt)
        assert led.output_tokens == estimate_tokens("y" * 40)

    def test_none_ledger_is_noop(self) -> None:
        # Must not raise.
        record_response_usage(None, _Resp("hi"))

    def test_malformed_response_never_raises(self) -> None:
        led = TokenLedger()
        record_response_usage(led, object(), prompt_text="p")
        # Estimate path still records a call (content stringified).
        assert led.calls == 1


class TestEstimateTokens:
    def test_empty(self) -> None:
        assert estimate_tokens("") == 0

    def test_roughly_quarter_chars(self) -> None:
        assert estimate_tokens("a" * 400) == 100
        assert estimate_tokens("abc") == 1  # min 1


class TestRunSummaryIntegration:
    def test_set_token_usage_populates_metrics(self) -> None:
        led = TokenLedger()
        led.add(100, 40)
        led.add(20, 10, estimated=True)
        summary = (
            RunSummaryBuilder(start_time=0.0)
            .set_sample("abc", "x.exe")
            .set_verdict("Malware", 3)
            .set_token_usage(led.snapshot())
            .build()
        )
        assert isinstance(summary.tokens, TokenUsageMetrics)
        assert summary.tokens.total_tokens == 170
        assert summary.tokens.llm_calls == 2
        assert summary.tokens.estimated_calls == 1
        d = summary.to_dict()
        assert d["tokens"]["total_tokens"] == 170
        assert "## Token Usage" in summary.to_markdown()

    def test_no_usage_leaves_tokens_none(self) -> None:
        summary = (
            RunSummaryBuilder(start_time=0.0)
            .set_sample("abc", None)
            .set_verdict("Benign", 0)
            .set_token_usage(TokenLedger().snapshot())  # zero calls
            .build()
        )
        assert summary.tokens is None
        assert summary.to_dict()["tokens"] is None
        assert "## Token Usage" not in summary.to_markdown()

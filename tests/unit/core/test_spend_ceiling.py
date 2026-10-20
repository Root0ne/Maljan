"""The operator's spend ceiling: priced from reported usage, never guessed.

``llm.max_spend_usd_per_job`` has no default. Spend is the provider-reported
cached input, input and output tokens of every call at the answering model's
prices — the operator's ``llm.model_prices`` first, the vendored table's
documented rows second. A model with no price is named once and its calls add
nothing, so the figure the ceiling is compared with is one the job has spent at
least.
"""

from __future__ import annotations

import json
import logging

import pytest

from maljan.analysis.run_summary import RunSummaryBuilder, spend_lines
from maljan.core.config import Settings
from maljan.core.spend import SpendMeter, table_prices
from maljan.core.token_ledger import TokenLedger

PRICES = {
    "deepseek-v4-pro": {
        "input_usd_per_mtok": 1.0,
        "cached_input_usd_per_mtok": 0.1,
        "output_usd_per_mtok": 4.0,
    }
}


class TestTheSettings:
    def test_there_is_no_ceiling_and_no_price_by_default(self) -> None:
        cfg = Settings(_env_file=None)
        assert cfg.llm.max_spend_usd_per_job is None
        assert cfg.llm.model_prices == {}
        assert SpendMeter.from_settings(cfg).snapshot() is None

    def test_an_operator_s_ceiling_and_prices_are_read(self) -> None:
        cfg = Settings(_env_file=None, llm={"max_spend_usd_per_job": 2.5, "model_prices": PRICES})
        meter = SpendMeter.from_settings(cfg)
        assert meter.ceiling_usd == 2.5
        price = meter.price_of("openai/deepseek-v4-pro @ https://api.deepseek.com")
        assert price is not None and price.source == "llm.model_prices"


class TestTheArithmetic:
    def test_cached_input_input_and_output_each_at_their_own_price(self) -> None:
        meter = SpendMeter(10.0, PRICES, table={})
        meter.settle(
            {"input_tokens": 1_000_000, "cached_input_tokens": 400_000, "output_tokens": 500_000},
            "deepseek-v4-pro",
        )
        # 600k uncached at 1.0, 400k cached at 0.1, 500k out at 4.0 per million.
        assert meter.spent() == pytest.approx(0.6 + 0.04 + 2.0)

    def test_a_cached_token_with_no_cached_price_costs_an_input_token(self) -> None:
        meter = SpendMeter(
            10.0, {"m": {"input_usd_per_mtok": 2.0, "output_usd_per_mtok": 0.0}}, table={}
        )
        meter.settle({"input_tokens": 1_000_000, "cached_input_tokens": 1_000_000}, "m")
        assert meter.spent() == pytest.approx(2.0)

    def test_the_vendored_table_prices_what_the_operator_did_not(self) -> None:
        rows = table_prices()
        assert "deepseek-flash" in rows and "deepseek-v4-pro" in rows
        vendor_pages = {"deepseek": "api-docs.deepseek.com", "claude": "platform.claude.com/docs"}
        for name, row in rows.items():
            page = next(page for prefix, page in vendor_pages.items() if name.startswith(prefix))
            assert f"https://{page}" in row.source, name
        meter = SpendMeter(1.0)
        price = meter.price_of("openai/deepseek-flash @ https://api.deepseek.com")
        assert price is not None and price.source == rows["deepseek-flash"].source

    def test_the_operator_s_price_wins_over_the_table_s(self) -> None:
        meter = SpendMeter(
            1.0, {"deepseek-flash": {"input_usd_per_mtok": 9, "output_usd_per_mtok": 9}}
        )
        price = meter.price_of("deepseek-flash")
        assert price is not None and price.input == 9.0


class TestAModelWithNoPrice:
    def test_is_not_counted_and_is_named_once(self, caplog: pytest.LogCaptureFixture) -> None:
        meter = SpendMeter(0.01, PRICES, table={})
        with caplog.at_level(logging.WARNING, logger="maljan"):
            for _ in range(3):
                meter.settle({"input_tokens": 10_000_000, "output_tokens": 0}, "mystery-model")
        assert meter.spent() == 0.0 and meter.reached() is False
        warned = [r for r in caplog.records if "has no price" in r.getMessage()]
        assert len(warned) == 1
        snapshot = meter.snapshot()
        assert snapshot is not None
        assert snapshot["unpriced_models"] == {"mystery-model": 3}
        assert "no price for mystery-model" in snapshot["note"]

    def test_a_call_that_reported_no_usage_adds_nothing(self) -> None:
        meter = SpendMeter(0.01, PRICES, table={})
        meter.settle(None, "deepseek-v4-pro")
        assert meter.spent() == 0.0


class TestTheCeiling:
    def test_is_reached_through_the_token_ledger_and_latches(self) -> None:
        meter = SpendMeter(1.0, PRICES, table={})
        ledger = TokenLedger(spend=meter)
        ledger.add({"input_tokens": 500_000, "output_tokens": 0}, model="deepseek-v4-pro")
        assert meter.reached() is False
        ledger.add({"input_tokens": 0, "output_tokens": 200_000}, model="deepseek-v4-pro")
        assert meter.reached() is True
        assert meter.reached() is True
        assert "spend ceiling of 1.0000 USD was reached" in meter.reason()

    def test_a_running_loop_s_turns_count_until_the_ledger_has_them(self) -> None:
        from langchain_core.messages import AIMessage

        meter = SpendMeter(1.0, PRICES, table={})
        turn = AIMessage(
            content="",
            usage_metadata={"input_tokens": 0, "output_tokens": 300_000, "total_tokens": 300_000},
        )
        meter.note_loop("loop", [turn], "deepseek-v4-pro")
        assert meter.spent() == pytest.approx(1.2) and meter.reached() is True
        meter.forget_loop("loop")
        assert meter.spent() == 0.0

    def test_with_no_ceiling_nothing_is_ever_reached(self) -> None:
        meter = SpendMeter(None, PRICES, table={})
        meter.settle({"input_tokens": 10**9, "output_tokens": 10**9}, "deepseek-v4-pro")
        assert meter.reached() is False and meter.reason() == ""


class TestTheRunSummary:
    def test_carries_the_spend_block_and_its_lines(self) -> None:
        meter = SpendMeter(1.0, PRICES, table={})
        meter.settle({"input_tokens": 0, "output_tokens": 300_000}, "deepseek-v4-pro")
        meter.reached()
        summary = RunSummaryBuilder(start_time=0.0).set_spend(meter.snapshot()).build()
        stored = summary.to_dict()["spend"]
        assert stored["reached"] is True and stored["spent_usd"] == pytest.approx(1.2)
        lines = spend_lines(stored)
        assert lines[0].startswith("Spent 1.2000 USD of the 1.0000 USD ceiling — reached")
        assert "## Spend Ceiling" in summary.to_markdown()

    def test_no_ceiling_is_no_block(self) -> None:
        summary = RunSummaryBuilder(start_time=0.0).set_spend(None).build()
        assert "spend" not in summary.to_dict()


class TestBeforeEachCall:
    """A call whose worst case would pass the ceiling: made held, or not made."""

    def _meter(self, ceiling: float = 1.0) -> SpendMeter:
        return SpendMeter(ceiling, PRICES, table={})

    def test_a_call_that_fits_is_made_as_it_is(self) -> None:
        meter = self._meter()
        assert (
            meter.admit(
                kind="loop turn", model="deepseek-v4-pro", prompt_chars=3000, cap_tokens=1000
            )
            is None
        )

    def test_an_ordinary_call_past_the_worst_case_is_not_made(self) -> None:
        from maljan.core.spend import SpendCeilingStop

        meter = self._meter()
        with pytest.raises(SpendCeilingStop, match="loop turn call"):
            meter.admit(
                kind="loop turn", model="deepseek-v4-pro", prompt_chars=3000, cap_tokens=500_000
            )
        assert meter.snapshot()["held_calls"]

    def test_the_verdict_is_made_with_its_cap_lowered_to_what_is_left(self) -> None:
        meter = self._meter()
        # 0.56 USD of input and a measured answer of 10,000 tokens (0.04 USD).
        meter.settle({"input_tokens": 560_000, "output_tokens": 10_000}, "deepseek-v4-pro")
        # 0.40 USD left at 4 USD a million output tokens is 100,000 tokens.
        held = meter.admit(
            kind="verdict", model="deepseek-v4-pro", prompt_chars=0, cap_tokens=384_000
        )
        assert held == 100_000
        (said,) = meter.snapshot()["held_calls"]
        assert "held to 100,000 output tokens" in said

    def test_after_the_ceiling_nothing_is_made_not_even_the_report(self) -> None:
        from maljan.core.spend import SpendCeilingStop

        meter = self._meter()
        meter.settle({"input_tokens": 0, "output_tokens": 300_000}, "deepseek-v4-pro")
        assert meter.reached()
        with pytest.raises(SpendCeilingStop, match="is exhausted"):
            meter.admit(
                kind="validation retry", model="deepseek-v4-pro", prompt_chars=10, cap_tokens=10
            )
        with pytest.raises(SpendCeilingStop, match="pays for 0 output tokens"):
            meter.admit(kind="report", model="deepseek-v4-pro", prompt_chars=10, cap_tokens=10)

    def test_a_model_with_no_price_is_made_until_the_ceiling_is_reached(self) -> None:
        meter = self._meter()
        assert (
            meter.admit(kind="loop turn", model="mystery", prompt_chars=10, cap_tokens=10) is None
        )


class TestTheTagIsKept:
    def test_two_tags_are_two_prices_and_the_base_name_is_the_fallback(self) -> None:
        meter = SpendMeter(
            1.0,
            {
                "qwen3:8b": {"input_usd_per_mtok": 1.0, "output_usd_per_mtok": 1.0},
                "qwen3": {"input_usd_per_mtok": 9.0, "output_usd_per_mtok": 9.0},
            },
            table={},
        )
        assert meter.price_of("ollama/qwen3:8b").input == 1.0
        assert meter.price_of("qwen3:32b").input == 9.0


class TestUnreportedUsage:
    def test_is_counted_and_the_spend_is_at_least(self, caplog: pytest.LogCaptureFixture) -> None:
        meter = SpendMeter(1.0, PRICES, table={})
        with caplog.at_level(logging.WARNING, logger="maljan"):
            meter.settle(None, "deepseek-v4-pro")
            meter.settle(None, "deepseek-v4-pro")
        snapshot = meter.snapshot()
        assert snapshot["unreported_calls"] == 2
        assert sum("reported no usage" in r.getMessage() for r in caplog.records) == 1
        assert spend_lines(snapshot)[0].startswith("Spent at least 0.0000 USD")


class TestACallSentWithNoCapOfItsOwn:
    """Cap 0: no output cap of its own, priced at the most it may answer, never refused for it."""

    MODEL = "unlisted-model-x"

    @pytest.fixture(autouse=True)
    def _nothing_learned(self):
        from maljan.llm import model_output_limits

        model_output_limits.forget_learned()
        yield
        model_output_limits.forget_learned()

    def _meter(self, ceiling: float = 1.0) -> SpendMeter:
        price = {"input_usd_per_mtok": 1.0, "output_usd_per_mtok": 4.0}
        return SpendMeter(ceiling, {self.MODEL: price}, table={})

    def _declare(self, tokens: int) -> None:
        from maljan.llm import model_output_limits

        model_output_limits.note_declared(self.MODEL, tokens, "a test's model list")

    def test_it_is_made_and_latches_nothing(self) -> None:
        meter = self._meter()
        meter.admit(kind="summary", model=self.MODEL, prompt_chars=400, cap_tokens=0)
        assert not meter.exhausted()
        assert not meter.snapshot().get("held_calls")

    def test_the_fallback_figure_is_sent_as_its_cap_so_the_reservation_holds(self) -> None:
        meter = self._meter()
        assert meter.admit(kind="summary", model=self.MODEL, prompt_chars=400, cap_tokens=0) == (
            8_192
        )
        assert (
            meter.preview(kind="summary", model=self.MODEL, prompt_chars=400, cap_tokens=0) == 8_192
        )
        # Not a hold: nothing the ceiling decided is recorded as one.
        assert not meter.snapshot().get("held_calls")

    def test_a_model_s_declared_maximum_is_not_sent_as_a_cap(self) -> None:
        self._declare(2_000)
        meter = self._meter()
        assert meter.admit(kind="summary", model=self.MODEL, prompt_chars=0, cap_tokens=0) is None

    def test_one_that_cannot_be_held_with_no_declared_maximum_is_refused(self) -> None:
        """Nothing bounds it: the fallback figure would only be a guess, so it is not made."""
        from maljan.core.spend import SpendCeilingStop

        meter = self._meter()
        with pytest.raises(SpendCeilingStop, match="cannot be bounded under the spend ceiling"):
            meter.admit(
                kind="summary", model=self.MODEL, prompt_chars=0, cap_tokens=0, holdable=False
            )

    def test_one_that_cannot_be_held_is_made_when_its_declared_maximum_fits(self) -> None:
        self._declare(2_000)
        meter = self._meter()
        meter.settle({"input_tokens": 990_000, "output_tokens": 0}, self.MODEL)
        # 2,000 tokens fit the 2,500 the 0.01 USD left pays for: made as it is.
        assert (
            meter.admit(
                kind="summary", model=self.MODEL, prompt_chars=0, cap_tokens=0, holdable=False
            )
            is None
        )

    def test_one_that_cannot_be_held_is_refused_when_its_declared_maximum_does_not_fit(
        self,
    ) -> None:
        from maljan.core.spend import SpendCeilingStop

        self._declare(4_000)
        meter = self._meter()
        meter.settle({"input_tokens": 990_000, "output_tokens": 0}, self.MODEL)
        with pytest.raises(SpendCeilingStop, match="4,000 tokens it may answer with"):
            meter.admit(
                kind="summary", model=self.MODEL, prompt_chars=0, cap_tokens=0, holdable=False
            )

    def test_where_little_is_left_it_is_held_to_what_that_pays_for(self) -> None:
        meter = self._meter()
        # 0.99 USD spent, with an answer of 2,500 tokens measured: the 0.01 USD
        # left at 4 USD a million output tokens pays for 2,500 tokens.
        meter.settle({"input_tokens": 980_000, "output_tokens": 2_500}, self.MODEL)
        held = meter.admit(kind="summary", model=self.MODEL, prompt_chars=0, cap_tokens=0)
        assert held == 2_500
        (said,) = meter.snapshot()["held_calls"]
        assert "sent with no cap of its own, so it may answer 8,192 tokens" in said
        assert "its cap was 0" not in said

    def test_with_nothing_measured_it_needs_the_most_it_may_answer(self) -> None:
        from maljan.core.spend import SpendCeilingStop

        meter = self._meter()
        meter.settle({"input_tokens": 990_000, "output_tokens": 0}, self.MODEL)
        with pytest.raises(SpendCeilingStop, match="the most it may answer, sent with no cap"):
            meter.admit(kind="summary", model=self.MODEL, prompt_chars=0, cap_tokens=0)

    @pytest.mark.parametrize("kind", ["verdict", "report"])
    def test_a_planned_tail_call_with_no_cap_is_reserved_for_the_most_it_may_answer(
        self, kind: str
    ) -> None:
        meter = self._meter()
        meter.plan_tail({kind: (self.MODEL, 1, 0, 0)})
        snapshot = meter.snapshot()
        # 8,192 output tokens at 4 USD a million, for the call and its planned retry.
        assert snapshot["reserve_usd"] >= 8_192 * 4.0 / 1_000_000
        assert "the most it may answer, sent with no cap" in json.dumps(snapshot["reserve"])

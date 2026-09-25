"""The operator's spend ceiling: priced from reported usage, never guessed.

``llm.max_spend_usd_per_job`` has no default. Spend is the provider-reported
cached input, input and output tokens of every call at the answering model's
prices — the operator's ``llm.model_prices`` first, the vendored table's
documented rows second. A model with no price is named once and its calls add
nothing, so the figure the ceiling is compared with is one the job has spent at
least.
"""

from __future__ import annotations

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
        assert all("api-docs.deepseek.com" in row.source for row in rows.values())
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

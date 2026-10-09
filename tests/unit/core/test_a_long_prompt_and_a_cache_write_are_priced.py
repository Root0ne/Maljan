"""A call is priced at its prompt's tier, its cache writes and reads at their own rates.

Anthropic's pricing page (https://platform.claude.com/docs/en/about-claude/pricing)
prices Claude Haiku 5.5 by prompt length: a request whose prompt, cache reads
and cache writes included, is over 100,000 tokens pays the higher prices, each
request on its own; a five-minute cache write costs 1.25 times an input token,
an hour's write twice, a cache read a tenth. The vendored table carries those
prices as data; the arithmetic here reads them, and a row without them is
priced exactly as before.
"""

from __future__ import annotations

import pytest

from maljan.core.spend import SpendMeter, table_prices
from maljan.core.token_ledger import TokenLedger, turn_usage

HAIKU = "claude-haiku-5-5"
MILLION = 1_000_000


def _meter(**kwargs: object) -> SpendMeter:
    return SpendMeter(100.0, **kwargs)  # type: ignore[arg-type]


class TestTheVendoredRow:
    def test_it_carries_the_documented_figures_and_its_page(self) -> None:
        row = table_prices()[HAIKU]
        assert (row.input, row.output, row.cached_input) == (0.1, 0.5, 0.01)
        assert (row.cache_write, row.cache_write_1h) == (0.125, 0.2)
        assert "platform.claude.com/docs/en/about-claude/pricing" in row.source
        ((over, long),) = row.tiers
        assert over == 100_000
        assert (long.input, long.output, long.cached_input) == (0.5, 2.5, 0.05)
        assert (long.cache_write, long.cache_write_1h) == (0.625, 1.0)


class TestWhatACallCosts:
    def test_a_short_prompt_with_cache_reads_and_writes(self) -> None:
        meter = _meter()
        meter.settle(
            {
                "input_tokens": 50_000,
                "cached_input_tokens": 30_000,
                "cache_write_input_tokens": 10_000,
                "output_tokens": 1_000,
            },
            HAIKU,
        )
        expected = (10_000 * 0.1 + 30_000 * 0.01 + 10_000 * 0.125 + 1_000 * 0.5) / MILLION
        assert meter.spent() == pytest.approx(expected)

    def test_a_prompt_over_the_threshold_pays_the_long_prices_on_every_token(self) -> None:
        meter = _meter()
        meter.settle(
            {
                "input_tokens": 150_000,
                "cached_input_tokens": 120_000,
                "cache_write_input_tokens": 20_000,
                "output_tokens": 2_000,
            },
            HAIKU,
        )
        expected = (10_000 * 0.5 + 120_000 * 0.05 + 20_000 * 0.625 + 2_000 * 2.5) / MILLION
        assert meter.spent() == pytest.approx(expected)

    def test_the_threshold_itself_is_the_short_price(self) -> None:
        meter = _meter()
        meter.settle({"input_tokens": 100_000, "output_tokens": 0}, HAIKU)
        assert meter.spent() == pytest.approx(100_000 * 0.1 / MILLION)

    def test_an_hour_s_write_is_priced_as_one(self) -> None:
        meter = _meter()
        meter.settle(
            {
                "input_tokens": 10_000,
                "cache_write_input_tokens": 10_000,
                "cache_write_1h_input_tokens": 4_000,
                "output_tokens": 0,
            },
            HAIKU,
        )
        assert meter.spent() == pytest.approx((6_000 * 0.125 + 4_000 * 0.2) / MILLION)

    def test_a_row_without_write_prices_charges_a_write_as_input(self) -> None:
        meter = SpendMeter(
            10.0, {"m": {"input_usd_per_mtok": 2.0, "output_usd_per_mtok": 0.0}}, table={}
        )
        meter.settle({"input_tokens": MILLION, "cache_write_input_tokens": MILLION}, "m")
        assert meter.spent() == pytest.approx(2.0)

    def test_an_operator_s_tier_is_read_from_the_settings(self) -> None:
        from maljan.core.config import Settings

        settings = Settings(
            _env_file=None,
            llm={
                "max_spend_usd_per_job": 5.0,
                "model_prices": {
                    "m": {
                        "input_usd_per_mtok": 1.0,
                        "output_usd_per_mtok": 1.0,
                        "tiers": [
                            {
                                "over_prompt_tokens": 10,
                                "input_usd_per_mtok": 3.0,
                                "output_usd_per_mtok": 4.0,
                            }
                        ],
                    }
                },
            },
        )
        meter = SpendMeter.from_settings(settings)
        meter.settle({"input_tokens": 20, "output_tokens": 10}, "m")
        assert meter.spent() == pytest.approx((20 * 3.0 + 10 * 4.0) / MILLION)


class TestBeforeACall:
    def test_a_prompt_is_admitted_at_its_tier_and_its_dearest_rate(self) -> None:
        row = table_prices()[HAIKU]
        short = row.for_admission(1_000)
        assert (short.input, short.output) == (0.125, 0.5)
        long = row.for_admission(200_000)
        assert (long.input, long.output) == (0.625, 2.5)
        assert row.for_admission(200_000, hour_writes=True).input == 1.0

    def test_an_hour_s_write_is_admitted_only_where_one_is_asked_for(self) -> None:
        from maljan.core.config import Settings

        asked = Settings(_env_file=None, llm={"anthropic": {"prompt_cache_ttl": "1h"}})
        assert SpendMeter.from_settings(asked).hour_writes is True
        assert SpendMeter.from_settings(Settings(_env_file=None)).hour_writes is False

    def test_the_worst_case_of_a_long_prompt(self) -> None:
        meter = _meter()
        worst = meter.worst_case(HAIKU, 200_000, 1_000)
        assert worst == pytest.approx((200_000 * 0.625 + 1_000 * 2.5) / MILLION)

    def test_a_row_without_tiers_or_write_prices_is_admitted_as_before(self) -> None:
        row = table_prices()["deepseek-v4-pro"]
        assert row.for_admission(500_000) is row


class TestTheLedgerReadsAnthropicUsage:
    class _Answer:
        def __init__(self, details: dict[str, int], total: int) -> None:
            self.usage_metadata = {
                "input_tokens": total,
                "output_tokens": 7,
                "input_token_details": details,
            }
            self.response_metadata: dict[str, object] = {}

    def test_reads_and_writes_land_in_their_own_fields(self) -> None:
        usage = turn_usage(self._Answer({"cache_read": 300, "cache_creation": 120}, 440))
        assert usage == {
            "input_tokens": 440,
            "output_tokens": 7,
            "cached_input_tokens": 300,
            "cache_write_input_tokens": 120,
        }

    def test_writes_split_by_lifetime_are_summed_and_the_hour_kept(self) -> None:
        usage = turn_usage(
            self._Answer(
                {
                    "cache_read": 0,
                    "cache_creation": 0,
                    "ephemeral_5m_input_tokens": 100,
                    "ephemeral_1h_input_tokens": 50,
                },
                170,
            )
        )
        assert usage is not None
        assert usage["cache_write_input_tokens"] == 150
        assert usage["cache_write_1h_input_tokens"] == 50

    def test_a_provider_that_reports_no_write_has_no_write_field(self) -> None:
        usage = turn_usage(self._Answer({"cache_read": 3}, 10))
        assert usage is not None and "cache_write_input_tokens" not in usage

    def test_the_run_summary_counts_them(self) -> None:
        from maljan.analysis.run_summary import tokens_sentence

        ledger = TokenLedger()
        ledger.add(turn_usage(self._Answer({"cache_read": 300, "cache_creation": 120}, 440)))
        snapshot = ledger.snapshot()
        assert snapshot["cached_input_tokens"] == 300
        assert snapshot["cache_write_input_tokens"] == 120
        assert snapshot["cache_write_calls"] == 1
        sentence = tokens_sentence(snapshot)
        assert sentence is not None
        assert "120 of the input written to the prompt cache" in sentence


class TestTheReviewedEdges:
    def test_the_tier_is_chosen_from_a_cautious_count_of_the_prompt(self) -> None:
        """Measured at three characters a token, a prompt Claude counts at about 2.5."""
        row = table_prices()[HAIKU]
        assert row.for_admission(80_000).output == 2.5
        assert row.for_admission(66_000).output == 0.5

    def test_an_unsplit_write_is_an_hour_s_where_every_write_is(self) -> None:
        """A streamed answer's usage carries its writes without the split by lifetime."""
        meter = SpendMeter(100.0, hour_writes=True)
        meter.settle({"input_tokens": 10_000, "cache_write_input_tokens": 10_000}, HAIKU)
        assert meter.spent() == pytest.approx(10_000 * 0.2 / MILLION)

    def test_a_window_keeps_the_row_s_tiers(self) -> None:
        from datetime import UTC, datetime

        row = {
            "input_usd_per_mtok": 1.0,
            "output_usd_per_mtok": 1.0,
            "tiers": [
                {"over_prompt_tokens": 10, "input_usd_per_mtok": 5.0, "output_usd_per_mtok": 5.0}
            ],
            "windows": [
                {
                    "utc_from": "00:00",
                    "utc_to": "12:00",
                    "input_usd_per_mtok": 2.0,
                    "output_usd_per_mtok": 2.0,
                }
            ],
        }
        meter = SpendMeter(
            10.0, {"m": row}, table={}, clock=lambda: datetime(2026, 10, 6, 3, 0, tzinfo=UTC)
        )
        meter.settle({"input_tokens": 20, "output_tokens": 0}, "m")
        assert meter.spent() == pytest.approx(20 * 5.0 / MILLION)

"""A call is counted at what it was charged: the price in force when it was sent, or the provider's.

DeepSeek documents peak hours (01:00-04:00 and 06:00-10:00 UTC, Monday to
Friday) at twice the rate of every other hour. The vendored table used to carry
the peak rate alone, so a job run off-peak was counted at twice what it was
billed and its ceiling latched at half of what it allowed. A price row now
carries its windows as data, a call is settled at the window its request was
sent in, and a cost the provider reports with its answer is used as it is.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from maljan.core.config import ModelPrice, Settings
from maljan.core.spend import PROVIDER_REPORTED, SpendMeter, table_prices
from maljan.core.token_ledger import TokenLedger, turn_usage

FLASH = "deepseek-flash"
# 2026-09-25 is a Friday, 2026-09-26 a Saturday.
FRIDAY_17 = datetime(2026, 9, 25, 17, 0, tzinfo=UTC)
FRIDAY_08 = datetime(2026, 9, 25, 8, 0, tzinfo=UTC)
FRIDAY_0959 = datetime(2026, 9, 25, 9, 59, tzinfo=UTC)
FRIDAY_10 = datetime(2026, 9, 25, 10, 0, tzinfo=UTC)
SATURDAY_08 = datetime(2026, 9, 26, 8, 0, tzinfo=UTC)

ONE_MILLION_OUT = {"input_tokens": 0, "output_tokens": 1_000_000}


def _settled_at(when: datetime, usage: dict | None = None) -> float:
    meter = SpendMeter(100.0)
    meter.settle({**(usage or ONE_MILLION_OUT), "sent_at": when.timestamp()}, FLASH)
    return meter.spent()


class TestTheVendoredRow:
    def test_carries_deepseek_s_peak_windows_with_their_page(self) -> None:
        row = table_prices()[FLASH]
        assert row.output == pytest.approx(0.6)
        assert "off-peak" in row.source and "api-docs.deepseek.com" in row.source
        assert len(row.windows) == 2
        assert all(window.price.output == pytest.approx(1.2) for window in row.windows)
        assert all("peak rate" in window.price.source for window in row.windows)


class TestACallIsSettledAtThePriceWhenItWasSent:
    def test_at_17_00_utc_the_off_peak_price(self) -> None:
        assert _settled_at(FRIDAY_17) == pytest.approx(0.6)

    def test_inside_a_weekday_peak_window_the_peak_price(self) -> None:
        assert _settled_at(FRIDAY_08) == pytest.approx(1.2)
        assert _settled_at(FRIDAY_0959) == pytest.approx(1.2)

    def test_a_window_s_end_is_outside_it(self) -> None:
        assert _settled_at(FRIDAY_10) == pytest.approx(0.6)

    def test_a_weekend_hour_is_off_peak(self) -> None:
        assert _settled_at(SATURDAY_08) == pytest.approx(0.6)

    def test_cached_input_and_input_follow_the_window_too(self) -> None:
        usage = {"input_tokens": 2_000_000, "cached_input_tokens": 1_000_000, "output_tokens": 0}
        assert _settled_at(FRIDAY_08, usage) == pytest.approx(0.3 + 0.006)
        assert _settled_at(FRIDAY_17, usage) == pytest.approx(0.15 + 0.003)

    def test_the_run_summary_names_the_rate_each_call_was_priced_at(self) -> None:
        meter = SpendMeter(100.0)
        meter.settle({**ONE_MILLION_OUT, "sent_at": FRIDAY_08.timestamp()}, FLASH)
        meter.settle({**ONE_MILLION_OUT, "sent_at": FRIDAY_17.timestamp()}, FLASH)
        said = meter.snapshot()["prices_from"][FLASH]
        assert "peak rate, 06:00-10:00 UTC" in said and "off-peak rate" in said

    def test_a_call_with_no_send_time_is_priced_at_the_meter_s_clock(self) -> None:
        meter = SpendMeter(100.0, clock=lambda: FRIDAY_08)
        meter.settle(ONE_MILLION_OUT, FLASH)
        assert meter.spent() == pytest.approx(1.2)


class TestAReportedCostWins:
    def test_over_the_table(self) -> None:
        meter = SpendMeter(100.0)
        meter.settle({**ONE_MILLION_OUT, "cost": 0.0421, "sent_at": FRIDAY_08.timestamp()}, FLASH)
        assert meter.spent() == pytest.approx(0.0421)
        assert meter.snapshot()["prices_from"] == {FLASH: PROVIDER_REPORTED}

    def test_for_a_model_with_no_price(self) -> None:
        meter = SpendMeter(100.0, table={})
        meter.settle({**ONE_MILLION_OUT, "cost": 0.5}, "router-model")
        assert meter.spent() == pytest.approx(0.5)
        assert "unpriced_models" not in meter.snapshot()

    def test_through_the_token_ledger_from_the_answer(self) -> None:
        from langchain_core.messages import AIMessage

        answer = AIMessage(
            content="x",
            usage_metadata={"input_tokens": 10, "output_tokens": 1_000_000, "total_tokens": 0},
            response_metadata={"token_usage": {"cost": 0.25}, "sent_at": FRIDAY_08.timestamp()},
        )
        usage = turn_usage(answer)
        assert usage is not None
        assert usage["cost"] == 0.25 and usage["sent_at"] == FRIDAY_08.timestamp()
        meter = SpendMeter(100.0)
        TokenLedger(spend=meter).add(usage, model=FLASH)
        assert meter.spent() == pytest.approx(0.25)


class TestAWindowAsData:
    def test_an_operator_s_row_may_carry_windows(self) -> None:
        cfg = Settings(
            _env_file=None,
            llm={
                "max_spend_usd_per_job": 5.0,
                "model_prices": {
                    "m": {
                        "input_usd_per_mtok": 1.0,
                        "output_usd_per_mtok": 1.0,
                        "source": "our contract",
                        "windows": [
                            {
                                "utc_from": "22:00",
                                "utc_to": "02:00",
                                "days": ["fri"],
                                "input_usd_per_mtok": 0.0,
                                "output_usd_per_mtok": 0.5,
                                "source": "night rate",
                            }
                        ],
                    }
                },
            },
        )
        meter = SpendMeter.from_settings(cfg)
        row = meter.price_of("m")
        assert row is not None
        # Across midnight: opened on Friday, so Saturday 01:00 is in it and
        # Friday 01:00 (opened on Thursday) is not.
        assert row.at(datetime(2026, 9, 26, 1, 0, tzinfo=UTC)).output == 0.5
        assert row.at(datetime(2026, 9, 25, 23, 0, tzinfo=UTC)).output == 0.5
        assert row.at(datetime(2026, 9, 25, 1, 0, tzinfo=UTC)).output == 1.0

    @pytest.mark.parametrize(
        "window",
        [
            {"utc_from": "25:00", "utc_to": "02:00"},
            {"utc_from": "02:00", "utc_to": "02:00"},
            {"utc_from": "01:00", "utc_to": "02:00", "days": ["someday"]},
        ],
    )
    def test_a_window_that_is_not_one_is_refused(self, window: dict) -> None:
        with pytest.raises(ValidationError):
            ModelPrice(
                input_usd_per_mtok=1,
                output_usd_per_mtok=1,
                windows=[{**window, "input_usd_per_mtok": 1, "output_usd_per_mtok": 1}],
            )


class TestTheClientStampsTheSendTime:
    def test_an_answer_carries_when_its_request_was_sent(self) -> None:
        import asyncio
        import time

        from langchain_core.language_models.fake_chat_models import FakeListChatModel

        from maljan.llm.generation_rate import with_sized_request_timeout

        stamped = with_sized_request_timeout(FakeListChatModel)(responses=["hello"])
        before = time.time()
        answer = asyncio.run(stamped.ainvoke("hi"))
        after = time.time()
        assert before <= answer.response_metadata["sent_at"] <= after
        answer = stamped.invoke("hi")
        assert answer.response_metadata["sent_at"] >= before

"""Audit AUD-22: reputation dates, teardown on the loop, per-component price maxima, table reads."""

from __future__ import annotations

import asyncio
import json
import time
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from maljan.core import spend
from maljan.core.config import Settings
from maljan.core.container import ServiceContainer
from maljan.core.reputation import _moment
from maljan.core.spend import Price, PriceWindow


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_r3_a_non_finite_date_is_no_date(value: float) -> None:
    assert _moment(value) is None


def test_r3_a_finite_epoch_still_reads() -> None:
    assert _moment(1_700_000_000.5) == "2023-11-14T22:13:20Z"


@pytest.mark.asyncio
async def test_r4_a_slow_provider_close_does_not_block_the_loop() -> None:
    container = ServiceContainer(config=Settings(), mock=True)
    provider = MagicMock()
    provider.close.side_effect = lambda: time.sleep(0.5)
    container._static_provider_cache = {"slow": provider}
    ticks: list[float] = []

    async def heartbeat() -> None:
        while True:
            ticks.append(time.monotonic())
            await asyncio.sleep(0.02)

    beat = asyncio.create_task(heartbeat())
    await container.aclose()
    beat.cancel()
    provider.close.assert_called_once()
    assert len(ticks) >= 5  # the loop kept turning while the provider closed


def test_r5_a_window_dearer_only_on_input_is_the_admission_price() -> None:
    out_heavy = Price(1.0, 10.0, source="a")
    in_heavy = Price(5.0, 2.0, source="b")
    base = Price(
        1.0,
        1.0,
        source="base",
        windows=(
            PriceWindow(0, 600, frozenset(), out_heavy),
            PriceWindow(600, 1200, frozenset(), in_heavy),
        ),
    )
    start = datetime(2026, 1, 5, 0, 0, tzinfo=UTC)
    worst = base.highest_over(start, 20 * 3600)
    assert worst.input == 5.0
    assert worst.output == 10.0


def test_r6_a_failed_table_read_is_not_cached(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    bad = tmp_path / "table.json"
    bad.write_text("{not json", encoding="utf-8")
    monkeypatch.setattr(spend, "_table", None)
    monkeypatch.setattr("maljan.core.paths.resolve_data", lambda _p: bad)
    with caplog.at_level("WARNING"):
        assert spend.table_prices() == {}
    assert spend._table is None
    assert "price table could not be read" in caplog.text
    good = {"m": {"input_usd_per_mtok": 1, "output_usd_per_mtok": 2, "source": "t"}}
    bad.write_text(json.dumps({"prices": good}), encoding="utf-8")
    assert "m" in spend.table_prices()


def test_r6_the_unpriced_statement_names_a_table_that_could_not_be_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bad = tmp_path / "table.json"
    bad.write_text("{not json", encoding="utf-8")
    monkeypatch.setattr(spend, "_table", None)
    monkeypatch.setattr("maljan.core.paths.resolve_data", lambda _p: bad)
    meter = spend.SpendMeter(10.0)
    assert meter.price_of("some-model") is None
    meter._note_unpriced("some-model")
    block = meter.snapshot()
    assert block is not None
    assert "price table could not be read:" in block["note"]
    assert block["price_table_error"]
    bad.write_text(json.dumps({"prices": {}}), encoding="utf-8")
    spend.table_prices()
    assert spend.table_failure is None

"""A failed attempt's prompt is priced at the share of it the job measured read from the cache.

A long conversation reads most of its prompt from the provider's cache, and an
estimate that priced the whole prompt as uncached input could charge several
times what was billed and stop a run near its ceiling early. A failed
attempt's estimate (``llm.transient``) is priced with the share of the
model's input this job measured as cache reads, and where nothing is measured
the estimate says it is priced as uncached and overstates.
"""

from __future__ import annotations

import pytest

from maljan.core.spend import AT_CACHED_SHARE, SpendMeter

PRICE = {
    "input_usd_per_mtok": 1.0,
    "cached_input_usd_per_mtok": 0.1,
    "output_usd_per_mtok": 4.0,
}
MODEL = "m"


def _estimate(**extra: object) -> dict[str, object]:
    return {"input_tokens": 1_000_000, "output_tokens": 0, "source": "estimated", **extra}


def test_the_measured_share_prices_the_prompt() -> None:
    meter = SpendMeter(100.0, {MODEL: PRICE}, table={})
    meter._inputs[MODEL] = [1000, 800]

    meter.settle(None, MODEL, "failed attempt", estimated=_estimate(**{AT_CACHED_SHARE: True}))

    # 200,000 uncached at 1.0 and 800,000 cached at 0.1 per million.
    assert meter.remaining() == pytest.approx(100.0 - 0.2 - 0.08)
    assert "80% read from the cache" in meter._estimated_source


def test_with_nothing_measured_it_is_uncached_and_says_it_overstates() -> None:
    meter = SpendMeter(100.0, {MODEL: PRICE}, table={})

    meter.settle(None, MODEL, "failed attempt", estimated=_estimate(**{AT_CACHED_SHARE: True}))

    assert meter.remaining() == pytest.approx(99.0)
    assert "overstates" in meter._estimated_source


def test_an_estimate_that_does_not_ask_is_priced_as_it_always_was() -> None:
    meter = SpendMeter(100.0, {MODEL: PRICE}, table={})
    meter._inputs[MODEL] = [1000, 800]

    meter.settle(None, MODEL, "watch ended", estimated=_estimate())

    assert meter.remaining() == pytest.approx(99.0)
    assert meter._estimated_source == "estimated"

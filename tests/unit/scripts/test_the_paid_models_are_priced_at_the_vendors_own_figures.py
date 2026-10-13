"""The paid models' prices in the vendored table are the vendors' own figures, per token.

The rehearsal's spend check and the product price a call from the same vendored
table (``maljan.core.spend.table_prices``), so a wrong figure there would pass
both. These are the figures read on the vendors' price pages on 2026-10-10:

* https://platform.claude.com/docs/en/about-claude/pricing — Claude Haiku 5.5,
  per million tokens: for prompts up to 100,000 tokens, base input $0.10,
  5-minute cache writes $0.125, 1-hour cache writes $0.20, cache hits and
  refreshes $0.01, output $0.50; for prompts over 100,000 tokens, $0.50,
  $0.625, $1, $0.05 and $2.50. "A request's prompt length counts all of its
  input tokens, including cache reads and cache writes."
* https://api-docs.deepseek.com/quick_start/pricing — per million tokens,
  off-peak / peak: deepseek-flash input cache hit $0.003 / $0.006, cache miss
  $0.15 / $0.3, output $0.6 / $1.2; deepseek-v4-pro $0.022 / $0.044, $0.66 /
  $1.32, $1.98 / $3.96. Peak hours are 01:00-04:00 and 06:00-10:00 UTC, Monday
  through Friday; every other hour is off-peak. "The legacy names
  deepseek-v4-flash and deepseek-v4-flash-vision-exp are still accepted",
  billed at the Flash price.

The page also exempts Chinese public holidays from the peak hours; the table
holds no holidays, so a call on such a day is priced at the peak rate, which
overstates it. That is the one difference between the page and the table.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from maljan.core.spend import table_prices

M = 1_000_000
# Off-peak: a Saturday noon. Peak: a Monday inside each window. Off-peak again:
# a Monday between the two windows.
OFF_PEAK = datetime(2026, 10, 10, 12, 0, tzinfo=UTC)
PEAK_EARLY = datetime(2026, 10, 12, 2, 0, tzinfo=UTC)
PEAK_LATE = datetime(2026, 10, 12, 7, 0, tzinfo=UTC)
BETWEEN_PEAKS = datetime(2026, 10, 12, 5, 0, tzinfo=UTC)


def _cost(model: str, when: datetime, **usage: int) -> float:
    price = table_prices()[model]
    return float(price.at(when).cost(usage))


def _per_mtok(cost: float, tokens: int) -> float:
    return cost * M / tokens


class TestClaudeHaiku55:
    MODEL = "claude-haiku-5-5"

    @pytest.mark.parametrize(
        ("prompt", "rates"),
        [
            # Up to 100,000 prompt tokens, the threshold itself included.
            (50_000, (0.10, 0.125, 0.20, 0.01, 0.50)),
            (100_000, (0.10, 0.125, 0.20, 0.01, 0.50)),
            # Over 100,000.
            (100_001, (0.50, 0.625, 1.0, 0.05, 2.50)),
            (400_000, (0.50, 0.625, 1.0, 0.05, 2.50)),
        ],
    )
    def test_each_part_at_its_tier(self, prompt: int, rates: tuple[float, ...]) -> None:
        base, write_5m, write_1h, read, output = rates
        when = OFF_PEAK
        assert _per_mtok(_cost(self.MODEL, when, input_tokens=prompt), prompt) == pytest.approx(
            base
        )
        written = _cost(self.MODEL, when, input_tokens=prompt, cache_write_input_tokens=prompt)
        assert _per_mtok(written, prompt) == pytest.approx(write_5m)
        hour = _cost(
            self.MODEL,
            when,
            input_tokens=prompt,
            cache_write_input_tokens=prompt,
            cache_write_1h_input_tokens=prompt,
        )
        assert _per_mtok(hour, prompt) == pytest.approx(write_1h)
        cached = _cost(self.MODEL, when, input_tokens=prompt, cached_input_tokens=prompt)
        assert _per_mtok(cached, prompt) == pytest.approx(read)
        answered = _cost(self.MODEL, when, input_tokens=prompt, output_tokens=M)
        assert answered - _cost(self.MODEL, when, input_tokens=prompt) == pytest.approx(output)

    def test_cache_reads_and_writes_count_toward_the_tier(self) -> None:
        # 60,000 uncached, 30,000 read and 20,000 written: a 110,000-token prompt.
        usage: dict[str, Any] = {
            "input_tokens": 110_000,
            "cached_input_tokens": 30_000,
            "cache_write_input_tokens": 20_000,
        }
        expected = (60_000 * 0.50 + 30_000 * 0.05 + 20_000 * 0.625) / M
        assert _cost(self.MODEL, OFF_PEAK, **usage) == pytest.approx(expected)


@pytest.mark.parametrize(
    ("model", "off_peak", "peak"),
    [
        # (cache miss, cache hit, output) per million tokens.
        ("deepseek-flash", (0.15, 0.003, 0.6), (0.3, 0.006, 1.2)),
        ("deepseek-v4-flash", (0.15, 0.003, 0.6), (0.3, 0.006, 1.2)),
        ("deepseek-v4-pro", (0.66, 0.022, 1.98), (1.32, 0.044, 3.96)),
    ],
)
def test_deepseek_off_peak_and_peak(
    model: str, off_peak: tuple[float, ...], peak: tuple[float, ...]
) -> None:
    for when, (miss, hit, output) in (
        (OFF_PEAK, off_peak),
        (BETWEEN_PEAKS, off_peak),
        (PEAK_EARLY, peak),
        (PEAK_LATE, peak),
    ):
        assert _per_mtok(_cost(model, when, input_tokens=M), M) == pytest.approx(miss), when
        cached = _cost(model, when, input_tokens=M, cached_input_tokens=M)
        assert _per_mtok(cached, M) == pytest.approx(hit), when
        assert _cost(model, when, output_tokens=M) == pytest.approx(output), when

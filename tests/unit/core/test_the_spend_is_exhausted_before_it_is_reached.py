"""A call the spend cannot pay for is held, then refused; a refusal exhausts the spend.

At a 2.00 USD ceiling on ``deepseek-flash``, a revision's whole 393,216-token
cap costs more than what was left long before the spend reached the ceiling,
and every such call used to be refused: the job stopped with a quarter of its
ceiling unused and every revision skipped. A call is now made with its output
cap held to what the spend it may use pays for, and refused only when that is
below the smallest answer it can give — the largest answer this job has
measured of its model, or, with none measured, its own configured cap. The
first refusal latches the spend as exhausted; the gates and the reason read
the latch.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from maljan.analysis.run_summary import spend_lines
from maljan.core.spend import SpendCeilingStop, SpendMeter

FLASH = "deepseek-flash"
FLASH_CAP = 393_216
# A weekday hour inside DeepSeek's peak window, so the figures are the peak ones.
PEAK = datetime(2026, 9, 25, 8, 0, tzinfo=UTC)


def _meter_after(spent_usd: float, measured_output: int = 12_000) -> SpendMeter:
    """A 2.00 USD meter at the vendored flash prices, ``spent_usd`` billed, one answer measured."""
    meter = SpendMeter(2.00, clock=lambda: PEAK)
    price = meter.price_now(FLASH)
    assert price is not None and price.output == pytest.approx(1.2)
    # The answer measured, and the rest of the spend as uncached input.
    rest = spent_usd - measured_output * price.output / 1e6
    meter.settle(
        {
            "input_tokens": int(rest / price.input * 1e6),
            "output_tokens": measured_output,
            "sent_at": PEAK.timestamp(),
        },
        FLASH,
    )
    assert meter.spent() == pytest.approx(spent_usd, abs=1e-6)
    return meter


class TestTheReviewsCase:
    def test_a_revision_whose_whole_cap_passes_what_is_left_is_made_held(self) -> None:
        # Run 2: 1.5226 USD counted, a revision of about 46k prompt tokens.
        meter = _meter_after(1.5226)

        held = meter.admit(
            kind="revision", model=FLASH, prompt_chars=46_000 * 4, cap_tokens=FLASH_CAP
        )

        assert held is not None and 12_000 <= held < FLASH_CAP
        assert meter.exhausted() is False
        (said,) = meter.snapshot()["held_calls"]
        assert f"held to {held:,} output tokens (its cap was {FLASH_CAP:,})" in said

    def test_a_call_whose_room_is_below_the_measured_answer_is_refused_and_exhausts(
        self,
    ) -> None:
        meter = _meter_after(1.99, measured_output=12_000)

        with pytest.raises(SpendCeilingStop, match="smallest answer it can give") as refused:
            meter.admit(kind="loop turn", model=FLASH, prompt_chars=1_000, cap_tokens=FLASH_CAP)

        assert "the largest answer this job has measured of deepseek-flash" in str(refused.value)
        assert meter.reached() is False and meter.exhausted() is True
        snapshot = meter.snapshot()
        assert snapshot["exhausted_by"] == "a refusal"
        assert "exhausted at 1.99" in spend_lines(snapshot)[0]
        assert "no longer paid for a call's smallest answer" in meter.reason()

    def test_with_nothing_measured_the_smallest_answer_is_the_configured_cap(self) -> None:
        meter = SpendMeter(0.40, clock=lambda: PEAK)
        with pytest.raises(SpendCeilingStop, match="its configured output cap"):
            meter.admit(kind="revision", model=FLASH, prompt_chars=4_000, cap_tokens=FLASH_CAP)

    def test_after_a_refusal_every_call_but_the_verdict_and_report_is_refused(self) -> None:
        meter = _meter_after(1.99)
        with pytest.raises(SpendCeilingStop):
            meter.admit(kind="loop turn", model=FLASH, prompt_chars=1_000, cap_tokens=FLASH_CAP)
        with pytest.raises(SpendCeilingStop, match="is exhausted"):
            meter.admit(kind="revision", model=FLASH, prompt_chars=10, cap_tokens=10)
        assert meter.admit(kind="report", model=FLASH, prompt_chars=10, cap_tokens=10) is None


class TestTheGatesReadTheLatch:
    def _refused(self) -> SpendMeter:
        meter = _meter_after(1.99)
        with pytest.raises(SpendCeilingStop):
            meter.admit(kind="loop turn", model=FLASH, prompt_chars=1_000, cap_tokens=FLASH_CAP)
        return meter

    def test_no_new_loop_starts_after_a_refusal(self) -> None:
        from types import SimpleNamespace

        from maljan.agents.base_agent import spend_reached

        assert (
            spend_reached(SimpleNamespace(token_ledger=SimpleNamespace(spend=_meter_after(1.0))))
            is False
        )
        agent = SimpleNamespace(token_ledger=SimpleNamespace(spend=self._refused()))
        assert spend_reached(agent) is True

    def test_an_ask_is_refused_after_a_refusal(self) -> None:
        from types import SimpleNamespace
        from unittest.mock import MagicMock

        from maljan.agents.delegation import refusal

        meter = self._refused()
        container = MagicMock()
        container.config.agents.definitions = {"helper": SimpleNamespace(enabled=True)}
        caller = SimpleNamespace(
            name="boss", call_chain=(), token_ledger=SimpleNamespace(spend=meter)
        )
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(
                "maljan.agents.delegation._servers_the_caller_may_not_reach", lambda *a: []
            )
            said = refusal(container, caller, "helper")
        assert said is not None and "spend ceiling" in said

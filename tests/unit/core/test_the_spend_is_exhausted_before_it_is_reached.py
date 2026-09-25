"""A call refused or held for spend exhausts it: every gate and the reason read that.

At a 2.00 USD ceiling on ``deepseek-flash``, a loop turn's worst case passes
what is left well before the spend reaches the ceiling. That refusal used to
leave ``reached()`` false, so every new loop, chunk, ask and negotiation round
still started, the degradation reason was empty, and a closing answer was made
at its whole 393,216-token cap. The first refusal or held call now latches the
spend as exhausted; the gates and the reason read the latch; a held call is
given what the remaining spend pays for and never less than the minimum answer
room, the overshoot recorded.
"""

from __future__ import annotations

import pytest

from maljan.analysis.run_summary import spend_lines
from maljan.core.spend import MIN_ANSWER_TOKENS, SpendCeilingStop, SpendMeter

FLASH = "deepseek-flash"
FLASH_CAP = 393_216


def _meter_after(spent_usd: float) -> SpendMeter:
    """A 2.00 USD meter at the vendored flash prices, with ``spent_usd`` of output billed."""
    meter = SpendMeter(2.00)
    price = meter.price_of(FLASH)
    assert price is not None
    meter.settle({"input_tokens": 0, "output_tokens": int(spent_usd / price.output * 1e6)}, FLASH)
    return meter


class TestTheReviewsCase:
    def test_a_refused_turn_exhausts_the_spend_before_it_is_reached(self) -> None:
        meter = _meter_after(1.56)

        with pytest.raises(SpendCeilingStop):
            meter.admit(kind="loop turn", model=FLASH, prompt_chars=90_000, cap_tokens=FLASH_CAP)

        assert meter.reached() is False
        assert meter.exhausted() is True
        reason = meter.reason()
        assert "was exhausted: a call's worst case would have passed what was left" in reason
        snapshot = meter.snapshot()
        assert snapshot is not None
        assert snapshot["exhausted"] is True and snapshot["reached"] is False
        assert snapshot["exhausted_by"] == "a worst-case refusal"
        assert snapshot["exhausted_at_usd"] == pytest.approx(1.56, abs=0.001)
        assert "exhausted at 1.56" in spend_lines(snapshot)[0]

    def test_after_it_every_ordinary_call_is_refused(self) -> None:
        meter = _meter_after(1.56)
        with pytest.raises(SpendCeilingStop):
            meter.admit(kind="loop turn", model=FLASH, prompt_chars=90_000, cap_tokens=FLASH_CAP)
        with pytest.raises(SpendCeilingStop, match="is exhausted"):
            meter.admit(kind="loop turn", model=FLASH, prompt_chars=10, cap_tokens=10)

    def test_a_closing_answer_near_the_ceiling_gets_the_minimum_room_not_its_whole_cap(
        self,
    ) -> None:
        meter = _meter_after(1.992)

        held = meter.admit(kind="salvage", model=FLASH, prompt_chars=90_000, cap_tokens=FLASH_CAP)

        assert held == MIN_ANSWER_TOKENS == 8192
        (said,) = meter.snapshot()["held_calls"]
        assert "the minimum answer room" in said
        assert meter.exhausted() is True

    def test_a_held_call_with_room_above_the_minimum_gets_that_room(self) -> None:
        meter = _meter_after(1.60)
        held = meter.admit(kind="verdict", model=FLASH, prompt_chars=3_000, cap_tokens=FLASH_CAP)
        assert held is not None and MIN_ANSWER_TOKENS < held < FLASH_CAP

    def test_a_cap_below_the_minimum_is_the_answer_s_own(self) -> None:
        meter = _meter_after(1.999)
        assert meter.admit(kind="report", model=FLASH, prompt_chars=3_000, cap_tokens=4_096) is None
        assert "own 4,096-token cap" in meter.snapshot()["held_calls"][-1]


class TestTheGatesReadTheLatch:
    def test_no_new_loop_starts_after_a_refusal(self) -> None:
        from types import SimpleNamespace

        from maljan.agents.base_agent import spend_reached

        meter = _meter_after(1.56)
        agent = SimpleNamespace(token_ledger=SimpleNamespace(spend=meter))
        assert spend_reached(agent) is False
        with pytest.raises(SpendCeilingStop):
            meter.admit(kind="loop turn", model=FLASH, prompt_chars=90_000, cap_tokens=FLASH_CAP)
        assert spend_reached(agent) is True

    def test_an_ask_is_refused_after_a_refusal(self) -> None:
        from types import SimpleNamespace
        from unittest.mock import MagicMock

        from maljan.agents.delegation import refusal

        meter = _meter_after(1.56)
        with pytest.raises(SpendCeilingStop):
            meter.admit(kind="loop turn", model=FLASH, prompt_chars=90_000, cap_tokens=FLASH_CAP)
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

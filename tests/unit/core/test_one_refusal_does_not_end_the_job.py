"""A call the spend ceiling refuses is not the end of the job while smaller calls still fit.

Run 4 on ``deepseek-flash`` under a 2.00 USD ceiling: at 0.98 USD spent, a
mediation turn that could only be made at its whole 393,216-token cap was
refused, and that one refusal latched the spend as exhausted — every revision
after it was "not made: the spend ceiling is exhausted" with 0.12 USD still
spendable above the reserve. A refusal is now recorded and its caller takes its
salvage path; the spend is exhausted only when no call of any kind the job
makes would still be admitted.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from maljan.analysis.run_summary import spend_lines
from maljan.core.spend import LOOP_TURN_CALL, SpendCeilingStop, SpendMeter
from maljan.llm.context_window import CHARS_PER_TOKEN

FLASH = "deepseek-flash"
CAP = 393_216
# A Friday at noon UTC: off-peak, as run 4 was.
OFF_PEAK = datetime(2026, 9, 25, 12, 0, tzinfo=UTC)


def _run_4_before_the_refusal() -> SpendMeter:
    """0.12 USD spendable above the reserve, a revision's answer of 20k measured."""
    meter = SpendMeter(2.00, clock=lambda: OFF_PEAK)
    meter.settle({"input_tokens": 20_000, "output_tokens": 6_000}, FLASH, LOOP_TURN_CALL)
    meter.admit(kind="revision", model=FLASH, prompt_chars=56_000 * CHARS_PER_TOKEN, cap_tokens=CAP)
    meter.settle({"input_tokens": 56_000, "output_tokens": 20_000}, FLASH, "revision")
    # The rest of the tool phases, as uncached input: 1.88 USD spent in all.
    meter.settle(
        {"input_tokens": int((1.88 - meter.spent()) / 0.15 * 1e6), "output_tokens": 0},
        FLASH,
        LOOP_TURN_CALL,
    )
    assert meter.remaining() == pytest.approx(0.12, abs=1e-4)
    return meter


class TestOneRefusal:
    def test_a_whole_cap_call_is_refused_and_the_spend_is_not_exhausted(self) -> None:
        meter = _run_4_before_the_refusal()

        with pytest.raises(SpendCeilingStop, match="its whole 393,216-token cap"):
            meter.admit(
                kind="mediation turn",
                model=FLASH,
                prompt_chars=80_000 * CHARS_PER_TOKEN,
                cap_tokens=CAP,
                holdable=False,
            )

        assert meter.exhausted() is False
        snapshot = meter.snapshot()
        assert snapshot["exhausted"] is False
        assert snapshot["refused_calls"] == 1
        assert any("a mediation turn call" in said for said in snapshot["held_calls"])
        assert meter.reason() == ""
        assert any("so the job went on" in line for line in spend_lines(snapshot))

    def test_the_revisions_after_it_are_made_held(self) -> None:
        meter = _run_4_before_the_refusal()
        with pytest.raises(SpendCeilingStop):
            meter.admit(
                kind="mediation turn",
                model=FLASH,
                prompt_chars=80_000 * CHARS_PER_TOKEN,
                cap_tokens=CAP,
                holdable=False,
            )

        for _ in range(3):
            held = meter.admit(
                kind="revision",
                model=FLASH,
                prompt_chars=56_000 * CHARS_PER_TOKEN,
                cap_tokens=CAP,
            )
            assert held is not None and 20_000 <= held < CAP
            meter.settle({"input_tokens": 56_000, "output_tokens": 2_000}, FLASH, "revision")
        assert meter.exhausted() is False

    def test_the_spend_is_exhausted_once_no_call_of_any_kind_fits(self) -> None:
        meter = _run_4_before_the_refusal()
        # Spent down until not even a revision's smallest answer fits.
        meter.settle(
            {"input_tokens": int(0.115 / 0.15 * 1e6), "output_tokens": 0}, FLASH, LOOP_TURN_CALL
        )
        with pytest.raises(SpendCeilingStop):
            meter.admit(
                kind="revision",
                model=FLASH,
                prompt_chars=56_000 * CHARS_PER_TOKEN,
                cap_tokens=CAP,
            )
        assert meter.exhausted() is True
        assert meter.snapshot()["exhausted_by"] == "a refusal"
        assert "the smallest answer of any call this job makes" in meter.reason()
        # And from then on only the tail and a loop's closing answer are made.
        with pytest.raises(SpendCeilingStop, match="is exhausted"):
            meter.admit(kind="loop turn", model=FLASH, prompt_chars=10, cap_tokens=10)

    def test_a_refusal_of_the_only_kind_there_is_exhausts_at_once(self) -> None:
        meter = SpendMeter(0.10, clock=lambda: OFF_PEAK)
        with pytest.raises(SpendCeilingStop):
            meter.admit(kind="revision", model=FLASH, prompt_chars=4_000, cap_tokens=CAP)
        assert meter.exhausted() is True

"""The reserve is the verdict and report calls' own plan, not a tool loop's conversation.

The first reserve priced the largest prompt the job had sent — a tool-loop
turn of 200,000 tokens — as uncached input for every one of the eighteen
planned calls, and at peak it kept 1.64 of a 2.00 USD ceiling from the tool
phases. The reserve is now the next planned call's worst case plus the expected
charge of the others: each at its own kind's prompt (the window accounting's
allowance, or the prompt actually sent), its input at the job's measured
cache-hit share, and the answer measured of single-shot calls. A planned call
spends only above the share of the planned calls after it.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from langchain_core.messages import AIMessage

from maljan.core.spend import LOOP_TURN_CALL, SpendCeilingStop, SpendMeter
from maljan.llm.context_window import CHARS_PER_TOKEN

FLASH = "deepseek-flash"
CAP = 393_216
WINDOW = 1_048_576
ALLOWED = WINDOW - CAP  # what the window leaves a verdict or section prompt
# A weekday afternoon (off-peak), and the same weekday inside a peak window.
FRIDAY_OFF_PEAK = datetime(2026, 9, 25, 17, 0, tzinfo=UTC)
FRIDAY_PEAK = datetime(2026, 9, 25, 8, 0, tzinfo=UTC)
# What run2's tool-loop turns cost (the root-cause report's Defect 2 table).
RUN2_LOOPS_OFF_PEAK = 0.51
RUN2_LOOPS_PEAK = 1.01


def _turn(prompt: int, cached: int, answer: int) -> AIMessage:
    return AIMessage(
        content="",
        usage_metadata={
            "input_tokens": prompt,
            "output_tokens": answer,
            "total_tokens": prompt + answer,
            "input_token_details": {"cache_read": cached},
        },
    )


def _run2_shaped(
    when: datetime, loop_prompt: int = 200_000, single_answer: int = 9_000
) -> SpendMeter:
    """Run2's shape: a 2.00 USD ceiling, 18 planned tail calls, 200k-token loop turns."""
    meter = SpendMeter(2.00, clock=lambda: when)
    meter.plan_tail({"verdict": (FLASH, 1, ALLOWED), "report": (FLASH, 17, ALLOWED)})
    # A loop running: its turns are 85% cached, and reasoning answers of 26k tokens.
    meter.note_loop(
        "reverser", [_turn(loop_prompt, int(loop_prompt * 0.85), 26_000) for _ in range(3)], FLASH
    )
    if single_answer:
        # A validation retry: a single-shot call of 46k prompt tokens.
        meter.admit(
            kind="validation retry",
            model=FLASH,
            prompt_chars=46_000 * CHARS_PER_TOKEN,
            cap_tokens=CAP,
        )
        meter.settle(
            {"input_tokens": 46_000, "cached_input_tokens": 39_100, "output_tokens": single_answer},
            FLASH,
        )
    return meter


class TestARun2ShapedJob:
    @pytest.mark.parametrize(
        ("when", "needed"),
        [(FRIDAY_OFF_PEAK, RUN2_LOOPS_OFF_PEAK), (FRIDAY_PEAK, RUN2_LOOPS_PEAK)],
    )
    def test_the_tool_phases_keep_what_run2_s_loops_spent(
        self, when: datetime, needed: float
    ) -> None:
        meter = _run2_shaped(when)
        snapshot = meter.snapshot()
        reserve = snapshot["reserve_usd"]
        assert 2.00 - reserve >= needed, snapshot["reserve"]
        if when is FRIDAY_OFF_PEAK:
            assert reserve < 1.00, "off-peak the tool phases keep most of the ceiling"

    def test_the_reserve_does_not_grow_with_a_loop_s_conversation(self) -> None:
        small = _run2_shaped(FRIDAY_OFF_PEAK, loop_prompt=100_000).snapshot()["reserve_usd"]
        large = _run2_shaped(FRIDAY_OFF_PEAK, loop_prompt=238_000).snapshot()["reserve_usd"]
        # Only the cache-hit share moves, and it is the same 85% in both.
        assert large == pytest.approx(small, rel=0.01)

    def test_its_derivation_is_stated(self) -> None:
        rows = {row["kind"]: row for row in _run2_shaped(FRIDAY_OFF_PEAK).snapshot()["reserve"]}
        assert rows["report"]["prompt_tokens"] == ALLOWED
        assert "window accounting allows" in rows["report"]["prompt_from"]
        assert rows["verdict"]["prompt_tokens"] == 46_000
        assert rows["report"]["answer_tokens"] == 9_000
        assert "single-shot" in rows["report"]["answer_from"]
        assert rows["report"]["cache_hit_share"] == pytest.approx(0.85, abs=0.001)


class TestAPlannedCallSpendsItsOwnShare:
    def test_the_verdict_leaves_the_report_s_share_untouched(self) -> None:
        prices = {"m": {"input_usd_per_mtok": 0.0, "output_usd_per_mtok": 10.0}}
        meter = SpendMeter(1.0, prices, table={})
        meter.settle({"input_tokens": 0, "output_tokens": 10_000}, "m")  # 0.10 spent
        meter.plan_tail({"verdict": ("m", 1, 1_000), "report": ("m", 1, 1_000)})
        # The report's planned share: 10,000 answer tokens at 10 USD a million.
        held = meter.admit(kind="verdict", model="m", prompt_chars=0, cap_tokens=393_216)
        assert held is not None and abs(held - 80_000) <= 1  # 0.90 left less 0.10 kept
        said = meter.snapshot()["held_calls"][-1]
        assert "being kept for the other planned verdict and report calls" in said

    def test_an_unplanned_retry_spends_only_what_is_left_above_the_plan(self) -> None:
        prices = {"m": {"input_usd_per_mtok": 0.0, "output_usd_per_mtok": 10.0}}
        meter = SpendMeter(0.45, prices, table={})
        meter.settle({"input_tokens": 0, "output_tokens": 10_000}, "m")  # 0.10 spent
        meter.plan_tail({"verdict": ("m", 1, 1_000), "report": ("m", 2, 1_000)})
        meter.admit(kind="verdict", model="m", prompt_chars=0, cap_tokens=10_000)
        meter.settle({"input_tokens": 0, "output_tokens": 10_000}, "m")  # 0.20 spent
        # A second verdict call is not planned: the two reports' 0.20 stay kept.
        with pytest.raises(SpendCeilingStop, match="other planned verdict and report calls"):
            meter.admit(kind="verdict", model="m", prompt_chars=0, cap_tokens=10_000)
        assert meter.admit(kind="report", model="m", prompt_chars=0, cap_tokens=10_000) is None


class TestAWindowEdge:
    def test_a_call_admitted_before_a_peak_window_reserves_the_peak_rate(self) -> None:
        # 00:59 on a Friday: the peak window opens at 01:00, inside the call's deadline.
        before = datetime(2026, 9, 25, 0, 59, tzinfo=UTC)
        meter = SpendMeter(10.0, clock=lambda: before)
        slot = object()
        meter.admit(
            kind="revision",
            model=FLASH,
            prompt_chars=0,
            cap_tokens=1_000_000,
            slot=slot,
            deadline_s=120,
        )
        assert meter.committed() == pytest.approx(1.2)  # the peak output rate
        meter.release(slot)
        meter.admit(
            kind="revision",
            model=FLASH,
            prompt_chars=0,
            cap_tokens=1_000_000,
            slot=slot,
            deadline_s=30,
        )
        assert meter.committed() == pytest.approx(0.6)  # sent and settled before the edge


class TestLoopTurnsAreMeasuredApart:
    def test_a_loop_turn_does_not_set_the_minimum_of_a_single_shot_call(self) -> None:
        prices = {"m": {"input_usd_per_mtok": 0.0, "output_usd_per_mtok": 10.0}}
        meter = SpendMeter(1.0, prices, table={})
        meter.settle({"input_tokens": 0, "output_tokens": 500}, "m", LOOP_TURN_CALL)
        # A loop turn is held at the loop's own measure.
        assert (
            meter.admit(kind="loop turn", model="m", prompt_chars=0, cap_tokens=393_216) is not None
        )
        # 0.995 left pays for 99,500 tokens, under the verdict's configured cap,
        # and no single-shot answer is measured: the cap is its smallest answer.
        with pytest.raises(SpendCeilingStop, match="its configured output cap"):
            meter.admit(kind="verdict", model="m", prompt_chars=0, cap_tokens=393_216)

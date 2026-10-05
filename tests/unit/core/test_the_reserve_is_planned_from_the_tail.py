"""The reserve is the verdict and report calls' own plan, not a tool loop's conversation.

The first reserve priced the largest prompt the job had sent — a tool-loop
turn of 200,000 tokens — as uncached input for every one of the eighteen
planned calls, and at peak it kept 1.64 of a 2.00 USD ceiling from the tool
phases. The next one priced a report call's prompt at the window's whole
allowance and its answer at the largest single-shot answer measured, which
kept 0.90 USD of a 2.00 USD ceiling for a tail that cost about 0.3. The reserve
is now what each planned call's admission demands — its prompt as uncached
input and its planned answer — at the prompt it will be sent (the largest of
its kind, else the largest single-shot prompt, else the largest opening
prompt of a conversation, bounded by the window's allowance) and the answer
this job measured (the verdict's largest single-shot answer, a report call's
mean). Each row also states its expected charge at the cache-hit share. A
planned call spends only above the share of the planned calls after it.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from langchain_core.messages import AIMessage

from maljan.core.spend import LOOP_TURN_CALL, SpendCeilingStop, SpendMeter, validation_retry
from maljan.llm.context_window import CHARS_PER_TOKEN

FLASH = "deepseek-flash"
CAP = 393_216
WINDOW = 1_048_576
ALLOWED = WINDOW - CAP  # what the window leaves a verdict or section prompt
# A weekday afternoon (off-peak), and the same weekday inside a peak window.
FRIDAY_OFF_PEAK = datetime(2026, 9, 25, 17, 0, tzinfo=UTC)
FRIDAY_PEAK = datetime(2026, 9, 25, 8, 0, tzinfo=UTC)
# What the tool-loop turns of a long paid run on this model cost, off-peak and
# at the peak rate: what the tool phases of such a job must be left.
LONG_RUN_LOOPS_OFF_PEAK = 0.51
LONG_RUN_LOOPS_PEAK = 1.01


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


def _plan(meter: SpendMeter) -> None:
    meter.plan_tail({"verdict": (FLASH, 1, ALLOWED, CAP), "report": (FLASH, 17, ALLOWED, CAP)})


def _a_long_paid_run(
    when: datetime, loop_prompt: int = 200_000, single_answer: int = 9_000
) -> SpendMeter:
    """A 2.00 USD ceiling, 18 planned calls, and a loop of 200k-token turns 85% cached."""
    meter = SpendMeter(2.00, clock=lambda: when)
    _plan(meter)
    # A loop running: its first turn read nothing from the cache, the ones
    # after it 85%, with reasoning answers of 26k tokens.
    meter.note_loop(
        "reverser",
        [
            _turn(loop_prompt, 0, 26_000),
            *[_turn(loop_prompt, int(loop_prompt * 0.85), 26_000) for _ in range(3)],
        ],
        FLASH,
    )
    if single_answer:
        # A validation retry: a single-shot call of 46k prompt tokens.
        meter.settle(
            {"input_tokens": 46_000, "cached_input_tokens": 0, "output_tokens": single_answer},
            FLASH,
        )
        meter._largest_prompt["single"] = 46_000
    return meter


class TestALongPaidRun:
    @pytest.mark.parametrize(
        ("when", "needed"),
        [(FRIDAY_OFF_PEAK, LONG_RUN_LOOPS_OFF_PEAK), (FRIDAY_PEAK, LONG_RUN_LOOPS_PEAK)],
    )
    def test_the_tool_phases_keep_what_a_long_paid_run_s_loops_spent(
        self, when: datetime, needed: float
    ) -> None:
        meter = _a_long_paid_run(when)
        snapshot = meter.snapshot()
        reserve = snapshot["reserve_usd"]
        assert 2.00 - reserve >= needed, snapshot["reserve"]
        if when is FRIDAY_OFF_PEAK:
            assert reserve < 1.00, "off-peak the tool phases keep most of the ceiling"

    def test_the_reserve_does_not_grow_with_a_loop_s_conversation(self) -> None:
        small = _a_long_paid_run(FRIDAY_OFF_PEAK, loop_prompt=100_000).snapshot()["reserve_usd"]
        large = _a_long_paid_run(FRIDAY_OFF_PEAK, loop_prompt=238_000).snapshot()["reserve_usd"]
        # Only the cache-hit share moves, and it is the same 85% in both.
        assert large == pytest.approx(small, rel=0.01)

    def test_its_derivation_is_stated(self) -> None:
        rows = {row["kind"]: row for row in _a_long_paid_run(FRIDAY_OFF_PEAK).snapshot()["reserve"]}
        # The prompt a report call will be sent, not the window's allowance.
        assert rows["report"]["prompt_tokens"] == 46_000
        assert "largest single-shot prompt sent" in rows["report"]["prompt_from"]
        assert rows["verdict"]["prompt_tokens"] == 46_000
        assert rows["report"]["answer_tokens"] == 9_000
        assert "mean of the 1 single-shot answer(s)" in rows["report"]["answer_from"]
        # The loop's first turn, which read nothing from the cache, is left out.
        assert rows["report"]["cache_hit_share"] == pytest.approx(0.85, abs=0.001)


class TestTheFirstCallsOfAJob:
    """A job's first calls read nothing from the cache; they do not price the plan."""

    def test_three_analysts_starting_at_once_are_all_admitted(self) -> None:
        meter = SpendMeter(2.00, clock=lambda: FRIDAY_OFF_PEAK)
        _plan(meter)
        # One triage turn first: a conversation's first call, nothing cached.
        meter.note_loop("triage", [_turn(20_000, 0, 3_000)], FLASH)
        meter.forget_loop("triage")
        meter.settle({"input_tokens": 20_000, "output_tokens": 3_000}, FLASH, LOOP_TURN_CALL)
        # Three analysts start in parallel, each on its first, uncached turn.
        slots = [object(), object(), object()]
        for slot in slots:
            meter.admit(
                kind="loop turn",
                model=FLASH,
                prompt_chars=20_000 * CHARS_PER_TOKEN,
                cap_tokens=CAP,
                slot=slot,
            )
        for index, slot in enumerate(slots):
            meter.note_loop(slot, [_turn(20_000, 0, 3_000)], FLASH)
            # And their second turns.
            meter.admit(
                kind="loop turn",
                model=FLASH,
                prompt_chars=40_000 * CHARS_PER_TOKEN,
                cap_tokens=CAP,
                slot=(slot, index),
            )
        assert meter.exhausted() is False
        reserve = meter.snapshot()["reserve_usd"]
        # With no single-shot answer measured the verdict is planned at its
        # whole cap, and every planned call with one validation retry: the
        # largest the plan is, and the tool phases still keep most of the
        # ceiling.
        assert reserve < 0.80
        assert 2.00 - reserve > 1.20

    def test_at_the_peak_rate_the_plan_still_leaves_the_tool_phases_the_most(self) -> None:
        meter = SpendMeter(2.00, clock=lambda: FRIDAY_PEAK)
        _plan(meter)
        meter.settle({"input_tokens": 20_000, "output_tokens": 3_000}, FLASH, LOOP_TURN_CALL)
        # Once a single-shot answer is measured (a validation retry of 46k
        # prompt tokens and a 9k answer), the plan stops counting on the
        # verdict's whole cap.
        meter.settle({"input_tokens": 46_000, "output_tokens": 9_000}, FLASH)
        meter._largest_prompt["single"] = 46_000
        assert 2.00 - meter.snapshot()["reserve_usd"] >= LONG_RUN_LOOPS_PEAK


class TestTheVerdictsRowCoversItsAdmission:
    def test_with_no_single_shot_answer_the_verdict_is_planned_at_its_whole_cap(self) -> None:
        meter = SpendMeter(2.00, clock=lambda: FRIDAY_OFF_PEAK)
        _plan(meter)
        meter.settle({"input_tokens": 1_000, "output_tokens": 3_000}, FLASH, LOOP_TURN_CALL)
        # The tool phases spend down to the reserve (uncached input at 0.15 a million).
        down_to = 2.00 - meter.snapshot()["reserve_usd"] - meter.spent()
        meter.settle(
            {"input_tokens": int(down_to / 0.15 * 1e6) - 1, "output_tokens": 0},
            FLASH,
            LOOP_TURN_CALL,
        )
        # What the verdict's admission demands — the prompt planned for it (the
        # opening prompt measured) and its whole cap, no single-shot answer
        # being measured — is what was kept: it is made.
        row = {r["kind"]: r for r in meter.snapshot()["reserve"]}["verdict"]
        assert row["prompt_tokens"] == 1_000
        assert (
            meter.admit(
                kind="verdict",
                model=FLASH,
                prompt_chars=1_000 * CHARS_PER_TOKEN,
                cap_tokens=CAP,
            )
            is None
        )


class TestAPlannedCallSpendsItsOwnShare:
    def test_the_verdict_leaves_the_report_s_share_untouched(self) -> None:
        prices = {"m": {"input_usd_per_mtok": 0.0, "output_usd_per_mtok": 10.0}}
        meter = SpendMeter(1.0, prices, table={})
        meter.settle({"input_tokens": 0, "output_tokens": 10_000}, "m")  # 0.10 spent
        meter.plan_tail({"verdict": ("m", 1, 1_000), "report": ("m", 1, 1_000)})
        # Kept: the verdict's own validation retry, the report call and its
        # retry, 10,000 answer tokens at 10 USD a million each.
        held = meter.admit(kind="verdict", model="m", prompt_chars=0, cap_tokens=393_216)
        assert held is not None and abs(held - 60_000) <= 1  # 0.90 left less 0.30 kept
        said = meter.snapshot()["held_calls"][-1]
        assert "being kept for the other planned verdict and report calls" in said

    def test_a_planned_retry_is_made_and_an_unplanned_call_spends_only_above_the_plan(
        self,
    ) -> None:
        prices = {"m": {"input_usd_per_mtok": 0.0, "output_usd_per_mtok": 10.0}}
        meter = SpendMeter(0.75, prices, table={})
        meter.settle({"input_tokens": 0, "output_tokens": 10_000}, "m")  # 0.10 spent
        meter.plan_tail({"verdict": ("m", 1, 1_000), "report": ("m", 2, 1_000)})
        meter.admit(kind="verdict", model="m", prompt_chars=0, cap_tokens=10_000)
        meter.settle({"input_tokens": 0, "output_tokens": 10_000}, "m", "verdict")  # 0.20
        # The verdict's validation retry was planned: it is made.
        with validation_retry():
            assert meter.admit(kind="verdict", model="m", prompt_chars=0, cap_tokens=10_000) is None
        meter.settle({"input_tokens": 0, "output_tokens": 10_000}, "m", "verdict")  # 0.30
        # A third verdict call is planned by nothing: the two reports and their
        # retries, 0.40, stay kept.
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

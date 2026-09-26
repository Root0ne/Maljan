"""The reserve for the verdict and the report is what they really cost, and never less.

A 2.00 USD DeepSeek run kept 0.90 USD for the verdict and the report through
its revision round: each of the seventeen report calls was planned at the
whole window's prompt allowance and at the largest single-shot answer the job
had measured. What its tail really made was twenty-seven calls: the verdict
and one validation retry of it, the narrative, sixteen sections and eight
section retries — about 0.42 USD off-peak in the shape below.

The shape here is that run's:
- a verdict and seventeen report calls planned on a 1,048,576-token window
  with a 393,216-token cap;
- tool loops whose first turn reads 30k prompt tokens and whose later turns
  read 200k, 85% of them cached;
- revisions of 56k prompt tokens whose answers average 16k (what the run's
  report calls averaged: 399,775 output tokens over 25 calls), the largest at
  40k.

The report calls played out read 53% of their prompt from the cache after the
first, as that run's did.
"""

from __future__ import annotations

import contextlib
from datetime import UTC, datetime

import pytest
from langchain_core.messages import AIMessage

from maljan.core.spend import LOOP_TURN_CALL, SpendCeilingStop, SpendMeter, validation_retry
from maljan.llm.context_window import CHARS_PER_TOKEN

FLASH = "deepseek-flash"
CAP = 393_216
WINDOW = 1_048_576
ALLOWED = WINDOW - CAP
REPORT_CALLS = 17
OFF_PEAK = datetime(2026, 9, 25, 12, 0, tzinfo=UTC)
REVISION_PROMPT = 56_000
REVISION_ANSWERS = [9_000, 11_000, 12_000, 13_000, 14_000, 15_000, 16_000, 40_000, 14_000, 16_000]
REPORT_ANSWER = 16_000
REPORT_CACHE_SHARE = 0.53
VERDICT_ANSWER = 30_000
# Which of the seventeen report calls (the narrative first) were asked again.
RETRIED_REPORT_CALLS = {2, 4, 5, 6, 7, 9, 12, 14}
# Off-peak deepseek-flash, per token.
INPUT, CACHED, OUTPUT = 0.15e-6, 0.003e-6, 0.6e-6


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


def _a_paid_run_at_its_revisions() -> SpendMeter:
    meter = SpendMeter(2.00, clock=lambda: OFF_PEAK)
    meter.plan_tail(
        {"verdict": (FLASH, 1, ALLOWED, CAP), "report": (FLASH, REPORT_CALLS, ALLOWED, CAP)}
    )
    turns = [_turn(30_000, 0, 26_000), *[_turn(200_000, 170_000, 26_000) for _ in range(5)]]
    meter.note_loop("reverser", turns, FLASH)
    meter.forget_loop("reverser")
    for turn in turns:
        usage = turn.usage_metadata or {}
        meter.settle(
            {
                "input_tokens": usage["input_tokens"],
                "cached_input_tokens": usage["input_token_details"]["cache_read"],
                "output_tokens": usage["output_tokens"],
            },
            FLASH,
            LOOP_TURN_CALL,
        )
    for answer in REVISION_ANSWERS:
        meter.admit(
            kind="revision",
            model=FLASH,
            prompt_chars=REVISION_PROMPT * CHARS_PER_TOKEN,
            cap_tokens=CAP,
        )
        meter.settle({"input_tokens": REVISION_PROMPT, "output_tokens": answer}, FLASH, "revision")
    return meter


def _the_tail() -> list[tuple[str, bool, int, int, int]]:
    """``(kind, retry, prompt, cached, answer)`` for each of the tail's twenty-seven calls."""
    later = int(REVISION_PROMPT * REPORT_CACHE_SHARE)
    calls = [
        ("verdict", False, REVISION_PROMPT, 0, VERDICT_ANSWER),
        ("verdict", True, REVISION_PROMPT + VERDICT_ANSWER, later, VERDICT_ANSWER),
    ]
    for index in range(1, REPORT_CALLS + 1):
        calls.append(("report", False, REVISION_PROMPT, 0 if index == 1 else later, REPORT_ANSWER))
        if index in RETRIED_REPORT_CALLS:
            calls.append(("report", True, REVISION_PROMPT + REPORT_ANSWER, later, REPORT_ANSWER))
    return calls


def _cost(prompt: int, cached: int, answer: int) -> float:
    return (prompt - cached) * INPUT + cached * CACHED + answer * OUTPUT


class TestALongPaidRunsTail:
    def test_the_tail_is_twenty_seven_calls(self) -> None:
        assert len(_the_tail()) == 27

    def test_the_reserve_covers_the_tail_and_stays_near_it(self) -> None:
        snapshot = _a_paid_run_at_its_revisions().snapshot()
        reserve = snapshot["reserve_usd"]
        tail = sum(_cost(p, c, a) for _k, _r, p, c, a in _the_tail())
        assert tail == pytest.approx(0.42, abs=0.01)
        # Every planned call and one retry of each, none made yet: above the
        # real tail, and well below the 0.90 USD kept before.
        assert tail <= reserve <= 0.80, snapshot["reserve"]

    def test_the_plan_is_this_job_s_measured_sizes(self) -> None:
        rows = {row["kind"]: row for row in _a_paid_run_at_its_revisions().snapshot()["reserve"]}
        report, verdict = rows["report"], rows["verdict"]
        assert report["prompt_tokens"] == REVISION_PROMPT
        assert "largest single-shot prompt sent" in report["prompt_from"]
        mean = -(-sum(REVISION_ANSWERS) // len(REVISION_ANSWERS))
        assert report["answer_tokens"] == mean
        assert (
            f"mean of the {len(REVISION_ANSWERS)} single-shot answer(s)" in (report["answer_from"])
        )
        assert verdict["answer_tokens"] == max(REVISION_ANSWERS)
        assert report["retries"] == REPORT_CALLS and verdict["retries"] == 1
        assert "one per planned call" in report["retries_from"]
        # The expected charge reads the cache-hit share; the reserve does not
        # count on it, because each call's admission prices its prompt uncached.
        assert report["cache_hit_share"] == pytest.approx(0.85, abs=0.001)
        assert report["expected_usd"] < report["usd"]

    def test_every_call_of_the_tail_and_its_retries_is_made_on_what_was_kept(self) -> None:
        meter = _a_paid_run_at_its_revisions()
        # The tool phases spend down to the reserve exactly.
        reserve = meter.snapshot()["reserve_usd"]
        meter.settle(
            {"input_tokens": int((2.00 - reserve - meter.spent()) / INPUT), "output_tokens": 0},
            FLASH,
            LOOP_TURN_CALL,
        )
        assert meter.remaining() == pytest.approx(reserve, abs=1e-6)
        with pytest.raises(SpendCeilingStop):
            meter.admit(kind="revision", model=FLASH, prompt_chars=3_000, cap_tokens=CAP)

        made = []
        for kind, retry, prompt, cached, answer in _the_tail():
            slot = object()
            with validation_retry() if retry else contextlib.nullcontext():
                meter.admit(
                    kind=kind,
                    model=FLASH,
                    prompt_chars=prompt * CHARS_PER_TOKEN,
                    cap_tokens=CAP,
                    slot=slot,
                )
            meter.settle(
                {"input_tokens": prompt, "cached_input_tokens": cached, "output_tokens": answer},
                FLASH,
                "verdict" if kind == "verdict" else "report section",
            )
            meter.release(slot)
            made.append((kind, retry))

        assert len(made) == 27
        assert meter.spent() <= 2.00 + 1e-9
        rows = {row["kind"]: row for row in meter.snapshot().get("reserve") or []}
        assert rows == {}, "nothing is left planned once the tail is made"


class TestARetryIsCountedAsOne:
    def test_a_validation_loop_s_correction_turn_is_admitted_as_a_retry(self) -> None:
        from maljan.pipeline.validation import Violation, retry_with_feedback_sync

        meter = SpendMeter(10.00, clock=lambda: OFF_PEAK)
        meter.plan_tail({"report": (FLASH, 2, ALLOWED, CAP)})
        meter.settle({"input_tokens": 3_000, "output_tokens": 1_000}, FLASH, "revision")
        answers = iter(["wrong", "right"])

        def run(_turns: list) -> str:
            meter.admit(kind="report", model=FLASH, prompt_chars=3_000, cap_tokens=1_000)
            return next(answers)

        def check(parsed: str) -> list[Violation]:
            return [Violation("report.rule", "fix it")] if parsed == "wrong" else []

        retry_with_feedback_sync(run, [], [check], parse=str)

        row = {r["kind"]: r for r in meter.snapshot()["reserve"]}["report"]
        # One first call made and one retry: one report call left, kept with
        # (1 + 1) / (1 + 1) = one retry.
        assert row["calls"] == 1
        assert row["retries"] == 1
        assert "1 retry measured over 1 report call(s)" in row["retries_from"]

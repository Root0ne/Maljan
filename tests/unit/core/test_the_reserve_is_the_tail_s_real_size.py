"""The reserve for the verdict and the report is what they really cost, and never less.

Run 4 on ``deepseek-flash`` under a 2.00 USD ceiling kept 0.90 USD for the
verdict and the report through its revision round: each of the seventeen
report calls was planned at the whole window's prompt allowance and at the
largest single-shot answer the job had measured. Run 3's real verdict and
report cost about 0.3 USD off-peak.

The shape here is run 4's: a verdict and seventeen report calls planned on a
1,048,576-token window with a 393,216-token cap; tool loops of 200k-token turns
85% cached; revisions of 56k prompt tokens whose answers average 16k (what run
4's report calls averaged: 399,775 output tokens over 25 calls) with the
largest at 40k. The report calls it plays out read 53% of their prompt from
the cache after the first, as run 4's did (791,936 of 1,501,638 input tokens).
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
ALLOWED = WINDOW - CAP
REPORT_CALLS = 17
OFF_PEAK = datetime(2026, 9, 25, 12, 0, tzinfo=UTC)
REVISION_PROMPT = 56_000
REVISION_ANSWERS = [9_000, 11_000, 12_000, 13_000, 14_000, 15_000, 16_000, 40_000, 14_000, 16_000]
REPORT_ANSWER = 16_000
REPORT_CACHE_SHARE = 0.53
VERDICT_ANSWER = 30_000
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


def _run_4_at_its_revisions() -> SpendMeter:
    meter = SpendMeter(2.00, clock=lambda: OFF_PEAK)
    meter.plan_tail(
        {"verdict": (FLASH, 1, ALLOWED, CAP), "report": (FLASH, REPORT_CALLS, ALLOWED, CAP)}
    )
    turns = [_turn(200_000, 0, 26_000), *[_turn(200_000, 170_000, 26_000) for _ in range(5)]]
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


def _realistic_tail() -> float:
    """What the verdict and the seventeen report calls of this shape cost."""
    verdict = REVISION_PROMPT * INPUT + VERDICT_ANSWER * OUTPUT
    first = REVISION_PROMPT * INPUT + REPORT_ANSWER * OUTPUT
    later = (
        REVISION_PROMPT * ((1 - REPORT_CACHE_SHARE) * INPUT + REPORT_CACHE_SHARE * CACHED)
        + REPORT_ANSWER * OUTPUT
    )
    return verdict + first + later * (REPORT_CALLS - 1)


class TestRun4sShape:
    def test_the_reserve_is_close_to_what_the_tail_costs(self) -> None:
        snapshot = _run_4_at_its_revisions().snapshot()
        reserve = snapshot["reserve_usd"]
        tail = _realistic_tail()
        assert tail == pytest.approx(0.26, abs=0.01)
        # Near the real tail and nowhere near the 0.90 USD run 4 kept.
        assert tail <= reserve <= 0.40, snapshot["reserve"]

    def test_the_plan_is_this_job_s_measured_sizes(self) -> None:
        rows = {row["kind"]: row for row in _run_4_at_its_revisions().snapshot()["reserve"]}
        report, verdict = rows["report"], rows["verdict"]
        assert report["prompt_tokens"] == REVISION_PROMPT
        assert "largest single-shot prompt sent" in report["prompt_from"]
        mean = -(-sum(REVISION_ANSWERS) // len(REVISION_ANSWERS))
        assert report["answer_tokens"] == mean
        assert (
            f"mean of the {len(REVISION_ANSWERS)} single-shot answer(s)" in (report["answer_from"])
        )
        assert verdict["answer_tokens"] == max(REVISION_ANSWERS)
        # The expected charge reads the cache-hit share; the reserve does not
        # count on it, because each call's admission prices its prompt uncached.
        assert report["cache_hit_share"] == pytest.approx(0.85, abs=0.001)
        assert report["expected_usd"] < report["usd"]

    def test_the_tail_is_made_whole_on_what_was_kept(self) -> None:
        meter = _run_4_at_its_revisions()
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
        for index, (kind, answer) in enumerate(
            [("verdict", VERDICT_ANSWER)] + [("report", REPORT_ANSWER)] * REPORT_CALLS
        ):
            slot = object()
            meter.admit(
                kind=kind,
                model=FLASH,
                prompt_chars=REVISION_PROMPT * CHARS_PER_TOKEN,
                cap_tokens=CAP,
                slot=slot,
            )
            cached = int(REVISION_PROMPT * REPORT_CACHE_SHARE) if index > 1 else 0
            meter.settle(
                {
                    "input_tokens": REVISION_PROMPT,
                    "cached_input_tokens": cached,
                    "output_tokens": answer,
                },
                FLASH,
                "verdict" if kind == "verdict" else "report section",
            )
            meter.release(slot)
            made.append(kind)

        assert made == ["verdict"] + ["report"] * REPORT_CALLS
        assert meter.spent() <= 2.00 + 1e-9

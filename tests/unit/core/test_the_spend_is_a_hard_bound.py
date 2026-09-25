"""The spend ceiling is a hard bound, and it keeps room for the verdict and the report.

Every admitted call reserves its worst case — its prompt as uncached input and
its held output cap — until it returns, so two calls running at once never
spend the same remainder. The verdict and the report calls a job will make are
planned from its start, and the other calls spend only above what those would
cost at this job's measured sizes. Nothing is sent that could take the job
past its ceiling.
"""

from __future__ import annotations

import random
import threading
from datetime import UTC, datetime

import pytest

from maljan.core.spend import SpendCeilingStop, SpendMeter
from maljan.llm.context_window import CHARS_PER_TOKEN

MODEL = "deepseek-v4-pro"
PRICES = {
    MODEL: {"input_usd_per_mtok": 1.0, "cached_input_usd_per_mtok": 0.1, "output_usd_per_mtok": 4.0}
}
NOW = datetime(2026, 9, 25, 12, 0, tzinfo=UTC)
# A prompt of 20,000 tokens, as the window accounting measures one.
PROMPT_CHARS = 20_000 * CHARS_PER_TOKEN


def _meter(ceiling: float = 1.0, measured: int = 10_000) -> SpendMeter:
    meter = SpendMeter(ceiling, PRICES, table={}, clock=lambda: NOW)
    if measured:
        meter.settle({"input_tokens": 0, "output_tokens": measured}, MODEL)
    return meter


class TestCallsInFlight:
    def test_two_parallel_calls_with_room_for_one_do_not_share_it(self) -> None:
        meter = _meter()  # 0.04 USD spent, 0.96 left
        first, second, third = object(), object(), object()

        whole = meter.admit(
            kind="revision", model=MODEL, prompt_chars=0, cap_tokens=200_000, slot=first
        )
        assert whole is None  # 0.80 USD, reserved while it runs

        held = meter.admit(
            kind="revision", model=MODEL, prompt_chars=0, cap_tokens=200_000, slot=second
        )
        assert held is not None and abs(held - 40_000) <= 1  # the 0.16 USD left

        with pytest.raises(SpendCeilingStop):
            meter.admit(
                kind="revision", model=MODEL, prompt_chars=0, cap_tokens=200_000, slot=third
            )
        assert meter.committed() <= 1.0 + 1e-9

    def test_a_returned_call_settles_at_its_cost_and_frees_the_rest(self) -> None:
        meter = _meter(measured=10_000)
        slot = object()
        meter.admit(kind="revision", model=MODEL, prompt_chars=0, cap_tokens=200_000, slot=slot)
        assert meter.remaining() == pytest.approx(0.16)
        meter.settle({"input_tokens": 0, "output_tokens": 5_000}, MODEL)
        meter.release(slot)
        assert meter.remaining() == pytest.approx(1.0 - 0.04 - 0.02)

    def test_the_held_context_releases_on_failure(self) -> None:
        meter = _meter()
        with (
            pytest.raises(RuntimeError),
            meter.held(kind="revision", model=MODEL, prompt_chars=0, cap_tokens=100_000),
        ):
            assert meter.remaining() == pytest.approx(0.56)
            raise RuntimeError("the call failed")
        assert meter.remaining() == pytest.approx(0.96)

    def test_a_loop_s_turn_is_released_once_the_loop_counts_it(self) -> None:
        from langchain_core.messages import AIMessage

        meter = _meter()
        key = object()
        meter.admit(kind="loop turn", model=MODEL, prompt_chars=0, cap_tokens=50_000, slot=key)
        assert meter.remaining() == pytest.approx(0.96 - 0.2)
        turn = AIMessage(
            content="",
            usage_metadata={"input_tokens": 0, "output_tokens": 1_000, "total_tokens": 1_000},
        )
        meter.note_loop(key, [turn], MODEL)
        assert meter.remaining() == pytest.approx(0.96 - 0.004)
        meter.forget_loop(key)
        assert meter.remaining() == pytest.approx(0.96)

    def test_a_loop_s_turn_keeps_room_for_the_loop_s_closing_answer(self) -> None:
        meter = _meter(ceiling=0.10, measured=10_000)  # 0.06 left; an answer costs 0.04
        with pytest.raises(SpendCeilingStop, match="closing answer"):
            meter.admit(kind="loop turn", model=MODEL, prompt_chars=0, cap_tokens=10_000)
        # The closing answer itself still fits.
        assert meter.admit(kind="salvage", model=MODEL, prompt_chars=0, cap_tokens=10_000) is None


class TestTheReserveForTheVerdictAndTheReport:
    def _planned(self) -> SpendMeter:
        meter = _meter(ceiling=1.0, measured=10_000)
        # A single-shot prompt of 20,000 tokens has been sent.
        meter.admit(kind="revision", model=MODEL, prompt_chars=PROMPT_CHARS, cap_tokens=10_000)
        meter.plan_tail({"verdict": (MODEL, 1), "report": (MODEL, 4)})
        return meter

    def test_is_sized_from_the_measured_prompt_and_answer(self) -> None:
        snapshot = self._planned().snapshot()
        # Five calls of 20,000 prompt tokens at 1.0 and 10,000 answer tokens at
        # 4.0 per million: 0.06 USD each.
        assert snapshot["reserve_usd"] == pytest.approx(0.30)
        rows = {row["kind"]: row for row in snapshot["reserve"]}
        assert rows["report"]["calls"] == 4 and rows["report"]["prompt_tokens"] == 20_000
        assert rows["verdict"]["answer_tokens"] == 10_000

    def test_other_calls_spend_only_above_it(self) -> None:
        meter = self._planned()  # 0.96 left, 0.30 kept
        held = meter.admit(kind="loop turn", model=MODEL, prompt_chars=0, cap_tokens=393_216)
        # 0.66 USD above the reserve, less the closing answer's 0.04 USD.
        assert held is not None and abs(held - 155_000) <= 1
        assert (
            "0.3000 USD being kept for the verdict and the report"
            in (meter.snapshot()["held_calls"][-1])
        )

    def test_the_verdict_and_the_report_spend_it(self) -> None:
        meter = self._planned()
        meter.settle({"input_tokens": 660_000, "output_tokens": 0}, MODEL)  # 0.30 left
        with pytest.raises(SpendCeilingStop, match="kept for the verdict and the report"):
            meter.admit(kind="revision", model=MODEL, prompt_chars=0, cap_tokens=10_000)
        assert meter.admit(kind="verdict", model=MODEL, prompt_chars=0, cap_tokens=10_000) is None
        for _ in range(4):
            assert (
                meter.admit(
                    kind="report", model=MODEL, prompt_chars=PROMPT_CHARS, cap_tokens=10_000
                )
                is None
            )
        assert meter.snapshot().get("reserve_usd") is None

    def test_with_nothing_measured_it_is_not_sized(self) -> None:
        meter = _meter(measured=0)
        meter.plan_tail({"verdict": (MODEL, 1), "report": (MODEL, 16)})
        assert "reserve_usd" not in meter.snapshot()


class TestASimulatedJob:
    def test_never_commits_or_spends_past_the_ceiling(self) -> None:
        rng = random.Random(7)
        ceiling = 2.0
        meter = SpendMeter(ceiling, PRICES, table={}, clock=lambda: NOW)
        meter.plan_tail({"verdict": (MODEL, 1), "report": (MODEL, 16)})
        lock = threading.Lock()
        peak = [0.0]

        def one_call(kind: str) -> None:
            slot = object()
            prompt = rng.randint(1_000, 60_000)
            cap = 64_000
            try:
                bound = meter.admit(
                    kind=kind, model=MODEL, prompt_chars=prompt * 4, cap_tokens=cap, slot=slot
                )
            except SpendCeilingStop:
                return
            with lock:
                peak[0] = max(peak[0], meter.committed())
            allowed = cap if bound is None else bound
            out = rng.randint(min(allowed, 2_000), allowed)
            cached = rng.randint(0, prompt)
            meter.settle(
                {"input_tokens": prompt, "cached_input_tokens": cached, "output_tokens": out},
                MODEL,
            )
            meter.release(slot)

        kinds = ["loop turn"] * 60 + ["revision"] * 10 + ["salvage"] * 5
        threads = [threading.Thread(target=one_call, args=(kind,)) for kind in kinds]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        for kind in ["verdict"] + ["report"] * 16:
            one_call(kind)

        assert peak[0] <= ceiling + 1e-9
        assert meter.spent() <= ceiling + 1e-9

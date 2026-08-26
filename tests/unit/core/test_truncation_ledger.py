"""The counters behind the P6 numbers, tested independently of the pipeline.

*Chasing Shadows*' pitfall P6 asks for truncation **frequency**. A frequency is a
ratio, and a ratio reported from an uninstrumented denominator is worse than no
number at all — so the arithmetic gets the same treatment every other reported
number in this repo gets (the ``test_*_scoring.py`` convention): pure helpers
tested apart from the accumulation, and the accumulation tested apart from the
call sites.

Two properties are load-bearing and each has a test that would fail loudly:

* **pass-throughs are counted.** ``tool_output_calls`` must include the calls
  that were *under* the limit, or the rate is computed against the wrong
  denominator and every run reads as 100% truncated.
* **telemetry never raises.** A ledger that can throw would turn a reporting
  detail into a failed analysis, which is a far worse bug than a missing count.
"""

from __future__ import annotations

import threading

import pytest

from maljan.core.truncation_ledger import (
    INTEGRITY_REASONS,
    TruncationLedger,
    chars_dropped,
    hit_length_cap,
    record_guardrail_outcome,
    record_judge_response,
    truncation_rate,
)


class TestTruncationRate:
    def test_zero_calls_is_zero_not_a_division_error(self) -> None:
        """A run that called nothing truncated nothing; it did not error."""
        assert truncation_rate(0, 0) == 0.0

    def test_negative_denominator_is_treated_as_no_calls(self) -> None:
        assert truncation_rate(3, -1) == 0.0

    @pytest.mark.parametrize(
        ("over", "calls", "expected"),
        [(0, 10, 0.0), (5, 10, 0.5), (10, 10, 1.0), (1, 3, 1 / 3)],
    )
    def test_ordinary_ratios(self, over: int, calls: int, expected: float) -> None:
        assert truncation_rate(over, calls) == pytest.approx(expected)

    def test_a_negative_numerator_clamps_rather_than_going_below_zero(self) -> None:
        assert truncation_rate(-4, 10) == 0.0


class TestCharsDropped:
    def test_the_ordinary_case(self) -> None:
        assert chars_dropped(1000, 400) == 600

    def test_a_summariser_that_expands_reports_zero_not_a_negative_loss(self) -> None:
        """FunctionSummarizer may return more text than it was given for a short
        input. That is not negative truncation; it is no truncation."""
        assert chars_dropped(100, 250) == 0

    def test_nothing_in_nothing_dropped(self) -> None:
        assert chars_dropped(0, 0) == 0


class TestToolOutputAccounting:
    def test_a_pass_through_still_counts_as_a_call(self) -> None:
        """The denominator bug this test exists to prevent: if pass-throughs are
        not counted, every run reports a 100% truncation rate."""
        ledger = TruncationLedger()
        ledger.record_tool_output(chars_in=50, chars_kept=50, over_limit=False)

        snap = ledger.snapshot()
        assert snap["tool_output_calls"] == 1
        assert snap["tool_output_over_limit"] == 0
        assert snap["tool_output_truncation_rate"] == 0.0

    def test_summarised_and_hard_truncated_are_separate_outcomes(self) -> None:
        """They are not the same event: one preserves meaning, one cuts mid-token."""
        ledger = TruncationLedger()
        ledger.record_tool_output(chars_in=9000, chars_kept=1200, over_limit=True, summarised=True)
        ledger.record_tool_output(
            chars_in=9000, chars_kept=6020, over_limit=True, hard_truncated=True
        )

        snap = ledger.snapshot()
        assert snap["tool_output_calls"] == 2
        assert snap["tool_output_over_limit"] == 2
        assert snap["tool_output_summarised"] == 1
        assert snap["tool_output_hard_truncated"] == 1
        assert snap["tool_output_truncation_rate"] == 1.0

    def test_chars_dropped_accumulates_across_calls(self) -> None:
        ledger = TruncationLedger()
        ledger.record_tool_output(chars_in=1000, chars_kept=600, over_limit=True)
        ledger.record_tool_output(chars_in=500, chars_kept=500, over_limit=False)

        assert ledger.snapshot()["tool_output_chars_dropped"] == 400

    def test_negative_inputs_are_clamped_not_subtracted(self) -> None:
        ledger = TruncationLedger()
        ledger.record_tool_output(chars_in=-5, chars_kept=-5, over_limit=False)

        snap = ledger.snapshot()
        assert snap["tool_output_chars_in"] == 0
        assert snap["tool_output_chars_kept"] == 0


class TestLoopAndGenerationCeilings:
    def test_react_loops_count_both_outcomes(self) -> None:
        ledger = TruncationLedger()
        ledger.record_react_loop(hit_step_cap=False)
        ledger.record_react_loop(hit_step_cap=True)
        ledger.record_react_loop(hit_step_cap=False)

        snap = ledger.snapshot()
        assert snap["react_invocations"] == 3
        assert snap["react_step_cap_hits"] == 1
        assert snap["react_step_cap_rate"] == pytest.approx(1 / 3)

    def test_judge_token_cap(self) -> None:
        ledger = TruncationLedger()
        ledger.record_judge_call(hit_token_cap=True)

        snap = ledger.snapshot()
        assert snap["judge_invocations"] == 1
        assert snap["judge_token_cap_rate"] == 1.0


class TestIntegrityPassAccounting:
    def test_reasons_accumulate_per_category(self) -> None:
        ledger = TruncationLedger()
        ledger.record_integrity_pass(
            objects_in=10,
            objects_out=7,
            dropped={"empty_pattern": 2, "dangling_relationship": 1},
        )

        snap = ledger.snapshot()
        assert snap["integrity_objects_removed"] == 3
        dropped = snap["integrity_dropped"]
        assert isinstance(dropped, dict)
        assert dropped["empty_pattern"] == 2
        assert dropped["dangling_relationship"] == 1
        assert dropped["duplicate_indicator"] == 0

    def test_an_unknown_reason_is_ignored_rather_than_inventing_a_category(self) -> None:
        """A typo at a call site must not create a category in the C7 report."""
        ledger = TruncationLedger()
        ledger.record_integrity_pass(objects_in=3, objects_out=3, dropped={"typo_reason": 9})

        dropped = ledger.snapshot()["integrity_dropped"]
        assert isinstance(dropped, dict)
        assert set(dropped) == set(INTEGRITY_REASONS)

    def test_a_pass_that_removed_nothing_is_still_recorded(self) -> None:
        """C7 needs how often the pass *fires*, not only when it finds something."""
        ledger = TruncationLedger()
        ledger.record_integrity_pass(objects_in=5, objects_out=5)

        snap = ledger.snapshot()
        assert snap["integrity_invocations"] == 1
        assert snap["integrity_objects_removed"] == 0

    def test_objects_removed_never_goes_negative(self) -> None:
        """The renderer's pass can *add* objects before repairing them."""
        ledger = TruncationLedger()
        ledger.record_integrity_pass(objects_in=2, objects_out=9)

        assert ledger.snapshot()["integrity_objects_removed"] == 0


class TestAnyBoundHit:
    def test_a_clean_run_reports_no_bound_hit(self) -> None:
        ledger = TruncationLedger()
        ledger.record_tool_output(chars_in=10, chars_kept=10, over_limit=False)
        ledger.record_react_loop(hit_step_cap=False)

        assert ledger.any_bound_hit is False

    def test_an_integrity_removal_alone_is_not_a_bound_hit(self) -> None:
        """Repairing a malformed bundle is not truncation, and conflating the two
        would inflate the P6 headline with something P6 is not about."""
        ledger = TruncationLedger()
        ledger.record_integrity_pass(objects_in=4, objects_out=1, dropped={"empty_pattern": 3})

        assert ledger.any_bound_hit is False

    @pytest.mark.parametrize("which", ["tool", "react", "judge"])
    def test_each_bound_alone_trips_the_headline(self, which: str) -> None:
        ledger = TruncationLedger()
        if which == "tool":
            ledger.record_tool_output(chars_in=9000, chars_kept=6000, over_limit=True)
        elif which == "react":
            ledger.record_react_loop(hit_step_cap=True)
        else:
            ledger.record_judge_call(hit_token_cap=True)

        assert ledger.any_bound_hit is True


class TestHitLengthCap:
    @pytest.mark.parametrize("reason", ["length", "LENGTH", "max_tokens"])
    def test_recognised_stop_reasons(self, reason: str) -> None:
        response = type("R", (), {"response_metadata": {"finish_reason": reason}})()
        assert hit_length_cap(response) is True

    @pytest.mark.parametrize("reason", ["stop", "tool_calls", ""])
    def test_a_normal_completion_is_not_a_cap(self, reason: str) -> None:
        response = type("R", (), {"response_metadata": {"finish_reason": reason}})()
        assert hit_length_cap(response) is False

    def test_a_provider_that_reports_nothing_counts_as_not_capped(self) -> None:
        """False, not True: a missing field must not inflate the reported rate."""
        assert hit_length_cap(object()) is False
        assert hit_length_cap(type("R", (), {"response_metadata": None})()) is False


class TestTelemetryNeverBreaksAnalysis:
    """A ledger that raises turns a reporting detail into a failed analysis."""

    def test_guardrail_recording_swallows_a_broken_ledger(self) -> None:
        class Exploding:
            def record_tool_output(self, **_: object) -> None:
                raise RuntimeError("ledger is broken")

        record_guardrail_outcome(Exploding(), chars_in=1, chars_kept=1, over_limit=False)

    def test_guardrail_recording_is_a_noop_without_a_ledger(self) -> None:
        record_guardrail_outcome(None, chars_in=1, chars_kept=1, over_limit=True)

    def test_judge_recording_swallows_a_broken_ledger(self) -> None:
        class Exploding:
            def record_judge_call(self, **_: object) -> None:
                raise RuntimeError("ledger is broken")

        record_judge_response(Exploding(), object())

    def test_judge_recording_is_a_noop_without_a_ledger(self) -> None:
        record_judge_response(None, object())


class TestConcurrency:
    def test_parallel_analysts_do_not_lose_counts(self) -> None:
        """Analysts run concurrently against one shared ledger; a lost update
        would silently under-report the very frequency P6 asks for."""
        ledger = TruncationLedger()

        def worker() -> None:
            for _ in range(200):
                ledger.record_tool_output(chars_in=10, chars_kept=4, over_limit=True)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        snap = ledger.snapshot()
        assert snap["tool_output_calls"] == 1600
        assert snap["tool_output_over_limit"] == 1600
        assert snap["tool_output_chars_dropped"] == 1600 * 6


class TestTheCapIsDetectedWhenTheServerWillNotSaySo:
    """``finish_reason`` is not a truncation signal on the server we run.

    Probed directly on 2026-08-15: asked for 64 tokens with ``n_predict`` set,
    ik_llama.cpp returned **exactly 64** and reported ``finish_reason: "stop"``.
    The response carries no ``stopped_limit``, no ``length``, nothing at all to
    say it was cut — only ``usage.completion_tokens`` equal to the cap.

    So the judge-ceiling counter was blind twice over. Before OUTPUT-CAP-01 the
    cap never reached the server (§3.35) and the counter measured an event that
    could not occur; after the fix the event occurs and ``finish_reason`` still
    does not report it. Comparing the produced count against the requested cap is
    the only evidence the server leaves.
    """

    def _response(self, *, tokens: int, reason: str = "stop") -> object:
        return type(
            "R",
            (),
            {
                "response_metadata": {
                    "finish_reason": reason,
                    "token_usage": {"completion_tokens": tokens},
                }
            },
        )()

    def test_a_silent_truncation_is_counted(self) -> None:
        from maljan.core.truncation_ledger import TruncationLedger, record_judge_response

        ledger = TruncationLedger()
        record_judge_response(ledger, self._response(tokens=8192), cap=8192)
        assert ledger.judge_token_cap_hits == 1

    def test_a_short_answer_is_not_counted(self) -> None:
        from maljan.core.truncation_ledger import TruncationLedger, record_judge_response

        ledger = TruncationLedger()
        record_judge_response(ledger, self._response(tokens=412), cap=8192)
        assert ledger.judge_token_cap_hits == 0
        assert ledger.judge_invocations == 1

    def test_without_a_cap_it_falls_back_to_the_finish_reason(self) -> None:
        """The old behaviour must survive for providers that do report it."""
        from maljan.core.truncation_ledger import TruncationLedger, record_judge_response

        ledger = TruncationLedger()
        record_judge_response(ledger, self._response(tokens=8192, reason="length"))
        assert ledger.judge_token_cap_hits == 1

        quiet = TruncationLedger()
        record_judge_response(quiet, self._response(tokens=8192), cap=None)
        assert quiet.judge_token_cap_hits == 0

    def test_the_usage_metadata_shape_is_also_read(self) -> None:
        """LangChain exposes the count in two places depending on the provider."""
        from maljan.core.truncation_ledger import completion_tokens_of

        r = type("R", (), {"usage_metadata": {"output_tokens": 77}, "response_metadata": {}})()
        assert completion_tokens_of(r) == 77

    def test_a_response_with_no_counts_is_not_a_hit(self) -> None:
        from maljan.core.truncation_ledger import TruncationLedger, record_judge_response

        ledger = TruncationLedger()
        record_judge_response(ledger, object(), cap=8192)
        assert ledger.judge_token_cap_hits == 0

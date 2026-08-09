"""The arithmetic and the evidence construction behind E.2, tested without an LLM.

E.2 decides the paper's framing, so the parts that can be wrong silently get
tested first. Three of these tests exist because the corresponding mistake would
produce a *publishable-looking* result that is meaningless:

* **the leak check** — if a ground-truth technique id reaches the evidence, every
  arm copies it and scores perfectly. The harness aborts on a leak; this pins
  that the detector actually detects.
* **empty prediction scores 0 precision** — the degenerate strategy in any
  equal-budget comparison is to say nothing. If saying nothing scored precision
  1.0, the arm that gives up would win the column.
* **the mediator is paid out of the budget** — if K analysts split B and the
  mediator gets a free extra call, `negotiated` quietly spends more than
  `single` and the equal-budget control the literature demands is broken.
"""

from __future__ import annotations

import pytest

from tests.evaluation.eval_consensus_ablation import (
    CHANNELS,
    bootstrap_ci,
    build_channels,
    extract_tids,
    invalid_id_rate,
    leaked_ids,
    load_samples,
    mean,
    paired_delta,
    per_call_budget,
    prf,
    render_all_channels,
    swap_one_channel,
)


class TestEvidenceCarriesNoAnswers:
    def test_no_fixture_leaks_a_technique_id_into_its_evidence(self) -> None:
        """The whole experiment is void if this ever fails."""
        for sid, tids in load_samples():
            channels = build_channels(tids)
            assert leaked_ids(channels) == [], f"{sid} leaks ids into evidence"

    def test_the_leak_detector_is_not_vacuous(self) -> None:
        """A detector that never fires would pass the test above forever."""
        assert leaked_ids({"static": "clearly T1055 here"}) == ["T1055"]
        assert leaked_ids({"a": "T1027 and T1055.001"}) == ["T1027", "T1055.001"]

    def test_every_fixture_technique_has_an_artifact(self) -> None:
        """A technique with no artifact is unreachable evidence — the arms would
        be scored against something the input cannot support."""
        for sid, tids in load_samples():
            channels = build_channels(tids)
            artifact_lines = sum(len(v.splitlines()) for v in channels.values())
            assert artifact_lines == len(tids), f"{sid}: {artifact_lines} artifacts for {len(tids)}"


class TestChannelsAreHeterogeneousAndBalanced:
    def test_every_fixture_populates_all_three_channels(self) -> None:
        """An empty channel hands `single` a free advantage: `negotiated` still
        pays B/(K+1) for an analyst with nothing to say."""
        for sid, tids in load_samples():
            channels = build_channels(tids)
            assert set(channels) == set(CHANNELS), f"{sid} channels: {sorted(channels)}"

    def test_an_unknown_technique_is_skipped_not_crashed(self) -> None:
        channels = build_channels(["T9999", "T1055"])
        assert "T9999" not in render_all_channels(channels)
        assert channels["dynamic"]

    def test_render_preserves_channel_order_and_labels(self) -> None:
        rendered = render_all_channels(build_channels(["T1547", "T1055", "T1071"]))
        assert rendered.index("[static evidence]") < rendered.index("[dynamic evidence]")
        assert rendered.index("[dynamic evidence]") < rendered.index("[network evidence]")

    def test_single_arm_sees_exactly_what_the_analysts_see(self) -> None:
        """Otherwise the comparison is confounded by input, not topology."""
        channels = build_channels(["T1547", "T1055", "T1071"])
        rendered = render_all_channels(channels)
        for text in channels.values():
            for line in text.splitlines():
                assert line in rendered


class TestNoiseControl:
    def test_the_victim_channel_is_replaced_by_the_donor(self) -> None:
        victim_sample = build_channels(["T1547", "T1055", "T1071"])
        donor = build_channels(["T1140", "T1486", "T1095"])
        out = swap_one_channel(victim_sample, donor, "static")
        assert out["static"] == donor["static"]
        assert out["dynamic"] == victim_sample["dynamic"]

    def test_the_other_channels_are_untouched(self) -> None:
        a = build_channels(["T1547", "T1055", "T1071"])
        b = build_channels(["T1140", "T1486", "T1095"])
        out = swap_one_channel(a, b, "static")
        assert out["network"] == a["network"]

    def test_a_donor_without_the_channel_leaves_the_arm_at_full_strength(self) -> None:
        """Falling back to the original keeps the analyst count constant; silently
        dropping a channel would make `noise` a two-analyst run and confound it
        with the very topology under test."""
        a = build_channels(["T1547", "T1055", "T1071"])
        out = swap_one_channel(a, {"dynamic": "x"}, "static")
        assert out["static"] == a["static"]
        assert set(out) == set(a)

    def test_the_swap_does_not_mutate_the_original(self) -> None:
        a = build_channels(["T1547", "T1055", "T1071"])
        before = dict(a)
        swap_one_channel(a, build_channels(["T1140"]), "static")
        assert a == before


class TestEqualBudget:
    def test_the_mediator_is_paid_for_out_of_the_same_budget(self) -> None:
        """Three analysts plus one mediator is four calls, not three."""
        assert per_call_budget(2400, 4) == 600
        assert per_call_budget(2400, 4) * 4 <= 2400

    def test_the_single_arm_gets_the_whole_budget_in_one_call(self) -> None:
        assert per_call_budget(2400, 1) == 2400

    def test_a_split_never_rounds_down_to_zero(self) -> None:
        """A zero cap would silently produce an empty arm that then 'loses'."""
        assert per_call_budget(3, 10) == 1

    def test_zero_calls_does_not_divide_by_zero(self) -> None:
        assert per_call_budget(2400, 0) == 2400


class TestExtractTids:
    def test_ids_are_deduplicated_and_order_preserved(self) -> None:
        assert extract_tids("T1055 then T1071 then T1055 again") == ["T1055", "T1071"]

    def test_sub_techniques_are_captured_whole(self) -> None:
        assert extract_tids("uses T1055.001 injection") == ["T1055.001"]

    def test_lowercase_is_not_matched_but_uppercase_is_normalised(self) -> None:
        assert extract_tids("T1055") == ["T1055"]

    def test_empty_and_none_are_safe(self) -> None:
        assert extract_tids("") == []
        assert extract_tids("no techniques here") == []


class TestPrecisionRecallF1:
    def test_a_perfect_prediction(self) -> None:
        p, r, f1 = prf(["T1055", "T1071"], ["T1055", "T1071"])
        assert (p, r, f1) == (1.0, 1.0, 1.0)

    def test_saying_nothing_scores_zero_precision_not_one(self) -> None:
        """The degenerate equal-budget strategy must not win a column."""
        assert prf([], ["T1055"]) == (0.0, 0.0, 0.0)

    def test_partial_overlap(self) -> None:
        p, r, f1 = prf(["T1055", "T9999"], ["T1055", "T1071"])
        assert p == pytest.approx(0.5)
        assert r == pytest.approx(0.5)
        assert f1 == pytest.approx(0.5)

    def test_duplicates_in_the_prediction_do_not_inflate_precision(self) -> None:
        p, _, _ = prf(["T1055", "T1055", "T1055"], ["T1055", "T1071"])
        assert p == pytest.approx(1.0)

    def test_case_is_normalised_on_both_sides(self) -> None:
        assert prf(["t1055"], ["T1055"])[2] == pytest.approx(1.0)

    def test_an_empty_ground_truth_scores_zero_rather_than_dividing_by_zero(self) -> None:
        assert prf(["T1055"], []) == (0.0, 0.0, 0.0)


class TestInvalidIdRate:
    def test_nothing_cited_is_zero_not_undefined(self) -> None:
        assert invalid_id_rate([], lambda _t: True) == 0.0

    def test_all_invalid(self) -> None:
        assert invalid_id_rate(["T9999"], lambda _t: False) == 1.0

    def test_mixed(self) -> None:
        assert invalid_id_rate(["T1055", "T9999"], lambda t: t == "T1055") == pytest.approx(0.5)


class TestStatistics:
    def test_mean_of_empty_is_zero(self) -> None:
        assert mean([]) == 0.0

    def test_a_bootstrap_ci_brackets_the_mean(self) -> None:
        values = [0.1, 0.2, 0.3, 0.4, 0.5]
        lo, hi = bootstrap_ci(values, iters=500)
        assert lo <= mean(values) <= hi

    def test_a_bootstrap_ci_is_deterministic(self) -> None:
        """Reported intervals must not move between runs of the same data."""
        values = [0.1, 0.9, 0.2, 0.8, 0.35]
        assert bootstrap_ci(values, iters=500) == bootstrap_ci(values, iters=500)

    def test_a_constant_sample_gives_a_degenerate_interval(self) -> None:
        lo, hi = bootstrap_ci([0.5] * 8, iters=500)
        assert lo == pytest.approx(0.5)
        assert hi == pytest.approx(0.5)

    def test_a_power_of_two_sample_size_does_not_collapse_the_interval(self) -> None:
        """The LCG low-bit trap: ``seed % n`` degenerates when n is a power of
        two, which silently produced a zero-width CI. Guards the high-bit fix."""
        lo, hi = bootstrap_ci([0.0, 1.0, 0.0, 1.0, 0.0, 1.0, 0.0, 1.0], iters=1000)
        assert hi > lo

    def test_fewer_than_two_values_reports_no_interval(self) -> None:
        assert bootstrap_ci([0.4]) == (0.0, 0.0)

    def test_paired_delta_is_elementwise(self) -> None:
        assert paired_delta([0.5, 0.2], [0.3, 0.4]) == pytest.approx([0.2, -0.2])

    def test_paired_delta_stops_at_the_shorter_arm(self) -> None:
        """A skipped generation in one arm must not silently misalign the pairs."""
        assert paired_delta([0.5, 0.2, 0.9], [0.3]) == pytest.approx([0.2])

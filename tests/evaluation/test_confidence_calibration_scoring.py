"""B2's metrics, tested where they are easiest to get quietly wrong.

An AUC implementation that mishandles ties, or that returns 0.5 when a class is
empty, produces a number that looks like a finding and is not one. Since B2's
whole purpose is to decide whether a confidence value carries signal, a metric
that manufactures "no signal" out of missing data would be worse than no metric.

The three tests that carry the most weight:

* **ties count 0.5.** A model that reports the same confidence for everything
  should score AUC 0.5, not 0.0 or 1.0 depending on comparison direction.
* **an empty class returns None, not 0.5.** Undefined must not be reported as
  measured.
* **unscoreable claims are counted, not dropped.** A claim with no technique id
  cannot be checked; excluding it silently biases the sample toward whatever the
  model chose to name.
"""

from __future__ import annotations

import pytest

from tests.evaluation.eval_confidence_calibration import (
    brier_score,
    expected_calibration_error,
    overconfidence,
    reliability_bins,
    roc_auc,
    score_claims,
    separation,
)


class _Claim:
    def __init__(self, technique_id: str | None, confidence: float | None) -> None:
        self.technique_id = technique_id
        self.confidence = confidence
        self.claim = "some finding"
        self.evidence_ref = "some artifact"


class TestRocAuc:
    def test_perfect_separation(self) -> None:
        assert roc_auc([0.9, 0.8, 0.2, 0.1], [1, 1, 0, 0]) == pytest.approx(1.0)

    def test_perfectly_inverted(self) -> None:
        assert roc_auc([0.1, 0.2, 0.8, 0.9], [1, 1, 0, 0]) == pytest.approx(0.0)

    def test_all_ties_score_one_half(self) -> None:
        """A model that says 0.8 for everything discriminates nothing — and must
        not score 0.0 or 1.0 depending on which way the comparison leans."""
        assert roc_auc([0.8, 0.8, 0.8, 0.8], [1, 1, 0, 0]) == pytest.approx(0.5)

    def test_a_single_tie_is_worth_half_a_pair(self) -> None:
        # pairs: (0.9 vs 0.5)=1, (0.5 vs 0.5)=0.5 -> 1.5/2
        assert roc_auc([0.9, 0.5, 0.5], [1, 1, 0]) == pytest.approx(0.75)

    def test_an_empty_class_is_undefined_not_no_skill(self) -> None:
        """0.5 would present missing data as a measured 'no discrimination'."""
        assert roc_auc([0.9, 0.8], [1, 1]) is None
        assert roc_auc([0.9, 0.8], [0, 0]) is None
        assert roc_auc([], []) is None

    def test_mismatched_lengths_are_a_hard_error(self) -> None:
        """Silent truncation would misalign every claim with the wrong label."""
        with pytest.raises(ValueError):
            roc_auc([0.9, 0.8], [1])


class TestSeparation:
    def test_the_ordinary_case(self) -> None:
        assert separation([0.9, 0.7, 0.3, 0.1], [1, 1, 0, 0]) == pytest.approx(0.6)

    def test_negative_when_wrong_claims_are_more_confident(self) -> None:
        assert separation([0.2, 0.9], [1, 0]) == pytest.approx(-0.7)

    def test_undefined_with_one_class(self) -> None:
        assert separation([0.9, 0.8], [1, 1]) is None


class TestBrier:
    def test_perfect_confident_predictions_score_zero(self) -> None:
        assert brier_score([1.0, 0.0], [1, 0]) == pytest.approx(0.0)

    def test_confidently_wrong_is_the_worst_case(self) -> None:
        assert brier_score([0.0, 1.0], [1, 0]) == pytest.approx(1.0)

    def test_hedging_at_one_half(self) -> None:
        assert brier_score([0.5, 0.5], [1, 0]) == pytest.approx(0.25)

    def test_empty_is_zero_not_an_error(self) -> None:
        assert brier_score([], []) == 0.0


class TestReliabilityBins:
    def test_empty_bins_are_omitted_not_reported_as_always_wrong(self) -> None:
        """An unvisited confidence band is not a band where the model fails."""
        bins = reliability_bins([0.9, 0.95], [1, 1], n_bins=5)
        assert len(bins) == 1
        assert bins[0][2] == pytest.approx(1.0)

    def test_confidence_of_exactly_one_lands_in_the_top_bin(self) -> None:
        """Half-open bins would otherwise drop 1.0 entirely."""
        bins = reliability_bins([1.0], [1], n_bins=5)
        assert len(bins) == 1
        assert bins[0][3] == 1

    def test_observed_accuracy_is_per_bin(self) -> None:
        bins = reliability_bins([0.1, 0.15, 0.9, 0.95], [0, 0, 1, 1], n_bins=5)
        accuracies = {round(lo, 1): acc for lo, _hi, acc, _n in bins}
        assert accuracies[0.0] == pytest.approx(0.0)
        assert accuracies[0.8] == pytest.approx(1.0)


class TestExpectedCalibrationError:
    def test_a_perfectly_calibrated_set_scores_near_zero(self) -> None:
        # 0.9-confidence claims that are right 100% of the time: gap 0.1
        assert expected_calibration_error([0.9] * 4, [1, 1, 1, 1], n_bins=5) == pytest.approx(0.1)

    def test_uniform_overconfidence_shows_up(self) -> None:
        """Claims at 0.9 that are right half the time: gap 0.4."""
        assert expected_calibration_error([0.9] * 4, [1, 1, 0, 0], n_bins=5) == pytest.approx(0.4)

    def test_empty_is_zero(self) -> None:
        assert expected_calibration_error([], []) == 0.0


class TestOverconfidence:
    def test_positive_when_stated_exceeds_actual(self) -> None:
        assert overconfidence([0.9, 0.9], [1, 0]) == pytest.approx(0.4)

    def test_negative_when_the_model_undersells_itself(self) -> None:
        assert overconfidence([0.4, 0.4], [1, 1]) == pytest.approx(-0.6)

    def test_it_separates_direction_where_ece_cannot(self) -> None:
        """ECE is an absolute gap; over- and under-confidence look identical to it."""
        over = ([0.9, 0.9], [1, 0])
        under = ([0.1, 0.1], [1, 0])
        assert expected_calibration_error(*over) == pytest.approx(
            expected_calibration_error(*under)
        )
        assert overconfidence(*over) > 0 > overconfidence(*under)


class TestScoreClaims:
    def test_a_claim_matching_ground_truth_is_correct(self) -> None:
        rows, unscoreable = score_claims(
            [_Claim("T1055", 0.9)], ["T1055"], sample_id="s", channel="static", repeat=0
        )
        assert unscoreable == 0
        assert rows[0].correct == 1

    def test_a_claim_outside_ground_truth_is_wrong(self) -> None:
        rows, _ = score_claims(
            [_Claim("T9999", 0.9)], ["T1055"], sample_id="s", channel="static", repeat=0
        )
        assert rows[0].correct == 0

    def test_case_is_normalised_on_both_sides(self) -> None:
        rows, _ = score_claims(
            [_Claim("t1055", 0.5)], ["t1055"], sample_id="s", channel="static", repeat=0
        )
        assert rows[0].correct == 1
        assert rows[0].technique_id == "T1055"

    def test_a_claim_without_a_technique_id_is_counted_not_dropped(self) -> None:
        """Silently excluding these biases the sample toward what the model named."""
        rows, unscoreable = score_claims(
            [_Claim(None, 0.9), _Claim("", 0.9), _Claim("   ", 0.9)],
            ["T1055"],
            sample_id="s",
            channel="static",
            repeat=0,
        )
        assert rows == []
        assert unscoreable == 3

    def test_a_claim_without_a_confidence_is_also_unscoreable(self) -> None:
        rows, unscoreable = score_claims(
            [_Claim("T1055", None)], ["T1055"], sample_id="s", channel="static", repeat=0
        )
        assert rows == []
        assert unscoreable == 1

    def test_a_confidence_of_zero_is_scoreable_not_missing(self) -> None:
        """0.0 is a real self-report — the model saying it does not believe its
        own claim — and treating it as absent would delete the most informative
        rows in the sample."""
        rows, unscoreable = score_claims(
            [_Claim("T1055", 0.0)], ["T1055"], sample_id="s", channel="static", repeat=0
        )
        assert unscoreable == 0
        assert rows[0].confidence == 0.0

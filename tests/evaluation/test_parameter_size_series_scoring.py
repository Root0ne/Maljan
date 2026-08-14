"""The C6 series arithmetic, tested before it decides anything about P8.

The series exists to answer one question — does F1 track parameter count on this
task — and the answer will be read as either "our findings are about the
architecture" or "our findings are about one model". That is too much weight for
untested arithmetic, so the parts that could quietly produce a wrong rho are
pinned here.

Three failures this guards against, each of which would be invisible in the
output:

* **ties broken by file order.** Two arms landing on the same mean F1 is
  entirely possible at n=25, and if ``ranks`` broke that tie by input position
  then the directory listing order would move the correlation.
* **a significance claim the design cannot support.** With four arms there are
  4! = 24 orderings, so the smallest reachable two-tailed p is 0.083. A test that
  reported p<0.05 for four points would be reporting an impossibility.
* **an incomplete series correlating anyway.** If one endpoint throttles and its
  arm never finishes, a rho over the survivors describes which endpoints
  answered, not which models are larger.
"""

from __future__ import annotations

import pytest

from tests.evaluation.eval_parameter_size_series import (
    best_achievable_p,
    build_report,
    exact_two_tailed_p,
    paired_delta,
    ranks,
    spearman,
    summarise_arm,
)


class TestRanks:
    def test_simple_ordering(self) -> None:
        assert ranks([10.0, 30.0, 20.0]) == [1.0, 3.0, 2.0]

    def test_ties_share_the_average_rank(self) -> None:
        """Not the input order — otherwise the directory listing decides rho."""
        assert ranks([5.0, 5.0, 9.0]) == [1.5, 1.5, 3.0]

    def test_a_wholly_constant_column_ranks_flat(self) -> None:
        assert ranks([2.0, 2.0, 2.0]) == [2.0, 2.0, 2.0]

    def test_ranking_is_order_independent(self) -> None:
        a = ranks([0.4, 0.4, 0.1, 0.9])
        b = ranks([0.4, 0.4, 0.1, 0.9][::-1])[::-1]
        assert a == b


class TestSpearman:
    def test_perfect_monotone_increase(self) -> None:
        assert spearman([1.0, 2.0, 3.0, 4.0], [10.0, 20.0, 30.0, 40.0]) == pytest.approx(1.0)

    def test_perfect_monotone_decrease(self) -> None:
        assert spearman([1.0, 2.0, 3.0, 4.0], [40.0, 30.0, 20.0, 10.0]) == pytest.approx(-1.0)

    def test_it_is_rank_based_not_value_based(self) -> None:
        """Parameter counts span 35B to 744B; a Pearson correlation there would
        be dominated by the largest arm's leverage rather than by the ordering."""
        assert spearman([1.0, 2.0, 3.0, 1000.0], [1.0, 2.0, 3.0, 4.0]) == pytest.approx(1.0)

    def test_a_constant_column_scores_zero_rather_than_nan(self) -> None:
        """All four arms scoring identically is a real possible outcome — and it
        is the strongest possible evidence *against* the size prior, so it must
        not arrive as a NaN in the paper's table."""
        assert spearman([35.0, 120.0, 428.0, 744.0], [0.4, 0.4, 0.4, 0.4]) == 0.0

    def test_too_few_points_is_zero(self) -> None:
        assert spearman([1.0], [1.0]) == 0.0
        assert spearman([], []) == 0.0

    def test_mismatched_lengths_do_not_crash(self) -> None:
        assert spearman([1.0, 2.0], [1.0]) == 0.0


class TestExactPermutationP:
    def test_four_arms_cannot_reach_significance(self) -> None:
        """2 of 24 orderings match a perfect correlation in absolute value, so
        p=0.083 is the floor. This is the number that keeps the series honest."""
        assert best_achievable_p(4) == pytest.approx(2 / 24)
        assert best_achievable_p(4) > 0.05

    def test_a_perfect_correlation_returns_that_floor(self) -> None:
        p = exact_two_tailed_p([35.0, 120.0, 428.0, 744.0], [0.1, 0.2, 0.3, 0.4])
        assert p == pytest.approx(2 / 24)

    def test_no_relationship_returns_a_large_p(self) -> None:
        assert exact_two_tailed_p([35.0, 120.0, 428.0, 744.0], [0.3, 0.1, 0.4, 0.2]) > 0.5

    def test_more_arms_lower_the_floor(self) -> None:
        """Stated as a property so the value of adding a fifth arm is visible."""
        assert best_achievable_p(5) < best_achievable_p(4)
        assert best_achievable_p(6) < best_achievable_p(5)

    def test_the_enumeration_refuses_sizes_it_should_not_enumerate(self) -> None:
        assert best_achievable_p(12) == 1.0


class TestPairing:
    def test_only_shared_keys_are_differenced(self) -> None:
        """Arms do not complete the same fixtures when an endpoint throttles, and
        an unpaired mean would mix the model effect with who finished what."""
        deltas, n = paired_delta({"a:0": 0.2, "b:0": 0.4}, {"a:0": 0.5, "c:0": 0.9})
        assert n == 1
        assert deltas == [pytest.approx(0.3)]

    def test_no_overlap_yields_nothing_rather_than_a_bogus_mean(self) -> None:
        deltas, n = paired_delta({"a:0": 0.2}, {"b:0": 0.9})
        assert (deltas, n) == ([], 0)


class TestSummariseArm:
    def test_errored_calls_do_not_score_as_zero(self) -> None:
        """A throttled or failed call scoring 0.0 would drag an arm's mean down
        in proportion to how unlucky its endpoint was that hour."""
        rows = [
            {"sample_id": "a", "repeat": 0, "f1": 0.5},
            {"sample_id": "b", "repeat": 0, "error": "429"},
        ]
        s = summarise_arm(rows)
        assert s["n"] == 1
        assert s["mean_f1"] == pytest.approx(0.5)
        assert s["failed"] == 1

    def test_keys_carry_the_repeat_so_repeats_do_not_collide(self) -> None:
        rows = [
            {"sample_id": "a", "repeat": 0, "f1": 0.2},
            {"sample_id": "a", "repeat": 1, "f1": 0.8},
        ]
        assert summarise_arm(rows)["n"] == 2

    def test_an_arm_with_nothing_scored_reports_no_mean(self) -> None:
        assert summarise_arm([{"sample_id": "a", "error": "boom"}])["mean_f1"] is None


def _arm(name: str, total: float, active: float, f1: float) -> dict[str, object]:
    return {
        "arm": name,
        "model": f"model-{name}",
        "total_params_b": total,
        "active_params_b": active,
        "mean_f1": f1,
        "n": 25,
        "by_key": {},
    }


class TestReport:
    def test_an_incomplete_series_refuses_to_correlate(self) -> None:
        """Two arms answering is not a trend; a rho there would describe which
        endpoint was reachable."""
        _md, blob = build_report([_arm("local", 35, 3, 0.41), _arm("glm", 744, 40, 0.44)])
        assert blob["status"] == "incomplete"
        assert "rho_total_params" not in blob

    def test_a_complete_series_reports_rho_with_its_floor(self) -> None:
        md, blob = build_report(
            [
                _arm("local", 35, 3, 0.41),
                _arm("nemotron", 120, 12, 0.42),
                _arm("minimax", 428, 22, 0.43),
                _arm("glm", 744, 40, 0.44),
            ]
        )
        assert blob["status"] == "complete"
        assert blob["rho_total_params"] == pytest.approx(1.0)
        assert blob["smallest_reachable_p"] == pytest.approx(2 / 24, abs=1e-3)
        assert "cannot reach p<0.05" in md or "perfect ordering gives p" in md

    def test_a_flat_series_reads_as_the_prior_failing(self) -> None:
        md, blob = build_report(
            [
                _arm("local", 35, 3, 0.41),
                _arm("nemotron", 120, 12, 0.41),
                _arm("minimax", 428, 22, 0.41),
                _arm("glm", 744, 40, 0.41),
            ]
        )
        assert blob["rho_total_params"] == 0.0
        assert "does not reproduce" in md

    def test_both_confounds_are_always_printed(self) -> None:
        """They are the reason a reader should not over-read the rho, so they
        travel with it rather than living in a paragraph someone may not copy."""
        md, _ = build_report(
            [
                _arm("local", 35, 3, 0.41),
                _arm("nemotron", 120, 12, 0.42),
                _arm("minimax", 428, 22, 0.40),
                _arm("glm", 744, 40, 0.44),
            ]
        )
        assert "Quantisation" in md
        assert "Lab and corpus" in md

    def test_the_span_is_reported_because_it_bounds_the_claim(self) -> None:
        _md, blob = build_report(
            [
                _arm("local", 35, 3, 0.41),
                _arm("nemotron", 120, 12, 0.42),
                _arm("minimax", 428, 22, 0.40),
                _arm("glm", 744, 40, 0.44),
            ]
        )
        assert blob["param_span"] == pytest.approx(744 / 35, abs=0.1)

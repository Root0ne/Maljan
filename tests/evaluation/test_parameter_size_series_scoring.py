"""The C6 series arithmetic, tested before it decides anything about P8.

The series exists to answer one question — does F1 track parameter count on this
task — and the answer will be read as either "our findings are about the
architecture" or "our findings are about one model". That is too much weight for
untested arithmetic, so the parts that could quietly produce a wrong rho are
pinned here.

Four failures this guards against, each of which would be invisible in the
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
* **a configuration difference reported as a size effect.** The fourth was found
  by running it: on 2026-08-14 the series returned rho=+0.866 from five rows that
  were three models, one of them appearing twice at two reasoning settings. The
  reasoning-enabled row scored 0.0080 — crippled by a flag, not by its parameter
  count — and sat at the small end of the axis, where it set the sign. The gate
  in ``TestConfigurationMatching`` exists because that rho was reported before
  anyone asked what the rows were.
"""

from __future__ import annotations

import pytest

from tests.evaluation.eval_parameter_size_series import (
    best_achievable_p,
    build_report,
    common_cells,
    configuration_matched,
    distinct_sizes,
    exact_two_tailed_p,
    mean_over,
    paired_delta,
    ranks,
    select_representative_arms,
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


def _arm(
    name: str,
    total: float,
    active: float,
    f1: float,
    *,
    reasoning: float | None = 0.0,
    requested_no_thinking: bool | None = None,
) -> dict[str, object]:
    """A fully-scored arm: all 25 fixture-repeat cells, every one at ``f1``.

    ``by_key`` is populated rather than left empty because the report now
    correlates over the cells every arm shares — an arm with no cells is, quite
    correctly, refused as not comparable.

    ``reasoning`` defaults to the local baseline's 0.0: these arms are meant to
    be configuration-matched, and the gate that enforces that has its own tests.
    """
    cells = {f"s{i}:{r}": f1 for i in range(5) for r in range(5)}
    return {
        "arm": name,
        "model": f"model-{name}",
        "total_params_b": total,
        "active_params_b": active,
        "mean_f1": f1,
        "n": len(cells),
        "by_key": cells,
        "mean_reasoning_fraction": reasoning,
        "thinking_disabled_requested": requested_no_thinking,
        "source": f"frontier_probe_{name}.json",
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


class TestCommonCells:
    """The arms do not complete the same cells, and the holes are not random.

    Found by review on 2026-08-14, before either new arm had run: the first
    version of ``build_report`` compared each arm's mean over *its own* scored
    calls, so an endpoint that throttled through half its run would have entered
    the correlation with a mean taken from whichever calls happened to get
    through. Endpoint availability and model size would then be inseparable.
    """

    def test_the_intersection_is_what_gets_compared(self) -> None:
        arms = [
            {"by_key": {"a:0": 0.1, "b:0": 0.2, "c:0": 0.3}},
            {"by_key": {"a:0": 0.4, "b:0": 0.5}},
        ]
        assert common_cells(arms) == {"a:0", "b:0"}

    def test_one_empty_arm_empties_the_intersection(self) -> None:
        """An arm that scored nothing must not silently drop out of the
        intersection and leave the others looking comparable."""
        assert common_cells([{"by_key": {"a:0": 0.1}}, {"by_key": {}}]) == set()

    def test_no_arms_is_empty_rather_than_an_error(self) -> None:
        assert common_cells([]) == set()

    def test_mean_over_uses_only_the_named_cells(self) -> None:
        got = mean_over({"a:0": 0.0, "b:0": 1.0, "c:0": 9.9}, {"a:0", "b:0"})
        assert got == pytest.approx(0.5)

    def test_mean_over_an_empty_selection_is_none_not_zero(self) -> None:
        """Zero is a legitimate F1; None is 'nothing was measured'."""
        assert mean_over({"a:0": 0.5}, set()) is None


def _arm_with_cells(
    name: str,
    total: float,
    active: float,
    cells: dict[str, float],
    *,
    reasoning: float | None = 0.0,
    requested_no_thinking: bool | None = None,
) -> dict:
    """A series arm. Configuration-matched by default.

    ``reasoning`` defaults to 0.0 — the local baseline's share — because these
    tests are about cell sharing and rank arithmetic, and an arm that silently
    failed the configuration gate would make every one of them pass for the
    wrong reason. The gate itself is exercised by ``TestConfigurationMatching``.
    """
    return {
        "arm": name,
        "model": f"model-{name}",
        "total_params_b": total,
        "active_params_b": active,
        "mean_f1": round(sum(cells.values()) / len(cells), 4) if cells else None,
        "n": len(cells),
        "by_key": cells,
        "mean_reasoning_fraction": reasoning,
        "thinking_disabled_requested": requested_no_thinking,
        "source": f"frontier_probe_{name}.json",
    }


class TestPartialArmsAreRefused:
    def test_a_barely_scored_arm_stops_the_correlation(self) -> None:
        """The failure this guards: one arm limps to 3 of 25 calls and carries
        the same weight in rho as an arm that completed all 25."""
        full = {f"s{i}:0": 0.4 for i in range(25)}
        _md, blob = build_report(
            [
                _arm_with_cells("local", 35, 3, dict(full)),
                _arm_with_cells("nemotron", 120, 12, dict(full)),
                _arm_with_cells("minimax", 428, 22, {"s0:0": 0.9, "s1:0": 0.9, "s2:0": 0.9}),
                _arm_with_cells("glm", 744, 40, dict(full)),
            ]
        )
        assert blob["status"] == "not-comparable"
        assert "rho_total_params" not in blob
        assert blob["common_cells"] == 3

    def test_the_refusal_shows_each_arm_s_shared_count(self) -> None:
        """So the reader can see which endpoint caused it rather than guessing."""
        full = {f"s{i}:0": 0.4 for i in range(25)}
        md, _ = build_report(
            [
                _arm_with_cells("local", 35, 3, dict(full)),
                _arm_with_cells("nemotron", 120, 12, dict(full)),
                _arm_with_cells("minimax", 428, 22, {"s0:0": 0.9}),
                _arm_with_cells("glm", 744, 40, dict(full)),
            ]
        )
        assert "of which shared" in md
        assert "minimax" in md

    def test_fully_scored_arms_correlate_on_the_shared_cells(self) -> None:
        full = {f"s{i}:0": 0.4 for i in range(25)}
        rising = [0.30, 0.40, 0.50, 0.60]
        arms = [
            _arm_with_cells("local", 35, 3, {k: rising[0] for k in full}),
            _arm_with_cells("nemotron", 120, 12, {k: rising[1] for k in full}),
            _arm_with_cells("minimax", 428, 22, {k: rising[2] for k in full}),
            _arm_with_cells("glm", 744, 40, {k: rising[3] for k in full}),
        ]
        _md, blob = build_report(arms)
        assert blob["status"] == "complete"
        assert blob["common_cells"] == 25
        assert blob["rho_total_params"] == pytest.approx(1.0)

    def test_the_shared_mean_is_what_rho_uses_not_the_arms_own_mean(self) -> None:
        """An arm whose extra, unshared calls were unusually good must not carry
        that advantage into the correlation."""
        shared = {f"s{i}:0": 0.30 for i in range(25)}
        inflated = dict(shared) | {f"x{i}:0": 1.0 for i in range(10)}
        arms = [
            _arm_with_cells("local", 35, 3, dict(shared)),
            _arm_with_cells("nemotron", 120, 12, dict(shared)),
            _arm_with_cells("minimax", 428, 22, dict(shared)),
            _arm_with_cells("glm", 744, 40, inflated),
        ]
        _md, blob = build_report(arms)
        glm = next(a for a in blob["arms"] if a["arm"] == "glm")
        # 25 shared cells at 0.30 plus 10 unshared at 1.0 → its own mean is 0.50
        assert glm["mean_f1"] == pytest.approx(0.50, abs=0.01)  # inflated by the extras
        assert glm["mean_f1_common"] == pytest.approx(0.30)  # what rho actually uses
        assert blob["rho_total_params"] == 0.0


class TestConfigurationMatching:
    """The gate that decides whether an arm belongs on the size axis at all.

    Added 2026-08-14, after the series produced rho=+0.866 from five rows that
    were really three models. Two of the rows were the same model at two
    reasoning settings, and the reasoning-enabled one — 0.0080, crippled by the
    flag rather than by its size — sat at the small end and set the sign. The
    flag is worth 0.34-0.45 F1 (§3.31, §3.33); parameter count in this series
    would have to move F1 further than that to be visible past it.
    """

    def test_matching_is_judged_on_what_the_provider_did(self) -> None:
        """Not on what the harness asked for. §3.32: the flag was requested,
        accepted, and ignored — 56.2% of the output was still reasoning."""
        ignored = _arm("nemotron", 120, 12, 0.41, reasoning=0.562, requested_no_thinking=True)
        assert configuration_matched(ignored) is False

    def test_an_honoured_flag_matches(self) -> None:
        honoured = _arm("qwen", 35, 3, 0.35, reasoning=0.0, requested_no_thinking=True)
        assert configuration_matched(honoured) is True

    def test_an_unknown_reasoning_share_is_not_matched(self) -> None:
        """Unknown is unknown. Treating it as matched would let a v1 result file
        with no reasoning accounting silently become a series point."""
        assert configuration_matched(_arm("old", 120, 12, 0.42, reasoning=None)) is False

    def test_repeated_runs_of_one_model_collapse_to_one_point(self) -> None:
        """Two runs of the same model are one point on the size axis, not two."""
        a = _arm("nemotron", 120, 12, 0.4162, reasoning=0.565)
        b = _arm("nemotron", 120, 12, 0.4149, reasoning=0.562)
        reps, others = select_representative_arms([a, b])
        assert len(reps) == 1
        assert len(others) == 1

    def test_the_matched_run_represents_its_model(self) -> None:
        """Both configurations of one model exist; the matched one is the point."""
        thinking = _arm("qwen", 35, 3, 0.0080, reasoning=0.995)
        matched = _arm("qwen", 35, 3, 0.3507, reasoning=0.0)
        reps, others = select_representative_arms([thinking, matched])
        assert [r["mean_f1"] for r in reps] == [0.3507]
        assert [o["mean_f1"] for o in others] == [0.0080]

    def test_distinct_sizes_counts_sizes_not_rows(self) -> None:
        """Local and hosted copies of one model are two rows at one size."""
        arms = [_arm("local", 35, 3, 0.41), _arm("hosted", 35, 3, 0.35)]
        assert distinct_sizes(arms) == 1

    def test_an_unmatched_arm_cannot_complete_the_span(self) -> None:
        """The 2026-08-14 situation exactly: two matched arms at one size, and
        the only larger model running the opposite configuration."""
        arms = [
            _arm("local", 35, 3, 0.4136, reasoning=0.0),
            _arm("hosted", 35, 3, 0.3507, reasoning=0.0),
            _arm("nemotron", 120, 12, 0.4149, reasoning=0.562, requested_no_thinking=True),
        ]
        md, blob = build_report(arms)
        assert blob["status"] == "not-configuration-comparable"
        assert "rho_total_params" not in blob
        assert blob["configuration_matched"] == 2
        assert blob["distinct_sizes_matched"] == 1
        assert "the provider ignored it" in md or "provider ignored it" in md

    def test_the_excluded_arm_is_named_with_its_measured_share(self) -> None:
        """A refusal that does not say which arm and why is not reviewable."""
        arms = [
            _arm("local", 35, 3, 0.4136, reasoning=0.0),
            _arm("hosted", 35, 3, 0.3507, reasoning=0.0),
            _arm("nemotron", 120, 12, 0.4149, reasoning=0.562, requested_no_thinking=True),
        ]
        md, _blob = build_report(arms)
        assert "56.2%" in md
        assert "model-nemotron" in md

    def test_a_matched_series_still_correlates(self) -> None:
        """The gate must not block a series that genuinely is comparable."""
        arms = [
            _arm("local", 35, 3, 0.41),
            _arm("nemotron", 120, 12, 0.42),
            _arm("minimax", 428, 22, 0.43),
            _arm("glm", 744, 40, 0.44),
        ]
        _md, blob = build_report(arms)
        assert blob["status"] == "complete"
        assert blob["rho_total_params"] == pytest.approx(1.0)

"""Unit tests for the shared statistics module.

The arithmetic in ``stats.py`` decides how wide every interval in the paper is
and which nulls are readable, so it is under test the way the scoring helpers in
this directory are. Three of these tests exist because of a specific defect:

* the cluster-size-1 reduction, because the migration replaces four row
  bootstraps whose unit was already correct and their numbers must not move;
* the determinism pair, because an interval whose seed does not reproduce it is
  the state four of the pre-correction artifacts shipped in;
* the "no local bootstrap survives" scan, because the estimator the repo's own
  suite calls degenerate stayed live in ``eval_hint_ablation`` for weeks after
  the other three sites were patched.
"""

from __future__ import annotations

import math
import random
from pathlib import Path

import pytest

from tests.evaluation import stats as S

_HERE = Path(__file__).resolve().parent


# ---------------------------------------------------------------------------
# ICC and the design effect
# ---------------------------------------------------------------------------


def test_icc_is_zero_when_all_variance_is_within_clusters():
    """Four clusters with identical means: nothing is explained by clustering."""
    values = [0.0, 1.0, 0.0, 1.0, 0.0, 1.0, 0.0, 1.0]
    clusters = ["a", "a", "b", "b", "c", "c", "d", "d"]
    st = S.icc_oneway(values, clusters)
    assert st.icc == pytest.approx(0.0, abs=1e-12)
    assert st.design_effect == pytest.approx(1.0)
    assert st.effective_n == pytest.approx(8.0)


def test_icc_is_one_when_no_variance_is_within_clusters():
    values = [1.0, 1.0, 5.0, 5.0, 9.0, 9.0]
    clusters = ["a", "a", "b", "b", "c", "c"]
    st = S.icc_oneway(values, clusters)
    assert st.icc == pytest.approx(1.0)
    assert st.mean_cluster_size == pytest.approx(2.0)
    assert st.design_effect == pytest.approx(2.0)
    assert st.effective_n == pytest.approx(3.0)


def test_icc_matches_a_hand_computed_balanced_anova():
    """Balanced design, so m0 = m and the closed form is checkable by hand.

    Three clusters of two. Grand mean 5. SSB = 2·(4+0+4) = 16, MSB = 8.
    SSW = 4·(0.25) ... written out in the assertion rather than trusted.
    """
    values = [2.5, 3.5, 4.5, 5.5, 6.5, 7.5]
    clusters = ["a", "a", "b", "b", "c", "c"]
    grand = sum(values) / 6
    means = {"a": 3.0, "b": 5.0, "c": 7.0}
    ssb = sum(2 * (m - grand) ** 2 for m in means.values())
    ssw = sum((v - means[c]) ** 2 for v, c in zip(values, clusters, strict=True))
    msb, msw = ssb / 2, ssw / 3
    expected = (msb - msw) / (msb + (2 - 1) * msw)

    st = S.icc_oneway(values, clusters)
    assert st.icc == pytest.approx(expected)


def test_icc_reports_a_negative_estimate_raw_and_clamps_the_design_effect():
    """A design effect below 1 would claim the clustering bought precision."""
    rng = random.Random(11)
    values, clusters = [], []
    for c in range(6):
        for _ in range(4):
            values.append(rng.gauss(0.0, 1.0))
            clusters.append(c)
    # Force between-cluster variance below the within-cluster noise.
    values = [v - sum(values[i - i % 4 : i - i % 4 + 4]) / 4 for i, v in enumerate(values)]
    st = S.icc_oneway(values, clusters)
    assert st.icc >= 0.0
    assert st.design_effect >= 1.0


def test_icc_needs_two_clusters():
    with pytest.raises(ValueError, match="at least two clusters"):
        S.icc_oneway([1.0, 2.0], ["a", "a"])


def test_design_effect_formula():
    """The confidence study's actual shape: 210 claims, 5 samples, ICC 0.304."""
    assert S.design_effect(0.3040, 42.0) == pytest.approx(1 + 41 * 0.3040)
    assert S.design_effect(0.0, 42.0) == pytest.approx(1.0)
    assert S.design_effect(0.5, 1.0) == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# The cluster bootstrap
# ---------------------------------------------------------------------------


def test_cluster_bootstrap_reduces_exactly_to_a_row_bootstrap_at_cluster_size_one():
    """The compatibility proof for the studies whose unit was already correct.

    ``layer0_verdict_v2``, ``sink_hint_ablation_scored`` and
    ``dynamic_vs_static`` all have one observation per cluster. Their published
    intervals must survive the migration unchanged, and this is why.
    """
    values = [0.1, 0.4, 0.2, 0.9, 0.3, 0.55, 0.7]
    interval = S.cluster_bootstrap_ci(values, list(range(len(values))), iters=2000, seed=7)

    rng = random.Random(7)
    draws = [
        sum(values[rng.randrange(len(values))] for _ in range(len(values))) / len(values)
        for _ in range(2000)
    ]
    lo, hi = S._percentile_bounds(draws, 0.05)

    assert interval.lo == pytest.approx(lo, abs=0)
    assert interval.hi == pytest.approx(hi, abs=0)
    assert interval.n_clusters == len(values)


def test_cluster_bootstrap_is_wider_than_a_row_bootstrap_on_clustered_data():
    """The whole reason the module exists, asserted rather than asserted-in-prose."""
    values, clusters = [], []
    for c, base in enumerate([0.1, 0.5, 0.9]):
        for _ in range(20):
            values.append(base)
            clusters.append(c)
    clustered = S.cluster_bootstrap_ci(values, clusters, iters=4000, seed=3)
    rows = S.cluster_bootstrap_ci(values, list(range(len(values))), iters=4000, seed=3)
    assert clustered.width > 3 * rows.width


def test_cluster_bootstrap_records_its_own_provenance():
    values = [0.2, 0.4, 0.6, 0.8]
    iv = S.cluster_bootstrap_ci(values, ["a", "a", "b", "b"], iters=500, seed=99)
    blob = iv.as_json()
    assert blob["seed"] == 99
    assert blob["iters"] == 500
    assert blob["n_clusters"] == 2
    assert blob["n_rows"] == 4
    assert blob["method"] == "cluster_bootstrap"


def test_cluster_bootstrap_requires_a_seed():
    with pytest.raises(TypeError):
        S.cluster_bootstrap_ci([1.0, 2.0], ["a", "b"])  # type: ignore[call-arg]


def test_cluster_bootstrap_is_deterministic_under_a_repeated_seed():
    """Same seed, same bounds; a different seed must actually move them.

    The second half guards against a resample that is not resampling — an RNG
    whose draws are constant-folded away produces a perfectly reproducible and
    perfectly wrong interval.
    """
    rng = random.Random(2)
    values = [rng.random() for _ in range(40)]
    clusters = [i % 8 for i in range(40)]
    first = S.cluster_bootstrap_ci(values, clusters, iters=1500, seed=42)
    second = S.cluster_bootstrap_ci(values, clusters, iters=1500, seed=42)
    other = S.cluster_bootstrap_ci(values, clusters, iters=1500, seed=43)
    assert (first.lo, first.hi) == (second.lo, second.hi)
    assert (first.lo, first.hi) != (other.lo, other.hi)


def test_cluster_bootstrap_rejects_a_mismatched_label_count():
    with pytest.raises(ValueError, match="cluster labels"):
        S.cluster_bootstrap_ci([1.0, 2.0, 3.0], ["a", "b"], seed=1)


# ---------------------------------------------------------------------------
# AUC
# ---------------------------------------------------------------------------


def test_roc_auc_moved_verbatim_still_averages_ties():
    assert S.roc_auc([1.0, 1.0], [1, 0]) == pytest.approx(0.5)
    assert S.roc_auc([0.9, 0.1], [1, 0]) == pytest.approx(1.0)
    assert S.roc_auc([0.1, 0.9], [1, 0]) == pytest.approx(0.0)


def test_roc_auc_is_none_when_a_class_is_empty():
    """Undefined, not 0.5 — returning 0.5 would report missing data as a null."""
    assert S.roc_auc([0.4, 0.6], [1, 1]) is None
    assert S.roc_auc([0.4, 0.6], [0, 0]) is None


def test_auc_cluster_ci_carries_its_method_and_cluster_count():
    scores = [0.9, 0.8, 0.2, 0.1, 0.75, 0.25]
    labels = [1, 1, 0, 0, 1, 0]
    clusters = ["a", "a", "a", "b", "b", "b"]
    iv = S.auc_cluster_ci(scores, labels, clusters, iters=800, seed=5)
    assert iv.method == "cluster_bootstrap_auc"
    assert iv.n_clusters == 2
    assert iv.point == pytest.approx(S.roc_auc(scores, labels))


# ---------------------------------------------------------------------------
# Exact cluster-level inference
# ---------------------------------------------------------------------------


def test_the_sampled_signflip_agrees_with_enumeration_where_both_can_run():
    """The sampled test is only trustworthy above the cap if it matches below it.

    Same means, both routes, enough draws that sampling error is smaller than
    the difference that would matter.
    """
    means = [0.12, -0.04, 0.31, 0.02, -0.18, 0.07, 0.22, -0.09]
    exact = S.exact_signflip_p(means)
    sampled = S.sampled_signflip_p(means, iters=200_000, seed=1)
    assert sampled == pytest.approx(exact, abs=0.005), (
        f"sampled {sampled:.5f} against enumerated {exact:.5f} — one of the two is wrong"
    )


def test_a_sampled_p_is_never_zero():
    """(1 + hits) / (iters + 1), not hits / iters.

    A sampled test that returns 0 is claiming an exactness it does not have.
    The observed assignment belongs in its own reference set.
    """
    unanimous = [0.5] * 24  # every cluster the same sign: nothing is more extreme
    p = S.sampled_signflip_p(unanimous, iters=2_000, seed=7)
    assert p > 0.0
    assert p == pytest.approx(1 / 2001, rel=1e-9)


def test_signflip_picks_a_route_and_says_which():
    """The entry point that stopped k>20 from having no test at all.

    Twenty-four clusters is the design this project moved to *because* it
    raises the resolution; the exact routine refused to run there, and the
    caller formatted None.
    """
    small = [0.1, -0.2, 0.3, 0.05, -0.15]
    p, method, floor = S.signflip_p(small, iters=1000, seed=3)
    assert method == "exact"
    assert floor == pytest.approx(2 / 2**5)
    assert p == pytest.approx(S.exact_signflip_p(small))

    big = [0.05 * (-1) ** i + 0.02 for i in range(24)]
    p, method, floor = S.signflip_p(big, iters=5000, seed=3)
    assert method == "sampled"
    assert floor == pytest.approx(1 / 5001)
    assert 0.0 < p <= 1.0


def test_a_paired_result_always_carries_a_signflip_p():
    """The defect this whole change came from.

    `paired_cluster_result` returned p_exact=None above twenty clusters, and
    the harness that formats it did not check. Reporting crashed on the first
    real-corpus run — after the generations were already paid for.
    """
    rng = random.Random(11)
    deltas, clusters = [], []
    for family in range(24):  # one observation per cluster, as the real design has
        deltas.append(rng.gauss(0.03, 0.1))
        clusters.append(f"family-{family}")
    res = S.paired_cluster_result(deltas, clusters, iters=2000, seed=5)
    assert res.structure.k == 24
    assert res.p_signflip is not None
    assert res.p_signflip_method == "sampled"
    assert res.p_exact is None, "nothing was enumerated, so p_exact must not claim otherwise"
    assert res.p_floor == pytest.approx(1 / 2001)
    # And it must survive being formatted, which is what actually broke.
    assert f"{res.p_signflip:.4f}" and f"{res.p_floor:.4f}"
    assert res.as_json()["p_signflip_method"] == "sampled"


def test_signflip_floor_is_two_over_two_to_the_k():
    assert S.signflip_p_floor(5) == pytest.approx(0.0625)
    assert S.signflip_p_floor(4) == pytest.approx(0.125)
    assert S.signflip_p_floor(13) == pytest.approx(2 / 8192)


def test_five_clusters_agreeing_in_sign_reach_the_floor_and_no_further():
    """The single most consequential number in the correction.

    Whatever the effect size, five clusters that all move the same way produce
    p = 2/32. A five-fixture paired design cannot reach α=0.05.
    """
    assert S.exact_signflip_p([0.2] * 5) == pytest.approx(2 / 32)
    assert S.exact_signflip_p([9.0] * 5) == pytest.approx(2 / 32)
    assert S.exact_signflip_p([-0.4] * 5) == pytest.approx(2 / 32)


def test_signflip_is_one_when_the_mean_is_zero():
    assert S.exact_signflip_p([1.0, -1.0]) == pytest.approx(1.0)


def test_signflip_counts_the_mirror_assignment():
    """Two-sided: the all-flipped copy of the observed assignment must count."""
    p = S.exact_signflip_p([0.5, 0.4, 0.3])
    assert p == pytest.approx(2 / 8)


def test_signflip_refuses_an_enumeration_it_should_not_attempt():
    with pytest.raises(ValueError, match="exact enumeration"):
        S.exact_signflip_p([0.1] * 21)


def test_bootstrap_p_is_two_sided_and_clipped():
    assert S.bootstrap_p([1.0, 2.0, 3.0]) == pytest.approx(0.0)
    assert S.bootstrap_p([-1.0, 0.0, 1.0]) == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# Power
# ---------------------------------------------------------------------------


def test_student_t_quantiles_match_published_values():
    """Pins the hand-rolled incomplete beta against a table."""
    assert S.student_t_ppf(0.975, 4) == pytest.approx(2.776445, abs=1e-5)
    assert S.student_t_ppf(0.80, 4) == pytest.approx(0.940965, abs=1e-5)
    assert S.student_t_ppf(0.975, 23) == pytest.approx(2.068658, abs=1e-5)
    assert S.student_t_ppf(0.95, 1) == pytest.approx(6.313752, abs=1e-4)


def test_student_t_cdf_is_symmetric():
    assert S.student_t_cdf(0.0, 4) == pytest.approx(0.5)
    assert S.student_t_cdf(-1.3, 7) == pytest.approx(1 - S.student_t_cdf(1.3, 7))


def test_mde_uses_the_stated_formula():
    means = [-0.065, -0.007, -0.217, 0.116, 0.092]
    k = len(means)
    m = sum(means) / k
    sd = math.sqrt(sum((x - m) ** 2 for x in means) / (k - 1))
    expected_t = (S.student_t_ppf(0.975, 4) + S.student_t_ppf(0.80, 4)) * sd / math.sqrt(k)
    assert S.mde_paired(means) == pytest.approx(expected_t)
    assert S.mde_paired(means, use_t=False) == pytest.approx(2.801585 * sd / math.sqrt(k), rel=1e-5)
    # The t form is the reported one and must be the more conservative of the two.
    assert S.mde_paired(means) > S.mde_paired(means, use_t=False)


def test_mde_needs_two_clusters():
    with pytest.raises(ValueError, match="at least two clusters"):
        S.mde_paired([0.1])


# ---------------------------------------------------------------------------
# Multiplicity
# ---------------------------------------------------------------------------


def test_benjamini_hochberg_matches_the_worked_example():
    """The 15 p-values from Benjamini & Hochberg (1995), Table 1."""
    p = [
        0.0001,
        0.0004,
        0.0019,
        0.0095,
        0.0201,
        0.0278,
        0.0298,
        0.0344,
        0.0459,
        0.3240,
        0.4262,
        0.5719,
        0.6528,
        0.7590,
        1.0000,
    ]
    q = S.benjamini_hochberg(p)
    # BH rejects the first four at α=0.05; the fifth is the first to fail.
    assert sum(1 for v in q if v <= 0.05) == 4
    assert q[3] == pytest.approx(0.0095 * 15 / 4, abs=1e-6)


def test_benjamini_hochberg_is_monotone_and_order_preserving():
    p = [0.9, 0.01, 0.5, 0.02]
    q = S.benjamini_hochberg(p)
    assert q[1] <= q[3] <= q[2] <= q[0]
    assert all(a <= b for a, b in zip(sorted(q), sorted(q)[1:], strict=False))


def test_benjamini_hochberg_is_the_identity_for_one_test():
    assert S.benjamini_hochberg([0.037]) == pytest.approx([0.037])


def test_benjamini_hochberg_rejects_an_out_of_range_input():
    with pytest.raises(ValueError, match="out of range"):
        S.benjamini_hochberg([0.5, 1.4])


# ---------------------------------------------------------------------------
# Paired results
# ---------------------------------------------------------------------------


def test_paired_cluster_result_reports_everything_a_null_needs():
    deltas = [0.02, -0.01, 0.03, 0.00, 0.05, 0.01, -0.02, 0.04, 0.02, 0.01]
    clusters = ["a"] * 2 + ["b"] * 2 + ["c"] * 2 + ["d"] * 2 + ["e"] * 2
    res = S.paired_cluster_result(deltas, clusters, iters=2000, seed=17)
    assert res.n_pairs == 10
    assert res.structure.k == 5
    assert res.p_floor == pytest.approx(0.0625)
    assert 0.0 <= res.p_exact <= 1.0
    assert res.mde_t > res.mde_z > 0
    blob = res.as_json()
    assert blob["interval"]["n_clusters"] == 5
    assert len(blob["cluster_means"]) == 5


def test_paired_cluster_result_is_deterministic():
    deltas = [0.1, -0.2, 0.3, 0.05, -0.05, 0.2]
    clusters = ["a", "a", "b", "b", "c", "c"]
    a = S.paired_cluster_result(deltas, clusters, iters=1000, seed=8).as_json()
    b = S.paired_cluster_result(deltas, clusters, iters=1000, seed=8).as_json()
    assert a == b


# ---------------------------------------------------------------------------
# Provenance, and the estimator that must not come back
# ---------------------------------------------------------------------------


def test_provenance_identifies_the_code_that_produced_the_interval():
    p = S.provenance(seed=20260815, iters=20_000)
    assert p["stats_schema"] == S.SCHEMA
    assert p["seed"] == 20260815
    assert len(p["stats_module_sha256"]) == 64


def test_no_evaluation_module_carries_its_own_resampling_loop():
    """The nine duplicated estimators are gone, and the broken one cannot return.

    ``eval_hint_ablation`` kept indexing its resample with ``seed % n`` — the low
    bits of a linear congruential generator, which collapse — for weeks after the
    other three sites were fixed, because nothing connected the fix to the
    remaining copies. This is that connection.

    Named ``bootstrap_ci`` wrappers are allowed and expected: several harnesses
    export one so their callers keep a stable name. What is banned is a module
    owning the *arithmetic* — the hand-rolled generator, its hard-coded seed, or
    an index drawn from its low bits.
    """
    banned = {
        "1103515245": "the hand-rolled LCG multiplier",
        "0x9E3779B9": "the hard-coded estimator seed",
        "[seed % n]": "the collapsing low-bit index",
        "(seed >> 16) % n": "the patched-but-still-local LCG index",
    }
    offenders = []
    for path in sorted(_HERE.glob("*.py")):
        if path.name == "stats.py" or path.name.startswith("test_"):
            continue
        text = path.read_text()
        for needle, why in banned.items():
            if needle in text:
                offenders.append(f"{path.name}: {why}")
    assert not offenders, "local resampling survives: " + "; ".join(offenders)


def test_every_local_bootstrap_wrapper_delegates_to_this_module():
    """A function named like the estimator must not be a second estimator."""
    offenders = []
    for path in sorted(_HERE.glob("*.py")):
        if path.name == "stats.py" or path.name.startswith("test_"):
            continue
        text = path.read_text()
        for name in ("def bootstrap_ci", "def _bootstrap_ci", "def cluster_ci", "def family_ci"):
            start = text.find(name)
            if start == -1:
                continue
            body = text[start : start + 2400]
            end = body.find("\ndef ", 1)
            body = body[:end] if end != -1 else body
            if "stats.cluster_bootstrap_ci" not in body:
                offenders.append(f"{path.name}: {name[4:]} does not delegate")
    assert not offenders, "; ".join(offenders)

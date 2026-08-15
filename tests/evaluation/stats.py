"""One bootstrap, resampled at the unit the observations are actually independent at.

Nine harnesses in this directory grew their own confidence interval. Two
algorithms, four seeds, one estimator the repo's own test suite calls degenerate
(``seed % n``, still live in ``eval_hint_ablation``), and three harnesses whose
stored intervals carry no seed at all and so cannot be reproduced from their own
artifact. That is the smaller problem.

The larger one is that every one of them resampled **rows**, and the rows are
not independent:

* ``confidence_calibration.json`` holds 210 claims drawn from **5** samples. The
  intra-cluster correlation on stated confidence is 0.30, so the design effect is
  13.5 and the effective sample size is about 16, not 210.
* ``cape_baseline.json`` holds 97 samples from **24** families, and ground truth
  is resolved per family — two binaries of one family are scored against a
  byte-identical label vector. ICC 0.69, design effect 3.1, effective n 31.
* The consensus and frontier arms are 25 rows that are 5 samples repeated 5 times.

A row bootstrap on clustered data does not estimate the uncertainty of the mean;
it estimates the uncertainty of the mean *of that particular set of clusters*,
which is a narrower and different quantity. Every interval the paper reported was
too narrow by the square root of its design effect, and the two headline numbers
were the two worst cases.

So: one module, resampling whole clusters. Three properties it enforces rather
than documents.

**A seed is not optional.** Every stochastic function takes ``seed`` as a
required keyword argument. Omitting it is a ``TypeError``, which is exactly what
the three harnesses without a ``SEED`` constant needed.

**An interval carries its own provenance.** ``Interval`` holds its seed, its
iteration count, its method and its cluster count, and the only way to serialise
one is ``as_json()``. An interval cannot reach a file stripped of the facts
needed to reproduce it.

**A p-value from a bootstrap is not a p-value.** At five clusters the bootstrap
happily reports p ≈ 0 for any effect whose five cluster means share a sign, which
is anticonservative to the point of being meaningless. ``exact_signflip_p``
enumerates the 2**k sign assignments and gives the honest answer, and
``signflip_p_floor`` states the smallest p the design can reach at all — at k=5
that is 2/32 = 0.0625, so no comparison on a five-fixture corpus can reach
α=0.05 whatever its effect size.
"""

from __future__ import annotations

import hashlib
import math
import random
from collections.abc import Callable, Hashable, Sequence
from dataclasses import dataclass
from pathlib import Path
from statistics import NormalDist
from typing import Any

SCHEMA = "maljan-stats/v1"
DEFAULT_ITERS = 20_000

# A bootstrap draw can be degenerate: five copies of one cluster whose labels are
# all the same class leaves AUC undefined. Dropping those draws is right — they
# carry no information about the statistic — but dropping many of them means the
# interval describes a conditioned subpopulation, so past this share it is an
# error rather than a footnote.
_MAX_DROPPED_SHARE = 0.10


# ---------------------------------------------------------------------------
# Results — every one of these knows how it was computed
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Interval:
    """A point estimate with a percentile interval, and how to reproduce it."""

    point: float
    lo: float
    hi: float
    method: str
    iters: int
    seed: int
    n_rows: int
    n_clusters: int
    alpha: float = 0.05
    dropped: int = 0

    @property
    def width(self) -> float:
        return self.hi - self.lo

    def excludes(self, null: float) -> bool:
        return null < self.lo or null > self.hi

    def as_json(self) -> dict[str, Any]:
        return {
            "point": self.point,
            "lo": self.lo,
            "hi": self.hi,
            "method": self.method,
            "iters": self.iters,
            "seed": self.seed,
            "n_rows": self.n_rows,
            "n_clusters": self.n_clusters,
            "alpha": self.alpha,
            "dropped_draws": self.dropped,
        }


@dataclass(frozen=True)
class ClusterStructure:
    """How much of the row count is real, once the clustering is accounted for."""

    icc: float
    icc_raw: float
    k: int
    n_rows: int
    mean_cluster_size: float
    design_effect: float
    effective_n: float

    def as_json(self) -> dict[str, Any]:
        return {
            "icc": self.icc,
            "icc_raw": self.icc_raw,
            "k": self.k,
            "n_rows": self.n_rows,
            "mean_cluster_size": self.mean_cluster_size,
            "design_effect": self.design_effect,
            "effective_n": self.effective_n,
        }


@dataclass(frozen=True)
class PairedResult:
    """A paired difference, its interval, and what the design could have seen."""

    delta: float
    interval: Interval
    p_bootstrap: float
    p_exact: float | None
    p_floor: float | None
    structure: ClusterStructure
    cluster_sd: float
    mde_z: float
    mde_t: float
    n_pairs: int
    cluster_means: tuple[float, ...]

    def as_json(self) -> dict[str, Any]:
        return {
            "delta": self.delta,
            "interval": self.interval.as_json(),
            "p_bootstrap": self.p_bootstrap,
            "p_exact_signflip": self.p_exact,
            "p_floor": self.p_floor,
            "structure": self.structure.as_json(),
            "cluster_sd": self.cluster_sd,
            "mde_z": self.mde_z,
            "mde_t": self.mde_t,
            "n_pairs": self.n_pairs,
            "cluster_means": list(self.cluster_means),
        }


# ---------------------------------------------------------------------------
# Point estimators
# ---------------------------------------------------------------------------


def mean(values: Sequence[float]) -> float:
    """Arithmetic mean. Present so migrating harnesses import one of these."""
    if not values:
        raise ValueError("mean of an empty sequence")
    return sum(values) / len(values)


def roc_auc(scores: Sequence[float], labels: Sequence[int]) -> float | None:
    """P(a positive outranks a negative), ties counted as 0.5.

    Moved verbatim from ``eval_confidence_calibration.roc_auc`` so the point
    estimate is unchanged by the move; that module now imports it from here. The
    original docstring, which is the reason the implementation looks like this:

    Returns **None** when either class is empty — the value is undefined, and
    returning 0.5 would present missing data as a measured "no discrimination"
    result. Pairwise rather than rank-based: n is small here and the pairwise
    form is obviously correct about ties, which is where AUC implementations
    usually go wrong.
    """
    pos = [s for s, y in zip(scores, labels, strict=True) if y == 1]
    neg = [s for s, y in zip(scores, labels, strict=True) if y == 0]
    if not pos or not neg:
        return None
    total = 0.0
    for p in pos:
        for n in neg:
            if p > n:
                total += 1.0
            elif p == n:
                total += 0.5
    return total / (len(pos) * len(neg))


# ---------------------------------------------------------------------------
# Cluster structure
# ---------------------------------------------------------------------------


def _grouped(
    values: Sequence[float], clusters: Sequence[Hashable]
) -> tuple[list[Hashable], dict[Hashable, list[float]]]:
    if len(values) != len(clusters):
        raise ValueError(f"{len(values)} values against {len(clusters)} cluster labels")
    if not values:
        raise ValueError("no observations")
    groups: dict[Hashable, list[float]] = {}
    order: list[Hashable] = []
    for v, c in zip(values, clusters, strict=True):
        if c not in groups:
            groups[c] = []
            order.append(c)
        groups[c].append(v)
    return order, groups


def icc_oneway(values: Sequence[float], clusters: Sequence[Hashable]) -> ClusterStructure:
    """One-way random-effects ICC, with the unbalanced correction m0.

    ``ICC = (MSB - MSW) / (MSB + (m0 - 1) * MSW)`` where m0 is the
    variance-weighted cluster size, which reduces to the common size when the
    design is balanced. A negative estimate means the between-cluster variance
    is smaller than sampling noise; it is reported raw and clamped to zero for
    the design effect, because a design effect below 1 would claim the clustering
    *bought* precision.

    The design effect itself uses the plain mean cluster size m̄ = N/k, which is
    the form the reporting convention names — m0 is an ANOVA correction and m̄ is
    what a reader can check against the row count.
    """
    order, groups = _grouped(values, clusters)
    k = len(order)
    n = len(values)
    if k < 2:
        raise ValueError(f"ICC needs at least two clusters, got {k}")

    grand = sum(values) / n
    sizes = [len(groups[c]) for c in order]
    means = {c: sum(groups[c]) / len(groups[c]) for c in order}

    ssb = sum(len(groups[c]) * (means[c] - grand) ** 2 for c in order)
    ssw = sum((v - means[c]) ** 2 for c in order for v in groups[c])

    msb = ssb / (k - 1)
    msw = ssw / (n - k) if n > k else 0.0

    m0 = (n - sum(s * s for s in sizes) / n) / (k - 1)
    denom = msb + (m0 - 1) * msw
    icc_raw = 0.0 if denom == 0 else (msb - msw) / denom
    icc = max(0.0, icc_raw)

    m_bar = n / k
    de = 1.0 + (m_bar - 1.0) * icc
    return ClusterStructure(
        icc=icc,
        icc_raw=icc_raw,
        k=k,
        n_rows=n,
        mean_cluster_size=m_bar,
        design_effect=de,
        effective_n=n / de,
    )


def design_effect(icc: float, mean_cluster_size: float) -> float:
    """DE = 1 + (m̄ - 1)·ICC — the factor a row-level n must be divided by."""
    return 1.0 + (mean_cluster_size - 1.0) * icc


# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------


def _cluster_draws(
    values: Sequence[float],
    clusters: Sequence[Hashable],
    statistic: Callable[[Sequence[float]], float | None],
    *,
    iters: int,
    seed: int,
) -> tuple[list[float], int]:
    order, groups = _grouped(values, clusters)
    pools = [groups[c] for c in order]
    k = len(pools)
    rng = random.Random(seed)
    draws: list[float] = []
    dropped = 0
    for _ in range(iters):
        pooled: list[float] = []
        for _ in range(k):
            pooled.extend(pools[rng.randrange(k)])
        stat = statistic(pooled)
        if stat is None or not math.isfinite(stat):
            dropped += 1
            continue
        draws.append(stat)
    return draws, dropped


def _percentile_bounds(draws: list[float], alpha: float) -> tuple[float, float]:
    if not draws:
        raise ValueError("every bootstrap draw was degenerate")
    ordered = sorted(draws)
    n = len(ordered)
    lo_i = min(n - 1, max(0, int(math.floor((alpha / 2) * n))))
    hi_i = min(n - 1, max(0, int(math.ceil((1 - alpha / 2) * n)) - 1))
    return ordered[lo_i], ordered[hi_i]


def cluster_bootstrap_ci(
    values: Sequence[float],
    clusters: Sequence[Hashable],
    statistic: Callable[[Sequence[float]], float | None] = mean,
    *,
    iters: int = DEFAULT_ITERS,
    seed: int,
    alpha: float = 0.05,
    method: str = "cluster_bootstrap",
) -> Interval:
    """Resample whole clusters with replacement; recompute the statistic on the pool.

    With every cluster of size 1 this reduces exactly to the row bootstrap it
    replaces, which is the compatibility proof for the three studies whose unit
    was already correct (``layer0_verdict_v2``, ``sink_hint_ablation_scored``,
    ``dynamic_vs_static``) and is pinned by a test.
    """
    point = statistic(list(values))
    if point is None:
        raise ValueError("statistic is undefined on the observed data")
    draws, dropped = _cluster_draws(values, clusters, statistic, iters=iters, seed=seed)
    if dropped > _MAX_DROPPED_SHARE * iters:
        raise ValueError(
            f"{dropped} of {iters} bootstrap draws were degenerate — the interval "
            "would describe a conditioned subpopulation, not the estimand"
        )
    lo, hi = _percentile_bounds(draws, alpha)
    order, _ = _grouped(list(values), list(clusters))
    return Interval(
        point=point,
        lo=lo,
        hi=hi,
        method=method,
        iters=iters,
        seed=seed,
        n_rows=len(values),
        n_clusters=len(order),
        alpha=alpha,
        dropped=dropped,
    )


def auc_cluster_ci(
    scores: Sequence[float],
    labels: Sequence[int],
    clusters: Sequence[Hashable],
    *,
    iters: int = DEFAULT_ITERS,
    seed: int,
    alpha: float = 0.05,
) -> Interval:
    """A cluster interval around ``roc_auc``, resampling samples rather than claims.

    Claims are nested in samples, so the row bootstrap that would have produced
    the interval this study never reported would have been about four times too
    narrow.
    """
    paired = list(zip(scores, labels, strict=True))
    encoded = list(range(len(paired)))

    def stat(indices: Sequence[float]) -> float | None:
        idx = [int(i) for i in indices]
        return roc_auc([paired[i][0] for i in idx], [paired[i][1] for i in idx])

    return cluster_bootstrap_ci(
        [float(i) for i in encoded],
        clusters,
        stat,
        iters=iters,
        seed=seed,
        alpha=alpha,
        method="cluster_bootstrap_auc",
    )


def bootstrap_p(draws: Sequence[float], null: float = 0.0) -> float:
    """Two-sided bootstrap p: 2·min(P(x ≤ null), P(x ≥ null)), clipped at 1.

    Anticonservative when the cluster count is small — with five clusters all
    moving the same way it returns 0.0, which the design cannot support. Always
    report it beside :func:`exact_signflip_p`.
    """
    if not draws:
        raise ValueError("no draws")
    n = len(draws)
    below = sum(1 for d in draws if d <= null) / n
    above = sum(1 for d in draws if d >= null) / n
    return min(1.0, 2.0 * min(below, above))


# ---------------------------------------------------------------------------
# Exact cluster-level inference
# ---------------------------------------------------------------------------


def signflip_p_floor(k: int) -> float:
    """The smallest two-sided p an exact sign-flip test can reach at k clusters.

    2/2**k. At k=5 this is 0.0625, so a five-cluster paired design cannot produce
    a result at α=0.05 however large the effect. This is a property of the
    design, not of the data, and it belongs beside every null the design reports.
    """
    if k < 1:
        raise ValueError("k must be positive")
    return 2.0 / (2**k)


def exact_signflip_p(cluster_means: Sequence[float]) -> float:
    """Exact two-sided cluster permutation test against a zero mean difference.

    Enumerates all 2**k sign assignments of the per-cluster mean differences and
    counts those whose mean is at least as extreme as the observed one. This is
    the honest test for a paired design: the randomisation unit is the cluster,
    so the permutation unit is the cluster too.
    """
    k = len(cluster_means)
    if k == 0:
        raise ValueError("no clusters")
    if k > 20:
        raise ValueError(f"exact enumeration of 2**{k} assignments is not the intent here")
    observed = abs(sum(cluster_means) / k)
    # Guard the float comparison: a flipped copy of the observed assignment must
    # count as "at least as extreme" even when the arithmetic reorders.
    tol = 1e-12 * max(1.0, observed)
    hits = 0
    for mask in range(2**k):
        total = 0.0
        for i, m in enumerate(cluster_means):
            total += -m if (mask >> i) & 1 else m
        if abs(total / k) >= observed - tol:
            hits += 1
    return hits / (2**k)


# ---------------------------------------------------------------------------
# Power
# ---------------------------------------------------------------------------


def _betacf(a: float, b: float, x: float) -> float:
    maxit, eps, fpmin = 300, 3.0e-16, 1.0e-300
    qab, qap, qam = a + b, a + 1.0, a - 1.0
    c = 1.0
    d = 1.0 - qab * x / qap
    if abs(d) < fpmin:
        d = fpmin
    d = 1.0 / d
    h = d
    for m in range(1, maxit + 1):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < fpmin:
            d = fpmin
        c = 1.0 + aa / c
        if abs(c) < fpmin:
            c = fpmin
        d = 1.0 / d
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        if abs(d) < fpmin:
            d = fpmin
        c = 1.0 + aa / c
        if abs(c) < fpmin:
            c = fpmin
        d = 1.0 / d
        step = d * c
        h *= step
        if abs(step - 1.0) < eps:
            break
    return h


def _betai(a: float, b: float, x: float) -> float:
    """Regularised incomplete beta I_x(a, b) — the t distribution needs it.

    Hand-rolled because the evaluation harnesses carry no scipy dependency and
    adding one for two quantiles would be the largest new dependency in the
    directory. Pinned in the tests against published quantiles.
    """
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    lbeta = math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b)
    front = math.exp(lbeta + a * math.log(x) + b * math.log1p(-x))
    if x < (a + 1.0) / (a + b + 2.0):
        return front * _betacf(a, b, x) / a
    return 1.0 - front * _betacf(b, a, 1.0 - x) / b


def student_t_cdf(t: float, df: float) -> float:
    if df <= 0:
        raise ValueError("degrees of freedom must be positive")
    x = df / (df + t * t)
    tail = 0.5 * _betai(df / 2.0, 0.5, x)
    return tail if t <= 0 else 1.0 - tail


def student_t_ppf(p: float, df: float) -> float:
    """Inverse Student-t by bisection on the CDF. df here is 4, so speed is moot."""
    if not 0.0 < p < 1.0:
        raise ValueError(f"p must be in (0, 1), got {p}")
    lo, hi = -1.0e3, 1.0e3
    for _ in range(200):
        mid = (lo + hi) / 2.0
        if student_t_cdf(mid, df) < p:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2.0


def mde_paired(
    cluster_means: Sequence[float],
    *,
    alpha: float = 0.05,
    power: float = 0.80,
    use_t: bool = True,
) -> float:
    """Smallest paired difference this design could detect at the stated power.

    ``MDE = (q_{1-α/2} + q_{power}) · SD / √k``, where SD is the sample standard
    deviation of the k per-cluster mean differences.

    The assumption, stated because it is doing real work: the cluster-mean
    difference is approximately normal and the k clusters are exchangeable and
    independent. At k=5 the normal quantiles are optimistic, so ``use_t`` is the
    default and the t form is the one to report. Both are approximations to the
    exact noncentral-t calculation; at these cluster counts the difference
    between them is smaller than the difference between either and the truth.
    """
    k = len(cluster_means)
    if k < 2:
        raise ValueError(f"MDE needs at least two clusters, got {k}")
    m = sum(cluster_means) / k
    sd = math.sqrt(sum((x - m) ** 2 for x in cluster_means) / (k - 1))
    if use_t:
        df = k - 1
        q = student_t_ppf(1.0 - alpha / 2.0, df) + student_t_ppf(power, df)
    else:
        nd = NormalDist()
        q = nd.inv_cdf(1.0 - alpha / 2.0) + nd.inv_cdf(power)
    return q * sd / math.sqrt(k)


# ---------------------------------------------------------------------------
# Paired designs
# ---------------------------------------------------------------------------


def paired_cluster_result(
    deltas: Sequence[float],
    clusters: Sequence[Hashable],
    *,
    iters: int = DEFAULT_ITERS,
    seed: int,
    alpha: float = 0.05,
    power: float = 0.80,
) -> PairedResult:
    """Everything a paired comparison has to report, computed at the cluster level.

    The interval comes from the cluster bootstrap, the p-value from the exact
    sign-flip permutation, and the minimum detectable effect from the spread of
    the per-cluster means. Reporting the interval without the MDE is what let a
    null at five clusters read as evidence of equivalence.
    """
    order, groups = _grouped(list(deltas), list(clusters))
    cluster_means = tuple(sum(groups[c]) / len(groups[c]) for c in order)
    k = len(order)

    interval = cluster_bootstrap_ci(
        deltas, clusters, mean, iters=iters, seed=seed, alpha=alpha, method="cluster_bootstrap"
    )
    draws, _ = _cluster_draws(deltas, clusters, mean, iters=iters, seed=seed)
    structure = icc_oneway(deltas, clusters) if k >= 2 else None
    if structure is None:  # pragma: no cover - guarded by cluster_bootstrap_ci
        raise ValueError("a paired result needs at least two clusters")

    sd = math.sqrt(sum((x - sum(cluster_means) / k) ** 2 for x in cluster_means) / (k - 1))
    return PairedResult(
        delta=sum(deltas) / len(deltas),
        interval=interval,
        p_bootstrap=bootstrap_p(draws),
        p_exact=exact_signflip_p(cluster_means) if k <= 20 else None,
        p_floor=signflip_p_floor(k) if k <= 20 else None,
        structure=structure,
        cluster_sd=sd,
        mde_z=mde_paired(cluster_means, alpha=alpha, power=power, use_t=False),
        mde_t=mde_paired(cluster_means, alpha=alpha, power=power, use_t=True),
        n_pairs=len(deltas),
        cluster_means=cluster_means,
    )


# ---------------------------------------------------------------------------
# Multiplicity
# ---------------------------------------------------------------------------


def benjamini_hochberg(pvalues: Sequence[float]) -> list[float]:
    """Step-up BH q-values, monotone-enforced, returned in the input order."""
    m = len(pvalues)
    if m == 0:
        return []
    for p in pvalues:
        if not 0.0 <= p <= 1.0:
            raise ValueError(f"p-value out of range: {p}")
    order = sorted(range(m), key=lambda i: pvalues[i])
    q = [0.0] * m
    running = 1.0
    for rank in range(m, 0, -1):
        i = order[rank - 1]
        running = min(running, pvalues[i] * m / rank)
        q[i] = running
    return q


# ---------------------------------------------------------------------------
# Provenance
# ---------------------------------------------------------------------------


def module_sha256() -> str:
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def provenance(*, seed: int, iters: int = DEFAULT_ITERS) -> dict[str, Any]:
    """Merged into every harness's output so an interval is self-describing.

    ``stats_module_sha256`` is what tells two intervals apart that were computed
    under the same seed by different code — the case that made the pre-correction
    artifacts impossible to audit.
    """
    return {
        "stats_schema": SCHEMA,
        "seed": seed,
        "bootstrap_iters": iters,
        "stats_module_sha256": module_sha256(),
    }

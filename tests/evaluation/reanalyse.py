"""Recompute every interval in the paper at the unit its observations are independent at.

This reads only committed per-sample artifacts. No LLM, no network, no sandbox,
no re-run of anything. Every number it produces was already implicit in data the
studies retained; what was missing was an estimator that respected the nesting.

Three quantities go with every comparison, because any one of them alone
misleads at these cluster counts:

* the **cluster bootstrap interval** — the honest width, typically 1.6 to 2.4
  times the row-level interval that was published;
* the **exact cluster sign-flip p** — because the bootstrap p returns ~0 for any
  effect whose cluster means happen to share a sign, which at five clusters is
  not evidence of anything;
* the **minimum detectable effect** at 80% power — because a null from a design
  that could only ever have seen effects above 0.30 F1 says nothing about the
  0.003 it reported, and reading it as equivalence is the error this file exists
  to make impossible.

**The finding that dominates the rest.** Five of the studies run on a corpus of
five fixtures. At k=5 the exact two-sided cluster permutation test cannot return
a p below 2/2**5 = 0.0625. No comparison measured on that corpus can reach
α = 0.05, whatever its effect size. Multiplicity correction is therefore not the
binding constraint on those studies; the cluster count is.

Multiplicity is still applied, in two declared families, because reporting nine
comparisons and correcting none is the other half of the same error. The
partition is an explicit constant below rather than something inferred from the
data: a comparison added without a family assignment raises.

Run:  .venv/bin/python tests/evaluation/reanalyse.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tests.evaluation import stats  # noqa: E402

OUT = _HERE / "cluster_analysis.json"

SEED = 20260815
ITERS = 20_000

# Which corpus a study was measured on. Kept explicit because the paper drew two
# of them on one axis: the fixture corpus is five synthesised inputs whose
# evidence is generated from their own answer key, and the CAPE corpus is 97 real
# binaries with family-level MITRE ground truth. They are not comparable and
# nothing here may pool them.
FIXTURE_CORPUS = "fixtures-n5"
CAPE_CORPUS = "cape-n97"
# The consensus arms re-run on real binaries: one sample per malware family, so
# every cluster holds exactly one observation and k is the sample count. That is
# the whole reason the run exists. On the fixture corpus k=5, where the exact
# two-sided cluster sign-flip test cannot return below 2/2^5 = 0.0625 and no
# comparison can reach alpha whatever its effect. Here k is 24 and the floor is
# 2/2^24, so a result is possible in principle rather than excluded by design.
CAPE_CONSENSUS_CORPUS = "cape-n24"

# The declared families for multiplicity correction. A fourth group — per-arm
# descriptive intervals, firing rates, counts — carries no null and is not
# corrected; correcting an estimate is a category error.
FAMILY_A = ("P1", "P2", "P3", "P4")  # pre-registered primary comparisons
FAMILY_B = ("E1", "E2", "E3", "E4", "E5")  # post-hoc configuration sweep
# Declared separately rather than folded into Family A, and the reason is not
# convenience: these are the same two contrasts on a different corpus, run after
# Family A was analysed. Adding them to A would silently re-correct four
# published q-values against evidence that did not exist when they were
# pre-registered. A replication is its own confirmatory set.
FAMILY_C = ("C1", "C2")  # the same contrasts, on real binaries
# Below this many families the real-corpus comparisons are not reported at all.
# A partially complete run has fewer clusters than it will have, and an interval
# from twelve families printed in the same table as one from twenty-four invites
# exactly the reading the cluster correction was written to stop.
MIN_CAPE_FAMILIES = 20


class ReanalysisError(RuntimeError):
    """An input the re-analysis needs is missing or has changed shape."""


def load(name: str) -> Any:
    path = _HERE / name
    if not path.exists():
        raise ReanalysisError(f"missing artifact: {name}")
    return json.loads(path.read_text())


def _round(value: Any, places: int = 6) -> Any:
    """Round floats for the artifact so two runs cannot differ in the last bit."""
    if isinstance(value, float):
        return round(value, places)
    if isinstance(value, dict):
        return {k: _round(v, places) for k, v in value.items()}
    if isinstance(value, list):
        return [_round(v, places) for v in value]
    return value


# ---------------------------------------------------------------------------
# Inputs, each reduced to (values, clusters)
# ---------------------------------------------------------------------------


def _consensus_arms() -> dict[str, dict[tuple[str, int], float]]:
    rows = load("consensus_ablation.json")
    arms: dict[str, dict[tuple[str, int], float]] = {}
    for r in rows:
        if not isinstance(r.get("f1"), int | float):
            continue
        arms.setdefault(r["arm"], {})[(r["sample_id"], int(r["repeat"]))] = float(r["f1"])
    if not arms:
        raise ReanalysisError("consensus_ablation.json yielded no scored arms")
    return arms


def _cape_families() -> dict[str, str]:
    """sha256 -> malware family, from the cohort that selected the samples."""
    cohort = load("dynamic_cohort_n100.json")["samples"]
    return {s["sha256"]: s["signature"] for s in cohort}


def _consensus_arms_cape() -> tuple[dict[str, dict[tuple[str, int], float]], dict[str, str]]:
    """The consensus arms on real binaries, read per generation.

    The checkpoint is the record, not the summary beside it: the harness appends
    one line before starting the next generation, so it is what survives an
    interruption, and this run was interrupted by the memory guard and resumed
    three times. Reading the rolled-up JSON instead would quietly analyse
    whichever prefix happened to be written last.
    """
    path = _HERE / "consensus_cape_checkpoint.jsonl"
    if not path.exists():
        raise ReanalysisError("missing artifact: consensus_cape_checkpoint.jsonl")
    arms: dict[str, dict[tuple[str, int], float]] = {}
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        if not isinstance(r.get("f1"), int | float):
            continue
        arms.setdefault(r["arm"], {})[(r["sample_id"], int(r["repeat"]))] = float(r["f1"])
    if not arms:
        raise ReanalysisError("consensus_cape_checkpoint.jsonl yielded no scored arms")

    # A cluster count is not a completeness check, and treating it as one is how
    # this project already burned itself: an interim arm reported 0.5025 at n=9,
    # read as a lead, and completing the sample moved the estimate through the
    # local mean and out the other side. A partial run of this shape passes a
    # family threshold long before it is finished, because the families arrive
    # one at a time.
    #
    # The harness writes its rolled-up JSON only when a full pass over every
    # sample and arm returns. That file is therefore the run's own statement
    # that it finished, and it is the gate — not the row count.
    rolled = _HERE / "consensus_ablation_cape.json"
    finished = False
    if rolled.exists():
        cells = {
            (r["arm"], r["sample_id"], int(r["repeat"]))
            for r in json.loads(rolled.read_text())
            if isinstance(r.get("f1"), int | float)
        }
        checkpoint_cells = {
            (arm, sid, rep) for arm, cellmap in arms.items() for sid, rep in cellmap
        }
        finished = checkpoint_cells <= cells
    if not finished:
        arms = {}

    families = _cape_families()
    unmapped = sorted({sid for cells in arms.values() for sid, _ in cells if sid not in families})
    if unmapped:
        raise ReanalysisError(
            f"{len(unmapped)} scored samples are not in the cohort that selected them: "
            f"{', '.join(s[:12] for s in unmapped[:5])}"
        )
    return arms, families


def _frontier_arm(stem: str) -> dict[tuple[str, int], float]:
    d = load(f"{stem}.json")
    rows = d.get("per_sample")
    if not rows:
        raise ReanalysisError(f"{stem}.json has no per_sample rows")
    return {(r["sample_id"], int(r["repeat"])): float(r["f1"]) for r in rows}


def _paired(
    left: dict[tuple[str, int], float],
    right: dict[tuple[str, int], float],
    cluster_of: dict[str, str] | None = None,
) -> tuple[list[float], list[str]]:
    """Deltas over the keys both arms hold, clustered by sample or by family.

    On the fixture corpus the sample *is* the cluster — repeats of one fixture
    are the correlated unit. On real binaries the family is: two samples of the
    same family share ground truth, so treating them as independent is the
    error this whole re-analysis exists to correct.
    """
    keys = sorted(set(left) & set(right))
    if len(keys) < 2:
        raise ReanalysisError("fewer than two paired observations")
    clusters = [k[0] if cluster_of is None else cluster_of[k[0]] for k in keys]
    return [left[k] - right[k] for k in keys], clusters


def _paired_entry(
    label: str,
    title: str,
    left: dict,
    right: dict,
    corpus: str,
    iters: int = ITERS,
    cluster_of: dict[str, str] | None = None,
) -> dict[str, Any]:
    deltas, clusters = _paired(left, right, cluster_of)
    res = stats.paired_cluster_result(deltas, clusters, iters=iters, seed=SEED)
    entry: dict[str, Any] = {
        "id": label,
        "title": title,
        "corpus": corpus,
        "better": sum(1 for d in deltas if d > 0),
        "worse": sum(1 for d in deltas if d < 0),
        "tied": sum(1 for d in deltas if d == 0),
        **res.as_json(),
    }

    # What the intersection threw away, named rather than absorbed.
    #
    # On a complete design nothing is dropped and this is empty. On real
    # binaries it is not: an arm can fail to produce a cell, and the arms fail
    # unevenly — the expensive one times out first, on the samples whose
    # evidence is largest. That is informative missingness, and an interval
    # computed over the survivors without saying so reports a design that was
    # never run. The same binary that goes missing here is the one the
    # sink-hint ablation excluded for exceeding its own time bound.
    if cluster_of is not None:
        both = set(left) & set(right)
        either = set(left) | set(right)
        lost = sorted({cluster_of[sid] for sid, _ in either - both})
        entry["clusters_paired"] = len({cluster_of[sid] for sid, _ in both})
        entry["clusters_unpaired"] = lost
        if lost:
            entry["missingness"] = (
                "not missing at random: these families lack a cell because an arm "
                "did not return inside its time bound, and the arms do not fail "
                "evenly across samples"
            )
    return entry


# ---------------------------------------------------------------------------
# The comparisons
# ---------------------------------------------------------------------------


def comparisons(iters: int = ITERS) -> dict[str, dict[str, Any]]:
    arms = _consensus_arms()
    for needed in ("negotiated", "single", "noise"):
        if needed not in arms:
            raise ReanalysisError(f"consensus arm missing: {needed}")

    # "local" throughout the paper is the consensus ablation's single-judge arm:
    # our own 3-bit Qwen3.6-35B-A3B on one desktop GPU, run over the same five
    # fixtures at the same five repeats as every frontier arm. It is *not* one of
    # the frontier_probe files — two of those host the same weights at the
    # vendor's full precision, which is the comparison E1 exists to make.
    local = arms["single"]
    out: dict[str, dict[str, Any]] = {
        "P1": _paired_entry(
            "P1",
            "negotiated multi-agent consensus minus a single judge",
            arms["negotiated"],
            arms["single"],
            FIXTURE_CORPUS,
            iters,
        ),
        "P2": _paired_entry(
            "P2",
            "stochastic noise control minus a single judge",
            arms["noise"],
            arms["single"],
            FIXTURE_CORPUS,
            iters,
        ),
        "P3": _paired_entry(
            "P3",
            "the 120B frontier model minus our local 35B",
            _frontier_arm("frontier_probe"),
            local,
            FIXTURE_CORPUS,
            iters,
        ),
        "E1": _paired_entry(
            "E1",
            "the same 35B weights at the vendor's full precision, minus our "
            "3-bit local copy — the quantisation question",
            _frontier_arm("frontier_probe_qwen35ba3b_nothink"),
            local,
            FIXTURE_CORPUS,
            iters,
        ),
        "E2": _paired_entry(
            "E2",
            "reasoning off minus on, vendor-hosted 35B — the flag's replication",
            _frontier_arm("frontier_probe_qwen35ba3b_nothink"),
            _frontier_arm("frontier_probe_qwen35ba3b"),
            FIXTURE_CORPUS,
            iters,
        ),
        "E3": _paired_entry(
            "E3",
            "reasoning off minus on, the third endpoint — the flag's largest effect",
            _frontier_arm("frontier_probe_qwenplus_nothink"),
            _frontier_arm("frontier_probe_qwenplus"),
            FIXTURE_CORPUS,
            iters,
        ),
        "E4": _paired_entry(
            "E4",
            "the 120B re-run with the reasoning parameter requested off, against "
            "the run that did not request it — the provider accepted and ignored it",
            _frontier_arm("frontier_probe_default_nothink"),
            _frontier_arm("frontier_probe"),
            FIXTURE_CORPUS,
            iters,
        ),
        "E5": _paired_entry(
            "E5",
            "the vendor-hosted 35B with reasoning on, minus our local copy with it off",
            _frontier_arm("frontier_probe_qwen35ba3b"),
            local,
            FIXTURE_CORPUS,
            iters,
        ),
    }

    # The same two contrasts on real binaries, when that run has produced enough
    # to pair. It is skipped rather than faked while the run is still going: a
    # comparison over four families would be reported with the same confidence
    # as one over twenty-four, and the family count is the entire point.
    cape_arms, cape_families = _consensus_arms_cape()
    if {"single", "negotiated"} <= set(cape_arms):
        shared = set(cape_arms["single"]) & set(cape_arms["negotiated"])
        if len({cape_families[sid] for sid, _ in shared}) >= MIN_CAPE_FAMILIES:
            out["C1"] = _paired_entry(
                "C1",
                "negotiated multi-agent consensus minus a single judge, on real binaries",
                cape_arms["negotiated"],
                cape_arms["single"],
                CAPE_CONSENSUS_CORPUS,
                iters,
                cluster_of=cape_families,
            )
    if {"single", "noise"} <= set(cape_arms):
        shared = set(cape_arms["single"]) & set(cape_arms["noise"])
        if len({cape_families[sid] for sid, _ in shared}) >= MIN_CAPE_FAMILIES:
            out["C2"] = _paired_entry(
                "C2",
                "the noise control minus a single judge, on real binaries",
                cape_arms["noise"],
                cape_arms["single"],
                CAPE_CONSENSUS_CORPUS,
                iters,
                cluster_of=cape_families,
            )

    out["P4"] = confidence_auc(iters)
    return out


def confidence_auc(iters: int = ITERS) -> dict[str, Any]:
    """The gate-validity claim: does verbal confidence rank correctness?

    The paper reported AUC 0.550 with no interval. The claims are nested in
    samples — 210 of them from five — and once resampled at the sample the
    interval contains 0.5. Three of the five samples are at or below chance and
    the pooled number is carried by one, which is the finding rather than the
    interval.
    """
    rows = load("confidence_calibration.json")
    scores = [float(r["confidence"]) for r in rows]
    labels = [int(r["correct"]) for r in rows]
    clusters = [str(r["sample_id"]) for r in rows]

    point = stats.roc_auc(scores, labels)
    if point is None:
        raise ReanalysisError("confidence AUC is undefined — one class is empty")
    interval = stats.auc_cluster_ci(scores, labels, clusters, iters=iters, seed=SEED)

    per_cluster: dict[str, dict[str, Any]] = {}
    for c in sorted(set(clusters)):
        s = [v for v, k in zip(scores, clusters, strict=True) if k == c]
        y = [v for v, k in zip(labels, clusters, strict=True) if k == c]
        per_cluster[c] = {"n": len(s), "auc": stats.roc_auc(s, y)}

    aucs = [v["auc"] for v in per_cluster.values() if v["auc"] is not None]
    centred = [a - 0.5 for a in aucs]
    draws, _ = stats._cluster_draws(
        [float(i) for i in range(len(scores))],
        clusters,
        lambda idx: stats.roc_auc([scores[int(i)] for i in idx], [labels[int(i)] for i in idx]),
        iters=iters,
        seed=SEED,
    )
    return {
        "id": "P4",
        "title": "verbal confidence ranks correctness (AUC against chance)",
        "corpus": FIXTURE_CORPUS,
        "delta": point - 0.5,
        "point": point,
        "interval": interval.as_json(),
        "p_bootstrap": stats.bootstrap_p(draws, null=0.5),
        "p_exact_signflip": stats.exact_signflip_p(centred),
        "p_floor": stats.signflip_p_floor(len(centred)),
        "structure": stats.icc_oneway(scores, clusters).as_json(),
        "correct_structure": stats.icc_oneway([float(v) for v in labels], clusters).as_json(),
        "mde_t": stats.mde_paired(centred),
        "mde_z": stats.mde_paired(centred, use_t=False),
        "per_cluster": per_cluster,
        "clusters_at_or_below_chance": sum(1 for a in aucs if a <= 0.5),
        "naive_descending_sort_auc": _naive_auc(scores, labels),
    }


def _naive_auc(scores: list[float], labels: list[int]) -> float:
    """AUC from a descending sort with ties broken by input order, not averaged.

    The comparator the paper quotes to show how much tie handling matters. It is
    derived rather than quoted because it is *defined* by an ordering, so a
    literal copied from an earlier run cannot be checked against anything.
    """
    order = sorted(range(len(scores)), key=lambda i: -scores[i])
    pos = sum(labels)
    neg = len(labels) - pos
    if not pos or not neg:
        raise ReanalysisError("naive AUC undefined — one class is empty")
    seen_neg = 0
    correct = 0
    for i in order:
        if labels[i] == 0:
            seen_neg += 1
        else:
            correct += seen_neg
    return 1.0 - correct / (pos * neg)


# ---------------------------------------------------------------------------
# Descriptive intervals (family C — no null, no correction)
# ---------------------------------------------------------------------------


def cape_baseline(iters: int = ITERS) -> dict[str, Any]:
    """The no-LLM anchor, resampled at the family because the labels are per family."""
    d = load("cape_baseline.json")
    rows = d.get("per_sample")
    if not rows:
        raise ReanalysisError("cape_baseline.json has no per-sample rows")
    families = [str(r["slug"]) for r in rows]
    out: dict[str, Any] = {"corpus": CAPE_CORPUS, "n": len(rows), "k": len(set(families))}
    for metric in ("precision", "recall", "f1"):
        vals = [float(r[metric]) for r in rows]
        interval = stats.cluster_bootstrap_ci(vals, families, iters=iters, seed=SEED)
        row_level = stats.cluster_bootstrap_ci(vals, list(range(len(vals))), iters=iters, seed=SEED)
        out[metric] = {
            "interval": interval.as_json(),
            "row_level_interval": row_level.as_json(),
            "widening": interval.width / row_level.width if row_level.width else None,
            "structure": stats.icc_oneway(vals, families).as_json(),
        }
    return out


def head_to_head(iters: int = ITERS) -> dict[str, Any]:
    """Pipeline against the no-LLM baseline **on the same samples**.

    The paper states three F1 values side by side — CAPE alone, the pipeline on
    static evidence, the pipeline with the sandbox report — with no sample size
    and no artifact behind the first of them. It is the only place the pipeline
    is compared to its baseline like for like, and it was the one number that
    could not be traced.

    Derived here: the 13 samples that completed both arms of the dynamic-vs-static
    study, scored for CAPE with the same signature-to-technique map and the same
    family-level ground truth the baseline study uses. Every arm on one axis, one
    population, one truth — which is what Figure 1 needed and did not have.
    """
    from tests.evaluation.eval_cape_baseline import cape_technique_ids
    from tests.evaluation.eval_temporal_drift import (
        available_fixture_slugs,
        load_ground_truth,
        resolve_fixture_slug,
    )
    from tests.evaluation.metrics import TTPAccuracyMetrics

    gt_dir = _HERE / "ground_truth" / "attck_malware"
    reports_dir = _REPO_ROOT / "data" / "cape_reports"
    slugs = available_fixture_slugs(gt_dir)
    cohort = load("dynamic_cohort_n100.json")
    by_sha = {s["sha256"]: s for s in cohort["samples"]}

    pairs = load("dynamic_vs_static.json").get("per_pair") or []
    if not pairs:
        raise ReanalysisError("dynamic_vs_static.json has no per_pair rows")

    rows: list[dict[str, Any]] = []
    for pair in pairs:
        sha = pair["sha256"]
        meta = by_sha.get(sha)
        report_path = reports_dir / f"{sha}.json"
        if meta is None or not report_path.exists():
            raise ReanalysisError(f"head-to-head sample {sha[:12]} has no report or cohort entry")
        slug = resolve_fixture_slug(meta.get("signature") or "", slugs)
        if slug is None:
            raise ReanalysisError(f"head-to-head sample {sha[:12]} resolves to no family")
        truth, valid = load_ground_truth(slug, gt_dir)
        report = json.loads(report_path.read_text())
        cape = TTPAccuracyMetrics(
            predicted_ttps=cape_technique_ids(report),
            ground_truth_ttps=truth,
            attck_valid_ttps=valid,
        )
        rows.append(
            {
                "sha256": sha,
                "family": slug,
                "cape_f1": cape.f1,
                "static_only_f1": float(pair["static_only"]["f1"]),
                "dynamic_f1": float(pair["dynamic"]["f1"]),
            }
        )

    families = [r["family"] for r in rows]
    out: dict[str, Any] = {
        "n": len(rows),
        "k": len(set(families)),
        "corpus": CAPE_CORPUS,
        "note": "the 13 samples that completed both arms, all three scored on one truth",
        "per_sample": rows,
    }
    for arm in ("cape_f1", "static_only_f1", "dynamic_f1"):
        vals = [r[arm] for r in rows]
        out[arm] = {
            "mean": sum(vals) / len(vals),
            "interval": stats.cluster_bootstrap_ci(
                vals, families, iters=iters, seed=SEED
            ).as_json(),
        }
    # The claim the paper makes with these numbers: does the whole pipeline beat
    # the signature engine it is built on? Paired, because every sample was run
    # through both.
    deltas = [r["dynamic_f1"] - r["cape_f1"] for r in rows]
    res = stats.paired_cluster_result(deltas, families, iters=iters, seed=SEED)
    out["pipeline_minus_cape"] = {
        "better": sum(1 for d in deltas if d > 0),
        "worse": sum(1 for d in deltas if d < 0),
        **res.as_json(),
    }
    return out


def arm_intervals(iters: int = ITERS) -> dict[str, Any]:
    """Per-arm F1 with a cluster interval. Estimates, so no p and no q."""
    out: dict[str, Any] = {}
    arms = _consensus_arms()
    for name, by_key in arms.items():
        keys = sorted(by_key)
        vals = [by_key[k] for k in keys]
        clusters = [k[0] for k in keys]
        out[f"consensus_{name}"] = {
            "corpus": FIXTURE_CORPUS,
            "interval": stats.cluster_bootstrap_ci(
                vals, clusters, iters=iters, seed=SEED
            ).as_json(),
            "structure": stats.icc_oneway(vals, clusters).as_json(),
        }
    for stem in (
        "frontier_probe",
        "frontier_probe_default_nothink",
        "frontier_probe_qwen35ba3b",
        "frontier_probe_qwen35ba3b_nothink",
        "frontier_probe_qwenplus",
        "frontier_probe_qwenplus_nothink",
    ):
        by_key = _frontier_arm(stem)
        keys = sorted(by_key)
        vals = [by_key[k] for k in keys]
        clusters = [k[0] for k in keys]
        entry: dict[str, Any] = {"corpus": FIXTURE_CORPUS}
        # A wholly degenerate arm — every F1 identical — has no interval to
        # estimate and no ICC to speak of. Reported as degenerate rather than
        # given a zero-width interval that would read as precision.
        if len(set(vals)) == 1:
            entry["degenerate_at"] = vals[0]
        else:
            entry["interval"] = stats.cluster_bootstrap_ci(
                vals, clusters, iters=iters, seed=SEED
            ).as_json()
            entry["structure"] = stats.icc_oneway(vals, clusters).as_json()
        out[stem] = entry
    return out


def judge_contribution_bound() -> dict[str, Any]:
    """ "80 of 80 arms" is 8 samples, and the honest statement is an upper bound.

    The mechanism check produced 80 rows over 8 sample ids, ten arms each. The
    rows within a sample are not independent trials of anything — they are one
    sample under ten configurations — so the denominator for "the judge added
    nothing" is 8, not 80. With 0 of 8 the Rule of Three gives a 95% upper bound
    of 3/8 on the per-sample rate.
    """
    d = load("b3_mechanism_check.json")
    rows = d.get("per_arm")
    if not rows:
        raise ReanalysisError("b3_mechanism_check.json has no per_arm rows")
    samples = {str(r["sample_id"]) for r in rows}
    added = {
        str(r["sample_id"]) for r in rows if r.get("judge_only_techniques") or r.get("judge_added")
    }
    k = len(samples)
    return {
        "arms": len(rows),
        "samples": k,
        "samples_where_the_judge_added_a_technique": len(added),
        "rule_of_three_upper_bound": 3.0 / k if k else None,
        "note": (
            "the row count is arms, not independent trials; the denominator that "
            "supports an inference is the sample count"
        ),
    }


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------


def _cape_cluster_count(comps: dict[str, Any]) -> int | None:
    """The family count the replication achieved, or None if it has not run.

    Reported in the design block rather than left to be read off an interval,
    because it is the number that decides whether the exact test has any room:
    at k the floor is 2/2**k, and the fixture corpus's k=5 put every comparison
    below alpha by construction.
    """
    ks = {c["structure"]["k"] for c in comps.values() if c["corpus"] == CAPE_CONSENSUS_CORPUS}
    if not ks:
        return None
    if len(ks) != 1:
        raise ReanalysisError(f"the replication corpus reports several cluster counts: {ks}")
    return ks.pop()


def analyse(iters: int = ITERS) -> dict[str, Any]:
    comps = comparisons(iters)

    declared = set(FAMILY_A) | set(FAMILY_B) | set(FAMILY_C)
    undeclared = sorted(set(comps) - declared)
    if undeclared:
        raise ReanalysisError("comparisons with no multiplicity family: " + ", ".join(undeclared))
    # Family C is conditional: its run may not have finished. A and B are not.
    missing = sorted((set(FAMILY_A) | set(FAMILY_B)) - set(comps))
    if missing:
        raise ReanalysisError("declared family members never computed: " + ", ".join(missing))

    families: dict[str, Any] = {}
    groups: list[tuple[str, tuple[str, ...]]] = [
        ("A_primary", FAMILY_A),
        ("B_posthoc", FAMILY_B),
    ]
    present_c = tuple(m for m in FAMILY_C if m in comps)
    if present_c:
        groups.append(("C_replication", present_c))
    for name, members in groups:
        p_boot = [comps[m]["p_bootstrap"] for m in members]
        p_exact = [comps[m]["p_exact_signflip"] for m in members]
        q_boot = stats.benjamini_hochberg(p_boot)
        q_exact = stats.benjamini_hochberg(p_exact)
        for m, qb, qe in zip(members, q_boot, q_exact, strict=True):
            comps[m]["q_bootstrap"] = qb
            comps[m]["q_exact"] = qe
            comps[m]["family"] = name
        families[name] = {
            "members": list(members),
            "m": len(members),
            "survivors_at_q05_bootstrap": sum(1 for q in q_boot if q <= 0.05),
            "survivors_at_q05_exact": sum(1 for q in q_exact if q <= 0.05),
        }

    fixture_k = {c["structure"]["k"] for c in comps.values() if c["corpus"] == FIXTURE_CORPUS}
    if len(fixture_k) != 1:
        raise ReanalysisError(f"the fixture corpus reports several cluster counts: {fixture_k}")
    k = fixture_k.pop()

    return _round(
        {
            "schema": "maljan-cluster-analysis/v1",
            "note": (
                "every interval recomputed at the cluster the observations are "
                "independent at; no LLM, no re-run, committed artifacts only"
            ),
            **stats.provenance(seed=SEED, iters=iters),
            "design": {
                "fixture_clusters": k,
                "signflip_floor": stats.signflip_p_floor(k),
                "floor_note": (
                    f"at {k} clusters the exact two-sided cluster permutation test "
                    f"cannot return a p below {stats.signflip_p_floor(k)}; no comparison "
                    "on this corpus can reach alpha=0.05 whatever its effect size"
                ),
                "corpora": {
                    FIXTURE_CORPUS: "five synthesised fixtures, evidence generated "
                    "from their own technique lists",
                    CAPE_CORPUS: "97 real Windows PE samples over 24 families, "
                    "family-level MITRE ground truth",
                    CAPE_CONSENSUS_CORPUS: "one real sample per family, so each "
                    "cluster holds one observation and the family count is the "
                    "cluster count",
                },
                "corpora_comparable": False,
                "replication_clusters": _cape_cluster_count(comps),
            },
            "families": families,
            "comparisons": comps,
            "cape_baseline": cape_baseline(iters),
            "head_to_head": head_to_head(iters),
            "arms": arm_intervals(iters),
            "judge_contribution": judge_contribution_bound(),
        }
    )


def main(out: Path | None = None) -> int:
    result = analyse()
    target = out or OUT
    target.write_text(json.dumps(result, indent=1, sort_keys=True) + "\n")

    d = result["design"]
    print(f"fixture corpus: {d['fixture_clusters']} clusters, exact-p floor {d['signflip_floor']}")
    print()
    header = (
        f"{'id':4s} {'effect':>9s}  {'cluster CI':<22s} {'p_exact':>8s} {'q_exact':>8s} {'MDE':>7s}"
    )
    print(header)
    print("-" * len(header))
    for cid in list(FAMILY_A) + list(FAMILY_B) + list(FAMILY_C):
        c = result["comparisons"].get(cid)
        if c is None:
            continue
        iv = c["interval"]
        ci = f"[{iv['lo']:+.4f}, {iv['hi']:+.4f}]"
        print(
            f"{cid:4s} {c['delta']:+9.4f}  {ci:<22s} "
            f"{c['p_exact_signflip']:8.4f} {c['q_exact']:8.4f} {c['mde_t']:7.3f}"
        )
    cb = result["cape_baseline"]["f1"]
    print(
        f"\nCAPE baseline F1 {cb['interval']['point']:.4f} "
        f"[{cb['interval']['lo']:.4f}, {cb['interval']['hi']:.4f}] "
        f"({cb['widening']:.2f}x the row-level width, effective n "
        f"{cb['structure']['effective_n']:.1f} over {cb['structure']['k']} families)"
    )
    jc = result["judge_contribution"]
    print(
        f"judge contribution: {jc['samples_where_the_judge_added_a_technique']} of "
        f"{jc['samples']} samples ({jc['arms']} arms), upper bound "
        f"{jc['rule_of_three_upper_bound']:.3f}"
    )
    print(f"\nwrote {target.relative_to(_REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

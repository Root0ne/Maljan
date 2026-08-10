"""C5: what CAPE alone scores, with no LLM anywhere in the loop.

**Why this is the highest-value number in the queue.** Every F1 this project has
reported is unanchored. A number is neither good nor bad until something else
has been scored on the same samples against the same ground truth, and the
natural something-else is the sandbox the pipeline is built on top of: CAPE
maps its own signature hits to ATT&CK technique IDs in the
``ttps`` block of every report, deterministically and without a model. That is
the baseline. If the pipeline cannot beat it, the pipeline's contribution is not
the number it reports.

**What is compared.** Per sample: CAPE's ``ttps`` technique IDs against the
sample family's MITRE ``uses`` set, resolved through the same alias map the
temporal-drift harness uses so the two studies score identically.

**The ceiling this inherits, stated once.** Family-level ``uses`` sets are a
coarse per-sample truth — one Emotet binary need not exhibit all ~47 catalogued
Emotet techniques — so absolute recall carries a structural ceiling. That bias
is constant across arms, which is exactly why a baseline matters: it is the only
way to read the pipeline's number as anything other than "low".

**No cross-study comparison.** Figures reported elsewhere in this project were
measured on other corpora under other conditions, and comparing to them would be
the unanchored claim this item exists to end. The comparison that counts is the
pipeline on these same samples — C3/C4.

Reads the local archive written by the report fetcher; no network, no sandbox.
"""

from __future__ import annotations

import json
import random
import sys
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tests.evaluation.eval_temporal_drift import (  # noqa: E402
    available_fixture_slugs,
    load_ground_truth,
    resolve_fixture_slug,
)
from tests.evaluation.metrics import TTPAccuracyMetrics  # noqa: E402

REPORTS_DIR = _REPO_ROOT / "data" / "cape_reports"
COHORT = _HERE / "dynamic_cohort_n100.json"
GT_DIR = _HERE / "ground_truth" / "attck_malware"
OUT = _HERE / "cape_baseline.json"
SEED = 20260810


def cape_technique_ids(report: dict[str, Any]) -> set[str]:
    """The technique IDs CAPE itself asserts, from the report's ``ttps`` block.

    Each entry is ``{"signature": ..., "ttps": [...], "mbcs": [...]}``. Only the
    ATT&CK ids are taken; MBC ids describe behaviour in a different vocabulary
    and mixing them would inflate the count with things ground truth cannot
    contain.
    """
    out: set[str] = set()
    for entry in report.get("ttps") or []:
        if not isinstance(entry, dict):
            continue
        for tid in entry.get("ttps") or []:
            text = str(tid).strip().upper()
            if text.startswith("T"):
                out.add(text)
    return out


def bootstrap_ci(values: list[float], iters: int = 2000, seed: int = SEED) -> tuple[float, float]:
    """Percentile bootstrap CI of the mean. Degenerate input returns the point."""
    if not values:
        return (0.0, 0.0)
    if len(values) == 1:
        return (values[0], values[0])
    rng = random.Random(seed)
    means = []
    n = len(values)
    for _ in range(iters):
        means.append(sum(rng.choice(values) for _ in range(n)) / n)
    means.sort()
    return (means[int(0.025 * iters)], means[int(0.975 * iters)])


def main() -> int:
    cohort = json.loads(COHORT.read_text())
    slugs = available_fixture_slugs(GT_DIR)
    by_sha = {s["sha256"]: s for s in cohort["samples"]}

    rows: list[dict[str, Any]] = []
    skipped: dict[str, list[str]] = {"no_report": [], "no_ground_truth": []}

    for sha, sample in by_sha.items():
        path = REPORTS_DIR / f"{sha}.json"
        if not path.exists():
            skipped["no_report"].append(sha)
            continue
        slug = resolve_fixture_slug(sample.get("signature") or "", slugs)
        if slug is None:
            skipped["no_ground_truth"].append(sha)
            continue
        gt, valid = load_ground_truth(slug, GT_DIR)
        report = json.loads(path.read_text())
        predicted = cape_technique_ids(report)
        m = TTPAccuracyMetrics(
            predicted_ttps=predicted, ground_truth_ttps=gt, attck_valid_ttps=valid
        )
        rows.append(
            {
                "sha256": sha,
                "year": sample["year"],
                "family": sample.get("signature"),
                "slug": slug,
                "n_predicted": len(predicted),
                "n_ground_truth": len(gt),
                "predicted": sorted(predicted),
                "precision": m.precision,
                "recall": m.recall,
                "f1": m.f1,
                "malscore": report.get("malscore"),
                "n_signatures": len(report.get("signatures") or []),
            }
        )

    print(
        f"scored={len(rows)}  no_report={len(skipped['no_report'])}  "
        f"no_ground_truth={len(skipped['no_ground_truth'])}"
    )
    if not rows:
        print("nothing to score yet — fetch reports first")
        return 1

    summary: dict[str, Any] = {"n": len(rows)}
    for key in ("precision", "recall", "f1"):
        vals = [r[key] for r in rows]
        mean = sum(vals) / len(vals)
        lo, hi = bootstrap_ci(vals)
        summary[key] = {"mean": round(mean, 4), "ci95": [round(lo, 4), round(hi, 4)]}
        print(f"  {key:9s} mean={mean:.4f}  95% CI [{lo:.4f}, {hi:.4f}]")

    empty = sum(1 for r in rows if r["n_predicted"] == 0)
    print(f"  samples where CAPE asserted no technique at all: {empty}/{len(rows)}")
    preds = sorted(r["n_predicted"] for r in rows)
    print(
        f"  techniques per sample: min={preds[0]} median={preds[len(preds) // 2]} max={preds[-1]}"
    )

    OUT.write_text(
        json.dumps(
            {
                "schema": "maljan-cape-baseline/v1",
                "note": "CAPE's own signature-derived ATT&CK ids, no LLM in the loop",
                "cohort_digest": cohort["cohort_digest"],
                "seed": SEED,
                "summary": summary,
                "empty_prediction_samples": empty,
                "skipped": {k: len(v) for k, v in skipped.items()},
                "per_sample": rows,
            },
            indent=1,
        )
    )
    print(f"wrote {OUT.relative_to(_REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Did B3 measure the judge, or a deterministic reconciliation step?

§3.27 reports B3 as an LLM result: *"the verdict follows the claims and ignores
the corroboration"* — 0 of 32 verdicts changed in the overlap condition, 32 of 32
in the disjoint condition. The reading was that the judge attends to the claim
list and not to the cascade's ranking or agreement flags.

**That reading may be an artefact of a code path nobody accounted for.** On
2026-08-14, while running C3, the log line

    judge_postprocess: added 51 cascade technique(s) the verdict LLM omitted

exposed ``_reconcile_with_cascade``: after the judge speaks, *every* technique in
``cascade_summary.results`` that is missing from the bundle is appended to it.
The cascade's technique set is therefore a guaranteed **subset of every bundle**,
whatever the judge produced. Verified directly against the function on a
synthetic bundle the same day.

If that is what drove B3, then both halves follow with no judge involvement at
all:

* **overlap** — removing a source whose every claim is duplicated by another
  leaves ``results`` unchanged, so the injected set is unchanged, so the bundle
  is unchanged. Predicted: 0 changes.
* **disjoint** — removing a source removes its techniques from ``results``
  entirely, so the injected set shrinks. Predicted: 32 changes.

Both are exactly what §3.27 observed. That is not evidence the account is wrong,
but it means the observation cannot distinguish the two explanations — and the
one already in the paper credits an LLM for the behaviour of an ``if`` statement.

This script decides it **offline**, from records already on disk. For every B3
arm it rebuilds the cascade set the harness would have produced — the same
fixtures, the same seeded assignment, the same construction — and compares it to
the technique set actually recorded for that arm.

* bundle == cascade set, every arm → the judge contributed **nothing** the
  cascade did not already hold, and §3.27's mechanism is the reconciliation.
* bundle ⊃ cascade set on some arms → the judge added techniques of its own, and
  §3.27's account survives for that residue, which is then the real measurement.

Run:  .venv/bin/python tests/evaluation/verify_b3_mechanism.py
No services, no network — reads `layer0_verdict_v2*.json` and recomputes.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent.parent
for _p in (_REPO_ROOT, _REPO_ROOT / "src"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from tests.evaluation.eval_layer0_verdict import (  # noqa: E402
    assign_to_sources,
    build_isr_reports,
    load_large_fixtures,
)

OUT = _HERE / "b3_mechanism_check.json"


def cascade_technique_ids(isr_reports: dict[str, Any]) -> set[str]:
    """The set ``_reconcile_with_cascade`` would inject for these ISRs.

    Read from ``results`` rather than from ``ranked_techniques`` because that is
    the field ``judge_agent`` uses to build ``valid_technique_ids``.
    """
    from maljan.analysis.ttp_cascade import TTPCascadeEngine

    summary = TTPCascadeEngine().compute(isr_reports)
    return {str(r.technique_id).upper() for r in getattr(summary, "results", []) if r.technique_id}


def load_arms() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for name in (
        "layer0_verdict_v2_overlap.json",
        "layer0_verdict_v2_disjoint.json",
        "layer0_verdict_v2.json",
    ):
        path = _HERE / name
        if not path.exists():
            continue
        blob = json.loads(path.read_text())
        condition = "overlap" if "overlap" in name else "disjoint" if "disjoint" in name else None
        per = blob.get("per_arm") or blob.get("per_sample") or blob.get("arms") or []
        for r in per:
            if isinstance(r, dict) and r.get("technique_ids") is not None:
                rows.append({**r, "_source": name, "_condition": r.get("condition") or condition})
    return rows


def main() -> int:
    arms = load_arms()
    if not arms:
        print("no B3 arm records found — nothing to check")
        return 1

    fixtures = dict(load_large_fixtures())
    checked: list[dict[str, Any]] = []
    skipped = 0

    for row in arms:
        sid = row.get("sample_id")
        arm = row.get("arm")
        cond = row.get("_condition")
        truth = fixtures.get(sid)
        if truth is None or arm is None or cond not in {"overlap", "disjoint"}:
            skipped += 1
            continue
        assignment = assign_to_sources(truth, overlap=(cond == "overlap"))
        isr = build_isr_reports(assignment, arm)
        cascade = cascade_technique_ids(isr)
        bundle = {str(t).upper() for t in (row.get("technique_ids") or [])}
        checked.append(
            {
                "sample_id": sid,
                "arm": arm,
                "condition": cond,
                "n_cascade": len(cascade),
                "n_bundle": len(bundle),
                "cascade_is_subset": cascade.issubset(bundle),
                "judge_only": sorted(bundle - cascade),
                "missing_from_bundle": sorted(cascade - bundle),
                "identical": cascade == bundle,
            }
        )

    if not checked:
        print(f"nothing comparable (skipped {skipped}) — arm/condition/sample keys did not line up")
        return 1

    n = len(checked)
    identical = sum(1 for c in checked if c["identical"])
    subset = sum(1 for c in checked if c["cascade_is_subset"])
    with_extra = [c for c in checked if c["judge_only"]]
    extra_total = sum(len(c["judge_only"]) for c in checked)
    missing_any = [c for c in checked if c["missing_from_bundle"]]

    print(f"arms compared: {n}  (skipped {skipped})")
    print(f"  cascade set is a subset of the bundle : {subset}/{n}")
    print(f"  bundle is exactly the cascade set     : {identical}/{n}")
    print(f"  arms where the judge added anything   : {len(with_extra)}/{n}")
    print(f"  techniques added by the judge, total  : {extra_total}")
    if missing_any:
        print(f"  arms missing cascade techniques       : {len(missing_any)}/{n}  <-- unexpected")

    verdict = (
        "RECONCILIATION" if identical == n else "JUDGE-RESIDUE" if len(with_extra) > 0 else "MIXED"
    )
    print(f"\nverdict: {verdict}")
    if verdict == "RECONCILIATION":
        print(
            "  Every bundle equals the cascade's own technique set. B3 measured\n"
            "  `_reconcile_with_cascade`, not the judge, and §3.27's mechanism\n"
            "  statement has to be rewritten: the judge did not 'follow the claims',\n"
            "  its technique output was replaced by them."
        )
    elif verdict == "JUDGE-RESIDUE":
        print(
            f"  The judge contributed {extra_total} technique(s) across {len(with_extra)} arm(s)\n"
            "  beyond what the cascade injected. §3.27's account applies to that residue;\n"
            "  the rest of the signal is the reconciliation step."
        )

    OUT.write_text(
        json.dumps(
            {
                "schema": "b3-mechanism-check/v1",
                "n_arms": n,
                "skipped": skipped,
                "cascade_subset_of_bundle": subset,
                "bundle_equals_cascade": identical,
                "arms_with_judge_additions": len(with_extra),
                "judge_added_techniques_total": extra_total,
                "verdict": verdict,
                "per_arm": checked,
            },
            indent=1,
        )
        + "\n"
    )
    print(f"\nwrote {OUT.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

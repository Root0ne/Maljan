"""When the judge times out, is the analyst's artefact the same one? — deterministic.

C3 found that four of eight judge calls never reach `_reconcile_with_cascade`
(§3.36): they time out, and `give_verdict` returns `_fallback_bundle_from_text`,
which does not consult the cascade at all. It builds its technique list by
scraping ATT&CK ids out of the raw ISR claims instead.

That leaves a question C3 records the inputs for but does not answer. **Does the
analyst receive a different set of techniques when the verdict times out?** Both
paths produce a bundle of comparable size — 20, 25, 23 and 16 techniques against
cascade sets of similar magnitude — and a reader could reasonably assume the
difference is cosmetic. It might equally be a different artefact wearing the same
shape, which is the failure mode this whole project keeps finding.

Nothing here needs a model. The cascade set is a deterministic function of the
seeded fixture, computed exactly as `eval_judge_contribution` computes it, and
the fallback's technique ids were recorded per call at the time. So this compares
two sets that both already exist.

**Read the output with §3.27.1 in mind.** Cascade membership is unconditional —
`compute` appends a result for every claimed technique id and the weights only
score them — and the fallback scrapes ids from those same claims. So an equality
here is a necessity of set arithmetic, not evidence of agreement, and the report
says so rather than reporting a Jaccard of 1.000 as a result. What the comparison
is actually good for is the *inverse*: the cascade has three filters the fallback
does not have (platform gating, empty-domain gating, the placeholder denylist),
and this study establishes whether any of them were active. If none were, the
paths agreed by construction and would diverge on a sample where one fires.

Reads the C3 checkpoint. Writes `fallback_bundle_content.{json,md}`.

Run:  .venv/bin/python tests/evaluation/eval_fallback_bundle_content.py
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

from tests.evaluation._tally import Tally  # noqa: E402
from tests.evaluation.eval_layer0_verdict import (  # noqa: E402
    assign_to_sources,
    build_isr_reports,
    load_large_fixtures,
)

CHECKPOINT = Path("/tmp/judge_contribution_checkpoint.jsonl")
OUT_JSON = _HERE / "fallback_bundle_content.json"
OUT_MD = _HERE / "fallback_bundle_content.md"


def cascade_ids_for(truth: list[str]) -> set[str]:
    """The technique set the cascade would have injected, for one fixture.

    Built through the same two calls the C3 harness makes before invoking the
    judge, so this is the set that *would* have reached the bundle had the call
    not timed out — not a re-derivation that might differ.
    """
    from maljan.analysis.ttp_cascade import TTPCascadeEngine

    isr_reports = build_isr_reports(assign_to_sources(truth, overlap=True), "all")
    summary = TTPCascadeEngine().compute(isr_reports)
    return {str(r.technique_id).strip().upper() for r in summary.results if r.technique_id}


def jaccard(a: set[str], b: set[str]) -> float:
    union = a | b
    return len(a & b) / len(union) if union else 1.0


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Fallback-vs-cascade technique sets.")
    ap.add_argument(
        "--checkpoint",
        default=str(CHECKPOINT),
        help="C3 checkpoint to read. Defaults to the live one; pass a preserved "
        "run to compare conditions without disturbing the current one.",
    )
    ap.add_argument("--suffix", default="", help="Appended to the output filenames.")
    args = ap.parse_args()

    checkpoint = Path(args.checkpoint)
    if not checkpoint.exists():
        print(f"no C3 checkpoint at {checkpoint} — run eval_judge_contribution.py first")
        return 1

    rows = []
    tally = Tally()
    for line in checkpoint.read_text().splitlines():
        tally.attempt()
        try:
            row = json.loads(line)
        except Exception as exc:  # noqa: BLE001
            tally.drop("torn_line", detail=type(exc).__name__)
            continue
        tally.parse_ok()
        tally.score_ok()
        rows.append(row)
    fallbacks = [r for r in rows if r.get("path") == "fallback"]
    if not fallbacks:
        print("no fallback calls on record — nothing to compare")
        return 1

    truth_by_id = dict(load_large_fixtures())

    per_call: list[dict[str, Any]] = []
    for row in fallbacks:
        sid = str(row.get("sample_id") or "")
        truth = truth_by_id.get(sid)
        if truth is None:
            continue
        fb = {str(t).strip().upper() for t in (row.get("fallback_technique_ids") or [])}
        casc = cascade_ids_for(truth)
        per_call.append(
            {
                "sample_id": sid,
                "reason": row.get("fallback_reason"),
                "fallback_n": len(fb),
                "cascade_n": len(casc),
                "shared": len(fb & casc),
                "only_in_fallback": sorted(fb - casc),
                "only_in_cascade": sorted(casc - fb),
                "jaccard": round(jaccard(fb, casc), 4),
                "identical": fb == casc,
            }
        )

    if not per_call:
        print("no fallback call could be matched to a fixture — aborting")
        return 1

    n = len(per_call)
    identical = sum(1 for c in per_call if c["identical"])
    lines = [
        "# Does a failed verdict change what the analyst receives?",
        "",
        f"{n} calls that fell back before reconciliation, compared against the cascade set each",
        "would have been given had it completed. Deterministic: no model was called.",
        "",
        "| fixture | fallback | cascade | shared | only in fallback | only in cascade | Jaccard |",
        "|---|---|---|---|---|---|---|",
    ]
    for c in per_call:
        lines.append(
            f"| `{c['sample_id']}` | {c['fallback_n']} | {c['cascade_n']} | {c['shared']} | "
            f"{len(c['only_in_fallback'])} | {len(c['only_in_cascade'])} | {c['jaccard']:.3f} |"
        )

    lines.append("")
    if identical == n:
        lines += [
            f"**Identical on {n} of {n} — and this is arithmetic, not a measurement.** Say",
            "so first, because a Jaccard of 1.000 is exactly what this project has twice",
            "written up as a finding before discovering it could not have come out otherwise.",
            "",
            "`TTPCascadeEngine.compute` appends a `CascadeResult` for **every** technique id",
            "any source claimed — there is no membership threshold; the weights set",
            "`weighted_confidence` and nothing else. `_fallback_bundle_from_text` scrapes ids",
            "from those same ISR claims with a `T\\d{4}` regex. Two routes to *the set of",
            "claimed technique ids*, so equality is the only possible result under this",
            "harness's configuration, and the table confirms the configuration rather than",
            "discovering the equality.",
            "",
            "**What it is still worth having.** The two paths are *not* equal in general, and",
            "the conditions under which they diverge are in the cascade and absent here:",
            "",
            "* `sample_platform` — the cascade drops claims whose rule declared an",
            "  incompatible platform; the fallback regex keeps them. Here it is `None`.",
            "* `empty_domains` — the cascade drops claims from a domain that produced no",
            "  input, so an absent sandbox cannot count as corroboration; the fallback has no",
            "  such notion. Not exercised here.",
            "* the placeholder denylist (`T0000`, `T9999`, `T1234`) — rejected by the",
            "  cascade, matched by the regex. None appear in these fixtures.",
            "",
            "So on a real sample where the sandbox is empty or a rule is platform-gated —",
            "the ordinary case — a timed-out verdict would hand the analyst techniques the",
            "cascade would have dropped, with nothing in the bundle recording which path",
            "built it. That is the claim this study supports: not that the paths agree, but",
            "that **nothing makes them agree**, and here every filter that would have",
            "separated them was inactive.",
        ]
    else:
        lines += [
            f"**The sets differ on {n - identical} of {n} calls.** A failed verdict does not",
            "merely cost the narrative — it changes which techniques reach the analyst, and",
            "neither the report nor the bundle records which construction path produced it.",
            "",
            "`_fallback_bundle_from_text` scrapes ATT&CK ids from **two** places: the ISR",
            "claims, and the model's own raw response. When the response is unparseable that",
            "second source is a degenerate decode, and every id in it enters the bundle",
            "without passing the cascade, the reconciliation step, the invalid-id filter or",
            "the integrity pass. Nothing downstream can tell those ids from corroborated",
            "ones.",
        ]

    only_fb = sum(len(c["only_in_fallback"]) for c in per_call)
    only_casc = sum(len(c["only_in_cascade"]) for c in per_call)
    lines += [
        "",
        f"Across all {n} calls: **{only_fb}** techniques appear only on the fallback path and",
        f"**{only_casc}** only on the reconciled one.",
    ]

    report = "\n".join(lines)
    print("\n" + report)
    out_md = OUT_MD.with_name(f"{OUT_MD.stem}{args.suffix}{OUT_MD.suffix}")
    out_json = OUT_JSON.with_name(f"{OUT_JSON.stem}{args.suffix}{OUT_JSON.suffix}")
    out_md.write_text(report + "\n")
    out_json.write_text(
        json.dumps(
            {
                "schema": "fallback-bundle-content/v1",
                "n_calls": n,
                "identical_sets": identical,
                "techniques_only_on_fallback_path": only_fb,
                "techniques_only_on_reconciled_path": only_casc,
                "per_call": per_call,
                "population": tally.as_dict(),
            },
            indent=1,
        )
        + "\n"
    )
    print(f"\nwrote {out_md.name} and {out_json.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

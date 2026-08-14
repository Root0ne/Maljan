"""C3 — does the weighted cascade beat simply unioning the Layer-0 claims?

The cascade is the system's evidence-quality apparatus: it takes each Layer-0
source's claims, weights them by a per-layer trust coefficient, marks a technique
corroborated when two distinct cascade domains carry it, and hands the judge a
ranked summary. The flat alternative is one line — union every claim, rank by
nothing, tell the judge nothing about agreement.

**This is the only architectural question the queue has left, and B3 makes a sharp
prediction about it.** §3.27 established that the judge reads the claim list and
nothing else: destroying corroboration while leaving the techniques standing
changed the verdict on 0 of 32 arms at Jaccard 1.000. If that is right, then a
flat union — which delivers the same claim list with no ranking and no
corroboration — must produce the same bundle. **Predicted: no difference.** A
difference would mean the judge is reading the cascade summary after all, and
§3.27's mechanism would need revisiting.

Design, deliberately mirroring B3 so the two are read together:

* Ground truth is distributed across the four Layer-0 sources that fire on this
  corpus (§3.23: `lolbin` and `network_dga` claim nothing on 0/97 archived
  reports, so an arm for either would measure a mechanism that never engages).
* ISRs are synthesised **deterministically** at a fixed confidence, so the arms
  differ in exactly one thing: whether the judge is given a cascade summary or a
  flat union.
* The **overlap** assignment is used, because a flat union and a cascade can only
  differ where corroboration exists to be lost — in the disjoint condition the
  two are identical by construction and the comparison would be vacuous.
* Fixtures carry ≥3 claims per source, from the same seeded selection B3 uses, so
  the two studies run on the same evidence.

Cost: 8 fixtures × 2 arms = 16 judge calls, and the model server is reloaded per
arm (§3.27's harness reached its whole 20 GB cap inside one fixture's five calls
once the fixtures grew).

Run:  .venv/bin/python tests/evaluation/eval_cascade_vs_union.py [--repeats K]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
for _p in (_REPO_ROOT, _REPO_ROOT / "src"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from maljan.core.config import get_settings  # noqa: E402
from maljan.core.container import ServiceContainer  # noqa: E402
from tests.evaluation.eval_consensus_ablation import bind_eval_llm  # noqa: E402
from tests.evaluation.eval_layer0_verdict import (  # noqa: E402
    assign_to_sources,
    build_isr_reports,
    bundle_technique_ids,
    jaccard,
    load_large_fixtures,
    restart_llama,
    verdict_changed,
)

OUT_JSON = _REPO_ROOT / "tests" / "evaluation" / "cascade_vs_union.json"
OUT_MD = _REPO_ROOT / "tests" / "evaluation" / "cascade_vs_union.md"
CHECKPOINT = Path("/tmp/cascade_vs_union_checkpoint.jsonl")

ARMS = ("cascade", "flat_union")


def flat_union_summary(isr_reports: dict[str, Any]) -> Any:
    """What the judge gets instead of a cascade: every claim, no ranking, no
    corroboration.

    Built as the *same object type* the cascade produces, with its ranking and
    agreement fields emptied, so the difference between arms is the content of
    the summary rather than the shape of it. Handing the judge a different schema
    would confound "the cascade's information" with "a prompt it has never seen".
    """
    from maljan.analysis.ttp_cascade import TTPCascadeEngine

    summary = TTPCascadeEngine().compute(isr_reports)
    tids: list[str] = []
    for isr in isr_reports.values():
        for claim in getattr(isr, "claims", []) or []:
            t = str(getattr(claim, "technique_id", "") or "").strip().upper()
            if t and t not in tids:
                tids.append(t)

    for field, value in (
        ("corroborated_techniques", []),
        ("corroborated_count", 0),
        ("ranked_techniques", tids),
        ("consensus_techniques", []),
        ("consensus_count", 0),
    ):
        if hasattr(summary, field):
            try:
                setattr(summary, field, value)
            except Exception:  # noqa: BLE001 — frozen field stays as it is, and we say so
                pass
    return summary


async def run_arm(judge: Any, isr_reports: dict[str, Any], arm: str) -> dict[str, Any]:
    from maljan.analysis.ttp_cascade import TTPCascadeEngine

    summary = (
        TTPCascadeEngine().compute(isr_reports)
        if arm == "cascade"
        else flat_union_summary(isr_reports)
    )
    reports = {
        name: "\n".join(f"- {c.claim}" for c in isr.claims) for name, isr in isr_reports.items()
    }
    bundle = await judge.give_verdict(
        reports=reports, history=[], isr_reports=isr_reports, cascade_summary=summary
    )
    tids = sorted(bundle_technique_ids(bundle))
    return {
        "arm": arm,
        "technique_ids": tids,
        "n_techniques": len(tids),
        "n_objects": len(getattr(bundle, "objects", []) or []),
        "corroborated_shown": int(getattr(summary, "corroborated_count", 0) or 0),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="C3 — weighted cascade vs flat union.")
    ap.add_argument("--repeats", type=int, default=1)
    ap.add_argument("--limit", type=int, default=0, help="Cap the fixture count (0 = all).")
    args = ap.parse_args()

    samples = load_large_fixtures()
    if args.limit:
        samples = samples[: args.limit]
    if not samples:
        print("no fixtures cleared the size floor — aborting", flush=True)
        return 1

    done: dict[str, dict[str, Any]] = {}
    if CHECKPOINT.exists():
        for line in CHECKPOINT.read_text().splitlines():
            try:
                row = json.loads(line)
            except Exception:  # noqa: BLE001
                continue
            if row.get("key"):
                done[row["key"]] = row
        print(f"resume: {len(done)} arms already recorded", flush=True)

    container = ServiceContainer(get_settings(), mock=False)
    judge = container.get_judge_agent()
    bind_eval_llm(judge, timeout_s=300)
    print(
        f"{len(samples)} fixtures x {len(ARMS)} arms x {args.repeats} repeats "
        f"= {len(samples) * len(ARMS) * args.repeats} judge calls, condition=overlap",
        flush=True,
    )

    for sid, truth in samples:
        assignment = assign_to_sources(truth, overlap=True)
        isr_reports = build_isr_reports(assignment, "all")
        for rep in range(args.repeats):
            for arm in ARMS:
                key = f"{arm}:{sid}:{rep}"
                if key in done:
                    continue
                if not restart_llama():
                    print("  model server did not come back healthy — stopping", flush=True)
                    return 1
                try:
                    row = asyncio.run(run_arm(judge, isr_reports, arm))
                except Exception as exc:  # noqa: BLE001 — a failed arm is data
                    row = {"arm": arm, "error": f"{type(exc).__name__}: {str(exc)[:160]}"}
                row |= {"key": key, "sample_id": sid, "repeat": rep}
                with CHECKPOINT.open("a") as fh:
                    fh.write(json.dumps(row) + "\n")
                done[key] = row
                print(
                    f"  {key}: {row.get('n_techniques', 'ERR')} techniques, "
                    f"{row.get('n_objects', '-')} objects",
                    flush=True,
                )

    return summarise(done, samples, args.repeats)


def summarise(
    done: dict[str, dict[str, Any]], samples: list[tuple[str, list[str]]], repeats: int
) -> int:
    pairs = []
    for sid, _ in samples:
        for rep in range(repeats):
            c = done.get(f"cascade:{sid}:{rep}")
            f = done.get(f"flat_union:{sid}:{rep}")
            if c and f and "error" not in c and "error" not in f:
                pairs.append((sid, rep, c, f))

    print(f"\npairs: {len(pairs)} scoreable")
    if not pairs:
        print("no scoreable pairs")
        return 1

    changed = sum(
        1
        for _, _, c, f in pairs
        if verdict_changed(set(c["technique_ids"]), set(f["technique_ids"]))
    )
    jac = [jaccard(set(c["technique_ids"]), set(f["technique_ids"])) for _, _, c, f in pairs]
    mean_j = sum(jac) / len(jac)

    lines = [
        "# C3 — weighted cascade vs flat union",
        "",
        "The judge receives either the cascade's ranked, corroboration-annotated summary or a flat",
        "union of the same claims with ranking and agreement stripped. The **claims themselves are",
        "identical between arms**; only what the judge is told about them differs.",
        "",
        "§3.27 predicted no difference: the judge was shown to read the claim list and",
        "nothing else.",
        "",
        f"| verdict changed | {changed}/{len(pairs)} |",
        "|---|---|",
        f"| mean Jaccard | {mean_j:.3f} |",
        "| corroborated techniques shown, cascade arm | "
        f"{sum(p[2].get('corroborated_shown', 0) for p in pairs)} |",
        "| corroborated techniques shown, flat arm | "
        f"{sum(p[3].get('corroborated_shown', 0) for p in pairs)} |",
        "",
    ]
    if changed == 0:
        lines += [
            "**The prediction holds.** Removing the cascade's entire contribution to what the",
            "judge is told — the ranking and the corroboration flags — leaves the bundle",
            "unchanged. Taken",
            "with §3.27, the apparatus computes a trust model that reaches the analyst's artefact",
            "through neither of its two channels.",
        ]
    else:
        lines += [
            f"**The prediction fails on {changed} of {len(pairs)} pairs.** The judge is using the",
            "cascade summary after all, and §3.27's account — that it reads only the claim list —",
            "is incomplete. The per-pair records below are the place to start.",
        ]
    report = "\n".join(lines)
    print("\n" + report, flush=True)
    OUT_MD.write_text(report + "\n")
    OUT_JSON.write_text(
        json.dumps(
            {
                "schema": "cascade-vs-union/v1",
                "condition": "overlap",
                "n_pairs": len(pairs),
                "verdict_changed": changed,
                "mean_jaccard": round(mean_j, 4),
                "per_pair": [
                    {"sample_id": s, "repeat": r, "cascade": c, "flat_union": f}
                    for s, r, c, f in pairs
                ],
            },
            indent=1,
        )
        + "\n"
    )
    print(f"\nwrote {OUT_JSON.name} and {OUT_MD.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

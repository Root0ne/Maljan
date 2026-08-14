"""C3 (redesigned) — what does the judge actually contribute to the bundle?

The original C3 compared a weighted cascade against a flat union of the same
claims. It was vacuous and was stopped four minutes into its first run: both arms
share one ``cascade_summary.results``, so ``valid_technique_ids`` is identical,
so ``_reconcile_with_cascade`` forces both bundles to contain the same techniques
whatever the judge produces. The comparison could only ever return "no
difference" (§3.27.1).

The question worth asking is the one that experiment could not reach. §3.27.1
established a **bound**: across 80 arms the bundle's technique set equals the
cascade's exactly, so the judge cannot subtract from it and added nothing to it.
That bound is consistent with two very different pipelines:

* the judge produced a usable verdict that **happened to match** the cascade, or
* the judge produced little or nothing usable and the bundle is the cascade's set
  **wearing the judge's name**.

Both leave an identical trace downstream. The paper currently states the bound
and names this measurement as outstanding; this is that measurement.

**Method.** Run the judge on the same fixtures B3 used, and intercept
``_reconcile_with_cascade`` to record its input and output. That is the exact
seam where the judge's own output ends and the deterministic set begins, so
nothing has to be inferred:

* how many ``attack-pattern`` objects the judge emitted;
* how many carried a **resolvable** ATT&CK ID — the rest are dropped, and a
  dropped pattern is a claim the model made and could not name;
* how many of the resolvable ones the cascade already held (agreement) versus
  how many were the judge's alone (contribution that survives);
* how many techniques were **injected** because the judge omitted them.

The headline number is the share of the final bundle that exists because the
judge put it there. If that is near zero, "the model has no influence over which
techniques reach the analyst" stops being a bound and becomes a description.

Cost: one judge call per fixture, model server reloaded per call (§3.22).

Run:  .venv/bin/python tests/evaluation/eval_judge_contribution.py [--limit N]
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
    load_large_fixtures,
    restart_llama,
)

OUT_JSON = _REPO_ROOT / "tests" / "evaluation" / "judge_contribution.json"
OUT_MD = _REPO_ROOT / "tests" / "evaluation" / "judge_contribution.md"
CHECKPOINT = Path("/tmp/judge_contribution_checkpoint.jsonl")


def _pattern_ids(objects: list[Any]) -> tuple[int, list[str]]:
    """(number of attack-patterns, the resolvable technique ids among them).

    Uses the production resolver rather than a local regex: the question is
    precisely which patterns *that code* considers nameable, and a second
    implementation here could disagree and silently change the answer.
    """
    from maljan.agents.judge_postprocess import _attack_pattern_technique_id

    total = 0
    ids: list[str] = []
    for obj in objects or []:
        if not isinstance(obj, dict) or obj.get("type") != "attack-pattern":
            continue
        total += 1
        tid = _attack_pattern_technique_id(obj)
        if tid:
            ids.append(str(tid).strip().upper())
    return total, ids


def install_spy(captured: list[dict[str, Any]]) -> Any:
    """Record what crosses the judge/cascade seam, then delegate untouched.

    Patching the module attribute works because ``postprocess_judge_bundle``
    resolves the name from module globals at call time. The real function still
    runs, so the pipeline behaves exactly as in production — this observes, it
    does not substitute.
    """
    import maljan.agents.judge_postprocess as jp

    original = jp._reconcile_with_cascade

    def spy(objects: list[Any], valid_technique_ids: frozenset[str]) -> list[Any]:
        emitted, resolvable = _pattern_ids(objects)
        out = original(objects, valid_technique_ids)
        _final_total, final_ids = _pattern_ids(out)
        cascade = {str(t).strip().upper() for t in valid_technique_ids}
        resolvable_set = set(resolvable)
        captured.append(
            {
                "judge_patterns_emitted": emitted,
                "judge_patterns_resolvable": len(resolvable_set),
                "judge_patterns_unresolvable_dropped": emitted - len(resolvable),
                "cascade_size": len(cascade),
                "judge_ids_agreeing_with_cascade": len(resolvable_set & cascade),
                "judge_ids_outside_cascade": sorted(resolvable_set - cascade),
                "injected_because_judge_omitted": len(cascade - resolvable_set),
                "final_bundle_size": len(set(final_ids)),
            }
        )
        return out

    jp._reconcile_with_cascade = spy
    return original


async def run_one(judge: Any, isr_reports: dict[str, Any]) -> dict[str, Any]:
    from maljan.analysis.ttp_cascade import TTPCascadeEngine

    summary = TTPCascadeEngine().compute(isr_reports)
    reports = {
        name: "\n".join(f"- {c.claim}" for c in isr.claims) for name, isr in isr_reports.items()
    }
    await judge.give_verdict(
        reports=reports, history=[], isr_reports=isr_reports, cascade_summary=summary
    )
    return {}


def summarise(rows: list[dict[str, Any]]) -> tuple[str, dict[str, Any]]:
    scored = [r for r in rows if "error" not in r and r.get("cascade_size") is not None]
    if not scored:
        return "no scoreable calls — nothing to report", {"status": "empty", "n": 0}

    n = len(scored)
    tot = {
        k: sum(int(r.get(k, 0) or 0) for r in scored)
        for k in (
            "judge_patterns_emitted",
            "judge_patterns_resolvable",
            "judge_patterns_unresolvable_dropped",
            "cascade_size",
            "judge_ids_agreeing_with_cascade",
            "injected_because_judge_omitted",
            "final_bundle_size",
        )
    }
    own = sum(len(r.get("judge_ids_outside_cascade") or []) for r in scored)
    calls_with_own = sum(1 for r in scored if r.get("judge_ids_outside_cascade"))
    calls_with_nothing_nameable = sum(1 for r in scored if not r.get("judge_patterns_resolvable"))

    # The headline: of every technique that reached a bundle, what share is there
    # because the judge named it and the cascade did not?
    own_share = own / tot["final_bundle_size"] if tot["final_bundle_size"] else 0.0
    unresolvable_share = (
        tot["judge_patterns_unresolvable_dropped"] / tot["judge_patterns_emitted"]
        if tot["judge_patterns_emitted"]
        else 0.0
    )

    lines = [
        "# C3 — what the judge contributes to the bundle",
        "",
        f"{n} judge calls, one per fixture, recorded at the seam where the judge's own output ends",
        "and the deterministic cascade set begins (`_reconcile_with_cascade`).",
        "",
        "| | total | per call |",
        "|---|---|---|",
        f"| attack-patterns the judge emitted | {tot['judge_patterns_emitted']} | "
        f"{tot['judge_patterns_emitted'] / n:.1f} |",
        f"| of those, carrying a resolvable ATT&CK id | {tot['judge_patterns_resolvable']} | "
        f"{tot['judge_patterns_resolvable'] / n:.1f} |",
        f"| **dropped — the model named no technique** | "
        f"**{tot['judge_patterns_unresolvable_dropped']}** ({unresolvable_share:.1%}) | "
        f"{tot['judge_patterns_unresolvable_dropped'] / n:.1f} |",
        f"| techniques the cascade held | {tot['cascade_size']} | {tot['cascade_size'] / n:.1f} |",
        f"| judge ids the cascade already held | {tot['judge_ids_agreeing_with_cascade']} | "
        f"{tot['judge_ids_agreeing_with_cascade'] / n:.1f} |",
        f"| **judge ids the cascade did not hold** | **{own}** | {own / n:.1f} |",
        f"| injected because the judge omitted them | {tot['injected_because_judge_omitted']} | "
        f"{tot['injected_because_judge_omitted'] / n:.1f} |",
        f"| final bundle | {tot['final_bundle_size']} | {tot['final_bundle_size'] / n:.1f} |",
        "",
        f"**Share of the final bundle the judge is responsible for: {own_share:.1%}** "
        f"({own} of {tot['final_bundle_size']} techniques), contributed on "
        f"{calls_with_own} of {n} calls.",
        "",
    ]

    if own == 0:
        lines += [
            "**The bound becomes a description.** Not one technique in any bundle is there because",
            "the judge named it. Every technique the analyst receives was already in the cascade's",
            f"set, and on {calls_with_nothing_nameable} of {n} calls the judge produced nothing",
            "nameable at all. The verdict model's influence over the ATT&CK content of its own",
            "verdict is zero — not small, not diluted: zero.",
        ]
    elif own_share < 0.05:
        lines += [
            f"**The judge contributes {own_share:.1%} of the bundle.** It is not nothing, and the",
            "paper should stop saying the model has no influence — but a component supplying one",
            "technique in twenty, downstream of a deterministic set that supplies the rest, is not",
            "the verdict-former the architecture describes.",
        ]
    else:
        lines += [
            f"**The judge contributes {own_share:.1%} of the bundle**, which is a real share and",
            "means §3.27.1's bound was hiding a working component. The reconciliation still",
            "guarantees the cascade's set reaches the analyst, but the model is adding to it.",
        ]

    if tot["judge_patterns_unresolvable_dropped"]:
        lines += [
            "",
            f"**{unresolvable_share:.1%} of the judge's own attack-patterns were discarded for",
            "naming no technique.** That is the model asserting a behaviour it cannot map — the",
            "failure the reconciliation step was written to paper over, measured here rather than",
            "inferred from its log line.",
        ]

    blob = {
        "schema": "judge-contribution/v1",
        "status": "complete",
        "n_calls": n,
        "failed_calls": len(rows) - n,
        "totals": tot,
        "judge_ids_outside_cascade_total": own,
        "calls_with_a_judge_contribution": calls_with_own,
        "calls_with_nothing_nameable": calls_with_nothing_nameable,
        "judge_share_of_final_bundle": round(own_share, 4),
        "unresolvable_share_of_judge_patterns": round(unresolvable_share, 4),
        "per_call": scored,
    }
    return "\n".join(lines), blob


def main() -> int:
    ap = argparse.ArgumentParser(description="C3 — the judge's contribution to the bundle.")
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
            # Only a scored row counts as done; an errored one is retried.
            if row.get("key") and "error" not in row:
                done[row["key"]] = row
        print(f"resume: {len(done)} scored calls on record", flush=True)

    captured: list[dict[str, Any]] = []
    install_spy(captured)

    container = ServiceContainer(get_settings(), mock=False)
    judge = container.get_judge_agent()
    bind_eval_llm(judge, timeout_s=300)
    print(f"{len(samples)} fixtures, one judge call each, condition=overlap", flush=True)

    rows: list[dict[str, Any]] = list(done.values())
    for sid, truth in samples:
        key = f"judge:{sid}"
        if key in done:
            continue
        assignment = assign_to_sources(truth, overlap=True)
        isr_reports = build_isr_reports(assignment, "all")
        if not restart_llama():
            print("  model server did not come back healthy — stopping", flush=True)
            break
        before = len(captured)
        try:
            asyncio.run(run_one(judge, isr_reports))
        except Exception as exc:  # noqa: BLE001 — a failed call is data
            row = {"key": key, "sample_id": sid, "error": f"{type(exc).__name__}: {str(exc)[:160]}"}
        else:
            new = captured[before:]
            if not new:
                row = {"key": key, "sample_id": sid, "error": "reconcile never ran"}
            else:
                row = {"key": key, "sample_id": sid, **new[-1]}
        with CHECKPOINT.open("a") as fh:
            fh.write(json.dumps(row) + "\n")
        rows.append(row)
        if "error" in row:
            print(f"  {sid}: {row['error']}", flush=True)
        else:
            print(
                f"  {sid}: judge emitted {row['judge_patterns_emitted']} pattern(s), "
                f"{row['judge_patterns_resolvable']} nameable, "
                f"{len(row['judge_ids_outside_cascade'])} of its own; "
                f"{row['injected_because_judge_omitted']} injected",
                flush=True,
            )

    report, blob = summarise(rows)
    print("\n" + report, flush=True)
    OUT_MD.write_text(report + "\n")
    OUT_JSON.write_text(json.dumps(blob, indent=1) + "\n")
    print(f"\nwrote {OUT_JSON.name} and {OUT_MD.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

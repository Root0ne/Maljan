"""Score the paired sink-hint ablation, with degenerate arms excluded by rule.

Two arms per sample, differing only in `use_sink_reachability`. The comparison
is paired and reported with a bootstrap interval, following §3.7.

**Why arms are screened before they are scored.** This model has a degenerate
repetition mode (§3.3). Four arms of the completed run produced 49 to 117 claims
carrying 2 to 14 distinct technique IDs — ratios of 8.4 to 34.3 — against a
healthy band that runs 1.1 to 2.5 on low-volume arms. Scored naively such an arm
looks like a large win for its side; it is a decode failure.

The rule is therefore **conjunctive**: an arm is degenerate when it is both
**voluminous** (>= 20 claims) and **repetitive** (>= 4 claims per distinct
technique). Both halves earn their place — one healthy arm sits at a ratio of
5.0 on 5 claims, and a ratio test alone would have discarded it. Any pair
containing a degenerate arm is reported separately rather than averaged in.

Note what these arms are *not*: their technique IDs are valid and plausible
(T1055, T1057, T1027, T1059), unlike §3.3's original loop, which repeated
*wrong* IDs the model could not recall. That fix — routing ID assignment through
a deterministic index — holds. What survives it is repetition at the claim level
rather than at the identifier level, which is a different mode wearing a similar
shape.

Symmetric failures — both arms hitting the wall-clock bound on the same sample —
are also excluded as pairs, and counted. They cost the pair but do not bias it,
which is worth stating rather than hiding in an n.

**A dead arm is screened against the host before it is called a failure.** On
2026-08-11 an arm exceeded its synthesis budget on a 16,000-character prompt
while the swap file was exhausted and the model server had 2.3 GB of itself
paged out; generating from disk is not the same instrument as generating from
RAM. Arms recorded with host state are excluded as `host_degraded` when free
swap fell below the floor. Arms from before that instrumentation existed are
excluded as `unattributable` — not as pipeline failures, because the data
cannot support that reading and the honest label is the one that says so.

Primary outcome is **distinct technique IDs**, because that is what the pipeline
emits downstream. Claim count is reported alongside it, since an early pair
showed the two moving in opposite directions and a single number would have
hidden that.
"""

from __future__ import annotations

import json
import random
import sys
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
IN = _HERE / "sink_hint_ablation.json"
OUT = _HERE / "sink_hint_ablation_scored.json"
SEED = 20260811

DEGENERATE_MIN_CLAIMS = 20
DEGENERATE_RATIO = 4.0
# Below this much free swap the model server generates from disk-backed pages,
# and a timeout stops being a statement about the pipeline. Arms are screened
# on it only when the host state was actually recorded; arms from before that
# instrumentation existed are reported as unknown rather than assumed healthy.
SWAP_FLOOR_MB = 1024


def is_degenerate(arm: dict[str, Any]) -> bool:
    n = arm.get("n_claims") or 0
    t = len(arm.get("technique_ids") or [])
    return n >= DEGENERATE_MIN_CLAIMS and n / max(1, t) >= DEGENERATE_RATIO


def is_dead(arm: dict[str, Any]) -> bool:
    return not arm.get("technique_ids") and (arm.get("n_claims") or 0) <= 1


def host_was_degraded(arm: dict[str, Any]) -> bool | None:
    """True/False if the host state was recorded, None if it was not."""
    swaps = [
        m.get("SwapFree")
        for m in (arm.get("host_mem_before"), arm.get("host_mem_after"))
        if isinstance(m, dict) and m.get("SwapFree") is not None
    ]
    if not swaps:
        return None
    return min(swaps) < SWAP_FLOOR_MB


def bootstrap_ci(values: list[float], iters: int = 2000) -> tuple[float, float]:
    if not values:
        return (0.0, 0.0)
    if len(values) == 1:
        return (values[0], values[0])
    rng = random.Random(SEED)
    means = sorted(
        sum(rng.choice(values) for _ in range(len(values))) / len(values) for _ in range(iters)
    )
    return (means[int(0.025 * iters)], means[int(0.975 * iters)])


def main() -> int:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else IN
    raw = json.loads(path.read_text())

    by_sample: dict[str, dict[str, Any]] = {}
    for key, arm in raw.items():
        sha, _, side = key.rpartition(":")
        by_sample.setdefault(sha, {})[side] = arm

    usable, excluded = (
        [],
        {
            "incomplete": [],
            "host_degraded": [],
            "failed_both": [],
            "unattributable": [],
            "degenerate": [],
        },
    )
    for sha, arms in by_sample.items():
        on, off = arms.get("on"), arms.get("off")
        if not on or not off:
            excluded["incomplete"].append(sha)
            continue
        if "error" in on or "error" in off:
            excluded["incomplete"].append(sha)
            continue
        on_dead, off_dead = is_dead(on), is_dead(off)
        # A dead arm on a swapping host says nothing about the hint. Screen it
        # out *before* the failed-both rule, so the two are never conflated:
        # one is a pipeline failure, the other is a failure of the machine the
        # pipeline was measured on, and only the first is a finding.
        if on_dead or off_dead:
            degraded = [host_was_degraded(a) for a in (on, off)]
            if True in degraded:
                excluded["host_degraded"].append(sha)
                continue
            if None in degraded:
                excluded["unattributable"].append(sha)
                continue
        if on_dead and off_dead:
            excluded["failed_both"].append(sha)
            continue
        if is_degenerate(on) or is_degenerate(off):
            excluded["degenerate"].append(sha)
            continue
        usable.append((sha, on, off))

    print(f"pairs: {len(by_sample)} seen, {len(usable)} usable")
    for reason, shas in excluded.items():
        if shas:
            print(f"  excluded ({reason}): {len(shas)} — {', '.join(s[:12] for s in shas)}")

    if not usable:
        print("\nno usable pairs — nothing to score")
        return 1

    d_tid = [len(on["technique_ids"]) - len(off["technique_ids"]) for _, on, off in usable]
    d_claims = [on["n_claims"] - off["n_claims"] for _, on, off in usable]
    d_secs = [on["seconds"] - off["seconds"] for _, on, off in usable]

    print(f"\npaired deltas (hint on − hint off), n={len(usable)}")
    summary: dict[str, Any] = {"n_pairs": len(usable)}
    for label, vals in (("technique IDs", d_tid), ("claims", d_claims), ("seconds", d_secs)):
        mean = sum(vals) / len(vals)
        lo, hi = bootstrap_ci([float(v) for v in vals])
        crosses = lo <= 0 <= hi
        print(
            f"  {label:14s} mean {mean:+7.2f}   95% CI [{lo:+.2f}, {hi:+.2f}]"
            f"   {'includes 0' if crosses else 'excludes 0'}"
        )
        summary[label] = {
            "mean": round(mean, 3),
            "ci95": [round(lo, 3), round(hi, 3)],
            "includes_zero": crosses,
        }

    wins = sum(1 for v in d_tid if v > 0)
    losses = sum(1 for v in d_tid if v < 0)
    print(
        f"  direction: hint better on {wins}, worse on {losses}, tied on "
        f"{len(d_tid) - wins - losses}"
    )
    summary["direction"] = {
        "hint_better": wins,
        "hint_worse": losses,
        "tied": len(d_tid) - wins - losses,
    }

    OUT.write_text(
        json.dumps(
            {
                "schema": "maljan-sink-hint-ablation/v1",
                "seed": SEED,
                "degenerate_rule": {
                    "min_claims": DEGENERATE_MIN_CLAIMS,
                    "claims_per_tid": DEGENERATE_RATIO,
                },
                "excluded": {k: v for k, v in excluded.items()},
                "summary": summary,
                "per_pair": [
                    {
                        "sha256": sha,
                        "on": {
                            "tids": len(on["technique_ids"]),
                            "claims": on["n_claims"],
                            "seconds": on["seconds"],
                        },
                        "off": {
                            "tids": len(off["technique_ids"]),
                            "claims": off["n_claims"],
                            "seconds": off["seconds"],
                        },
                    }
                    for sha, on, off in usable
                ],
            },
            indent=1,
        )
    )
    print(f"\nwrote {OUT.relative_to(_HERE.parent.parent)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

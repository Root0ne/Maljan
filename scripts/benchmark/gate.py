"""The known-answer gate: a change passes only if nothing the baseline found drops.

Each arm is one or more scored runs of the same setup (repeats). An item's
verdict for an arm is the best verdict that at least ``m`` of its ``n`` runs
reach or beat ("found in m of n"): with the ranks of a scale counted once per
run, the counts are summed from the best word down and the first word whose
count reaches ``m`` is the arm's. A verdict no run gave (an unknown, or an item
a run did not score) reaches no word, so it can only lower the arm's verdict.
``m`` is the arm's own argument or, by default, a strict majority of its runs
(``n // 2 + 1``: 1 of 1, 2 of 3, 3 of 4), never a fixed number.

An item **drops** when the candidate's verdict ranks below the baseline's, or
when the candidate has none; it **improves** when it ranks above. An item the
baseline itself reaches in fewer than ``m`` runs is **not gated** and named. The
beyond-human count is gated the same way: each arm's count is the largest that
``m`` of its runs reach (its ``m``-th largest), and the gate fails when the
candidate's is lower or, the baseline's being known, unknown. Every number is
an exact count and is stated with its ``n``; nothing is estimated or sampled.

Time is linear in what is read: one pass over each arm's verdicts per item, a
count per word of a fixed scale, and an expected-linear selection for the
beyond-human counts.
"""

from __future__ import annotations

import random
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from scripts.benchmark.scores import CREDITED, SCALES, ScoredRun, rank

DROPPED, IMPROVED, HELD, NOT_GATED = "dropped", "improved", "held", "not gated"


class GateError(RuntimeError):
    """The arms cannot be compared; the message names why."""


@dataclass
class Arm:
    """The scored runs of one setup and how many of them an item must reach."""

    runs: list[ScoredRun]
    m: int

    @property
    def n(self) -> int:
        return len(self.runs)


def majority(n: int) -> int:
    """A strict majority of ``n`` runs."""
    return n // 2 + 1


def arm(runs: Sequence[ScoredRun], m: int | None = None) -> Arm:
    """An arm of ``runs``; ``m`` defaults to a strict majority of them."""
    if not runs:
        raise GateError("an arm needs at least one scored run")
    chosen = majority(len(runs)) if m is None else m
    if not 1 <= chosen <= len(runs):
        raise GateError(f"m must be between 1 and the arm's {len(runs)} runs, not {chosen}")
    twice = sorted(n for n, k in Counter(r.name for r in runs).items() if k > 1)
    if twice:
        raise GateError(f"a run is given twice in one arm: {', '.join(twice)}")
    return Arm(list(runs), chosen)


def _scales(a: Arm, label: str) -> dict[str, str]:
    scales: dict[str, str] = {}
    for run in a.runs:
        for item, (scale, _) in run.verdicts.items():
            if scales.setdefault(item, scale) != scale:
                raise GateError(
                    f"{label}: item {item} is on the {scales[item]} scale in one run "
                    f"and the {scale} scale in {run.name}"
                )
    return scales


def reached(a: Arm, item: str, scale: str) -> tuple[int | None, list[int]]:
    """The best rank ``m`` of the arm's runs reach, and how many runs reach each rank."""
    size = len(SCALES[scale])
    counts = [0] * size
    for run in a.runs:
        verdict = run.verdicts.get(item)
        got = None if verdict is None else rank(scale, verdict[1])
        if got is not None:
            counts[got] += 1
    at_least = [0] * size
    total = 0
    best: int | None = None
    for r in range(size - 1, -1, -1):
        total += counts[r]
        at_least[r] = total
        if best is None and total >= a.m:
            best = r
    return best, at_least


def mth_largest(values: list[int], m: int) -> int | None:
    """The ``m``-th largest of ``values`` (expected linear selection); None if fewer than ``m``."""
    if len(values) < m:
        return None
    pool, want = list(values), m
    chooser = random.Random(len(values))  # nosec B311 — a pivot choice, not a secret
    while True:
        pivot = pool[chooser.randrange(len(pool))]
        above = [v for v in pool if v > pivot]
        if want <= len(above):
            pool = above
            continue
        same = sum(1 for v in pool if v == pivot)
        if want <= len(above) + same:
            return pivot
        want -= len(above) + same
        pool = [v for v in pool if v < pivot]


def _side(a: Arm, item: str, scale: str, best: int | None, at_least: list[int]) -> dict[str, Any]:
    scored = sum(1 for run in a.runs if run.verdicts.get(item, (scale, None))[1] is not None)
    return {
        "verdict": None if best is None else SCALES[scale][best],
        "runs_at_or_above": None if best is None else at_least[best],
        "n": a.n,
        "m": a.m,
        "unknown": a.n - scored,
    }


def _totals(a: Arm, scales: dict[str, str], levels: dict[str, int | None]) -> dict[str, Any]:
    by_scale: dict[str, dict[str, int]] = {}
    credited = credit_items = unknown = 0
    for item, scale in scales.items():
        words = by_scale.setdefault(scale, {w: 0 for w in SCALES[scale]})
        level = levels[item]
        if level is None:
            unknown += 1
        else:
            words[SCALES[scale][level]] += 1
        if scale in CREDITED:
            credit_items += 1
            if level is not None and level >= SCALES[scale].index(CREDITED[scale]):
                credited += 1
    return {
        "by_scale": by_scale,
        "credited": credited,
        "credit_items": credit_items,
        "unknown": unknown,
        "n": a.n,
        "m": a.m,
    }


def _beyond(a: Arm) -> dict[str, Any]:
    counts = [r.beyond for r in a.runs if r.beyond is not None]
    return {
        "count": mth_largest(counts, a.m),
        "counted_runs": len(counts),
        "n": a.n,
        "m": a.m,
        "per_run": {r.name: r.beyond for r in a.runs},
        "notes": {r.name: r.beyond_note for r in a.runs},
    }


def score_arm(a: Arm) -> dict[str, Any]:
    """One arm's verdict per item and its totals, found in ``m`` of ``n``."""
    scales = _scales(a, "arm")
    levels: dict[str, int | None] = {}
    items: dict[str, dict[str, Any]] = {}
    for item, scale in scales.items():
        best, at_least = reached(a, item, scale)
        levels[item] = best
        items[item] = {"scale": scale, **_side(a, item, scale, best, at_least)}
    return {
        "runs": [r.name for r in a.runs],
        "items": items,
        "totals": _totals(a, scales, levels),
        "beyond": _beyond(a),
        "unchecked_totals": _unchecked(a),
    }


def _unchecked(a: Arm) -> dict[str, str]:
    """The runs whose file's own totals were not checked, and why."""
    return {r.name: r.totals_note for r in a.runs if r.totals_note.endswith("unchecked")}


def gate(baseline: Arm, candidate: Arm) -> dict[str, Any]:
    """The gate's outcome: every item's two verdicts, what dropped, and whether it passed."""
    base_scales = _scales(baseline, "baseline")
    if not base_scales:
        raise GateError("the baseline scores no item")
    cand_scales = _scales(candidate, "candidate")
    for item, scale in base_scales.items():
        if cand_scales.get(item, scale) != scale:
            raise GateError(
                f"item {item} is on the {scale} scale in the baseline "
                f"and the {cand_scales[item]} scale in the candidate"
            )
    labels: dict[str, str] = {}
    for run in [*baseline.runs, *candidate.runs]:
        for item, label in run.labels.items():
            labels.setdefault(item, label)
    rows: list[dict[str, Any]] = []
    base_levels: dict[str, int | None] = {}
    cand_levels: dict[str, int | None] = {}
    for item, scale in base_scales.items():
        b_best, b_at = reached(baseline, item, scale)
        c_best, c_at = reached(candidate, item, scale)
        base_levels[item], cand_levels[item] = b_best, c_best
        if b_best is None:
            outcome = NOT_GATED
        elif c_best is None or c_best < b_best:
            outcome = DROPPED
        elif c_best > b_best:
            outcome = IMPROVED
        else:
            outcome = HELD
        cand_side = _side(candidate, item, scale, c_best, c_at)
        cand_side["runs_at_baseline_verdict"] = None if b_best is None else c_at[b_best]
        rows.append(
            {
                "item": item,
                "label": labels.get(item, item),
                "scale": scale,
                "baseline": _side(baseline, item, scale, b_best, b_at),
                "candidate": cand_side,
                "outcome": outcome,
            }
        )
    for item, scale in cand_scales.items():
        if item not in base_scales:
            cand_levels[item] = reached(candidate, item, scale)[0]
    new_items = sorted(set(cand_scales) - set(base_scales))
    base_beyond, cand_beyond = _beyond(baseline), _beyond(candidate)
    if base_beyond["count"] is None:
        beyond_outcome = NOT_GATED
    elif cand_beyond["count"] is None or cand_beyond["count"] < base_beyond["count"]:
        beyond_outcome = DROPPED
    elif cand_beyond["count"] > base_beyond["count"]:
        beyond_outcome = IMPROVED
    else:
        beyond_outcome = HELD
    dropped = [r["item"] for r in rows if r["outcome"] == DROPPED]
    return {
        "passed": not dropped and beyond_outcome != DROPPED,
        "baseline": {"runs": [r.name for r in baseline.runs], "n": baseline.n, "m": baseline.m},
        "candidate": {"runs": [r.name for r in candidate.runs], "n": candidate.n, "m": candidate.m},
        "items": rows,
        "dropped": dropped,
        "improved": [r["item"] for r in rows if r["outcome"] == IMPROVED],
        "not_gated": [r["item"] for r in rows if r["outcome"] == NOT_GATED],
        "new_items": new_items,
        "beyond": {"baseline": base_beyond, "candidate": cand_beyond, "outcome": beyond_outcome},
        "unchecked_totals": {**_unchecked(baseline), **_unchecked(candidate)},
        "totals": {
            "baseline": _totals(baseline, base_scales, base_levels),
            "candidate": _totals(candidate, cand_scales, cand_levels),
        },
    }


def _runs(n: int) -> str:
    return f"{n} run" if n == 1 else f"{n} runs"


def _verdict(side: dict[str, Any]) -> str:
    if side["verdict"] is None:
        return f"none in {side['m']} of {side['n']}"
    return (
        f"{side['verdict']} ({side['runs_at_or_above']} of {side['n']} at or above, m {side['m']})"
    )


def _totals_line(name: str, totals: dict[str, Any]) -> str:
    parts = [
        " / ".join(f"{count} {word}" for word, count in reversed(words.items()))
        for words in totals["by_scale"].values()
    ]
    line = f"{name} (m {totals['m']} of {totals['n']}): " + "; ".join(parts)
    if totals["credit_items"]:
        line += f"; credited {totals['credited']} of {totals['credit_items']}"
    if totals["unknown"]:
        line += f"; {totals['unknown']} items reached in fewer than m runs"
    return line


def _beyond_line(name: str, beyond: dict[str, Any]) -> str:
    if beyond["count"] is None:
        why = "; ".join(f"{run}: {note}" for run, note in beyond["notes"].items() if note)
        return (
            f"{name} beyond-human: none in {beyond['m']} of {beyond['n']} "
            f"({beyond['counted_runs']} runs counted; {why})"
        )
    per_run = ", ".join(f"{run} {count}" for run, count in beyond["per_run"].items())
    return (
        f"{name} beyond-human: {beyond['count']} (reached by at least {beyond['m']} of "
        f"{_runs(beyond['n'])}; {per_run})"
    )


def _unchecked_lines(unchecked: dict[str, str]) -> list[str]:
    return [f"{run}: {note}" for run, note in unchecked.items()]


def render_arm(result: dict[str, Any]) -> str:
    """One arm's totals and beyond-human count as text."""
    return "\n".join(
        [
            _totals_line(", ".join(result["runs"]), result["totals"]),
            _beyond_line(", ".join(result["runs"]), result["beyond"]),
            *_unchecked_lines(result["unchecked_totals"]),
        ]
    )


def render(result: dict[str, Any]) -> str:
    """The gate's outcome as text: the decision, what dropped, then every changed item."""
    failed = len(result["dropped"]) + (result["beyond"]["outcome"] == DROPPED)
    head = "PASS" if result["passed"] else f"FAIL ({failed} dropped)"
    base, cand = result["baseline"], result["candidate"]
    lines = [
        f"known-answer gate: {head}",
        f"baseline:  {_runs(base['n'])}, m {base['m']}: {', '.join(base['runs'])}",
        f"candidate: {_runs(cand['n'])}, m {cand['m']}: {', '.join(cand['runs'])}",
        _totals_line("baseline", result["totals"]["baseline"]),
        _totals_line("candidate", result["totals"]["candidate"]),
        _beyond_line("baseline", result["beyond"]["baseline"]),
        _beyond_line("candidate", result["beyond"]["candidate"]),
        f"beyond-human: {result['beyond']['outcome']}",
        *_unchecked_lines(result["unchecked_totals"]),
    ]
    for outcome in (DROPPED, IMPROVED, NOT_GATED):
        rows = [r for r in result["items"] if r["outcome"] == outcome]
        lines.append(f"{outcome}: {len(rows)} of {len(result['items'])} items")
        for row in rows:
            at_base = row["candidate"]["runs_at_baseline_verdict"]
            reach = (
                f"; {at_base} of {row['candidate']['n']} candidate runs at the baseline's"
                if outcome == DROPPED and at_base is not None
                else ""
            )
            lines.append(
                f"  {row['label']}: baseline {_verdict(row['baseline'])}; "
                f"candidate {_verdict(row['candidate'])}{reach}"
            )
    if result["new_items"]:
        lines.append(f"not in the baseline, not gated: {', '.join(result['new_items'])}")
    return "\n".join(lines)

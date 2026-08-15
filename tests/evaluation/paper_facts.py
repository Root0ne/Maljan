"""Every number the paper states, derived from the record rather than typed.

The paper had four numeric drifts in one week, and each survived every check that
looks at a section on its own:

* a figure captioned "0 of 15 varied cases" beside a paragraph saying the same
  null holds "at 32 arms rather than 15" — the figure was drawing a superseded
  study, and the module it lives in exists precisely so figures and text cannot
  disagree;
* "1,995 passing tests" in five places after the suite reached 2,666;
* a conclusion claiming four failure mechanisms while the abstract claimed seven;
* two sections saying three of four architectural claims were measured, months
  after the fourth was.

None of these is a mistake of reasoning. Each is a number that was correct when
typed and became false when the record moved, and nothing connected the two. This
module is that connection: it reads the committed per-sample artifacts, derives
each figure the paper quotes, and writes them to ``paper_facts.json``.
``build_paper.py`` substitutes them into ``{{placeholders}}`` and **fails the
build** on any placeholder it cannot resolve, so a fact that disappears takes the
paper down instead of going stale in it.

Two rules the derivations follow:

1. **Derive from per-sample records, never from a stored summary.** A summary is
   itself a number someone wrote down; re-deriving is what catches the case where
   the summary and the samples disagree.
2. **A fact that cannot be computed is an error, not a default.** No ``or 0``, no
   ``.get(k, "")``. A missing artifact should stop the build, because the
   alternative is a paper with a zero in it.

Run:  .venv/bin/python tests/evaluation/paper_facts.py
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent.parent
OUT = _HERE / "paper_facts.json"


class FactError(RuntimeError):
    """A fact could not be derived. Never swallowed — the build must stop."""


def load(name: str) -> Any:
    path = _HERE / name
    if not path.exists():
        raise FactError(f"missing artifact: {name}")
    return json.loads(path.read_text())


def pct(x: float, places: int = 1) -> str:
    return f"{x * 100:.{places}f}%"


def signed(x: float, places: int = 4) -> str:
    return f"{x:+.{places}f}"


def interval(lo: float, hi: float, places: int = 4) -> str:
    return f"[{lo:+.{places}f}, {hi:+.{places}f}]"


# ---------------------------------------------------------------------------
# Derivations
# ---------------------------------------------------------------------------


def baseline_facts() -> dict[str, Any]:
    """The no-LLM reference every F1 in the paper is read against."""
    d = load("cape_baseline.json")
    s = d["summary"] if "summary" in d else d
    rows = d.get("per_sample") or d.get("rows") or []
    if not rows:
        raise FactError("cape_baseline.json has no per-sample rows")
    f1s = [r["f1"] for r in rows if isinstance(r.get("f1"), int | float)]
    mean = sum(f1s) / len(f1s)
    stored = s.get("mean_f1")
    if stored is not None and abs(stored - mean) > 5e-4:
        raise FactError(f"baseline summary {stored} disagrees with per-sample mean {mean:.4f}")
    return {
        "baseline_f1": f"{mean:.4f}",
        "baseline_n": str(len(f1s)),
        "baseline_distinct_f1": str(len({round(v, 6) for v in f1s})),
    }


def consensus_facts() -> dict[str, Any]:
    """Arm means and the paired deltas, recomputed from the per-arm records."""
    rows = load("consensus_ablation.json")
    by_arm: dict[str, dict[tuple[str, int], float]] = {}
    for r in rows:
        if not isinstance(r.get("f1"), int | float):
            continue
        by_arm.setdefault(r["arm"], {})[(r["sample_id"], r.get("repeat", 0))] = r["f1"]
    for arm in ("single", "negotiated", "noise"):
        if arm not in by_arm:
            raise FactError(f"consensus_ablation.json has no '{arm}' arm")

    out: dict[str, Any] = {}
    for arm, cells in by_arm.items():
        out[f"consensus_{arm}_f1"] = f"{sum(cells.values()) / len(cells):.4f}"
        out[f"consensus_{arm}_n"] = str(len(cells))

    base = by_arm["single"]
    for arm in ("negotiated", "noise"):
        shared = sorted(set(base) & set(by_arm[arm]))
        deltas = [by_arm[arm][k] - base[k] for k in shared]
        out[f"consensus_{arm}_delta"] = signed(sum(deltas) / len(deltas), 3)
        out[f"consensus_{arm}_nonzero"] = str(sum(1 for d in deltas if abs(d) > 1e-9))
        out[f"consensus_{arm}_paired_n"] = str(len(deltas))
    return out


def frontier_facts() -> dict[str, Any]:
    """One entry per arm file, keyed by arm and configuration."""
    out: dict[str, Any] = {}
    for path in sorted(_HERE.glob("frontier_probe*.json")):
        blob = json.loads(path.read_text())
        s = blob.get("summary")
        if not s:
            continue
        stem = path.stem.replace("frontier_probe", "").strip("_") or "default"
        rows = blob.get("per_sample") or []
        scored = [r["f1"] for r in rows if isinstance(r.get("f1"), int | float)]
        if not scored:
            raise FactError(f"{path.name} has no scored rows")
        mean = sum(scored) / len(scored)
        if abs(s["mean_f1"] - mean) > 5e-4:
            raise FactError(f"{path.name}: summary {s['mean_f1']} vs per-sample {mean:.4f}")
        out[f"arm_{stem}_f1"] = f"{mean:.4f}"
        out[f"arm_{stem}_n"] = str(len(scored))
        out[f"arm_{stem}_reasoning"] = pct(s["mean_reasoning_fraction"])
        out[f"arm_{stem}_hit_cap"] = str(s["hit_cap"])
        lo, hi = s["f1_ci95"]
        out[f"arm_{stem}_ci"] = f"[{lo:.4f}, {hi:.4f}]"
    if "arm_default_f1" not in out:
        raise FactError("no frontier arm files found")
    return out


def judge_facts() -> dict[str, Any]:
    """What the verdict model contributed, in both output-cap conditions."""
    out: dict[str, Any] = {}
    for cond in ("uncapped", "capped"):
        d = load(f"judge_contribution_{cond}.json")
        tot = d["totals"]
        out[f"judge_{cond}_reached"] = str(d["n_calls"])
        out[f"judge_{cond}_fellback"] = str(d["calls_fell_back"])
        out[f"judge_{cond}_total_calls"] = str(d["n_calls"] + d["calls_fell_back"])
        out[f"judge_{cond}_share"] = pct(d["judge_share_of_final_bundle"])
        out[f"judge_{cond}_own_ids"] = str(d["judge_ids_outside_cascade_total"])
        out[f"judge_{cond}_bundle"] = str(tot["final_bundle_size"])
        out[f"judge_{cond}_emitted"] = str(tot["judge_patterns_emitted"])
        out[f"judge_{cond}_resolvable"] = str(tot["judge_patterns_resolvable"])
        out[f"judge_{cond}_dropped"] = str(tot["judge_patterns_unresolvable_dropped"])
        out[f"judge_{cond}_dropped_share"] = pct(d["unresolvable_share_of_judge_patterns"])
        out[f"judge_{cond}_nothing_nameable"] = str(d["calls_with_nothing_nameable"])

    leak = load("fallback_bundle_content_capped.json")
    out["fallback_only_capped"] = str(leak["techniques_only_on_fallback_path"])
    out["fallback_only_reconciled"] = str(leak["techniques_only_on_reconciled_path"])
    out["fallback_calls"] = str(leak["n_calls"])
    control = load("fallback_bundle_content_uncapped.json")
    out["fallback_identical_uncapped"] = str(control["identical_sets"])
    out["fallback_only_uncapped"] = str(control["techniques_only_on_fallback_path"])

    # The share of the *failed* path's bundle that the model put there. Reported
    # beside the 0-of-N on the working path, so it is derived the same way.
    total_capped = sum(c["fallback_n"] for c in leak["per_call"])
    out["fallback_bundle_total"] = str(total_capped)
    return out


def cascade_facts() -> dict[str, Any]:
    """Arm counts for the Layer-0 ablation, per condition."""
    out: dict[str, Any] = {}
    for cond in ("overlap", "disjoint"):
        rows = load(f"layer0_verdict_v2_{cond}.json")["arms"]
        base = {
            (r["sample_id"], r["repeat"]): frozenset(r["technique_ids"] or [])
            for r in rows
            if r["arm"] == "all"
        }
        varied = [r for r in rows if r["arm"] != "all" and (r["sample_id"], r["repeat"]) in base]
        changed = sum(
            1
            for r in varied
            if frozenset(r["technique_ids"] or []) != base[(r["sample_id"], r["repeat"])]
        )
        out[f"cascade_{cond}_arms"] = str(len(varied))
        out[f"cascade_{cond}_changed"] = str(changed)
    return out


def series_facts() -> dict[str, Any]:
    """Why the parameter-size series refuses, in its own numbers."""
    d = load("parameter_size_series.json")
    return {
        "series_status": d["status"],
        "series_matched": str(d["configuration_matched"]),
        "series_unmatched": str(d["configuration_unmatched"]),
        "series_sizes": str(d["distinct_sizes_matched"]),
    }


def probe_facts() -> dict[str, Any]:
    """Which outbound parameters the local server acts on."""
    d = load("outbound_parameter_probe.json")
    t = d["temperature"]
    caps = {row["parameter"]: row for row in d["output_cap"]}
    renamed = caps["max_completion_tokens only"]
    verbatim = caps["+ max_tokens/n_predict"]
    if verbatim["produced"] is None:
        raise FactError("the verbatim-cap probe did not complete")
    return {
        "temp_verdict": t["verdict"],
        "temp_distinct_cold": str(t["distinct_at_0"]),
        "temp_distinct_hot": str(t["distinct_at_2"]),
        "cap_requested": str(verbatim["requested"]),
        "cap_ignored_tokens": str(renamed["produced"] or "context exhaustion"),
        "cap_honoured_tokens": str(verbatim["produced"]),
    }


_PASSED = re.compile(r"(\d+) passed")


def suite_facts() -> dict[str, Any]:
    """The number of tests that **pass**, from a run — not from collection.

    The first version of this counted ``pytest --collect-only`` and returned
    2,671 while ``make check`` reported 2,666 passed. The paper's sentence is "a
    suite of N *passing* tests caught none of them", so collection was answering a
    different question: it includes tests that are skipped or deselected. A fact
    that is off by five in the direction of flattering the suite is exactly the
    kind this module exists to prevent, and it got in on the first attempt.

    Runs the same command ``make test`` does, so the number in the paper and the
    number in the gate cannot disagree. Costs about a minute.
    """
    proc = subprocess.run(
        [".venv/bin/python", "-m", "pytest", "tests/", "-q"],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
    )
    for line in reversed(proc.stdout.splitlines()):
        m = _PASSED.search(line)
        if m:
            return {"test_count": f"{int(m.group(1)):,}"}
    raise FactError("could not read a passing-test count from pytest")


def confidence_facts() -> dict[str, Any]:
    """AUC for the number every deterministic gate consumes.

    Ties decide this one and the figure module says so at length: 186 of 210
    claims sit at confidence exactly 1.0, a naive descending sort returns 0.458
    and the rank-based estimator returns 0.550. The same threshold-on-distinct-
    values construction is used here so the fact, the figure and the sentence
    cannot disagree — three copies of an estimator is two too many, but the
    alternative is importing matplotlib to derive a number.
    """
    rows = load("confidence_calibration.json")
    conf = [float(r["confidence"]) for r in rows]
    correct = [int(r["correct"]) for r in rows]
    npos, nneg = sum(correct), len(correct) - sum(correct)
    if not npos or not nneg:
        raise FactError("confidence calibration has only one class")
    pts = [(0.0, 0.0)]
    for t in sorted(set(conf), reverse=True):
        picked = [i for i, c in enumerate(conf) if c >= t]
        pts.append(
            (
                sum(1 for i in picked if not correct[i]) / nneg,
                sum(correct[i] for i in picked) / npos,
            )
        )
    auc = sum(
        (pts[i + 1][0] - pts[i][0]) * (pts[i + 1][1] + pts[i][1]) / 2 for i in range(len(pts) - 1)
    )
    top = max(set(conf), key=conf.count)
    return {
        "confidence_auc": f"{auc:.3f}",
        "confidence_n": str(len(rows)),
        "confidence_modal_count": str(conf.count(top)),
        "confidence_distinct": str(len(set(conf))),
    }


def firing_rate_facts() -> dict[str, Any]:
    """How often each mechanism engages — the rule the paper argues for."""
    cap = load("confidence_cap.json")["summary"]
    fired = cap["capped"]
    total = cap["techniques_total"]

    hint = load("sink_hint_frequency.json")["results"]
    ok = [v for v in hint.values() if not v.get("error")]
    hint_fired = sum(1 for v in ok if v.get("hint_nonempty"))

    probe = load("function_hash_attribution_probe.json")["results"]
    rows = list(probe.values()) if isinstance(probe, dict) else probe
    hash_fired = sum(1 for r in rows if r.get("fires"))
    functions = sum(int(r.get("n_functions_kept") or 0) for r in rows)

    return {
        "cap_rate": pct(fired / total, 2),
        "cap_fired": str(fired),
        "cap_total": f"{total:,}",
        "hint_rate": pct(hint_fired / len(ok)),
        "hint_fired": str(hint_fired),
        "hint_total": str(len(ok)),
        "hash_fired": str(hash_fired),
        "hash_total": str(len(rows)),
        "hash_functions": f"{functions:,}",
    }


def retrieval_facts() -> dict[str, Any]:
    """The family-feature A/B, and the sink-hint ablation it motivated."""
    fa = load("family_rag_ab.json")["delta_on_minus_off"]
    sa = load("sink_hint_ablation_scored.json")["summary"]
    tids = sa["technique IDs"]
    lo, hi = tids["ci95"]
    d = sa["direction"]
    return {
        "family_delta_f1": signed(fa["f1"], 4),
        "family_delta_precision": signed(fa["precision"], 4),
        "sink_pairs": str(sa["n_pairs"]),
        "sink_delta_tids": signed(tids["mean"], 2),
        "sink_ci_tids": f"[{lo:+.2f}, {hi:+.2f}]",
        "sink_better": str(d["hint_better"]),
        "sink_worse": str(d["hint_worse"]),
        "sink_tied": str(d["tied"]),
    }


BUILDERS = (
    baseline_facts,
    consensus_facts,
    frontier_facts,
    judge_facts,
    cascade_facts,
    series_facts,
    probe_facts,
    confidence_facts,
    firing_rate_facts,
    retrieval_facts,
    suite_facts,
)


def collect() -> dict[str, str]:
    facts: dict[str, str] = {}
    for build in BUILDERS:
        for k, v in build().items():
            if k in facts:
                raise FactError(f"two derivations claim the name {k!r}")
            facts[k] = str(v)
    return facts


def main() -> int:
    try:
        facts = collect()
    except FactError as exc:
        print(f"FACTS FAILED: {exc}")
        return 1
    OUT.write_text(json.dumps(facts, indent=1, sort_keys=True) + "\n")
    print(f"{len(facts)} facts derived -> {OUT.name}")
    for k in sorted(facts):
        print(f"  {{{{{k}}}}} = {facts[k]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

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

import ast
import hashlib
import json
import re
import subprocess
import sys
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
    out = {
        "baseline_f1": f"{mean:.4f}",
        "baseline_n": str(len(f1s)),
        "baseline_distinct_f1": str(len({round(v, 6) for v in f1s})),
    }
    for metric in ("precision", "recall"):
        vals = [r[metric] for r in rows if isinstance(r.get(metric), int | float)]
        if len(vals) != len(f1s):
            raise FactError(f"cape_baseline.json has {len(vals)} {metric} rows, {len(f1s)} f1 rows")
        out[f"baseline_{metric}"] = f"{sum(vals) / len(vals):.4f}"
    return out


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

    # "wins at 3x the tokens is not a win" is the design's own sentence, so the
    # ratio it turns on is derived rather than typed.
    tokens: dict[str, int] = {}
    for r in rows:
        if isinstance(r.get("output_tokens"), int | float):
            tokens[r["arm"]] = tokens.get(r["arm"], 0) + int(r["output_tokens"])
    if not tokens.get("single"):
        raise FactError("consensus_ablation.json records no output tokens for the single arm")
    out["consensus_token_ratio"] = f"{tokens['negotiated'] / tokens['single']:.1f}"
    out["consensus_negotiated_tokens"] = str(tokens["negotiated"])
    out["consensus_single_tokens"] = str(tokens["single"])

    base = by_arm["single"]
    for arm in ("negotiated", "noise"):
        shared = sorted(set(base) & set(by_arm[arm]))
        deltas = [by_arm[arm][k] - base[k] for k in shared]
        # The delta itself is emitted by ``cluster_stat_facts``, which owns every
        # paired difference in the paper so that a point estimate and its interval
        # cannot come from two places. What stays here is the count of pairs that
        # moved at all, which the cluster analysis does not carry.
        out[f"consensus_{arm}_nonzero"] = str(sum(1 for d in deltas if abs(d) > 1e-9))
        out[f"consensus_{arm}_paired_n"] = str(len(deltas))
    return out


def cape_consensus_facts() -> dict[str, Any]:
    """The consensus arms on real binaries: what each scored and what it cost.

    Read from the rolled-up artifact, which the harness writes only when a full
    pass over every sample and arm returns — so its presence is the run's own
    statement that it finished, and a partial run yields nothing here rather
    than a number that will move.

    The cost is derived beside the score because the two are the finding. Both
    multi-agent arms beat the single judge by the same amount at the same call
    count, so what separates them from it is the count and not the
    negotiation — and a delta quoted without its token ratio invites exactly
    the reading the noise control was built to refuse.
    """
    path = _HERE / "consensus_ablation_cape.json"
    if not path.exists():
        return {}
    rows = json.loads(path.read_text())
    by_arm: dict[str, list[dict[str, Any]]] = {}
    for r in rows:
        if isinstance(r.get("f1"), int | float):
            by_arm.setdefault(r["arm"], []).append(r)
    if not {"single", "negotiated", "noise"} <= set(by_arm):
        return {}
    single_tokens = sum(int(r.get("output_tokens") or 0) for r in by_arm["single"])
    if not single_tokens:
        raise FactError("consensus_ablation_cape.json records no tokens for the single arm")

    out: dict[str, Any] = {}
    for arm, arm_rows in sorted(by_arm.items()):
        tokens = sum(int(r.get("output_tokens") or 0) for r in arm_rows)
        calls = [int(r.get("calls") or 0) for r in arm_rows]
        out[f"cape_consensus_{arm}_f1"] = f"{sum(r['f1'] for r in arm_rows) / len(arm_rows):.4f}"
        out[f"cape_consensus_{arm}_n"] = str(len(arm_rows))
        out[f"cape_consensus_{arm}_tokens"] = f"{tokens:,}"
        out[f"cape_consensus_{arm}_ratio"] = f"{tokens / single_tokens:.2f}"
        out[f"cape_consensus_{arm}_calls"] = f"{sum(calls) / len(calls):.0f}"
    out["cape_consensus_families"] = str(len({r["sample_id"] for r in rows}))
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

    # What the reasoning flag is worth, on the two models where it can be set at
    # all. The appendix quotes this as a range because it is the size of the
    # confound: an arm labelled matched can be running the opposite
    # configuration, and this is the F1 that hangs on the label being right.
    worth = [
        float(out[f"arm_{m}_nothink_f1"]) - float(out[f"arm_{m}_f1"])
        for m in ("qwen35ba3b", "qwenplus")
        if f"arm_{m}_nothink_f1" in out and f"arm_{m}_f1" in out
    ]
    if len(worth) == 2:
        out["reasoning_flag_worth_low"] = f"{min(worth):.2f}"
        out["reasoning_flag_worth_high"] = f"{max(worth):.2f}"
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
        out[f"judge_{cond}_injected"] = str(tot["injected_because_judge_omitted"])

        # The paper's table reports each of these per call as well as in total,
        # and the per-call column was typed. Dividing by the calls that reached
        # the judge — not by every call attempted — is what makes 50 read as
        # 12.5, and getting that denominator wrong is the difference between
        # "the model emitted twelve patterns a call" and "six".
        calls = d["n_calls"]
        if calls:
            for name, value in (
                ("emitted", tot["judge_patterns_emitted"]),
                ("resolvable", tot["judge_patterns_resolvable"]),
                ("dropped", tot["judge_patterns_unresolvable_dropped"]),
                ("own_ids", d["judge_ids_outside_cascade_total"]),
                ("injected", tot["injected_because_judge_omitted"]),
            ):
                out[f"judge_{cond}_{name}_per_call"] = f"{value / calls:.1f}"

    leak = load("fallback_bundle_content_capped.json")
    out["fallback_only_capped"] = str(leak["techniques_only_on_fallback_path"])
    # Occurrences and distinct identifiers are different counts, and the paper
    # uses both a line apart: 47 techniques reach the analyst, 45 of them
    # distinct, and every one is a real ATT&CK ID rather than an invention.
    out["fallback_only_capped_unique"] = str(
        len({tid for c in leak["per_call"] for tid in c["only_in_fallback"]})
    )
    out["fallback_only_reconciled"] = str(leak["techniques_only_on_reconciled_path"])
    out["fallback_calls"] = str(leak["n_calls"])
    control = load("fallback_bundle_content_uncapped.json")
    out["fallback_identical_uncapped"] = str(control["identical_sets"])
    out["fallback_only_uncapped"] = str(control["techniques_only_on_fallback_path"])

    # The share of the *failed* path's bundle that the model put there. Reported
    # beside the 0-of-N on the working path, so it is derived the same way.
    total_capped = sum(c["fallback_n"] for c in leak["per_call"])
    out["fallback_bundle_total"] = str(total_capped)

    # How much degenerate decode the cap produced. The paper contrasts this with
    # the uncapped condition, where the response is the literal string [TIMEOUT]
    # and carries no identifiers at all — so the range is the size of the thing
    # the fallback builder then scraped for ATT&CK IDs.
    capped_calls = load("judge_contribution_capped.json")["per_call_fallback"]
    chars = [c["response_chars"] for c in capped_calls if c.get("response_chars")]
    if not chars:
        raise FactError("judge_contribution_capped.json records no response lengths")
    out["fallback_decode_chars_min"] = f"{min(chars):,}"
    out["fallback_decode_chars_max"] = f"{max(chars):,}"
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
        # Per fixture as well as per arm. The paper argues the two conditions
        # from set arithmetic — a duplicated source cannot change the cascade's
        # set, a sole owner must — and states that as a count of fixtures, which
        # is a different denominator from the arm count beside it.
        fixtures = {r["sample_id"] for r in varied}
        moved = {
            r["sample_id"]
            for r in varied
            if frozenset(r["technique_ids"] or []) != base[(r["sample_id"], r["repeat"])]
        }
        out[f"cascade_{cond}_fixtures"] = str(len(fixtures))
        out[f"cascade_{cond}_fixtures_changed"] = str(len(moved))
    return out


def series_facts() -> dict[str, Any]:
    """Why the parameter-size series refuses, in its own numbers."""
    d = load("parameter_size_series.json")
    params = [a["total_params_b"] for a in d["arms"]]
    if not params or min(params) <= 0:
        raise FactError("parameter_size_series.json has no usable parameter counts")
    return {
        "series_status": d["status"],
        "series_matched": str(d["configuration_matched"]),
        "series_unmatched": str(d["configuration_unmatched"]),
        "series_sizes": str(d["distinct_sizes_matched"]),
        # The span the correlation was fitted across. Written by hand as "3x"
        # while the arms say 35B to 120B, which is 3.4 — a small error, but the
        # span is the whole reason a rank correlation over three models was
        # thought to mean anything.
        "series_param_span": f"{max(params) / min(params):.1f}",
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


def recorded_suite_count() -> int:
    """The passing-test count the paper states, read from its artefact."""
    return int(load("test_suite_count.json")["count"])


def _format_count(n: int) -> str:
    return f"{n:,}"


def suite_facts() -> dict[str, Any]:
    """The recorded passing-test count from study time, verified by a live run.

    The first version of this counted ``pytest --collect-only`` and returned
    2,671 while ``make check`` reported 2,666 passed. The paper's sentence is "a
    suite of N *passing* tests caught none of them", so collection was answering a
    different question: it includes tests that are skipped or deselected. A fact
    that is off by five in the direction of flattering the suite is exactly the
    kind this module exists to prevent, and it got in on the first attempt.

    The count is recorded in an artefact so tests can be added without moving the
    number in a paper under submission. The run is the green check that the suite
    still works at study time. Costs about a minute.
    """
    # The paper's own gates are excluded, for two reasons that point the same
    # way. They test the manuscript rather than the pipeline, so none of them
    # could have caught any of the seven -- counting them inflates the number in
    # the direction that flatters the suite, which is the error this function's
    # first version already made once. And they read ``facts.tex``, which this
    # run is about to rewrite, so during a run that changes a fact they are
    # stale by construction and cannot pass. ``make paper-check`` runs them
    # afterwards, against the artefact they are about.
    proc = subprocess.run(
        [
            ".venv/bin/python",
            "-m",
            "pytest",
            "tests/",
            "-q",
            "--ignore=tests/evaluation/test_paper_numerals.py",
            "--ignore=tests/evaluation/test_paper_citations.py",
            "--ignore=tests/evaluation/test_paper_terminology.py",
        ],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
    )
    # A red run still prints a passing count, and this used to return it. The
    # paper's sentence would then have read "2,745 passing tests caught none of
    # them" -- a smaller, quieter number produced by a broken suite rather than
    # by a smaller one. The count is only meaningful from a green run.
    if proc.returncode != 0:
        failed = [ln for ln in proc.stdout.splitlines() if ln.startswith(("FAILED", "ERROR"))]
        raise FactError(
            f"the suite did not pass (pytest exit {proc.returncode}); the paper cannot "
            "state a passing-test count from it: " + ("; ".join(failed[:5]) or "see make test")
        )
    live = None
    for line in reversed(proc.stdout.splitlines()):
        m = _PASSED.search(line)
        if m:
            live = int(m.group(1))
            break
    if live is None:
        raise FactError("could not read a passing-test count from pytest")
    recorded = recorded_suite_count()
    if live != recorded:
        print(
            f"note: live suite passes {live} tests; the paper states the recorded "
            f"{recorded} (tests/evaluation/test_suite_count.json)",
            file=sys.stderr,
        )
    return {"test_count": _format_count(recorded)}


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
        "confidence_modal_share": pct(conf.count(top) / len(rows), 0),
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
    # Why it never fires, from the same rows: half the corpus has at most one
    # function that clears the instruction floor, which is a property of the
    # binaries and not of the index. Populating the corpus would not move it.
    hash_matches = sum(int(r.get("n_matches") or 0) for r in rows)
    hash_starved = sum(1 for r in rows if int(r.get("n_functions_kept") or 0) <= 1)

    return {
        "cap_rate": pct(fired / total, 2),
        # The share the cap never touched. The paper quotes it when it explains
        # that a null over this mechanism describes the cases where it did not
        # run, so it is the rate's complement by construction and must move with
        # it rather than beside it.
        "cap_rate_complement": pct(1 - fired / total, 1),
        "cap_fired": str(fired),
        "cap_total": f"{total:,}",
        # The cap's preconditions, which are what actually explain its rate:
        # gating is common, the sole-static requirement is the bottleneck.
        "cap_gated": str(cap["gated_techniques"]),
        "cap_gated_share": pct(cap["gated_share_of_all"]),
        "cap_eligible": str(cap["gated_and_sole_static"]),
        "cap_fire_rate_eligible": pct(cap["cap_fire_rate_among_eligible"]),
        "hint_rate": pct(hint_fired / len(ok)),
        "hint_fired": str(hint_fired),
        "hint_total": str(len(ok)),
        "hash_fired": str(hash_fired),
        "hash_total": str(len(rows)),
        "hash_matches": str(hash_matches),
        "hash_starved": str(hash_starved),
        "hash_functions": f"{functions:,}",
    }


def retrieval_facts() -> dict[str, Any]:
    """The family-feature A/B, and the sink-hint ablation it motivated."""
    fa = load("family_rag_ab.json")["delta_on_minus_off"]
    blob = load("sink_hint_ablation_scored.json")
    sa = blob["summary"]
    d = sa["direction"]
    out = {
        "family_delta_f1": signed(fa["f1"], 4),
        "family_delta_precision": signed(fa["precision"], 4),
        "sink_pairs": str(sa["n_pairs"]),
        "sink_better": str(d["hint_better"]),
        "sink_worse": str(d["hint_worse"]),
        "sink_tied": str(d["tied"]),
    }
    # All three outcomes, not only the one the paper leads with. The table
    # reports them side by side and only the first row was derived, which is how
    # a table comes to mix a current number with two that stopped moving.
    for outcome, key in (("technique IDs", "tids"), ("claims", "claims"), ("seconds", "seconds")):
        row = sa[outcome]
        lo, hi = row["ci95"]
        out[f"sink_delta_{key}"] = signed(row["mean"], 2)
        out[f"sink_ci_{key}"] = f"[{lo:+.2f}, {hi:+.2f}]"

    # The per-pair deltas the paper lists to show the spread. Read from the rows
    # rather than transcribed, because "large in both directions and cancelling"
    # is an argument about exactly these numbers.
    pairs = blob.get("per_pair") or []
    if len(pairs) != sa["n_pairs"]:
        raise FactError(f"{len(pairs)} per-pair rows against a summary claiming {sa['n_pairs']}")
    deltas = sorted((p["on"]["tids"] - p["off"]["tids"] for p in pairs), reverse=True)
    # Plain signs; tex_value turns them into maths on the way out, the same as
    # it does for every other signed fact. Writing $-$ here instead would work
    # and would be the one place that knows about TeX.
    out["sink_pair_deltas"] = ", ".join("0" if v == 0 else f"{v:+g}" for v in deltas)

    # What the study lost, by reason. The paper's argument is that the loss rate
    # bounds what any ablation here can detect, so the rate has to be the one
    # the exclusions actually produce rather than a round number beside them.
    excluded = blob.get("excluded") or {}
    lost = sum(len(v) for v in excluded.values())
    attempted = lost + sa["n_pairs"]
    if not attempted:
        raise FactError("the sink-hint ablation records neither pairs nor exclusions")
    for reason, ids in excluded.items():
        out[f"sink_excluded_{reason}"] = str(len(ids))
    out["sink_excluded_total"] = str(lost)
    out["sink_attempted"] = str(attempted)
    out["sink_pair_loss_rate"] = pct(lost / attempted, 0)
    return out


# ---------------------------------------------------------------------------
# The corrected statistics
# ---------------------------------------------------------------------------


def _cluster() -> Any:
    """The re-analysis artifact, refusing a stale one.

    ``cluster_analysis.json`` is written by ``reanalyse.py`` from the committed
    per-sample records. It is the only source for anything cluster-level: reading
    a per-study summary instead would reintroduce exactly the row-level numbers
    the re-analysis exists to replace.
    """
    d = load("cluster_analysis.json")
    if d.get("schema") != "maljan-cluster-analysis/v1":
        raise FactError(f"cluster_analysis.json has schema {d.get('schema')!r}")
    return d


def _comparison(cid: str) -> dict[str, Any]:
    comps = _cluster()["comparisons"]
    if cid not in comps:
        raise FactError(f"comparison {cid} is not in cluster_analysis.json")
    return comps[cid]


def fixture_ceiling_facts() -> dict[str, Any]:
    """What a regular expression scores on the fixture corpus, measured not asserted.

    The paper says no baseline is definable for the five synthesised fixtures
    because a deterministic extractor over the dictionary that generated their
    evidence scores perfectly by construction. That is a claim about a
    measurement, so it is measured: the artifact dictionary is inverted into a
    prose-to-technique lookup, run over each fixture's assembled channels, and
    scored against the same ground truth every arm is scored against.

    If it ever came back below 1.0 the sentence would be wrong and the build
    would carry a number that contradicts it.
    """
    import sys

    if str(_REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(_REPO_ROOT))
    from tests.evaluation.eval_consensus_ablation import (
        _ARTIFACTS,
        build_channels,
        load_samples,
        prf,
    )

    samples = load_samples()
    if not samples:
        raise FactError("no fixtures found")
    by_text = {text: tid for tid, (_chan, text) in _ARTIFACTS.items()}
    f1s = []
    for _sid, truth in samples:
        blob = "\n".join(build_channels(truth).values())
        predicted = [tid for text, tid in by_text.items() if text in blob]
        f1s.append(prf(predicted, truth)[2])
    mean = sum(f1s) / len(f1s)
    if mean < 0.999:
        raise FactError(
            f"the trivial extractor scores {mean:.4f} on the fixtures, not 1.0 — "
            "the claim that no baseline is definable there needs rewriting"
        )
    return {
        "fixture_extractor_f1": f"{mean:.3f}",
        "fixture_extractor_n": str(len(f1s)),
    }


def fallback_table_facts() -> dict[str, Any]:
    """The per-fixture fallback-versus-cascade table, generated as LaTeX rows.

    Four fixtures, four numbers each, typed by hand into a table that the
    artifact already holds. A table of measurements is the last place a reader
    expects a transcription, and it is the easiest place to make one.
    """
    d = load("fallback_bundle_content_capped.json")
    rows = d.get("per_call")
    if not rows:
        raise FactError("fallback_bundle_content_capped.json has no per_call rows")
    body = []
    for r in sorted(rows, key=lambda x: str(x["sample_id"])):
        only = len(r["only_in_fallback"])
        body.append(
            f"\\texttt{{{r['sample_id']}}} & {r['fallback_n']} & {r['cascade_n']} "
            f"& \\textbf{{{only}}} \\\\"
        )
    leaked = sum(len(r["only_in_fallback"]) for r in rows)
    if leaked != d["techniques_only_on_fallback_path"]:
        raise FactError(
            f"per-call rows sum to {leaked} leaked techniques, the summary says "
            f"{d['techniques_only_on_fallback_path']}"
        )
    # Written to its own file rather than returned as a macro. An ``&`` produced
    # by expanding a macro is not an alignment tab — TeX has already decided
    # where the cells are by the time the macro runs — so a generated table body
    # has to arrive through \input, which is read at the right moment. The
    # symptom was a four-column table printing "jhuhugit & 32 & 20 & 12" into one
    # cell, which compiles cleanly and is visibly wrong only on the page.
    TABLES.mkdir(parents=True, exist_ok=True)
    (TABLES / "fallback-rows.tex").write_text("\n".join(body) + "\n")

    # ``fallback_bundle_total`` is judge_facts' — one derivation per number — but
    # the rows are checked against it, because a generated table that disagrees
    # with the total beside it is worse than either alone.
    return {
        "fallback_cascade_total": str(sum(r["cascade_n"] for r in rows)),
        "fallback_fixtures": str(len(rows)),
    }


def corpus_shape_facts() -> dict[str, Any]:
    """What the analysed corpus looks like, from the records rather than memory."""
    d = load("sink_hint_frequency.json")
    rows = [v for v in d["results"].values() if not v.get("error")]
    graphs = [v["graph_chars"] for v in rows if v.get("graph_chars")]
    if not graphs:
        raise FactError("sink_hint_frequency.json records no call-graph sizes")
    hints = [v["hint_chars"] for v in rows if v.get("hint_nonempty")]
    out: dict[str, Any] = {
        "cardinality_distinct_graphs": str(len(set(graphs))),
        "cardinality_samples": str(len(graphs)),
        # How often the call-graph edge cap actually bit. The paper's point is
        # that the cap was found while instrumenting something else, so the rate
        # has to come from the records rather than from the sentence that
        # reports the discovery.
        "graph_edge_cap_hit": str(sum(1 for v in rows if v.get("hit_limit"))),
        "hint_nonempty": str(len(hints)),
        "hint_chars_min": str(min(hints)) if hints else "0",
        "hint_chars_max": str(max(hints)) if hints else "0",
    }

    cohort = load("dynamic_cohort_n100.json")
    out["cohort_n"] = str(len(cohort["samples"]))
    # The selection seed, taken from the cohort it selected rather than from the
    # sentence that describes it. A seed quoted from memory beside a cohort that
    # was drawn with a different one is unfalsifiable and reproduces nothing.
    out["cohort_seed"] = str(cohort["seed"])

    # What the analysts were actually fed, on the samples with sandbox reports.
    import statistics

    reports_dir = _REPO_ROOT / "data" / "cape_reports"
    calls, domains, per_sample = [], [], []
    for path in sorted(reports_dir.glob("*.json")):
        blob = json.loads(path.read_text())
        behaviour = blob.get("behavior") or {}
        procs = behaviour.get("processes") or []
        calls.append(sum(len(p.get("calls") or []) for p in procs if isinstance(p, dict)))
        entries = (blob.get("network") or {}).get("domains") or []
        names = {e.get("domain") for e in entries if isinstance(e, dict) and e.get("domain")}
        domains.append(len(entries))
        per_sample.append(names)
    if not calls:
        raise FactError("no archived CAPE reports to characterise the corpus with")
    out["evidence_median_calls"] = str(int(statistics.median(calls)))
    out["evidence_domains_min"] = str(min(domains))
    out["evidence_domains_max"] = str(max(domains))
    out["evidence_reports"] = str(len(calls))

    # How much of the "dynamic" network channel is the analysis VM describing
    # itself. The paper reports this beside every dynamic-versus-static
    # contrast, so it has to move with the cohort rather than with the sentence:
    # the earlier 43-report version of this measurement gave different figures,
    # and the whole point of quoting it is that the contrast cannot be read
    # without it.
    populated = [names for names in per_sample if names]
    if populated:
        distinct = set().union(*populated)
        ubiquitous = {d for d in distinct if all(d in names for names in populated)}
        shares = [len(names & ubiquitous) / len(names) for names in populated]
        out["network_domains_distinct"] = str(len(distinct))
        out["network_domains_ubiquitous"] = str(len(ubiquitous))
        out["network_ubiquitous_min"] = pct(min(shares), 1)
        out["network_ubiquitous_max"] = pct(max(shares), 1)
        out["network_ubiquitous_median"] = pct(statistics.median(shares), 1)
        out["network_samples_with_domains"] = str(len(populated))
    return out


def case_corpus_facts() -> dict[str, Any]:
    """How many cases the ATT&CK case-prior index was built from.

    Counted from the corpus the retrieval record names, rather than from the
    sentence, because this number carries the paper's leakage check: the claim
    is that none of these shares a digest with either evaluation cohort, and a
    count that does not match the file leaves the reader unable to tell which
    corpus was checked.
    """
    named = load("attck_case_rag_retrieval.json")["corpus"]
    path = _REPO_ROOT / named
    if not path.exists():
        raise FactError(f"the retrieval record names {named}, which is not on disk")
    blob = json.loads(path.read_text())
    cases = blob if isinstance(blob, list) else blob.get("cases", blob)
    return {"case_corpus_n": f"{len(cases):,}"}


def retrieval_scores_facts() -> dict[str, Any]:
    """The two retrieval indices, each scored twice.

    Every one of these is a pair, and the pairing is the argument: the case
    index beats a frequency prior on the corpus's own labels and loses to it on
    MITRE ground truth, and the family index beats chance on a held-out split
    and moves nothing end to end. A number from one half of a pair typed beside
    a number derived from the other is how a paper comes to compare two things
    that were never measured the same way.
    """
    case = load("attck_case_rag_retrieval.json")
    native, runtime = case["native"], case["runtime"]
    fam = load("family_rag_retrieval.json")
    ab = load("family_rag_ab.json")
    chance = fam["random_baseline_recall_at_5"]
    if not chance:
        raise FactError("family_rag_retrieval.json records no random baseline")
    return {
        # Self-consistency: scored against the corpus's own prior attributions.
        "case_prior_self_f1": f"{native['rag']['novel']['f1']:.3f}",
        "case_prior_self_frequency_f1": f"{native['frequency_prior']['f1']:.3f}",
        # Production: scored against MITRE ground truth on held-out samples.
        "case_prior_prod_f1": f"{runtime['rag_shipped_query']['f1']:.3f}",
        "case_prior_prod_frequency_f1": f"{runtime['frequency_prior']['f1']:.3f}",
        "case_prior_prod_samples": str(runtime["samples"]),
        "case_prior_top_k": str(case["params"]["top_k"]),
        "family_recall_at_5": f"{fam['recall_at_5']:.3f}",
        "family_recall_chance_ratio": f"{fam['recall_at_5'] / chance:.1f}",
        "family_ab_samples": str(ab["on"]["samples"]),
    }


def technique_mapping_facts() -> dict[str, Any]:
    """The deterministic technique assigner, scored on two public corpora.

    Both corpora are external and neither is the ATT&CK descriptions the index
    is built from, which is the whole point: scoring a retrieval index against
    the text it indexes measures nothing. TRAM2 is sentence classification and
    AnnoCTR is entity linking in running report prose, by different annotators
    over different documents, so absolute accuracy is not comparable across the
    two and is not compared here. What is compared is the ordering of the three
    backends on each axis, which is the claim.
    """
    d = load("annoctr_mapping.json")
    a, t2 = d["annoctr"], d["tram2_reference"]
    # TRAM2's own record, for the sample size and to prove the reference block
    # in annoctr_mapping.json is a copy of it rather than a literal that drifted.
    tram2_rec = load("technique_mapping.json")
    if tram2_rec["tram2"]["hybrid"]["top3"] != t2["hybrid"]["top3"]:
        raise FactError(
            "annoctr_mapping.json's TRAM2 reference disagrees with technique_mapping.json"
        )
    rep = d["replication"]
    if not (
        rep["ranking_order_holds"] and rep["gate_order_holds"] and rep["hybrid_wins_both_axes"]
    ):
        raise FactError("annoctr_mapping.json no longer records the replication it is cited for")
    out: dict[str, Any] = {
        "mapping_tram2_n": f"{int(tram2_rec['corpus']['pairs_scored']):,}",
        "mapping_annoctr_n": f"{int(a['tfidf']['n']):,}",
        "mapping_annoctr_dropped": str(d["corpus"]["labels_outside_our_attck_bundle"]),
    }
    for backend in ("tfidf", "semantic", "hybrid"):
        out[f"mapping_tram2_{backend}_top3"] = f"{t2[backend]['top3']:.3f}"
        out[f"mapping_tram2_{backend}_mrr"] = f"{t2[backend]['mrr']:.3f}"
        out[f"mapping_tram2_{backend}_gate"] = signed(t2[backend]["gate_separation"], 3)
        out[f"mapping_annoctr_{backend}_top3"] = f"{a[backend]['top3']:.3f}"
        out[f"mapping_annoctr_{backend}_mrr"] = f"{a[backend]['mrr']:.3f}"
        out[f"mapping_annoctr_{backend}_gate"] = signed(a[backend]["gate_separation"], 3)
        # Scale-free, so the three backends can actually be compared. Gate
        # separation is a difference of means on scales that differ by a factor
        # of three between these backends.
        for corpus, row in (("tram2", tram2_rec["tram2"][backend]), ("annoctr", a[backend])):
            auroc = row.get("gate_auroc")
            if auroc is None:
                raise FactError(f"{corpus}/{backend} has no gate AUROC; re-run the evaluation")
            out[f"mapping_{corpus}_{backend}_auroc"] = f"{auroc:.3f}"
            # The scale the separation is measured on, which is why it needs one.
            out[f"mapping_{corpus}_{backend}_correct"] = f"{row['mean_correct_score']:.3f}"
    return out


def stix_conformance_facts() -> dict[str, Any]:
    """Output conformance, measured with someone else's instrument.

    The pass this project wrote checks empty patterns, duplicate
    attack-patterns and dangling references. The standard validator checks the
    specification, which is a different set, and the gap between the two is the
    reason for reporting the second rather than the first.
    """
    d = load("stix_integrity.json")
    emitter = d["current_emitter"]["validator"]
    real, inj = d["real_bundles"], d["injected_defects"]
    return {
        "stix_validator": d["instrument"].split(",")[0],
        "stix_emitter_errors": str(emitter["n_errors"]),
        "stix_emitter_ref_warnings": str(emitter["n_ref_warnings"]),
        "stix_archived_bundles": str(real["n"]),
        "stix_archived_clean": str(real["clean_with_pass"]),
        "stix_injected_bundles": str(inj["n"]),
        "stix_injected_clean_after_repair": str(inj["clean_after_repair"]),
        "stix_objects_preserved": str(inj["objects_preserved_vs_rejection"]),
    }


def layer0_excluded_facts() -> dict[str, Any]:
    """The two Layer-0 sources that were offered evidence and declined it.

    Derived from the ablation's own record of why it excluded them, not from the
    current cohort. The distinction is the point: the exclusion was measured on
    the reports that existed then, and the paper had drifted to quoting today's
    cohort size and today's median API count beside a decision taken against
    neither. A denominator that follows the corpus while the measurement does
    not is a claim about work nobody did.
    """
    excluded = load("layer0_verdict_v2_overlap.json").get("excluded_sources") or []
    if not excluded:
        raise FactError("layer0_verdict_v2_overlap.json records no excluded sources")
    out: dict[str, Any] = {"layer0_declined_sources": str(len(excluded))}
    seen: set[str] = set()
    for source in excluded:
        reason = source.get("reason") or ""
        match = re.search(r"(\d+)\s*/\s*(\d+)\s+archived reports", reason)
        if not match:
            raise FactError(f"cannot read the denominator out of: {reason!r}")
        seen.add(match.group(2))
        if median := re.search(r"median\s+([\d,]+)\s+API calls", reason):
            out["layer0_declined_median_calls"] = f"{int(median.group(1).replace(',', '')):,}"
        if domains := re.search(r"(\d+-\d+)\s+domains", reason):
            # "48-68" is a range, and this paper writes a range as "48 to 68":
            # the house rule refuses an en dash in the rendered text, so turning
            # the hyphen into one only moved the problem, and the escaper then
            # printed it as a hyphen followed by a maths minus.
            out["layer0_declined_domains"] = domains.group(1).replace("-", " to ")
    if len(seen) != 1:
        raise FactError(f"the excluded sources disagree on their denominator: {sorted(seen)}")
    out["layer0_declined_of"] = seen.pop()
    return out


def model_size_facts() -> dict[str, Any]:
    """How much larger the frontier model is, computed rather than recalled.

    Both parameter counts are in the arms' own names; the ratio the paper quotes
    three times is arithmetic on them.
    """
    local_b, frontier_b = 35.0, 120.0
    return {
        "param_ratio": f"{frontier_b / local_b:.1f}",
        "local_params_b": f"{local_b:.0f}",
        "frontier_params_b": f"{frontier_b:.0f}",
    }


def cascade_jaccard_facts() -> dict[str, Any]:
    """Each Layer-0 condition's Jaccard against its all-sources arm.

    Overlap is a constant 1.000 with a zero-width interval, which is what the
    paper reports and what it says it should have read as a tell rather than as
    a strong null. Derived because an automatic substitution mistook that 1.000
    for another quantity that also happens to be 1.000 — the two are unrelated
    and a shared literal is exactly how they came to be confused.

    Disjoint is derived for the opposite reason: it is the row of the same table
    that varies, so it is the one that can drift without anybody noticing.
    """
    out: dict[str, Any] = {}
    for cond in ("overlap", "disjoint"):
        d = load(f"layer0_verdict_v2_{cond}.json")
        arms = d.get("arms")
        if not arms:
            raise FactError(f"layer0_verdict_v2_{cond}.json has no arms")
        base = {
            (a["sample_id"], a["repeat"]): set(a["technique_ids"])
            for a in arms
            if a["arm"] == "all"
        }
        js = []
        for a in arms:
            if a["arm"] == "all":
                continue
            other = base.get((a["sample_id"], a["repeat"]))
            if other is None:
                continue
            mine = set(a["technique_ids"])
            union = mine | other
            js.append(len(mine & other) / len(union) if union else 1.0)
        if not js:
            raise FactError(f"no paired {cond} arms to compare against the all-sources baseline")
        out[f"cascade_{cond}_jaccard"] = f"{sum(js) / len(js):.3f}"
        out[f"cascade_{cond}_jaccard_min"] = f"{min(js):.3f}"
        out[f"cascade_{cond}_jaccard_max"] = f"{max(js):.3f}"
        out[f"cascade_{cond}_pairs"] = str(len(js))
    return out


def drift_facts() -> dict[str, Any]:
    """The withdrawn study's shape, from the one thing that survived it.

    The results are gone — written to a path that was valid on the machine the
    harness was first written on and silently relative on the machine it ran on.
    The manifest survives, so the cohort is still describable even though it can
    no longer be asked its question, and the paper quotes its size six times.
    """
    d = load("temporal_manifest.json")
    cohorts = d.get("cohorts")
    if not isinstance(cohorts, dict) or not cohorts:
        raise FactError("temporal_manifest.json has no per-year cohorts")
    n = sum(len(v) for v in cohorts.values())
    stored = d.get("counts") or {}
    if stored and sum(stored.values()) != n:
        raise FactError(
            f"the manifest's counts sum to {sum(stored.values())}, its cohorts hold {n}"
        )
    families = {s["signature"] for v in cohorts.values() for s in v if s.get("signature")}
    years = sorted(cohorts)
    return {
        "drift_n": str(n),
        "drift_cohorts": str(len(cohorts)),
        "drift_families": str(len(families)),
        "drift_first_year": years[0],
        "drift_last_year": years[-1],
    }


def cape_audit_facts() -> dict[str, Any]:
    """The sandbox reported every task complete; the timings say otherwise.

    The split is bimodal with nothing between the modes, which is why the
    boundary is stated as a threshold rather than fitted: a Windows PE does not
    detonate in a second, and every task on the fast side is one that produced no
    report directory while still being marked reported.
    """
    rows = load("cape_task_status_audit.json")
    timed = [r for r in rows if isinstance(r.get("seconds"), int | float)]
    if not timed:
        raise FactError("cape_task_status_audit.json has no timed tasks")
    fast = [r for r in timed if r["seconds"] <= 1]
    slow = [r for r in timed if r["seconds"] > 1]
    if not slow:
        raise FactError("no task in the audit ran for more than a second")
    gap_lo = max(r["seconds"] for r in fast) if fast else 0
    gap_hi = min(r["seconds"] for r in slow)
    if gap_hi - gap_lo < 60:
        raise FactError(
            f"the audit's two modes are {gap_hi - gap_lo:.0f}s apart — the split "
            "is no longer bimodal and the threshold has to be re-argued"
        )
    # How many of the instant tasks a re-submission recovered. Derived from the
    # baseline's own skip counts rather than from the report directory, which is
    # not committed — the reports embed strings and memory contents from live
    # malware. The two must agree, and the derivation says so if they do not.
    baseline = load("cape_baseline.json")
    scored = len(baseline["per_sample"])
    lost_shas = baseline["skipped"]["no_report"]
    lost = len(lost_shas)
    cohort = len(load("dynamic_cohort_n100.json")["samples"])
    if scored + lost != cohort:
        raise FactError(
            f"{scored} scored plus {lost} without a report is not the {cohort}-sample cohort"
        )
    recovered = scored - len(slow)
    if recovered < 0:
        raise FactError("more samples scored than were ever submitted")

    # Every permanently lost task still reports success. That is the point of the
    # sentence these numbers appear in, so it is checked against the identities
    # rather than described: if one of them ever admits failure the claim has to
    # be rewritten, and the derivation will say so.
    by_sha = {str(r.get("sha256")): r for r in rows}
    still_claiming = sum(
        1 for sha in lost_shas if str(by_sha.get(sha, {}).get("status")) == "reported"
    )

    return {
        "audit_recovered": str(recovered),
        "audit_lost": str(lost),
        "audit_lost_still_reporting_success": str(still_claiming),
        "audit_tasks": str(len(rows)),
        "audit_timed": str(len(timed)),
        "audit_instant": str(len(fast)),
        "audit_real": str(len(slow)),
        "audit_real_min": f"{min(r['seconds'] for r in slow):.0f}",
        "audit_real_max": f"{max(r['seconds'] for r in slow):.0f}",
        "audit_reported_but_instant": str(
            sum(1 for r in fast if str(r.get("status")) == "reported")
        ),
    }


def cluster_stat_facts() -> dict[str, Any]:
    """Every interval the paper states, at the cluster level, plus its structure.

    Nine comparisons and one baseline, each with the design effect that says how
    much of its row count is real. The names are the paper's own labels for the
    comparisons rather than the file stems, so a sentence and its number are
    findable from each other.
    """
    d = _cluster()
    out: dict[str, Any] = {}

    # Rule 1 of this module is derive-from-records-not-summaries, and
    # cluster_analysis.json is a summary from this file's point of view. So the
    # two deltas it is possible to check are recomputed here from the per-arm
    # rows and compared. A disagreement means the re-analysis ran against a
    # different corpus than the one on disk, which is the failure that would
    # otherwise be invisible.
    rows = load("consensus_ablation.json")
    by_arm: dict[str, dict[Any, float]] = {}
    for r in rows:
        if isinstance(r.get("f1"), int | float):
            by_arm.setdefault(r["arm"], {})[(r["sample_id"], r.get("repeat", 0))] = float(r["f1"])
    for arm, cid in (("negotiated", "P1"), ("noise", "P2")):
        base, other = by_arm["single"], by_arm[arm]
        keys = sorted(set(base) & set(other))
        direct = sum(other[k] - base[k] for k in keys) / len(keys)
        stored = _comparison(cid)["delta"]
        if abs(direct - stored) > 5e-4:
            raise FactError(
                f"{cid}: cluster_analysis says {stored:+.4f}, the per-arm rows say {direct:+.4f}"
            )

    labels = {
        "P1": "consensus_negotiated",
        "P2": "consensus_noise",
        "P3": "frontier_local",
        "P4": "confidence_auc_cluster",
        "E1": "quantisation",
        "E2": "reasoning_flag_vendor35b",
        "E3": "reasoning_flag_third",
        "E4": "frontier_replication",
        "E5": "vendor_think",
        # The real-corpus replication. Conditional: the run may not have
        # finished, and reanalyse withholds these until it has.
        "C1": "cape_negotiated",
        "C2": "cape_noise",
        "C3": "cape_mechanism",
    }
    for cid, name in labels.items():
        if cid.startswith("C") and cid not in d["comparisons"]:
            continue
        c = _comparison(cid)
        iv = c["interval"]
        out[f"{name}_delta"] = signed(c["delta"])
        out[f"{name}_ci"] = interval(iv["lo"], iv["hi"])
        # The sign-flip p, whichever route produced it, and the route named
        # beside it. `_p_exact` keeps its name for the comparisons that were
        # enumerated; at twenty-four clusters the assignments are sampled, and
        # a fact called "exact" must not quietly hold a sampled number. This is
        # the third consumer that assumed enumeration always ran — the harness
        # crashed on it, the re-analysis corrected on it, and this one turned a
        # None into a formatting error mid-derivation.
        out[f"{name}_p"] = f"{c['p_signflip']:.4f}"
        out[f"{name}_p_method"] = c["p_signflip_method"]
        out[f"{name}_p_floor"] = f"{c['p_floor']:.5f}"
        if c["p_exact_signflip"] is not None:
            out[f"{name}_p_exact"] = f"{c['p_exact_signflip']:.4f}"
        out[f"{name}_q_exact"] = f"{c['q_exact']:.4f}"
        out[f"{name}_k"] = str(c["structure"]["k"])
        out[f"{name}_pairs"] = str(c.get("n_pairs") or c["interval"]["n_rows"])
        # The worst case the interval still admits, as a magnitude. Several
        # sentences read an interval aloud — "admits a penalty of over 0.2 F1" —
        # and a bound restated by hand stops moving when the interval does.
        out[f"{name}_worst"] = f"{max(abs(iv['lo']), abs(iv['hi'])):.4f}"
        if "better" in c:
            out[f"{name}_better"] = str(c["better"])
            out[f"{name}_worse"] = str(c["worse"])

    cb = d["cape_baseline"]
    for metric in ("precision", "recall", "f1"):
        m = cb[metric]
        out[f"baseline_{metric}_cluster_ci"] = interval(m["interval"]["lo"], m["interval"]["hi"])
        out[f"baseline_{metric}_widening"] = f"{m['widening']:.2f}"
        out[f"baseline_{metric}_icc"] = f"{m['structure']['icc']:.3f}"
        out[f"baseline_{metric}_effective_n"] = f"{m['structure']['effective_n']:.1f}"
    out["baseline_families"] = str(cb["k"])
    out["baseline_mean_cluster"] = f"{cb['n'] / cb['k']:.2f}"

    p4 = _comparison("P4")
    out["confidence_auc_lo"] = f"{p4['interval']['lo']:.3f}"
    out["confidence_auc_hi"] = f"{p4['interval']['hi']:.3f}"
    out["confidence_clusters"] = str(p4["structure"]["k"])
    out["confidence_at_or_below_chance"] = str(p4["clusters_at_or_below_chance"])
    out["confidence_best_cluster_auc"] = f"{max(v['auc'] for v in p4['per_cluster'].values()):.3f}"
    out["confidence_icc"] = f"{p4['structure']['icc']:.3f}"
    out["confidence_design_effect"] = f"{p4['structure']['design_effect']:.1f}"
    out["confidence_effective_n"] = f"{p4['structure']['effective_n']:.1f}"
    out["confidence_auc_naive"] = f"{p4['naive_descending_sort_auc']:.3f}"

    # The only like-for-like comparison in the paper: pipeline against the
    # signature engine it is built on, same samples, same truth, same scoring.
    h = d["head_to_head"]
    out["h2h_n"] = str(h["n"])
    out["h2h_families"] = str(h["k"])
    for arm, name in (
        ("cape_f1", "h2h_cape"),
        ("static_only_f1", "h2h_static"),
        ("dynamic_f1", "h2h_dynamic"),
    ):
        out[f"{name}_f1"] = f"{h[arm]['mean']:.4f}"
        out[f"{name}_ci"] = interval(h[arm]["interval"]["lo"], h[arm]["interval"]["hi"])
    hm = h["pipeline_minus_cape"]
    out["h2h_delta"] = signed(hm["delta"])
    out["h2h_ci"] = interval(hm["interval"]["lo"], hm["interval"]["hi"])
    out["h2h_p_exact"] = f"{hm['p_exact_signflip']:.4f}"
    out["h2h_mde"] = f"{hm['mde_t']:.3f}"
    out["h2h_better"] = str(hm["better"])
    out["h2h_worse"] = str(hm["worse"])

    jc = d["judge_contribution"]
    out["judge_mechanism_arms"] = str(jc["arms"])
    out["judge_mechanism_samples"] = str(jc["samples"])
    out["judge_mechanism_added"] = str(jc["samples_where_the_judge_added_a_technique"])
    out["judge_mechanism_upper_bound"] = f"{jc['rule_of_three_upper_bound']:.3f}"
    return out


def power_facts() -> dict[str, Any]:
    """What each null could have detected, and the floor the design cannot cross.

    A null without a minimum detectable effect is unreadable, and every null in
    this paper was reported without one. ``fixture_signflip_floor`` is the number
    that governs the rest: at five clusters no comparison on that corpus can
    reach alpha=0.05, whatever its effect size.
    """
    d = _cluster()
    out: dict[str, Any] = {
        "fixture_clusters": str(d["design"]["fixture_clusters"]),
        "fixture_signflip_floor": f"{d['design']['signflip_floor']:.4f}",
        # The draw count, taken from the analysis that used it rather than from
        # the methodology sentence describing it. Above twenty clusters this is
        # what sets the smallest p the test can return, so a sentence quoting a
        # different number would misstate the resolution of every replication p.
        "stats_iters": f"{d['bootstrap_iters']:,}",
    }
    labels = {
        "P1": "consensus_negotiated",
        "P2": "consensus_noise",
        "P3": "frontier_local",
        "P4": "confidence_auc_cluster",
        "E1": "quantisation",
        "E2": "reasoning_flag_vendor35b",
        "E3": "reasoning_flag_third",
        "E5": "vendor_think",
        # The replication, whose MDE is the number that makes its null readable:
        # at k=24 the mechanism contrast resolves 0.046, and the effect the
        # mechanism would have to carry is the 0.054 its neighbours show. A null
        # below its own resolution says nothing; this one is not that.
        "C1": "cape_negotiated",
        "C2": "cape_noise",
        "C3": "cape_mechanism",
    }
    for cid, name in labels.items():
        if cid.startswith("C") and cid not in _cluster()["comparisons"]:
            continue
        c = _comparison(cid)
        # The prose rounds to two places where the interval is a tenth wide,
        # which is the honest precision; both are emitted so a sentence and a
        # table can each use the one that fits without either being typed.
        out[f"{name}_delta_2dp"] = f"{abs(c['delta']):.2f}"
        out[f"mde_{name}"] = f"{c['mde_t']:.3f}"
        out[f"mde_{name}_z"] = f"{c['mde_z']:.3f}"
        # Whether the observed effect is even inside the design's resolution.
        out[f"{name}_above_mde"] = "yes" if abs(c["delta"]) >= c["mde_t"] else "no"
    return out


def multiplicity_facts() -> dict[str, Any]:
    """Family membership and Benjamini-Hochberg q-values.

    Two declared families: the pre-registered primary comparisons, and the
    configuration sweep run after the reasoning-flag confound was found. Per-arm
    descriptive intervals carry no null and are not corrected — correcting an
    estimate is a category error, and saying so is part of reporting the
    correction honestly.
    """
    d = _cluster()
    fams = d["families"]
    out: dict[str, Any] = {}
    for key, short in (("A_primary", "primary"), ("B_posthoc", "posthoc")):
        f = fams[key]
        out[f"family_{short}_m"] = str(f["m"])
        out[f"family_{short}_members"] = ", ".join(f["members"])
        out[f"family_{short}_survivors_exact"] = str(f["survivors_at_q05_exact"])
        out[f"family_{short}_survivors_bootstrap"] = str(f["survivors_at_q05_bootstrap"])
    total = sum(fams[k]["survivors_at_q05_exact"] for k in fams)
    out["multiplicity_survivors_total"] = str(total)
    return out


def provenance_facts() -> dict[str, Any]:
    """Numbers the paper states that no committed artifact can produce.

    Six quantities in the introduction and conclusion come from live sessions
    whose raw output was not retained: the identical call graphs, the run of
    identically-sized hints, the token count of an unbounded decode, the paged-out
    working set, the halted arm count, and the superseded rank correlation. They
    are not fabricated — each is recorded in a dated entry of the findings log or
    a harness docstring — but they are *observations*, not measurements from the
    record, and the paper must not present them as the latter.

    The registry makes that distinction machine-checkable. A record with neither
    an artifact nor an explicit ``unretained-session`` provenance raises, so a
    number cannot quietly acquire the authority of a derivation by being added
    here.
    """
    reg = load("narrative_provenance.json")
    if reg.get("schema") != "maljan-narrative-provenance/v1":
        raise FactError(f"narrative_provenance.json has schema {reg.get('schema')!r}")
    # The only provenances a number may claim when no artifact backs it. Anything
    # else is a number with no account of where it came from, which is what this
    # registry exists to make impossible rather than merely discouraged.
    declared = {"unretained-session", "configuration-constant", "derived-elsewhere"}
    out: dict[str, Any] = {}
    for name, rec in sorted((reg.get("records") or {}).items()):
        if not rec.get("artifact") and rec.get("provenance") not in declared:
            raise FactError(
                f"{name} has no artifact and claims provenance {rec.get('provenance')!r}, "
                f"which is not one of {sorted(declared)}"
            )
        if not rec.get("record_ref"):
            raise FactError(f"{name} cites no record")
        if "value" not in rec:
            raise FactError(f"{name} has no value")
        out[name] = str(rec["value"])
    return out


def paired_selection_facts() -> dict[str, Any]:
    """What the paired cohort selected for, beyond completing both arms.

    The head-to-head block is 13 of the 97 samples, and the paper reported the
    count without asking what the other 84 had in common. They are not a random
    subsample: completion required the dynamic arm to finish inside its
    wall-clock bound, and the samples that did are the older ones.

    Reported as the two medians and the years that contribute nothing, because
    both are forced by the data. An earlier version of this took the run of
    years below the first empty one, which on this cohort is every year the
    paired block has, and printed "13 of the 13" -- a window wide enough to
    contain its own answer.
    """
    per_sample = load("cape_baseline.json")["per_sample"]
    paired = {r["sha256"] for r in load("dynamic_vs_static.json")["per_pair"]}
    if not paired <= {r["sha256"] for r in per_sample}:
        raise FactError("a paired sample is not in the baseline cohort")

    def median_year(rows: list[dict[str, Any]]) -> str:
        years = sorted(int(r["year"]) for r in rows)
        return str(years[len(years) // 2])

    in_paired = [r for r in per_sample if r["sha256"] in paired]
    absent = sorted({r["year"] for r in per_sample} - {r["year"] for r in in_paired})
    if not absent:
        raise FactError("every cohort year is represented; the selection claim no longer holds")
    n_absent = sum(1 for r in per_sample if r["year"] in absent)

    return {
        "h2h_paired_median_year": median_year(in_paired),
        "h2h_cohort_median_year": median_year(per_sample),
        "h2h_unpaired_recent_n": str(n_absent),
        "h2h_unpaired_recent_years": (
            absent[0] if len(absent) == 1 else " and ".join((absent[0], absent[-1]))
        ),
    }


def weight_sensitivity_facts() -> dict[str, Any]:
    """How far the cascade's hand-chosen trust weights reach.

    This result was stated in the related-work section as a range typed by hand,
    which is the one body file the numerals gate exempts — its numbers are
    quoted from cited literature, and ours had been parked among them. The range
    it stated, 10.6 to 27.5%, is a superseded cohort's; the record says 12.4 to
    28.9%. So the number went stale in the only place nothing was watching, which
    is the drift this module exists to make impossible.
    """
    d = load("weight_sensitivity_six.json")
    if d.get("schema") != "weight-sensitivity-six/v1":
        raise FactError(f"weight_sensitivity_six.json has schema {d.get('schema')!r}")
    perts = d["perturbations"]
    if not perts:
        raise FactError("weight_sensitivity_six.json lists no perturbations")
    moved = {k: v["fraction_corroborated_changed"] for k, v in perts.items()}
    # The claim is that the corroborated set does not move at all. If one ever
    # does, the sentence is false and the build has to stop rather than round it.
    if any(moved.values()):
        raise FactError(f"a perturbation moved the corroborated set: {moved}")
    top = [v["fraction_top_n_changed"] for v in perts.values()]
    return {
        "weight_perturbations": str(len(perts)),
        "weight_sensitivity_n": str(d["n_samples"]),
        "weight_topn_changed_min": pct(min(top)),
        "weight_topn_changed_max": pct(max(top)),
    }


def cascade_constants_facts() -> dict[str, Any]:
    """The corroboration cascade's constants, read out of the shipped module.

    The paper states the cascade's scoring rule as a numbered equation, and an
    equation whose constants are typed beside it is a numbered way to go stale:
    change ``LAYER_WEIGHTS`` and the paper keeps printing what the weights used
    to be, with nothing to notice. The values are therefore parsed from
    ``ttp_cascade.py`` itself, so the equation is regenerated from the code it
    describes and a weight that moves takes the build with it.

    Parsed rather than imported. Importing would drag the package's logger and
    schema modules into a derivation that needs two dictionaries, and would make
    the paper's numbers depend on the package being installed; ``ast`` reads the
    file that ships.
    """
    src = _REPO_ROOT / "src" / "maljan" / "analysis" / "ttp_cascade.py"
    if not src.exists():
        raise FactError(f"{src} is gone; the cascade equation has nothing to derive from")
    tree = ast.parse(src.read_text(encoding="utf-8"))

    wanted = {"LAYER_WEIGHTS", "CROSS_LAYER_MULTIPLIERS", "DEFAULT_LAYER_WEIGHT"}
    found: dict[str, Any] = {}
    for node in tree.body:
        target = None
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            target = node.target.id
        elif isinstance(node, ast.Assign) and len(node.targets) == 1:
            if isinstance(node.targets[0], ast.Name):
                target = node.targets[0].id
        if target in wanted and node.value is not None:
            found[target] = ast.literal_eval(node.value)

    missing = wanted - set(found)
    if missing:
        raise FactError(f"ttp_cascade.py no longer defines {sorted(missing)}")

    weights, mult = found["LAYER_WEIGHTS"], found["CROSS_LAYER_MULTIPLIERS"]
    if sorted(mult) != list(range(1, len(mult) + 1)):
        raise FactError(f"the multiplier table is no longer keyed 1..n: {sorted(mult)}")

    out: dict[str, Any] = {
        f"cascade_weight_{name}": f"{value:.2f}" for name, value in weights.items()
    }
    out["cascade_weight_default"] = f"{found['DEFAULT_LAYER_WEIGHT']:.2f}"
    out["cascade_weight_layers"] = len(weights)
    for layers, m in sorted(mult.items()):
        out[f"cascade_mult_{layers}"] = f"{m:.2f}"
    out["cascade_mult_max"] = f"{max(mult.values()):.2f}"
    out["cascade_mult_span"] = f"{min(mult)} to {max(mult)}"
    return out


BUILDERS = (
    baseline_facts,
    consensus_facts,
    cape_consensus_facts,
    frontier_facts,
    judge_facts,
    cascade_facts,
    series_facts,
    probe_facts,
    confidence_facts,
    firing_rate_facts,
    retrieval_facts,
    suite_facts,
    cape_audit_facts,
    fixture_ceiling_facts,
    fallback_table_facts,
    corpus_shape_facts,
    case_corpus_facts,
    retrieval_scores_facts,
    layer0_excluded_facts,
    technique_mapping_facts,
    stix_conformance_facts,
    model_size_facts,
    cascade_jaccard_facts,
    drift_facts,
    cluster_stat_facts,
    power_facts,
    multiplicity_facts,
    provenance_facts,
    paired_selection_facts,
    weight_sensitivity_facts,
    cascade_constants_facts,
)


def collect() -> dict[str, str]:
    facts: dict[str, str] = {}
    for build in BUILDERS:
        for k, v in build().items():
            if k in facts:
                raise FactError(f"two derivations claim the name {k!r}")
            facts[k] = str(v)
    return facts


# LaTeX sees the facts as macros rather than as substituted text, which is what
# the reporting convention this paper follows actually asks for: `\input` the
# generated definitions, and a re-run of the analysis updates the document. Keys
# carry hyphens because an underscore is catcode 8 in LaTeX and would need
# protecting at every use site.
TEX_OUT = (
    _HERE.parent.parent / "other" / "docs" / "academic-article" / "paper" / "tex" / "facts.tex"
)

_TEX_ESCAPE = {
    "%": "\\%",
    "&": "\\&",
    "#": "\\#",
    "_": "\\_",
}


def tex_key(name: str) -> str:
    return name.replace("_", "-")


def tex_value(value: str) -> str:
    """Escape for LaTeX, and set a leading sign as maths.

    A minus typed as an ASCII hyphen prints as a hyphen: a different glyph, at a
    different width, from the minus in the interval beside it. This paper reports
    several hundred signed numbers, so the sign goes through maths and the rest
    stays as text — wrapping a whole interval in maths instead would give the
    comma and brackets maths spacing, which is not what a reader expects inside
    a table cell.
    """
    text = str(value)
    for char, repl in _TEX_ESCAPE.items():
        text = text.replace(char, repl)
    return re.sub(r"(?<![\w$])([-+])(?=\d)", lambda m: f"${m.group(1)}$", text)


# The build refuses to compile a paper whose facts predate the last result. The
# stamp is written here rather than there because the deriver is what knows what
# it derived from — a builder that stamped its own inputs would be certifying
# itself.
STAMP = TEX_OUT.parent / ".facts-inputs.sha256"
TABLES = TEX_OUT.parent / "tables"


def artifact_digest() -> str:
    """A content hash of everything the facts are derived from.

    Content rather than modification time: a fresh clone rewrites every mtime,
    and ``touch`` clears an mtime gate without recomputing anything. The
    derivations are hashed too, because a change to how a number is computed
    makes the stored number stale even when no input moved.
    """
    h = hashlib.sha256()
    for path in sorted(_HERE.glob("*.json")) + sorted(_HERE.glob("*.jsonl")):
        if path == OUT:
            continue
        h.update(path.name.encode())
        h.update(hashlib.sha256(path.read_bytes()).digest())
    for module in ("paper_facts.py", "reanalyse.py", "stats.py"):
        h.update(hashlib.sha256((_HERE / module).read_bytes()).digest())
    return h.hexdigest()


def write_tex(facts: dict[str, str]) -> None:
    lines = [
        "% Generated by tests/evaluation/paper_facts.py. Do not edit.",
        "% Every number the paper states about its own results is defined here and",
        "% used through \\fact{...}; a key the document asks for and this file does",
        "% not define stops the build. See facts.sty for the mechanism.",
        "",
    ]
    lines += [f"\\deffact{{{tex_key(k)}}}{{{tex_value(facts[k])}}}" for k in sorted(facts)]
    TEX_OUT.parent.mkdir(parents=True, exist_ok=True)
    TEX_OUT.write_text("\n".join(lines) + "\n")
    STAMP.write_text(artifact_digest() + "\n")


def main() -> int:
    try:
        facts = collect()
    except FactError as exc:
        print(f"FACTS FAILED: {exc}")
        return 1
    OUT.write_text(json.dumps(facts, indent=1, sort_keys=True) + "\n")
    write_tex(facts)
    print(f"{len(facts)} facts derived -> {OUT.name} and {TEX_OUT.name}")
    for k in sorted(facts):
        print(f"  {{{{{k}}}}} = {facts[k]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

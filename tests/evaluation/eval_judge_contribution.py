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


def as_dicts(objects: list[Any]) -> list[dict[str, Any]]:
    """STIX objects as plain dicts, whichever side of validation they came from.

    ``_reconcile_with_cascade`` sees dicts, because it runs inside
    ``postprocess_judge_bundle`` before the bundle is validated. The fallback
    path does not: ``_fallback_bundle_from_text`` ends in
    ``Bundle.model_validate(...)`` and ``Bundle.objects`` is typed as a union of
    pydantic models, so every object arrives as a model instance.

    ``_pattern_ids`` skips anything that is not a dict, so reading the fallback
    bundle without this returned **zero attack-patterns for every fallback,
    structurally** — a number that looks like a finding about the bundle and is
    really a fact about the type check. Caught on 2026-08-14 by reading the
    production fallback builder, which visibly copies technique ids out of the
    ISR claims: a bundle that provably contains patterns cannot report none.
    """
    out: list[dict[str, Any]] = []
    for obj in objects or []:
        if isinstance(obj, dict):
            out.append(obj)
        elif hasattr(obj, "model_dump"):
            try:
                out.append(obj.model_dump(mode="json", exclude_none=True))
            except Exception:  # noqa: BLE001 — an unserialisable object is not a pattern
                continue
    return out


def _fallback_reason(raw: str) -> str:
    """Name the branch of ``give_verdict`` that routed this call to the fallback.

    The four early returns are distinguishable from the text they were handed,
    which is why this reads ``raw`` rather than a stack: ``"[TIMEOUT]"`` is a
    literal the timeout branch passes in, and the two JSON branches are decided
    by re-running the same parser on the same string. Anything that parses to a
    dict and still arrived here got past both JSON gates, so the only remaining
    path is the one where post-processing or Bundle validation raised.
    """
    if raw == "[TIMEOUT]":
        return "verdict_timed_out"
    try:
        from maljan.utils.json_cleaner import safe_parse_json

        data = safe_parse_json(raw)
    except Exception:  # noqa: BLE001 — the parser's own failure is still data
        return "json_parser_raised"
    if data is None:
        return "no_json_in_response"
    if not isinstance(data, dict):
        return "json_not_an_object"
    return "postprocess_or_validation_raised"


def install_spy(captured: list[dict[str, Any]]) -> Any:
    """Record what crosses the judge/cascade seam, then delegate untouched.

    Patching the module attribute works because ``postprocess_judge_bundle``
    resolves the name from module globals at call time. The real function still
    runs, so the pipeline behaves exactly as in production — this observes, it
    does not substitute.

    **Two seams, not one.** The first run of this harness recorded five of nine
    calls as the error ``"reconcile never ran"`` and they were read as machine
    trouble. They are not. ``give_verdict`` has four early returns —
    ``judge_agent.py`` at the timeout branch, the two JSON gates, and the
    post-processing ``except`` — and every one of them returns
    ``_fallback_bundle_from_text`` **without calling ``postprocess_judge_bundle``
    at all**. On those calls ``_reconcile_with_cascade`` genuinely never runs, so
    the cascade's technique set is never injected and the bundle is built by a
    different construction path entirely.

    That matters beyond this harness. §3.27.1's finding — the bundle's technique
    set equals the cascade's exactly — was measured on calls that reached
    reconciliation. It says nothing about calls that never got there. So the
    fallback is instrumented as a *second outcome* rather than an absence: which
    branch fired, and how much text the model had produced when it did.
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
                "path": "reconciled",
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

    from maljan.agents.judge_agent import JudgeAgent

    original_fallback = JudgeAgent._fallback_bundle_from_text

    def fallback_spy(self: Any, raw: str, *args: Any, **kwargs: Any) -> Any:
        bundle = original_fallback(self, raw, *args, **kwargs)
        objects = as_dicts(list(getattr(bundle, "objects", []) or []))
        total, resolvable = _pattern_ids(objects)
        captured.append(
            {
                "path": "fallback",
                "fallback_reason": _fallback_reason(raw),
                "response_chars": 0 if raw == "[TIMEOUT]" else len(raw),
                "fallback_patterns_emitted": total,
                "fallback_patterns_resolvable": len(set(resolvable)),
                "final_bundle_size": len(set(resolvable)),
                # Where those techniques came from matters more than how many
                # there are. The fallback builder copies ids out of the ISR
                # claims, so a non-empty bundle here is Layer-0 evidence reaching
                # the analyst *without* the cascade's ranking ever being applied.
                "fallback_technique_ids": sorted(set(resolvable)),
            }
        )
        return bundle

    JudgeAgent._fallback_bundle_from_text = fallback_spy
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


def fallback_breakdown(rows: list[dict[str, Any]]) -> dict[str, int]:
    """Count the fallback rows by the branch that produced them."""
    out: dict[str, int] = {}
    for r in rows:
        if r.get("path") == "fallback":
            reason = str(r.get("fallback_reason") or "unknown")
            out[reason] = out.get(reason, 0) + 1
    return out


def reachability_lines(
    n_reconciled: int, fell_back: list[dict[str, Any]], errored: int
) -> list[str]:
    """Report how often the judge's output reached reconciliation at all.

    Written as its own section because it answers a different question from the
    rest of the harness. Everything else here measures what the judge contributed
    *given* that its output reached the seam; this measures how often it did.
    """
    total = n_reconciled + len(fell_back) + errored
    if not total:
        return []
    lines = [
        "",
        "## Did the judge's output reach the cascade seam at all?",
        "",
        "`give_verdict` returns `_fallback_bundle_from_text` from four places — the verdict",
        "timeout, both JSON gates, and the post-processing `except`. None of them call",
        "`postprocess_judge_bundle`, so on those calls `_reconcile_with_cascade` never runs and",
        "the cascade's technique set is **never injected**. This is not the same failure as a bad",
        "verdict: it is a different bundle-construction path, and §3.27.1's equality was measured",
        "only on the calls that avoided it.",
        "",
        f"| reached reconciliation | {n_reconciled}/{total} |",
        "|---|---|",
        f"| fell back before reconciliation | **{len(fell_back)}/{total}** |",
    ]
    if errored:
        lines.append(f"| raised before returning a bundle | {errored}/{total} |")
    breakdown = fallback_breakdown(fell_back)
    if breakdown:
        lines += ["", "| fallback branch | calls |", "|---|---|"]
        for reason, count in sorted(breakdown.items(), key=lambda kv: -kv[1]):
            lines.append(f"| `{reason}` | {count} |")
    if fell_back:
        share = len(fell_back) / total
        lines += [
            "",
            f"**{share:.0%} of judge calls never reached the reconciliation step.** On those the",
            "cascade contributed nothing to the bundle, because the code that injects it was not",
            "the path taken. Any claim about what the bundle contains has to say which path it is",
            "about.",
        ]
    return lines


def summarise(rows: list[dict[str, Any]]) -> tuple[str, dict[str, Any]]:
    # A row that reached the seam carries ``cascade_size``; the legacy rows from
    # the first run predate the ``path`` key and are recognised the same way.
    scored = [
        r
        for r in rows
        if "error" not in r and r.get("path") != "fallback" and r.get("cascade_size") is not None
    ]
    fell_back = [r for r in rows if r.get("path") == "fallback"]
    errored = sum(1 for r in rows if "error" in r)
    if not scored:
        # Every call taking the fallback path is not an empty result — it is the
        # strongest possible version of this study's finding, so it is reported.
        lines = ["# C3 — what the judge contributes to the bundle", ""]
        lines += ["No call reached the reconciliation seam.", ""]
        lines += reachability_lines(0, fell_back, errored)
        return "\n".join(lines), {
            "schema": "judge-contribution/v1",
            "status": "no-call-reached-reconciliation",
            "n_calls": 0,
            "calls_fell_back": len(fell_back),
            "fallback_reasons": fallback_breakdown(fell_back),
            "failed_calls": errored,
            "per_call": rows,
        }

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

    lines += reachability_lines(n, fell_back, errored)

    blob = {
        "schema": "judge-contribution/v2",
        "status": "complete",
        "n_calls": n,
        # A fallback is an outcome, not a failure, and counting it as one was how
        # the first run came to describe five recorded measurements as errors.
        "calls_fell_back": len(fell_back),
        "fallback_reasons": fallback_breakdown(fell_back),
        "failed_calls": errored,
        "totals": tot,
        "judge_ids_outside_cascade_total": own,
        "calls_with_a_judge_contribution": calls_with_own,
        "calls_with_nothing_nameable": calls_with_nothing_nameable,
        "judge_share_of_final_bundle": round(own_share, 4),
        "unresolvable_share_of_judge_patterns": round(unresolvable_share, 4),
        "per_call": scored,
        "per_call_fallback": fell_back,
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
    # 900 s, not the 300 s the ablation harnesses use, and the difference is the
    # measurement rather than a convenience.
    #
    # ``give_verdict`` wraps its call in ``asyncio.wait_for`` at the judge's own
    # configured ceiling — ``react_agent_timeout_overrides["judge"] = 600`` — while
    # the provider builds its HTTP client at 1800 s, so in production the judge
    # gets **one contiguous 600 s attempt**. Binding 300 s here made the request
    # die at 300 s, hand a connection error to ``retry_on_connection_error``, and
    # start a second attempt that the outer 600 s then killed at 23:42:50 on
    # 2026-08-14. The model never received a contiguous 600 s window.
    #
    # That matters because this study reports how often the judge leaves the
    # reconciliation path. A per-request cap tighter than production's would
    # *manufacture* the timeouts being counted. Binding above the outer ceiling
    # makes ``wait_for`` the operative limit, exactly as it is in production; the
    # bound value still exists so a stalled socket cannot run unbounded (§ the
    # 14-minute call that ignored a "180 s cap" — ``bind_eval_llm``).
    bind_eval_llm(judge, timeout_s=900)
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
                # With both seams instrumented there is no longer a silent third
                # path: a call that returns a bundle has crossed one of them. If
                # this fires, the pipeline changed and the harness is blind again.
                row = {
                    "key": key,
                    "sample_id": sid,
                    "error": "neither reconcile nor fallback was reached — spy is blind",
                }
            else:
                row = {"key": key, "sample_id": sid, **new[-1]}
        with CHECKPOINT.open("a") as fh:
            fh.write(json.dumps(row) + "\n")
        rows.append(row)
        if "error" in row:
            print(f"  {sid}: {row['error']}", flush=True)
        elif row.get("path") == "fallback":
            print(
                f"  {sid}: FELL BACK ({row['fallback_reason']}) after "
                f"{row['response_chars']} chars — reconciliation never ran, "
                f"{row['fallback_patterns_resolvable']} nameable technique(s) in the bundle",
                flush=True,
            )
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

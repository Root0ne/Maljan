"""B8: does the frontier arm work, and what does an equal token budget buy it?

A cheap sanity check before the n=100 cohort run (C6): the plumbing answers, the
output parses into technique IDs, the spend ceiling is wired, and — the part
that turned out to matter — how much of the arm's output budget goes to
*reasoning* rather than to the answer.

That last question is not incidental. §3.7 compares arms at an **equal token
budget**, and the frontier candidate is a reasoning model whose usage metadata
reports `output_token_details.reasoning` separately from content. A one-token
answer ("T1055") measured **92 output tokens, 77 of them reasoning — 84%**. If
the budget were applied to content alone, the frontier arm would receive several
times the actual generation for the same nominal cap, and the comparison C6 is
built to make would be void before it starts.

So this probe measures the reasoning fraction on the **real evaluation prompts**
rather than a one-liner, because a short question is exactly the case where a
reasoning model looks worst and the number cannot be assumed to carry.

Uses the same five fixtures and the same `single`-arm prompt as the consensus
ablation, so the two are directly comparable. Costs nothing on a `:free`
endpoint; the meter still counts tokens, because the paper reports cost in
tokens regardless of what the invoice says.

**2026-08-14 — one arm became a series.** A second provider put two more models
within reach on the author's own account, so this now runs any configured arm by
name and the four of them span a 21x range in declared parameters:

    Qwen3.6-35B-A3B (local)       35B total / 3B active
    Nemotron-3-Super-120B-A12B   120B / 12B
    MiniMax-M3                   428B / 22B
    GLM-5.2                      744B / 40B

That changes what the experiment can say. One comparison model can only agree or
disagree with `arXiv:2606.18166`'s parameter-size prior on a single point; four
can test the trend on this task. The sizes are read from configuration rather
than written into the prose, so the correlation and the data cannot drift apart.

**Throttling is handled, not counted as failure.** Measured on NVIDIA NIM the
same day: two calls four seconds apart succeed and the next six return HTTP 429.
B8's first attempt treated 429s as failed calls and reported n=9 with a point
estimate the completed run later moved by 0.086. Calls now go through
``PacedCaller``, and the retries are reported rather than hidden.

Run:  .venv/bin/python tests/evaluation/eval_frontier_probe.py --arm glm --repeats 5
      .venv/bin/python tests/evaluation/eval_frontier_probe.py --list
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
if str(_REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "src"))

from tests.evaluation.eval_consensus_ablation import (  # noqa: E402
    SINGLE_PROMPT,
    bootstrap_ci,
    build_channels,
    extract_tids,
    load_samples,
    prf,
    render_all_channels,
)

BUDGET = 2400  # the same total output budget the `single` arm gets in §3.7


def out_path(arm: str) -> Path:
    """Where an arm's record goes.

    ``default`` keeps the original filename. B8's result is already cited by the
    figure script and by §3.16, and renaming a stored measurement to tidy up a
    naming scheme is how a record and the text that cites it come apart.
    """
    return _HERE / ("frontier_probe.json" if arm == "default" else f"frontier_probe_{arm}.json")


def checkpoint_path(arm: str) -> Path:
    return Path(f"/tmp/frontier_probe_{arm}_checkpoint.jsonl")


def main() -> int:
    from maljan.core.config import get_settings
    from maljan.core.frontier import (
        PacedCaller,
        arm_provenance,
        build_frontier_llm,
        build_meter,
        resolve_arms,
    )

    ap = argparse.ArgumentParser(description="Frontier comparison arm on the §3.7 fixtures.")
    ap.add_argument("--arm", default="default", help="Configured arm name (see --list).")
    ap.add_argument("--repeats", type=int, default=1)
    ap.add_argument("--list", action="store_true", help="Show configured arms and exit.")
    args = ap.parse_args()

    arms = resolve_arms(get_settings().llm.frontier)
    if args.list:
        if not arms:
            print("no frontier arms are configured and ready")
            return 1
        for name, a in arms.items():
            p = arm_provenance(name, a)
            print(
                f"  {name:10s} {p['model']:40s} "
                f"{p['total_params_b']:6.0f}B total / {p['active_params_b']:5.0f}B active"
            )
        return 0
    if args.arm not in arms:
        print(f"arm {args.arm!r} is not configured or not ready; have: {sorted(arms) or 'none'}")
        return 1

    cfg = arms[args.arm]
    provenance = arm_provenance(args.arm, cfg)
    llm = build_frontier_llm(cfg, max_tokens=BUDGET)
    meter = build_meter(cfg)
    caller = PacedCaller.for_arm(cfg)
    samples = load_samples()
    print(
        f"arm={args.arm}  model={cfg.model}  budget={BUDGET} output tokens/call  "
        f"fixtures={len(samples)}  pacing={caller.min_interval_s}s"
    )

    repeats = args.repeats
    print(f"repeats={repeats}  (the local `single` arm in §3.7 is n=25: 5 fixtures x 5)")

    # Resume: a throttle storm can stretch 25 calls across a long wall-clock, and
    # losing completed calls to an interruption is how a series loses a point.
    #
    # **Only a scored call counts as done.** An errored row is kept in the
    # checkpoint as a record but is retried on the next run, because the errors
    # this arm actually produces are transient: a 429 that outlasts PacedCaller's
    # six backoffs is the endpoint being busy, not the call being impossible.
    # Treating it as permanent would turn one bad hour into 25 holes that no
    # later run could ever fill — and a partially scored arm still enters the
    # series, so those holes would silently become the measurement. (This is the
    # same defect the C4 harness had on 2026-08-12, reintroduced here and caught
    # before it ran; "error rows counted as done" is evidently a mistake worth
    # testing for rather than remembering.)
    ckpt = checkpoint_path(args.arm)
    latest: dict[str, dict[str, Any]] = {}
    if ckpt.exists():
        for line in ckpt.read_text().splitlines():
            try:
                prior = json.loads(line)
            except Exception:  # noqa: BLE001
                continue
            key = f"{prior.get('sample_id')}:{prior.get('repeat')}"
            # A later scored row supersedes an earlier error; an error never
            # supersedes a score.
            if key in latest and "error" in prior and "error" not in latest[key]:
                continue
            latest[key] = prior
    rows: list[dict[str, Any]] = list(latest.values())
    done = {k for k, r in latest.items() if "error" not in r}
    if latest:
        print(f"resume: {len(done)} scored, {len(latest) - len(done)} errored (will retry)")

    for rep in range(repeats):
        for sample_id, truth in samples:
            if f"{sample_id}:{rep}" in done:
                continue
            channels = build_channels(truth)
            prompt = f"{SINGLE_PROMPT}\n\n{render_all_channels(channels)}"
            t0 = time.time()
            try:
                # Paced: throttles are waited out, everything else is a result.
                resp = caller.invoke(llm.invoke, prompt)
            except Exception as e:  # noqa: BLE001 — a failed call is a result too
                print(f"  {sample_id:22s} FAILED {type(e).__name__}: {e}")
                row = {
                    "sample_id": sample_id,
                    "repeat": rep,
                    "error": f"{type(e).__name__}: {e}"[:300],
                }
                rows.append(row)
                with ckpt.open("a") as fh:
                    fh.write(json.dumps(row) + "\n")
                continue
            dt = time.time() - t0
            text = str(resp.content)
            usage = getattr(resp, "usage_metadata", None) or {}
            details = usage.get("output_token_details") or {}
            out_tokens = int(usage.get("output_tokens") or 0)
            reasoning = int(details.get("reasoning") or 0)
            predicted = extract_tids(text)
            p, r, f1 = prf(predicted, truth)
            finish = (getattr(resp, "response_metadata", None) or {}).get("finish_reason")
            row = {
                "sample_id": sample_id,
                "repeat": rep,
                "seconds": round(dt, 1),
                "input_tokens": int(usage.get("input_tokens") or 0),
                "output_tokens": out_tokens,
                "reasoning_tokens": reasoning,
                "content_tokens": max(0, out_tokens - reasoning),
                "reasoning_fraction": round(reasoning / out_tokens, 3) if out_tokens else None,
                "finish_reason": finish,
                "hit_cap": finish in {"length", "max_tokens"},
                "n_predicted": len(predicted),
                "predicted": predicted,
                "truth": truth,
                "precision": round(p, 4),
                "recall": round(r, 4),
                "f1": round(f1, 4),
                "parsed": bool(predicted),
            }
            rows.append(row)
            with ckpt.open("a") as fh:
                fh.write(json.dumps(row) + "\n")
            meter.charge(int(usage.get("input_tokens") or 0), out_tokens)
            print(
                f"  {sample_id:22s} {dt:5.1f}s  out={out_tokens:5d} "
                f"(reasoning {reasoning:5d} = {reasoning / out_tokens:5.1%})  "
                f"tids={len(predicted):2d}  F1={f1:.3f}  finish={finish}"
            )

    scored = [r for r in rows if "error" not in r]
    if not scored:
        print("no successful calls")
        return 1

    frac = [r["reasoning_fraction"] for r in scored if r["reasoning_fraction"] is not None]
    f1s = [r["f1"] for r in scored]
    # Same estimator as the consensus ablation, so the two intervals mean the
    # same thing when the arms are put side by side.
    lo, hi = bootstrap_ci(f1s)
    summary = {
        "n": len(scored),
        "failed": len(rows) - len(scored),
        "parsed": sum(1 for r in scored if r["parsed"]),
        "hit_cap": sum(1 for r in scored if r["hit_cap"]),
        "mean_f1": round(sum(f1s) / len(f1s), 4),
        "f1_ci95": [round(lo, 4), round(hi, 4)],
        "mean_reasoning_fraction": round(sum(frac) / len(frac), 3) if frac else None,
        "meter": meter.snapshot(),
        # What the run cost in waiting. A series whose arms needed wildly
        # different numbers of retries took wildly different wall-clock, and that
        # is worth seeing next to the scores rather than inferring from them.
        "pacing": caller.snapshot(),
    }
    print("\nRESULT")
    print(f"  parsed {summary['parsed']}/{summary['n']}   hit the cap {summary['hit_cap']}")
    print(f"  mean F1 {summary['mean_f1']}  95% CI {summary['f1_ci95']}")
    print(f"  mean reasoning fraction of output {summary['mean_reasoning_fraction']}")
    print(f"  meter {summary['meter']}")

    out = out_path(args.arm)
    out.write_text(
        json.dumps(
            {
                "schema": "maljan-frontier-probe/v2",
                "model": cfg.model,
                "arm": provenance,
                "budget_output_tokens": BUDGET,
                "summary": summary,
                "per_sample": rows,
            },
            indent=1,
        )
    )
    print(f"wrote {out.relative_to(_REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

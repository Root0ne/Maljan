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
"""

from __future__ import annotations

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

OUT = _HERE / "frontier_probe.json"
BUDGET = 2400  # the same total output budget the `single` arm gets in §3.7


def main() -> int:
    from maljan.core.config import get_settings
    from maljan.core.frontier import build_frontier_llm, build_meter, frontier_ready

    cfg = get_settings().llm.frontier
    ready, why = frontier_ready(cfg)
    if not ready:
        print(f"frontier arm not configured: {why}")
        return 1

    llm = build_frontier_llm(cfg, max_tokens=BUDGET)
    meter = build_meter(cfg)
    samples = load_samples()
    print(f"model={cfg.model}  budget={BUDGET} output tokens/call  fixtures={len(samples)}")

    repeats = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    print(f"repeats={repeats}  (the local `single` arm in §3.7 is n=25: 5 fixtures x 5)")

    rows: list[dict[str, Any]] = []
    for rep in range(repeats):
        for sample_id, truth in samples:
            channels = build_channels(truth)
            prompt = f"{SINGLE_PROMPT}\n\n{render_all_channels(channels)}"
            t0 = time.time()
            try:
                resp = llm.invoke(prompt)
            except Exception as e:  # noqa: BLE001 — a failed call is a result too
                print(f"  {sample_id:22s} FAILED {type(e).__name__}: {e}")
                rows.append({"sample_id": sample_id, "error": f"{type(e).__name__}: {e}"})
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
            rows.append(
                {
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
            )
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
    }
    print("\nRESULT")
    print(f"  parsed {summary['parsed']}/{summary['n']}   hit the cap {summary['hit_cap']}")
    print(f"  mean F1 {summary['mean_f1']}  95% CI {summary['f1_ci95']}")
    print(f"  mean reasoning fraction of output {summary['mean_reasoning_fraction']}")
    print(f"  meter {summary['meter']}")

    OUT.write_text(
        json.dumps(
            {
                "schema": "maljan-frontier-probe/v1",
                "model": cfg.model,
                "budget_output_tokens": BUDGET,
                "summary": summary,
                "per_sample": rows,
            },
            indent=1,
        )
    )
    print(f"wrote {OUT.relative_to(_REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

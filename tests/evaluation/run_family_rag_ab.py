"""Small LLM-in-the-loop A/B for the family-feature + ATT&CK-case RAGs (findings-log §4).

The leakage-free *retrieval* eval (eval_family_rag_retrieval.py) showed the RAG carries
real-but-modest signal (~6.3x chance, recall@5 ~0.20). The open question it cannot answer:
does feeding those advisory candidates to the static analyst actually improve the LLM's
final TTP output? This harness answers that with a controlled A/B on a small, balanced,
leakage-free subset.

Design:
  * Test set: tests/evaluation/ab_manifest.json (n=210 samples whose family is BOTH in the
    MABEL catalog AND has an ATT&CK ground-truth fixture -> the RAG can surface the right
    candidate AND we can score TTPs).
  * Catalogs: MABEL (data/family_fingerprints_mabel_v1.json + data/attck_case_corpus_v1.json)
    -- disjoint from the n=210 SAMPLES, so leakage-free, yet the families are represented.
  * Two runs of eval_temporal_drift over the SAME subset, as separate subprocesses (so the
    cached get_settings() re-reads the toggled env each time):
        OFF: both RAG flags false.
        ON : both RAG flags true, catalog paths pointed at the MABEL artifacts.
  * Metric: aggregate technique-level precision / recall / F1 / hallucination delta.

Prerequisites (operator): llama-server up (LLM) + Ghidra MCP up (decompilation);
SANDBOX__BACKEND=mock recommended (static-only A/B, no live-malware upload). Cost ~= 2 x
N x per-sample pipeline time.

Run:
    uv run python tests/evaluation/run_family_rag_ab.py
"""

# ruff: noqa: E402

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parents[1]
_EVAL = _HERE / "eval_temporal_drift.py"
_MANIFEST = _HERE / "ab_manifest.json"
_OFF_CKPT = _HERE / "ab_off.jsonl"
_ON_CKPT = _HERE / "ab_on.jsonl"
_OUT = _HERE / "family_rag_ab.json"

_MABEL_CATALOG = "data/family_fingerprints_mabel_v1.json"
_MABEL_CORPUS = "data/attck_case_corpus_v1.json"


def _run_condition(checkpoint: Path, rag_on: bool) -> int:
    """Run eval_temporal_drift over the A/B manifest with the RAGs on or off."""
    env = dict(os.environ)
    flag = "true" if rag_on else "false"
    env["PREPROCESSING__USE_FAMILY_FEATURE_RAG"] = flag
    env["PREPROCESSING__USE_ATTCK_CASE_RAG"] = flag
    # This is a STATIC-feature A/B (both RAGs feed the static analyst). Force the
    # mock sandbox so the dynamic analyst never detonates/uploads these live
    # malware samples to a public sandbox service — and so the only variable
    # between OFF and ON is the RAG evidence, not sandbox nondeterminism.
    env["SANDBOX__BACKEND"] = "mock"
    # Cap the negotiation to a single round. With the mock sandbox the dynamic /
    # network analysts run on empty inputs, so they routinely register dissent;
    # the judge then enters its ReAct verdict loop, which the local 35B model
    # cannot converge within the 180s budget and times out EVERY round — driving
    # every sample to the default max_iterations=5 ceiling (~90 min/sample, ~50h
    # total) with a timeout-degraded verdict. The signal this A/B measures — the
    # static analyst's RAG-influenced TTP claims — is fully produced in round 1
    # (both RAG hints inject into the round-1 static prompt; the judge-node ATT&CK
    # correction runs regardless of round count). Capping to 1 round removes the
    # judge-timeout runaway, and the SAME cap on both arms keeps the OFF-vs-ON
    # delta valid. Override with NEGOTIATION__MAX_ITERATIONS in the environment.
    env.setdefault("NEGOTIATION__MAX_ITERATIONS", "1")
    if rag_on:
        env["PREPROCESSING__FAMILY_FINGERPRINT_CATALOG_PATH"] = _MABEL_CATALOG
        env["PREPROCESSING__ATTCK_CASE_CORPUS_PATH"] = _MABEL_CORPUS
    cmd = [
        sys.executable,
        str(_EVAL),
        "--manifest",
        str(_MANIFEST),
        "--checkpoint",
        str(checkpoint),
    ]
    print(
        f"\n=== A/B condition: RAG {'ON' if rag_on else 'OFF'} -> {checkpoint.name} ===", flush=True
    )
    return subprocess.run(cmd, env=env, cwd=str(_REPO_ROOT)).returncode


def _aggregate(checkpoint: Path) -> dict:
    """Mean technique-level metrics over a checkpoint JSONL."""
    rows = []
    if checkpoint.exists():
        for line in checkpoint.read_text(encoding="utf-8").splitlines():
            if line.strip():
                rows.append(json.loads(line))
    n = len(rows) or 1

    def _mean(key: str) -> float:
        return round(sum(float(r.get(key, 0) or 0) for r in rows) / n, 4)

    return {
        "samples": len(rows),
        "precision": _mean("precision"),
        "recall": _mean("recall"),
        "f1": _mean("f1"),
        "hallucination_rate": _mean("hallucination_rate"),
    }


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Family-RAG + ATT&CK-case-RAG LLM-in-the-loop A/B.")
    ap.add_argument(
        "--fresh",
        action="store_true",
        help="Wipe both checkpoints and start over. Default is RESUME: keep existing "
        "ab_off.jsonl / ab_on.jsonl rows; eval_temporal_drift skips already-scored samples. "
        "Each condition's checkpoint only ever holds that condition's rows, so resuming "
        "cannot mix OFF and ON.",
    )
    args = ap.parse_args()

    if not _MANIFEST.exists():
        print(f"ERROR: A/B manifest not found: {_MANIFEST}", file=sys.stderr)
        return 2

    def _rows(p: Path) -> int:
        if not p.exists():
            return 0
        return sum(1 for ln in p.read_text("utf-8").splitlines() if ln.strip())

    if args.fresh:
        for c in (_OFF_CKPT, _ON_CKPT):
            c.unlink(missing_ok=True)
    else:
        off_n, on_n = _rows(_OFF_CKPT), _rows(_ON_CKPT)
        if off_n or on_n:
            print(f"RESUME: OFF {off_n}/19, ON {on_n}/19 already scored (pass --fresh to restart).")

    if _run_condition(_OFF_CKPT, rag_on=False) != 0:
        print("ERROR: OFF condition failed (LLM/Ghidra up?).", file=sys.stderr)
        return 1
    if _run_condition(_ON_CKPT, rag_on=True) != 0:
        print("ERROR: ON condition failed.", file=sys.stderr)
        return 1

    off, on = _aggregate(_OFF_CKPT), _aggregate(_ON_CKPT)
    delta = {
        k: round(on[k] - off[k], 4) for k in ("precision", "recall", "f1", "hallucination_rate")
    }
    result = {
        "schema": "maljan-family-rag-ab/v1",
        "catalogs": {"family": _MABEL_CATALOG, "attck_case": _MABEL_CORPUS},
        "leakage_free": "MABEL disjoint from n=210 samples; families present",
        "off": off,
        "on": on,
        "delta_on_minus_off": delta,
    }
    _OUT.write_text(json.dumps(result, indent=2), encoding="utf-8")

    print("\n=== Family-RAG + ATT&CK-case-RAG A/B (TTP-level) ===")
    print(f"OFF: {off}")
    print(f"ON : {on}")
    print(f"delta (ON-OFF): {delta}")
    print(f"Wrote {_OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

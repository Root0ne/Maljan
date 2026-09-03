"""Leakage-free retrieval evaluation for the family-feature RAG (findings-log §4 U3).

The vendored family catalogs were either built FROM the eval set (the n=210 bootstrap →
leakage) or only verified anecdotally. This script measures the RAG's *retrieval* quality
on a held-out split with NO leakage, using the Ultimate-RAT-Collection extraction tree:

    data/samples/extracted/<Family>/a0/...   -> TRAIN  (build the family fingerprint)
    data/samples/extracted/<Family>/a1/...   -> TEST   (query profiles)

a0 and a1 are *different source archives* (versions) of the same family, so a test
sample was never used to build the catalog — yet its family IS represented (by a0). This
is exactly the production scenario: attribute a NEW sample of a known family. We report
recall@k and MRR against a random-chance baseline. It measures the retrieval layer only
(the LLM still decides on top of the candidates); a full LLM A/B is out of scope here.

This is an OFFLINE eval script — never imported by the pipeline. It reuses the runtime
feature extractor + profile renderer + index so train and test share one embedding space.

Run:
    uv run python tests/evaluation/eval_family_rag_retrieval.py \
        --extracted-dir data/samples/extracted --top-k 5 \
        --out tests/evaluation/family_rag_retrieval.json
"""

# ruff: noqa: E402

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
for _p in (_REPO_ROOT, _REPO_ROOT / "src"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from maljan.analysis.family_feature_rag import (
    build_family_fingerprint_text,
    build_sample_profile_text,
)
from maljan.extractors.pe_extractor import build_static_analysis
from maljan.memory.family_fingerprint_index import FamilyFingerprintIndex
from tests.evaluation._tally import Tally


def _profiles_from_dir(dir_path: Path, cap: int, tally: Tally) -> list[str]:
    """Static-feature profiles for up to ``cap`` parseable PEs under ``dir_path``."""
    out: list[str] = []
    for f in sorted(dir_path.rglob("*")):
        if len(out) >= cap:
            break
        if not f.is_file():
            continue
        tally.attempt()
        try:
            static = build_static_analysis(sample_path=str(f))
        except Exception as exc:  # noqa: BLE001 - skip unparseable members (NE/16-bit/non-PE)
            tally.drop("unparseable", detail=type(exc).__name__)
            continue
        if static is None:
            tally.drop("no_static")
            continue
        tally.parse_ok()
        prof = build_sample_profile_text(static)
        if prof:
            tally.score_ok()
            out.append(prof)
        else:
            tally.drop("no_profile_text")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Leakage-free family-feature RAG retrieval eval.")
    ap.add_argument("--extracted-dir", type=str, default="data/samples/extracted")
    ap.add_argument("--top-k", type=int, default=5)
    ap.add_argument("--min-train", type=int, default=2, help="Min train profiles/family.")
    ap.add_argument("--max-train", type=int, default=20, help="Cap train profiles/family.")
    ap.add_argument("--max-test", type=int, default=10, help="Cap test profiles/family.")
    ap.add_argument("--out", type=str, default="tests/evaluation/family_rag_retrieval.json")
    args = ap.parse_args()

    root = Path(args.extracted_dir)
    if not root.is_dir():
        print(f"ERROR: --extracted-dir not found: {root}", file=sys.stderr)
        return 2

    # Build the held-out split: a0 -> train fingerprint, a1 -> test queries.
    train_records: list[dict] = []
    test_queries: list[tuple[str, str]] = []  # (true_family, profile)
    tally = Tally()
    fams = sorted(p for p in root.iterdir() if p.is_dir())
    for fam in fams:
        a0, a1 = fam / "a0", fam / "a1"
        if not a0.is_dir() or not a1.is_dir():
            continue  # need both halves for a leakage-free split
        train = _profiles_from_dir(a0, args.max_train, tally)
        if len(train) < args.min_train:
            continue
        test = _profiles_from_dir(a1, args.max_test, tally)
        if not test:
            continue
        desc = build_family_fingerprint_text(train)
        if not desc:
            continue
        train_records.append({"family_id": fam.name, "description": desc})
        test_queries.extend((fam.name, p) for p in test)
        print(f"  {fam.name}: {len(train)} train / {len(test)} test", flush=True)

    if len(train_records) < 2 or not test_queries:
        print("ERROR: not enough families with both a0 and a1 halves.", file=sys.stderr)
        return 1

    index = FamilyFingerprintIndex.from_records(train_records)
    n_fam = len(train_records)

    # Score each test query: rank of its true family in the retrieval.
    hits = {1: 0, 3: 0, 5: 0}
    rr_sum = 0.0
    for true_fam, profile in test_queries:
        ranked = index.search(profile, top_k=max(args.top_k, 5), min_score=0.0)
        rank = next((i + 1 for i, c in enumerate(ranked) if c.family == true_fam), 0)
        if rank:
            rr_sum += 1.0 / rank
            for k in hits:
                if rank <= k:
                    hits[k] += 1

    n = len(test_queries)
    result = {
        "schema": "maljan-family-rag-retrieval-eval/v1",
        "source": "Ultimate-RAT-Collection held-out split (a0=train, a1=test)",
        "families": n_fam,
        "test_samples": n,
        "recall_at_1": round(hits[1] / n, 4),
        "recall_at_3": round(hits[3] / n, 4),
        "recall_at_5": round(hits[5] / n, 4),
        "mrr": round(rr_sum / n, 4),
        "random_baseline_recall_at_5": round(min(5, n_fam) / n_fam, 4),
        "leakage_free": True,
        "population": tally.as_dict(),
    }
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")

    print("\n=== Family-feature RAG retrieval (leakage-free, held-out RAT split) ===")
    print(f"families={n_fam}  test_samples={n}")
    print(
        f"recall@1={result['recall_at_1']}  recall@3={result['recall_at_3']}  "
        f"recall@5={result['recall_at_5']}  MRR={result['mrr']}"
    )
    print(
        f"random-chance recall@5 = {result['random_baseline_recall_at_5']} (1-in-{n_fam} families)"
    )
    print(f"Wrote {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

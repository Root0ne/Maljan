"""Evaluate evidence -> ATT&CK technique mapping: TF-IDF vs semantic backend.

Measures how well the deterministic technique mapper (the engine behind §1.5
correct_isr_reports) assigns the correct ATT&CK technique to a piece of evidence
text, comparing the TF-IDF index against the semantic (BGE-384) index.

Test set: TRAM2 single_label.json (MITRE Center for Threat-Informed Defense) —
human-labeled (sentence, technique_id) pairs from real threat reports. This is
methodologically honest: TRAM2 sentences are INDEPENDENT of the ATT&CK technique
descriptions the index is built from, so it is a genuine generalization test
(scoring against the ATT&CK descriptions themselves would be circular).

Metrics per backend: top-1 accuracy, top-3 accuracy, MRR. Plus a score-separation
summary (mean similarity of the correct match vs the top-1 score when wrong) to
inform the autocorrect alignment threshold for each backend.

Run:  uv run python tests/evaluation/eval_technique_mapping.py [--limit N]
This is a measurement tool, not a pytest test (filename intentionally not test_*).
"""

from __future__ import annotations

import argparse
import json
import re
import urllib.request
from pathlib import Path

from maljan.memory import embeddings
from maljan.memory.attck_index import ATTCKIndex
from maljan.memory.semantic_attck_index import SemanticATTCKIndex

TRAM2_URL = (
    "https://raw.githubusercontent.com/center-for-threat-informed-defense"
    "/tram/main/data/tram2-data/single_label.json"
)
_CACHE = Path.home() / ".cache" / "maljan" / "tram2_single_label.json"
_TID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def _fetch_tram2() -> list[dict[str, str]]:
    if _CACHE.exists():
        print(f"TRAM2: using cache {_CACHE}", flush=True)
        cached: list[dict[str, str]] = json.loads(_CACHE.read_text(encoding="utf-8"))
        return cached
    print(f"TRAM2: downloading {TRAM2_URL}", flush=True)
    with urllib.request.urlopen(TRAM2_URL, timeout=60) as resp:  # noqa: S310
        raw = resp.read().decode("utf-8")
    _CACHE.parent.mkdir(parents=True, exist_ok=True)
    _CACHE.write_text(raw, encoding="utf-8")
    fresh: list[dict[str, str]] = json.loads(raw)
    return fresh


def _embedding_backend_note() -> str:
    """Sanity-check whether real fastembed semantics are active vs BoW fallback."""
    related = embeddings.cosine(
        embeddings.encode("ransomware encrypts victim files for ransom"),
        embeddings.encode("malware scrambles the disk and demands payment"),
    )
    unrelated = embeddings.cosine(
        embeddings.encode("ransomware encrypts victim files for ransom"),
        embeddings.encode("the binary resolves a DNS name and beacons over HTTP"),
    )
    real = related > unrelated + 0.1  # semantics separate; BoW would not
    label = "REAL fastembed BGE" if real else "BoW FALLBACK (semantic eval INVALID)"
    return f"embedding backend: {label} (related={related:.3f} vs unrelated={unrelated:.3f})"


def _evaluate(index: ATTCKIndex, pairs: list[tuple[str, str]]) -> dict[str, float]:
    top1 = top3 = 0
    rr_sum = 0.0
    correct_scores: list[float] = []
    wrong_top1_scores: list[float] = []
    for text, label in pairs:
        results = index.search(text, top_k=5)
        ranked = [r.technique.technique_id.upper() for r in results]
        if not ranked:
            wrong_top1_scores.append(0.0)
            continue
        if ranked[0] == label:
            top1 += 1
            correct_scores.append(results[0].score)
        else:
            wrong_top1_scores.append(results[0].score)
        if label in ranked[:3]:
            top3 += 1
        if label in ranked:
            rr_sum += 1.0 / (ranked.index(label) + 1)
    n = len(pairs)
    return {
        "n": float(n),
        "top1": top1 / n,
        "top3": top3 / n,
        "mrr": rr_sum / n,
        "mean_correct_score": (sum(correct_scores) / len(correct_scores))
        if correct_scores
        else 0.0,
        "mean_wrong_top1_score": (sum(wrong_top1_scores) / len(wrong_top1_scores))
        if wrong_top1_scores
        else 0.0,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=600, help="even-stride sample size")
    args = ap.parse_args()

    print("Building TF-IDF index...", flush=True)
    tfidf = ATTCKIndex.from_loader()
    print("Building semantic index (embeds the catalog once)...", flush=True)
    semantic = SemanticATTCKIndex.from_loader()
    print(_embedding_backend_note(), flush=True)

    entries = _fetch_tram2()
    # Keep only well-formed labels that exist in the current catalog (skip
    # revoked/legacy TRAM2 IDs that no current technique can match).
    pairs_all: list[tuple[str, str]] = []
    for e in entries:
        text = (e.get("text") or "").strip()
        label = (e.get("label") or "").strip().upper()
        if text and _TID_RE.match(label) and tfidf.technique_exists(label):
            pairs_all.append((text, label))

    # Even-stride sample to bound runtime while spanning the whole corpus.
    if args.limit and len(pairs_all) > args.limit:
        stride = len(pairs_all) / args.limit
        pairs = [pairs_all[int(i * stride)] for i in range(args.limit)]
    else:
        pairs = pairs_all
    print(
        f"TRAM2: {len(pairs_all)} valid (sentence,label) pairs; evaluating {len(pairs)} (sampled).",
        flush=True,
    )

    print("Scoring TF-IDF...", flush=True)
    tf = _evaluate(tfidf, pairs)
    print("Scoring semantic...", flush=True)
    se = _evaluate(semantic, pairs)

    lines = [
        "# Technique-mapping evaluation: TF-IDF vs semantic (TRAM2)",
        "",
        "- Test set: TRAM2 single_label (human-labeled threat-report sentences), "
        "independent of the ATT&CK build corpus.",
        f"- Sample: {int(tf['n'])} (sentence, technique_id) pairs.",
        f"- {_embedding_backend_note()}",
        "",
        "| backend | top-1 | top-3 | MRR | mean correct-score | mean wrong-top1-score |",
        "|---|---|---|---|---|---|",
        f"| TF-IDF | {tf['top1']:.3f} | {tf['top3']:.3f} | {tf['mrr']:.3f} | "
        f"{tf['mean_correct_score']:.3f} | {tf['mean_wrong_top1_score']:.3f} |",
        f"| semantic | {se['top1']:.3f} | {se['top3']:.3f} | {se['mrr']:.3f} | "
        f"{se['mean_correct_score']:.3f} | {se['mean_wrong_top1_score']:.3f} |",
        "",
        f"Delta (semantic - tfidf): top-1 {se['top1'] - tf['top1']:+.3f}, "
        f"top-3 {se['top3'] - tf['top3']:+.3f}, MRR {se['mrr'] - tf['mrr']:+.3f}",
    ]
    report = "\n".join(lines)
    print("\n" + report, flush=True)
    out = Path("D:/tmp/technique_mapping_eval.md")
    try:
        out.write_text(report + "\n", encoding="utf-8")
        print(f"\nWrote {out}", flush=True)
    except OSError:
        pass


if __name__ == "__main__":
    main()

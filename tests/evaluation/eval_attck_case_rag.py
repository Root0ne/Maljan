"""Isolated retrieval evaluation for the ATT&CK case-prior RAG (findings-log §4 U2).

``use_attck_case_rag`` is OFF by default and the only evidence about it is the n=19
end-to-end A/B (``family_rag_ab.json``), which switched the family RAG on at the same
time and measured final technique precision/recall. That experiment cannot say whether
*this* retrieval layer works: two treatments, one arm, and an operating point where the
pipeline predicted 2-3 techniques against a 16-18 technique ground truth (recall ~0.006),
which leaves no room to observe a retrieval effect either way.

So this measures the retrieval layer alone, against the control that actually matters.

THE CONTROL. The corpus is extremely skewed — T1129 appears in 71% of the 1733 cases,
T1027 in 67%, and there are only 77 distinct techniques in total. A recommender that
ignores the query entirely and always returns the globally most frequent K techniques
will therefore score well. Retrieval only earns its cost if it beats that prior. Random
selection from the 77 is reported as a floor.

TWO QUERY REGIMES, because they are not the same experiment:

  native    query = another case's own ``summary_text``. Both sides of the comparison
            are written in the corpus's vocabulary, so this is the OPTIMISTIC ceiling:
            what the index could do if the runtime query looked like the corpus.

            Reported twice, because the corpus is not i.i.d.: 742 of its 1733 cases
            (43%) share a byte-identical ``summary_text`` with another case. Plain
            leave-one-out therefore hands 43% of queries their own twin, which is a
            retrieval problem nobody has in production. The ``novel`` variant drops
            every neighbour at or above ``--exclude-above`` similarity, approximating
            a sample the corpus has genuinely not seen.

  runtime   query = ``build_sample_profile_text(static)`` over real samples — literally
            what ``attck_case_rag.retrieve_techniques`` is handed in production —
            scored against independent ATT&CK ground truth (the family labels in
            ``ab_manifest.json`` resolved through ``ground_truth/attck_malware``).
            The module docstring already concedes the query is a static-feature
            profile while the corpus is behavioural; this quantifies that gap
            instead of leaving it as a caveat.

The gate for enabling the feature is the same one the ATT&CK autocorrect gate had to
pass: a retrieval score that does not separate its answers from an uninformed prior is
not evidence, and injecting it into the analyst prompt would launder the prior into
something that reads like corroboration.

Offline script — never imported by the pipeline.

Run (inside the worker, which has fastembed and the BGE model cached):
    docker exec maljan-worker /app/.venv/bin/python \
        /app/tests/evaluation/eval_attck_case_rag.py \
        --out /app/tests/evaluation/attck_case_rag_retrieval.json
"""

# ruff: noqa: E402

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
# The eval dir itself so the family-slug resolver can be reused from eval_temporal_drift
# rather than re-implemented (a second slugifier would drift from the fixture names).
for _p in (_REPO_ROOT, _REPO_ROOT / "src", Path(__file__).resolve().parent):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import numpy as np

from maljan.memory import embeddings

# Defaults mirror PreprocessingConfig so the eval measures the shipped operating point.
_TOP_K = 5
_MIN_SCORE = 0.35
_MAX_TECHNIQUES = 8


def _load_cases(path: Path) -> list[dict]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    cases = doc.get("cases") or []
    out = []
    for c in cases:
        text = str(c.get("summary_text", "")).strip()
        tids = [str(t).strip() for t in (c.get("technique_ids") or []) if str(t).strip()]
        if text and tids:
            out.append({"sample_id": str(c.get("sample_id", "")), "text": text, "tids": tids})
    return out


def _prf(predicted: list[str], truth: set[str]) -> tuple[float, float, float]:
    """Precision / recall / F1 of a technique-id recommendation."""
    if not predicted:
        return 0.0, 0.0, 0.0
    hits = len(set(predicted) & truth)
    p = hits / len(predicted)
    r = hits / len(truth) if truth else 0.0
    f1 = 2 * p * r / (p + r) if (p + r) else 0.0
    return p, r, f1


def _aggregate(
    neighbour_idx: list[int],
    neighbour_score: list[float],
    truths: list[list[str]],
    max_techniques: int,
) -> list[str]:
    """Mirror ``AttckCaseIndex.recommend_techniques``: rank by support, then score."""
    support: dict[str, int] = {}
    best: dict[str, float] = {}
    for j, sc in zip(neighbour_idx, neighbour_score, strict=True):
        for tid in dict.fromkeys(truths[j]):
            support[tid] = support.get(tid, 0) + 1
            best[tid] = max(best.get(tid, 0.0), sc)
    ranked = sorted(support, key=lambda t: (support[t], best[t]), reverse=True)
    return ranked[:max_techniques]


def _mean(rows: list[tuple[float, float, float]]) -> dict[str, float]:
    if not rows:
        return {"precision": 0.0, "recall": 0.0, "f1": 0.0}
    n = len(rows)
    return {
        "precision": round(sum(r[0] for r in rows) / n, 4),
        "recall": round(sum(r[1] for r in rows) / n, 4),
        "f1": round(sum(r[2] for r in rows) / n, 4),
    }


def _frequency_prior(truths: list[list[str]], max_techniques: int) -> tuple[list[str], list[str]]:
    """The retrieval-free control: the globally most frequent techniques."""
    freq: dict[str, int] = {}
    for tids in truths:
        for tid in dict.fromkeys(tids):
            freq[tid] = freq.get(tid, 0) + 1
    prior = sorted(freq, key=lambda t: freq[t], reverse=True)[:max_techniques]
    return prior, sorted(freq)


def _native_regime(
    cases: list[dict],
    mat: np.ndarray,
    top_k: int,
    min_score: float,
    max_techniques: int,
    exclude_above: float,
) -> dict:
    """Leave-one-out over the corpus with corpus-native queries + both controls.

    ``exclude_above`` additionally suppresses near-duplicate neighbours, which is the
    only way to read the number as a forecast rather than a description of the corpus.
    """
    truths = [c["tids"] for c in cases]
    n = len(cases)
    prior, vocabulary = _frequency_prior(truths, max_techniques)

    sims = mat @ mat.T
    np.fill_diagonal(sims, -1.0)  # leave-one-out

    rng = random.Random(20260808)
    prior_rows: list[tuple[float, float, float]] = []
    rand_rows: list[tuple[float, float, float]] = []
    variants: dict[str, dict] = {}

    for label, ceiling in (("all_neighbours", 1.01), ("novel", exclude_above)):
        rows: list[tuple[float, float, float]] = []
        top_scores: list[float] = []
        empty = 0
        hit_at_1 = 0
        for i in range(n):
            truth = set(truths[i])
            row = sims[i]
            usable = np.where(row < ceiling, row, -1.0)
            order = np.argpartition(-usable, top_k)[:top_k]
            order = order[np.argsort(-usable[order])]
            keep = [(int(j), float(usable[j])) for j in order if usable[j] >= min_score]
            top_scores.append(float(usable[order[0]]))

            predicted = (
                _aggregate([j for j, _ in keep], [s for _, s in keep], truths, max_techniques)
                if keep
                else []
            )
            if not predicted:
                empty += 1
            elif predicted[0] in truth:
                hit_at_1 += 1
            rows.append(_prf(predicted, truth))

            if label == "all_neighbours":
                # Controls answer with the SAME budget so the comparison is like-for-like.
                prior_rows.append(_prf(prior, truth))
                rand_rows.append(
                    _prf(rng.sample(vocabulary, min(max_techniques, len(vocabulary))), truth)
                )

        variants[label] = {
            "abstained": empty,
            "hit_at_1": round(hit_at_1 / n, 4),
            "top_neighbour_similarity": {
                "mean": round(float(np.mean(top_scores)), 4),
                "p05": round(float(np.percentile(top_scores, 5)), 4),
                "p50": round(float(np.percentile(top_scores, 50)), 4),
                "p95": round(float(np.percentile(top_scores, 95)), 4),
            },
            **_mean(rows),
        }

    texts = [c["text"] for c in cases]
    dup_clusters = len(texts) - len(set(texts))

    return {
        "cases": n,
        "distinct_techniques": len(vocabulary),
        "duplicate_summary_texts": dup_clusters,
        "exclude_above": exclude_above,
        "rag": variants,
        "frequency_prior": _mean(prior_rows),
        "random_baseline": _mean(rand_rows),
        "frequency_prior_techniques": prior,
    }


def _labelled_samples(manifest: Path, sample_dir: Path, gt_dir: Path) -> list[dict]:
    """Resolve the A/B manifest into (sample file, ATT&CK ground-truth) pairs."""
    from eval_temporal_drift import resolve_fixture_slug  # sibling eval script

    if not manifest.is_file() or not gt_dir.is_dir():
        return []
    available = {p.stem for p in gt_dir.glob("*.json")}
    doc = json.loads(manifest.read_text(encoding="utf-8"))
    out: list[dict] = []
    for cohort in (doc.get("cohorts") or {}).values():
        for entry in cohort:
            sha = str(entry.get("sha256", ""))
            slug = resolve_fixture_slug(str(entry.get("signature", "")), available)
            if not sha or not slug:
                continue
            matches = list(sample_dir.glob(f"{sha}.*"))
            if not matches:
                continue
            truth = json.loads((gt_dir / f"{slug}.json").read_text(encoding="utf-8"))
            tids = [str(t) for t in (truth.get("technique_ids") or [])]
            if tids:
                out.append({"path": matches[0], "family": entry.get("signature"), "truth": tids})
    return out


def _runtime_regime(
    sample_dir: Path,
    manifest: Path,
    gt_dir: Path,
    cases: list[dict],
    mat: np.ndarray,
    top_k: int,
    min_score: float,
    max_techniques: int,
) -> dict:
    """Query the index the way production does, scored on independent ground truth."""
    from maljan.analysis.family_feature_rag import build_sample_profile_text
    from maljan.extractors.pe_extractor import build_static_analysis

    labelled = _labelled_samples(manifest, sample_dir, gt_dir)
    if not labelled:
        return {"samples": 0, "note": "no labelled samples resolvable"}

    rows: list[dict] = []
    for item in labelled:
        try:
            static = build_static_analysis(sample_path=str(item["path"]))
        except Exception:  # noqa: BLE001 - unparseable members are simply skipped
            continue
        if static is None:
            continue
        text = build_sample_profile_text(static)
        if not text:
            continue
        rows.append(
            {**item, "shipped": text, "imports_lowercased": _lowercased_imports(static, text)}
        )

    if not rows:
        return {"samples": 0, "note": "no parseable labelled samples"}

    truths = [c["tids"] for c in cases]
    prior, _ = _frequency_prior(truths, max_techniques)

    def _score(key: str) -> tuple[dict, dict, list[dict]]:
        qmat = np.asarray(embeddings.encode_batch([r[key] for r in rows]), dtype=np.float32)
        sims = qmat @ mat.T
        scored: list[tuple[float, float, float]] = []
        tops: list[float] = []
        cleared = 0
        detail: list[dict] = []
        for k, r in enumerate(rows):
            truth = {str(t) for t in r["truth"]}
            row = sims[k]
            order = np.argpartition(-row, top_k)[:top_k]
            order = order[np.argsort(-row[order])]
            best = float(row[order[0]])
            tops.append(best)
            keep = [(int(j), float(row[j])) for j in order if row[j] >= min_score]
            if keep:
                cleared += 1
            predicted = (
                _aggregate([j for j, _ in keep], [s for _, s in keep], truths, max_techniques)
                if keep
                else []
            )
            p, rec, f1 = _prf(predicted, truth)
            scored.append((p, rec, f1))
            detail.append(
                {
                    "sample": r["path"].name[:16],
                    "family": r["family"],
                    "top_similarity": round(best, 4),
                    "predicted": predicted,
                    "precision": round(p, 4),
                }
            )
        similarity = {
            "cleared_min_score": cleared,
            "cleared_fraction": round(cleared / len(rows), 4),
            "mean": round(float(np.mean(tops)), 4),
            "min": round(float(np.min(tops)), 4),
            "max": round(float(np.max(tops)), 4),
        }
        return _mean(scored), similarity, detail

    shipped, shipped_sim, detail = _score("shipped")
    # The shipped query and the corpus share only the boilerplate ("capabilities:",
    # "suspicious imports:"); the payloads are import-category counts vs capa rule
    # sentences, CamelCase vs lowercase. This variant keeps only the one segment whose
    # vocabulary actually overlaps, to test whether the gap is fixable by rendering.
    matched, matched_sim, _ = _score("imports_lowercased")

    return {
        "samples": len(rows),
        "top_neighbour_similarity": shipped_sim,
        "rag_shipped_query": shipped,
        "rag_vocabulary_matched_query": matched,
        "rag_vocabulary_matched_similarity": matched_sim,
        "frequency_prior": _mean([_prf(prior, {str(t) for t in r["truth"]}) for r in rows]),
        "per_sample": detail,
    }


def _lowercased_imports(static: object, fallback: str) -> str:
    """Render only the suspicious-import segment, lowercased to match the corpus."""
    names = list(
        dict.fromkeys(
            imp.function.lower()
            for imp in getattr(static, "imports", [])
            if getattr(imp, "is_suspicious", False) and imp.function
        )
    )[:12]
    return ("suspicious imports: " + ", ".join(names)) if names else fallback


def main() -> int:
    ap = argparse.ArgumentParser(description="Isolated ATT&CK case-prior RAG retrieval eval.")
    ap.add_argument("--corpus", type=str, default="data/attck_case_corpus_v1.json")
    ap.add_argument("--sample-dir", type=str, default="data/samples")
    ap.add_argument("--top-k", type=int, default=_TOP_K)
    ap.add_argument("--min-score", type=float, default=_MIN_SCORE)
    ap.add_argument("--max-techniques", type=int, default=_MAX_TECHNIQUES)
    ap.add_argument("--manifest", type=str, default="tests/evaluation/ab_manifest.json")
    ap.add_argument(
        "--ground-truth-dir", type=str, default="tests/evaluation/ground_truth/attck_malware"
    )
    ap.add_argument(
        "--exclude-above",
        type=float,
        default=0.99,
        help="Suppress neighbours at/above this cosine (near-duplicate leakage control).",
    )
    ap.add_argument("--out", type=str, default="tests/evaluation/attck_case_rag_retrieval.json")
    args = ap.parse_args()

    corpus = Path(args.corpus)
    if not corpus.is_file():
        print(f"ERROR: corpus not found: {corpus}", file=sys.stderr)
        return 2

    cases = _load_cases(corpus)
    print(f"corpus: {len(cases)} labelled cases", flush=True)
    print("embedding corpus (one pass) ...", flush=True)
    mat = np.asarray(embeddings.encode_batch([c["text"] for c in cases]), dtype=np.float32)
    print(f"embedded: {mat.shape}", flush=True)

    result = {
        "schema": "maljan-attck-case-rag-retrieval/v1",
        "corpus": str(corpus),
        "params": {
            "top_k": args.top_k,
            "min_score": args.min_score,
            "max_techniques": args.max_techniques,
        },
        "native": _native_regime(
            cases, mat, args.top_k, args.min_score, args.max_techniques, args.exclude_above
        ),
    }

    sample_dir = Path(args.sample_dir)
    if sample_dir.is_dir():
        print("building runtime-style queries ...", flush=True)
        result["runtime"] = _runtime_regime(
            sample_dir,
            Path(args.manifest),
            Path(args.ground_truth_dir),
            cases,
            mat,
            args.top_k,
            args.min_score,
            args.max_techniques,
        )

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in result.items() if k != "runtime"}, indent=2))
    if "runtime" in result:
        rt = dict(result["runtime"])
        rt.pop("per_sample", None)
        print(json.dumps({"runtime": rt}, indent=2))
    print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

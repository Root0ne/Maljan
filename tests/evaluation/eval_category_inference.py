"""Head-to-head: static keyword vs dynamic semantic malware-category inference.

Answers two questions with numbers, not assertions:

  1. How reliable is the static keyword classifier
     (:func:`schema_pruner.infer_malware_category`) — and how much of its
     accuracy comes from the text literally naming the category?
  2. Can a dynamic embedding classifier
     (:class:`semantic_category.SemanticCategoryClassifier`) do better,
     especially when the literal category word is absent?

Ground truth: ``category_eval_data.build_category_samples()`` — ATT&CK malware
SDOs labelled by their self-declared type (sentence 1), with the declaring
sentence removed from the *behavioral* input so the classifier cannot echo the
label. See that module for the non-circularity argument.

Two regimes per method:
  * **full**       — whole description (the category word is usually present).
  * **behavioral** — declaring sentence removed (must infer from behaviour).

Methods:
  * keyword            — static substring scoring (production default).
  * semantic-zeroshot  — prototypes from ATT&CK technique descriptions.
  * semantic-fewshot   — leave-one-out: prototypes from the other 100 samples.
  * hybrid             — keyword, falling back to zeroshot when keyword abstains.
  * majority           — always predict the most frequent class (floor).

Metrics: accuracy, macro-F1, per-class precision/recall/F1, UNKNOWN/abstain
rate, and a confusion matrix. A handful of keyword/semantic disagreements are
printed for qualitative inspection.

Run:  uv run python tests/evaluation/eval_category_inference.py
This is a measurement tool, not a pytest test (filename intentionally not test_*).
"""

# This script bootstraps sys.path before importing first-party packages, so the
# module-level imports below intentionally do not sit at the very top (E402).
# ruff: noqa: E402

from __future__ import annotations

import sys
from pathlib import Path

# Make the repo root importable so `tests.evaluation.*` resolves whether run via
# `uv run python tests/evaluation/eval_category_inference.py` (script dir on
# path) or as a module.
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from maljan.analysis.schema_pruner import MalwareCategory, infer_malware_category
from maljan.analysis.semantic_category import (
    SemanticCategoryClassifier,
    _category_technique_ids,
    _load_technique_texts,
    _mean_unit_vector,
    backend_is_semantic,
)
from maljan.memory import embeddings
from tests.evaluation.category_eval_data import (
    CategorySample,
    build_category_samples,
    category_distribution,
)

_CATS = [
    MalwareCategory.RANSOMWARE,
    MalwareCategory.RAT,
    MalwareCategory.DROPPER,
    MalwareCategory.WORM,
    MalwareCategory.INFOSTEALER,
]
_ALL = [*_CATS, MalwareCategory.UNKNOWN]


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------
def _metrics(y_true: list[MalwareCategory], y_pred: list[MalwareCategory]) -> dict[str, object]:
    n = len(y_true)
    correct = sum(1 for t, p in zip(y_true, y_pred, strict=True) if t == p)
    unknown = sum(1 for p in y_pred if p is MalwareCategory.UNKNOWN)

    per_class: dict[str, dict[str, float]] = {}
    f1s: list[float] = []
    for c in _CATS:
        tp = sum(1 for t, p in zip(y_true, y_pred, strict=True) if t == c and p == c)
        fp = sum(1 for t, p in zip(y_true, y_pred, strict=True) if t != c and p == c)
        fn = sum(1 for t, p in zip(y_true, y_pred, strict=True) if t == c and p != c)
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
        support = sum(1 for t in y_true if t == c)
        per_class[c.value] = {
            "precision": prec,
            "recall": rec,
            "f1": f1,
            "support": float(support),
        }
        if support:
            f1s.append(f1)

    # Confusion matrix: rows = true, cols = pred (over _ALL).
    confusion = {t.value: {p.value: 0 for p in _ALL} for t in _CATS}
    for t, p in zip(y_true, y_pred, strict=True):
        confusion[t.value][p.value] += 1

    return {
        "n": n,
        "accuracy": correct / n if n else 0.0,
        "macro_f1": sum(f1s) / len(f1s) if f1s else 0.0,
        "unknown_rate": unknown / n if n else 0.0,
        "per_class": per_class,
        "confusion": confusion,
    }


# ---------------------------------------------------------------------------
# Method runners (return predictions aligned with `samples`)
# ---------------------------------------------------------------------------
def _predict_keyword(texts: list[str]) -> list[MalwareCategory]:
    return [infer_malware_category({"sample": t}) for t in texts]


def _predict_zeroshot(texts: list[str], clf: SemanticCategoryClassifier) -> list[MalwareCategory]:
    return [clf.infer(t).category for t in texts]


def _predict_hybrid(texts: list[str], clf: SemanticCategoryClassifier) -> list[MalwareCategory]:
    """Keyword first; semantic zero-shot fills in where keyword abstains."""
    out: list[MalwareCategory] = []
    for t in texts:
        kw = infer_malware_category({"sample": t})
        out.append(kw if kw is not MalwareCategory.UNKNOWN else clf.infer(t).category)
    return out


def _predict_fewshot_loo(
    labels: list[MalwareCategory], sample_vectors: list[list[float]]
) -> list[MalwareCategory]:
    """Leave-one-out few-shot: prototype[c] = mean of all OTHER samples of c.

    Reuses precomputed sample embeddings — prototypes are recomputed per held-out
    item by excluding its vector, so no re-encoding is needed.
    """
    preds: list[MalwareCategory] = []
    n = len(labels)
    for i in range(n):
        protos: dict[MalwareCategory, list[float]] = {}
        for c in _CATS:
            vecs = [sample_vectors[j] for j in range(n) if j != i and labels[j] == c]
            proto = _mean_unit_vector(vecs)
            if proto:
                protos[c] = proto
        if not protos:
            preds.append(MalwareCategory.UNKNOWN)
            continue
        vi = sample_vectors[i]
        scores = {c: embeddings.cosine(vi, p) for c, p in protos.items()}
        best = max(scores, key=lambda c: scores[c])
        preds.append(best)
    return preds


def _predict_majority(labels: list[MalwareCategory]) -> list[MalwareCategory]:
    dist: dict[MalwareCategory, int] = {}
    for c in labels:
        dist[c] = dist.get(c, 0) + 1
    top = max(dist, key=lambda c: dist[c])
    return [top] * len(labels)


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def _fmt_method_block(name: str, m: dict[str, object]) -> list[str]:
    per_class = m["per_class"]  # type: ignore[index]
    lines = [
        f"### {name}",
        f"- accuracy **{m['accuracy']:.3f}**, macro-F1 **{m['macro_f1']:.3f}**, "
        f"abstain(UNKNOWN) {m['unknown_rate']:.3f}  (n={m['n']})",
        "",
        "| class | precision | recall | F1 | support |",
        "|---|---|---|---|---|",
    ]
    for c in _CATS:
        pc = per_class[c.value]  # type: ignore[index]
        lines.append(
            f"| {c.value} | {pc['precision']:.3f} | {pc['recall']:.3f} | "
            f"{pc['f1']:.3f} | {int(pc['support'])} |"
        )
    lines.append("")
    return lines


def _fmt_confusion(name: str, m: dict[str, object]) -> list[str]:
    confusion = m["confusion"]  # type: ignore[index]
    header = "| true\\pred | " + " | ".join(c.value[:4] for c in _ALL) + " |"
    sep = "|" + "---|" * (len(_ALL) + 1)
    lines = [f"#### confusion — {name} (row=true, col=pred)", "", header, sep]
    for t in _CATS:
        row = confusion[t.value]  # type: ignore[index]
        cells = " | ".join(str(row[p.value]) for p in _ALL)
        lines.append(f"| {t.value} | {cells} |")
    lines.append("")
    return lines


def _disagreements(
    samples: list[CategorySample],
    y_true: list[MalwareCategory],
    kw: list[MalwareCategory],
    sem: list[MalwareCategory],
    limit: int = 12,
) -> list[str]:
    lines = [
        "### keyword vs semantic-fewshot disagreements (behavioral regime)",
        "",
        "| family | true | keyword | fewshot | behavioral text (head) |",
        "|---|---|---|---|---|",
    ]
    shown = 0
    for s, t, k, m in zip(samples, y_true, kw, sem, strict=True):
        if k == m:
            continue
        head = s.behavioral_text[:70].replace("|", "/").replace("\n", " ")
        lines.append(f"| {s.name} | {t.value} | {k.value} | {m.value} | {head} |")
        shown += 1
        if shown >= limit:
            break
    lines.append("")
    return lines


def _run_regime(
    name: str,
    samples: list[CategorySample],
    texts: list[str],
    labels: list[MalwareCategory],
    zeroshot: SemanticCategoryClassifier,
) -> tuple[list[str], dict[str, list[MalwareCategory]]]:
    vectors = embeddings.encode_batch(texts)
    kw = _predict_keyword(texts)
    fewshot = _predict_fewshot_loo(labels, vectors)
    # Production-shaped hybrid: keyword stays authoritative; few-shot fills ONLY
    # where keyword abstains (UNKNOWN). Keeps keyword precision, recovers its
    # 38% behavioral-regime abstentions with the stronger learned classifier.
    hybrid_kw_few = [
        k if k is not MalwareCategory.UNKNOWN else f for k, f in zip(kw, fewshot, strict=True)
    ]
    preds = {
        "keyword": kw,
        "semantic-zeroshot": _predict_zeroshot(texts, zeroshot),
        "semantic-fewshot(LOO)": fewshot,
        "hybrid(kw->zeroshot)": _predict_hybrid(texts, zeroshot),
        "hybrid(kw->fewshot)": hybrid_kw_few,
        "majority": _predict_majority(labels),
    }
    lines = [f"## Regime: {name}", ""]
    for method, yp in preds.items():
        lines += _fmt_method_block(method, _metrics(labels, yp))
    return lines, preds


def main() -> None:
    samples = build_category_samples()
    if not samples:
        print("No samples (ATT&CK cache missing). Aborting.", flush=True)
        return

    labels = [s.category for s in samples]
    dist = category_distribution(samples)
    sem_ok = backend_is_semantic()
    seeds = {c.value: len(t) for c, t in _category_technique_ids().items()}

    print(f"Samples: {len(samples)} | distribution: {dist}", flush=True)
    print(f"backend_is_semantic = {sem_ok}", flush=True)

    print("Building zero-shot prototypes from ATT&CK technique descriptions...", flush=True)
    tech_texts = _load_technique_texts()
    zeroshot = SemanticCategoryClassifier.from_attck_techniques(techniques_text=tech_texts)

    full_lines, _ = _run_regime(
        "FULL description (category word usually present)",
        samples,
        [s.full_text for s in samples],
        labels,
        zeroshot,
    )
    beh_texts = [s.behavioral_text for s in samples]
    beh_lines, beh_preds = _run_regime(
        "BEHAVIORAL only (declaring sentence removed)",
        samples,
        beh_texts,
        labels,
        zeroshot,
    )

    header = [
        "# Malware-category inference: static keyword vs dynamic semantic",
        "",
        f"- Ground truth: {len(samples)} ATT&CK malware SDOs, labelled by the "
        "self-declared type in the description (independent of the classifier).",
        f"- Class distribution: {dist}  (worm/infostealer are sparse in the ATT&CK "
        "corpus — treat their per-class numbers as indicative).",
        f"- Embedding backend: {'REAL BGE-384' if sem_ok else 'BoW FALLBACK (semantic INVALID)'}.",
        f"- Zero-shot prototype seed techniques per category: {seeds}.",
        "- `behavioral` removes the declaring sentence so the classifier cannot "
        "echo the label — this is the honest test of inference from behaviour.",
        "",
    ]

    confusion_lines = ["## Confusion matrices (behavioral regime)", ""]
    for method in ("keyword", "semantic-fewshot(LOO)"):
        confusion_lines += _fmt_confusion(method, _metrics(labels, beh_preds[method]))

    disagree_lines = _disagreements(
        samples, labels, beh_preds["keyword"], beh_preds["semantic-fewshot(LOO)"]
    )

    report = "\n".join(header + full_lines + beh_lines + confusion_lines + disagree_lines)
    print("\n" + report, flush=True)
    out = Path("D:/tmp/category_inference_eval.md")
    try:
        out.write_text(report + "\n", encoding="utf-8")
        print(f"\nWrote {out}", flush=True)
    except OSError:
        pass


if __name__ == "__main__":
    main()

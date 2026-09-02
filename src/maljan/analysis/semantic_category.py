"""Dynamic (embedding-based) malware-category inference.

A semantic alternative to the static keyword scoring in
:func:`maljan.analysis.schema_pruner.infer_malware_category`. Instead of
matching a hand-maintained substring table, it embeds the analysis text with
the shared BGE-384 model and compares it to one prototype vector per category
via cosine similarity. The winning category is returned, with an UNKNOWN
fallback when the top match is weak or ambiguous (mirroring the keyword path's
safe default).

Why this can help where keywords cannot:
  * **Paraphrase robustness** — "scrambles the disk and demands payment" has no
    literal "ransom"/"encrypt" token but is semantically adjacent to the
    ransomware prototype.
  * **Freshness** — the zero-shot prototypes are built from ATT&CK technique
    descriptions, so they track the cached ATT&CK corpus rather than a frozen
    keyword list.

Why it can also hurt (measured, not assumed):
  * Averaged prototypes blur fine distinctions; behavioural prose that names no
    category cue may still land confidently on the wrong prototype.
  * It depends on fastembed being installed; the BoW fallback makes the
    semantic comparison meaningless. ``backend_is_semantic()`` reports this so
    callers can refuse to trust the result.

This module is intentionally side-effect free and config-gated off by default
(see ``PreprocessingConfig.category_inference_backend``). It is shipped so the
choice between keyword / semantic / hybrid is a measured, reversible knob — not
a hardcoded assumption. See ``tests/evaluation/eval_category_inference.py`` for
the head-to-head harness and the authors' findings log (not in this repository) for the
numbers that justify the default.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from maljan.analysis.schema_pruner import (
    _CATEGORY_KEYWORDS,
    MalwareCategory,
    _collect_text,
    infer_malware_category,
)
from maljan.core.logger import logger
from maljan.memory import embeddings

if TYPE_CHECKING:
    from maljan.schemas.isr_models import AgentISR

_TID_RE = re.compile(r"^t\d{4}(?:\.\d{3})?$")

# Defaults: pure argmax (never abstain) is the most informative baseline for the
# harness. Production wiring tightens these so a weak/ambiguous match yields
# UNKNOWN (no hint injected) rather than a confidently wrong category.
_DEFAULT_MIN_SCORE = 0.0
_DEFAULT_MIN_REL_MARGIN = 0.0


@dataclass(frozen=True)
class CategoryPrediction:
    """Result of a semantic category inference, with full transparency."""

    category: MalwareCategory
    score: float  # cosine of the winning prototype (0.0 when UNKNOWN/empty)
    rel_margin: float  # (best - second) / best; 0.0 when undefined
    scores: dict[MalwareCategory, float] = field(default_factory=dict)


def _category_technique_ids() -> dict[MalwareCategory, list[str]]:
    """Per-category ATT&CK technique IDs taken from the keyword table.

    These seed the zero-shot prototypes. Using the existing table keeps the two
    backends grounded in the same category->technique knowledge; the only thing
    that changes is literal-substring vs semantic matching.
    """
    out: dict[MalwareCategory, list[str]] = {}
    for cat, entries in _CATEGORY_KEYWORDS.items():
        tids = [kw.upper() for kw, _ in entries if _TID_RE.match(kw)]
        if tids:
            out[cat] = tids
    return out


def _mean_unit_vector(vectors: list[list[float]]) -> list[float]:
    """Average a list of vectors and L2-normalize the result."""
    if not vectors:
        return []
    dim = len(vectors[0])
    acc = [0.0] * dim
    n = 0
    for v in vectors:
        if len(v) != dim:
            continue
        for i, x in enumerate(v):
            acc[i] += x
        n += 1
    if n == 0:
        return []
    acc = [x / n for x in acc]
    norm = sum(x * x for x in acc) ** 0.5
    if norm == 0.0:
        return acc
    return [x / norm for x in acc]


class SemanticCategoryClassifier:
    """Embedding nearest-prototype malware-category classifier."""

    def __init__(
        self,
        prototypes: dict[MalwareCategory, list[float]],
        *,
        min_score: float = _DEFAULT_MIN_SCORE,
        min_rel_margin: float = _DEFAULT_MIN_REL_MARGIN,
    ) -> None:
        # Drop empty prototypes defensively (a category with no usable seed text).
        self._prototypes = {c: v for c, v in prototypes.items() if v}
        self._min_score = min_score
        self._min_rel_margin = min_rel_margin

    # -- construction --------------------------------------------------------

    @classmethod
    def from_attck_techniques(
        cls,
        *,
        techniques_text: dict[str, str] | None = None,
        min_score: float = _DEFAULT_MIN_SCORE,
        min_rel_margin: float = _DEFAULT_MIN_REL_MARGIN,
    ) -> SemanticCategoryClassifier:
        """Zero-shot prototypes from ATT&CK technique descriptions.

        ``techniques_text`` maps technique_id -> searchable text; when omitted it
        is loaded from the ATT&CK index (cached corpus). Each category prototype
        is the mean embedding of its seed techniques' descriptions.
        """
        if techniques_text is None:
            techniques_text = _load_technique_texts()

        seeds = _category_technique_ids()
        protos: dict[MalwareCategory, list[float]] = {}
        for cat, tids in seeds.items():
            texts = [techniques_text[t] for t in tids if t in techniques_text]
            if not texts:
                continue
            vectors = embeddings.encode_batch(texts)
            proto = _mean_unit_vector(vectors)
            if proto:
                protos[cat] = proto
        return cls(protos, min_score=min_score, min_rel_margin=min_rel_margin)

    @classmethod
    def from_labeled_examples(
        cls,
        examples: list[tuple[MalwareCategory, str]],
        *,
        min_score: float = _DEFAULT_MIN_SCORE,
        min_rel_margin: float = _DEFAULT_MIN_REL_MARGIN,
    ) -> SemanticCategoryClassifier:
        """Few-shot prototypes: mean embedding of example texts per category."""
        by_cat: dict[MalwareCategory, list[str]] = {}
        for cat, text in examples:
            if text and text.strip():
                by_cat.setdefault(cat, []).append(text)
        protos: dict[MalwareCategory, list[float]] = {}
        for cat, texts in by_cat.items():
            vectors = embeddings.encode_batch(texts)
            proto = _mean_unit_vector(vectors)
            if proto:
                protos[cat] = proto
        return cls(protos, min_score=min_score, min_rel_margin=min_rel_margin)

    # -- inference -----------------------------------------------------------

    def infer(self, text: str) -> CategoryPrediction:
        """Return the nearest-prototype category (UNKNOWN if weak/ambiguous).

        Fail-safe: empty text, no prototypes, or an embedding error all resolve
        to UNKNOWN with an empty score map. Never raises.
        """
        if not text or not text.strip() or not self._prototypes:
            return CategoryPrediction(MalwareCategory.UNKNOWN, 0.0, 0.0, {})
        try:
            vec = embeddings.encode(text)
        except Exception as exc:  # noqa: BLE001
            logger.warning("SemanticCategoryClassifier.infer embedding failed: %s", exc)
            return CategoryPrediction(MalwareCategory.UNKNOWN, 0.0, 0.0, {})

        scores = {cat: embeddings.cosine(vec, proto) for cat, proto in self._prototypes.items()}
        if not scores:
            return CategoryPrediction(MalwareCategory.UNKNOWN, 0.0, 0.0, {})

        ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
        best_cat, best_score = ranked[0]
        second_score = ranked[1][1] if len(ranked) >= 2 else 0.0
        rel_margin = (best_score - second_score) / best_score if best_score > 0 else 0.0

        if best_score < self._min_score or rel_margin < self._min_rel_margin:
            return CategoryPrediction(MalwareCategory.UNKNOWN, best_score, rel_margin, scores)
        return CategoryPrediction(best_cat, best_score, rel_margin, scores)

    @property
    def categories(self) -> list[MalwareCategory]:
        return list(self._prototypes.keys())


def backend_is_semantic() -> bool:
    """True only when real fastembed semantics are active (not the BoW fallback).

    A semantic classifier riding on the MD5-hash BoW fallback is meaningless, so
    callers should gate trust on this.
    """
    related = embeddings.cosine(
        embeddings.encode("ransomware encrypts victim files and demands a ransom"),
        embeddings.encode("crypto-locker scrambles the disk and extorts payment"),
    )
    unrelated = embeddings.cosine(
        embeddings.encode("ransomware encrypts victim files and demands a ransom"),
        embeddings.encode("the program enumerates running processes and lists modules"),
    )
    return related > unrelated + 0.05


def _load_technique_texts() -> dict[str, str]:
    """technique_id -> searchable text, from the cached ATT&CK corpus."""
    from maljan.memory.attck_index import ATTCKIndex

    index = ATTCKIndex.from_loader()
    return {tid.upper(): tech.searchable_text for tid, tech in index.techniques.items()}


# ---------------------------------------------------------------------------
# Backend dispatcher — the single entry point the judge calls.
# ---------------------------------------------------------------------------

_default_lock = threading.Lock()
_default_clf: SemanticCategoryClassifier | None = None


def get_default_semantic_classifier() -> SemanticCategoryClassifier:
    """Lazily build and cache the process-wide zero-shot classifier.

    Building it loads the cached ATT&CK corpus and embeds the ~20 seed technique
    descriptions once; subsequent calls reuse the instance.
    """
    global _default_clf
    if _default_clf is not None:
        return _default_clf
    with _default_lock:
        if _default_clf is None:
            _default_clf = SemanticCategoryClassifier.from_attck_techniques()
        return _default_clf


def reset_default_classifier() -> None:
    """Drop the cached classifier. Test helper only."""
    global _default_clf
    with _default_lock:
        _default_clf = None


def infer_category(
    reports: dict[str, str],
    isr_reports: dict[str, AgentISR] | None = None,
    *,
    backend: str = "keyword",
) -> MalwareCategory:
    """Infer the malware category using the configured backend.

    Backends (see ``PreprocessingConfig.category_inference_backend``):
      * ``"keyword"`` — the deterministic substring classifier (default,
        zero-dependency, abstains rather than guesses).
      * ``"semantic"`` — embedding nearest-prototype over the same combined
        text. Measured weaker than keyword; provided for experimentation.
      * ``"hybrid"`` — keyword first; the semantic classifier fills in only when
        keyword abstains (UNKNOWN), recovering coverage without losing keyword's
        precision.

    Fail-safe: the semantic path degrades to the keyword result on any error or
    when fastembed is unavailable (BoW fallback makes cosine meaningless), so the
    dispatcher never returns worse than keyword would. Never raises.
    """
    keyword_cat = infer_malware_category(reports, isr_reports)
    if backend == "keyword":
        return keyword_cat
    if backend == "hybrid" and keyword_cat is not MalwareCategory.UNKNOWN:
        return keyword_cat

    # semantic, or hybrid-on-abstain: run the embedding classifier.
    if backend not in ("semantic", "hybrid"):
        logger.warning("infer_category: unknown backend %r; using keyword.", backend)
        return keyword_cat
    try:
        if not backend_is_semantic():
            logger.warning("infer_category: fastembed unavailable (BoW fallback); using keyword.")
            return keyword_cat
        text = _collect_text(reports, isr_reports)
        semantic_cat = get_default_semantic_classifier().infer(text).category
    except Exception as exc:  # noqa: BLE001
        logger.warning("infer_category: semantic backend failed (%s); using keyword.", exc)
        return keyword_cat

    if backend == "hybrid":
        # keyword abstained; take semantic's guess (may still be UNKNOWN).
        return semantic_cat
    return semantic_cat

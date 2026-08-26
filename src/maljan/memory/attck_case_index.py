"""In-memory semantic index over LTM-mined, ATT&CK-labelled case behaviours.

The cross-sample knowledge half of the function-level RAG (findings-log §4 U2).
The per-sample function index (``function_index``) retrieves over THIS sample's own
decompiled functions only — it has no external knowledge corpus. This module mines
our own growing long-term memory (Qdrant ``StoredCase``: a behavioural
``summary_text`` plus the ``technique_ids`` the pipeline ultimately attributed) into
a vendored corpus and, at analysis time, retrieves the prior cases whose behaviour is
most similar to the current sample — then **aggregates** their technique_ids into a
ranked ATT&CK *candidate* list (technique frequency across behaviourally-similar
neighbours).

The candidates are handed to the static analyst **as evidence**; the LLM decides which
techniques actually apply (the same advisory role YARA / sink-reachability / the
family-feature RAG already play). Nothing here predicts a TTP — it surfaces prior-art
techniques that recur in behaviourally-similar malware, raising the static analyst's
first-pass TTP precision without a second statistical brain.

Parity by construction: the corpus stores case ``summary_text`` (not vectors), and this
index embeds it at load with the SAME ``embeddings.encode_batch`` the runtime query
uses — so query and corpus always live in one embedding space (mirrors
``SemanticATTCKIndex`` / ``FamilyFingerprintIndex``, which also embed at load rather
than vendoring vectors).

Fail-safe + OFF by default: a missing corpus yields ``None`` (no candidates), and the
feature is gated behind ``PreprocessingConfig.use_attck_case_rag``.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from pathlib import Path

from maljan.core.logger import logger
from maljan.memory import embeddings

# Process-level cache: one index per corpus path (embedding the corpus is the
# expensive part). Mirrors the family-fingerprint / function-index "build once" intent.
_CACHE_LOCK = threading.Lock()
_CACHE: dict[str, AttckCaseIndex | None] = {}


@dataclass(frozen=True)
class CaseNeighbour:
    """One retrieved prior case with its behavioural similarity to the sample."""

    sample_id: str
    score: float
    technique_ids: list[str] = field(default_factory=list)
    malware_category: str = "UNKNOWN"


@dataclass(frozen=True)
class TechniqueCandidate:
    """An ATT&CK technique aggregated across behaviourally-similar prior cases.

    ``support`` is how many of the retrieved neighbours exhibited the technique;
    ``score`` is the best (max) cosine similarity among the neighbours that did.
    """

    technique_id: str
    support: int
    score: float


class AttckCaseIndex:
    """In-memory cosine index over LTM case behavioural summaries."""

    def __init__(self) -> None:
        # (sample_id, technique_ids, malware_category, L2-normalized embedding)
        self._entries: list[tuple[str, list[str], str, list[float]]] = []

    @classmethod
    def from_records(cls, cases: list[dict]) -> AttckCaseIndex:
        """Embed each case's ``summary_text`` once (batch).

        Rows with a blank ``summary_text`` are dropped (nothing to match on).
        """
        idx = cls()
        rows = [c for c in cases if isinstance(c, dict) and str(c.get("summary_text", "")).strip()]
        if not rows:
            return idx
        vectors = embeddings.encode_batch([str(c["summary_text"]) for c in rows])
        idx._entries = [
            (
                str(c.get("sample_id", "")),
                [str(t).strip() for t in (c.get("technique_ids") or []) if str(t).strip()],
                str(c.get("malware_category", "") or "UNKNOWN"),
                vec,
            )
            for c, vec in zip(rows, vectors, strict=True)
        ]
        return idx

    def __len__(self) -> int:
        return len(self._entries)

    def search(self, query_text: str, top_k: int, min_score: float) -> list[CaseNeighbour]:
        """Return up to ``top_k`` cases with cosine >= ``min_score``, best first."""
        if not self._entries or not query_text.strip():
            return []
        qv = embeddings.encode(query_text)
        scored = [
            CaseNeighbour(sid, embeddings.cosine(qv, vec), list(tids), cat)
            for sid, tids, cat, vec in self._entries
        ]
        scored = [n for n in scored if n.score >= min_score]
        scored.sort(key=lambda n: n.score, reverse=True)
        return scored[: max(top_k, 0)]

    def recommend_techniques(
        self,
        query_text: str,
        *,
        top_k: int,
        min_score: float,
        max_techniques: int,
    ) -> list[TechniqueCandidate]:
        """Aggregate the technique_ids of the top-k neighbours into ranked candidates.

        For each ATT&CK technique seen across the retrieved neighbours, ``support`` is
        the neighbour count and ``score`` is the best similarity among them. Ranked by
        support (recurrence) then score (closest behavioural match), capped at
        ``max_techniques``. Returns ``[]`` when nothing clears the floor.
        """
        neighbours = self.search(query_text, top_k=top_k, min_score=min_score)
        if not neighbours:
            return []
        support: dict[str, int] = {}
        best: dict[str, float] = {}
        for n in neighbours:
            for tid in dict.fromkeys(n.technique_ids):  # de-dup within a case
                support[tid] = support.get(tid, 0) + 1
                best[tid] = max(best.get(tid, 0.0), n.score)
        cands = [TechniqueCandidate(tid, support[tid], best[tid]) for tid in support]
        cands.sort(key=lambda c: (c.support, c.score), reverse=True)
        return cands[: max(max_techniques, 0)]


def load_attck_case_index(corpus_path: str) -> AttckCaseIndex | None:
    """Load (and cache) the vendored ATT&CK case corpus, or None.

    None — never raised — when the corpus file is absent or malformed, so callers
    treat "no corpus" as the normal disabled state. Cached per path for the process
    lifetime.
    """
    key = str(corpus_path)
    with _CACHE_LOCK:
        if key in _CACHE:
            return _CACHE[key]
        result = _load_uncached(key)
        _CACHE[key] = result
        return result


def _load_uncached(corpus_path: str) -> AttckCaseIndex | None:
    if not corpus_path or not Path(corpus_path).is_file():
        logger.info("attck-case-RAG: case corpus not found at '%s' — RAG disabled.", corpus_path)
        return None
    try:
        doc = json.loads(Path(corpus_path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        logger.warning("attck-case-RAG: failed to read corpus '%s' (%s).", corpus_path, exc)
        return None
    cases = doc.get("cases") if isinstance(doc, dict) else None
    if not isinstance(cases, list) or not cases:
        logger.warning("attck-case-RAG: corpus '%s' has no 'cases' — RAG disabled.", corpus_path)
        return None
    index = AttckCaseIndex.from_records(cases)
    logger.info("attck-case-RAG: loaded %d case behaviours from '%s'.", len(index), corpus_path)
    return index if len(index) else None


def reset_cache() -> None:
    """Clear the process corpus cache (test hook; not used at runtime)."""
    with _CACHE_LOCK:
        _CACHE.clear()

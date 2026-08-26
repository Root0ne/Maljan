"""Semantic (embedding-based) ATT&CK technique index.

A drop-in alternative to the TF-IDF :class:`~maljan.memory.attck_index.ATTCKIndex`
that scores evidence against techniques with dense BGE-384 sentence embeddings
instead of bag-of-words TF-IDF. It exists to address the TF-IDF lexical failure
mode observed in production (ransomware evidence matching a crypto-algorithm
technique on the shared token "AES" rather than the impact technique) — semantic
similarity captures meaning, not surface tokens.

Design: subclass ATTCKIndex and reuse all of its non-vector machinery (technique
lookup, tactic catalogue, the ``from_loader`` / ``from_techniques`` factories,
``SearchResult``). Only the three vector operations are overridden — ``_build``
(embed every technique once), ``search``, and ``validate_and_score`` — so every
downstream caller (ATTCKValidator, correct_isr_reports) works unchanged.

NOTE: semantic cosine scores live on a different scale than TF-IDF (BGE puts even
loosely related text around 0.3-0.5), so the alignment thresholds tuned for the
TF-IDF backend do NOT transfer. Pick a semantic threshold empirically — see
``tests/evaluation/eval_technique_mapping.py``.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from maljan.core.logger import logger
from maljan.memory import embeddings
from maljan.memory.attck_index import ATTCKIndex, SearchResult
from maljan.memory.attck_loader import ATTCK_CACHE_DIR, ATTCKTechnique

# Embedding the 697-technique corpus costs ~1.3 GB of resident memory and ~120 s
# of wall time, and the memory is never returned: fastembed's onnxruntime arena
# grows to fit the largest inference it has seen and does not shrink, so
# ``malloc_trim`` reclaims ~2 MB of it. Measured 2026-07-28 in the worker
# container — it was the single largest term in the judge node's ~1.4 GB
# footprint, and the judge holds the index as a process-wide singleton
# (``ATTCKValidator.get_instance``), so every worker paid it once and kept it.
#
# The corpus is static between ATT&CK releases and the vectors are a pure
# function of it, so the whole cost is recomputation. The cache key is a hash of
# the exact (id, text) pairs that would be embedded: the STIX bundle
# auto-refreshes every 30 days (see attck_loader), and a cache keyed on anything
# looser would silently serve vectors for the previous release.
_EMB_CACHE_DIR = ATTCK_CACHE_DIR
_EMB_CACHE_VERSION = 1


class SemanticATTCKIndex(ATTCKIndex):
    """In-memory dense-embedding index over MITRE ATT&CK techniques.

    Shares the ATTCKIndex interface and factories; only the vector
    representation and the two scoring entry points differ.
    """

    def __init__(self) -> None:
        super().__init__()
        # technique_id (upper) -> 384-dim L2-normalized embedding
        self._emb: dict[str, list[float]] = {}

    # ------------------------------------------------------------------
    # Index construction (override: embeddings instead of TF-IDF)
    # ------------------------------------------------------------------

    def _build(self, techniques: list[ATTCKTechnique]) -> None:
        """Embed every technique's searchable text once, in corpus order."""
        self.techniques = {t.technique_id.upper(): t for t in techniques}
        self._build_embeddings()
        self._built = True
        logger.info("SemanticATTCKIndex built: %d techniques embedded.", len(self._emb))

    def _build_embeddings(self) -> None:
        """Fill ``self._emb`` from ``self.techniques`` (must already be set).

        Factored out so HybridATTCKIndex can add embeddings on top of the
        TF-IDF build without duplicating the embedding step.
        """
        tids = list(self.techniques.keys())
        texts = [self.techniques[tid].searchable_text for tid in tids]

        key = _corpus_key(tids, texts)
        cached = _load_cached_embeddings(key, tids)
        if cached is not None:
            self._emb = cached
            logger.info(
                "SemanticATTCKIndex: reused cached embeddings for %d techniques (key=%s).",
                len(cached),
                key[:12],
            )
            return

        vectors = embeddings.encode_batch(texts)
        self._emb = dict(zip(tids, vectors, strict=True))
        _store_cached_embeddings(key, self._emb)

    # ------------------------------------------------------------------
    # Scoring (override: cosine over dense embeddings)
    # ------------------------------------------------------------------

    def search(
        self,
        query: str,
        top_k: int = 5,
        filter_tactics: list[str] | None = None,
    ) -> list[SearchResult]:
        """Rank techniques by embedding cosine similarity to ``query``."""
        if not self._built:
            raise RuntimeError(
                "SemanticATTCKIndex not built. Call from_loader() or from_techniques()."
            )

        query_vec = embeddings.encode(query)
        scores: list[tuple[str, float]] = []
        for tid, doc_vec in self._emb.items():
            if filter_tactics:
                tech = self.techniques[tid]
                if not any(t in tech.tactic_phases for t in filter_tactics):
                    continue
            sim = embeddings.cosine(query_vec, doc_vec)
            if sim > 0.0:
                scores.append((tid, sim))

        scores.sort(key=lambda x: x[1], reverse=True)
        return [
            SearchResult(technique=self.techniques[tid], score=score, rank=rank)
            for rank, (tid, score) in enumerate(scores[:top_k], 1)
        ]

    def validate_and_score(self, technique_id: str, evidence_text: str) -> float:
        """Cosine similarity between evidence and the technique embedding."""
        tech_vec = self._emb.get(technique_id.upper())
        if tech_vec is None:
            logger.warning("SemanticATTCKIndex: technique '%s' not found in index.", technique_id)
            return 0.0
        return embeddings.cosine(embeddings.encode(evidence_text), tech_vec)


# ---------------------------------------------------------------------------
# Embedding cache
# ---------------------------------------------------------------------------
# Never raises. A cache that can break an analysis is worse than no cache: the
# fallback is simply to embed, which is what the code did before this existed.


def _corpus_key(tids: list[str], texts: list[str]) -> str:
    """Hash the exact corpus that would be embedded.

    Order-sensitive on purpose — ``_emb`` is keyed by technique id, but a
    reordering means the loader produced a different corpus and the cheap thing
    is to re-embed rather than reason about whether it mattered. Includes the
    embedding dimension so a model swap (see ``embeddings._MODEL_NAME``) cannot
    silently reuse vectors from the previous model.
    """
    digest = hashlib.sha256()
    digest.update(f"v{_EMB_CACHE_VERSION}:{embeddings.EMBED_DIM}\n".encode())
    for tid, text in zip(tids, texts, strict=True):
        digest.update(tid.encode("utf-8"))
        digest.update(b"\0")
        digest.update(text.encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def _cache_path(key: str) -> Path:
    return _EMB_CACHE_DIR / f"embeddings-{key[:32]}.json"


def _load_cached_embeddings(key: str, tids: list[str]) -> dict[str, list[float]] | None:
    """Return the cached vectors, or ``None`` to fall back to embedding."""
    path = _cache_path(key)
    try:
        if not path.is_file():
            return None
        raw = json.loads(path.read_text(encoding="utf-8"))
        vectors = raw.get("vectors")
        if not isinstance(vectors, dict):
            return None
        out: dict[str, list[float]] = {}
        for tid in tids:
            vec = vectors.get(tid)
            # A cache missing a technique the corpus asks for, or carrying a
            # vector of the wrong width, is not partially usable: search()
            # would score that technique as absent and quietly stop being able
            # to correct to it.
            if not isinstance(vec, list) or len(vec) != embeddings.EMBED_DIM:
                return None
            out[tid] = [float(v) for v in vec]
        return out
    except (OSError, ValueError, TypeError) as exc:
        logger.debug("SemanticATTCKIndex: embedding cache unreadable (%s); re-embedding.", exc)
        return None


def _store_cached_embeddings(key: str, emb: dict[str, list[float]]) -> None:
    """Write the cache. Best-effort: a read-only cache dir must not fail a run."""
    path = _cache_path(key)
    try:
        _EMB_CACHE_DIR.mkdir(parents=True, exist_ok=True)
        # Write-then-rename so a worker that dies mid-write cannot leave a
        # truncated file that the next one reads as valid JSON.
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(
            json.dumps(
                {"version": _EMB_CACHE_VERSION, "dim": embeddings.EMBED_DIM, "vectors": emb}
            ),
            encoding="utf-8",
        )
        tmp.replace(path)
        # Old keys are previous ATT&CK releases or a previous model. Leaving
        # them accumulates a few MB per release forever.
        for stale in _EMB_CACHE_DIR.glob("embeddings-*.json"):
            if stale != path:
                stale.unlink(missing_ok=True)
        logger.info("SemanticATTCKIndex: cached %d embeddings to %s.", len(emb), path.name)
    except OSError as exc:
        logger.debug("SemanticATTCKIndex: could not write embedding cache (%s).", exc)

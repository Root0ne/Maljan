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

from maljan.core.logger import logger
from maljan.memory import embeddings
from maljan.memory.attck_index import ATTCKIndex, SearchResult
from maljan.memory.attck_loader import ATTCKTechnique


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
        tids = list(self.techniques.keys())
        texts = [self.techniques[tid].searchable_text for tid in tids]
        vectors = embeddings.encode_batch(texts)
        self._emb = dict(zip(tids, vectors, strict=True))
        self._built = True
        logger.info("SemanticATTCKIndex built: %d techniques embedded.", len(self._emb))

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

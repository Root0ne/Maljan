"""Hybrid ATT&CK technique index: semantic ranking + TF-IDF gating.

The TRAM2 evaluation (findings-log §1.5.1) found the two index backends are
complementary: the semantic (BGE-384) index *ranks* candidate techniques better
(top-3 / MRR), while the TF-IDF index gives a *cleaner alignment gate* (it scores
near 0 for unrelated evidence, which the §1.5 autocorrect's low-alignment swap
relies on — the semantic scores cram near 0.7 regardless of correctness).

This index combines both: it answers ``search()`` (candidate RANKING) with
semantic embeddings and ``validate_and_score()`` (absolute alignment GATE) with
TF-IDF. ``correct_isr_reports`` already routes ranking through ``search`` and
gating through ``validate_and_score``, so it gets best-of-both with no change.

Because the gate is TF-IDF, the existing TF-IDF alignment threshold
(``attck_autocorrect_min_alignment``) applies directly to this backend too.
"""

from __future__ import annotations

from maljan.core.logger import logger
from maljan.memory.attck_index import ATTCKIndex
from maljan.memory.attck_loader import ATTCKTechnique
from maljan.memory.semantic_attck_index import SemanticATTCKIndex


class HybridATTCKIndex(SemanticATTCKIndex):
    """Semantic ``search`` (inherited) + TF-IDF ``validate_and_score`` (overridden).

    Builds both representations: the TF-IDF vectors via ATTCKIndex._build and the
    dense embeddings via SemanticATTCKIndex._build_embeddings.
    """

    def _build(self, techniques: list[ATTCKTechnique]) -> None:
        # TF-IDF build first (sets self.techniques, self._tf_vecs, self._idf,
        # self._built) ...
        ATTCKIndex._build(self, techniques)
        # ... then add the dense embeddings on top.
        self._build_embeddings()
        logger.info("HybridATTCKIndex built: %d techniques (TF-IDF + embeddings).", self.size)

    # search() is inherited from SemanticATTCKIndex -> semantic ranking.

    def validate_and_score(self, technique_id: str, evidence_text: str) -> float:
        """Absolute alignment gate via TF-IDF (clean 0-for-unrelated property)."""
        return ATTCKIndex.validate_and_score(self, technique_id, evidence_text)

"""The ATT&CK index, as a shared lazily-built singleton.

What is left here is a lookup: does this technique id exist, and what is the
catalogue entry behind it. The scoring, the suggestion ranking and the pass
that rewrote an analyst's technique id in place are gone — an agent asks
``tools.knowledge`` the same questions on its own initiative now, and
``pipeline.validation`` reports an id the catalogue does not have rather than
substituting one.

The index is built on first use so a pure text run pays no startup cost.

Usage (in agents or nodes):
    from maljan.memory.attck_validator import ATTCKValidator

    validator = ATTCKValidator.get_instance()
    is_valid = validator.validate_ttp_id("T1055.001")
    technique = validator.get_technique("T1055.001")
"""

from __future__ import annotations

import threading

from maljan.core.logger import logger
from maljan.memory.attck_index import ATTCKIndex
from maljan.memory.attck_loader import ATTCKTechnique


class ATTCKValidator:
    """Thread-safe singleton validator backed by the ATT&CK TF-IDF index.

    Use ATTCKValidator.get_instance() to obtain the shared instance.
    The index is initialized lazily on first use.
    """

    _instance: ATTCKValidator | None = None
    _lock: threading.Lock = threading.Lock()

    def __init__(self, index: ATTCKIndex) -> None:
        self._index = index

    # ------------------------------------------------------------------
    # Singleton factory
    # ------------------------------------------------------------------

    @staticmethod
    def _build_index(backend: str | None, force_refresh: bool) -> ATTCKIndex:
        """Build the ATT&CK index for the requested backend.

        ``backend == "semantic"`` uses dense BGE embeddings; anything else
        (default) uses the TF-IDF index. The semantic class is imported lazily
        so the embedding model is only loaded when that backend is selected.
        """
        if backend == "semantic":
            from maljan.memory.semantic_attck_index import SemanticATTCKIndex

            logger.info("ATTCKValidator: using SEMANTIC (embedding) ATT&CK index.")
            return SemanticATTCKIndex.from_loader(force_refresh=force_refresh)
        if backend == "hybrid":
            from maljan.memory.hybrid_attck_index import HybridATTCKIndex

            logger.info("ATTCKValidator: using HYBRID (semantic rank + TF-IDF gate) index.")
            return HybridATTCKIndex.from_loader(force_refresh=force_refresh)
        return ATTCKIndex.from_loader(force_refresh=force_refresh)

    @classmethod
    def get_instance(
        cls, force_refresh: bool = False, backend: str | None = None
    ) -> ATTCKValidator:
        """Return the shared ATTCKValidator, building the index if needed.

        ``backend`` selects the index implementation ("tfidf" default, or
        "semantic" for dense embeddings). The first caller to build the
        singleton fixes the backend; later callers reuse it (pass
        ``force_refresh=True`` to switch backends in tests).

        Thread-safety:
            ``force_refresh`` ALWAYS acquires the lock so that a refresh
            cannot race with another caller that observes a stale instance
            outside the lock. The previous implementation skipped the lock
            when the singleton already existed, allowing two threads to
            rebuild the index simultaneously.
        """
        if force_refresh:
            with cls._lock:
                logger.info("Force-refreshing ATTCKValidator (rebuilding index)...")
                cls._instance = cls(cls._build_index(backend, force_refresh=True))
                return cls._instance

        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    logger.info("Initializing ATTCKValidator (loading index)...")
                    cls._instance = cls(cls._build_index(backend, force_refresh=False))
        return cls._instance

    @classmethod
    def current_instance(cls) -> ATTCKValidator | None:
        """Return the built singleton if one exists, else None (never builds).

        Lets best-effort consumers (e.g. STIX technique-name back-fill) reuse the
        already-loaded index without forcing an expensive build when it is absent.
        """
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Drop the cached singleton (intended for test isolation)."""
        with cls._lock:
            cls._instance = None

    @classmethod
    def from_index(cls, index: ATTCKIndex) -> ATTCKValidator:
        """Create a validator from a pre-built index. Used in tests."""
        return cls(index)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def validate_ttp_id(self, technique_id: str) -> bool:
        """Return True if the technique ID exists in the current ATT&CK release.

        A False return means the agent hallucinated a non-existent TTP ID.

        Args:
            technique_id: e.g., "T1055" or "T1055.001"

        Returns:
            True if the ID is valid and not deprecated/revoked.
        """
        exists = self._index.technique_exists(technique_id)
        if not exists:
            logger.warning(
                "ATT&CK validation: '%s' not found. Possible hallucination.", technique_id
            )
        return exists

    def get_technique(self, technique_id: str) -> ATTCKTechnique | None:
        """Return the full ATTCKTechnique object for a given ID."""
        return self._index.get_by_id(technique_id)

    @property
    def technique_count(self) -> int:
        """Number of techniques in the current index."""
        return self._index.size

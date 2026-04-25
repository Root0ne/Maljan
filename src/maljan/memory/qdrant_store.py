"""QdrantStore — Qdrant vector database backend for long-term memory.

Phase 5 production backend. Full implementation using qdrant-client.

Requirements:
  uv add qdrant-client
  docker run -p 6333:6333 qdrant/qdrant

Design:
  - Embedding: term-frequency bag-of-words (same algorithm as InMemoryStore)
    projected to a fixed 512-dimensional vector via a deterministic hash
    trick. No external embedding model required at runtime.
  - Upgrade path: replace _embed() with a sentence-transformer or OpenAI
    embedding call — only _embed() changes, nothing else.
  - Upsert semantics: sample_id is hashed to a stable uint64 point ID so
    re-analyzing the same file replaces the old entry.
  - Collection auto-creation: if the collection does not exist on first
    store(), it is created with COSINE distance.
  - StoredCase fields are persisted as Qdrant point payload so they can be
    fully reconstructed without a separate database.
  - Connection: a single QdrantClient is created in __init__ and reused.
    The Qdrant Python client is thread-safe for concurrent reads.

Configuration (.env):
  MEMORY__BACKEND=qdrant
  MEMORY__QDRANT_URL=http://localhost:6333
  MEMORY__QDRANT_COLLECTION=maljan_cases
  MEMORY__TOP_K=3
"""

from __future__ import annotations

import hashlib
import math
from collections import Counter
from datetime import UTC
from typing import Any

from maljan.core.logger import logger
from maljan.memory.long_term_memory import StoredCase


class QdrantNotAvailableError(ImportError):
    """Raised when qdrant-client is not installed."""


# ---------------------------------------------------------------------------
# Embedding helpers (deterministic, no external model)
# ---------------------------------------------------------------------------

_EMBED_DIM = 512  # fixed projection dimension


def _tokenize(text: str) -> list[str]:
    """Lowercase whitespace tokenizer."""
    return text.lower().split()


def _embed(text: str) -> list[float]:
    """Project text to a _EMBED_DIM-dimensional float vector.

    Algorithm:
      1. Build a term-frequency Counter from the text tokens.
      2. For each unique token, deterministically map it to one of the
         _EMBED_DIM buckets using MD5 (no collision problems at this scale).
      3. Accumulate TF-weighted contributions per bucket.
      4. L2-normalize the result so Qdrant COSINE distance is meaningful.

    This produces the same vector for the same text on every run (no
    randomness), making it suitable for upsert/update workflows.
    """
    tf = Counter(_tokenize(text))
    vec = [0.0] * _EMBED_DIM
    for token, freq in tf.items():
        # Stable bucket index from MD5
        digest = hashlib.md5(token.encode(), usedforsecurity=False).digest()
        idx = int.from_bytes(digest[:4], "little") % _EMBED_DIM
        vec[idx] += float(freq)

    # L2 normalize
    norm = math.sqrt(sum(v * v for v in vec))
    if norm > 0.0:
        vec = [v / norm for v in vec]
    return vec


def _stable_id(sample_id: str) -> int:
    """Return a stable unsigned 64-bit integer ID for a sample_id string.

    Qdrant point IDs must be uint64 or UUID. We use the first 8 bytes of
    the SHA-256 digest to derive a stable uint64 from the sample_id string.
    Collision probability at typical Maljan corpus sizes (<10 000 cases) is
    negligible (birthday bound ~2^32 with 64-bit space).
    """
    digest = hashlib.sha256(sample_id.encode()).digest()
    return int.from_bytes(digest[:8], "little")


# ---------------------------------------------------------------------------
# QdrantStore
# ---------------------------------------------------------------------------


class QdrantStore:
    """Qdrant-backed MemoryStore for production long-term case retrieval.

    Implements the MemoryStore Protocol. Drop-in replacement for
    InMemoryStore when persistence and semantic-search at scale are needed.

    Usage:
        store = QdrantStore(url="http://localhost:6333", collection="maljan_cases")
        store.store(case)
        results = store.retrieve("ransomware encryption C2", top_k=3)

    Args:
        url:        Qdrant server URL (e.g., "http://localhost:6333").
        collection: Qdrant collection name. Auto-created on first store() call.
    """

    def __init__(self, url: str, collection: str = "maljan_cases") -> None:
        try:
            from qdrant_client import QdrantClient
        except ImportError as exc:
            raise QdrantNotAvailableError(
                "qdrant-client is required for QdrantStore.\n"
                "Install with: uv add qdrant-client\n"
                "Start Qdrant: docker run -p 6333:6333 qdrant/qdrant"
            ) from exc

        self._url = url
        self._collection = collection
        self._client: Any = QdrantClient(url=url)
        self._collection_ready = False

        logger.info(
            "QdrantStore initialized (url=%s, collection=%s, embed_dim=%d).",
            url,
            collection,
            _EMBED_DIM,
        )

    # ------------------------------------------------------------------
    # MemoryStore Protocol implementation
    # ------------------------------------------------------------------

    def store(self, case: StoredCase) -> None:
        """Upsert a StoredCase into the Qdrant collection.

        Creates the collection on the first call if it does not exist.
        Uses upsert semantics: if a point with the same sample_id already
        exists, it is replaced in place.
        """
        from qdrant_client.models import Distance, PointStruct, VectorParams

        self._ensure_collection(VectorParams, Distance)

        point_id = _stable_id(case.sample_id)
        vector = _embed(case.summary_text)
        payload = {
            "sample_id": case.sample_id,
            "summary_text": case.summary_text,
            "technique_ids": case.technique_ids,
            "malware_category": case.malware_category,
            "stix_bundle_json": case.stix_bundle_json,
            "created_at": case.created_at.astimezone(UTC).isoformat(),
        }

        self._client.upsert(
            collection_name=self._collection,
            points=[PointStruct(id=point_id, vector=vector, payload=payload)],
        )
        logger.info(
            "QdrantStore.store: upserted sample_id=%s (point_id=%d).",
            case.sample_id,
            point_id,
        )

    def retrieve(self, query: str, top_k: int = 3) -> list[StoredCase]:
        """Return the top_k most similar cases from Qdrant.

        Args:
            query:  Free-text search query (e.g., concatenated ISR claim text).
            top_k:  Maximum number of results to return.

        Returns:
            List of StoredCase objects ordered by descending cosine similarity.
            Empty list when the collection is empty or query is blank.
        """
        if not query.strip():
            return []

        if not self._collection_exists():
            logger.debug(
                "QdrantStore.retrieve: collection '%s' does not exist yet.",
                self._collection,
            )
            return []

        vector = _embed(query)
        hits = self._client.search(
            collection_name=self._collection,
            query_vector=vector,
            limit=top_k,
            with_payload=True,
        )

        results: list[StoredCase] = []
        for hit in hits:
            p = hit.payload or {}
            try:
                results.append(
                    StoredCase(
                        sample_id=p["sample_id"],
                        summary_text=p.get("summary_text", ""),
                        technique_ids=p.get("technique_ids", []),
                        malware_category=p.get("malware_category", "UNKNOWN"),
                        stix_bundle_json=p.get("stix_bundle_json", ""),
                    )
                )
            except (KeyError, TypeError) as exc:
                logger.warning(
                    "QdrantStore.retrieve: skipping malformed payload: %s", exc
                )

        logger.debug(
            "QdrantStore.retrieve: query='%s...' top_k=%d returned %d results.",
            query[:40],
            top_k,
            len(results),
        )
        return results

    def count(self) -> int:
        """Return the total number of points in the Qdrant collection."""
        if not self._collection_exists():
            return 0
        info = self._client.get_collection(self._collection)
        return info.points_count or 0

    def clear(self) -> None:
        """Delete and recreate the Qdrant collection (removes all points).

        After clear(), the collection still exists but is empty. The next
        store() call will recreate the vector config if needed.
        """
        if self._collection_exists():
            self._client.delete_collection(self._collection)
            self._collection_ready = False
            logger.info(
                "QdrantStore.clear: collection '%s' deleted.", self._collection
            )

    def __repr__(self) -> str:
        return (
            f"QdrantStore(url={self._url!r}, "
            f"collection={self._collection!r}, "
            f"count={self.count()})"
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _collection_exists(self) -> bool:
        """Return True if the Qdrant collection currently exists."""
        try:
            existing = {c.name for c in self._client.get_collections().collections}
            return self._collection in existing
        except Exception as exc:
            logger.warning("QdrantStore._collection_exists error: %s", exc)
            return False

    def _ensure_collection(self, VectorParams: Any, Distance: Any) -> None:
        """Create the collection if it does not yet exist (idempotent)."""
        if self._collection_ready:
            return

        if not self._collection_exists():
            self._client.create_collection(
                collection_name=self._collection,
                vectors_config=VectorParams(
                    size=_EMBED_DIM,
                    distance=Distance.COSINE,
                ),
            )
            logger.info(
                "QdrantStore: created collection '%s' (dim=%d, distance=COSINE).",
                self._collection,
                _EMBED_DIM,
            )

        self._collection_ready = True

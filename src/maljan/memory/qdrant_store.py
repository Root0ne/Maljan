"""QdrantStore — Qdrant vector database backend for long-term memory.

Phase 5 production backend. Uses the shared ``maljan.memory.embeddings``
module to encode text with a real semantic model (``BAAI/bge-small-en-v1.5``,
384-dim) instead of the previous MD5-hash projection. This lets the judge
retrieve "behaviorally similar" cases even when the wording differs.

Requirements:
  uv add qdrant-client fastembed
  docker run -p 6333:6333 qdrant/qdrant

Design notes:

- **Collection name** is now ``maljan_cases_v2`` by default so legacy
  hash-vector collections (dim=512) do not collide with the new 384-dim
  schema. Operators upgrading from the old format should either point at a
  fresh collection or delete the old one explicitly.
- **Upsert semantics**: ``sample_id`` is hashed to a stable uint64 point ID
  so re-analyzing the same file replaces the old entry.
- **Collection auto-creation**: if the collection does not exist on first
  ``store()``, it is created with COSINE distance and ``EMBED_DIM`` size.
- **StoredCase fields** are persisted as Qdrant point payload so they can
  be fully reconstructed without a separate database.
- **Connection**: a single QdrantClient is created in ``__init__`` and
  reused. The Qdrant Python client is thread-safe for concurrent reads.

Configuration (.env):
  MEMORY__BACKEND=qdrant
  MEMORY__QDRANT_URL=http://localhost:6333
  MEMORY__QDRANT_COLLECTION=maljan_cases_v2
  MEMORY__TOP_K=3
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC
from typing import Any

from maljan.core.exceptions import MemoryStoreError
from maljan.core.logger import logger
from maljan.memory.embeddings import EMBED_DIM, encode
from maljan.memory.long_term_memory import StoredCase


class QdrantNotAvailableError(MemoryStoreError, ImportError):
    """Raised when qdrant-client is not installed.

    Inherits from both MemoryStoreError (canonical Maljan hierarchy) and
    ImportError so legacy ``except ImportError`` callers continue to work.
    """


def _stable_id(sample_id: str) -> int:
    """Return a stable unsigned 64-bit integer ID for a sample_id string.

    Qdrant point IDs must be uint64 or UUID. We use the first 8 bytes of
    the SHA-256 digest to derive a stable uint64 from the sample_id string.
    Collision probability at typical Maljan corpus sizes (<10 000 cases) is
    negligible (birthday bound ~2^32 with 64-bit space).
    """
    digest = hashlib.sha256(sample_id.encode()).digest()
    return int.from_bytes(digest[:8], "little")


class QdrantStore:
    """Qdrant-backed MemoryStore for production long-term case retrieval.

    Implements the MemoryStore Protocol. Drop-in replacement for
    InMemoryStore when persistence and semantic-search at scale are needed.

    Usage:
        store = QdrantStore(url="http://localhost:6333",
                            collection="maljan_cases_v2")
        store.store(case)
        results = store.retrieve("ransomware encryption C2", top_k=3)

    Args:
        url:        Qdrant server URL (e.g., "http://localhost:6333").
        collection: Qdrant collection name. Auto-created on first store() call.
    """

    def __init__(
        self, url: str, collection: str = "maljan_cases_v2", api_key: str | None = None
    ) -> None:
        try:
            from qdrant_client import QdrantClient
        except ImportError as exc:
            raise QdrantNotAvailableError(
                "qdrant-client is required for QdrantStore.\n"
                "Install with: uv add qdrant-client fastembed\n"
                "Start Qdrant: docker run -p 6333:6333 qdrant/qdrant"
            ) from exc

        self._url = url
        self._collection = collection
        self._client: Any = QdrantClient(url=url, api_key=api_key)
        self._collection_ready = False

        logger.info(
            "QdrantStore initialized (url=%s, collection=%s, embed_dim=%d).",
            url,
            collection,
            EMBED_DIM,
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
        vector = encode(case.summary_text)
        payload = {
            "sample_id": case.sample_id,
            "summary_text": case.summary_text,
            "technique_ids": case.technique_ids,
            "malware_category": case.malware_category,
            "stix_bundle_json": case.stix_bundle_json,
            "created_at": case.created_at.astimezone(UTC).isoformat(),
            # Quality signals persisted so retroactive purges and dashboards
            # can identify low-signal runs even after the write-time LTM-01
            # gate (audit 2026-05-17, follow-up 2026-05-19).
            "corroborated_count": case.corroborated_count,
            "total_techniques": case.total_techniques or len(case.technique_ids),
            "has_analyst_errors": case.has_analyst_errors,
        }

        self._client.upsert(
            collection_name=self._collection,
            points=[PointStruct(id=point_id, vector=vector, payload=payload)],
            wait=True,  # Ensure the point is committed before returning
        )
        logger.info(
            "QdrantStore.store: upserted sample_id=%s (point_id=%d).",
            case.sample_id,
            point_id,
        )

    def retrieve(
        self,
        query: str,
        top_k: int = 3,
        exclude_sample_id: str | None = None,
    ) -> list[StoredCase]:
        """Return the top_k most similar cases from Qdrant.

        Args:
            query:  Free-text search query (e.g., concatenated ISR claim text).
            top_k:  Maximum number of results to return.
            exclude_sample_id: Optional sha256 of the current sample. Hits
                with the same ``sample_id`` are filtered out so a fresh
                analysis cannot feed its own previous run back into itself
                as a "weighted prior" (audit 2026-05-17, LTM-01).

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

        vector = encode(query)
        # Fetch a few extra rows when we need to filter out the current
        # sample — this keeps us at ``top_k`` results after exclusion.
        fetch_k = top_k + 1 if exclude_sample_id else top_k
        # query_points() is the current API (qdrant-client >= 1.9);
        # search() is deprecated in newer versions.
        response = self._client.query_points(
            collection_name=self._collection,
            query=vector,
            limit=fetch_k,
            with_payload=True,
        )
        hits = response.points

        results: list[StoredCase] = []
        skipped_self = 0
        for hit in hits:
            p = hit.payload or {}
            if exclude_sample_id and p.get("sample_id") == exclude_sample_id:
                skipped_self += 1
                continue
            try:
                results.append(
                    StoredCase(
                        sample_id=p["sample_id"],
                        summary_text=p.get("summary_text", ""),
                        technique_ids=p.get("technique_ids", []),
                        malware_category=p.get("malware_category", "UNKNOWN"),
                        stix_bundle_json=p.get("stix_bundle_json", ""),
                        corroborated_count=int(p.get("corroborated_count", 0) or 0),
                        total_techniques=int(p.get("total_techniques", 0) or 0),
                        has_analyst_errors=bool(p.get("has_analyst_errors", False)),
                    )
                )
            except (KeyError, TypeError) as exc:
                logger.warning("QdrantStore.retrieve: skipping malformed payload: %s", exc)
            if len(results) >= top_k:
                break
        if skipped_self:
            logger.info(
                "QdrantStore.retrieve: skipped %d self-match(es) for sample_id=%s.",
                skipped_self,
                exclude_sample_id[:16] + "..." if exclude_sample_id else "?",
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
        try:
            info = self._client.get_collection(self._collection)
            return int(info.points_count or 0)
        except Exception as exc:
            logger.warning("QdrantStore.count() error: %s", exc)
            return 0

    def clear(self) -> None:
        """Delete and recreate the Qdrant collection (removes all points).

        After clear(), the collection still exists but is empty. The next
        store() call will recreate the vector config if needed.
        """
        if self._collection_exists():
            self._client.delete_collection(collection_name=self._collection)
            self._collection_ready = False
            logger.info("QdrantStore.clear: collection '%s' deleted.", self._collection)

    def purge_low_quality(
        self,
        *,
        max_total_techniques: int = 1,
        require_uncorroborated: bool = True,
        include_analyst_errors: bool = True,
    ) -> int:
        """Delete low-quality stored cases from Qdrant.

        Scrolls the collection with a small page size, evaluates each point
        against the LTM-01 quality gate, and issues a single ``delete``
        for the offending IDs. Older points that pre-date the quality-signal
        payload (no ``total_techniques`` field) are treated as 0 — they are
        purged by default. Operators can disable that branch by passing
        ``max_total_techniques=-1``.
        """
        if not self._collection_exists():
            return 0

        # qdrant-client typechecks PointIdsList against the exact union
        # ``list[int | str | UUID]`` — narrowing this is a mypy invariance
        # error even though we only ever push ints. Match the lib's type.
        to_delete: list[int | str | uuid.UUID] = []
        offset: Any = None
        while True:
            try:
                points, offset = self._client.scroll(
                    collection_name=self._collection,
                    limit=256,
                    offset=offset,
                    with_payload=True,
                    with_vectors=False,
                )
            except Exception as exc:
                logger.warning("QdrantStore.purge_low_quality: scroll failed (%s).", exc)
                break

            for pt in points:
                payload = pt.payload or {}
                if include_analyst_errors and bool(payload.get("has_analyst_errors", False)):
                    to_delete.append(pt.id)
                    continue
                if max_total_techniques < 0:
                    continue
                total = int(payload.get("total_techniques", 0) or 0)
                corroborated = int(payload.get("corroborated_count", 0) or 0)
                if total > max_total_techniques:
                    continue
                if require_uncorroborated and corroborated > 0:
                    continue
                to_delete.append(pt.id)

            if offset is None:
                break

        if to_delete:
            from qdrant_client.models import PointIdsList

            self._client.delete(
                collection_name=self._collection,
                points_selector=PointIdsList(points=to_delete),
                wait=True,
            )
            logger.info(
                "QdrantStore.purge_low_quality: removed %d low-quality case(s).",
                len(to_delete),
            )
        return len(to_delete)

    def __repr__(self) -> str:
        return (
            f"QdrantStore(url={self._url!r}, collection={self._collection!r}, count={self.count()})"
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
        """Create the collection if needed and validate its vector dimension."""
        if self._collection_ready:
            return

        if not self._collection_exists():
            self._client.create_collection(
                collection_name=self._collection,
                vectors_config=VectorParams(
                    size=EMBED_DIM,
                    distance=Distance.COSINE,
                ),
            )
            logger.info(
                "QdrantStore: created collection '%s' (dim=%d, distance=COSINE).",
                self._collection,
                EMBED_DIM,
            )
        else:
            # Validate that an existing collection's vector dimension matches
            # our embedding size — silent dim mismatch causes upserts to fail
            # asynchronously later, which is much harder to debug.
            try:
                info = self._client.get_collection(self._collection)
                vectors = getattr(getattr(info, "config", None), "params", None)
                vp = getattr(vectors, "vectors", None) if vectors else None
                actual = getattr(vp, "size", None) if vp else None
                if actual is not None and actual != EMBED_DIM:
                    raise QdrantNotAvailableError(
                        f"QdrantStore: collection '{self._collection}' has vector dim "
                        f"{actual} but client expected {EMBED_DIM}. Delete the "
                        "collection or point at a fresh one — likely a leftover from "
                        "the pre-fastembed (dim=512) schema."
                    )
            except QdrantNotAvailableError:
                raise
            except Exception as exc:
                logger.debug("QdrantStore: collection dim probe failed (%s); continuing.", exc)

        self._collection_ready = True

"""FunctionHashStore — exact-match function-hash attribution backend (Qdrant).

A deterministic attribution tier that complements the semantic ``QdrantStore``
long-term memory. Where ``QdrantStore`` does *fuzzy* prose retrieval (BGE
embeddings over ISR summaries), this store does *exact* matching: it keeps one
point per (sample, function) holding the function's normalized-opcode hash and
the malware family the sample was attributed to. When a new sample shares one
of those opcode hashes, that is a near-certain code-reuse link to the family —
a far higher-precision signal than text similarity.

Design notes:

- **One point per (sample_id, func_hash).** The point ID is a stable uint64
  derived from ``"{sample_id}|{func_hash}"`` so re-analyzing a sample replaces
  its points in place instead of duplicating them.
- **No semantic vectors.** Qdrant requires a vector, so each point carries a
  1-dim dummy vector with DOT distance; we never run vector search, only
  payload-filtered scrolls (``func_hash`` MatchAny). A keyword payload index on
  ``func_hash`` keeps lookups fast as the corpus grows.
- **Fail-safe.** Every public method swallows backend errors and degrades to a
  no-op / empty result, so an attribution-store hiccup never breaks analysis.
- **Tiny-function caveat is the caller's job.** This store matches whatever
  hashes it is given; the caller must filter out low-instruction-count stubs
  (which collide across unrelated binaries) before upserting/matching.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from maljan.core.exceptions import MemoryStoreError
from maljan.core.logger import logger

# 1-dim dummy vector: we only ever filter by payload, never search by vector.
_DUMMY_VECTOR: list[float] = [1.0]
# Cap the MatchAny list size per scroll so a 1000-function binary does not
# build a single pathological filter.
_MATCH_BATCH = 256


class FunctionHashStoreUnavailableError(MemoryStoreError, ImportError):
    """Raised when qdrant-client is not installed.

    Inherits ImportError too so legacy ``except ImportError`` callers still work.
    """


@dataclass(frozen=True)
class FunctionMatch:
    """A single shared function between the query sample and a stored sample."""

    func_hash: str
    family: str
    sample_id: str
    func_name: str


def _point_id(sample_id: str, func_hash: str) -> int:
    """Return a stable uint64 point ID for a (sample_id, func_hash) pair."""
    digest = hashlib.sha256(f"{sample_id}|{func_hash}".encode()).digest()
    return int.from_bytes(digest[:8], "little")


class FunctionHashStore:
    """Qdrant-backed exact-match store for function-hash attribution.

    Usage:
        store = FunctionHashStore(url="http://localhost:6333",
                                  collection="maljan_function_hashes_v1")
        store.upsert_sample(sample_id, family, [(func_hash, func_name), ...])
        matches = store.match([h1, h2, ...], exclude_sample_id=sample_id)
    """

    def __init__(
        self,
        url: str,
        collection: str = "maljan_function_hashes_v1",
        api_key: str | None = None,
    ) -> None:
        try:
            from qdrant_client import QdrantClient
        except ImportError as exc:  # pragma: no cover - exercised via integration
            raise FunctionHashStoreUnavailableError(
                "qdrant-client is required for FunctionHashStore.\n"
                "Install with: uv add qdrant-client\n"
                "Start Qdrant: docker run -p 6333:6333 qdrant/qdrant"
            ) from exc

        self._url = url
        self._collection = collection
        self._client: Any = QdrantClient(url=url, api_key=api_key)
        self._collection_ready = False
        logger.info("FunctionHashStore initialized (url=%s, collection=%s).", url, collection)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def upsert_sample(self, sample_id: str, family: str, functions: list[tuple[str, str]]) -> int:
        """Upsert one point per function for ``sample_id`` under ``family``.

        ``functions`` is a list of ``(func_hash, func_name)`` tuples (already
        filtered by the caller for meaningful instruction counts). Returns the
        number of points written; 0 on any failure (fail-safe).
        """
        if not functions:
            return 0
        try:
            from qdrant_client.models import PointStruct

            self._ensure_collection()
            seen: set[str] = set()
            points = []
            for func_hash, func_name in functions:
                if not func_hash or func_hash in seen:
                    continue
                seen.add(func_hash)
                points.append(
                    PointStruct(
                        id=_point_id(sample_id, func_hash),
                        vector=_DUMMY_VECTOR,
                        payload={
                            "func_hash": func_hash,
                            "family": family,
                            "sample_id": sample_id,
                            "func_name": func_name,
                        },
                    )
                )
            if not points:
                return 0
            self._client.upsert(collection_name=self._collection, points=points, wait=True)
            logger.info(
                "FunctionHashStore: upserted %d function hashes for sample_id=%s (family=%s).",
                len(points),
                sample_id[:16],
                family,
            )
            return len(points)
        except Exception as exc:  # fail-safe: never break the caller
            logger.warning("FunctionHashStore.upsert_sample failed (%s); skipped.", exc)
            return 0

    def match(
        self,
        hashes: list[str],
        exclude_sample_id: str | None = None,
    ) -> list[FunctionMatch]:
        """Return stored functions whose hash is in ``hashes``.

        Filters out points belonging to ``exclude_sample_id`` so a re-analysis
        cannot match its own previous run. Empty list on any failure.
        """
        candidates = [h for h in dict.fromkeys(hashes) if h]
        if not candidates or not self._collection_exists():
            return []
        try:
            from qdrant_client.models import FieldCondition, Filter, MatchAny

            results: list[FunctionMatch] = []
            for start in range(0, len(candidates), _MATCH_BATCH):
                batch = candidates[start : start + _MATCH_BATCH]
                flt = Filter(must=[FieldCondition(key="func_hash", match=MatchAny(any=batch))])
                offset: Any = None
                while True:
                    points, offset = self._client.scroll(
                        collection_name=self._collection,
                        scroll_filter=flt,
                        limit=256,
                        offset=offset,
                        with_payload=True,
                        with_vectors=False,
                    )
                    for pt in points:
                        p = pt.payload or {}
                        sid = p.get("sample_id", "")
                        if exclude_sample_id and sid == exclude_sample_id:
                            continue
                        results.append(
                            FunctionMatch(
                                func_hash=p.get("func_hash", ""),
                                family=p.get("family", "UNKNOWN"),
                                sample_id=sid,
                                func_name=p.get("func_name", ""),
                            )
                        )
                    if offset is None:
                        break
            return results
        except Exception as exc:  # fail-safe
            logger.warning("FunctionHashStore.match failed (%s); returning no matches.", exc)
            return []

    def count(self) -> int:
        """Return the total number of stored function-hash points (0 on error)."""
        if not self._collection_exists():
            return 0
        try:
            info = self._client.get_collection(self._collection)
            return int(info.points_count or 0)
        except Exception as exc:
            logger.warning("FunctionHashStore.count error: %s", exc)
            return 0

    def __repr__(self) -> str:
        return f"FunctionHashStore(url={self._url!r}, collection={self._collection!r})"

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _collection_exists(self) -> bool:
        try:
            existing = {c.name for c in self._client.get_collections().collections}
            return self._collection in existing
        except Exception as exc:
            logger.warning("FunctionHashStore._collection_exists error: %s", exc)
            return False

    def _ensure_collection(self) -> None:
        """Create the collection + ``func_hash`` keyword index if needed."""
        if self._collection_ready:
            return
        from qdrant_client.models import Distance, PayloadSchemaType, VectorParams

        if not self._collection_exists():
            self._client.create_collection(
                collection_name=self._collection,
                # 1-dim dummy vector with DOT distance — payload-filter only,
                # never searched, so COSINE zero-norm issues do not apply.
                vectors_config=VectorParams(size=1, distance=Distance.DOT),
            )
            try:
                self._client.create_payload_index(
                    collection_name=self._collection,
                    field_name="func_hash",
                    field_schema=PayloadSchemaType.KEYWORD,
                )
            except Exception as exc:  # index is an optimization, not required
                logger.debug("FunctionHashStore: func_hash index skipped (%s).", exc)
            logger.info(
                "FunctionHashStore: created collection '%s' (1-dim DOT, func_hash index).",
                self._collection,
            )
        self._collection_ready = True

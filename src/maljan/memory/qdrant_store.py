"""QdrantStore — Qdrant vector database backend for long-term memory.

Phase 5 production backend. Requires:
  - qdrant-client Python package: uv add qdrant-client
  - Running Qdrant instance: docker run -p 6333:6333 qdrant/qdrant

Architecture notes:
  - Uses Qdrant's dense vector search with a simple bag-of-words embedding
    for Phase 5. A future upgrade path is to swap _embed() for a proper
    sentence-transformer or OpenAI embedding model.
  - The collection is auto-created on first store() call if it does not exist.
  - StoredCase fields are stored as Qdrant payload so they can be
    reconstructed without a separate database.

Current implementation status:
  QdrantStore is a STUB — the class is importable and raises a clear
  ImportError at instantiation when qdrant-client is not installed. When
  qdrant-client IS installed, store() and retrieve() raise NotImplementedError
  with guidance. This enables the container and config machinery to reference
  QdrantStore without requiring the package at import time.

  To fully implement QdrantStore, replace the NotImplementedError bodies with
  actual qdrant_client calls following the outline comments below.
"""

from __future__ import annotations

from maljan.core.logger import logger
from maljan.memory.long_term_memory import StoredCase


class QdrantNotAvailableError(ImportError):
    """Raised when qdrant-client is not installed."""


class QdrantStore:
    """Qdrant-backed MemoryStore for production long-term case retrieval.

    Usage (after `uv add qdrant-client` and starting Qdrant):
        store = QdrantStore(url="http://localhost:6333", collection="maljan_cases")
        store.store(case)
        results = store.retrieve("ransomware encryption C2", top_k=3)

    Args:
        url:        Qdrant server URL (e.g., "http://localhost:6333").
        collection: Name of the Qdrant collection to use. Auto-created on
                    first store() call when it does not exist.
    """

    # Embedding vector size for the simple bag-of-words stub.
    # Replace with the actual model dimension when using real embeddings.
    _VECTOR_SIZE = 128

    def __init__(self, url: str, collection: str = "maljan_cases") -> None:
        try:
            import qdrant_client  # noqa: F401
        except ImportError as exc:
            raise QdrantNotAvailableError(
                "qdrant-client is required for QdrantStore. "
                "Install with: uv add qdrant-client\n"
                "Then start Qdrant: docker run -p 6333:6333 qdrant/qdrant"
            ) from exc

        self._url = url
        self._collection = collection
        logger.info(
            "QdrantStore initialized (url=%s, collection=%s). "
            "Note: store()/retrieve() are stubs — implement with qdrant_client calls.",
            url,
            collection,
        )

    def store(self, case: StoredCase) -> None:
        """Upsert a StoredCase into the Qdrant collection.

        Implementation outline:
            from qdrant_client import QdrantClient
            from qdrant_client.models import PointStruct, VectorParams, Distance

            client = QdrantClient(url=self._url)
            # Auto-create collection if needed:
            #   client.recreate_collection(
            #       collection_name=self._collection,
            #       vectors_config=VectorParams(size=EMBED_DIM, distance=Distance.COSINE),
            #   )
            # Embed the summary_text:
            #   vector = self._embed(case.summary_text)
            # Upsert:
            #   client.upsert(
            #       collection_name=self._collection,
            #       points=[PointStruct(
            #           id=_stable_id(case.sample_id),
            #           vector=vector,
            #           payload={
            #               "sample_id": case.sample_id,
            #               "summary_text": case.summary_text,
            #               "technique_ids": case.technique_ids,
            #               "malware_category": case.malware_category,
            #               "stix_bundle_json": case.stix_bundle_json,
            #               "created_at": case.created_at.isoformat(),
            #           },
            #       )],
            #   )
        """
        raise NotImplementedError(  # noqa: TRY003
            "QdrantStore.store() is not yet implemented. "
            "Follow the outline comment in the method body to add qdrant_client calls."
        )

    def retrieve(self, query: str, top_k: int = 3) -> list[StoredCase]:
        """Retrieve the top_k most similar cases from Qdrant.

        Implementation outline:
            from qdrant_client import QdrantClient

            client = QdrantClient(url=self._url)
            vector = self._embed(query)
            hits = client.search(
                collection_name=self._collection,
                query_vector=vector,
                limit=top_k,
            )
            return [
                StoredCase(
                    sample_id=hit.payload["sample_id"],
                    summary_text=hit.payload["summary_text"],
                    technique_ids=hit.payload.get("technique_ids", []),
                    malware_category=hit.payload.get("malware_category", "UNKNOWN"),
                    stix_bundle_json=hit.payload.get("stix_bundle_json", ""),
                )
                for hit in hits
            ]
        """
        raise NotImplementedError(  # noqa: TRY003
            "QdrantStore.retrieve() is not yet implemented. "
            "Follow the outline comment in the method body to add qdrant_client calls."
        )

    def count(self) -> int:
        """Return the total number of points in the Qdrant collection.

        Implementation outline:
            client = QdrantClient(url=self._url)
            info = client.get_collection(self._collection)
            return info.points_count
        """
        raise NotImplementedError(  # noqa: TRY003
            "QdrantStore.count() is not yet implemented."
        )

    def clear(self) -> None:
        """Delete and recreate the Qdrant collection (removes all points).

        Implementation outline:
            client = QdrantClient(url=self._url)
            client.delete_collection(self._collection)
        """
        raise NotImplementedError(  # noqa: TRY003
            "QdrantStore.clear() is not yet implemented."
        )

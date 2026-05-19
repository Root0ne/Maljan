"""InMemoryStore — pure-Python long-term memory backend.

Phase 5 default backend for ephemeral / single-run analyses. Uses the shared
``maljan.memory.embeddings`` module so the similarity model matches whatever
``QdrantStore`` would use in production:

- When fastembed is installed: semantic ``BAAI/bge-small-en-v1.5`` embeddings
  (384-dim, cosine similarity). "ransomware encrypts files" and
  "crypto-locker scrambles the disk" score similarly.
- When fastembed is missing: deterministic BoW projection (~lexical match
  only). Logged loudly so operators notice.

Limitations vs. Qdrant:

- O(n) cosine scan on retrieve — fine for <1000 cases, degrades at scale.
- No persistence across process restarts (RAM only).

When to upgrade to QdrantStore:

- Store grows beyond ~500 cases.
- Persistence across analysis sessions is required.
- Multiple processes share the same memory base.
"""

from __future__ import annotations

from maljan.memory.embeddings import cosine, encode
from maljan.memory.long_term_memory import StoredCase


class InMemoryStore:
    """Pure-Python MemoryStore implementation backed by semantic embeddings.

    Thread safety: NOT thread-safe. For single-threaded pipelines this is
    fine. If the store is shared across threads, wrap with a threading.Lock.

    Usage:
        store = InMemoryStore()
        store.store(StoredCase(sample_id="s1", summary_text="ransomware ..."))
        results = store.retrieve("encryption C2 beacon", top_k=3)
    """

    def __init__(self) -> None:
        # Each entry: (case, embedding_vector). Embeddings are cached at
        # store-time so retrieve() never recomputes them.
        self._cases: list[tuple[StoredCase, list[float]]] = []

    def store(self, case: StoredCase) -> None:
        """Persist a case, replacing any existing entry with the same sample_id.

        Upsert semantics ensure repeated analysis runs on the same sample do
        not cause unbounded store growth.
        """
        self._cases = [(c, v) for c, v in self._cases if c.sample_id != case.sample_id]
        self._cases.append((case, encode(case.summary_text)))

    def retrieve(
        self,
        query: str,
        top_k: int = 3,
        exclude_sample_id: str | None = None,
    ) -> list[StoredCase]:
        """Return the top_k stored cases most similar to the query text.

        Args:
            query:  Free-text search query (e.g., concatenated ISR claim text).
            top_k:  Maximum cases to return. May return fewer when the store
                    contains fewer than top_k entries.
            exclude_sample_id: When provided, drop hits whose ``sample_id``
                equals this value (audit 2026-05-17, LTM-01). Stops a
                fresh analysis from feeding its own past run back to the
                judge as a "weighted prior".

        Returns:
            Ordered list of StoredCase objects, descending by similarity score.
            Empty list when store is empty or query is blank.
        """
        if not self._cases or not query.strip():
            return []

        query_vec = encode(query)
        scored: list[tuple[float, StoredCase]] = [
            (cosine(query_vec, vec), case)
            for case, vec in self._cases
            if not exclude_sample_id or case.sample_id != exclude_sample_id
        ]
        scored.sort(key=lambda pair: pair[0], reverse=True)
        return [case for _, case in scored[:top_k]]

    def count(self) -> int:
        """Return the number of cases currently in the store."""
        return len(self._cases)

    def clear(self) -> None:
        """Remove all stored cases."""
        self._cases.clear()

    def purge_low_quality(
        self,
        *,
        max_total_techniques: int = 1,
        require_uncorroborated: bool = True,
        include_analyst_errors: bool = True,
    ) -> int:
        """Drop low-quality cases per the LTM-01 audit gate.

        See ``MemoryStore.purge_low_quality`` for the contract. The
        in-memory implementation walks the case list and rebuilds it,
        keeping only entries that pass the gate.
        """

        def _low_quality(case: StoredCase) -> bool:
            if include_analyst_errors and case.has_analyst_errors:
                return True
            if max_total_techniques < 0:
                return False
            if case.total_techniques > max_total_techniques:
                return False
            if require_uncorroborated and case.corroborated_count > 0:
                return False
            return True

        before = len(self._cases)
        self._cases = [(c, v) for c, v in self._cases if not _low_quality(c)]
        return before - len(self._cases)

    def __repr__(self) -> str:
        return f"InMemoryStore(count={self.count()})"

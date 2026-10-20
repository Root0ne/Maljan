"""InMemoryStore — pure-Python long-term memory backend.

Default backend for ephemeral / single-run analyses. Uses the shared
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

from maljan.memory.embeddings import cosine, encode_with_backend, model_backend_id
from maljan.memory.long_term_memory import MemoryStoreDefaults, StoredCase, owner_key


class InMemoryStore(MemoryStoreDefaults):
    """Pure-Python MemoryStore implementation backed by semantic embeddings.

    Thread safety: NOT thread-safe. For single-threaded pipelines this is
    fine. If the store is shared across threads, wrap with a threading.Lock.

    Usage:
        store = InMemoryStore()
        store.store(StoredCase(sample_id="s1", summary_text="ransomware ..."))
        results = store.retrieve("encryption C2 beacon", top_k=3)
    """

    keeps_owners = True

    def __init__(self) -> None:
        # Each entry: (case, embedding_vector, backend). Embeddings are cached
        # at store-time so retrieve() never recomputes them; the backend that
        # produced each is kept beside it, because a bag-of-words vector and a
        # model vector are not comparable.
        self._cases: list[tuple[StoredCase, list[float], str]] = []

    def store(self, case: StoredCase) -> None:
        """Persist a case, replacing any existing entry with the same sample_id and owner.

        Upsert semantics ensure repeated analysis runs on the same sample do
        not cause unbounded store growth. Two owners' cases of one sample are
        two entries.
        """
        owner = owner_key(case.owner)
        self._cases = [
            entry
            for entry in self._cases
            if not (entry[0].sample_id == case.sample_id and owner_key(entry[0].owner) == owner)
        ]
        vector, backend = encode_with_backend(case.summary_text)
        self._cases.append((case, vector, backend))

    def _vector_in(self, index: int, backend: str) -> list[float]:
        """Entry ``index``'s vector in ``backend``'s space, embedding its text again when needed.

        A vector made by another backend is never compared with the query's:
        the case's text is embedded again by the query's backend, and kept
        when that is the model.
        """
        case, vector, made_by = self._cases[index]
        if made_by == backend:
            return vector
        again, again_by = encode_with_backend(case.summary_text)
        if again_by == model_backend_id():
            self._cases[index] = (case, again, again_by)
        return again if again_by == backend else []

    def retrieve(
        self,
        query: str,
        top_k: int = 3,
        exclude_sample_id: str | None = None,
        owner: str | None = None,
    ) -> list[StoredCase]:
        """Return the top_k stored cases most similar to the query text.

        Args:
            query:  Free-text search query (e.g., concatenated ISR claim text).
            top_k:  Maximum cases to return. May return fewer when the store
                    contains fewer than top_k entries.
            exclude_sample_id: When provided, drop hits whose ``sample_id``
                equals this value. Stops a
                fresh analysis from feeding its own past run back to the
                judge as a "weighted prior".
            owner: Only this owner's cases; ``None`` reads the unscoped ones
                (``long_term_memory.recall``).

        Returns:
            Ordered list of StoredCase objects, descending by similarity score.
            Empty list when store is empty or query is blank.
        """
        if not self._cases or not query.strip():
            return []

        scope = owner_key(owner)
        query_vec, backend = encode_with_backend(query)
        scored: list[tuple[float, StoredCase]] = []
        for index, (case, _vec, _by) in enumerate(self._cases):
            if exclude_sample_id and case.sample_id == exclude_sample_id:
                continue
            if owner_key(case.owner) != scope:
                continue
            scored.append((cosine(query_vec, self._vector_in(index, backend)), case))
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
        dry_run: bool = False,
    ) -> int:
        """Drop low-quality cases per the write-time quality gate.

        See ``MemoryStore.purge_low_quality`` for the contract. The
        in-memory implementation walks the case list and rebuilds it,
        keeping only entries that pass the gate; ``dry_run`` only counts.
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

        if dry_run:
            return sum(1 for entry in self._cases if _low_quality(entry[0]))
        before = len(self._cases)
        self._cases = [entry for entry in self._cases if not _low_quality(entry[0])]
        return before - len(self._cases)

    def __repr__(self) -> str:
        return f"InMemoryStore(count={self.count()})"

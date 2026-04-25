"""InMemoryStore — pure-Python long-term memory backend.

Phase 5 default backend. Uses word-count cosine similarity for retrieval —
no external dependencies, no network access, no Docker required.

Similarity model:
  - Tokenize: lowercase split on whitespace.
  - Represent each text as a term-frequency (Counter) vector.
  - Cosine similarity: dot(a, b) / (|a| * |b|).
  - Simple, deterministic, reproducible — correct for tens of stored cases.

Limitations vs. Qdrant/embedding models:
  - No semantic understanding: "encryption" and "cipher" are unrelated tokens.
  - O(n) scan on retrieve — fine for <1000 cases, degrades at large scale.
  - No persistence across process restarts.

When to upgrade to QdrantStore:
  - Store grows beyond ~500 cases.
  - Semantic similarity matters (same behavior, different terminology).
  - Persistence across analysis sessions is required.
"""

from __future__ import annotations

import math
from collections import Counter

from maljan.memory.long_term_memory import StoredCase

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _tokenize(text: str) -> list[str]:
    """Lowercase whitespace-split tokenizer."""
    return text.lower().split()


def _term_freq_vector(text: str) -> Counter:
    """Return a term-frequency Counter for the input text."""
    return Counter(_tokenize(text))


def _cosine_similarity(a: Counter, b: Counter) -> float:
    """Compute cosine similarity between two term-frequency vectors.

    Returns 0.0 for zero-length vectors (avoids division by zero).
    """
    if not a or not b:
        return 0.0
    dot = sum(a[w] * b[w] for w in a if w in b)
    norm_a = math.sqrt(sum(v * v for v in a.values()))
    norm_b = math.sqrt(sum(v * v for v in b.values()))
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return dot / (norm_a * norm_b)


# ---------------------------------------------------------------------------
# InMemoryStore
# ---------------------------------------------------------------------------


class InMemoryStore:
    """Pure-Python MemoryStore implementation with cosine similarity retrieval.

    Thread safety: NOT thread-safe. For single-threaded pipelines this is
    fine. If the store is shared across threads, wrap with a threading.Lock.

    Usage:
        store = InMemoryStore()
        store.store(StoredCase(sample_id="s1", summary_text="ransomware ..."))
        results = store.retrieve("encryption C2 beacon", top_k=3)
    """

    def __init__(self) -> None:
        self._cases: list[StoredCase] = []

    def store(self, case: StoredCase) -> None:
        """Persist a case, replacing any existing entry with the same sample_id.

        Upsert semantics ensure repeated analysis runs on the same sample do
        not cause unbounded store growth.
        """
        # Remove stale entry if it exists (upsert)
        self._cases = [c for c in self._cases if c.sample_id != case.sample_id]
        self._cases.append(case)

    def retrieve(self, query: str, top_k: int = 3) -> list[StoredCase]:
        """Return the top_k stored cases most similar to the query text.

        Args:
            query:  Free-text search query (e.g., concatenated ISR claim text).
            top_k:  Maximum cases to return. May return fewer when the store
                    contains fewer than top_k entries.

        Returns:
            Ordered list of StoredCase objects, descending by similarity score.
            Empty list when store is empty or query is blank.
        """
        if not self._cases or not query.strip():
            return []

        query_vec = _term_freq_vector(query)
        scored: list[tuple[float, StoredCase]] = []
        for case in self._cases:
            score = _cosine_similarity(query_vec, _term_freq_vector(case.summary_text))
            scored.append((score, case))

        scored.sort(key=lambda pair: pair[0], reverse=True)
        return [case for _, case in scored[:top_k]]

    def count(self) -> int:
        """Return the number of cases currently in the store."""
        return len(self._cases)

    def clear(self) -> None:
        """Remove all stored cases."""
        self._cases.clear()

    def __repr__(self) -> str:
        return f"InMemoryStore(count={self.count()})"

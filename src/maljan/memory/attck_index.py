"""In-memory TF-IDF index over MITRE ATT&CK technique descriptions.

Provides two capabilities:
  1. Technique lookup by exact ID (O(1) dict).
  2. Semantic similarity search by free-text behavioral description (TF-IDF cosine).

Design notes:
  - Pure Python + stdlib: no numpy, scipy, or vector DB required at development time.
  - The index is built once and kept in memory. For production scale, this module's
    interface is intentionally compatible with a Qdrant backend (Phase 5).
  - Thread-safety: the index is read-only after build() — safe for concurrent access.

Usage:
    index = ATTCKIndex.from_loader()          # download + build (one-time)
    index = ATTCKIndex.from_techniques(list)  # for testing with fixture data

    tech = index.get_by_id("T1055")
    results = index.search("process injection via WriteProcessMemory", top_k=5)
    validation = index.validate_technique("T1055.001", "WriteProcessMemory API call")
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass

from maljan.core.logger import logger
from maljan.memory.attck_loader import ATTCKTechnique, load_attck_bundle

# Stopwords to exclude from TF-IDF tokens (minimal set for security domain)
_STOPWORDS = frozenset(
    {
        "a",
        "an",
        "the",
        "and",
        "or",
        "of",
        "to",
        "in",
        "is",
        "are",
        "was",
        "were",
        "be",
        "been",
        "being",
        "have",
        "has",
        "had",
        "do",
        "does",
        "did",
        "will",
        "would",
        "could",
        "should",
        "may",
        "might",
        "shall",
        "can",
        "this",
        "that",
        "these",
        "those",
        "it",
        "its",
        "with",
        "for",
        "on",
        "at",
        "by",
        "from",
        "as",
        "into",
        "through",
        "during",
        "including",
        "until",
        "against",
        "between",
        "about",
        "which",
        "when",
        "where",
        "how",
        "all",
        "also",
        "such",
        "other",
        "than",
        "then",
        "so",
        "but",
        "not",
        "no",
        "if",
        "use",
        "used",
        "using",
    }
)


@dataclass
class SearchResult:
    """A single ATT&CK technique returned by a similarity search."""

    technique: ATTCKTechnique
    score: float  # TF-IDF cosine similarity (0.0–1.0)
    rank: int  # 1-based rank in the result set


class ATTCKIndex:
    """In-memory TF-IDF index for MITRE ATT&CK technique retrieval.

    Attributes:
        techniques: All indexed techniques, keyed by technique_id.
    """

    def __init__(self) -> None:
        self.techniques: dict[str, ATTCKTechnique] = {}
        self._idf: dict[str, float] = {}
        self._tf_vecs: dict[str, dict[str, float]] = {}  # technique_id → tf-idf vector
        self._built: bool = False

    # ------------------------------------------------------------------
    # Factory methods
    # ------------------------------------------------------------------

    @classmethod
    def from_loader(
        cls,
        force_refresh: bool = False,
    ) -> ATTCKIndex:
        """Build an index from the official MITRE ATT&CK STIX bundle.

        Downloads and caches the bundle on first call (~9 MB).
        Subsequent calls use the local cache.
        """
        techniques = load_attck_bundle(force_refresh=force_refresh)
        return cls.from_techniques(techniques)

    @classmethod
    def from_techniques(cls, techniques: list[ATTCKTechnique]) -> ATTCKIndex:
        """Build an index from a pre-parsed list of ATTCKTechnique objects.

        Primarily used in tests with fixture data to avoid network calls.
        """
        index = cls()
        index._build(techniques)
        return index

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_by_id(self, technique_id: str) -> ATTCKTechnique | None:
        """Return a technique by its exact ATT&CK ID (e.g., 'T1055')."""
        return self.techniques.get(technique_id.upper())

    def technique_exists(self, technique_id: str) -> bool:
        """Return True if the technique ID exists in the current ATT&CK release."""
        return technique_id.upper() in self.techniques

    def search(
        self,
        query: str,
        top_k: int = 5,
        filter_tactics: list[str] | None = None,
    ) -> list[SearchResult]:
        """Find the most relevant techniques for a behavioral description.

        Args:
            query: Free-text behavioral description, e.g. "process hollowing
                   via NtUnmapViewOfSection to evade AV detection".
            top_k: Maximum number of results to return.
            filter_tactics: If provided, restrict results to these MITRE tactic slugs
                            (e.g., ["defense-evasion", "execution"]).

        Returns:
            List of SearchResult ordered by descending TF-IDF cosine similarity.
        """
        if not self._built:
            raise RuntimeError("ATTCKIndex not built. Call from_loader() or from_techniques().")

        query_vec = self._tf_idf_vector(self._tokenize(query))
        scores: list[tuple[str, float]] = []

        for tid, doc_vec in self._tf_vecs.items():
            tech = self.techniques[tid]
            if filter_tactics:
                if not any(t in tech.tactic_phases for t in filter_tactics):
                    continue
            sim = _cosine_similarity(query_vec, doc_vec)
            if sim > 0.0:
                scores.append((tid, sim))

        scores.sort(key=lambda x: x[1], reverse=True)

        results: list[SearchResult] = []
        for rank, (tid, score) in enumerate(scores[:top_k], 1):
            results.append(SearchResult(technique=self.techniques[tid], score=score, rank=rank))

        return results

    def validate_and_score(
        self,
        technique_id: str,
        evidence_text: str,
    ) -> float:
        """Validate that a proposed TTP aligns with its ATT&CK definition.

        Computes a similarity score between the agent's evidence text and
        the official ATT&CK technique description. A low score indicates
        a potential hallucination or incorrect TTP mapping.

        Args:
            technique_id: The proposed MITRE ATT&CK ID (e.g., "T1055.001").
            evidence_text: The agent's evidence citation for this technique.

        Returns:
            Similarity score 0.0–1.0. Returns 0.0 if the technique ID is unknown.
        """
        tech = self.get_by_id(technique_id)
        if tech is None:
            logger.warning("ATT&CK validation: technique '%s' not found in index.", technique_id)
            return 0.0

        tech_vec = self._tf_vecs.get(technique_id.upper(), {})
        evidence_vec = self._tf_idf_vector(self._tokenize(evidence_text))
        score = _cosine_similarity(evidence_vec, tech_vec)

        logger.debug("ATT&CK validation: %s vs evidence → score=%.3f", technique_id, score)
        return score

    @property
    def size(self) -> int:
        """Number of indexed techniques."""
        return len(self.techniques)

    # ------------------------------------------------------------------
    # Private: index construction
    # ------------------------------------------------------------------

    def _build(self, techniques: list[ATTCKTechnique]) -> None:
        """Construct the TF-IDF index from a list of techniques."""
        self.techniques = {t.technique_id.upper(): t for t in techniques}

        # Step 1: tokenize every document
        tokenized_docs: dict[str, list[str]] = {
            tid: self._tokenize(tech.searchable_text) for tid, tech in self.techniques.items()
        }

        # Step 2: compute IDF over the corpus
        n_docs = len(tokenized_docs)
        doc_freq: Counter[str] = Counter()
        for tokens in tokenized_docs.values():
            doc_freq.update(set(tokens))

        self._idf = {
            term: math.log((n_docs + 1) / (df + 1)) + 1.0  # smoothed IDF
            for term, df in doc_freq.items()
        }

        # Step 3: compute TF-IDF vectors
        for tid, tokens in tokenized_docs.items():
            tf = Counter(tokens)
            doc_len = len(tokens) or 1
            self._tf_vecs[tid] = {
                term: (count / doc_len) * self._idf.get(term, 0.0) for term, count in tf.items()
            }

        self._built = True
        logger.info("ATTCKIndex built: %d techniques indexed.", n_docs)

    def _tf_idf_vector(self, tokens: list[str]) -> dict[str, float]:
        """Convert a token list to a TF-IDF weighted sparse vector."""
        tf = Counter(tokens)
        doc_len = len(tokens) or 1
        return {
            term: (count / doc_len) * self._idf.get(term, 0.0)
            for term, count in tf.items()
            if term in self._idf  # ignore OOV terms
        }

    @staticmethod
    def _tokenize(text: str) -> list[str]:
        """Lowercase, strip punctuation, remove stopwords."""
        tokens = re.findall(r"\b[a-z][a-z0-9_-]{1,}\b", text.lower())
        return [t for t in tokens if t not in _STOPWORDS]


# ------------------------------------------------------------------
# Pure-Python cosine similarity (no external deps)
# ------------------------------------------------------------------


def _cosine_similarity(a: dict[str, float], b: dict[str, float]) -> float:
    """Sparse cosine similarity between two TF-IDF vectors."""
    if not a or not b:
        return 0.0
    dot = sum(a[k] * b[k] for k in a if k in b)
    norm_a = math.sqrt(sum(v * v for v in a.values()))
    norm_b = math.sqrt(sum(v * v for v in b.values()))
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return dot / (norm_a * norm_b)

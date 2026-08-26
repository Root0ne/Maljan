"""Per-sample function-level RAG retrieval for the static analyst (TraceRAG).

findings-log §4 Item 2. A large binary is split by the chunker into
function-boundary ``TextChunk``s; feeding all of them to the LLM is wasteful and
buries the malicious core. TraceRAG [arXiv:2509.08865] instead retrieves the most
behavior-relevant functions by natural-language query. This module builds an
**ephemeral, per-sample, in-memory** cosine index over the static chunks (reusing
``embeddings.encode_batch`` + ``cosine`` — the same machinery as
``SemanticATTCKIndex``) and selects a focused subset via a fixed set of
malware-behavior queries.

No persistence, no Qdrant: the index lives for one analyst call and is discarded.
Off by default — gated behind ``PreprocessingConfig.static_function_rag_top_k``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from maljan.core.logger import logger
from maljan.memory import embeddings

if TYPE_CHECKING:
    from maljan.loaders.binary_chunker import TextChunk

# Behavior-focused NL queries bridging high-level intent -> low-level code (the
# TraceRAG retrieval bridge). Spans the common malware capability clusters so the
# union of per-query hits covers the malicious core without dumping every function.
BEHAVIOR_QUERIES: list[str] = [
    "process injection and executing code inside other processes",
    "persistence via registry run keys, services, scheduled tasks, or autostart",
    "command-and-control network beaconing and remote server connections",
    "credential theft and access to stored passwords or secrets",
    "anti-analysis, anti-debugging, sandbox and virtual-machine evasion",
    "file encryption, ransomware, or destructive wiping payloads",
    "obfuscation, packing, and string or payload decoding routines",
    "host and system discovery or reconnaissance",
]


class FunctionIndex:
    """Ephemeral in-memory cosine index over a single sample's static chunks."""

    def __init__(self) -> None:
        # (chunk, L2-normalized embedding) in original chunk order.
        self._entries: list[tuple[TextChunk, list[float]]] = []

    @classmethod
    def from_chunks(cls, chunks: list[TextChunk]) -> FunctionIndex:
        """Embed every chunk's content once (batch) and build the index."""
        idx = cls()
        if not chunks:
            return idx
        vectors = embeddings.encode_batch([c.content for c in chunks])
        idx._entries = list(zip(chunks, vectors, strict=True))
        return idx

    def __len__(self) -> int:
        return len(self._entries)

    def search(self, query: str, top_k: int = 5) -> list[tuple[TextChunk, float]]:
        """Return up to ``top_k`` (chunk, score) pairs ranked by cosine, score>0."""
        if not self._entries or not query.strip():
            return []
        qv = embeddings.encode(query)
        scored = [(chunk, embeddings.cosine(qv, vec)) for chunk, vec in self._entries]
        scored = [pair for pair in scored if pair[1] > 0.0]
        scored.sort(key=lambda p: p[1], reverse=True)
        return scored[:top_k]

    def select_for_queries(
        self,
        queries: list[str],
        top_k_per_query: int,
    ) -> list[TextChunk]:
        """Union of the top-k chunks across ``queries``, in original chunk order.

        Deduplicates by ``chunk.index`` so a function relevant to several queries
        is fed once. Returns ``[]`` when nothing scores above zero (the caller
        falls back to the full chunk set).
        """
        if top_k_per_query <= 0:
            return []
        chosen: dict[int, TextChunk] = {}
        for q in queries:
            for chunk, _score in self.search(q, top_k_per_query):
                chosen.setdefault(chunk.index, chunk)
        return [chosen[i] for i in sorted(chosen)]


def select_relevant_chunks(
    chunks: list[TextChunk],
    top_k_per_query: int,
    *,
    queries: list[str] | None = None,
) -> list[TextChunk]:
    """Build an ephemeral index over ``chunks`` and return the behavior-relevant
    subset. Never returns empty — falls back to the full set if retrieval finds
    nothing (so the analyst always has data). Convenience wrapper for the node.
    """
    if top_k_per_query <= 0 or not chunks:
        return chunks
    index = FunctionIndex.from_chunks(chunks)
    selected = index.select_for_queries(queries or BEHAVIOR_QUERIES, top_k_per_query)
    if not selected:
        logger.info("function-RAG: no chunk scored > 0; keeping all %d chunks.", len(chunks))
        return chunks
    logger.info(
        "function-RAG: selected %d/%d static chunks via %d behavior queries.",
        len(selected),
        len(chunks),
        len(queries or BEHAVIOR_QUERIES),
    )
    return selected

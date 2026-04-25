"""Domain-aware binary/text chunker for large malware analysis inputs.

Problem: LLM context windows have hard token limits. Raw PE static analysis
output, CAPEv2 sandbox JSON, and network capture summaries can easily exceed
8k–32k tokens for real-world malware samples. Without chunking, the pipeline
silently truncates data or crashes with context overflow errors.

Solution — Hierarchical Chunk-and-Summarize:
  1. The analyst's input text is split into overlapping chunks.
  2. Each chunk is analysed independently, producing a partial summary.
  3. Partial summaries are merged into a single consolidated context which the
     agent uses for ISR construction.

Chunking strategy selection:
  - STATIC domain  → function-boundary splitting (splits at Ghidra function
                      headers or decompiled section dividers when present;
                      falls back to sliding window if no markers found).
  - DYNAMIC domain → API-sequence splitting (splits at process/PID boundaries
                      or time-window markers; falls back to sliding window).
  - NETWORK domain → flow-session splitting (splits at flow delimiters;
                      falls back to sliding window).
  - ALL domains    → sliding-window fallback when domain-specific markers
                      are absent.

Token approximation: 1 token ≈ 4 characters (GPT-4 average). This avoids a
tiktoken dependency at the cost of ~10–15% estimation error, which is
acceptable for chunking decisions.

Usage:
    from maljan.loaders.binary_chunker import BinaryChunker
    from maljan.core.config import ChunkingConfig

    chunker = BinaryChunker(ChunkingConfig())
    chunks = chunker.chunk("static", long_text)
    for chunk in chunks:
        partial_summary = llm.invoke(chunk.content)
    merged = chunker.merge_summaries([...summaries...])
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum, auto

from maljan.core.config import ChunkingConfig
from maljan.core.logger import logger

# Characters per token approximation (GPT-4 average)
_CHARS_PER_TOKEN: int = 4


class ChunkStrategy(Enum):
    """Chunking strategy applied to produce a particular chunk set."""

    FUNCTION_BOUNDARY = auto()   # Static: splits at decompiler function headers
    API_SEQUENCE = auto()        # Dynamic: splits at PID/process boundaries
    FLOW_SESSION = auto()        # Network: splits at flow delimiters
    SLIDING_WINDOW = auto()      # Fallback: fixed-size overlapping windows


@dataclass
class TextChunk:
    """A single content chunk ready for LLM consumption.

    Attributes:
        index:        0-based position in the chunk sequence.
        total:        Total number of chunks in this split.
        strategy:     Which strategy produced this chunk.
        content:      The chunk text (includes overlap region from previous chunk).
        char_count:   Raw character count.
        token_estimate: Approximate token count (char_count // _CHARS_PER_TOKEN).
        domain:       Analysis domain this chunk belongs to.
    """

    index: int
    total: int
    strategy: ChunkStrategy
    content: str
    char_count: int
    token_estimate: int
    domain: str
    metadata: dict[str, object] = field(default_factory=dict)

    @property
    def is_first(self) -> bool:
        return self.index == 0

    @property
    def is_last(self) -> bool:
        return self.index == self.total - 1

    def to_prompt_header(self) -> str:
        """Return a header line injected before the chunk in the LLM prompt."""
        return (
            f"[CHUNK {self.index + 1}/{self.total} | "
            f"domain={self.domain} | strategy={self.strategy.name} | "
            f"~{self.token_estimate} tokens]"
        )


class BinaryChunker:
    """Domain-aware chunker that splits large analyst input into LLM-safe chunks.

    Args:
        config: ChunkingConfig from the application Settings.

    Usage:
        chunker = BinaryChunker(settings.chunking)
        chunks = chunker.chunk("static", long_decompiled_text)
        if len(chunks) == 1 and config.skip_if_fits:
            # data fits in one context — no chunking needed
    """

    # Static domain: Ghidra/Radare2/Binary Ninja function headers
    _STATIC_BOUNDARY_RE = re.compile(
        r"(?=^(?:(?:void|int|BOOL|DWORD|PVOID|HANDLE|HKEY|LPVOID)\s+\w+\s*\()"
        r"|^(?:#+\s*(?:Function|Subroutine|sub_[0-9a-fA-F]+)))",
        re.MULTILINE,
    )

    # Dynamic domain: CAPEv2/Cuckoo process separators
    _DYNAMIC_BOUNDARY_RE = re.compile(
        r"(?=^(?:PID:\s*\d+|Process:\s*\w+\.exe|--- Process|=+ Process))",
        re.MULTILINE,
    )

    # Network domain: flow / connection session dividers
    _NETWORK_BOUNDARY_RE = re.compile(
        r"(?=^(?:Flow \d+:|Connection \d+:|--- (?:TCP|UDP|HTTP|DNS) Flow|Session \d+:))",
        re.MULTILINE,
    )

    # Domain → (boundary regex, strategy enum)
    _DOMAIN_STRATEGIES: dict[str, tuple[re.Pattern[str], ChunkStrategy]] = {
        "static": (_STATIC_BOUNDARY_RE, ChunkStrategy.FUNCTION_BOUNDARY),
        "dynamic": (_DYNAMIC_BOUNDARY_RE, ChunkStrategy.API_SEQUENCE),
        "network": (_NETWORK_BOUNDARY_RE, ChunkStrategy.FLOW_SESSION),
    }

    def __init__(self, config: ChunkingConfig) -> None:
        self._config = config
        self._max_chars = config.max_tokens_per_chunk * _CHARS_PER_TOKEN
        self._overlap_chars = config.overlap_tokens * _CHARS_PER_TOKEN

    def chunk(self, domain: str, text: str) -> list[TextChunk]:
        """Split `text` into LLM-safe chunks for the given domain.

        When `config.skip_if_fits` is True and the text fits in a single
        chunk, a list with one chunk is returned immediately (no splitting).

        Args:
            domain: One of "static", "dynamic", "network", or any custom domain.
            text: The full parsed text from the data loader.

        Returns:
            Ordered list of TextChunk objects. Always has at least one element.
        """
        if not text:
            return [self._make_single_chunk(domain, "", ChunkStrategy.SLIDING_WINDOW)]

        if self._config.skip_if_fits and len(text) <= self._max_chars:
            logger.debug(
                "Chunking skipped for domain='%s': %d chars fits in limit (%d chars).",
                domain,
                len(text),
                self._max_chars,
            )
            return [self._make_single_chunk(domain, text, ChunkStrategy.SLIDING_WINDOW)]

        # Try domain-specific splitting first
        if domain in self._DOMAIN_STRATEGIES:
            pattern, strategy = self._DOMAIN_STRATEGIES[domain]
            segments = self._split_by_boundary(text, pattern)
            if len(segments) > 1:
                logger.info(
                    "Chunking domain='%s' using %s: %d boundary segments found.",
                    domain,
                    strategy.name,
                    len(segments),
                )
                return self._pack_segments(domain, segments, strategy)
            logger.debug(
                "No '%s' boundary markers found in domain='%s'. Falling back to sliding window.",
                strategy.name,
                domain,
            )

        # Sliding window fallback
        return self._sliding_window(domain, text)

    def merge_summaries(self, summaries: list[str], domain: str = "") -> str:
        """Merge partial chunk summaries into a consolidated analysis context.

        The merged text is still subject to max_tokens_per_chunk — if the
        summaries themselves are too large, a second-pass chunk could be run.
        This is not done automatically; callers decide whether to recurse.

        Args:
            summaries: One summary string per chunk, in order.
            domain: Optional domain label for the header.

        Returns:
            Single consolidated text ready for ISR construction.
        """
        if not summaries:
            return ""
        if len(summaries) == 1:
            return summaries[0]

        label = f" [{domain.upper()}]" if domain else ""
        header = f"=== Consolidated Analysis{label} ({len(summaries)} chunks) ==="
        parts = [header]
        for i, summary in enumerate(summaries, 1):
            parts.append(f"--- Chunk {i}/{len(summaries)} Summary ---\n{summary.strip()}")
        return "\n\n".join(parts)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _split_by_boundary(self, text: str, pattern: re.Pattern[str]) -> list[str]:
        """Split `text` at regex boundary positions, filtering empty segments."""
        parts = pattern.split(text)
        return [p for p in parts if p.strip()]

    def _pack_segments(
        self,
        domain: str,
        segments: list[str],
        strategy: ChunkStrategy,
    ) -> list[TextChunk]:
        """Pack variable-length segments into max-size bins with overlap.

        Segments that individually exceed max_chars are further split with
        the sliding window algorithm before packing.
        """
        # First, ensure each segment fits; expand oversized ones
        safe_segments: list[str] = []
        for seg in segments:
            if len(seg) <= self._max_chars:
                safe_segments.append(seg)
            else:
                # Expand oversized segment into sub-windows
                safe_segments.extend(self._raw_sliding_windows(seg))

        # Greedily pack segments into bins
        bins: list[str] = []
        current_parts: list[str] = []
        current_len = 0

        for seg in safe_segments:
            if current_len + len(seg) > self._max_chars and current_parts:
                bins.append("\n".join(current_parts))
                # Carry the last segment as overlap
                tail = current_parts[-1][-self._overlap_chars :] if self._overlap_chars else ""
                current_parts = [tail, seg] if tail else [seg]
                current_len = len(tail) + len(seg)
            else:
                current_parts.append(seg)
                current_len += len(seg)

        if current_parts:
            bins.append("\n".join(current_parts))

        return self._bins_to_chunks(domain, bins, strategy)

    def _sliding_window(self, domain: str, text: str) -> list[TextChunk]:
        """Pure sliding-window split — domain-agnostic fallback."""
        windows = self._raw_sliding_windows(text)
        return self._bins_to_chunks(domain, windows, ChunkStrategy.SLIDING_WINDOW)

    def _raw_sliding_windows(self, text: str) -> list[str]:
        """Split text into overlapping fixed-size character windows."""
        step = self._max_chars - self._overlap_chars
        if step <= 0:
            step = self._max_chars  # degenerate config guard
        windows: list[str] = []
        start = 0
        while start < len(text):
            end = min(start + self._max_chars, len(text))
            windows.append(text[start:end])
            if end == len(text):
                break
            start += step
        return windows or [text]

    def _bins_to_chunks(
        self,
        domain: str,
        bins: list[str],
        strategy: ChunkStrategy,
    ) -> list[TextChunk]:
        total = len(bins)
        chunks: list[TextChunk] = []
        for i, content in enumerate(bins):
            chunks.append(
                TextChunk(
                    index=i,
                    total=total,
                    strategy=strategy,
                    content=content,
                    char_count=len(content),
                    token_estimate=len(content) // _CHARS_PER_TOKEN,
                    domain=domain,
                )
            )
        logger.info(
            "Chunked domain='%s' into %d chunks using %s.",
            domain,
            total,
            strategy.name,
        )
        return chunks

    def _make_single_chunk(
        self, domain: str, content: str, strategy: ChunkStrategy
    ) -> TextChunk:
        return TextChunk(
            index=0,
            total=1,
            strategy=strategy,
            content=content,
            char_count=len(content),
            token_estimate=len(content) // _CHARS_PER_TOKEN,
            domain=domain,
        )

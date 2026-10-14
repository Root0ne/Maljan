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

Chunk size: what the analyst's prompt has room for, measured by the analyst
from its own window (``BaseAnalyst._input_room_chars``) and handed in as
``room``. ``chunking.max_tokens_per_chunk``, where an operator set it, wins, at
1 token ≈ 4 characters (GPT-4 average). With no window learned, the size the
platform shipped with (``UNKNOWN_WINDOW_CHUNK_TOKENS``).
Sources that fit the size together are joined into one chunk
(:func:`joined_when_it_fits`), so an analyst whose input fits runs one loop.

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

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from enum import Enum, auto

from maljan.core.config import ChunkingConfig
from maljan.core.logger import logger
from maljan.llm.context_window import (
    UNKNOWN_WINDOW_CHUNK_TOKENS,
    chars_for_tokens,
    tokens_for_chars,
)

# Characters per token approximation (GPT-4 average)
_CHARS_PER_TOKEN: int = 4

# How many characters of input the analyst's prompt has room for, asked about
# the text it would carry; ``None`` when nothing bounds it (no window learned).
Room = Callable[[str], "int | None"]

# What joins two sources that fit one chunk: the break the upstream block is
# put in front of a head chunk with.
SOURCE_SEPARATOR = "\n\n"


def head_object(data: str) -> dict | None:
    """The JSON object a chunk opens with, read whole whatever follows it.

    A head chunk of a sample-fed agent opens with the sample context as one
    JSON object (``analysis_file_path`` and the rest); when another source fits
    beside it (:func:`joined_when_it_fits`) that source follows after
    :data:`SOURCE_SEPARATOR`, and the joined text is no longer one JSON
    document. Only the first value is decoded, so what is joined after it
    never decides whether the head is read. ``None`` when the chunk does not
    open with a JSON object. One pass over the first value.
    """
    stripped = data.lstrip()
    if not stripped.startswith("{"):
        return None
    try:
        parsed, _end = json.JSONDecoder().raw_decode(stripped)
    except (json.JSONDecodeError, ValueError, RecursionError):
        return None
    return parsed if isinstance(parsed, dict) else None


# The chunk size this platform shipped with, in characters: what an input is
# split at with no window learned.
SHIPPED_CHUNK_CHARS = chars_for_tokens(UNKNOWN_WINDOW_CHUNK_TOKENS, _CHARS_PER_TOKEN)

# What sized a chunk, kept on every chunk the chunker makes
# (``TextChunk.metadata``): ``SIZED_BY`` names one of the three, ``CHUNK_CHARS``
# is the size in characters.
SIZED_BY = "sized_by"
CHUNK_CHARS = "chunk_chars"
SIZED_BY_OPERATOR = "operator"
SIZED_BY_ROOM = "room"
SIZED_BY_UNKNOWN_WINDOW = "unknown_window"


def configured_chunk_chars(config: ChunkingConfig | None) -> int | None:
    """The operator's ``max_tokens_per_chunk`` in characters, or ``None`` where it is unset."""
    configured = getattr(config, "max_tokens_per_chunk", None)
    if isinstance(configured, int) and not isinstance(configured, bool) and configured > 0:
        return chars_for_tokens(configured, _CHARS_PER_TOKEN)
    return None


def sized_chunk_chars(
    config: ChunkingConfig | None, text: str, room: Room | None
) -> tuple[int | None, str]:
    """``(characters, what sized them)`` for one chunk of ``text``; ``None`` characters is no bound.

    The operator's ``max_tokens_per_chunk`` where it is set
    (:data:`SIZED_BY_OPERATOR`); otherwise the room the analyst's prompt has
    for ``text`` (:data:`SIZED_BY_ROOM`). With no room measured — no window
    learned, or no analyst to ask — the chunk size the platform shipped with
    (``UNKNOWN_WINDOW_CHUNK_TOKENS``, :data:`SIZED_BY_UNKNOWN_WINDOW`), as a
    tool answer keeps its old constant on an unknown window; the run says so
    where it splits an input. A prompt with no room left for any input is no
    bound: the framing alone does not fit, there is nothing to split at, and
    the prompt that carries the input shortens it and says so
    (``BaseAnalyst._truncate_input``).
    """
    configured = configured_chunk_chars(config)
    if configured is not None:
        return configured, SIZED_BY_OPERATOR
    chars = room(text) if room is not None else None
    if chars is None:
        return SHIPPED_CHUNK_CHARS, SIZED_BY_UNKNOWN_WINDOW
    if isinstance(chars, int) and not isinstance(chars, bool) and chars > 0:
        return chars, SIZED_BY_ROOM
    return None, SIZED_BY_ROOM


def chunk_chars(config: ChunkingConfig, text: str, room: Room | None) -> int | None:
    """Characters one chunk of ``text`` may hold, ``None`` for none (:func:`sized_chunk_chars`)."""
    return sized_chunk_chars(config, text, room)[0]


def _one_json_object(text: str) -> bool:
    """Whether ``text`` is one JSON object and nothing else, as the node reads a head chunk."""
    stripped = text.strip()
    if not stripped.startswith("{"):
        return False
    try:
        return isinstance(json.loads(stripped), dict)
    except (json.JSONDecodeError, ValueError, RecursionError):
        return False


class HeadRoom:
    """The room for the source whose first chunk is added to after it is sized.

    The node puts the sample path and the upstream block into the head chunk
    once the input is chunked; ``added`` says, for a text, how many characters
    that adds to it. Called, this is the analyst's whole room, which every
    chunk of the source but the first is sized at; :meth:`first` is what the
    first chunk may hold so that it still fits once they are in. Only the first
    chunk is made smaller, so however large the addition is the source gains
    at most one chunk over a split at the room.
    """

    def __init__(self, room: Room, added: Callable[[str], int]) -> None:
        self._room = room
        self._added = added

    def __call__(self, text: str) -> int | None:
        return self._room(text)

    def first(self, text: str, chars: int) -> int:
        """Characters the first chunk of ``text`` may hold where a chunk holds ``chars``.

        ``chars`` where the text fits whole with what is added. ``chars`` too
        for a JSON head (one JSON object) that fits the room on its own: cut,
        it is no JSON head and loses the sample path the node writes into it,
        so it goes whole and the prompt that carries it shortens it as a
        document and says so. Otherwise ``chars`` less what is added to the
        first piece — a piece is no JSON head, so that is the block in front
        of it. Where the addition alone fills the room the first chunk is over
        it whatever piece it holds; it is then sized as the others are, and
        its prompt shortens it and says so.
        """
        added = max(0, int(self._added(text)))
        if len(text) + added <= chars:
            return chars
        if len(text) <= chars and _one_json_object(text):
            return chars
        piece = max(0, int(self._added(text[:chars]))) if len(text) > chars else added
        left = chars - piece
        return left if left > 0 else chars


def head_room(room: Room | None, added: Callable[[str], int]) -> Room | None:
    """The room for the source whose first chunk is added to after it is sized (:class:`HeadRoom`).

    A room not measured (``None``) is passed on unchanged.
    """
    if room is None:
        return None
    return HeadRoom(room, added)


def first_chunk_chars(text: str, room: Room | None, chars: int, sized_by: str) -> int:
    """Characters the first chunk of ``text`` may hold where a chunk holds ``chars``.

    ``chars`` unless the room was measured and is a :class:`HeadRoom`, whose
    first chunk is kept smaller by what the node adds to it. An operator's
    figure and the unknown-window size are each the chunk size as set, the
    head's included.
    """
    if sized_by != SIZED_BY_ROOM or not isinstance(room, HeadRoom):
        return chars
    return room.first(text, chars)


def joined_when_it_fits(chunks: list, config: ChunkingConfig, room: Room | None) -> list:
    """Sources that fit one chunk together joined into one, in order; ``chunks`` when none join.

    An agent reads several sources (the sample context and a sandbox slice),
    each chunked on its own, and every chunk is a full tool loop run after the
    one before it. Whole sources next to each other that the chunk size holds
    together are one loop: joined with :data:`SOURCE_SEPARATOR`, each source
    unchanged, from the first onwards while the next still fits. A piece of a
    source the chunker split (``total`` above 1) is joined with nothing. Two
    pieces of one source never fit one chunk together — the chunker cut them
    apart because they did not — and a piece's header names its place in its
    own source, which a chunk holding another source beside it would misstate.
    The list is returned as it came when nothing joins, when it is one chunk,
    or when ``skip_if_fits`` is off (chunking forced).
    """
    if len(chunks) < 2 or getattr(config, "skip_if_fits", True) is False:
        return chunks
    runs: list[list] = []
    whole: list = []
    for chunk in chunks:
        if getattr(chunk, "total", 1) == 1:
            whole.append(chunk)
            continue
        if whole:
            runs.append(whole)
            whole = []
        runs.append([chunk])
    if whole:
        runs.append(whole)
    joined: list = []
    for run in runs:
        joined.extend(_joined_run(run, config, room))
    if len(joined) == len(chunks):
        return chunks
    return joined


def _joined_run(run: list, config: ChunkingConfig, room: Room | None) -> list:
    """One run of whole sources, those next to each other that fit one chunk joined.

    The size is asked once, about the whole run joined, and each join is then
    a sum of lengths, so the run is read a fixed number of times.
    """
    if len(run) < 2:
        return run
    limit = chunk_chars(config, SOURCE_SEPARATOR.join(str(chunk.content) for chunk in run), room)
    groups: list[list] = [[run[0]]]
    size = len(str(run[0].content))
    for chunk in run[1:]:
        grown = size + len(SOURCE_SEPARATOR) + len(str(chunk.content))
        if limit is None or grown <= limit:
            groups[-1].append(chunk)
            size = grown
        else:
            groups.append([chunk])
            size = len(str(chunk.content))
    return [_one_chunk(group) for group in groups]


def _one_chunk(group: list) -> object:
    """The chunks of ``group`` as one, their contents joined in order."""
    if len(group) == 1:
        return group[0]
    content = SOURCE_SEPARATOR.join(str(chunk.content) for chunk in group)
    metadata: dict[str, object] = {}
    for chunk in group:
        metadata.update(getattr(chunk, "metadata", None) or {})
    return replace(
        group[0],
        index=0,
        total=1,
        content=content,
        char_count=len(content),
        token_estimate=tokens_for_chars(len(content), _CHARS_PER_TOKEN, ceil=False),
        metadata=metadata,
    )


class ChunkStrategy(Enum):
    """Chunking strategy applied to produce a particular chunk set."""

    FUNCTION_BOUNDARY = auto()  # Static: splits at decompiler function headers
    API_SEQUENCE = auto()  # Dynamic: splits at PID/process boundaries
    FLOW_SESSION = auto()  # Network: splits at flow delimiters
    SLIDING_WINDOW = auto()  # Fallback: fixed-size overlapping windows


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
        self._overlap_chars = chars_for_tokens(config.overlap_tokens, _CHARS_PER_TOKEN)

    def chunk(self, domain: str, text: str, room: Room | None = None) -> list[TextChunk]:
        """Split `text` into LLM-safe chunks for the given domain.

        A chunk holds what :func:`sized_chunk_chars` allows: the operator's
        ``max_tokens_per_chunk``, else the ``room`` the analyst's prompt has
        for this text, else the unknown-window size; the first chunk of a
        :class:`HeadRoom` source holds less by what the node adds to it
        (:func:`first_chunk_chars`). A prompt with no room left for input is
        one chunk. When `config.skip_if_fits` is True and the text fits in a
        single chunk, a list with one chunk is returned immediately (no
        splitting). Every chunk records what sized it (:data:`SIZED_BY`,
        :data:`CHUNK_CHARS` in ``metadata``).

        Args:
            domain: One of "static", "dynamic", "network", or any custom domain.
            text: The full parsed text from the data loader.
            room: The analyst's input room for a text, in characters.

        Returns:
            Ordered list of TextChunk objects. Always has at least one element.
        """
        if not text:
            return [self._make_single_chunk(domain, "", ChunkStrategy.SLIDING_WINDOW)]

        max_chars, sized_by = sized_chunk_chars(self._config, text, room)
        if max_chars is None:
            logger.debug(
                "Chunking skipped for domain='%s': no room left for input, %d chars whole.",
                domain,
                len(text),
            )
            return [self._make_single_chunk(domain, text, ChunkStrategy.SLIDING_WINDOW)]

        first = first_chunk_chars(text, room, max_chars, sized_by)
        chunks = self._sized(domain, text, max_chars, first)
        for chunk in chunks:
            chunk.metadata.update({SIZED_BY: sized_by, CHUNK_CHARS: max_chars})
        return chunks

    def _sized(self, domain: str, text: str, max_chars: int, first: int) -> list[TextChunk]:
        """``text`` as chunks of ``max_chars``, the first of ``first`` (at most ``max_chars``)."""
        if self._config.skip_if_fits and len(text) <= first:
            logger.debug(
                "Chunking skipped for domain='%s': %d chars fits in limit (%d chars).",
                domain,
                len(text),
                first,
            )
            return [self._make_single_chunk(domain, text, ChunkStrategy.SLIDING_WINDOW)]
        if first >= max_chars or len(text) <= first:
            return self._split(domain, text, max_chars)
        # Only the head piece is smaller: what the node adds goes into it alone.
        start = first - self._overlap_chars if first > self._overlap_chars else first
        rest = self._split(domain, text[start:], max_chars)
        return self._bins_to_chunks(
            domain, [text[:first], *(chunk.content for chunk in rest)], rest[0].strategy
        )

    def _split(self, domain: str, text: str, max_chars: int) -> list[TextChunk]:
        """``text`` split at ``max_chars``: at the domain's boundaries, else by a sliding window."""
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
                return self._pack_segments(domain, segments, strategy, max_chars)
            logger.debug(
                "No '%s' boundary markers found in domain='%s'. Falling back to sliding window.",
                strategy.name,
                domain,
            )

        # Sliding window fallback
        return self._sliding_window(domain, text, max_chars)

    def merge_summaries(self, summaries: list[str], domain: str = "") -> str:
        """Merge partial chunk summaries into a consolidated analysis context.

        The merged text is still subject to the chunk size — if the
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
        max_chars: int,
    ) -> list[TextChunk]:
        """Pack variable-length segments into max-size bins with overlap.

        Segments that individually exceed max_chars are further split with
        the sliding window algorithm before packing.
        """
        # First, ensure each segment fits; expand oversized ones
        safe_segments: list[str] = []
        for seg in segments:
            if len(seg) <= max_chars:
                safe_segments.append(seg)
            else:
                # Expand oversized segment into sub-windows
                safe_segments.extend(self._raw_sliding_windows(seg, max_chars))

        # Greedily pack segments into bins
        bins: list[str] = []
        current_parts: list[str] = []
        current_len = 0

        for seg in safe_segments:
            if current_len + len(seg) > max_chars and current_parts:
                bins.append("\n".join(current_parts))
                # Carry the last `_overlap_chars` characters of the bin we just
                # closed as overlap — not just the last segment, so the upper
                # context survives bin transitions.
                if self._overlap_chars:
                    closed_bin = bins[-1]
                    tail = closed_bin[-self._overlap_chars :]
                else:
                    tail = ""
                current_parts = [tail, seg] if tail else [seg]
                current_len = len(tail) + len(seg)
            else:
                current_parts.append(seg)
                current_len += len(seg)

        if current_parts:
            bins.append("\n".join(current_parts))

        return self._bins_to_chunks(domain, bins, strategy)

    def _sliding_window(self, domain: str, text: str, max_chars: int) -> list[TextChunk]:
        """Pure sliding-window split — domain-agnostic fallback."""
        windows = self._raw_sliding_windows(text, max_chars)
        return self._bins_to_chunks(domain, windows, ChunkStrategy.SLIDING_WINDOW)

    def _raw_sliding_windows(self, text: str, max_chars: int) -> list[str]:
        """Split text into overlapping fixed-size character windows.

        Guards against pathological configurations: ``overlap >= max_chars``
        would otherwise create an infinite loop. We clamp the step to at
        least 1/4 of ``max_chars`` and log a warning.
        """
        step = max_chars - self._overlap_chars
        min_step = max(1, max_chars // 4)
        if step < min_step:
            logger.warning(
                "BinaryChunker overlap (%d) too large for max_chars (%d); clamping step to %d.",
                self._overlap_chars,
                max_chars,
                min_step,
            )
            step = min_step
        windows: list[str] = []
        start = 0
        while start < len(text):
            end = min(start + max_chars, len(text))
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
                    token_estimate=tokens_for_chars(len(content), _CHARS_PER_TOKEN, ceil=False),
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

    def _make_single_chunk(self, domain: str, content: str, strategy: ChunkStrategy) -> TextChunk:
        return TextChunk(
            index=0,
            total=1,
            strategy=strategy,
            content=content,
            char_count=len(content),
            token_estimate=tokens_for_chars(len(content), _CHARS_PER_TOKEN, ceil=False),
            domain=domain,
        )

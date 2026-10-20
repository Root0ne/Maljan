"""The byte counts of many ranges of one buffer, in work and memory linear in both.

A section table chooses its own ranges, and nothing stops every one of a
thousand sections from naming the same megabyte of the file, or each from
naming a slightly different one; an ELF can name a section for every 64 bytes
of the file. Counting each range's bytes on its own then reads the file once
per section. This module reads the buffer once, into checkpoints: every
``BLOCK`` bytes, the counts of every byte value before that point and the
first place at or after it that holds each value. A range's counts are the
counts at the checkpoints inside it, one less the other, plus the bytes
between its ends and those checkpoints, read directly (fewer than ``BLOCK``
at each end).

The entropy every caller computes from the counts sums one term per byte value
in the order a :class:`collections.Counter` over the range lists them, the
order in which each value first occurs in it; floating-point addition depends
on that order, so the counts are put in it before the entropy is computed,
and the entropy is the one a ``Counter`` over the range's bytes gives, to the
bit. Each range's entropy is computed when the range is answered and only the
number is kept.

Work and memory: the buffer is read once (a window of blocks at a time, so
the working arrays stay a few megabytes), each range costs at most two blocks
and the 256 byte values more, and the checkpoints hold as many bytes as the
buffer (``BLOCK``).
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Callable, Iterable, Iterator
from typing import Any

import numpy as np

from maljan.tools.pe_image import _SCAN_WORDS

# How many bytes are read at a time: it bounds the working arrays (eight bytes
# per byte read, for the first-occurrence sort), never what is read.
STRETCH = _SCAN_WORDS
# How many bytes one checkpoint covers. A checkpoint holds two tables of 256
# four-byte numbers (the counts before it, the first places after it), 2048
# bytes, so checkpoints this far apart hold as many bytes as the buffer.
BLOCK = 2 * 256 * 4

# The work done, by kind, for the tests that hold the pass linear: the bytes
# read and the ranges answered. Counted, never timed.
WORK: Counter[str] = Counter()


def _firsts(piece: np.ndarray, base: int, absent: int) -> tuple[np.ndarray, np.ndarray]:
    """The counts of every byte value in ``piece`` and the first place of each (``absent``)."""
    WORK["bytes"] += len(piece)
    counts = np.bincount(piece, minlength=256).astype(np.int64)
    first = np.full(256, absent, dtype=np.int64)
    if len(piece):
        # A stable sort groups the bytes by value, each group in the order of
        # its places, so a group's first member is the value's first place.
        order = np.argsort(piece, kind="stable")
        starts = np.concatenate(([0], np.cumsum(counts)[:-1]))
        present = np.flatnonzero(counts)
        first[present] = base + order[starts[present]]
    return counts, first


class _Checkpoints:
    """Every ``BLOCK`` bytes: the counts before the point, and the first place at or after it."""

    def __init__(self, array: np.ndarray) -> None:
        size = len(array)
        self.array = array
        self.size = size
        kind = np.int32 if size < 2**31 else np.int64
        blocks = size // BLOCK
        self.before = np.zeros((blocks + 1, 256), dtype=kind)
        after = np.full((blocks + 1, 256), size, dtype=kind)
        rows = max(1, STRETCH // BLOCK)
        running = np.zeros(256, dtype=np.int64)
        for low in range(0, blocks, rows):
            high = min(blocks, low + rows)
            window = array[low * BLOCK : high * BLOCK].reshape(high - low, BLOCK)
            WORK["bytes"] += window.size
            count = high - low
            keys = (np.arange(count, dtype=np.int64)[:, None] * 256 + window).ravel()
            held = np.bincount(keys, minlength=count * 256).reshape(count, 256)
            self.before[low + 1 : high + 1] = running + np.cumsum(held, axis=0)
            running += held.sum(axis=0)
            order = np.argsort(window, axis=1, kind="stable")
            ordered = np.take_along_axis(window, order, axis=1)
            new = np.ones_like(ordered, dtype=bool)
            new[:, 1:] = ordered[:, 1:] != ordered[:, :-1]
            row, column = np.nonzero(new)
            after[low + row, ordered[row, column]] = (low + row) * BLOCK + order[row, column]
        tail = _firsts(array[blocks * BLOCK :], blocks * BLOCK, size)[1]
        after[blocks] = tail
        # The first place at or after a checkpoint is the first in its block,
        # else the first at or after the next checkpoint.
        self.after = np.minimum.accumulate(after[::-1], axis=0)[::-1]

    def counts(self, start: int, stop: int) -> list[int]:
        """``list(Counter(buffer[start:stop]).values())``."""
        WORK["ranges"] += 1
        inner = -(-start // BLOCK)
        outer = stop // BLOCK
        if outer <= inner:
            counts, first = _firsts(self.array[start:stop], start, self.size)
        else:
            counts, first = _firsts(self.array[start : inner * BLOCK], start, self.size)
            tail = np.bincount(self.array[outer * BLOCK : stop], minlength=256)
            WORK["bytes"] += stop - outer * BLOCK
            counts += self.before[outer].astype(np.int64) - self.before[inner] + tail
            first = np.where(first < self.size, first, self.after[inner])
        present = np.flatnonzero(counts)
        ordered: list[int] = counts[present[np.argsort(first[present])]].tolist()
        return ordered


def _each_range(
    data: Any, spans: Iterable[tuple[int, int]]
) -> Iterator[tuple[tuple[int, int], list[int]]]:
    wanted = {(int(start), int(stop)) for start, stop in spans if stop > start}
    if not wanted:
        return
    checkpoints = _Checkpoints(np.frombuffer(data, dtype=np.uint8))
    for span in sorted(wanted):
        yield span, checkpoints.counts(*span)


def range_entropies(
    data: Any, spans: Iterable[tuple[int, int]], entropy: Callable[[list[int]], float]
) -> dict[tuple[int, int], float]:
    """For each ``(start, stop)``, ``entropy`` of the counts of ``data[start:stop]``.

    ``start`` and ``stop`` are slice bounds already clipped to the buffer
    (``0 <= start <= stop <= len(data)``); an empty range is not answered. The
    counts handed to ``entropy`` are ``list(Counter(data[start:stop]).values())``;
    only the number is kept.
    """
    return {span: entropy(counts) for span, counts in _each_range(data, spans)}


def range_counts(data: Any, spans: Iterable[tuple[int, int]]) -> dict[tuple[int, int], list[int]]:
    """For each ``(start, stop)``, the counts themselves (for a reader that checks them)."""
    return dict(_each_range(data, spans))


def counter_entropy(counts: list[int]) -> float:
    """The Shannon entropy ``Counter``-based code computes from these counts, in their order.

    ``p * math.log2(p)`` summed term by term, as ``pe_extractor`` has always
    computed it; ``0.0`` for no bytes.
    """
    total = sum(counts)
    if not total:
        return 0.0
    entropy = 0.0
    for count in counts:
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def pefile_entropy(counts: list[int]) -> float:
    """The entropy ``pefile``'s ``SectionStructure.entropy_H`` computes from these counts.

    ``float(x) / len(data)`` and ``math.log(p, 2)``, term by term in the
    counts' order, starting from the integer zero as it does; ``0.0`` for no
    bytes.
    """
    total = sum(counts)
    if not total:
        return 0.0
    entropy: float = 0
    for count in counts:
        p_x = float(count) / total
        entropy -= p_x * math.log(p_x, 2)
    return entropy


def pefile_section_span(section: Any, size: int) -> tuple[int, int]:
    """The slice of the file ``pefile``'s ``section.get_data()`` returns, as bounds.

    ``get_data()`` with no arguments reads from the adjusted raw pointer for
    the raw size, never past the unadjusted pointer plus the raw size; the
    bounds are that slice's, clipped to the file as slicing clips them.
    """
    offset = section.get_PointerToRawData_adj()
    if section.SizeOfRawData is not None:
        end = offset + section.SizeOfRawData
    else:
        end = offset
    if section.PointerToRawData is not None and section.SizeOfRawData is not None:
        end = min(end, section.PointerToRawData + section.SizeOfRawData)
    start, stop, _ = slice(offset, end).indices(size)
    return start, max(start, stop)


def pefile_section_entropies(pe: Any) -> list[float]:
    """``section.get_entropy()`` of every section of a parsed ``pefile.PE``, in their order.

    The same numbers, each distinct range of the file answered once from the
    checkpoints (:func:`range_entropies`) however many sections name it or
    overlap it.
    """
    sections = list(getattr(pe, "sections", []) or [])
    data = pe.__data__
    spans = [pefile_section_span(section, len(data)) for section in sections]
    entropies = range_entropies(data, spans, pefile_entropy)
    return [entropies.get(span, 0.0) for span in spans]

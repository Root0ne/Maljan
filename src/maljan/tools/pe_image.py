"""A PE file's bytes as the image they map to, for the tools that read values out of it.

``resolve_api_hashes`` and ``decode_string_blobs`` both answer in addresses: where
a value occurs, which function holds that place, and which code refers to a
blob. This module is the one reading of the file both use, so the two tools and
their tests agree on what an address is.

What it states and where it stops:

* **Addresses are offsets from the image base** (RVAs), the numbers a
  disassembler that loaded the file anywhere agrees with. A byte outside every
  section (the headers, an overlay) has a file offset and no RVA.
* **The function around an address** comes from the file's own function table,
  the exception directory (``.pdata``) of an x64 image, which lists the start
  and end of every function that has unwind data. An entry whose unwind data
  is chained to another entry is a fragment of that entry's function (a cold
  part moved away from it), and its addresses are stated with the start of the
  function the chain leads to — or with none when the chain cannot be followed.
  An x86 image has no such table: when the caller has another tool's list of
  function starts for the file, the nearest of them at or before the address
  in the same section is stated under a field of its own,
  ``after_function_start`` with its ``function_source`` (the list's source,
  where the caller names one) — never as ``function``, because such a list
  says where functions start and not where they end, so it says what precedes
  the address, not what holds it; otherwise an address is stated alone. An
  address outside every listed function has no function stated: a start is
  never guessed at.
* **The exception directory is not program data.** The tools that read the
  data sections read them with its bytes set to zero, so a table of function
  addresses is not searched for text or hash values.
* **References to an address** are found by a scan, not by disassembly: every
  position in an executable section whose four bytes, read as a signed
  displacement from the end of those four bytes, land on the address (the
  RIP-relative form an x64 instruction takes an address with), and every
  position in any section holding the address as an absolute virtual address
  (four bytes on x86, eight on x64). A scan can find a displacement that is not
  one; what it reports is where the bytes are, and the reader decides.

The sample is only read; nothing in it is run.
"""

from __future__ import annotations

import heapq
import json
import struct
from array import array
from bisect import bisect_right
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, overload

import numpy as np
import pefile

# IMAGE_SCN_MEM_EXECUTE and IMAGE_SCN_CNT_CODE.
_EXECUTE = 0x20000000
_CODE = 0x00000020
# IMAGE_SCN_MEM_DISCARDABLE: debug information and relocations, which the
# program does not read as data.
_DISCARDABLE = 0x02000000
# IMAGE_FILE_MACHINE_AMD64.
_AMD64 = 0x8664
# The exception directory's index in the data directory array.
_EXCEPTION_DIRECTORY = 3
# The import directory's index.
_IMPORT_DIRECTORY = 1

# The most places one answer lists, every value's together: as many as the
# largest tool answer any model is given holds (its share, ``ANSWER_SHARE``, of
# the characters of the largest window this platform believes in) at the
# fewest characters a place takes as JSON. No model is handed more, so an
# answer whose values stand in more places lists the first of them, in the
# order it states its values, and says once how many it left out
# (``PlaceBudget``).
#
# It is a bound past which no model could read the places, not the size of
# the answer a given call is shown: an ordinary answer never reaches it, so
# it never cuts what a model would read, and the recorder still shortens an
# answer to the room the call has. What it stops is the work and the memory of
# stating millions of places for a file built to hold them.
_SMALLEST_PLACE = json.dumps({"offset": "0x0"}) + ", "


def _place_budget() -> int:
    """``PLACE_BUDGET``, worked out on first use.

    The window figures live with the model-facing code, whose imports a
    process that only reads a PE need not pay for until it states places.
    """
    held = globals().get("PLACE_BUDGET")
    if held is None:
        from maljan.llm.context_window import (
            ANSWER_SHARE,
            MAX_BELIEVABLE_WINDOW_TOKENS,
            chars_for_tokens,
        )

        room = int(chars_for_tokens(MAX_BELIEVABLE_WINDOW_TOKENS) * ANSWER_SHARE)
        held = globals()["PLACE_BUDGET"] = room // len(_SMALLEST_PLACE)
    return int(held)


def __getattr__(name: str) -> Any:
    if name == "PLACE_BUDGET":
        return _place_budget()
    raise AttributeError(name)


PLACES_CUT = (
    "{skipped} more places hold the values found than are listed: the answer lists the first "
    "{budget} places in all, as many as the largest tool answer any model is given holds"
)

# The longest import name and DLL name read: the bounds the PE reader this
# platform depends on (pefile) reads them to. A name with no NUL within its
# bound, or before the file bytes of the section its address falls in end, is
# not read.
_IMPORT_NAME_BOUND = int(pefile.MAX_IMPORT_NAME_LENGTH)
_DLL_NAME_BOUND = int(pefile.MAX_DLL_LENGTH)

# How many 32-bit values ``Image.occurrences_of`` compares at a time: it bounds
# the scan's working memory (a few megabytes), never what the scan finds.
_SCAN_WORDS = 1 << 18
# How many import entries are read at a time: each takes some hundred bytes of
# working arrays while it is read, so this bounds that memory, never what is read.
_IMPORT_STRETCH = _SCAN_WORDS >> 4
# How many bytes a name is first looked for its NUL in, and how many bytes of
# windows are read at a time: they bound the work and memory of that search,
# never what it finds.
_SHORT_NAME = 32
_WINDOW_BYTES = _SCAN_WORDS // 4

# Said when the import tables list more slots than the file can store.
IMPORTS_CUT = (
    "the import tables list more slots than the file can store ({cap}, one per {width} bytes "
    "of it); the slots past the first {cap} are not read"
)
# Said when names the import tables point at are not read.
NAMES_NOT_READ = (
    "{functions} import entries and {dlls} import descriptors name no readable function or "
    "DLL name (no NUL within the name's bound or its section, or an address outside every "
    "section), and are stated without one"
)
# Said when descriptors' address tables overlap.
TABLES_OVERLAP = (
    "{descriptors} descriptors' address tables overlap another's; {slots} slots more than one "
    "of them names are named as the last of them in the directory's order names them"
)


class PlaceBudget:
    """The places one answer lists, every value's together, at most ``PLACE_BUDGET``.

    ``take`` states the places of one value's offsets while the budget lasts
    and counts the rest; ``cut`` is the one sentence the answer carries when
    any were left out, and empty otherwise.
    """

    def __init__(self, budget: int | None = None) -> None:
        self.budget = _place_budget() if budget is None else budget
        self.left = self.budget
        self.skipped = 0

    def take(self, offsets: Any, where: Any) -> list[dict[str, Any]]:
        """The places of ``offsets`` (a list or an array) while the budget lasts."""
        kept = offsets[: max(self.left, 0)]
        self.left -= len(kept)
        self.skipped += len(offsets) - len(kept)
        listed = kept.tolist() if isinstance(kept, np.ndarray) else kept
        return [where(at) for at in listed]

    @property
    def cut(self) -> str:
        if not self.skipped:
            return ""
        return PLACES_CUT.format(skipped=self.skipped, budget=self.budget)


class NotAPortableExecutable(ValueError):
    """The file is not a PE image this module can map."""


@dataclass(frozen=True)
class Section:
    """One section header, as the image maps it."""

    name: str
    rva: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & (_EXECUTE | _CODE))

    @property
    def mapped_size(self) -> int:
        """How many of the section's bytes come from the file."""
        return min(self.raw_size, self.virtual_size or self.raw_size)


class _FirstCover:
    """Which of a list of ranges first holds a number, by bisection rather than a walk.

    The answer a walk of the ranges in their order gives (the first range
    whose ``[low, high)`` holds the number), computed once: the ranges are cut
    into the intervals between their ends, each interval given the first range
    that covers it, by a sweep over the sorted ends. Building it costs the
    ranges times their logarithm and each lookup the logarithm of the
    intervals, and overlapping ranges answer as they do in the walk.
    """

    def __init__(self, spans: list[tuple[int, int]]) -> None:
        kept = sorted((low, high, index) for index, (low, high) in enumerate(spans) if high > low)
        self.spans = spans
        # The list the ranges were taken from, when a caller keeps it.
        self.held: object = None
        self.starts: list[int] = []
        self.owners: list[int | None] = []
        active: list[tuple[int, int]] = []  # (index, high), a heap by index
        position = 0
        for point in sorted({end for low, high, _ in kept for end in (low, high)}):
            while position < len(kept) and kept[position][0] == point:
                _low, high, index = kept[position]
                heapq.heappush(active, (index, high))
                position += 1
            # A range whose end is passed but is not on top stays in the heap;
            # it is dropped when it reaches the top, before it can answer.
            while active and active[0][1] <= point:
                heapq.heappop(active)
            self.starts.append(point)
            self.owners.append(active[0][0] if active else None)

    def at(self, value: int) -> int | None:
        position = bisect_right(self.starts, value) - 1
        if position < 0:
            return None
        index = self.owners[position]
        if index is None:
            return None
        low, high = self.spans[index]
        return index if low <= value < high else None

    def at_many(self, values: np.ndarray) -> np.ndarray:
        """:meth:`at` of every value at once, ``-1`` where none holds it."""
        if not self.starts:
            return np.full(len(values), -1, dtype=np.int64)
        held = getattr(self, "_arrays", None)
        if held is None:
            # Built once, so a call costs its values, not the ranges.
            held = self._arrays = (
                np.asarray(self.starts, dtype=np.int64),
                np.asarray([-1 if o is None else o for o in self.owners], dtype=np.int64),
                np.asarray([low for low, _ in self.spans] or [0], dtype=np.int64),
                np.asarray([high for _, high in self.spans] or [0], dtype=np.int64),
            )
        starts, owners, lows, highs = held
        position = np.searchsorted(starts, values.astype(np.int64), side="right") - 1
        found = np.where(position >= 0, owners[np.maximum(position, 0)], -1)
        safe = np.maximum(found, 0)
        inside = (found >= 0) & (lows[safe] <= values) & (values < highs[safe])
        return np.where(inside, found, -1)


class SectionList(list[Section]):
    """An image's sections, counting every change so a lookup built over them is never stale."""

    version = 0

    def _changed(self) -> None:
        self.version += 1

    def __setitem__(self, index: Any, value: Any) -> None:
        super().__setitem__(index, value)
        self._changed()

    def __delitem__(self, index: Any) -> None:
        super().__delitem__(index)
        self._changed()

    def __iadd__(self, other: Any) -> SectionList:  # type: ignore[override,misc]
        super().__iadd__(other)
        self._changed()
        return self

    def __imul__(self, count: Any) -> SectionList:  # type: ignore[override,misc]
        super().__imul__(count)
        self._changed()
        return self

    def append(self, value: Section) -> None:
        super().append(value)
        self._changed()

    def extend(self, values: Any) -> None:
        super().extend(values)
        self._changed()

    def insert(self, index: Any, value: Section) -> None:
        super().insert(index, value)
        self._changed()

    def pop(self, index: Any = -1) -> Section:
        value = super().pop(index)
        self._changed()
        return value

    def remove(self, value: Section) -> None:
        super().remove(value)
        self._changed()

    def clear(self) -> None:
        super().clear()
        self._changed()

    def sort(self, *args: Any, **kwargs: Any) -> None:
        super().sort(*args, **kwargs)
        self._changed()

    def reverse(self) -> None:
        super().reverse()
        self._changed()


@dataclass
class Image:
    """The file's bytes, its sections and its function table."""

    data: bytes
    image_base: int
    is64: bool
    size_of_image: int
    sections: list[Section] = field(default_factory=list)
    # The COFF header's machine field (0x8664 for AMD64, 0x14c for i386).
    machine: int = 0
    # The ranges of ``.pdata``, sorted by their begin: the begin, the end
    # (exclusive) and the start of the function each belongs to (a chained
    # fragment's primary entry), ``None`` when a chain could not be followed.
    function_starts: list[int] = field(default_factory=list)
    function_ends: list[int] = field(default_factory=list)
    function_owners: list[int | None] = field(default_factory=list)
    # Function starts handed in from another tool's list, for an image with no
    # table of its own; only starts, so the nearest one before an address is
    # what is stated, and said to be.
    outside_starts: list[int] = field(default_factory=list)
    outside_source: str = ""
    # The file offset and length of the exception directory, when there is one.
    exception_directory: tuple[int, int] | None = None
    # The import directory's RVA and size, when the header names one.
    import_directory: tuple[int, int] | None = None
    _imports: ImportSlots | None = field(default=None, repr=False)
    # Set when the import tables listed more slots than were read
    # (``IMPORTS_CUT``) or named names that were not read (``NAMES_NOT_READ``).
    imports_note: str = ""
    # The first-match lookups over the section ranges, built on first use and
    # built again whenever the section list is replaced or changed.
    _covers: dict[str, tuple[tuple[int, int], _FirstCover]] = field(
        default_factory=dict, repr=False
    )

    def __setattr__(self, name: str, value: Any) -> None:
        if name == "sections" and not isinstance(value, SectionList):
            value = SectionList(value)
        super().__setattr__(name, value)

    # -- mapping ------------------------------------------------------------

    def _cover(self, kind: str) -> _FirstCover:
        sections = self.sections
        key = (id(sections), getattr(sections, "version", 0))
        held = self._covers.get(kind)
        if held is not None and held[0] == key and held[1].held is sections:
            return held[1]
        if kind == "offset":
            spans = [(s.raw_offset, s.raw_offset + s.mapped_size) for s in self.sections]
        else:
            spans = [(s.rva, s.rva + max(s.virtual_size, s.raw_size)) for s in self.sections]
        cover = _FirstCover(spans)
        cover.held = sections
        self._covers[kind] = (key, cover)
        return cover

    def section_at_offset(self, offset: int) -> Section | None:
        """The first section in the header's order whose file bytes hold ``offset``."""
        index = self._cover("offset").at(offset)
        return None if index is None else self.sections[index]

    def rva_of_offset(self, offset: int) -> int | None:
        section = self.section_at_offset(offset)
        if section is None:
            return None
        return section.rva + (offset - section.raw_offset)

    def section_at_rva(self, rva: int) -> Section | None:
        """The first section in the header's order whose range (the larger size) holds ``rva``."""
        index = self._cover("rva").at(rva)
        return None if index is None else self.sections[index]

    def offset_of_rva(self, rva: int) -> int | None:
        section = self.section_at_rva(rva)
        if section is None or rva - section.rva >= section.mapped_size:
            return None
        return section.raw_offset + (rva - section.rva)

    def section_bytes(self, section: Section) -> bytes:
        return self.data[section.raw_offset : section.raw_offset + section.mapped_size]

    def data_bytes(self, section: Section) -> bytes:
        """A data section's bytes with the exception directory's bytes set to zero."""
        raw = self.section_bytes(section)
        if self.exception_directory is None:
            return raw
        start, length = self.exception_directory
        low = max(start, section.raw_offset) - section.raw_offset
        high = min(start + length, section.raw_offset + len(raw)) - section.raw_offset
        if high <= low:
            return raw
        return raw[:low] + b"\0" * (high - low) + raw[high:]

    def data_sections(self) -> list[Section]:
        """The sections that hold bytes from the file, are not code and stay loaded.

        A discardable section (debug information, relocations) is not data the
        program reads, and its tables of small numbers read as text under some
        key far more often than any program data does.
        """
        return [
            s
            for s in self.sections
            if not s.executable and s.mapped_size > 0 and not s.characteristics & _DISCARDABLE
        ]

    def code_sections(self) -> list[Section]:
        return [s for s in self.sections if s.executable and s.mapped_size > 0]

    # -- functions ----------------------------------------------------------

    def function_at(self, rva: int) -> int | None:
        """The start of the function whose stated range holds ``rva``, or ``None``."""
        if not self.function_starts:
            return None
        index = bisect_right(self.function_starts, rva) - 1
        if index < 0 or rva >= self.function_ends[index]:
            return None
        return self.function_owners[index]

    def start_before(self, rva: int) -> int | None:
        """The nearest start handed in from elsewhere at or before ``rva``, same section."""
        if self.outside_starts:
            index = bisect_right(self.outside_starts, rva) - 1
            if index < 0:
                return None
            start = self.outside_starts[index]
            section = self.section_at_rva(rva)
            if section is None or self.section_at_rva(start) is not section:
                return None
            return start
        return None

    def function_bounds(self, rva: int) -> tuple[int, int] | None:
        """The start and end (exclusive) of the stated code range around ``rva``, or ``None``.

        From the file's function table, the range of the entry that holds the
        address (a chained fragment is its own range: it starts at an
        instruction and ends where its entry says). From function starts handed
        in from elsewhere, the nearest start at or before the address up to the
        next start after it, or the section's end. With neither, ``None``.
        """
        if self.function_starts:
            index = bisect_right(self.function_starts, rva) - 1
            if index < 0 or rva >= self.function_ends[index]:
                return None
            return self.function_starts[index], self.function_ends[index]
        before = self.start_before(rva)
        if before is None:
            return None
        section = self.section_at_rva(rva)
        if section is None:
            return None
        end = section.rva + section.mapped_size
        later = bisect_right(self.outside_starts, rva)
        if later < len(self.outside_starts):
            end = min(end, self.outside_starts[later])
        return before, end

    def imports_by_slot(self) -> ImportSlots:
        """``{slot RVA: "DLL!name"}`` for every import-table entry, read once.

        The import address table as the file stores it: each entry's slot is
        where the loader writes the function's address, so a call through that
        slot calls that import. An entry imported by ordinal is named
        ``DLL!#ordinal``. Nothing is read that the headers do not point at.
        A read-only mapping (``ImportSlots``): the names are joined when a slot
        is looked up, never held per slot.
        """
        if self._imports is None:
            self._imports = _read_imports(self)
        return self._imports

    def use_function_starts(self, starts: list[int], source: str) -> None:
        """Take function starts from elsewhere, for an image with no table of its own."""
        if self.function_starts:
            return
        self.outside_starts = sorted({int(start) for start in starts})
        self.outside_source = source

    @property
    def function_table(self) -> str:
        """Which table the functions come from, said in the answers."""
        if self.function_starts:
            chained = sum(
                1
                for begin, owner in zip(self.function_starts, self.function_owners, strict=False)
                if owner != begin
            )
            said = f"exception directory, {len(self.function_starts)} entries"
            if chained:
                said += (
                    f" ({chained} chained fragments stated with the start of the function they "
                    "belong to, or with none when the chain could not be followed)"
                )
            return said
        if self.outside_starts:
            return (
                f"{self.outside_source}, {len(self.outside_starts)} function starts (they list "
                "where functions start, not where they end: each place states the nearest start "
                "at or before it in the same section as after_function_start, and no function)"
            )
        return "none (the image lists no functions; addresses are stated without one)"

    # -- scanning -----------------------------------------------------------

    def where(self, offset: int) -> dict[str, object]:
        """One place in the file, as the tools state it."""
        rva = self.rva_of_offset(offset)
        section = self.section_at_offset(offset)
        place: dict[str, object] = {
            "offset": hex(offset),
            "rva": hex(rva) if rva is not None else None,
            "section": section.name if section else None,
        }
        place["function"] = None
        if rva is not None and section is not None and section.executable:
            start = self.function_at(rva)
            place["function"] = hex(start) if start is not None else None
            before = self.start_before(rva)
            if before is not None:
                place["after_function_start"] = hex(before)
                if self.outside_source:
                    place["function_source"] = self.outside_source
        return place

    def occurrences(self, value: int, width: int = 4) -> list[int]:
        """Every file offset where ``value`` is stored little-endian, aligned or not."""
        needle = int(value).to_bytes(width, "little")
        found: list[int] = []
        start = self.data.find(needle)
        while start != -1:
            found.append(start)
            start = self.data.find(needle, start + 1)
        return found

    def occurrences_of(self, values: set[int] | list[int]) -> dict[int, list[int]]:
        """For each 32-bit ``value``, :meth:`occurrences` of it, found in one pass over the file."""
        return {value: found.tolist() for value, found in value_offsets(self.data, values).items()}

    def references(self, targets: set[int]) -> dict[int, list[int]]:
        """For each target RVA, the file offsets of the bytes that refer to it.

        Relative references are looked for in executable sections of an x64
        image; absolute ones in every section.
        """
        found: dict[int, list[int]] = {target: [] for target in targets}
        if not targets:
            return found
        wanted = np.fromiter(sorted(targets), dtype=np.int64)
        for section in self.sections:
            raw = self.section_bytes(section)
            if len(raw) < 4:
                continue
            if self.is64 and section.executable:
                for shift in range(4):
                    usable = (len(raw) - shift) // 4 * 4
                    if usable <= 0:
                        continue
                    disp = np.frombuffer(raw[shift : shift + usable], dtype="<i4").astype(np.int64)
                    positions = np.arange(shift, shift + usable, 4, dtype=np.int64)
                    landing = section.rva + positions + 4 + disp
                    for index in np.nonzero(np.isin(landing, wanted))[0]:
                        found[int(landing[index])].append(
                            section.raw_offset + int(positions[index])
                        )
            width = 8 if self.is64 else 4
            kind = "<u8" if self.is64 else "<u4"
            absolute = {self.image_base + target: target for target in targets}
            wanted_va = np.fromiter(sorted(absolute), dtype=np.uint64)
            for shift in range(width):
                usable = (len(raw) - shift) // width * width
                if usable <= 0:
                    continue
                values = np.frombuffer(raw[shift : shift + usable], dtype=kind).astype(np.uint64)
                hits = np.nonzero(np.isin(values, wanted_va))[0]
                for index in hits:
                    target = absolute[int(values[index])]
                    found[target].append(section.raw_offset + shift + int(index) * width)
        for target in found:
            found[target] = sorted(set(found[target]))
        return found


def value_offsets(data: bytes, values: Any, width: int = 4) -> dict[int, np.ndarray]:
    """For each ``width``-byte ``value``, every offset where ``data`` stores it little-endian.

    One pass: every position's ``width`` bytes are read once, as ``width``
    views of the bytes themselves (one per starting byte, none copied)
    compared a stretch at a time, and kept where they are one of ``values``.
    Each hit is held as one number, the value's rank times the file's length
    plus the offset, so one sort in place orders the hits by value and then
    by offset; each value's offsets are handed back as a slice of that one
    array, ascending, aligned or not, as a ``find`` of each value from every
    position after the last lists them.
    """
    wanted_values = sorted({int(value) for value in values})
    empty = np.empty(0, dtype=np.int64)
    found: dict[int, np.ndarray] = {value: empty for value in wanted_values}
    if not found or len(data) < width:
        return found
    kind = f"<u{width}"
    wanted = np.asarray(wanted_values, dtype=np.uint64).astype(kind)
    span = len(data)
    keys: list[np.ndarray] = []
    for shift in range(width):
        words = np.frombuffer(data, dtype=kind, count=(len(data) - shift) // width, offset=shift)
        for start in range(0, len(words), _SCAN_WORDS):
            stretch = words[start : start + _SCAN_WORDS]
            index = np.searchsorted(wanted, stretch)
            np.minimum(index, len(wanted) - 1, out=index)
            hits = np.flatnonzero(wanted[index] == stretch)
            if len(hits):
                keys.append(index[hits] * span + (shift + width * (start + hits)))
    if not keys:
        return found
    ordered = np.concatenate(keys)
    keys.clear()
    ordered.sort()
    bounds = np.searchsorted(ordered, np.arange(len(wanted_values) + 1, dtype=np.int64) * span)
    for rank, value in enumerate(wanted_values):
        low, high = int(bounds[rank]), int(bounds[rank + 1])
        if high > low:
            piece = ordered[low:high]
            piece -= rank * span
            found[value] = piece
    return found


def take_function_starts(image: Image, starts: Any, source: str) -> None:
    """Hand an image function starts (``0x..`` strings or ints) from ``source``.

    Only an image with no function table of its own takes them; anything that
    is not a number is left out.
    """
    values: list[int] = []
    for start in starts or []:
        try:
            values.append(int(start, 16) if isinstance(start, str) else int(start))
        except (TypeError, ValueError):
            continue
    if values:
        image.use_function_starts(values, source)


def load(path: str | Path) -> Image:
    """The image ``path`` maps to, or :class:`NotAPortableExecutable`."""
    data = Path(path).read_bytes()
    return parse(data)


def parse(data: bytes) -> Image:
    """The image these bytes map to, read from the headers directly."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise NotAPortableExecutable("not a PE file (no MZ header)")
    (pe_offset,) = struct.unpack_from("<I", data, 0x3C)
    if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise NotAPortableExecutable("not a PE file (no PE signature)")
    machine, count, _, _, _, optional_size, _ = struct.unpack_from("<HHIIIHH", data, pe_offset + 4)
    optional = pe_offset + 24
    if optional + 2 > len(data):
        raise NotAPortableExecutable("truncated optional header")
    (magic,) = struct.unpack_from("<H", data, optional)
    is64 = magic == 0x20B
    if magic not in (0x10B, 0x20B):
        raise NotAPortableExecutable(f"unknown optional header magic {magic:#x}")
    try:
        if is64:
            (image_base,) = struct.unpack_from("<Q", data, optional + 24)
            directories = optional + 112
        else:
            (image_base,) = struct.unpack_from("<I", data, optional + 28)
            directories = optional + 96
        (size_of_image,) = struct.unpack_from("<I", data, optional + 56)
        (directory_count,) = struct.unpack_from("<I", data, directories - 4)
    except struct.error as exc:
        raise NotAPortableExecutable(f"truncated optional header: {exc}") from exc
    sections: list[Section] = []
    table = optional + optional_size
    for index in range(count):
        at = table + index * 40
        if at + 40 > len(data):
            break
        name = data[at : at + 8].split(b"\0", 1)[0].decode("latin-1")
        vsize, rva, raw_size, raw_offset = struct.unpack_from("<IIII", data, at + 8)
        (characteristics,) = struct.unpack_from("<I", data, at + 36)
        raw_size = max(0, min(raw_size, len(data) - raw_offset)) if raw_offset < len(data) else 0
        sections.append(Section(name, rva, vsize, raw_offset, raw_size, characteristics))
    image = Image(
        data=data,
        image_base=image_base,
        is64=is64,
        size_of_image=size_of_image,
        sections=sections,
        machine=machine,
    )
    if directory_count > _IMPORT_DIRECTORY:
        entry = directories + _IMPORT_DIRECTORY * 8
        if entry + 8 <= len(data):
            rva, size = struct.unpack_from("<II", data, entry)
            if rva:
                image.import_directory = (rva, size)
    if machine == _AMD64 and directory_count > _EXCEPTION_DIRECTORY:
        entry = directories + _EXCEPTION_DIRECTORY * 8
        if entry + 8 <= len(data):
            rva, size = struct.unpack_from("<II", data, entry)
            _read_function_table(image, rva, size)
    return image


# UNW_FLAG_CHAININFO: the unwind data ends in the RUNTIME_FUNCTION of the entry
# this one continues.
_CHAININFO = 0x4
# How many links a chain is followed through before it is called unfollowable.
_CHAIN_DEPTH = 32


def _chained_to(image: Image, unwind: int) -> tuple[int, int] | None:
    """The (begin, unwind) of the entry an unwind record chains to, or ``None``."""
    offset = image.offset_of_rva(unwind)
    if offset is None or offset + 4 > len(image.data):
        return None
    header, _prolog, codes = image.data[offset], image.data[offset + 1], image.data[offset + 2]
    if not (header >> 3) & _CHAININFO:
        return None
    chained = offset + 4 + 2 * ((codes + 1) & ~1)
    if chained + 12 > len(image.data):
        return None
    begin, _finish, next_unwind = struct.unpack_from("<III", image.data, chained)
    return begin, next_unwind


def _owner(
    image: Image,
    begin: int,
    unwind: int,
    links: dict[int, tuple[int, int] | None] | None = None,
) -> int | None:
    """The start of the function an entry belongs to: its own begin, or its chain's end.

    ``links`` remembers each unwind record's link across the entries of one
    table, so a chain many entries share is read once.
    """
    known: dict[int, tuple[int, int] | None] = {} if links is None else links
    current_begin, current_unwind = begin, unwind
    for _ in range(_CHAIN_DEPTH):
        if current_unwind in known:
            link = known[current_unwind]
        else:
            link = known[current_unwind] = _chained_to(image, current_unwind)
        if link is None:
            return current_begin
        current_begin, current_unwind = link
    return None


def _read_function_table(image: Image, rva: int, size: int) -> None:
    """The x64 RUNTIME_FUNCTION entries: begin, end and unwind RVAs, twelve bytes each."""
    offset = image.offset_of_rva(rva) if rva else None
    if offset is None or size < 12:
        return
    end = min(len(image.data), offset + size)
    image.exception_directory = (offset, end - offset)
    ranges: dict[int, tuple[int, int]] = {}
    for at in range(offset, end - 11, 12):
        begin, finish, unwind = struct.unpack_from("<III", image.data, at)
        if begin == 0 and finish == 0:
            break
        if finish > begin and begin not in ranges:
            ranges[begin] = (finish, unwind)
    starts = sorted(ranges)
    image.function_starts = starts
    image.function_ends = [ranges[start][0] for start in starts]
    links: dict[int, tuple[int, int] | None] = {}
    image.function_owners = [_owner(image, start, ranges[start][1], links) for start in starts]


class _Records(Sequence[tuple[int, int, int, int]]):
    """The descriptors that read entries, as four columns of 64-bit numbers.

    Each is ``(address table RVA, DLL name RVA, file offset of its thunk
    array, entries read)``: thirty-two bytes a descriptor, no object per one.
    """

    def __init__(self) -> None:
        self._columns = (array("q"), array("q"), array("q"), array("q"))

    def append(self, record: tuple[int, int, int, int]) -> None:
        for column, value in zip(self._columns, record, strict=True):
            column.append(value)

    def __len__(self) -> int:
        return len(self._columns[0])

    @overload
    def __getitem__(self, index: int) -> tuple[int, int, int, int]: ...

    @overload
    def __getitem__(self, index: slice) -> list[tuple[int, int, int, int]]: ...

    def __getitem__(self, index: int | slice) -> Any:
        if isinstance(index, slice):
            return [self[i] for i in range(*index.indices(len(self)))]
        a, b, c, d = self._columns
        return (a[index], b[index], c[index], d[index])


class ImportSlots(Mapping[int, str]):
    """``{slot RVA: "DLL!name"}`` over an image's import descriptors, joined when looked up.

    What is held is one record per descriptor, ``(address table RVA, DLL name
    RVA, file offset of its thunk array, entries read)``, and per named slot
    three numbers in sorted arrays: the slot, the descriptor that names it and
    the entry's index. No name is held, the DLL's neither, and no index of the
    file is built: each name is sliced from the file when a slot is looked up,
    up to the next NUL within its bound and its section, which a search of at
    most the bound's bytes finds. A slot more than one
    descriptor names is named by the last of them in the directory's order
    (the loader writes them in that order); an entry with no readable name
    names no slot.
    """

    def __init__(self, image: Image) -> None:
        self.image = image
        self.width = 8 if image.is64 else 4
        self._kind = "<Q" if image.is64 else "<I"
        self._ordinal = 1 << (self.width * 8 - 1)
        self.records = _Records()
        self._bounds: tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray] | None = None
        self._slots = np.empty(0, dtype=np.int64)
        self._owners = np.empty(0, dtype=np.int32)
        self._indexes = np.empty(0, dtype=np.int32)

    # -- names --------------------------------------------------------------

    def _end(self, start: int, stop: int) -> int:
        """The file offset of the NUL that ends the name at ``start`` before ``stop``, or -1.

        ``stop`` is at most a name's bound past ``start``, so the search reads
        at most that many bytes, whatever the file holds.
        """
        if start >= stop:
            return -1
        return self.image.data.find(b"\0", start, stop)

    def _place(self, rva: int, skip: int, bound: int) -> tuple[int, int]:
        """The file offsets a name ``skip`` bytes past ``rva`` starts at and must end before.

        ``(0, 0)`` when ``rva`` is in no section's file bytes.
        """
        index = self.image._cover("rva").at(rva)
        if index is None:
            return 0, 0
        section = self.image.sections[index]
        relative = rva - section.rva
        if relative >= section.mapped_size:
            return 0, 0
        size = max(0, min(section.mapped_size, len(self.image.data) - section.raw_offset))
        start = relative + skip
        return section.raw_offset + start, section.raw_offset + min(size, start + bound + 1)

    def _text(self, rva: int, skip: int, bound: int) -> str:
        start, stop = self._place(rva, skip, bound)
        end = self._end(start, stop)
        return self.image.data[start:end].decode("latin-1") if end > start else ""

    def name(self, rva: int, bound: int) -> str:
        """The NUL-terminated name at ``rva``, inside the section ``rva`` falls in.

        Empty when ``rva`` is in no section's file bytes, or when no NUL ends
        the name within ``bound`` bytes or before that section's bytes end.
        """
        return self._text(rva, 0, bound)

    def has_name(self, rva: int, bound: int) -> bool:
        """Whether :meth:`name` reads a name at ``rva``, without making the string."""
        start, stop = self._place(rva, 0, bound)
        return self._end(start, stop) > start

    def dll(self, record: int) -> str:
        """The DLL name descriptor ``record`` names, read from the file."""
        return self.name(self.records[record][1], _DLL_NAME_BOUND)

    def entry(self, table: int, index: int) -> str:
        """The function the ``index``-th entry of the thunk array at ``table`` names, or ""."""
        (value,) = struct.unpack_from(self._kind, self.image.data, table + self.width * index)
        if value & self._ordinal:
            return f"#{value & 0xFFFF}"
        # The hint/name row, in the section the row's address falls in: two
        # bytes of hint, then the name.
        return self._text(value & 0x7FFFFFFF, 2, _IMPORT_NAME_BOUND)

    def _section_bounds(self) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """Per section: its RVA, file offset, mapped size and bytes the file holds of it."""
        if self._bounds is None:
            sections = self.image.sections
            length = len(self.image.data)
            self._bounds = (
                np.asarray([s.rva for s in sections] or [0], dtype=np.int64),
                np.asarray([s.raw_offset for s in sections] or [0], dtype=np.int64),
                np.asarray([s.mapped_size for s in sections] or [0], dtype=np.int64),
                np.asarray(
                    [min(s.mapped_size, max(0, length - s.raw_offset)) for s in sections] or [0],
                    dtype=np.int64,
                ),
            )
        return self._bounds

    def _readable(self, offsets: np.ndarray) -> np.ndarray:
        """Whether each entry at file ``offsets`` names a function, as :meth:`entry` reads it."""
        data = self.image.data
        kind = f"<u{self.width}"
        words = np.zeros(len(offsets), dtype=np.uint64)
        for residue in range(self.width):
            pick = np.flatnonzero(offsets % self.width == residue)
            if len(pick):
                view = np.frombuffer(
                    data, dtype=kind, count=(len(data) - residue) // self.width, offset=residue
                )
                words[pick] = view[(offsets[pick] - residue) // self.width]
        ordinal = (words & np.uint64(self._ordinal)) != 0
        hints = (words & np.uint64(0x7FFFFFFF)).astype(np.int64)
        owners = self.image._cover("rva").at_many(hints)
        readable = ordinal.copy()
        named = np.flatnonzero((owners >= 0) & ~ordinal)
        if not len(named):
            return np.asarray(readable, dtype=bool)
        rvas, bases, mapped_sizes, sizes = self._section_bounds()
        owner = owners[named]
        relative = hints[named] - rvas[owner]
        start = relative + 2
        stop = bases[owner] + np.minimum(sizes[owner], start + _IMPORT_NAME_BOUND + 1)
        start = bases[owner] + start
        ends = _first_nuls(data, start, stop)
        readable[named] = (relative < mapped_sizes[owner]) & (ends > start)
        return np.asarray(readable, dtype=bool)

    # -- the slots ------------------------------------------------------------

    def _index(self) -> tuple[int, int]:
        """Fill the slot arrays from the records; answer unread entries and slots named twice.

        The entries are read ``_IMPORT_STRETCH`` at a time into arrays sized
        once for all of them, so the working memory past the three arrays is a
        stretch's, whatever the file holds.
        """
        width = self.width
        total = sum(count for _, _, _, count in self.records)
        every = np.empty(total, dtype=np.int64)
        by = np.empty(total, dtype=np.int32)
        at = np.empty(total, dtype=np.int32)
        filled = 0
        unread = 0
        pieces: list[tuple[int, int, int]] = []
        held = 0

        def flush() -> None:
            nonlocal filled, unread
            if not pieces:
                return
            counts = np.asarray([count for _, _, count in pieces], dtype=np.int64)
            firsts = np.asarray([first for _, first, _ in pieces], dtype=np.int64)
            records = np.asarray([record for record, _, _ in pieces], dtype=np.int64)
            tables = np.asarray([self.records[r][2] for r, _, _ in pieces], dtype=np.int64)
            addresses = np.asarray([self.records[r][0] for r, _, _ in pieces], dtype=np.int64)
            begins = np.cumsum(counts) - counts
            local = (
                np.arange(int(counts.sum()), dtype=np.int64)
                - np.repeat(begins, counts)
                + np.repeat(firsts, counts)
            )
            named = self._readable(np.repeat(tables, counts) + width * local)
            kept = int(named.sum())
            every[filled : filled + kept] = (np.repeat(addresses, counts) + width * local)[named]
            by[filled : filled + kept] = np.repeat(records, counts)[named]
            at[filled : filled + kept] = local[named]
            filled += kept
            unread += len(named) - kept
            pieces.clear()

        for record, (_address, _dll, _table, count) in enumerate(self.records):
            first = 0
            while first < count:
                take = min(count - first, _IMPORT_STRETCH - held)
                pieces.append((record, first, take))
                held += take
                first += take
                if held >= _IMPORT_STRETCH:
                    flush()
                    held = 0
        flush()
        every, by, at = every[:filled], by[:filled], at[:filled]
        if filled > 1 and not bool((every[1:] > every[:-1]).all()):
            # Stable, so the slots one value names stay in the directory's order.
            order = np.argsort(every, kind="stable")
            every, by, at = every[order], by[order], at[order]
            del order
            last = np.ones(filled, dtype=bool)
            last[:-1] = every[1:] != every[:-1]
            every, by, at = every[last], by[last], at[last]
        self._slots, self._owners, self._indexes = every, by, at
        return unread, filled - len(every)

    def _position(self, slot: int) -> int:
        position = int(np.searchsorted(self._slots, slot))
        if position < len(self._slots) and int(self._slots[position]) == slot:
            return position
        return -1

    def __getitem__(self, slot: object) -> str:
        if not isinstance(slot, int | np.integer):
            raise KeyError(slot)
        position = self._position(int(slot))
        if position < 0:
            raise KeyError(slot)
        record = int(self._owners[position])
        function = self.entry(self.records[record][2], int(self._indexes[position]))
        if not function:
            raise KeyError(slot)
        dll = self.dll(record)
        return f"{dll}!{function}" if dll else function

    def __iter__(self) -> Iterator[int]:
        for start in range(0, len(self._slots), _SCAN_WORDS):
            yield from self._slots[start : start + _SCAN_WORDS].tolist()

    def __len__(self) -> int:
        return len(self._slots)

    def libraries(self) -> set[str]:
        """The DLL names the slots are named with, in lower case (the text before a ``!``).

        The slots are grouped by descriptor once (one stable sort); a group
        whose descriptor names a DLL adds that name, and a group whose
        descriptor names none adds what each of its names holds before a
        ``!``, as reading every slot's ``DLL!name`` would.
        """
        found: set[str] = set()
        if not len(self._owners):
            return found
        order = np.argsort(self._owners, kind="stable")
        owners = self._owners[order]
        cuts = np.flatnonzero(owners[1:] != owners[:-1]) + 1
        firsts = np.concatenate(([0], cuts)).tolist()
        ends = [*cuts.tolist(), len(owners)]
        for first, end in zip(firsts, ends, strict=True):
            record = int(owners[first])
            dll = self.dll(record)
            if dll:
                found.add(dll.split("!", 1)[0].lower())
                continue
            # No DLL name: each slot is named by its function alone.
            table = self.records[record][2]
            for index in self._indexes[order[first:end]].tolist():
                name = self.entry(table, index)
                if "!" in name:
                    found.add(name.split("!", 1)[0].lower())
        return found


def _first_nuls(data: bytes, starts: np.ndarray, stops: np.ndarray) -> np.ndarray:
    """For each ``[start, stop)`` of ``data``, the offset of its first NUL, or -1 when none.

    The stretches are at most a name's bound long. They are read as windows
    of a few bytes first, where nearly every name ends, and only the ones
    still open as windows of the whole bound: each window a row of a view of
    the file's own bytes (no copy of the file), a bounded number of rows at a
    time, so the work is the bytes the names span and the memory a batch's.
    A stretch too near the file's end for a whole window is searched alone.
    """
    raw = np.frombuffer(data, dtype=np.uint8)
    ends = np.full(len(starts), -1, dtype=np.int64)
    pending = np.flatnonzero(starts < stops)
    longest = int((stops - starts).max()) if len(starts) else 0
    for window in (_SHORT_NAME, max(longest, _SHORT_NAME)):
        if not len(pending) or len(raw) < window:
            break
        rows_view = np.lib.stride_tricks.sliding_window_view(raw, window)
        columns = np.arange(window, dtype=np.int32)
        rows = max(1, _WINDOW_BYTES // window)
        still: list[np.ndarray] = []
        for first in range(0, len(pending), rows):
            picked = pending[first : first + rows]
            begin = starts[picked]
            whole = begin <= len(raw) - window
            near_end = picked[~whole]
            picked, begin = picked[whole], begin[whole]
            for at in near_end.tolist():
                ends[at] = data.find(b"\0", int(starts[at]), int(stops[at]))
            limit = np.minimum(stops[picked] - begin, window)
            zero = (rows_view[begin] == 0) & (columns < limit[:, None])
            found = zero.any(axis=1)
            ends[picked[found]] = begin[found] + zero[found].argmax(axis=1)
            # A stretch longer than the window and not ended in it is read again.
            still.append(picked[~found & (stops[picked] - begin > window)])
        pending = np.concatenate(still) if still else pending[:0]
    for at in pending.tolist():
        ends[at] = data.find(b"\0", int(starts[at]), int(stops[at]))
    return ends


def _run_length(data: bytes, table: int, width: int, limit: int) -> int:
    """How many entries the thunk array at ``table`` holds before its zero entry or the file's end.

    Read no further than ``limit`` + 1 entries, in stretches that double from
    a few words: a longer array answers ``limit`` + 1. The caller's limit is
    what is left of the slot budget, so the words read in all stay within the
    budget plus a few per descriptor, and nothing is kept between calls.
    """
    kind = "<u8" if width == 8 else "<u4"
    available = max(0, (len(data) - table) // width)
    ceiling = min(available, limit + 1)
    read = 0
    stretch = _SHORT_NAME
    while read < ceiling:
        count = min(stretch, ceiling - read)
        words = np.frombuffer(data, dtype=kind, count=count, offset=table + width * read)
        zero = np.flatnonzero(words == 0)
        if len(zero):
            return read + int(zero[0])
        read += count
        stretch *= 2
    return ceiling


def _overlapping(records: Sequence[tuple[int, int, int, int]], width: int) -> int:
    """How many descriptors' address tables overlap an earlier-placed one's."""
    spans = sorted((address, address + width * count) for address, _, _, count in records if count)
    overlapping = 0
    reach = None
    for low, high in spans:
        if reach is not None and low < reach:
            overlapping += 1
        reach = high if reach is None else max(reach, high)
    return overlapping


def _read_imports(image: Image) -> ImportSlots:
    """The import slots of the import directory the header points at.

    Each descriptor is read until the all-zero one that ends the table or the
    file's end; each thunk array until its zero entry or the file's end. The
    names come from the lookup table, or from the address table where the
    lookup table is absent (the two hold the same entries before binding).

    Each descriptor is held as one record and no name is held (``ImportSlots``);
    a name is read inside the section its address falls in, up to its bound
    (``_IMPORT_NAME_BOUND``, ``_DLL_NAME_BOUND``). The entries read in all are
    at most one per ``width`` bytes of the file, which stores the address
    tables; past that the rest are not read. ``image.imports_note`` says so,
    says when address tables overlap, and says how many entries and
    descriptors name no readable name.
    """
    slots = ImportSlots(image)
    if image.import_directory is None:
        return slots
    data = image.data
    width = slots.width
    budget = len(data) // width
    used = 0
    unread_dlls = 0
    notes: list[str] = []
    # Descriptors that name the same DLL name or thunk array one after another
    # are read once for it.
    last_name: tuple[int, bool] | None = None
    last_table: tuple[int, int] | None = None
    at = image.offset_of_rva(image.import_directory[0])
    while at is not None and at + 20 <= len(data):
        lookup, _stamp, _chain, name_rva, address = struct.unpack_from("<IIIII", data, at)
        if not (lookup or name_rva or address):
            break
        at += 20
        if last_name is None or last_name[0] != name_rva:
            last_name = (name_rva, slots.has_name(name_rva, _DLL_NAME_BOUND))
        if not last_name[1]:
            unread_dlls += 1
        table = image.offset_of_rva(lookup or address)
        if table is None:
            continue
        if last_table is None or last_table[0] != table:
            last_table = (table, _run_length(data, table, width, budget - used))
        entries = last_table[1]
        cut = entries > budget - used
        entries = min(entries, budget - used)
        used += entries
        if entries:
            slots.records.append((address, name_rva, table, entries))
        if cut:
            notes.append(IMPORTS_CUT.format(cap=budget, width=width))
            break
    unread_functions, named_twice = slots._index()
    overlapping = _overlapping(slots.records, width)
    if overlapping:
        notes.append(TABLES_OVERLAP.format(descriptors=overlapping, slots=named_twice))
    if unread_functions or unread_dlls:
        notes.append(NAMES_NOT_READ.format(functions=unread_functions, dlls=unread_dlls))
    image.imports_note = "; ".join(notes)
    return slots

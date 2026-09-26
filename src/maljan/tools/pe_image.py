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
  An x86 image has no such table: when the caller has capa's function starts
  for the file, the nearest of them at or before the address in the same
  section is stated under a field of its own, ``after_function_start`` with
  its ``function_source`` — never as ``function``, because capa lists where
  functions start and not where they end, so it says what precedes the
  address, not what holds it; otherwise an address is stated alone. An
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

import struct
from bisect import bisect_right
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np

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


@dataclass
class Image:
    """The file's bytes, its sections and its function table."""

    data: bytes
    image_base: int
    is64: bool
    size_of_image: int
    sections: list[Section] = field(default_factory=list)
    # The ranges of ``.pdata``, sorted by their begin: the begin, the end
    # (exclusive) and the start of the function each belongs to (a chained
    # fragment's primary entry), ``None`` when a chain could not be followed.
    function_starts: list[int] = field(default_factory=list)
    function_ends: list[int] = field(default_factory=list)
    function_owners: list[int | None] = field(default_factory=list)
    # Function starts handed in from elsewhere (capa), for an image with no
    # table of its own; only starts, so the nearest one before an address is
    # what is stated, and said to be.
    outside_starts: list[int] = field(default_factory=list)
    outside_source: str = ""
    # The file offset and length of the exception directory, when there is one.
    exception_directory: tuple[int, int] | None = None
    # The import directory's RVA and size, when the header names one.
    import_directory: tuple[int, int] | None = None
    _imports: dict[int, str] | None = field(default=None, repr=False)

    # -- mapping ------------------------------------------------------------

    def section_at_offset(self, offset: int) -> Section | None:
        for section in self.sections:
            if section.raw_offset <= offset < section.raw_offset + section.mapped_size:
                return section
        return None

    def rva_of_offset(self, offset: int) -> int | None:
        section = self.section_at_offset(offset)
        if section is None:
            return None
        return section.rva + (offset - section.raw_offset)

    def section_at_rva(self, rva: int) -> Section | None:
        for section in self.sections:
            if section.rva <= rva < section.rva + max(section.virtual_size, section.raw_size):
                return section
        return None

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
        later = [start for start in self.outside_starts if start > rva]
        end = min([*later, section.rva + section.mapped_size])
        return before, end

    def imports_by_slot(self) -> dict[int, str]:
        """``{slot RVA: "DLL!name"}`` for every import-table entry, read once.

        The import address table as the file stores it: each entry's slot is
        where the loader writes the function's address, so a call through that
        slot calls that import. An entry imported by ordinal is named
        ``DLL!#ordinal``. Nothing is read that the headers do not point at.
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


def _owner(image: Image, begin: int, unwind: int) -> int | None:
    """The start of the function an entry belongs to: its own begin, or its chain's end."""
    current_begin, current_unwind = begin, unwind
    for _ in range(_CHAIN_DEPTH):
        link = _chained_to(image, current_unwind)
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
    image.function_owners = [_owner(image, start, ranges[start][1]) for start in starts]


def _c_string(data: bytes, offset: int) -> str:
    """The NUL-terminated name at ``offset``, as latin-1."""
    end = data.find(b"\0", offset)
    return data[offset : end if end != -1 else len(data)].decode("latin-1")


def _read_imports(image: Image) -> dict[int, str]:
    """``{slot RVA: "DLL!name"}`` from the import directory the header points at.

    Each descriptor is read until the all-zero one that ends the table or the
    file's end; each thunk array until its zero entry or the file's end. The
    names come from the lookup table, or from the address table where the
    lookup table is absent (the two hold the same entries before binding).
    """
    found: dict[int, str] = {}
    if image.import_directory is None:
        return found
    data = image.data
    width = 8 if image.is64 else 4
    ordinal_flag = 1 << (width * 8 - 1)
    at = image.offset_of_rva(image.import_directory[0])
    while at is not None and at + 20 <= len(data):
        lookup, _stamp, _chain, name_rva, address = struct.unpack_from("<IIIII", data, at)
        if not (lookup or name_rva or address):
            break
        at += 20
        name_at = image.offset_of_rva(name_rva)
        dll = _c_string(data, name_at) if name_at is not None else ""
        table = image.offset_of_rva(lookup or address)
        index = 0
        while table is not None and table + width * (index + 1) <= len(data):
            (value,) = struct.unpack_from("<Q" if image.is64 else "<I", data, table + width * index)
            if not value:
                break
            if value & ordinal_flag:
                function = f"#{value & 0xFFFF}"
            else:
                hint_at = image.offset_of_rva(value & 0x7FFFFFFF)
                function = _c_string(data, hint_at + 2) if hint_at is not None else ""
            if function:
                found[address + width * index] = f"{dll}!{function}" if dll else function
            index += 1
    return found

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
  and end of every function that has unwind data. An x86 image has no such
  table, and an address outside every listed function has no function stated:
  a start that is not in the table is not guessed at.
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
    # Sorted function starts and the matching ends (exclusive), from ``.pdata``.
    function_starts: list[int] = field(default_factory=list)
    function_ends: list[int] = field(default_factory=list)

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
        """The start of the listed function whose range holds ``rva``, or ``None``."""
        index = bisect_right(self.function_starts, rva) - 1
        if index < 0:
            return None
        if rva < self.function_ends[index]:
            return self.function_starts[index]
        return None

    @property
    def function_table(self) -> str:
        """Which table the functions come from, said in the answers."""
        if self.function_starts:
            return f"exception directory, {len(self.function_starts)} functions"
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
        if rva is not None and section is not None and section.executable:
            start = self.function_at(rva)
            place["function"] = hex(start) if start is not None else None
        else:
            place["function"] = None
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
    if machine == _AMD64 and directory_count > _EXCEPTION_DIRECTORY:
        entry = directories + _EXCEPTION_DIRECTORY * 8
        if entry + 8 <= len(data):
            rva, size = struct.unpack_from("<II", data, entry)
            _read_function_table(image, rva, size)
    return image


def _read_function_table(image: Image, rva: int, size: int) -> None:
    """The x64 RUNTIME_FUNCTION entries: begin, end and unwind RVAs, twelve bytes each."""
    offset = image.offset_of_rva(rva) if rva else None
    if offset is None or size < 12:
        return
    end = min(len(image.data), offset + size)
    ranges: dict[int, int] = {}
    for at in range(offset, end - 11, 12):
        begin, finish, _unwind = struct.unpack_from("<III", image.data, at)
        if begin == 0 and finish == 0:
            break
        if finish > begin and begin not in ranges:
            ranges[begin] = finish
    starts = sorted(ranges)
    image.function_starts = starts
    image.function_ends = [ranges[start] for start in starts]

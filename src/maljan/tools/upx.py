"""UPX unpacking: a UPX-packed PE read back into the program it holds, from UPX's own records.

A UPX-packed file shows every reader the packer's stub: its strings, its three
imports, its high-entropy section. The program is inside, compressed, with the
records UPX keeps to put it back. This module reads those records and writes
the program out as a file of its own, the way ``upx -d`` does, in Python and
with no program run: nothing in the sample executes, and no ``upx`` binary is
needed on the host.

What it reads, in UPX's own layout:

* **The pack header**, the 32 bytes that start ``UPX!``, where UPX writes it:
  in the 1024 bytes from 64 before the second section's file data, or (older
  versions) from the third section's. It states the format, the compression
  method and level, the filter, the compressed and unpacked sizes and the
  adler32 of both; its last byte is the sum of the bytes before it modulo 251,
  and a header whose sum does not match is an error.
* **The compressed data** right after the header, checked against the stated
  adler32 before anything is decompressed, and decompressed by the method the
  header names: NRV2B, NRV2D and NRV2E (each in its 32-bit, 16-bit and 8-bit
  bit-stream form) by decoders written here, LZMA by the standard library's raw
  LZMA1 filter. The unpacked data must be exactly the stated size and its
  adler32 the stated one; UPX's PE packer checksums the data as it was
  compressed, with the code filter still applied, and the answer says which
  reading matched. A mismatch is an error and no image is written.
* **The code filter** UPX applied to the code section (``0x24``, ``0x25``,
  ``0x26``: call and jump targets made absolute and stored big-endian behind a
  marker byte), undone over the code range the stored header names.
* **The original PE header and section table** UPX stored after the image,
  then the import records (library names from the packed file's own import
  table, function names and ordinals from UPX's list), the relocation records
  (delta-coded positions, values stored byte-swapped and less the image base),
  the export table UPX moved out of the image, and the resources UPX kept
  uncompressed, each put back where the original header says it was. The
  rebuilt file's sections hold the unpacked image at the file offsets its
  section table states.

What it never does: guess. A file with no pack header, a format, method,
filter or record kind this reader does not read, and a header that states more
than the platform's fixed sample upload cap (``core.delivery_limits``) are
answered ``no:`` with the reason; a header, stream or record that does not
decode as UPX wrote it is an error naming where and why. Nothing is tried with
other parameters and no partial image is written.

Bounds come from structure. The unpacked size is held to the upload cap and to
the image the packed file maps; every decoder reads its input once and writes
at most the stated size, a back-reference is copied in slices, and every count
a record states is held to the bytes that hold it. Time and memory are linear
in the file and the unpacked size.
"""

from __future__ import annotations

import hashlib
import lzma
import re
import struct
import zlib
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from maljan.core.delivery_limits import SAMPLE_UPLOAD_MAX_BYTES
from maljan.tools import binary, pe_image
from maljan.tools.errors import TOOL_FAILED, tool_error

TOOL = "unpack_upx"

# The display label of the unpacked file, which names it on disk through the
# carving writer's own rule (``binary.carved_file_name``).
UNPACKED_LABEL = "upx-unpacked"

# The most bytes the unpacked data and the rebuilt file may hold: the
# platform's fixed sample upload cap. The program a packed file holds is a
# sample of that kind, and a header stating more is answered with the cap.
UNPACKED_CAP = SAMPLE_UPLOAD_MAX_BYTES

REMEDIATION = (
    "the file's UPX data does not decode as UPX writes it, so no unpacked file was written; "
    "read the packed file itself with the other tools"
)

# -- what the pack header names ---------------------------------------------------

_MAGIC = b"UPX!"
_HEADER_SIZE = 32
# Where UPX looks for the header: from 64 bytes before the second section's
# file data, or (older versions) at the third section's, 1024 bytes each.
_WINDOW_BEFORE = 64
_WINDOW = 1024
# Header versions 10 and later have the 32-byte layout read here.
_FIRST_VERSION = 10
# The version byte UPX writes into files it will not unpack itself.
_REFUSED_VERSION = 0xFF

FORMAT_WIN32_PE = 9
FORMAT_WIN64_PEP = 36
FORMATS = {FORMAT_WIN32_PE: "win32/pe", FORMAT_WIN64_PEP: "win64/pep"}
_MACHINE_OF_FORMAT = {FORMAT_WIN32_PE: 0x14C, FORMAT_WIN64_PEP: 0x8664}

# Method number: (name, decoder, bit-stream word size in bytes).
METHODS: dict[int, tuple[str, str, int]] = {
    2: ("NRV2B_LE32", "2b", 4),
    3: ("NRV2B_8", "2b", 1),
    4: ("NRV2B_LE16", "2b", 2),
    5: ("NRV2D_LE32", "2d", 4),
    6: ("NRV2D_8", "2d", 1),
    7: ("NRV2D_LE16", "2d", 2),
    8: ("NRV2E_LE32", "2e", 4),
    9: ("NRV2E_8", "2e", 1),
    10: ("NRV2E_LE16", "2e", 2),
    14: ("LZMA", "lzma", 0),
}

# Filter number: the opcodes whose targets UPX rewrote (call, jump, both).
FILTERS: dict[int, tuple[int, ...]] = {0x24: (0xE8,), 0x25: (0xE9,), 0x26: (0xE8, 0xE9)}
_FILTER_NAMES = {0x24: "call", 0x25: "jump", 0x26: "call and jump"}

CAPABILITY_FACTS = (
    "Reads a UPX-packed Windows PE (UPX formats win32/pe and win64/pep) from UPX's own pack "
    "header and records, in Python, with nothing run and no upx program needed: methods "
    + ", ".join(f"{name} ({number})" for number, (name, _, _) in METHODS.items())
    + "; code filters "
    + ", ".join(f"{number:#04x} ({_FILTER_NAMES[number]})" for number in FILTERS)
    + " and none. Both adler32 checksums are checked; the unpacked file is written beside the "
    "files carve_payloads writes, and its carved_path is in the answer."
)

# -- the stored PE header ---------------------------------------------------------

_OH_SIZE = {False: 248, True: 264}
_DIRECTORIES = {False: 120, True: 136}
_DIRECTORY_COUNT_AT = {False: 116, True: 132}
_SECTION_ENTRY = 40
_EXPORT, _IMPORT, _RESOURCE, _BASERELOC, _DEBUG, _BOUND_IMPORT, _IAT = 0, 1, 2, 5, 6, 11, 12
_RELOCS_STRIPPED = 0x0001
_RT_GROUP_ICON = 14
_IMPORT_DESCRIPTOR = 20
_EXPORT_DIRECTORY = 40

# Every no: sentence, written once.
NOT_A_PE = "no: the file is not a PE image ({why})"
NO_HEADER = (
    "no: the file holds no UPX pack header (the bytes UPX!) where UPX writes one: the 1024 "
    "bytes from 64 before the second section's file data, or from the third section's"
)
NO_SECTIONS = "no: the file has fewer than two sections, and UPX's pack header is placed by them"
OLD_VERSION = (
    "no: the UPX pack header at {offset} is version {version}; versions before 10 are not read here"
)
REFUSED = (
    "no: the UPX pack header at {offset} is version 255, which UPX writes into files it "
    "will not unpack"
)
FORMAT_NOT_READ = (
    "no: the UPX pack header at {offset} states format {format}; the formats read here are "
    "9 (win32/pe) and 36 (win64/pep)"
)
MACHINE_MISMATCH = (
    "no: the UPX pack header states format {format} ({name}) and the PE header machine "
    "{machine:#06x}"
)
METHOD_NOT_READ = "no: UPX method {method} is not read here"
FILTER_NOT_READ = "no: UPX filter {filter:#04x} is not read here"
OVER_CAP = (
    "no: the UPX pack header states {size} unpacked bytes, above the platform's fixed sample "
    "upload cap of {cap} bytes; nothing was decompressed"
)
FILE_OVER_CAP = (
    "no: the rebuilt file would be {size} bytes, above the platform's fixed sample upload cap "
    "of {cap} bytes; nothing was written"
)
RELOCS16_NOT_READ = "no: the file's 16-bit relocation records are not read here"


class NotRead(Exception):
    """The file is not one this reader unpacks; the message is the ``no:`` sentence."""

    def __init__(self, message: str, header: PackHeader | None = None) -> None:
        super().__init__(message)
        self.header = header


class Damaged(Exception):
    """The UPX data does not decode or rebuild as UPX wrote it; the message says where."""

    def __init__(self, message: str, header: PackHeader | None = None) -> None:
        super().__init__(message)
        self.header = header


@dataclass(frozen=True)
class PackHeader:
    """UPX's pack header as written in the file."""

    offset: int
    version: int
    format: int
    method: int
    level: int
    u_adler: int
    c_adler: int
    u_len: int
    c_len: int
    u_file_size: int
    filter: int
    filter_cto: int
    n_mru: int

    @property
    def data_offset(self) -> int:
        """Where the compressed data starts: right after the header."""
        return self.offset + _HEADER_SIZE

    def facts(self) -> dict[str, Any]:
        method = METHODS.get(self.method)
        return {
            "offset": hex(self.offset),
            "compressed_data_offset": hex(self.data_offset),
            "version": self.version,
            "format": f"{FORMATS.get(self.format, 'not read here')} ({self.format})",
            "method": f"{method[0] if method else 'not read here'} ({self.method})",
            "level": self.level,
            "filter": hex(self.filter),
            "filter_cto": hex(self.filter_cto),
        }


@dataclass
class Unpacked:
    """One unpack: the rebuilt file and the facts read on the way."""

    header: PackHeader
    image: bytes
    u_adler: int
    c_adler: int
    checksum_reading: str
    entry_point: int
    rebuilt: dict[str, str] = field(default_factory=dict)
    overlay: int = 0


# ---------------------------------------------------------------------------
# Little helpers that refuse rather than read past an end
# ---------------------------------------------------------------------------


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def _u16(buf: bytes | bytearray, at: int, what: str) -> int:
    if at < 0 or at + 2 > len(buf):
        raise Damaged(f"{what} at {at:#x} lies outside the unpacked data")
    return int(struct.unpack_from("<H", buf, at)[0])


def _u32(buf: bytes | bytearray, at: int, what: str) -> int:
    if at < 0 or at + 4 > len(buf):
        raise Damaged(f"{what} at {at:#x} lies outside the unpacked data")
    return int(struct.unpack_from("<I", buf, at)[0])


def _word(buf: bytes | bytearray, at: int, width: int, what: str) -> int:
    if at < 0 or at + width > len(buf):
        raise Damaged(f"{what} at {at:#x} lies outside the unpacked data")
    return int.from_bytes(buf[at : at + width], "little")


def _put(buf: bytearray, at: int, data: bytes | bytearray, what: str) -> None:
    """Write ``data`` at ``at``, never past the end: a slice assignment there would grow ``buf``."""
    if at < 0 or at + len(data) > len(buf):
        raise Damaged(f"{what} at {at:#x} ({len(data)} bytes) lies outside the unpacked data")
    buf[at : at + len(data)] = data


def _put_word(buf: bytearray, at: int, value: int, width: int, what: str) -> None:
    _put(buf, at, (value & ((1 << (8 * width)) - 1)).to_bytes(width, "little"), what)


def _next_nuls(data: bytes, starts: list[int], end: int) -> dict[int, int]:
    """Where the NUL ending each string that starts at one of ``starts`` lies, before ``end``.

    Each byte between the lowest start and ``end`` is scanned once: the starts
    are visited from the highest down, and a start whose segment up to the next
    start holds no NUL ends where that next start's string ends. A start with
    no NUL before ``end`` maps to -1.
    """
    found: dict[int, int] = {}
    bound, carried = end, -1
    for start in sorted(set(starts), reverse=True):
        at = data.find(b"\0", start, bound) if start < bound else -1
        found[start] = at if at >= 0 else carried
        bound, carried = start, found[start]
    return found


# ---------------------------------------------------------------------------
# The packed file
# ---------------------------------------------------------------------------


@dataclass
class _Packed:
    """What the packed file's own headers state, read once."""

    data: bytes
    image: pe_image.Image
    pe_offset: int
    machine: int
    flags: int
    directories: dict[int, tuple[int, int]]

    def directory(self, index: int) -> tuple[int, int]:
        return self.directories.get(index, (0, 0))

    def mapped(self, rva: int) -> tuple[int, int] | None:
        """The file offset of ``rva`` and where its section's file bytes end."""
        section = self.image.section_at_rva(rva)
        if section is None or rva - section.rva >= section.mapped_size:
            return None
        return section.raw_offset + (rva - section.rva), section.raw_offset + section.mapped_size

    def read(self, rva: int, size: int, what: str) -> bytes:
        place = self.mapped(rva)
        if place is None or size < 0 or place[0] + size > place[1]:
            raise Damaged(f"{what} at rva {rva:#x} ({size} bytes) is not held in the packed file")
        return self.data[place[0] : place[0] + size]

    @property
    def overlay_start(self) -> int:
        return max(
            (s.raw_offset + s.raw_size for s in self.image.sections if s.raw_size), default=0
        )


def _read_packed(data: bytes) -> _Packed:
    try:
        image = pe_image.parse(data)
    except pe_image.NotAPortableExecutable as exc:
        raise NotRead(NOT_A_PE.format(why=exc)) from exc
    (pe_offset,) = struct.unpack_from("<I", data, 0x3C)
    machine, _count = struct.unpack_from("<HH", data, pe_offset + 4)
    (flags,) = struct.unpack_from("<H", data, pe_offset + 22)
    directories_at = pe_offset + 24 + (112 if image.is64 else 96)
    directories: dict[int, tuple[int, int]] = {}
    if directories_at <= len(data):
        (count,) = struct.unpack_from("<I", data, directories_at - 4)
        for index in range(min(count, 16)):
            at = directories_at + 8 * index
            if at + 8 > len(data):
                break
            directories[index] = struct.unpack_from("<II", data, at)
    return _Packed(data, image, pe_offset, machine, flags, directories)


def _checksum_byte(block: bytes) -> int:
    """UPX's header checksum: the bytes after the magic, before the last, summed modulo 251."""
    return sum(block[4:31]) % 251


def read_pack_header(data: bytes) -> PackHeader:
    """The pack header where UPX writes it, or :class:`NotRead` or :class:`Damaged` saying why."""
    packed = _read_packed(data)
    return _find_header(packed)


def _find_header(packed: _Packed) -> PackHeader:
    sections = packed.image.sections
    if len(sections) < 2:
        raise NotRead(NO_SECTIONS)
    windows = [max(0, sections[1].raw_offset - _WINDOW_BEFORE)]
    if len(sections) > 2:
        windows.append(sections[2].raw_offset)
    data = packed.data
    for start in windows:
        at = data.find(_MAGIC, start, start + _WINDOW)
        if at < 0:
            continue
        return _parse_header(data, at)
    raise NotRead(NO_HEADER)


def _parse_header(data: bytes, at: int) -> PackHeader:
    block = data[at : at + _HEADER_SIZE]
    offset = hex(at)
    if len(block) < 8:
        raise Damaged(f"the UPX pack header at {offset} is cut off by the end of the file")
    version = block[4]
    if version == _REFUSED_VERSION:
        raise NotRead(REFUSED.format(offset=offset))
    if version < _FIRST_VERSION:
        raise NotRead(OLD_VERSION.format(offset=offset, version=version))
    if len(block) < _HEADER_SIZE:
        raise Damaged(f"the UPX pack header at {offset} is cut off by the end of the file")
    if block[5] >= 128:
        raise NotRead(FORMAT_NOT_READ.format(offset=offset, format=block[5]))
    u_adler, c_adler, u_len, c_len, u_file_size = struct.unpack_from("<IIIII", block, 8)
    header = PackHeader(
        offset=at,
        version=version,
        format=block[5],
        method=block[6],
        level=block[7] & 15,
        u_adler=u_adler,
        c_adler=c_adler,
        u_len=u_len,
        c_len=c_len,
        u_file_size=u_file_size,
        filter=block[28],
        filter_cto=block[29],
        n_mru=block[30] + 1 if block[30] else 0,
    )
    stated, summed = block[31], _checksum_byte(block)
    if stated != summed:
        raise Damaged(
            f"the UPX pack header at {offset} states checksum byte {stated} and its bytes sum "
            f"to {summed} (modulo 251)",
            header,
        )
    if c_len < 2 or u_len < 2 or u_len < c_len:
        raise Damaged(
            f"the UPX pack header at {offset} states {c_len} compressed and {u_len} unpacked "
            "bytes, which no UPX stream has",
            header,
        )
    return header


# ---------------------------------------------------------------------------
# Decompression
# ---------------------------------------------------------------------------

# The largest offset prefix the NRV bit streams carry: past it no offset fits
# in the 32 bits the format reads, and UPX's own decoder stops there.
_MAX_PREFIX = 0xFFFFFF + 3
_END_MARKER = 0xFFFFFFFF


def _nrv(kind: str, width: int, src: bytes, size: int) -> bytearray:
    """Decode one NRV2B, NRV2D or NRV2E stream into exactly ``size`` bytes, or raise.

    Bits are read most significant first from words of ``width`` bytes (1, 2
    or 4, little-endian), and literals and offset bytes from the stream between
    them, as UPX's decoders read them. Every count is held to what is left of
    ``size`` as it is read, so no number grows past the output, and the stream
    must end at its end marker with every byte read.
    """
    n = len(src)
    dst = bytearray()
    state = [0, 0, 0]  # bit buffer, bits left in it, read position
    word_bits = width * 8

    def bit() -> int:
        if state[1] == 0:
            at = state[2]
            if at + width > n:
                raise Damaged(f"the compressed stream ends at byte {n} before its end marker")
            state[0] = int.from_bytes(src[at : at + width], "little")
            state[2] = at + width
            state[1] = word_bits
        state[1] -= 1
        return (state[0] >> state[1]) & 1

    def byte() -> int:
        at = state[2]
        if at >= n:
            raise Damaged(f"the compressed stream ends at byte {n} before its end marker")
        state[2] = at + 1
        return src[at]

    def gamma(start: int, limit: int, beyond: str) -> int:
        value = start
        while True:
            value = value * 2 + bit()
            if value > limit:
                raise Damaged(f"{beyond.format(at=len(dst))}")
            if bit():
                return value

    past_offsets = "an offset at output byte {at} runs past what the stream can hold"
    past_size = (
        f"a length at output byte {{at}} runs past the {size} unpacked bytes the header states"
    )

    last_offset = 1
    near = 0xD00 if kind == "2b" else 0x500
    while True:
        while bit():
            if len(dst) >= size:
                raise Damaged(f"the stream writes past the {size} unpacked bytes the header states")
            dst.append(byte())
        length_bit = 0
        if kind == "2b":
            prefix = gamma(1, _MAX_PREFIX, past_offsets)
        else:
            prefix = 1
            while True:
                prefix = prefix * 2 + bit()
                if prefix > _MAX_PREFIX:
                    raise Damaged(past_offsets.format(at=len(dst)))
                if bit():
                    break
                prefix = (prefix - 1) * 2 + bit()
                if prefix > _MAX_PREFIX:
                    raise Damaged(past_offsets.format(at=len(dst)))
        if prefix == 2:
            offset = last_offset
            if kind != "2b":
                length_bit = bit()
        else:
            combined = (prefix - 3) * 256 + byte()
            if combined == _END_MARKER:
                break
            if kind == "2b":
                offset = combined + 1
            else:
                length_bit = (combined & 1) ^ 1
                offset = (combined >> 1) + 1
            last_offset = offset
        room = size - len(dst)
        if kind == "2b":
            length = bit() * 2 + bit()
            if length == 0:
                length = gamma(1, room + 2, past_size) + 2
        elif kind == "2d":
            length = length_bit * 2 + bit()
            if length == 0:
                length = gamma(1, room + 2, past_size) + 2
        elif length_bit:
            length = 1 + bit()
        elif bit():
            length = 3 + bit()
        else:
            length = gamma(1, room + 3, past_size) + 3
        count = length + (offset > near) + 1
        olen = len(dst)
        if offset > olen:
            raise Damaged(
                f"a back-reference at output byte {olen} reaches {offset} bytes back, before the "
                "start of the output"
            )
        if count > room:
            raise Damaged(f"the stream writes past the {size} unpacked bytes the header states")
        begin = olen - offset
        if offset >= count:
            dst += dst[begin : begin + count]
        else:
            run = bytes(dst[begin:olen])
            dst += run * (count // offset) + run[: count % offset]
    if len(dst) != size:
        raise Damaged(f"the stream ends after {len(dst)} bytes; the header states {size}")
    if state[2] != n:
        raise Damaged(f"the stream's end marker is at byte {state[2]} of the {n} compressed bytes")
    return dst


def _lzma(src: bytes, size: int) -> bytearray:
    """Decode UPX's LZMA stream (two properties bytes, then raw LZMA1) into ``size`` bytes."""
    if len(src) < 3:
        raise Damaged("the LZMA stream is shorter than its properties")
    pb, lp, lc = src[0] & 7, src[1] >> 4, src[1] & 15
    if pb >= 5 or lp >= 5 or lc >= 9 or (src[0] >> 3) != lc + lp:
        raise Damaged(f"the LZMA stream's properties bytes {src[:2].hex()} are not UPX's")
    filters = [
        {"id": lzma.FILTER_LZMA1, "lc": lc, "lp": lp, "pb": pb, "dict_size": max(4096, size)}
    ]
    try:
        decoder = lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=filters)
        out = decoder.decompress(src[2:], max_length=size)
    except (lzma.LZMAError, ValueError) as exc:
        raise Damaged(f"the LZMA stream does not decode: {exc}") from exc
    if len(out) != size:
        raise Damaged(f"the LZMA stream ends after {len(out)} bytes; the header states {size}")
    return bytearray(out)


def decompress(method: int, src: bytes, size: int) -> bytearray:
    """``src`` decoded by UPX method ``method`` into exactly ``size`` bytes."""
    _name, kind, width = METHODS[method]
    if kind == "lzma":
        return _lzma(src, size)
    return _nrv(kind, width, src, size)


# ---------------------------------------------------------------------------
# The code filter
# ---------------------------------------------------------------------------


def unfilter(buf: bytearray, start: int, length: int, filter_id: int, cto: int) -> int:
    """Undo UPX filter ``filter_id`` over ``buf[start:start+length]``; how many targets were read.

    Each call or jump opcode the filter names, at a position before the last
    five bytes of the range, whose next byte is the marker ``cto``, holds a
    big-endian absolute target; it is put back as the little-endian
    displacement from the byte after the opcode, and the scan resumes after
    it. ``addvalue`` is the range's own offset in the image, as UPX gives it.
    """
    opcodes = FILTERS[filter_id]
    marker = bytes([cto])
    pattern = re.compile(
        b"(?=["
        + b"".join(re.escape(bytes([op])) for op in opcodes)
        + b"]"
        + re.escape(marker)
        + b")"
    )
    end = start + length - 5
    addvalue = start
    resume = start
    restored = 0
    top = cto << 24
    # The marker byte after an opcode at the last position is still inside
    # the buffer, so the search may look one byte past the last position.
    for found in pattern.finditer(buf, start, max(start, min(len(buf), end + 1))):
        at = found.start()
        if at >= end:
            break
        if at < resume:
            continue
        stored = int.from_bytes(buf[at + 1 : at + 5], "big")
        value = (stored - (at - start) - 1 - addvalue - top) & 0xFFFFFFFF
        buf[at + 1 : at + 5] = value.to_bytes(4, "little")
        resume = at + 5
        restored += 1
    return restored


# ---------------------------------------------------------------------------
# The rebuild
# ---------------------------------------------------------------------------


@dataclass
class _Original:
    """The PE header UPX stored, held as bytes and read and written by field."""

    raw: bytearray
    is64: bool

    def u16(self, at: int) -> int:
        return int(struct.unpack_from("<H", self.raw, at)[0])

    def u32(self, at: int) -> int:
        return int(struct.unpack_from("<I", self.raw, at)[0])

    def set_u16(self, at: int, value: int) -> None:
        struct.pack_into("<H", self.raw, at, value)

    def set_u32(self, at: int, value: int) -> None:
        struct.pack_into("<I", self.raw, at, value & 0xFFFFFFFF)

    @property
    def objects(self) -> int:
        return self.u16(6)

    @property
    def flags(self) -> int:
        return self.u16(22)

    @property
    def image_base(self) -> int:
        return int(struct.unpack_from("<Q", self.raw, 48)[0]) if self.is64 else self.u32(52)

    def directory(self, index: int) -> tuple[int, int]:
        at = _DIRECTORIES[self.is64] + 8 * index
        return self.u32(at), self.u32(at + 4)

    def set_directory(self, index: int, rva: int, size: int) -> None:
        at = _DIRECTORIES[self.is64] + 8 * index
        self.set_u32(at, rva)
        self.set_u32(at + 4, size)


class _Records:
    """UPX's records after the stored header, read in the order UPX wrote them."""

    def __init__(self, buf: bytearray, at: int) -> None:
        self.buf = buf
        self.at = at

    def u32(self, what: str) -> int:
        value = _u32(self.buf, self.at, what)
        self.at += 4
        return value

    def u16(self, what: str) -> int:
        value = _u16(self.buf, self.at, what)
        self.at += 2
        return value

    def u8(self, what: str) -> int:
        if self.at >= len(self.buf):
            raise Damaged(f"{what} at {self.at:#x} lies outside the unpacked data")
        value = self.buf[self.at]
        self.at += 1
        return value


@dataclass
class _Image:
    """The unpacked data with the facts every rebuild step reads."""

    buf: bytearray
    original: _Original
    rvamin: int
    packed: _Packed
    records: _Records

    @property
    def width(self) -> int:
        return 8 if self.original.is64 else 4

    def at(self, rva: int, what: str) -> int:
        """The position in the unpacked data of ``rva``."""
        position = rva - self.rvamin
        if position < 0 or position > len(self.buf):
            raise Damaged(f"{what} at rva {rva:#x} lies outside the unpacked image")
        return position


def _rebuild_imports(image: _Image) -> str:
    """Write the import table back from UPX's records; the sentence saying what was written."""
    original, buf = image.original, image.buf
    table_rva, table_size = original.directory(_IMPORT)
    if table_rva == 0 or table_size <= _IMPORT_DESCRIPTOR:
        return "none: the stored header names no import table"
    records = image.records
    idata = records.u32("the import records' position")
    names_rva = records.u32("the import names' position")
    packed_rva, _packed_size = image.packed.directory(_IMPORT)
    place = image.packed.mapped(packed_rva) if packed_rva else None
    if place is None:
        raise Damaged(
            "the packed file's import table, which holds the library names, is not in the file"
        )
    base, end = place
    data = image.packed.data
    width = image.width
    ord_mask = 1 << (8 * width - 1)

    # First pass: where each record starts, and the library names' total size.
    starts: list[int] = []
    p = idata
    while _u32(buf, p, "an import record") != 0:
        starts.append(p)
        p += 8
        while True:
            if p >= len(buf):
                raise Damaged(f"the import records run past the unpacked data at {p:#x}")
            tag = buf[p]
            if tag == 0:
                break
            if tag == 1:
                close = buf.find(b"\0", p + 1)
                if close < 0:
                    raise Damaged(f"an imported name at {p + 1:#x} is not terminated")
                p = close + 1
            elif tag == 0xFF:
                p += 3
            else:
                p += 5
        p += 1
    name_offsets = [base + _u32(buf, s, "a library name") for s in starts]
    nuls = _next_nuls(data, [o for o in name_offsets if base <= o < end], end)
    dll_names: list[bytes] = []
    for offset in name_offsets:
        close = nuls.get(offset, -1) if base <= offset < end else -1
        if close < 0:
            raise Damaged(
                f"a library name at file offset {offset:#x} is not held in the packed import table"
            )
        dll_names.append(data[offset:close])
    total_dll = _align(sum(len(n) + 1 for n in dll_names), 2)

    descriptor = image.at(table_rva, "the import table")
    dll_at = image.at(names_rva, "the import names") if names_rva else 0
    names_at = dll_at + total_dll
    names_start = names_at
    functions = 0
    for start, dll in zip(starts, dll_names, strict=True):
        iat_rva = _u32(buf, start + 4, "an import address table") + image.rvamin
        if names_rva:
            _put(buf, dll_at, dll + b"\0", "a library name")
            _put_word(buf, descriptor + 12, dll_at + image.rvamin, 4, "an import descriptor")
            dll_at += len(dll) + 1
        else:
            held = _u32(buf, descriptor + 12, "an import descriptor")
            _put(buf, image.at(held, "a library name"), dll + b"\0", "a library name")
        _put_word(buf, descriptor + 16, iat_rva, 4, "an import descriptor")
        slot = image.at(iat_rva, "an import address table")
        p = start + 8
        while buf[p] != 0:
            tag = buf[p]
            if tag == 1:
                close = buf.find(b"\0", p + 1)
                if close < 0:
                    raise Damaged(f"an imported name at {p + 1:#x} is not terminated")
                name = bytes(buf[p + 1 : close + 1])
                if names_rva:
                    if (names_at - names_start) & 1:
                        names_at -= 1
                    _put(buf, names_at + 2, name, "an imported name")
                    _put_word(buf, slot, names_at + image.rvamin, width, "an import slot")
                    names_at += 2 + len(name)
                else:
                    held = _word(buf, slot, width, "an import slot")
                    _put(buf, image.at(held + 2, "an imported name"), name, "an imported name")
                p = close + 1
            elif tag == 0xFF:
                ordinal = _u16(buf, p + 1, "an imported ordinal")
                _put_word(buf, slot, ordinal + ord_mask, width, "an import slot")
                p += 3
            else:
                where = _u32(buf, p + 1, "an imported ordinal's place")
                value = int.from_bytes(
                    image.packed.read(packed_rva + where, width, "an imported ordinal"), "little"
                )
                if not value & ord_mask:
                    raise Damaged(
                        f"the packed import entry at rva {packed_rva + where:#x} is not an ordinal"
                    )
                _put_word(buf, slot, value, width, "an import slot")
                p += 5
            if p >= len(buf):
                raise Damaged(f"the import records run past the unpacked data at {p:#x}")
            slot += width
            functions += 1
        _put_word(buf, slot, 0, width, "an import slot")
        descriptor += _IMPORT_DESCRIPTOR
    return f"from UPX's import records: {len(starts)} libraries, {functions} functions"


def _reloc_table(entries: list[tuple[int, int]]) -> bytes:
    """Base relocation blocks, one per 4 KiB page, each padded to whole 32-bit words."""
    out = bytearray()
    page_entries: list[int] = []
    page = None
    for rva, kind in sorted(entries):
        if page is not None and rva & ~0xFFF != page:
            out += _reloc_block(page, page_entries)
            page_entries = []
        page = rva & ~0xFFF
        page_entries.append((kind << 12) | (rva & 0xFFF))
    if page is not None:
        out += _reloc_block(page, page_entries)
    return bytes(out)


def _reloc_block(page: int, items: list[int]) -> bytes:
    if len(items) % 2:
        items = [*items, 0]
    return struct.pack(f"<II{len(items)}H", page, 8 + 2 * len(items), *items)


def _rebuild_relocations(image: _Image) -> str:
    """Put the relocated values back and write the relocation table from UPX's records."""
    original, buf = image.original, image.buf
    table_rva, table_size = original.directory(_BASERELOC)
    if not table_rva or not table_size or original.flags & _RELOCS_STRIPPED:
        return "none: the file states its relocations stripped or names no relocation table"
    if table_size == 8:
        _put(
            buf,
            image.at(table_rva, "the relocation table"),
            b"\0\0\0\0\x08\0\0\0",
            "the relocation table",
        )
        return "the empty eight-byte table the stored header names"
    records = image.records
    stream = records.u32("the relocation records' position")
    big = records.u8("the relocation kinds")
    if big & 6:
        raise NotRead(RELOCS16_NOT_READ)
    width = image.width
    image_size = stream
    positions: list[int] = []
    p = stream
    position = -4
    while True:
        if p >= len(buf):
            raise Damaged(f"the relocation records run past the unpacked data at {p:#x}")
        step = buf[p]
        if step == 0:
            break
        if step < 0xF0:
            position += step
            p += 1
        else:
            delta = (step & 0x0F) * 0x10000 + _u16(buf, p + 1, "a relocation record")
            p += 3
            if delta == 0:
                delta = _u32(buf, p, "a relocation record")
                p += 4
            position += delta
        if position < 0 or position + width > image_size:
            raise Damaged(f"a relocation at {position:#x} lies outside the image its records cover")
        buf[position : position + width] = buf[position : position + width][::-1]
        positions.append(position)
    add = original.image_base + image.rvamin
    kind = 10 if original.is64 else 3
    for position in positions:
        value = int.from_bytes(buf[position : position + width], "little") + add
        buf[position : position + width] = (value & ((1 << (8 * width)) - 1)).to_bytes(
            width, "little"
        )
    table = _reloc_table([(image.rvamin + position, kind) for position in positions])
    _put(buf, image.at(table_rva, "the relocation table"), table, "the relocation table")
    original.set_directory(_BASERELOC, table_rva, len(table))
    return f"from UPX's relocation records: {len(positions)} relocations"


def _rebuild_exports(image: _Image) -> str:
    """Write back the export table UPX moved out of the image, laid out as UPX lays it."""
    original, buf, packed = image.original, image.buf, image.packed
    table_rva, table_size = original.directory(_EXPORT)
    packed_rva, packed_size = packed.directory(_EXPORT)
    if table_size == 0:
        return "none: the stored header names no export table"
    if table_rva == packed_rva:
        return "kept: the export table is where the stored header names it"
    if _align(packed_size, 4) == 0:
        return "kept: the packed file holds no export table to move back"
    place = packed.mapped(packed_rva)
    if place is None or place[0] + packed_size > place[1] or packed_size < _EXPORT_DIRECTORY:
        raise Damaged("the packed file's export table is not wholly in the file")
    base = place[0]
    data = packed.data
    limit = base + packed_size
    directory = bytearray(data[base : base + _EXPORT_DIRECTORY])
    name_rva, _ordinal_base, count, names, functions_rva, names_rva, ordinals_rva = (
        struct.unpack_from("<IIIIIII", directory, 12)
    )

    def offset_of(rva: int, size: int, what: str) -> int:
        at = base + (rva - packed_rva)
        if rva < packed_rva or at + size > limit:
            raise Damaged(f"{what} at rva {rva:#x} lies outside the packed export table")
        return at

    if not name_rva:
        raise Damaged("the packed export table names no library name")
    name_at = offset_of(name_rva, 1, "the export table's library name")
    functions_at = offset_of(functions_rva, 4 * count, "the exported functions")
    pointers_at = offset_of(names_rva, 4 * names, "the export name pointers")
    ordinals_at = offset_of(ordinals_rva, 2 * names, "the export ordinals")
    functions = list(struct.unpack_from(f"<{count}I", data, functions_at))
    name_rvas = list(struct.unpack_from(f"<{names}I", data, pointers_at))
    forwarders = [f for f in functions if packed_rva <= f < packed_rva + packed_size]
    starts = [name_at] + [offset_of(r, 1, "an export name") for r in name_rvas]
    starts += [base + (f - packed_rva) for f in forwarders]
    nuls = _next_nuls(data, starts, limit)

    def text(at: int) -> bytes:
        close = nuls.get(at, -1)
        if close < 0:
            raise Damaged(f"an export string at file offset {at:#x} is not terminated")
        return data[at:close]

    lengths = sum(nuls[s] - s + 1 for s in starts if nuls.get(s, -1) >= 0)
    size = _EXPORT_DIRECTORY + 4 * count + 6 * names + lengths
    if size > len(buf):
        raise Damaged("the export table UPX moved is larger than the unpacked image")
    out = bytearray(_align(size, 4))
    functions_new = table_rva + _EXPORT_DIRECTORY
    pointers_new = functions_new + 4 * count
    ordinals_new = pointers_new + 4 * names
    name_new = ordinals_new + 2 * names
    library = text(name_at) + b"\0"
    out[name_new - table_rva : name_new - table_rva + len(library)] = library
    out[ordinals_new - table_rva : name_new - table_rva] = data[
        ordinals_at : ordinals_at + 2 * names
    ]
    cursor = name_new + len(library)
    for index, function in enumerate(functions):
        if packed_rva <= function < packed_rva + packed_size:
            forward = text(base + (function - packed_rva)) + b"\0"
            out[cursor - table_rva : cursor - table_rva + len(forward)] = forward
            function = cursor
            cursor += len(forward)
        struct.pack_into("<I", out, functions_new - table_rva + 4 * index, function)
    for index, rva in enumerate(name_rvas):
        name = text(base + (rva - packed_rva)) + b"\0"
        out[cursor - table_rva : cursor - table_rva + len(name)] = name
        struct.pack_into("<I", out, pointers_new - table_rva + 4 * index, cursor)
        cursor += len(name)
    struct.pack_into("<III", directory, 12, name_new, _ordinal_base, count)
    struct.pack_into("<IIII", directory, 24, names, functions_new, pointers_new, ordinals_new)
    out[:_EXPORT_DIRECTORY] = directory
    _put(buf, image.at(table_rva, "the export table"), out, "the export table")
    return f"from the packed file's export table: {count} functions, {names} names"


@dataclass
class _Leaf:
    data: bytearray
    type_id: int
    new_offset: int = 0


@dataclass
class _Branch:
    header: bytes
    children: list[tuple[int, bytes | None, _Branch | _Leaf]]


def _read_resources(image: _Image) -> tuple[_Branch | None, list[_Leaf], int, int, int]:
    """The packed file's resource tree, its leaves in order, its sizes and its directory's RVA."""
    packed = image.packed
    root_rva, _ = packed.directory(_RESOURCE)
    place = packed.mapped(root_rva)
    if place is None:
        raise Damaged("the packed file's resource table is not in the file")
    start, end = place
    data = packed.data
    # A tree holds each entry once; entries shared between directories could
    # name more nodes than the section has bytes for, so the count is held there.
    budget = (end - start) // 8 + 1
    leaves: list[_Leaf] = []
    sizes = [0, 0]  # directory bytes, name bytes

    def read(offset: int, size: int, what: str) -> bytes:
        at = start + offset
        if offset < 0 or at + size > end:
            raise Damaged(f"{what} at offset {offset:#x} of the resource table lies outside it")
        return data[at : at + size]

    def walk(offset: int, level: int, type_id: int) -> _Branch | _Leaf | None:
        nonlocal budget
        budget -= 1
        if budget < 0:
            raise Damaged("the resource table names more entries than its section holds")
        if level == 3:
            leaf = _Leaf(bytearray(read(offset, 16, "a resource data entry")), type_id)
            leaves.append(leaf)
            sizes[0] += 16
            return leaf
        header = read(offset, 16, "a resource directory")
        named, ids = struct.unpack_from("<HH", header, 12)
        count = named + ids
        if count == 0:
            return None
        entries = read(offset + 16, 8 * count, "a resource directory's entries")
        children: list[tuple[int, bytes | None, _Branch | _Leaf]] = []
        for index in range(count):
            name, child = struct.unpack_from("<II", entries, 8 * index)
            if bool(child & 0x80000000) != (level < 2):
                raise Damaged(
                    "the resource table is not three levels of directories over data entries"
                )
            label: bytes | None = None
            if name & 0x80000000:
                length = struct.unpack("<H", read(name & 0x7FFFFFFF, 2, "a resource name"))[0]
                # Names shared between entries could come to more bytes than
                # the section holds; a tree's names are its own bytes.
                sizes[1] += 2 + 2 * length
                if sizes[1] > end - start:
                    raise Damaged("the resource names come to more bytes than their section holds")
                label = read(name & 0x7FFFFFFF, 2 + 2 * length, "a resource name")
            node = walk(child & 0x7FFFFFFF, level + 1, name if level == 0 else type_id)
            if node is None:
                raise Damaged("a resource directory holds an empty directory")
            children.append((name, label, node))
        sizes[0] += 16 + 8 * count
        return _Branch(header, children)

    root = walk(0, 0, 0)
    if isinstance(root, _Leaf):
        raise Damaged("the resource table's root is not a directory")
    return root, leaves, sizes[0], sizes[1], root_rva


def _build_resources(root: _Branch, directory_size: int, name_size: int) -> bytes:
    """The resource directory as UPX lays it out: depth first, names after every entry."""
    total = _align(directory_size + name_size, 4)
    out = bytearray(total)
    cursor = [0, directory_size]  # next directory byte, next name byte

    def build(node: _Branch | _Leaf, level: int) -> None:
        at = cursor[0]
        if isinstance(node, _Leaf):
            entry = bytearray(node.data)
            if node.new_offset:
                struct.pack_into("<I", entry, 0, node.new_offset)
            out[at : at + 16] = entry
            cursor[0] += 16
            return
        out[at : at + 16] = node.header
        cursor[0] += 16 + 8 * len(node.children)
        for index, (name, label, child) in enumerate(node.children):
            tag = name
            if label is not None:
                tag = cursor[1] | 0x80000000
                out[cursor[1] : cursor[1] + len(label)] = label
                cursor[1] += len(label)
            pointer = cursor[0] | (0x80000000 if level < 2 else 0)
            struct.pack_into("<II", out, at + 16 + 8 * index, tag, pointer)
            build(child, level + 1)

    build(root, 0)
    return bytes(out)


def _rebuild_resources(image: _Image) -> str:
    """Move the resources UPX kept uncompressed back to their places, and the directory if wiped."""
    original, buf, packed = image.original, image.buf, image.packed
    table_rva, table_size = original.directory(_RESOURCE)
    packed_rva, packed_size = packed.directory(_RESOURCE)
    if table_size == 0 or packed_size == 0:
        return "none: the stored header or the packed file names no resource table"
    icons = image.records.u16("the icon count")
    root, leaves, directory_size, name_size, root_rva = _read_resources(image)
    section_end = packed.mapped(root_rva)
    held = (section_end[1] - section_end[0]) if section_end else 0
    moved_bytes = 0
    moved = 0
    for leaf in leaves:
        offset, size = struct.unpack_from("<II", leaf.data, 0)
        if offset <= packed_rva:
            continue
        moved_bytes += size
        if moved_bytes > held:
            raise Damaged(
                "the resource entries name more moved data than the resource section holds"
            )
        origin = int.from_bytes(packed.read(offset - 4, 4, "a moved resource's origin"), "little")
        leaf.new_offset = origin
        at = image.at(origin, "a moved resource")
        _put(buf, at, packed.read(offset, size, "a moved resource"), "a moved resource")
        if icons and leaf.type_id == _RT_GROUP_ICON:
            _put_word(buf, at + 4, icons, 2, "a group icon's count")
            icons = 0
        moved += 1
    said = f"{moved} resources UPX kept uncompressed moved back"
    if root is None or directory_size == 0:
        return said
    directory_at = image.at(table_rva, "the resource directory")
    if _u32(buf, directory_at + 12, "the resource directory") != 0:
        return f"{said}; the directory kept as stored"
    _put(
        buf,
        directory_at,
        _build_resources(root, directory_size, name_size),
        "the resource directory",
    )
    return f"{said}; the directory rebuilt from the packed file's"


# ---------------------------------------------------------------------------
# The whole unpack
# ---------------------------------------------------------------------------


def unpack(data: bytes) -> Unpacked:
    """The program a UPX-packed PE holds, rebuilt as a file, or the reason it is not."""
    packed = _read_packed(data)
    header = _find_header(packed)
    try:
        return _unpack(packed, header)
    except (NotRead, Damaged) as exc:
        if exc.header is None:
            exc.header = header
        raise


def _unpack(packed: _Packed, header: PackHeader) -> Unpacked:
    offset = hex(header.offset)
    if header.format not in FORMATS:
        raise NotRead(FORMAT_NOT_READ.format(offset=offset, format=header.format))
    if packed.machine != _MACHINE_OF_FORMAT[header.format]:
        raise NotRead(
            MACHINE_MISMATCH.format(
                format=header.format, name=FORMATS[header.format], machine=packed.machine
            )
        )
    if header.method not in METHODS:
        raise NotRead(METHOD_NOT_READ.format(method=header.method))
    if header.filter and header.filter not in FILTERS:
        raise NotRead(FILTER_NOT_READ.format(filter=header.filter))
    if header.u_len > UNPACKED_CAP:
        raise NotRead(OVER_CAP.format(size=header.u_len, cap=UNPACKED_CAP))
    if header.u_len > packed.image.size_of_image:
        raise Damaged(
            f"the UPX pack header states {header.u_len} unpacked bytes, more than the "
            f"{packed.image.size_of_image} bytes of image the packed file maps"
        )
    data = packed.data
    end = header.data_offset + header.c_len
    if end > len(data):
        raise Damaged(
            f"the compressed data runs to byte {end} and the file ends at byte {len(data)}: the "
            "file is cut short"
        )
    stream = data[header.data_offset : end]
    c_adler = zlib.adler32(stream)
    if c_adler != header.c_adler:
        raise Damaged(
            f"the compressed data's adler32 is {c_adler:#010x}; the pack header states "
            f"{header.c_adler:#010x}"
        )
    buf = decompress(header.method, stream, header.u_len)
    del stream
    as_decompressed = zlib.adler32(buf)

    is64 = header.format == FORMAT_WIN64_PEP
    records_at = _u32(buf, header.u_len - 4, "the stored header's position")
    oh_size = _OH_SIZE[is64]
    if records_at + oh_size > header.u_len:
        raise Damaged(f"the stored PE header at {records_at:#x} lies outside the unpacked data")
    original = _Original(bytearray(buf[records_at : records_at + oh_size]), is64)
    if bytes(original.raw[:4]) != b"PE\0\0" or original.u16(24) != (0x20B if is64 else 0x10B):
        raise Damaged(f"the stored PE header at {records_at:#x} does not read as a PE header")
    objects = original.objects
    table_at = records_at + oh_size
    if objects == 0 or table_at + _SECTION_ENTRY * objects > header.u_len:
        raise Damaged(f"the stored section table at {table_at:#x} lies outside the unpacked data")
    sections = [
        bytearray(buf[table_at + _SECTION_ENTRY * i : table_at + _SECTION_ENTRY * (i + 1)])
        for i in range(objects)
    ]
    rvamin = int(struct.unpack_from("<I", sections[0], 12)[0])

    filtered = 0
    if header.filter:
        code_base, code_size = original.u32(44), original.u32(28)
        code_at = code_base - rvamin
        if code_at < 0 or code_at + code_size > header.u_len:
            raise Damaged(
                f"the stored header's code range (rva {code_base:#x}, {code_size} bytes) lies "
                "outside the unpacked data"
            )
        filtered = unfilter(buf, code_at, code_size, header.filter, header.filter_cto)
    if as_decompressed == header.u_adler:
        reading = "the data as decompressed"
        if header.filter:
            reading += ", before the filter is undone"
        u_adler = as_decompressed
    else:
        u_adler = zlib.adler32(buf) if header.filter else as_decompressed
        if u_adler != header.u_adler:
            computed = f"{as_decompressed:#010x}"
            if header.filter:
                computed += f" as decompressed and {u_adler:#010x} with the filter undone"
            raise Damaged(
                f"the unpacked data's adler32 is {computed}; the pack header states "
                f"{header.u_adler:#010x}"
            )
        reading = "the data with the filter undone"

    if packed.flags & _RELOCS_STRIPPED:
        original.set_u16(22, original.flags | _RELOCS_STRIPPED)
        original.set_directory(_BASERELOC, 0, 0)

    image = _Image(
        buf, original, rvamin, packed, _Records(buf, table_at + _SECTION_ENTRY * objects)
    )
    rebuilt = {
        "imports": _rebuild_imports(image),
        "relocations": _rebuild_relocations(image),
        "exports": _rebuild_exports(image),
        "resources": _rebuild_resources(image),
    }
    if header.filter:
        rebuilt["code filter"] = f"{filtered} call and jump targets put back"
    for index in (_DEBUG, _IAT, _BOUND_IMPORT):
        original.set_directory(index, 0, 0)
    original.set_u32(88, 0)  # the checksum, which no longer holds
    file, overlay = _assemble(packed, original, sections, buf, rvamin)
    return Unpacked(
        header=header,
        image=file,
        u_adler=u_adler,
        c_adler=c_adler,
        checksum_reading=reading,
        entry_point=original.u32(40),
        rebuilt=rebuilt,
        overlay=overlay,
    )


def _assemble(
    packed: _Packed,
    original: _Original,
    sections: list[bytearray],
    buf: bytearray,
    rvamin: int,
) -> tuple[bytes, int]:
    """The rebuilt file: the packed DOS header, the stored headers, the sections, the overlay."""
    is64 = original.is64
    oh_size = _OH_SIZE[is64]
    file_alignment = original.u32(60)
    if file_alignment == 0 or file_alignment & (file_alignment - 1):
        raise Damaged(
            f"the stored header's file alignment {file_alignment:#x} is not a power of two"
        )
    original.set_u16(20, oh_size - 24)
    original.set_u32(_DIRECTORY_COUNT_AT[is64], 16)
    pe_offset = packed.pe_offset
    headers_end = pe_offset + oh_size + _SECTION_ENTRY * len(sections)
    stored = [int(struct.unpack_from("<I", s, 20)[0]) for s in sections]
    first = next((value for value in stored if value), 0)
    start = first or _align(headers_end, file_alignment)
    if start < headers_end:
        raise Damaged(
            f"the stored section table puts section data at {start:#x}, inside the headers, "
            f"which end at {headers_end:#x}"
        )
    pieces: list[tuple[int, int, int]] = []  # file offset, unpacked position, size
    cursor = start
    for index, section in enumerate(sections):
        if not stored[index]:
            continue
        rva, size = struct.unpack_from("<II", section, 12)
        at = rva - rvamin
        if at < 0 or at + size > len(buf):
            raise Damaged(
                f"section {index + 1}'s data (rva {rva:#x}, {size} bytes) lies outside the "
                "unpacked data"
            )
        struct.pack_into("<I", section, 20, cursor)
        pieces.append((cursor, at, size))
        cursor += _align(size, file_alignment)
    data = packed.data
    overlay = data[packed.overlay_start :] if packed.overlay_start < len(data) else b""
    total = cursor + len(overlay)
    if total > UNPACKED_CAP:
        raise NotRead(FILE_OVER_CAP.format(size=total, cap=UNPACKED_CAP))
    original.set_u32(84, start)
    out = bytearray(total)
    out[:pe_offset] = data[:pe_offset]
    out[pe_offset : pe_offset + oh_size] = original.raw
    for index, section in enumerate(sections):
        at = pe_offset + oh_size + _SECTION_ENTRY * index
        out[at : at + _SECTION_ENTRY] = section
    for file_at, at, size in pieces:
        out[file_at : file_at + size] = buf[at : at + size]
    out[cursor:] = overlay
    return bytes(out), len(overlay)


# ---------------------------------------------------------------------------
# The tool
# ---------------------------------------------------------------------------


def _sections_of(image: bytes) -> list[dict[str, Any]]:
    loaded = pe_image.parse(image)
    return [
        {
            "name": s.name,
            "virtual_address": hex(s.rva),
            "virtual_size": s.virtual_size,
            "raw_offset": s.raw_offset,
            "raw_size": s.raw_size,
        }
        for s in loaded.sections
    ]


def _import_counts(image: bytes) -> tuple[int, int]:
    """How many functions the rebuilt file's own import table names, and from how many libraries."""
    slots = pe_image.parse(image).imports_by_slot()
    libraries = {name.split("!", 1)[0].lower() for name in slots.values() if "!" in name}
    return len(slots), len(libraries)


def unpack_upx(
    path: str, destination: str | Path, *, write: Callable[[Path, bytes], str | None] | None = None
) -> dict[str, Any]:
    """Unpack the UPX-packed PE at ``path`` and write the program under ``destination``.

    The answer states the pack header, both sizes, both checksums and whether
    each matched, then the unpacked file: its SHA-256, size, ``carved_path``,
    entry point, section table, import count, what each rebuild step wrote and
    the overlay carried over. A file this reader does not unpack answers
    ``unpacked`` with the ``no:`` sentence; data that does not decode is an
    error naming where.
    """
    target = Path(path)
    if not target.is_file():
        return {"error": f"no such file: {path}", "tool": TOOL}
    try:
        data = target.read_bytes()
    except OSError as exc:
        return {"error": f"the file could not be read: {type(exc).__name__}", "tool": TOOL}
    try:
        result = unpack(data)
    except NotRead as said:
        answer: dict[str, Any] = {"unpacked": str(said)}
        if said.header is not None:
            answer["pack_header"] = said.header.facts()
        return answer
    except Damaged as exc:
        failed = tool_error(TOOL_FAILED, str(exc), tool=TOOL, remediation=REMEDIATION)
        if exc.header is not None:
            failed["pack_header"] = exc.header.facts()
        return failed
    header = result.header
    digest = hashlib.sha256(result.image).hexdigest()
    where = Path(destination)
    try:
        where.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as exc:
        return {"error": f"cannot create the directory for the unpacked file: {exc}", "tool": TOOL}
    child = where / binary.carved_file_name(UNPACKED_LABEL, digest)
    written = (write or binary._write_carved)(child, result.image)
    if written is not None:
        return tool_error(TOOL_FAILED, written, tool=TOOL, remediation=REMEDIATION)
    functions, libraries = _import_counts(result.image)
    return {
        "unpacked": "yes",
        "pack_header": header.facts(),
        "compressed_size": header.c_len,
        "unpacked_size": header.u_len,
        "original_file_size": header.u_file_size,
        "checksums": {
            "compressed": {
                "stated": f"{header.c_adler:#010x}",
                "computed": f"{result.c_adler:#010x}",
                "matched": True,
            },
            "unpacked": {
                "stated": f"{header.u_adler:#010x}",
                "computed": f"{result.u_adler:#010x}",
                "matched": True,
                "over": result.checksum_reading,
            },
        },
        "child": {
            "name": UNPACKED_LABEL,
            "sha256": digest,
            "size": len(result.image),
            "path": str(child),
            "carved_path": str(child),
        },
        "entry_point": hex(result.entry_point),
        "import_count": functions,
        "import_libraries": libraries,
        "rebuilt": result.rebuilt,
        "overlay_bytes": result.overlay,
        "sections": _sections_of(result.image),
    }

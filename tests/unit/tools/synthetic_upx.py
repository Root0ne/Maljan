"""A UPX-packed PE built in memory by the tests, with encoders written for the tests.

No real program and no ``upx`` binary are used: the tests write a small PE of
their own (code with calls and jumps, an import table, relocated pointers, an
export table and resources), lay it out the way UPX's PE packer lays out what
it compresses (the image, the import and relocation records, the stored PE
header and section table, the records' position in the last four bytes),
apply the call/jump filter, compress it with the NRV2B, NRV2D or NRV2E
encoder below or the standard library's LZMA1, and write the packed file
around it: UPX0, UPX1 holding the pack header and the stream, and a third
section with the packed import table, the moved export table and the
resources UPX keeps uncompressed.

The encoders are greedy and plain: what they must be is a valid bit stream in
each format, with literals, near and far offsets, the repeated-offset form and
long and overlapping copies.
"""

from __future__ import annotations

import lzma
import struct
import zlib
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# The NRV encoders
# ---------------------------------------------------------------------------


class _Bits:
    """Bits written most significant first into words of ``width`` bytes, bytes between them."""

    def __init__(self, width: int) -> None:
        self.out = bytearray()
        self.width = width
        self.slot = 0
        self.count = 0
        self.value = 0

    def bit(self, value: int) -> None:
        if self.count == 0:
            self.slot = len(self.out)
            self.out += bytes(self.width)
        self.value = (self.value << 1) | (value & 1)
        self.count += 1
        if self.count == 8 * self.width:
            self._flush()

    def _flush(self) -> None:
        self.out[self.slot : self.slot + self.width] = self.value.to_bytes(self.width, "little")
        self.count = 0
        self.value = 0

    def byte(self, value: int) -> None:
        self.out.append(value)

    def finish(self) -> bytes:
        if self.count:
            self.value <<= 8 * self.width - self.count
            self._flush()
        return bytes(self.out)


def _gamma(bits: _Bits, value: int) -> None:
    """NRV2B's prefix code: each bit after the top one, then 1 after the last and 0 otherwise."""
    for shift in range(value.bit_length() - 2, -1, -1):
        bits.bit((value >> shift) & 1)
        bits.bit(1 if shift == 0 else 0)


def _gamma2(bits: _Bits, value: int, last: int = 1) -> None:
    """NRV2D and NRV2E's offset prefix code, two data bits per continuation."""
    if value < 4:
        bits.bit(value - 2)
        bits.bit(last)
        return
    low, rest = value & 1, value >> 1
    _gamma2(bits, (rest >> 1) + 1, 0)
    bits.bit(rest & 1)
    bits.bit(low)
    bits.bit(last)


END_PREFIX = 0xFFFFFF + 3


def nrv_compress(data: bytes, kind: str, width: int = 4) -> bytes:
    """``data`` as an NRV2B (``"2b"``), NRV2D (``"2d"``) or NRV2E (``"2e"``) stream."""
    bits = _Bits(width)
    near = 0xD00 if kind == "2b" else 0x500
    last = 1
    table: dict[bytes, int] = {}
    position = 0
    size = len(data)
    while position < size:
        best_length, best_offset = 0, 0
        for candidate in (position - last, table.get(data[position : position + 3], -1)):
            if candidate < 0 or candidate >= position:
                continue
            length = 0
            while position + length < size and data[candidate + length] == data[position + length]:
                length += 1
            offset = position - candidate
            if length > best_length or (length == best_length and offset == last):
                best_length, best_offset = length, offset
        if position + 3 <= size:
            table[data[position : position + 3]] = position
        if best_length < 2 + (best_offset > near) or position == 0:
            bits.bit(1)
            bits.byte(data[position])
            position += 1
            continue
        _match(bits, kind, best_offset, best_length, last, near)
        for at in range(position + 1, min(position + best_length, size - 2)):
            table[data[at : at + 3]] = at
        last = best_offset
        position += best_length
    bits.bit(0)
    if kind == "2b":
        _gamma(bits, END_PREFIX)
    else:
        _gamma2(bits, END_PREFIX)
    bits.byte(0xFF)
    return bits.finish()


def _match(bits: _Bits, kind: str, offset: int, count: int, last: int, near: int) -> None:
    bits.bit(0)
    x = count - 1 - (offset > near)
    if kind == "2b":
        if offset == last:
            _gamma(bits, 2)
        else:
            _gamma(bits, ((offset - 1) >> 8) + 3)
            bits.byte((offset - 1) & 0xFF)
        if x <= 3:
            bits.bit(x >> 1)
            bits.bit(x & 1)
        else:
            bits.bit(0)
            bits.bit(0)
            _gamma(bits, x - 2)
        return
    if kind == "2d":
        first = x >> 1 if x <= 3 else 0
    else:
        first = 1 if x <= 2 else 0
    if offset == last:
        _gamma2(bits, 2)
        bits.bit(first)
    else:
        combined = (offset - 1) * 2 + (first ^ 1)
        _gamma2(bits, (combined >> 8) + 3)
        bits.byte(combined & 0xFF)
    if kind == "2d":
        if x <= 3:
            bits.bit(x & 1)
        else:
            bits.bit(0)
            _gamma(bits, x - 2)
    elif x <= 2:
        bits.bit(x - 1)
    elif x <= 4:
        bits.bit(1)
        bits.bit(x - 3)
    else:
        bits.bit(0)
        _gamma(bits, x - 3)


def lzma_compress(data: bytes, lc: int = 3, lp: int = 0, pb: int = 2) -> bytes:
    """``data`` as UPX writes LZMA: two properties bytes, then the raw LZMA1 stream."""
    raw = lzma.compress(
        data,
        format=lzma.FORMAT_RAW,
        filters=[{"id": lzma.FILTER_LZMA1, "lc": lc, "lp": lp, "pb": pb, "dict_size": 1 << 20}],
    )
    return bytes([((lc + lp) << 3) | pb, (lp << 4) | lc]) + raw


METHOD_ENCODERS = {
    2: ("2b", 4),
    3: ("2b", 1),
    4: ("2b", 2),
    5: ("2d", 4),
    6: ("2d", 1),
    7: ("2d", 2),
    8: ("2e", 4),
    9: ("2e", 1),
    10: ("2e", 2),
}


def compress(method: int, data: bytes) -> bytes:
    if method == 14:
        return lzma_compress(data)
    kind, width = METHOD_ENCODERS[method]
    return nrv_compress(data, kind, width)


# ---------------------------------------------------------------------------
# The call/jump filter, forward
# ---------------------------------------------------------------------------


def cto_filter(buf: bytearray, start: int, length: int, cto: int, opcodes: tuple[int, ...]) -> int:
    """UPX's filter 0x24-0x26 applied: each in-range target stored big-endian behind ``cto``."""
    size = length
    position = 0
    converted = 0
    while position < size - 5:
        at = start + position
        if buf[at] in opcodes:
            target = (int.from_bytes(buf[at + 1 : at + 5], "little") + position + 1) & 0xFFFFFFFF
            if target < size:
                stored = (target + start + (cto << 24)) & 0xFFFFFFFF
                buf[at + 1 : at + 5] = stored.to_bytes(4, "big")
                converted += 1
                position += 5
                continue
            assert buf[at + 1] != cto, "a target the filter leaves must not carry the marker"
        position += 1
    return converted


# ---------------------------------------------------------------------------
# The program and its packed file
# ---------------------------------------------------------------------------

RVAMIN = 0x1000
TEXT, RDATA, DATA, RSRC, RELOC = 0x1000, 0x2000, 0x3000, 0x4000, 0x5000
IMAGE_END = 0x6000
IMPORT_TABLE = RDATA
IAT = RDATA + 0x100
NAMES = RDATA + 0x400
EXPORT_TABLE = RDATA + 0x800
RCDATA_AT = RSRC + 0x100
ICON_AT = RSRC + 0x200
ENTRY = TEXT + 0x10
PE_OFFSET = 0x80
UPX1_RAW = 0x400
FILE_ALIGNMENT = 0x200
CTO = 0x7A


@dataclass
class Packed:
    """A packed file and what unpacking it must give back."""

    data: bytes
    text: bytes
    data_section: bytes
    imports: dict[str, list[str | int]]
    relocated: list[int]
    exports: list[tuple[str, int]]
    forwarders: list[tuple[str, str]]
    rcdata: bytes
    icon: bytes
    icon_count: int
    image_base: int
    u_len: int
    obuf: bytes = b""
    header_offset: int = 0


@dataclass
class Program:
    """What the tests choose about the program and how it is packed."""

    is64: bool = False
    method: int = 2
    filter_id: int = 0x26
    level: int = 8
    imports: dict[str, list[str | int]] = field(
        default_factory=lambda: {
            "KERNEL32.DLL": ["CreateFileW", "WriteFile", 42],
            "WS2_32.dll": ["connect", 23, "send"],
            "USER32.dll": ["#packed-ordinal"],
        }
    )
    relocate: bool = True
    exports: list[tuple[str, int]] = field(
        default_factory=lambda: [("Alpha", TEXT + 0x20), ("Beta", TEXT + 0x40)]
    )
    forwarders: list[tuple[str, str]] = field(
        default_factory=lambda: [("Gamma", "NTDLL.RtlZeroMemory")]
    )
    wipe_resource_directory: bool = True
    icon_count: int = 3
    # Whether the stated adler32 of the unpacked data is over the data with
    # the filter undone rather than as compressed.
    checksum_unfiltered: bool = False
    overlay: bytes = b""

    @property
    def image_base(self) -> int:
        return 0x140000000 if self.is64 else 0x400000

    @property
    def width(self) -> int:
        return 8 if self.is64 else 4


def _code(size: int) -> bytearray:
    """Code with calls and jumps into itself, a call out of range, and filler between."""
    code = bytearray(b"\x90" * size)
    position = 0x10
    step = 0
    while position + 16 < size - 0x40:
        opcode = 0xE8 if step % 3 else 0xE9
        target = (step * 0x37) % (size - 0x40)
        code[position] = opcode
        code[position + 1 : position + 5] = struct.pack("<i", target - (position + 5))
        position += 5 + (step % 7)
        step += 1
    # A call whose target lies past the code range: the filter leaves it.
    code[size - 0x30] = 0xE8
    code[size - 0x2F : size - 0x2B] = struct.pack("<i", 0x100000)
    for at in range(0x20, 0x60, 4):
        code[at] = 0x55 + (at & 0x1F)
    return code


def _optional_header(program: Program, directories: dict[int, tuple[int, int]]) -> bytes:
    """The original program's PE header (signature, file header, optional header)."""
    is64 = program.is64
    size = 240 if is64 else 224
    machine = 0x8664 if is64 else 0x14C
    flags = 0x0022 if is64 else 0x0102
    coff = struct.pack("<4sHHIIIHH", b"PE\0\0", machine, 5, 0, 0, 0, size, flags)
    opt = bytearray(size)
    struct.pack_into("<HBB", opt, 0, 0x20B if is64 else 0x10B, 14, 0)
    struct.pack_into("<IIIII", opt, 4, 0x1000, 0x3000, 0, ENTRY, TEXT)
    if is64:
        struct.pack_into("<Q", opt, 24, program.image_base)
    else:
        struct.pack_into("<II", opt, 24, DATA, program.image_base)
    struct.pack_into("<II", opt, 32, 0x1000, FILE_ALIGNMENT)
    struct.pack_into("<HHHHHH", opt, 40, 6, 0, 0, 0, 6, 0)
    struct.pack_into("<IIII", opt, 52, 0, IMAGE_END, 0x400, 0x1234)
    struct.pack_into("<HH", opt, 68, 2, 0x8140)
    count_at = 108 if is64 else 92
    struct.pack_into("<I", opt, count_at, 16)
    for index, (rva, length) in directories.items():
        struct.pack_into("<II", opt, count_at + 4 + 8 * index, rva, length)
    return coff + bytes(opt)


def _section(name: str, vsize: int, rva: int, raw_size: int, raw: int, flags: int) -> bytes:
    return struct.pack("<8sIIIIIIHHI", name.encode(), vsize, rva, raw_size, raw, 0, 0, 0, 0, flags)


def _reloc_stream(positions: list[int]) -> bytes:
    out = bytearray()
    previous = -4
    for position in sorted(positions):
        delta = position - previous
        if delta < 0xF0:
            out.append(delta)
        elif delta < 0x100000 and delta & 0xFFFF:
            out.append(0xF0 | (delta >> 16))
            out += struct.pack("<H", delta & 0xFFFF)
        else:
            out.append(0xF0)
            out += struct.pack("<HI", 0, delta)
        previous = position
    out.append(0)
    return bytes(out)


def _resource_tree(packed_rva: int, icon_moved_at: int) -> tuple[bytes, bytes]:
    """The packed resource tree (at ``packed_rva``) and the original one, as UPX would see them.

    Two types: RT_RCDATA id 1 (kept compressed in the image, at ``RCDATA_AT``)
    and RT_GROUP_ICON named ``ICONS`` (kept uncompressed, at
    ``icon_moved_at`` in the packed file, from ``ICON_AT`` in the image).
    """

    def tree(rcdata_rva: int, icon_rva: int, rcdata_size: int, icon_size: int) -> bytes:
        out = bytearray()
        # root (0), type dirs (0x20, 0x40), name dirs (0x60, 0x80), data (0xA0, 0xB0), name 0xC0
        out += struct.pack("<IIHHHH", 0, 0, 4, 0, 0, 2)
        out += struct.pack("<II", 10, 0x80000020)
        out += struct.pack("<II", 14, 0x80000040)
        out += bytes(0x20 - len(out))
        out += struct.pack("<IIHHHH", 0, 0, 0, 0, 0, 1) + struct.pack("<II", 1, 0x80000060)
        out += bytes(0x40 - len(out))
        out += struct.pack("<IIHHHH", 0, 0, 0, 0, 1, 0) + struct.pack("<II", 0x800000C0, 0x80000080)
        out += bytes(0x60 - len(out))
        out += struct.pack("<IIHHHH", 0, 0, 0, 0, 0, 1) + struct.pack("<II", 0x409, 0xA0)
        out += bytes(0x80 - len(out))
        out += struct.pack("<IIHHHH", 0, 0, 0, 0, 0, 1) + struct.pack("<II", 0x409, 0xB0)
        out += bytes(0xA0 - len(out))
        out += struct.pack("<IIII", rcdata_rva, rcdata_size, 1252, 0)
        out += struct.pack("<IIII", icon_rva, icon_size, 1252, 0)
        out += struct.pack("<H", 5) + "ICONS".encode("utf-16-le")
        return bytes(out)

    return tree(RCDATA_AT, icon_moved_at, 0x40, 0x20), tree(RCDATA_AT, ICON_AT, 0x40, 0x20)


def _export_table(table_rva: int, program: Program) -> bytes:
    """An export table at ``table_rva`` laid out as UPX's export writer lays it out."""
    names = sorted(program.exports + [(n, "") for n, _ in program.forwarders])
    count = len(names)
    functions_at = table_rva + 40
    pointers_at = functions_at + 4 * count
    ordinals_at = pointers_at + 4 * count
    name_at = ordinals_at + 2 * count
    library = b"program.dll\0"
    cursor = name_at + len(library)
    strings = bytearray(library)
    functions: list[int] = []
    for name, _target in names:
        forward = dict(program.forwarders).get(name)
        if forward is not None:
            functions.append(cursor)
            text = forward.encode() + b"\0"
            strings += text
            cursor += len(text)
        else:
            functions.append(dict(program.exports)[name])
    pointers: list[int] = []
    for name, _target in names:
        pointers.append(cursor)
        text = name.encode() + b"\0"
        strings += text
        cursor += len(text)
    out = struct.pack(
        "<IIHHIIIIIII", 0, 0, 0, 0, name_at, 1, count, count, functions_at, pointers_at, ordinals_at
    )
    out += struct.pack(f"<{count}I", *functions)
    out += struct.pack(f"<{count}I", *pointers)
    out += struct.pack(f"<{count}H", *range(count))
    out += bytes(strings)
    return out


def build(program: Program | None = None) -> Packed:
    """The packed file for ``program`` and what unpacking it gives back."""
    program = program or Program()
    width = program.width
    base = program.image_base
    image = bytearray(IMAGE_END - RVAMIN)

    def put(rva: int, data: bytes) -> None:
        image[rva - RVAMIN : rva - RVAMIN + len(data)] = data

    code = _code(0x1000)
    put(TEXT, code)
    data_section = bytearray(0x1000)
    relocated: list[int] = []
    if program.relocate:
        for index in range(40):
            slot = DATA + width * index * 3
            value = base + RDATA + 0x10 * index
            data_section[slot - DATA : slot - DATA + width] = value.to_bytes(width, "little")
            relocated.append(slot)
        # A slot past 0xF0 bytes from the last, and one far away: the long forms.
        far = DATA + 0xF00
        data_section[far - DATA : far - DATA + width] = (base + TEXT).to_bytes(width, "little")
        relocated.append(far)
    put(DATA, data_section)
    rcdata = bytes(range(0x40))
    icon = bytes([0, 0, 1, 0, 0, 0]) + bytes(range(0x30, 0x30 + 26))
    put(RCDATA_AT, rcdata)

    # The packed import table's library names and the ordinal UPX keeps there,
    # at offsets from its start: the records name them by these offsets.
    dll_offsets: dict[str, int] = {}
    cursor = 0x80
    for dll in program.imports:
        dll_offsets[dll] = cursor
        cursor += len(dll) + 1
    ordinal_slot = 0x60
    original_tree = _resource_tree(0, 0)[1]
    if not program.wipe_resource_directory:
        put(RSRC, original_tree)

    # -- UPX's records after the image
    records = bytearray()
    idata_at = len(image)
    for index, (dll, entries) in enumerate(program.imports.items()):
        records += struct.pack("<II", dll_offsets[dll], IAT + 0x40 * index - RVAMIN)
        for entry in entries:
            if isinstance(entry, int):
                records += b"\xff" + struct.pack("<H", entry)
            elif entry == "#packed-ordinal":
                records += b"\x02" + struct.pack("<I", ordinal_slot)
            else:
                records += b"\x01" + entry.encode() + b"\0"
        records += b"\0"
    records += b"\0\0\0\0"
    relocs_at = idata_at + len(records)
    if program.relocate:
        for slot in relocated:
            at = slot - RVAMIN
            value = (int.from_bytes(image[at : at + width], "little") - base - RVAMIN) & (
                (1 << (8 * width)) - 1
            )
            image[at : at + width] = value.to_bytes(width, "big")
        records += _reloc_stream([slot - RVAMIN for slot in relocated])
    directories = {
        1: (IMPORT_TABLE, 20 * (len(program.imports) + 1)),
        2: (RSRC, 0x100),
        5: (RELOC, 0x200) if program.relocate else (0, 0),
    }
    if program.exports:
        directories[0] = (EXPORT_TABLE, len(_export_table(EXPORT_TABLE, program)))
    oh = _optional_header(program, directories)
    stored_sections = b"".join(
        _section(name, 0x1000, rva, 0x1000, 0x400 + 0x1000 * index, flags)
        for index, (name, rva, flags) in enumerate(
            [
                (".text", TEXT, 0x60000020),
                (".rdata", RDATA, 0x40000040),
                (".data", DATA, 0xC0000040),
                (".rsrc", RSRC, 0x40000040),
                (".reloc", RELOC, 0x42000040),
            ]
        )
    )
    extra_at = idata_at + len(records)
    extra = bytearray(oh + stored_sections)
    extra += struct.pack("<II", idata_at, NAMES)
    if program.relocate:
        extra += struct.pack("<IB", relocs_at, 0)
    extra += struct.pack("<H", program.icon_count)
    obuf = bytearray(image + records + extra + struct.pack("<I", extra_at))
    unfiltered = zlib.adler32(obuf)
    opcodes = {0x24: (0xE8,), 0x25: (0xE9,), 0x26: (0xE8, 0xE9)}.get(program.filter_id)
    if opcodes:
        cto_filter(obuf, TEXT - RVAMIN, 0x1000, CTO, opcodes)
    u_adler = unfiltered if program.checksum_unfiltered else zlib.adler32(obuf)
    stream = compress(program.method, bytes(obuf))

    # -- the packed file
    u_len = len(obuf)
    upx0_size = _align(u_len, 0x1000)
    upx1_rva = RVAMIN + upx0_size
    upx1_raw_size = _align(len(stream) + 0x40, FILE_ALIGNMENT)
    upx1_size = _align(upx1_raw_size, 0x1000)
    third_rva = upx1_rva + upx1_size
    third = bytearray(0x1000)
    for dll, offset in dll_offsets.items():
        third[offset : offset + len(dll) + 1] = dll.encode() + b"\0"
    packed_ordinal = (1 << (8 * width - 1)) | 77
    third[ordinal_slot : ordinal_slot + width] = packed_ordinal.to_bytes(width, "little")
    export_rva = third_rva + 0x200
    export_copy = _export_table(export_rva, program) if program.exports else b""
    third[0x200 : 0x200 + len(export_copy)] = export_copy
    resource_rva = third_rva + 0x400
    packed_tree = _resource_tree(resource_rva, third_rva + 0x604)[0]
    third[0x400 : 0x400 + len(packed_tree)] = packed_tree
    third[0x600:0x604] = struct.pack("<I", ICON_AT)
    third[0x604 : 0x604 + len(icon)] = icon
    third_raw = UPX1_RAW + upx1_raw_size
    header = bytearray(_MAGIC_BLOCK(program, u_adler, zlib.adler32(stream), u_len, len(stream)))
    file = bytearray(third_raw + len(third))
    file[0:2] = b"MZ"
    struct.pack_into("<I", file, 0x3C, PE_OFFSET)
    machine = 0x8664 if program.is64 else 0x14C
    opt_size = 240 if program.is64 else 224
    struct.pack_into(
        "<4sHHIIIHH", file, PE_OFFSET, b"PE\0\0", machine, 3, 0, 0, 0, opt_size, 0x0102
    )
    opt = PE_OFFSET + 24
    struct.pack_into("<H", file, opt, 0x20B if program.is64 else 0x10B)
    struct.pack_into("<I", file, opt + 16, upx1_rva + 0x10)
    if program.is64:
        struct.pack_into("<Q", file, opt + 24, base)
    else:
        struct.pack_into("<I", file, opt + 28, base)
    struct.pack_into("<II", file, opt + 32, 0x1000, FILE_ALIGNMENT)
    struct.pack_into("<II", file, opt + 56, third_rva + 0x1000, 0x400)
    count_at = opt + (108 if program.is64 else 92)
    struct.pack_into("<I", file, count_at, 16)
    struct.pack_into("<II", file, count_at + 4 + 8 * 1, third_rva, 0x80)
    struct.pack_into("<II", file, count_at + 4 + 8 * 2, resource_rva, len(packed_tree))
    if program.exports:
        struct.pack_into("<II", file, count_at + 4, export_rva, len(export_copy))
    table = opt + opt_size
    file[table : table + 40] = _section("UPX0", upx0_size, RVAMIN, 0, UPX1_RAW, 0xE0000080)
    file[table + 40 : table + 80] = _section(
        "UPX1", upx1_size, upx1_rva, upx1_raw_size, UPX1_RAW, 0xE0000040
    )
    file[table + 80 : table + 120] = _section(
        ".rsrc", 0x1000, third_rva, len(third), third_raw, 0xC0000040
    )
    header_at = UPX1_RAW - 32
    file[header_at - 5 : header_at] = b"4.24\0"
    file[header_at : header_at + 32] = header
    file[UPX1_RAW : UPX1_RAW + len(stream)] = stream
    file[third_raw : third_raw + len(third)] = third
    file += program.overlay
    return Packed(
        data=bytes(file),
        text=bytes(code),
        data_section=bytes(data_section),
        imports=program.imports,
        relocated=relocated,
        exports=program.exports,
        forwarders=program.forwarders,
        rcdata=rcdata,
        icon=icon,
        icon_count=program.icon_count,
        image_base=base,
        u_len=u_len,
        obuf=bytes(obuf),
        header_offset=header_at,
    )


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def pack_header(
    *,
    version: int = 13,
    format_id: int = 9,
    method: int = 2,
    level: int = 8,
    u_adler: int = 0,
    c_adler: int = 0,
    u_len: int = 0,
    c_len: int = 0,
    u_file_size: int = 0,
    filter_id: int = 0x26,
    cto: int = CTO,
) -> bytes:
    """A 32-byte pack header with its checksum byte."""
    block = bytearray(b"UPX!" + bytes([version, format_id, method, level]))
    block += struct.pack("<IIIII", u_adler, c_adler, u_len, c_len, u_file_size)
    block += bytes([filter_id, cto, 0])
    block.append(sum(block[4:31]) % 251)
    return bytes(block)


def _MAGIC_BLOCK(program: Program, u_adler: int, c_adler: int, u_len: int, c_len: int) -> bytes:  # noqa: N802
    return pack_header(
        format_id=36 if program.is64 else 9,
        method=program.method,
        level=program.level,
        u_adler=u_adler,
        c_adler=c_adler,
        u_len=u_len,
        c_len=c_len,
        u_file_size=0x5400,
        filter_id=program.filter_id,
    )

"""A dynamically linked ELF built as bytes, for tests that read one.

A test that read a system binary ran only where the system binaries are ELF:
on a host whose binaries are Mach-O it failed instead. The image built here
holds what such a binary was read for: an interpreter, one ``DT_NEEDED``
library, undefined function symbols in ``.dynsym`` and a ``.gnu.version_r``
table naming the library each symbol's version was needed from. It is never
run; its program headers only describe its own layout.

The host's own ``/bin/ls`` is read beside it where that is an ELF binary, so a
real toolchain's output stays tested on such a host (``ELF_SOURCES``).
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

# The two images a test reads: the one built here, and the host's own binary.
ELF_SOURCES = pytest.mark.parametrize("source", ["built", "host"])
HOST_BINARY = Path("/bin/ls")

INTERP = "/lib64/ld-linux-x86-64.so.2"
LIBRARY = "libc.so.6"
# The imported functions by the version each was needed at.
IMPORTS = {
    "GLIBC_2.2.5": ("malloc", "free", "strlen", "opendir", "readdir"),
    "GLIBC_2.34": ("__libc_start_main",),
}

_SHT_PROGBITS, _SHT_STRTAB, _SHT_DYNAMIC, _SHT_DYNSYM = 1, 3, 6, 11
_SHT_GNU_VERNEED, _SHT_GNU_VERSYM = 0x6FFFFFFE, 0x6FFFFFFF
_PT_LOAD, _PT_DYNAMIC, _PT_INTERP = 1, 2, 3
_DT_NULL, _DT_NEEDED, _DT_STRTAB, _DT_SYMTAB, _DT_STRSZ, _DT_SYMENT = 0, 1, 5, 6, 10, 11
_DT_VERSYM, _DT_VERNEED, _DT_VERNEEDNUM = 0x6FFFFFF0, 0x6FFFFFFE, 0x6FFFFFFF
_SHF_ALLOC = 2
_PHDRS = 3
_SECTIONS_AT = 64 + _PHDRS * 56


def _elf_hash(name: bytes) -> int:
    value = 0
    for byte in name:
        value = (value << 4) + byte
        high = value & 0xF0000000
        if high:
            value ^= high >> 24
        value &= ~high
    return value & 0xFFFFFFFF


class _Strings:
    def __init__(self) -> None:
        self.data = bytearray(b"\0")
        self.at: dict[str, int] = {"": 0}

    def add(self, text: str) -> int:
        if text not in self.at:
            self.at[text] = len(self.data)
            self.data += text.encode() + b"\0"
        return self.at[text]


def dynamic_elf() -> bytes:
    """An ELF64 little-endian x86-64 shared object importing ``IMPORTS`` from ``LIBRARY``."""
    dynstr = _Strings()
    library = dynstr.add(LIBRARY)
    version_index = {name: 2 + i for i, name in enumerate(IMPORTS)}
    version_name = {name: dynstr.add(name) for name in IMPORTS}
    symbols = [(dynstr.add(f), version) for version, names in IMPORTS.items() for f in names]

    dynsym = bytes(24) + b"".join(
        struct.pack("<IBBHQQ", name, (1 << 4) | 2, 0, 0, 0, 0) for name, _ in symbols
    )
    versym = struct.pack("<H", 0) + b"".join(
        struct.pack("<H", version_index[version]) for _, version in symbols
    )
    verneed = struct.pack("<HHIII", 1, len(IMPORTS), library, 16, 0)
    for i, version in enumerate(IMPORTS):
        step = 16 if i + 1 < len(IMPORTS) else 0
        verneed += struct.pack(
            "<IHHII",
            _elf_hash(version.encode()),
            0,
            version_index[version],
            version_name[version],
            step,
        )
    interp = INTERP.encode() + b"\0"

    # Section bodies in file order; each address is its offset (one PT_LOAD at 0).
    layout: list[tuple[str, int, bytes, int, int, int]] = []  # name, type, body, link, info, ent
    offsets: dict[str, int] = {}
    cursor = _SECTIONS_AT

    def place(
        name: str, kind: int, body: bytes, link: int = 0, info: int = 0, ent: int = 0
    ) -> None:
        nonlocal cursor
        cursor = (cursor + 7) & ~7
        offsets[name] = cursor
        layout.append((name, kind, body, link, info, ent))
        cursor += len(body)

    # Section indices: 1 .interp, 2 .dynstr, 3 .dynsym, 4 .gnu.version,
    # 5 .gnu.version_r, 6 .dynamic, 7 .shstrtab.
    place(".interp", _SHT_PROGBITS, interp)
    place(".dynstr", _SHT_STRTAB, bytes(dynstr.data))
    place(".dynsym", _SHT_DYNSYM, dynsym, link=2, info=1, ent=24)
    place(".gnu.version", _SHT_GNU_VERSYM, versym, link=3, ent=2)
    place(".gnu.version_r", _SHT_GNU_VERNEED, verneed, link=2, info=1)
    dynamic = b"".join(
        struct.pack("<qQ", tag, value)
        for tag, value in (
            (_DT_NEEDED, library),
            (_DT_STRTAB, offsets[".dynstr"]),
            (_DT_SYMTAB, offsets[".dynsym"]),
            (_DT_STRSZ, len(dynstr.data)),
            (_DT_SYMENT, 24),
            (_DT_VERSYM, offsets[".gnu.version"]),
            (_DT_VERNEED, offsets[".gnu.version_r"]),
            (_DT_VERNEEDNUM, 1),
            (_DT_NULL, 0),
        )
    )
    place(".dynamic", _SHT_DYNAMIC, dynamic, link=2, ent=16)
    shstrtab = _Strings()
    for name, *_ in layout:
        shstrtab.add(name)
    shstrtab.add(".shstrtab")
    place(".shstrtab", _SHT_STRTAB, bytes(shstrtab.data))

    shoff = (cursor + 7) & ~7
    body = bytearray(shoff)
    for name, _kind, data, *_ in layout:
        body[offsets[name] : offsets[name] + len(data)] = data
    headers = bytes(64)
    for name, kind, data, link, info, ent in layout:
        flags = 0 if name == ".shstrtab" else _SHF_ALLOC
        address = 0 if name == ".shstrtab" else offsets[name]
        headers += struct.pack(
            "<IIQQQQIIQQ",
            shstrtab.at[name],
            kind,
            flags,
            address,
            offsets[name],
            len(data),
            link,
            info,
            8 if ent else 1,
            ent,
        )
    image = body + headers

    elf_header = (
        b"\x7fELF\x02\x01\x01"
        + bytes(9)
        + struct.pack(
            "<HHIQQQIHHHHHH",
            3,  # ET_DYN
            0x3E,  # x86-64
            1,
            0,
            64,
            shoff,
            0,
            64,
            56,
            _PHDRS,
            64,
            len(layout) + 1,
            len(layout),  # .shstrtab is the last section
        )
    )
    end = offsets[".shstrtab"]
    program = b"".join(
        struct.pack("<IIQQQQQQ", kind, flags, offset, offset, offset, size, size, align)
        for kind, flags, offset, size, align in (
            (_PT_INTERP, 4, offsets[".interp"], len(interp), 1),
            (_PT_LOAD, 4, 0, end, 0x1000),
            (_PT_DYNAMIC, 6, offsets[".dynamic"], len(dynamic), 8),
        )
    )
    image[:_SECTIONS_AT] = elf_header + program
    return bytes(image)


def elf_bytes(source: str) -> bytes:
    """The image ``source`` names; the host's is skipped where it is absent or not ELF."""
    if source == "built":
        return dynamic_elf()
    blob = HOST_BINARY.read_bytes() if HOST_BINARY.is_file() else b""
    if blob[:4] != b"\x7fELF":
        pytest.skip(f"{HOST_BINARY} is absent or not an ELF binary on this host")
    return blob

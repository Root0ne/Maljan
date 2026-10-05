"""A minimal PE image built in memory for the tests that read values out of one.

No real program is used anywhere: the tests lay out a code section, a data
section and, for an x64 image, a function table with the bytes each test needs
at addresses it chooses, and check that the tools report those addresses.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

FILE_ALIGNMENT = 0x200
SECTION_ALIGNMENT = 0x1000

TEXT_RVA = 0x1000
RDATA_RVA = 0x2000
DATA_RVA = 0x3000
PDATA_RVA = 0x4000

_CODE = 0x60000020  # code, execute, read
_RDATA = 0x40000040  # initialised data, read
_DATA = 0xC0000040  # initialised data, read, write


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


@dataclass
class SyntheticPE:
    """The sections of one image; ``build`` lays them out as a PE file."""

    is64: bool = True
    image_base: int = 0x140000000
    text: bytearray = field(default_factory=lambda: bytearray(0x400))
    rdata: bytearray = field(default_factory=lambda: bytearray(0x400))
    data: bytearray = field(default_factory=lambda: bytearray(0x400))
    # (start RVA, end RVA) or (start, end, unwind RVA) of each entry, written
    # as the x64 function table.
    functions: list[tuple[int, ...]] = field(default_factory=list)
    # Bytes written inside the function table's directory after its entries.
    pdata_tail: bytes = b""
    # The import directory's (RVA, size), once ``imports_at`` wrote one.
    import_directory: tuple[int, int] | None = None

    def imports_at(self, offset: int, imports: dict[str, list[str]]) -> dict[str, int]:
        """Write an import table into ``.rdata`` at ``offset``; answer each name's slot RVA.

        Descriptors first (the all-zero one last), then per library its lookup
        table, its address table (the slots), its name and its hint/name rows.
        """
        width = 8 if self.is64 else 4
        descriptors = 20 * (len(imports) + 1)
        cursor = offset + descriptors
        slots: dict[str, int] = {}
        for index, (dll, names) in enumerate(imports.items()):
            table_size = width * (len(names) + 1)
            lookup, address = cursor, cursor + table_size
            cursor = address + table_size
            dll_name = cursor
            self.put("rdata", dll_name, dll.encode() + b"\0")
            cursor += len(dll) + 1
            entries: list[int] = []
            for name in names:
                entries.append(RDATA_RVA + cursor)
                self.put("rdata", cursor, b"\0\0" + name.encode() + b"\0")
                cursor += 2 + len(name) + 1
            packing = "<Q" if self.is64 else "<I"
            for position, entry in enumerate(entries):
                self.put("rdata", lookup + width * position, struct.pack(packing, entry))
                self.put("rdata", address + width * position, struct.pack(packing, entry))
                slots[names[position]] = RDATA_RVA + address + width * position
            self.put(
                "rdata",
                offset + 20 * index,
                struct.pack(
                    "<IIIII", RDATA_RVA + lookup, 0, 0, RDATA_RVA + dll_name, RDATA_RVA + address
                ),
            )
        self.import_directory = (RDATA_RVA + offset, descriptors)
        return slots

    def put(self, section: str, offset: int, blob: bytes) -> int:
        """Write ``blob`` at ``offset`` inside a section; answer its RVA."""
        target = getattr(self, section)
        if offset + len(blob) > len(target):
            target.extend(b"\0" * (offset + len(blob) - len(target)))
        target[offset : offset + len(blob)] = blob
        return {"text": TEXT_RVA, "rdata": RDATA_RVA, "data": DATA_RVA}[section] + offset

    def lea_to(self, text_offset: int, target_rva: int) -> None:
        """``lea rcx, [rip+disp32]`` at ``text_offset`` taking ``target_rva``."""
        instruction_end = TEXT_RVA + text_offset + 7
        displacement = target_rva - instruction_end
        self.put("text", text_offset, b"\x48\x8d\x0d" + struct.pack("<i", displacement))

    def build(self) -> bytes:
        sections: list[tuple[bytes, int, bytes, int]] = [
            (b".text", TEXT_RVA, bytes(self.text), _CODE),
            (b".rdata", RDATA_RVA, bytes(self.rdata), _RDATA),
            (b".data", DATA_RVA, bytes(self.data), _DATA),
        ]
        pdata = b""
        if self.is64 and self.functions:
            pdata = b"".join(
                struct.pack("<III", entry[0], entry[1], entry[2] if len(entry) > 2 else 0)
                for entry in self.functions
            )
            # A zero entry ends the table; anything after it is still inside the directory.
            if self.pdata_tail:
                pdata += b"\0" * 12 + self.pdata_tail
            sections.append((b".pdata", PDATA_RVA, pdata, _RDATA))
        optional_size = 0xF0 if self.is64 else 0xE0
        headers_size = _align(0x80 + 24 + optional_size + 40 * len(sections), FILE_ALIGNMENT)

        dos = bytearray(0x80)
        dos[0:2] = b"MZ"
        struct.pack_into("<I", dos, 0x3C, 0x80)
        machine = 0x8664 if self.is64 else 0x14C
        characteristics = 0x0022 if self.is64 else 0x0102
        file_header = struct.pack(
            "<4sHHIIIHH", b"PE\0\0", machine, len(sections), 0, 0, 0, optional_size, characteristics
        )
        size_of_image = _align(
            max(rva + len(body) for _, rva, body, _ in sections), SECTION_ALIGNMENT
        )
        optional = bytearray(optional_size)
        struct.pack_into("<H", optional, 0, 0x20B if self.is64 else 0x10B)
        struct.pack_into("<I", optional, 16, TEXT_RVA)  # AddressOfEntryPoint
        if self.is64:
            struct.pack_into("<Q", optional, 24, self.image_base)
        else:
            struct.pack_into("<I", optional, 28, self.image_base)
        struct.pack_into("<II", optional, 32, SECTION_ALIGNMENT, FILE_ALIGNMENT)
        struct.pack_into("<I", optional, 56, size_of_image)
        struct.pack_into("<I", optional, 60, headers_size)
        struct.pack_into("<H", optional, 68, 2)  # subsystem: GUI
        directories = 112 if self.is64 else 96
        struct.pack_into("<I", optional, directories - 4, 16)
        if pdata:
            struct.pack_into("<II", optional, directories + 3 * 8, PDATA_RVA, len(pdata))
        if self.import_directory is not None:
            struct.pack_into("<II", optional, directories + 1 * 8, *self.import_directory)

        table = bytearray()
        bodies = bytearray()
        raw_offset = headers_size
        for name, rva, body, flags in sections:
            raw_size = _align(len(body), FILE_ALIGNMENT)
            table += struct.pack(
                "<8sIIIIIIHHI", name, len(body), rva, raw_size, raw_offset, 0, 0, 0, 0, flags
            )
            bodies += body + b"\0" * (raw_size - len(body))
            raw_offset += raw_size
        head = bytes(dos) + file_header + bytes(optional) + bytes(table)
        return head + b"\0" * (headers_size - len(head)) + bytes(bodies)

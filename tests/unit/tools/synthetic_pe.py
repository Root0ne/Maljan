"""A minimal PE image built in memory for the tests that read values out of one.

No real program is used anywhere: the tests lay out a code section, a data
section and, for an x64 image, a function table with the bytes each test needs
at addresses it chooses, and check that the tools report those addresses.

The calibration set (``scripts/calibration``) builds its cases with the same
class: sections of a name and flags of its choosing after the fixed ones, a
resource section and an overlay. An image that uses none of them is laid out
byte for byte as before.
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

RESOURCE_DIRECTORY = 2  # the data directory index of the resource tree
_DIRECTORY_HEADER = 16  # IMAGE_RESOURCE_DIRECTORY
_DIRECTORY_ENTRY = 8  # IMAGE_RESOURCE_DIRECTORY_ENTRY
_DATA_ENTRY = 16  # IMAGE_RESOURCE_DATA_ENTRY
_SUBDIRECTORY = 0x80000000  # an entry's offset names a directory, not a data entry
_NEUTRAL_LANGUAGE = 0


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
    # Sections laid out after the fixed ones, in order: (name, body, characteristics).
    extra_sections: list[tuple[bytes, bytes, int]] = field(default_factory=list)
    # Resources as (type id, name id, data), written as a ``.rsrc`` section last.
    resources: list[tuple[int, int, bytes]] = field(default_factory=list)
    # Bytes after the last section, which no header describes.
    overlay: bytes = b""

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

    def call_slot(self, text_offset: int, slot_rva: int) -> None:
        """``call [slot]`` at ``text_offset``: RIP-relative on x64, absolute on x86."""
        if self.is64:
            displacement = slot_rva - (TEXT_RVA + text_offset + 6)
            self.put("text", text_offset, b"\xff\x15" + struct.pack("<i", displacement))
        else:
            self.put(
                "text", text_offset, b"\xff\x15" + struct.pack("<I", self.image_base + slot_rva)
            )

    def refer(self, text_offset: int, target_rva: int) -> None:
        """Take ``target_rva`` at ``text_offset``: ``lea rcx`` on x64, ``push imm32`` on x86."""
        if self.is64:
            self.lea_to(text_offset, target_rva)
        else:
            self.put("text", text_offset, b"\x68" + struct.pack("<I", self.image_base + target_rva))

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
        for name, body, flags in self.extra_sections:
            sections.append((name, _next_rva(sections), bytes(body), flags))
        if self.resources:
            rsrc_rva = _next_rva(sections)
            sections.append((b".rsrc", rsrc_rva, _resource_tree(rsrc_rva, self.resources), _RDATA))
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
        if self.resources:
            rsrc = sections[-1]
            struct.pack_into(
                "<II", optional, directories + RESOURCE_DIRECTORY * 8, rsrc[1], len(rsrc[2])
            )

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
        return head + b"\0" * (headers_size - len(head)) + bytes(bodies) + self.overlay


def _next_rva(sections: list[tuple[bytes, int, bytes, int]]) -> int:
    """Where a section after ``sections`` starts: past the last one, at the section alignment."""
    _, rva, body, _ = sections[-1]
    if not body:
        raise ValueError("a section must hold at least one byte to place the next one after it")
    return _align(rva + len(body), SECTION_ALIGNMENT)


def _resource_tree(rva: int, resources: list[tuple[int, int, bytes]]) -> bytes:
    """A resource section at ``rva``: type, name and language levels, each name in one language.

    Laid out level by level: the root, one directory per type, one per name,
    the data entries, then the data.
    """
    by_type: dict[int, list[tuple[int, bytes]]] = {}
    for type_id, name_id, blob in sorted(resources, key=lambda r: (r[0], r[1])):
        by_type.setdefault(type_id, []).append((name_id, blob))
    names = len(resources)
    per_name = _DIRECTORY_HEADER + _DIRECTORY_ENTRY
    type_level = _DIRECTORY_HEADER + _DIRECTORY_ENTRY * len(by_type)
    name_level = type_level + sum(
        _DIRECTORY_HEADER + _DIRECTORY_ENTRY * len(rows) for rows in by_type.values()
    )
    entry_level = name_level + per_name * names
    data_level = entry_level + _DATA_ENTRY * names

    def directory(ids: list[int], offsets: list[int]) -> bytes:
        head = struct.pack("<IIHHHH", 0, 0, 0, 0, 0, len(ids))
        return head + b"".join(struct.pack("<II", i, o) for i, o in zip(ids, offsets, strict=True))

    root_offsets: list[int] = []
    types, languages, entries, blobs = bytearray(), bytearray(), bytearray(), bytearray()
    index = 0
    for rows in by_type.values():
        root_offsets.append(_SUBDIRECTORY | (type_level + len(types)))
        name_offsets: list[int] = []
        for _name_id, blob in rows:
            name_offsets.append(_SUBDIRECTORY | (name_level + per_name * index))
            languages += directory([_NEUTRAL_LANGUAGE], [entry_level + _DATA_ENTRY * index])
            entries += struct.pack("<IIII", rva + data_level + len(blobs), len(blob), 0, 0)
            blobs += blob
            index += 1
        types += directory([name_id for name_id, _ in rows], name_offsets)
    root = directory(list(by_type), root_offsets)
    return root + bytes(types) + bytes(languages) + bytes(entries) + bytes(blobs)

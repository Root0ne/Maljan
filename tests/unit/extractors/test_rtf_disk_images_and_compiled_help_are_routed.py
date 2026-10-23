"""RTF, raw disk images, virtual hard disks and compiled help files are identified and routed.

Each by the bytes its specification fixes, and nothing else of the file is
read: RTF's ``{\\rtf`` header, the ITSF header of compiled HTML help, the
``conectix`` cookie a dynamic virtual disk keeps at its start, a fixed virtual
disk's footer (its last 512 bytes alone), and a raw disk's boot sector. Each
label is a routed format, so a tool or a pack step declared for it is routed
to, and each is a container the shipped readers do not open, which the run
says.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from maljan.core.pack_steps import PackStep
from maljan.core.tool_declarations import ToolFacts
from maljan.extractors.sample_identity import (
    detect_file_type,
    file_type_category,
    routed_formats,
    unparsed_container_reason,
)
from maljan.tools.identify import identify_file

SECTOR = 512


def _boot(head: bytes = b"", **at: bytes) -> bytearray:
    """Two crafted sectors: ``head`` first, each ``o<offset>`` value there, the signature."""
    sector = bytearray(SECTOR * 2)
    sector[: len(head)] = head
    sector[510:512] = b"\x55\xaa"
    for offset, value in at.items():
        start = int(offset.lstrip("o"))
        sector[start : start + len(value)] = value
    return sector


def _mbr(status: int = 0x80, kind: int = 0x07, first: int = 1, length: int = 1) -> bytearray:
    """An MBR with one partition entry; as made, the partition is the file's second sector."""
    disk = _boot()
    disk[446] = status
    disk[450] = kind
    disk[454:458] = first.to_bytes(4, "little")
    disk[458:462] = length.to_bytes(4, "little")
    return disk


def _vbr(jump: bytes = b"\xeb\x3c\x90", per_sector: int = 512, per_cluster: int = 8) -> bytearray:
    """A volume boot record: a jump and a BIOS parameter block."""
    return _boot(jump, o11=per_sector.to_bytes(2, "little"), o13=bytes([per_cluster]))


NTFS = _vbr(b"\xeb\x52\x90NTFS    ")
FAT32 = _vbr(b"\xeb\x58\x90MSDOS5.0", per_cluster=1)
NEAR_JUMP = _vbr(b"\xe9\x00\x01", per_sector=4096, per_cluster=64)
EXFAT = _boot(b"\xeb\x76\x90EXFAT   ", o108=b"\x09\x03")
GPT = _boot(o512=b"EFI PART")


@pytest.mark.parametrize(
    ("blob", "label"),
    [
        (b"{\\rtf1\\ansi\\deff0 {\\fonttbl}", "rtf"),
        (b"ITSF\x03\x00\x00\x00`\x00\x00\x00", "chm"),
        (b"ITSF\x02\x00\x00\x00`\x00\x00\x00", "chm"),
        (b"conectix\x00\x00\x00\x02" + bytes(600), "vhd"),
        (bytes(_mbr()), "img"),
        (bytes(NTFS), "img"),
        (bytes(EXFAT), "img"),
        (bytes(FAT32), "img"),
        (bytes(NEAR_JUMP), "img"),
        (bytes(GPT), "img"),
        (bytes(_mbr()) + b"conectix" + bytes(SECTOR - 8), "vhd"),
        (bytes(_mbr()) + b"\x00conectix" + bytes(SECTOR - 9), "vhd"),
    ],
)
def test_each_is_identified_by_its_specification_s_bytes(blob: bytes, label: str) -> None:
    assert detect_file_type(Path("/nowhere/sample.bin"), blob) == label
    assert label in routed_formats()


@pytest.mark.parametrize(
    "blob",
    [
        b"{\\rt1 almost",  # not the \rtf control word
        b"ITSF\x04\x00\x00\x00",  # no ITSF version a compiler writes
        bytes(_boot()),  # a boot signature over nothing a disk holds
        bytes(_mbr(status=0x01)),  # a partition status no MBR writes
        bytes(_mbr(kind=0)),  # four empty partition entries
        bytes(_mbr(first=0)),  # a partition over the MBR itself
        bytes(_mbr(length=0)),  # a partition of no sectors
        bytes(_mbr(length=2)),  # a partition past the end of the file
        bytes(_mbr(length=0xFFFFFFFF)),
        bytes(_boot(b"\xeb\x3c\x91")),  # a short jump not followed by a NOP
        bytes(_vbr(per_sector=500)),  # bytes per sector no volume uses
        bytes(_vbr(per_cluster=6)),  # sectors per cluster not a power of two
        bytes(_vbr(per_cluster=0)),
        bytes(_boot(b"\xeb\x76\x90EXFAT   ", o108=b"\x08\x03")),  # a sector shift out of range
        bytes(_boot(b"\x00\x00\x00NTFS    ")),  # an OEM name with no jump before it
        bytes(SECTOR) + b"conectix",  # a cookie that is not the footer
    ],
)
def test_bytes_that_only_resemble_one_are_not_it(blob: bytes) -> None:
    assert detect_file_type(Path("/nowhere/sample.bin"), blob) not in {"rtf", "chm", "img", "vhd"}


@pytest.mark.parametrize(
    ("name", "head", "label"),
    [
        ("a.bin", b"MZ\x90\x00", "pe"),  # an executable with the two bytes at 510
        ("a.bin", b"\x7fELF", "elf"),
        ("run", b"#!/bin/sh\n", "sh"),  # a script by its shebang
        ("run.ps1", b"", "ps1"),  # a script by its name
        ("run.js", b"", "js"),
    ],
)
def test_a_boot_signature_never_outranks_what_the_file_is(
    name: str, head: bytes, label: str
) -> None:
    """Two bytes at offset 510, even over a well-formed MBR, do not make a disk of a program."""
    blob = bytearray(_mbr())
    blob[: len(head)] = head
    assert detect_file_type(Path(f"/nowhere/{name}"), bytes(blob)) == label


def test_a_fixed_virtual_disk_is_read_only_at_its_footer(tmp_path: Path) -> None:
    """The header the detector is handed and the last 512 bytes: nothing between is read."""
    disk = tmp_path / "disk.vhd"
    disk.write_bytes(bytes(_mbr()) + bytes(SECTOR * 64) + b"conectix" + bytes(SECTOR - 8))
    header = disk.read_bytes()[: SECTOR * 2]
    assert detect_file_type(disk, header) == "vhd"
    assert identify_file(str(disk))["file_type"] == "vhd"
    raw = tmp_path / "disk.img"
    raw.write_bytes(bytes(_mbr()) + bytes(SECTOR * 64))
    assert identify_file(str(raw))["file_type"] == "img"


def test_a_misnamed_document_is_routed_by_its_bytes(tmp_path: Path) -> None:
    sample = tmp_path / "invoice.doc"
    sample.write_bytes(b"{\\rtf1 {\\object\\objemb}}")
    assert identify_file(str(sample))["file_type"] == "rtf"


@pytest.mark.parametrize(
    ("label", "category"),
    [("rtf", "document"), ("img", "archive"), ("vhd", "archive"), ("chm", "archive")],
)
def test_each_is_routed_under_its_category(label: str, category: str) -> None:
    assert file_type_category(label) == category


@pytest.mark.parametrize("label", ["rtf", "img", "vhd", "chm"])
def test_a_tool_and_a_pack_step_are_declared_for_it(label: str) -> None:
    assert ToolFacts(kind="document_facts", routed_formats=(label,)).routed_formats == (label,)
    step = PackStep(id="reader", server="s", tool="t", formats=(label,))
    assert step.formats == (label,)


@pytest.mark.parametrize(
    ("name", "blob", "said"),
    [
        ("a.doc", b"{\\rtf1 x}", "RTF document"),
        ("a.bin", b"ITSF\x03\x00\x00\x00" + bytes(16), "compiled HTML help"),
        ("a.bin", bytes(_mbr()), "disc image"),
        ("a.bin", b"conectix" + bytes(600), "virtual disk"),
    ],
)
def test_the_run_says_no_shipped_reader_opened_it(
    tmp_path: Path, name: str, blob: bytes, said: str
) -> None:
    sample = tmp_path / name
    sample.write_bytes(blob)
    reason = unparsed_container_reason(sample)
    assert reason is not None and reason.startswith(f"{said} container was not parsed")

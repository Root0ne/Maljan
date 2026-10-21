"""The review round of AUD-51: hostile ELF version tables, a rooted .bit name, the fallback note."""

from __future__ import annotations

import io
import struct
import time
from pathlib import Path

import pytest
from elftools.elf.elffile import ELFFile

from maljan.extractors.capability_matrix import (
    CORROBORATION_NOT_READ_NOTE,
    NO_CORROBORATION_ROW_NOTE,
    build_capability_matrix,
)
from maljan.extractors.network_extractor import _scored_domain
from maljan.extractors.pe_extractor import _parse_elf_imports
from maljan.schemas.isr_models import AgentISR, ClaimEvidence

LS = Path("/bin/ls")


def _hostile_ls(which: str) -> bytes:
    """/bin/ls with its .gnu.version_r damaged as a hostile sample would."""
    base = bytearray(LS.read_bytes())
    elf = ELFFile(io.BytesIO(bytes(base)))
    idx = next(i for i, s in enumerate(elf.iter_sections()) if s.name == ".gnu.version_r")
    sec = elf.get_section(idx)
    sh_info = elf["e_shoff"] + idx * elf["e_shentsize"] + 44
    vn = sec["sh_offset"]
    if which == "loop":
        struct.pack_into("<I", base, sh_info, 0x7FFFFFFF)
        struct.pack_into("<I", base, vn + 12, 0)
    elif which == "auxloop":
        struct.pack_into("<H", base, vn + 2, 0xFFFF)
        aux = vn + struct.unpack_from("<I", base, vn + 8)[0]
        struct.pack_into("<I", base, aux + 12, 0)
        struct.pack_into("<I", base, sh_info, 0xFFFF)
        struct.pack_into("<I", base, vn + 12, 0)
    elif which == "past_eof":
        struct.pack_into("<I", base, vn + 12, 0x7FFFFFF0)
    elif which == "cnt0":
        struct.pack_into("<H", base, vn + 2, 0)
    return bytes(base)


@pytest.mark.parametrize("which", ["loop", "auxloop", "past_eof", "cnt0"])
def test_n1_a_hostile_version_table_costs_no_time_and_no_import_row(which: str) -> None:
    if not LS.is_file():
        pytest.skip("no system ELF to read")
    clean = _parse_elf_imports(LS.read_bytes())
    started = time.monotonic()
    rows = _parse_elf_imports(_hostile_ls(which))
    assert time.monotonic() - started < 10
    assert sum(1 for r in rows if r.function) == sum(1 for r in clean if r.function)


def test_n3_a_fully_qualified_bit_name_is_flagged() -> None:
    assert _scored_domain("payload.bit.").suspicious
    assert not _scored_domain("www.bitly.com.").suspicious


def test_l9_a_run_without_a_ledger_reads_as_it_did() -> None:
    """No ledger, no corroboration was read: the row says nothing about one."""
    claim = ClaimEvidence(claim="injects", evidence_ref="r", confidence=0.8, technique_id="T1055")
    isr = {"static": AgentISR(agent_id="static", domain="static", claims=[claim])}
    stix = {
        "type": "bundle",
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--1",
                "name": "T1055",
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1055"}],
            }
        ],
    }
    cells, _ = build_capability_matrix(stix_output=stix, isr_reports=isr)
    assert NO_CORROBORATION_ROW_NOTE not in cells[0].note
    assert CORROBORATION_NOT_READ_NOTE not in cells[0].note


def test_n_a_version_table_naming_one_long_string_costs_the_sections_size() -> None:
    """Many need entries whose names run into one huge unterminated-looking string."""
    if not LS.is_file():
        pytest.skip("no system ELF to read")
    n, length = 4000, 2_000_000
    base = bytearray(LS.read_bytes())
    elf = ELFFile(io.BytesIO(bytes(base)))
    secs = {s.name: (i, s) for i, s in enumerate(elf.iter_sections())}
    header = elf["e_shoff"] + secs[".gnu.version_r"][0] * elf["e_shentsize"]
    dynstr = secs[".dynstr"][1]["sh_offset"]
    region = len(base)
    first_name = region + 16 * n - dynstr
    entries = b"".join(struct.pack("<HHIII", 1, 1, first_name + (i % 64), 0, 16) for i in range(n))
    base += entries + b"A" * length + b"\0"
    struct.pack_into("<Q", base, header + 24, region)
    struct.pack_into("<Q", base, header + 32, 16 * n)
    struct.pack_into("<I", base, header + 44, n)
    started = time.monotonic()
    rows = _parse_elf_imports(bytes(base))
    assert time.monotonic() - started < 10
    assert rows

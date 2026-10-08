"""An unpacked program is a file of its own in the evidence roots, placed against its own layout.

The answers are the tools' own, computed over a synthetic UPX-packed PE
(``synthetic_upx``); the ledger entries carry them as the recorder stores a
tool's answer. The unpacking's root is where the compressed data it read
starts in the packed file; a call that reads the unpacked program by its
``carved_path`` is about that program, named by the digest the unpacking
states, and placed against the program's own section table.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from tests.unit.tools import synthetic_upx as su
from tests.unit.tools.synthetic_pe import SyntheticPE

from maljan.analysis.evidence_roots import run_roots
from maljan.schemas.evidence import LedgerEntry
from maljan.tools import binary, upx


def _entry(eid: str, tool: str, answer: dict[str, Any], **args: Any) -> LedgerEntry:
    return LedgerEntry(
        id=eid, tool=tool, args=args, structured=answer, ok="error" not in answer, agent="pipeline"
    )


def _ledger(tmp_path: Path) -> tuple[list[LedgerEntry], dict[str, Any], str]:
    sample = tmp_path / "packed.exe"
    sample.write_bytes(su.build().data)
    unpacked = upx.unpack_upx(str(sample), tmp_path / "carved")
    child = unpacked["child"]["carved_path"]
    child_strings = {"strings": [{"offset": 0x1600, "text": "child-only"}]}
    return (
        [
            _entry("ev_0001", "pe_info", binary.pe_info(str(sample)), path=str(sample)),
            _entry("ev_0002", "unpack_upx", unpacked, path=str(sample)),
            _entry("ev_0003", "analysis__pe_info", binary.pe_info(child), carved_path=child),
            _entry("ev_0004", "analysis__strings", child_strings, carved_path=child),
            _entry(
                "ev_0005",
                "strings",
                {"strings": [{"offset": 0x500, "text": "sample-only"}]},
                path=str(sample),
            ),
        ],
        unpacked,
        str(sample),
    )


def test_the_unpacking_s_root_is_its_compressed_data_in_the_packed_layout(tmp_path: Path) -> None:
    led, unpacked, _ = _ledger(tmp_path)
    upx1 = next(s for s in led[0].structured["sections"] if s["name"] == "UPX1")
    assert unpacked["pack_header"]["compressed_data_offset"] == hex(su.UPX1_RAW)
    start = int(upx1["virtual_address"], 16)
    assert run_roots(led).of_entry("ev_0002").roots == [f"{start:#x} in UPX1"]


def test_a_read_of_the_unpacked_program_is_placed_against_its_own_sections(
    tmp_path: Path,
) -> None:
    led, unpacked, _ = _ledger(tmp_path)
    digest = unpacked["child"]["sha256"][:12]
    roots = run_roots(led)
    # File offset 0x1600 is .rdata's first 0x200 bytes in the unpacked program
    # (raw 0x1400, rva 0x2000); in the packed file it would be inside UPX1.
    assert roots.of_entry("ev_0004").roots == [f"0x2200 in .rdata of file sha256 {digest}"]
    # The same offset read from the sample is placed in the packed file's UPX1.
    upx1 = next(s for s in led[0].structured["sections"] if s["name"] == "UPX1")
    placed = int(upx1["virtual_address"], 16) + 0x500 - su.UPX1_RAW
    assert roots.of_entry("ev_0005").roots == [f"{placed:#x} in UPX1"]


def test_a_file_that_was_not_unpacked_gives_its_sentence(tmp_path: Path) -> None:
    plain = tmp_path / "plain.exe"
    plain.write_bytes(SyntheticPE().build())
    answer = upx.unpack_upx(str(plain), tmp_path / "carved")
    led = [_entry("ev_0001", "unpack_upx", answer, path=str(plain))]
    found = run_roots(led).of_entry("ev_0001")
    assert found.roots == [] and found.reason == upx.NO_HEADER

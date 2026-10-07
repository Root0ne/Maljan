"""A byte transform's evidence root is where its input range starts in the image.

The answers are the module's own, computed over a synthetic PE written by the
test; the ledger entries carry them as the recorder stores a tool's answer.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from tests.unit.tools.synthetic_pe import SyntheticPE

from maljan.analysis.evidence_roots import FAILED, run_roots
from maljan.schemas.evidence import LedgerEntry
from maljan.tools import pe_image
from maljan.tools.transforms import transform_bytes


def _sample(tmp_path: Path) -> tuple[str, int]:
    image = SyntheticPE()
    at = image.put("data", 0x80, b"\x13\x37" * 32)
    target = tmp_path / "s.exe"
    target.write_bytes(image.build())
    return str(target), at


def _pe_info(eid: str, path: str) -> LedgerEntry:
    loaded = pe_image.load(path)
    sections = [
        {
            "name": s.name,
            "virtual_address": hex(s.rva),
            "virtual_size": s.virtual_size,
            "raw_offset": s.raw_offset,
            "raw_size": s.raw_size,
        }
        for s in loaded.sections
    ]
    return LedgerEntry(
        id=eid,
        tool="pe_info",
        args={"path": path},
        structured={"sections": sections, "image_base": hex(loaded.image_base)},
    )


def _transform(eid: str, path: str, **args: Any) -> LedgerEntry:
    answer = transform_bytes(path, **args)
    return LedgerEntry(
        id=eid,
        tool="analysis__transform_bytes",
        args={"path": path, **args},
        structured=answer,
        ok="error" not in answer,
    )


def test_the_root_is_the_range_s_start_with_its_section(tmp_path: Path) -> None:
    path, at = _sample(tmp_path)
    ledger = [
        _pe_info("ev_0001", path),
        _transform("ev_0002", path, rva=hex(at), length=16),
        LedgerEntry(
            id="ev_0003",
            tool="decode_string_blobs",
            args={"path": path},
            structured={"results": [{"rva": hex(at), "text": "x"}]},
        ),
    ]
    roots = run_roots(ledger)
    assert roots.of_entry("ev_0002").roots == [f"{at:#x} in .data"]
    # The blob decoder reading the same place is the same root.
    assert roots.of_entry("ev_0003").roots == roots.of_entry("ev_0002").roots


def test_a_file_offset_is_placed_by_the_rva_the_answer_states(tmp_path: Path) -> None:
    path, at = _sample(tmp_path)
    data = next(s for s in pe_image.load(path).sections if s.name == ".data")
    offset = data.raw_offset + (at - data.rva)
    ledger = [_pe_info("ev_0001", path), _transform("ev_0002", path, offset=offset, length=8)]
    assert run_roots(ledger).of_entry("ev_0002").roots == [f"{at:#x} in .data"]


def test_a_range_no_section_holds_gives_the_answer_s_reason(tmp_path: Path) -> None:
    path, _at = _sample(tmp_path)
    flat = tmp_path / "flat.bin"
    flat.write_bytes(b"\x00" * 64)
    ledger = [
        _pe_info("ev_0001", path),
        _transform("ev_0002", path, offset=0, length=2),
        _transform("ev_0003", str(flat), offset=0, length=2),
    ]
    roots = run_roots(ledger)
    header = roots.of_entry("ev_0002")
    assert header.roots == []
    assert header.reason == "no: file offset 0x0 lies in no section's bytes in the file"
    other = roots.of_entry("ev_0003")
    assert other.roots == [] and other.reason.startswith("no: the file is not a PE image")


def test_a_failed_transform_read_nothing(tmp_path: Path) -> None:
    path, at = _sample(tmp_path)
    ledger = [_transform("ev_0001", path, rva=hex(at), steps=[{"op": "rot13"}])]
    assert run_roots(ledger).of_entry("ev_0001").reason == FAILED

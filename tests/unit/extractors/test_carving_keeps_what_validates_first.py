"""A carve's cap is filled by evidence, not by the order of the signatures.

The carver kept the first eight hits in signature order, PE magic first, so
eight ``MZ`` decoys ahead of a real payload filled the cap and the payload was
never carved, and nothing said so. Every candidate is now found in one pass
and ranked by whether its header validates as the format its magic names;
the cap keeps the validated ones first, and whenever candidates are left out
a row says how many and of which kinds.
"""

from __future__ import annotations

import struct

from maljan.extractors.pe_extractor import (
    _MAX_CARVED_CHILDREN,
    _carve_from,
    carve_payloads,
)

DECOY = b"MZ\x90\x00" + b"\x00" * 60  # PE magic, no PE header behind it


def _real_pe() -> bytes:
    head = bytearray(b"MZ\x90\x00" + b"\x00" * 0x3C)
    head[0x3C:0x40] = struct.pack("<I", 0x40)
    return bytes(head) + b"PE\x00\x00" + struct.pack("<H", 0x14C) + b"\x00" * 2048


def _blob(decoys: int, *tail: bytes) -> bytes:
    out = b"\x00" * 16
    for _ in range(decoys):
        out += DECOY + b"\x00" * 64
    for part in tail:
        out += part
    return out + b"\x00" * 2048


def test_decoys_ahead_of_a_real_pe_do_not_crowd_it_out() -> None:
    real = _real_pe()
    blob = _blob(_MAX_CARVED_CHILDREN + 1, real)
    at = blob.index(real)
    rows = _carve_from(blob, 0)
    carved = [r for r in rows if r.get("carved")]
    assert len(carved) == _MAX_CARVED_CHILDREN
    assert at in [r["offset"] for r in carved]
    assert at in [int(label.split("+0x")[1], 16) for label, _ in carve_payloads(blob)]


def test_the_candidates_the_cap_leaves_out_are_stated() -> None:
    blob = _blob(_MAX_CARVED_CHILDREN + 1, _real_pe(), b"PK\x03\x04" + b"\x00" * 40)
    rows = _carve_from(blob, 0)
    notes = [r for r in rows if not r.get("carved")]
    assert len(notes) == 1
    note = notes[0]
    assert note["left_out"] == 3
    assert note["kinds"] == {"PE": 2, "ZIP": 1}
    assert f"{_MAX_CARVED_CHILDREN} carved" in note["type"]
    assert "3 more candidates not carved" in note["type"]
    # The note is not a payload: carve_payloads hands on carved rows only.
    assert len(carve_payloads(blob)) == _MAX_CARVED_CHILDREN


def _real_zip() -> bytes:
    header = struct.pack("<4sHHHHHIIIHH", b"PK\x03\x04", 20, 0, 8, 0, 0, 0, 0, 0, 5, 0)
    return header + b"a.txt" + b"\x00" * 64


def test_each_validated_kind_gets_a_slot_first() -> None:
    """Nine real PEs ahead of a real ZIP do not take the ZIP's slot."""
    pes = [_real_pe() for _ in range(_MAX_CARVED_CHILDREN + 1)]
    blob = _blob(0, *pes, _real_zip())
    rows = _carve_from(blob, 0)
    carved = [r for r in rows if r.get("carved")]
    assert [r["type"] for r in carved].count("carved:ZIP") == 1
    assert len(carved) == _MAX_CARVED_CHILDREN
    note = [r for r in rows if not r.get("carved")][0]
    assert note["kinds"] == {"PE": 2}
    assert note["kinds_validated"] == {"PE": 2}
    assert note["left_out_validated"] == 2


def test_a_blob_of_magic_bytes_carves_in_constant_memory() -> None:
    """32 MB of repeated PE magic: thousands of candidates, of which the carver
    holds a handful, hashing the kept ones in place (a copy of each would be
    32 MB, and a list of every candidate grows with the blob)."""
    import tracemalloc

    block = 4096
    blocks = 32 * 1024 * 1024 // block
    blob = (b"MZ\x90\x00" + b"\x00" * (block - 4)) * blocks
    tracemalloc.start()
    try:
        rows = _carve_from(blob, 0)
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 256 * 1024
    note = [r for r in rows if not r.get("carved")][0]
    # Every block but the sample's own first one is a candidate.
    assert note["left_out"] == blocks - 1 - _MAX_CARVED_CHILDREN


def test_under_the_cap_every_candidate_is_kept_in_file_order() -> None:
    real = _real_pe()
    blob = _blob(2, real)
    rows = _carve_from(blob, 0)
    assert all(r.get("carved") for r in rows)
    offsets = [r["offset"] for r in rows]
    assert offsets == sorted(offsets) and len(offsets) == 3

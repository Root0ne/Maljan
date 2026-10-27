"""A pack row pointed to its stored output keeps every sentence its renderer writes.

The technique question shows a pack row whose entry's stored output it shows
whole below as the row's head and a pointer. The head is the row its own
renderer writes with no listed item (``triage_pack.pack_row_heads``), so the
platform's sentences on reading the row (what the decoding schemes cannot
see, that the texts are the sample's words) stay; only the items, which the
stored output holds, go. A failed call's row is never pointed.

Every value is synthetic.
"""

from __future__ import annotations

import struct
import zlib
from pathlib import Path

from maljan.agents.evidence_recorder import EvidenceRecorder
from maljan.agents.judge_agent import PACK_ROW_SHOWN_BELOW, pack_rows_shown_below
from maljan.pipeline import triage_pack
from maljan.pipeline.triage_pack import (
    PACK_HEADING,
    PIPELINE,
    CapaSettings,
    PackInputs,
    pack_block,
    pack_entries,
    pack_row_heads,
    run_pack,
)
from maljan.schemas.evidence import EvidenceCounter

from ..tools.synthetic_pe import DATA_RVA, TEXT_RVA, SyntheticPE

FUNCTION = TEXT_RVA + 0x100


def _entries(tmp_path: Path) -> list:
    image = SyntheticPE(functions=[(TEXT_RVA, FUNCTION), (FUNCTION, TEXT_RVA + 0x300)])
    for offset, name in ((0x40, b"VirtualAlloc"), (0x60, b"CreateFileW")):
        image.put("text", offset, b"\x3d" + struct.pack("<I", zlib.crc32(name)))
    blob = bytes(byte ^ 0x9C for byte in b"open the settings file\0")
    image.lea_to(0x120, image.put("data", 0x80, blob))
    target = tmp_path / "s.exe"
    target.write_bytes(image.build())
    recorder = EvidenceRecorder(PIPELINE, counter=EvidenceCounter(), stage="triage_pack")
    inputs = PackInputs(
        sample_path=str(target),
        sha256="a" * 64,
        file_type="pe",
        strings_head=10,
        capa=CapaSettings(rules_dir="", signatures_dir="", timeout_s=1),
    )
    return list(pack_entries(run_pack(recorder, inputs).entries))


def _blobs(entries: list) -> tuple[str, str]:
    entry = next(e for e in entries if e.tool == "decode_string_blobs")
    return str(entry.id), str(entry.output)


class TestTheHeadKeepsTheRenderersSentences:
    def test_the_head_has_the_caveats_and_none_of_the_items(self, tmp_path: Path) -> None:
        entries = _entries(tmp_path)
        entry_id, _output = _blobs(entries)

        head = pack_row_heads(entries)[entry_id.lower()]

        assert head.startswith(f"[{entry_id}] decoded blobs: ")
        assert triage_pack.DECODED_BLOBS_RECALL in head
        assert triage_pack.DECODED_BLOBS_PROVENANCE in head
        assert "open the settings file" not in head

    def test_the_pointed_row_keeps_the_caveats_and_points_below(self, tmp_path: Path) -> None:
        entries = _entries(tmp_path)
        entry_id, output = _blobs(entries)
        heads = pack_row_heads(entries)
        # The row as a pack of many decodings writes it: its head, then its items.
        items = "; ".join(f'"text {i}"@{hex(DATA_RVA + i)} [xor8 key 0x9c]' for i in range(60))
        block = f"{PACK_HEADING}\n{heads[entry_id.lower()]}: {items}"

        pointed = pack_rows_shown_below(block, {entry_id.lower(): output * 40}, heads)

        row = pointed.splitlines()[1]
        assert row == f"{heads[entry_id.lower()]} — {PACK_ROW_SHOWN_BELOW}."
        assert triage_pack.DECODED_BLOBS_RECALL in row
        assert '"text 1"' not in row

    def test_a_row_its_pointer_would_not_shorten_stays_whole(self, tmp_path: Path) -> None:
        entries = _entries(tmp_path)
        entry_id, output = _blobs(entries)
        block = pack_block(entries, 0)

        pointed = pack_rows_shown_below(
            block, {entry_id.lower(): output * 40}, pack_row_heads(entries)
        )

        assert f'"open the settings file"@{hex(DATA_RVA + 0x80)}' in pointed

    def test_no_entry_is_no_head(self) -> None:
        assert pack_row_heads([]) == {}

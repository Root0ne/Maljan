"""The pack every agent reads carries the hash values and the encoded strings the platform resolved.

Both tools run as the pack's last two steps on a PE, and their lines show each
value's function name and each decoded text with the places they stand or are
referred to from, as offsets from the image base, and the function the file's
table puts around each place: the numbers the reverser takes to its
decompiler. When the pack's derived room runs out, a line says how many it
shows and which call gives the rest.
"""

from __future__ import annotations

import json
import struct
import zlib
from pathlib import Path
from typing import Any

import pytest

from maljan.agents.evidence_recorder import EvidenceRecorder
from maljan.agents.prompts import REVERSER_PROMPT
from maljan.pipeline import triage_pack
from maljan.pipeline.triage_pack import (
    PIPELINE,
    CapaSettings,
    PackInputs,
    pack_block,
    pack_entries,
    run_pack,
)
from maljan.schemas.evidence import EvidenceCounter, build_entry, format_entry_id

from ..tools.synthetic_pe import DATA_RVA, TEXT_RVA, SyntheticPE

FUNCTION = TEXT_RVA + 0x100


def _sample(tmp_path: Path) -> str:
    image = SyntheticPE(functions=[(TEXT_RVA, FUNCTION), (FUNCTION, TEXT_RVA + 0x300)])
    for offset, name in ((0x40, b"VirtualAlloc"), (0x60, b"CreateFileW")):
        image.put("text", offset, b"\x3d" + struct.pack("<I", zlib.crc32(name)))
    blob = bytes(byte ^ 0x9C for byte in b"open the settings file\0")
    image.lea_to(0x120, image.put("data", 0x80, blob))
    target = tmp_path / "s.exe"
    target.write_bytes(image.build())
    return str(target)


def _pack(path: str, file_type: str = "pe") -> Any:
    recorder = EvidenceRecorder(PIPELINE, counter=EvidenceCounter(), stage="triage_pack")
    inputs = PackInputs(
        sample_path=path,
        sha256="a" * 64,
        file_type=file_type,
        strings_head=10,
        capa=CapaSettings(rules_dir="", signatures_dir="", timeout_s=1),
    )
    return run_pack(recorder, inputs)


class TestThePackRunsThem:
    def test_a_pe_gets_both_after_every_other_step(self, tmp_path: Path) -> None:
        result = _pack(_sample(tmp_path))
        tools = [entry.tool for entry in result.entries]
        assert tools[-2:] == ["resolve_api_hashes", "decode_string_blobs"]
        hashes, blobs = result.entries[-2:]
        assert hashes.ok and blobs.ok
        assert hashes.structured["total"] == 2
        assert blobs.structured["results"][0]["text"] == "open the settings file"

    def test_a_file_that_is_not_routed_as_a_pe_does_not(self, tmp_path: Path) -> None:
        target = tmp_path / "a.txt"
        target.write_text("plain text\n", encoding="utf-8")
        tools = [entry.tool for entry in _pack(str(target), "text").entries]
        assert "resolve_api_hashes" not in tools and "decode_string_blobs" not in tools


class TestAnImageWithoutAFunctionTable:
    def test_capa_s_function_starts_are_handed_to_both_steps(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.tools import rules

        image = SyntheticPE(is64=False, image_base=0x400000)
        for offset, name in ((0x140, b"VirtualAlloc"), (0x160, b"CreateFileW")):
            image.put("text", offset, b"\x3d" + struct.pack("<I", zlib.crc32(name)))
        target = tmp_path / "s.exe"
        target.write_bytes(image.build())
        monkeypatch.setattr(
            rules,
            "capa",
            lambda path, **_: {"capabilities": [], "meta": {}, "function_starts": ["0x1100"]},
        )
        result = _pack(str(target))
        hashes = next(e for e in result.entries if e.tool == "resolve_api_hashes")
        assert hashes.args["function_starts"] == "capa's 1 function starts"
        assert hashes.structured["function_table"].startswith("capa, 1 function starts")
        places = [p for row in hashes.structured["hits"] for p in row["occurrences"]]
        assert {p["function"] for p in places} == {hex(TEXT_RVA + 0x100)}


def _entry(tool: str, payload: dict[str, Any], seq: int) -> Any:
    return build_entry(
        entry_id=format_entry_id(seq),
        seq=seq,
        agent=PIPELINE,
        tool=tool,
        args={},
        server=PIPELINE,
        output=json.dumps(payload),
        ok=True,
        stage="triage_pack",
    )


def _lines(tmp_path: Path, room: int = 0) -> tuple[str, str]:
    result = _pack(_sample(tmp_path))
    block = pack_block(pack_entries(result.entries), room)
    hashes = next(line for line in block.splitlines() if "] resolved hashes:" in line)
    blobs = next(line for line in block.splitlines() if "] decoded blobs:" in line)
    return hashes, blobs


class TestTheLines:
    def test_each_value_is_named_where_it_stands(self, tmp_path: Path) -> None:
        hashes, _ = _lines(tmp_path)
        value = f"{zlib.crc32(b'VirtualAlloc'):#010x}"
        assert f"{value} = kernel32.dll/kernelbase.dll!VirtualAlloc [poly_edb88320_ascii]" in hashes
        assert f"@ {hex(TEXT_RVA + 0x41)} (in {hex(TEXT_RVA)})" in hashes
        assert "all 2 shown" in hashes

    def test_each_decoded_text_names_its_scheme_and_who_refers_to_it(self, tmp_path: Path) -> None:
        _, blobs = _lines(tmp_path)
        assert f'"open the settings file"@{hex(DATA_RVA + 0x80)} [xor8 key 0x9c]' in blobs
        assert f"referred to at {hex(TEXT_RVA + 0x123)} (in {hex(FUNCTION)})" in blobs
        assert triage_pack.DECODED_BLOBS_PROVENANCE in blobs
        assert triage_pack.DECODED_BLOBS_RECALL in blobs
        assert "not the platform's findings" not in blobs, "these are the platform's decodings"

    def test_a_pack_out_of_room_says_how_many_it_shows_and_where_the_rest_are(self) -> None:
        hits = [
            {
                "value": f"{index:#010x}",
                "readings": [{"algorithm": "a", "name": f"Name{index}", "dlls": ["x.dll"]}],
                "occurrences": [{"rva": hex(0x1000 + index), "function": None}],
            }
            for index in range(40)
        ]
        payload = {"hits": hits, "total": 40, "candidates": {"scanned": 100}, "algorithms": ["a"]}
        whole = triage_pack._resolved_hashes(payload)
        assert "all 40 shown" in whole
        cut = triage_pack._resolved_hashes(payload, max_chars=len(whole) // 2)
        assert cut and len(cut) <= len(whole) // 2
        assert "one resolve_api_hashes call away at offset" in cut

        rows = [
            {
                "text": f"text number {index}",
                "rva": hex(0x3000 + index),
                "scheme": "xor8",
                "parameters": {"key": "0x9c"},
                "references": [],
            }
            for index in range(40)
        ]
        payload = {"results": rows, "total": 40, "unreferenced": 3}
        whole = triage_pack._decoded_blobs(payload)
        cut = triage_pack._decoded_blobs(payload, max_chars=len(whole) // 2)
        assert "one decode_string_blobs call away at offset" in cut
        assert "3 more decodings no code refers to" in cut

    def test_lone_hits_become_a_count_before_any_hit_is_cut(self) -> None:
        def row(index: int) -> dict[str, Any]:
            return {
                "value": f"{index:#010x}",
                "readings": [{"algorithm": "a", "name": f"Name{index}", "dlls": ["x.dll"]}],
                "occurrences": [{"rva": hex(0x1000 + index), "function": None}],
            }

        payload = {
            "hits": [row(1), row(2)],
            "lone_hits": [row(100 + index) for index in range(300)],
            "total": 2,
            "candidates": {"scanned": 9},
            "algorithms": ["a"],
        }
        whole = triage_pack._resolved_hashes(payload)
        room = len(whole) // 10
        cut = triage_pack._resolved_hashes(payload, max_chars=room)
        assert cut, "the line is not dropped for its lone hits"
        assert "all 2 shown" in cut and "Name1" in cut and "Name2" in cut
        assert "300 more resolve" in cut
        assert triage_pack.LONE_HITS_ROOM_SENTENCE in cut
        assert triage_pack._resolved_hashes({**payload, "hits": [], "total": 0}, max_chars=room)

    def test_nothing_decoded_still_says_what_the_schemes_cannot_see(self) -> None:
        line = triage_pack._decoded_blobs({"results": [], "total": 0})
        assert triage_pack.DECODED_BLOBS_RECALL in line

    def test_a_module_name_reads_as_one(self) -> None:
        row = {
            "value": "0x00000001",
            "readings": [
                {"algorithm": "a", "set": "modules", "name": "one.dll", "dlls": []},
                {"algorithm": "b", "set": "exports", "name": "Two", "dlls": ["x.dll"]},
            ],
            "occurrences": [],
        }
        assert triage_pack._hash_item(row) == "0x00000001 = module one.dll [a] | x.dll!Two [b]"

    def test_nothing_found_is_said_in_a_line_of_its_own(self) -> None:
        assert triage_pack._resolved_hashes(
            {"hits": [], "total": 0, "candidates": {"scanned": 9}}
        ).startswith("no value the file holds names a Windows function or module")
        assert triage_pack._decoded_blobs({"results": [], "total": 0}).startswith(
            "no encoded text found"
        )


class TestTheReverser:
    def test_the_brief_carries_both_lines(self, tmp_path: Path) -> None:
        from maljan.pipeline.nodes import brief_agent

        class _Agent:
            pass

        class _Container:
            class config:  # noqa: N801
                class reporting:  # noqa: N801
                    upstream_findings_max_chars = 1_000_000

        result = _pack(_sample(tmp_path))
        agent = _Agent()
        state = {"evidence_ledger": [entry.model_dump(mode="json") for entry in result.entries]}
        brief_agent(agent, state, _Container())  # type: ignore[arg-type]
        assert "!VirtualAlloc [poly_edb88320_ascii]" in agent.facts_block
        assert '"open the settings file"@' in agent.facts_block

    def test_it_is_told_to_name_the_function_and_the_text(self) -> None:
        assert "resolved to function names" in REVERSER_PROMPT
        assert "name the function and the\ntext in your finding" in REVERSER_PROMPT

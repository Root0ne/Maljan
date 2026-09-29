"""The pack runs the deobfuscation passes on every run and states each result, or why there is none.

Two passes come after every step the pack had before them, so each earlier id
is the id it was: the platform's scan for published constants of ciphers,
hash functions and checksums (``find_crypto_constants``) and Ghidra's
anti-analysis scan. A pass that cannot run is one entry that says ``no:`` and
why, never a missing line, and a pass that runs and finds nothing says so in
one line. Their lines take room from no earlier line at any budget.
"""

from __future__ import annotations

import json
import re
import struct
from pathlib import Path
from typing import Any

import httpx
import pytest

from maljan.agents.evidence_recorder import EvidenceRecorder
from maljan.analysis.ghidra_passes import ANTI_ANALYSIS_TOOL, GhidraPasses
from maljan.pipeline import triage_pack
from maljan.pipeline.triage_pack import (
    PIPELINE,
    CapaSettings,
    PackInputs,
    pack_block,
    pack_entries,
    render_pack,
    run_pack,
)
from maljan.schemas.evidence import EvidenceCounter, build_entry, format_entry_id
from maljan.tools import crypto_constants, rules

from ..fake_ghidra import X64_BASE, FakeGhidra
from ..tools.synthetic_pe import TEXT_RVA, SyntheticPE

NEW = ("find_crypto_constants", ANTI_ANALYSIS_TOOL)
ROUTINE = TEXT_RVA + 0x200


def _set(identifier: str) -> crypto_constants.ConstantSet:
    return {e.id: e for e in crypto_constants.catalogue()}[identifier]


@pytest.fixture(autouse=True)
def _capa_with_a_checksum_routine(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        rules,
        "capa",
        lambda path, **_: {
            "capabilities": [
                {
                    "namespace": "data-manipulation/checksum/crc32",
                    "rule": "hash data with CRC32",
                    "attck": [],
                    "mbc": [],
                    "addresses": [hex(ROUTINE)],
                }
            ],
            "function_starts": [hex(TEXT_RVA), hex(ROUTINE)],
            "meta": {},
        },
    )


def _sample(tmp_path: Path, *, table: bool = True, polynomial: bool = False) -> str:
    image = SyntheticPE(
        image_base=X64_BASE,
        functions=[(TEXT_RVA, TEXT_RVA + 0x100), (ROUTINE, ROUTINE + 0x40)],
    )
    if table:
        image.put("data", 0x100, bytes(_set("aes_sbox").values))
    if polynomial:
        image.put("text", 0x210, b"\x35" + struct.pack("<I", 0xEDB88320))
    target = tmp_path / "s.exe"
    target.write_bytes(image.build())
    return str(target)


def _pack(path: str, file_type: str = "pe", ghidra: GhidraPasses | None = None) -> Any:
    recorder = EvidenceRecorder(PIPELINE, counter=EvidenceCounter(), stage="triage_pack")
    inputs = PackInputs(
        sample_path=path,
        sha256="a" * 64,
        file_type=file_type,
        strings_head=10,
        capa=CapaSettings(rules_dir="", signatures_dir="", timeout_s=1),
    )
    return run_pack(recorder, inputs, ghidra=ghidra)


def _fake_passes(fake: FakeGhidra) -> GhidraPasses:
    return GhidraPasses(
        base_url="http://ghidra.invalid",
        sample_path="/data/samples/.work/s.exe",
        transport=httpx.MockTransport(fake.handler),
    )


def _line(result: Any, tool: str) -> str:
    entry = next(e for e in result.entries if e.tool == tool)
    return next(
        line
        for line in pack_block(pack_entries(result.entries), 0).splitlines()
        if line.startswith(f"[{entry.id}]")
    )


class TestThePassesComeLast:
    def test_the_constant_scan_follows_every_earlier_step(self, tmp_path: Path) -> None:
        tools = [e.tool for e in _pack(_sample(tmp_path)).entries]
        assert tools[-1] == "find_crypto_constants"
        assert tools[-3:-1] == ["resolve_api_hashes", "decode_string_blobs"]

    def test_the_ids_before_the_passes_are_unchanged(self, tmp_path: Path) -> None:
        path = _sample(tmp_path)
        plain = _pack(path)
        with_ghidra = _pack(path, ghidra=_fake_passes(FakeGhidra()))
        before = [(e.id, e.tool) for e in plain.entries if e.tool not in NEW]
        assert [(e.id, e.tool) for e in with_ghidra.entries][: len(before)] == before

    def test_an_elf_is_scanned_for_constants_and_a_text_file_is_not(self, tmp_path: Path) -> None:
        elf = tmp_path / "a.elf"
        elf.write_bytes(b"\x7fELF\x02\x01\x01" + b"\0" * 57)
        assert "find_crypto_constants" in [e.tool for e in _pack(str(elf), "elf").entries]
        text = tmp_path / "a.txt"
        text.write_text("plain text\n", encoding="utf-8")
        assert "find_crypto_constants" not in [e.tool for e in _pack(str(text), "text").entries]


class TestTheConstantLine:
    def test_a_table_found_is_named_where_it_stands(self, tmp_path: Path) -> None:
        line = _line(_pack(_sample(tmp_path)), "find_crypto_constants")
        assert "crypto constants: 1 of " in line
        assert "AES forward substitution box [table] @ 0x3100" in line

    def test_none_found_is_one_short_no_line(self, tmp_path: Path) -> None:
        line = _line(_pack(_sample(tmp_path, table=False)), "find_crypto_constants")
        assert line.endswith(
            f"crypto constants: no: none of the {len(crypto_constants.catalogue())} published "
            "constant sets stands in the file"
        )

    def test_what_capa_states_in_the_same_function_is_said_to_agree(self, tmp_path: Path) -> None:
        result = _pack(_sample(tmp_path, table=False, polynomial=True))
        entry = next(e for e in result.entries if e.tool == "find_crypto_constants")
        row = entry.structured["found"][0]
        assert row["capa"] == [{"rule": "hash data with CRC32", "at": hex(ROUTINE)}]
        line = _line(result, "find_crypto_constants")
        assert (
            "CRC-32 generator polynomial, bit-reversed: agrees with capa at "
            f"{hex(ROUTINE)} (hash data with CRC32)"
        ) in line
        assert "0xedb88320" not in line

    def test_the_scan_is_given_capa_s_function_starts(self, tmp_path: Path) -> None:
        result = _pack(_sample(tmp_path))
        entry = next(e for e in result.entries if e.tool == "find_crypto_constants")
        assert entry.args["function_starts"] == "capa's 2 function starts"


class TestGhidraUnavailable:
    def test_one_entry_says_no_and_why_and_the_run_is_not_degraded(self, tmp_path: Path) -> None:
        passes = GhidraPasses(unavailable="Ghidra is switched off (core.static.ghidra.enabled)")
        result = _pack(_sample(tmp_path), ghidra=passes)
        ghidra = [e for e in result.entries if e.tool == ANTI_ANALYSIS_TOOL]
        assert len(ghidra) == 1 and ghidra[0].ok is False
        assert ghidra[0].error == "not run: Ghidra is switched off (core.static.ghidra.enabled)"
        assert _line(result, ANTI_ANALYSIS_TOOL).endswith(
            "anti-analysis (Ghidra): no: Ghidra is switched off (core.static.ghidra.enabled)"
        )
        assert result.failed == [] and result.degradation_reasons == []

    def test_no_emulation_entry_is_made(self, tmp_path: Path) -> None:
        result = _pack(_sample(tmp_path), ghidra=_fake_passes(FakeGhidra()))
        assert "emulate_api_hashes" not in [e.tool for e in result.entries]


class TestGhidraAnswers:
    def test_the_exact_part_is_stated_with_its_id(self, tmp_path: Path) -> None:
        fake = FakeGhidra(
            findings=[
                {
                    "category": "suspicious_instruction",
                    "technique": "INT 0x2d",
                    "address": "140001010",
                    "function": "F",
                    "instruction": "INT 0x2d",
                },
                {
                    "category": "suspicious_instruction",
                    "technique": "INT 0x2d",
                    "address": "140001020",
                    "function": "F",
                    "instruction": "INT3",
                },
                {
                    "category": "debugger_detection",
                    "technique": "CloseHandle",
                    "address": "140001030",
                    "function": "F",
                },
            ]
        )
        result = _pack(_sample(tmp_path), ghidra=_fake_passes(fake))
        entry = next(e for e in result.entries if e.tool == ANTI_ANALYSIS_TOOL)
        assert entry.ok and entry.server == PIPELINE
        line = _line(result, ANTI_ANALYSIS_TOOL)
        assert "suspicious_instruction: INT 0x2d @ 0x1010 (in F)" in line
        assert "0x1020" not in line and "CloseHandle" not in line
        assert "2 more of its matches are not stated" in line

    def test_a_match_in_a_function_capa_names_for_anti_analysis_is_marked(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            rules,
            "capa",
            lambda path, **_: {
                "capabilities": [
                    {
                        "namespace": "anti-analysis/anti-debugging/debugger-detection",
                        "rule": "check for time delay via RDTSC",
                        "addresses": [hex(TEXT_RVA + 0x8)],
                    }
                ],
                "function_starts": [hex(TEXT_RVA), hex(ROUTINE)],
                "meta": {},
            },
        )
        fake = FakeGhidra(
            findings=[
                {
                    "category": "suspicious_instruction",
                    "technique": "RDTSC",
                    "address": "140001010",
                    "function": "F",
                    "instruction": "RDTSC",
                },
                {
                    "category": "suspicious_instruction",
                    "technique": "SIDT",
                    "address": "140001210",
                    "function": "G",
                    "instruction": "SIDT [EAX]",
                },
            ]
        )
        result = _pack(_sample(tmp_path), ghidra=_fake_passes(fake))
        entry = next(e for e in result.entries if e.tool == ANTI_ANALYSIS_TOOL)
        by_what = {row["what"]: row for row in entry.structured["stated"]}
        assert by_what["RDTSC"]["capa"][0]["rule"] == "check for time delay via RDTSC"
        assert "capa" not in by_what["SIDT [EAX]"]
        view = triage_pack._novel_view(entry)
        assert view is not None
        assert [row["what"] for row in view.structured["stated"]] == ["SIDT [EAX]"]
        assert view.structured["also_stated"] == 1

    def test_a_scan_that_matched_nothing_says_what_it_checks(self, tmp_path: Path) -> None:
        result = _pack(_sample(tmp_path), ghidra=_fake_passes(FakeGhidra()))
        line = _line(result, ANTI_ANALYSIS_TOOL)
        assert line.endswith(
            "anti-analysis (Ghidra): no: Ghidra's scan (listed API calls, listed x86 "
            "instructions, FS:[0x30] and FS:[0x18]) matched nothing"
        )
        assert "found no anti-analysis technique" not in line

    def test_a_sample_ghidra_cannot_open_fails_with_ghidra_s_words(self, tmp_path: Path) -> None:
        fake = FakeGhidra(load={"error": "File not found: /data/samples/.work/s.exe"})
        result = _pack(_sample(tmp_path), ghidra=_fake_passes(fake))
        entry = next(e for e in result.entries if e.tool == ANTI_ANALYSIS_TOOL)
        assert entry.ok is False and "File not found" in entry.error
        assert ": no: the pass failed: Ghidra did not open the job's sample: File not found" in (
            _line(result, ANTI_ANALYSIS_TOOL)
        )
        assert triage_pack.failure_reason(ANTI_ANALYSIS_TOOL) in result.degradation_reasons


def _entry(seq: int, tool: str, payload: Any, ok: bool = True, error: str | None = None) -> Any:
    return build_entry(
        entry_id=format_entry_id(seq),
        seq=seq,
        agent=PIPELINE,
        tool=tool,
        args={},
        server=PIPELINE,
        output=payload if isinstance(payload, str) else json.dumps(payload),
        ok=ok,
        error=error,
        stage="triage_pack",
    )


def _synthetic_pack(novel: bool = False) -> list[Any]:
    """A pack whose earlier lines far exceed every budget, and the two pass entries after it.

    The constant set agrees with capa, a fact the pack already carries, unless
    ``novel``: then no capa rule names it and it is a fact of its own.
    """
    hits = [
        {
            "value": f"{index:#010x}",
            "readings": [
                {"algorithm": "a", "set": "exports", "name": f"Name{index}", "dlls": ["x"]}
            ],
            "occurrences": [{"rva": hex(0x1000 + index), "function": "0x1000"}],
        }
        for index in range(400)
    ]
    blobs = [
        {
            "text": f"a decoded text number {index} " * 3,
            "rva": hex(0x3000 + index),
            "scheme": "xor8",
            "parameters": {"key": "0x9c"},
            "references": [{"at": hex(0x1100 + index), "function": "0x1100"}],
        }
        for index in range(400)
    ]
    capa = [
        {"rule": f"rule {index}", "addresses": [hex(0x1000 + a) for a in range(12)]}
        for index in range(60)
    ]
    earlier = [
        _entry(1, "identify_file", {"file_type": "pe", "platform": "windows", "size": 1}),
        _entry(2, "capa", {"capabilities": capa}),
        _entry(3, "strings", {"strings": [f"string {i}" for i in range(500)], "total": 500}),
        _entry(4, "resolve_api_hashes", {"hits": hits, "total": 400, "candidates": {"scanned": 9}}),
        _entry(5, "decode_string_blobs", {"results": blobs, "total": 400}),
    ]
    place = {"offset": "0x10", "rva": "0x1010", "function": "0x1000"}
    constants = {
        "found": [
            {
                "id": "aes_sbox",
                "algorithm": "AES",
                "what": "forward substitution box",
                "tables": [{"byte_order": "", "place": place}],
                **({} if novel else {"capa": [{"rule": "encrypt data using AES", "at": "0x1000"}]}),
            }
        ],
        "lone": [],
        "sets_searched": 26,
    }
    message = "not run: Ghidra is switched off (core.static.ghidra.enabled)"
    passes = [
        _entry(6, "find_crypto_constants", constants),
        _entry(7, ANTI_ANALYSIS_TOOL, message, ok=False, error=message),
    ]
    return earlier + passes


_TRAILER = re.compile(r"\A(\d+) more pack entr(?:y|ies) not shown here; ")


def _split(text: str) -> tuple[list[str], int]:
    lines = text.splitlines()
    said = _TRAILER.match(lines[-1]) if lines else None
    return (lines[:-1], int(said.group(1))) if said else (lines, 0)


def _ids(lines: list[str]) -> set[str]:
    return {line.split("]", 1)[0].lstrip("[") for line in lines}


class TestThePassLinesTakeNoRoomFromEarlierLines:
    @pytest.mark.parametrize("budget", [6_000, 18_432, 36_864])
    def test_restated_facts_leave_every_earlier_line_as_it_is(self, budget: int) -> None:
        entries = _synthetic_pack()
        earlier = [e for e in entries if e.tool not in NEW]
        without, left_without = _split(render_pack(earlier, budget))
        text = render_pack(entries, budget)
        lines, left = _split(text)
        assert len(render_pack(entries, 0)) > budget, "the pack does not fit whole"
        assert len(text) <= budget
        shown_passes = _ids(lines) & {"ev_0006", "ev_0007"}
        if len(shown_passes) == 2:
            assert lines[: len(without)] == without and left == left_without
        # Every entry is shown or counted, never left out unsaid.
        assert left == len(entries) - len(lines)

    def test_a_pass_entry_with_no_room_is_counted_in_the_trailer(self) -> None:
        entries = _synthetic_pack()
        earlier = [e for e in entries if e.tool not in NEW]
        budget = len(render_pack(earlier, 6_000))
        text = render_pack(entries, budget)
        lines, left = _split(text)
        assert len(text) <= budget
        assert left == len(entries) - len(lines)
        assert left >= 1, "a pass line had no room and is counted"

    def test_pass_lines_come_before_the_trailer(self) -> None:
        entries = _synthetic_pack()
        text = render_pack(entries, 36_864)
        lines = text.splitlines()
        assert not any(_TRAILER.match(line) for line in lines[:-1])

    def test_a_new_fact_is_fitted_with_the_earlier_lines(self) -> None:
        entries = _synthetic_pack(novel=True)
        for budget in (6_000, 18_432):
            text = render_pack(entries, budget)
            assert len(text) <= budget
            assert any(
                line.startswith("[ev_0006] crypto constants: 1 of 26") and "AES" in line
                for line in text.splitlines()
            ), budget

    def test_a_line_that_can_show_no_item_is_left_out(self) -> None:
        place = {"offset": "0x10", "rva": "0x1010", "function": "0x1000"}
        data = {
            "found": [{"algorithm": "AES", "what": "box", "tables": [{"place": place}]}],
            "sets_searched": 26,
        }
        assert triage_pack._constant_sets(data, max_chars=40) == ""
        stated = {"stated": [{"category": "c", "what": "RDTSC", "offset": "0x1"}]}
        assert triage_pack._anti_analysis(stated, max_chars=40) == ""


class TestTheNodeSaysWhichGhidra:
    def _step(self, state: dict[str, Any], **ghidra: Any) -> GhidraPasses:
        from maljan.core.config import Settings
        from maljan.core.container import ServiceContainer
        from maljan.pipeline.nodes import _ghidra_passes_step

        settings = Settings(_env_file=None, static={"ghidra": ghidra})
        container = ServiceContainer(settings, mock=True)
        return _ghidra_passes_step(container, state)  # type: ignore[arg-type]

    def test_switched_off(self) -> None:
        passes = self._step({}, enabled=False)
        assert passes.unavailable == "Ghidra is switched off (core.static.ghidra.enabled)"

    def test_over_stdio(self) -> None:
        passes = self._step({}, enabled=True, transport="stdio")
        assert passes.unavailable.startswith("Ghidra is reached over stdio")

    def test_with_no_copy_of_the_sample_for_it(self) -> None:
        passes = self._step({}, enabled=True, transport="http", url="http://ghidra.invalid:8089")
        assert "no copy of the sample" in passes.unavailable

    def test_reachable_with_its_copy(self) -> None:
        passes = self._step(
            {"static_sample_paths": {"ghidra": "/data/samples/.work/s.exe"}},
            enabled=True,
            transport="http",
            url="http://ghidra.invalid:8089",
        )
        assert passes.unavailable == ""
        assert passes.sample_path == "/data/samples/.work/s.exe"
        assert passes.base_url == "http://ghidra.invalid:8089"

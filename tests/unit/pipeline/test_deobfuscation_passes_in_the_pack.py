"""The pack runs the deobfuscation passes on every run and states each result, or why there is none.

Three passes come after every step the pack had before them, so each earlier
id is the id it was: the platform's scan for published constants of ciphers,
hash functions and checksums (``find_crypto_constants``), Ghidra's
anti-analysis scan and Ghidra's emulation of the sample's own hashing
routines. A pass that cannot run is an entry that says ``no:`` and why, never
a missing line, and a pass that runs and finds nothing says so in one line.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

import httpx
import pytest

from maljan.agents.evidence_recorder import EvidenceRecorder
from maljan.analysis.ghidra_passes import ANTI_ANALYSIS_TOOL, EMULATION_TOOL, GhidraPasses
from maljan.pipeline import events, triage_pack
from maljan.pipeline.triage_pack import (
    PIPELINE,
    CapaSettings,
    PackInputs,
    pack_block,
    pack_entries,
    run_pack,
)
from maljan.schemas.evidence import EvidenceCounter
from maljan.tools import crypto_constants, rules

from ..fake_ghidra import ROUTINE, X64_BASE, FakeGhidra, routine_output
from ..tools.synthetic_pe import TEXT_RVA, SyntheticPE

NEW = ("find_crypto_constants", ANTI_ANALYSIS_TOOL, EMULATION_TOOL)
BEFORE = ["resolve_api_hashes", "decode_string_blobs"]


@pytest.fixture(autouse=True)
def _capa_with_a_hashing_routine(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        rules,
        "capa",
        lambda path, **_: {
            "capabilities": [
                {
                    "namespace": "data-manipulation/hashing/custom",
                    "rule": "hash data using a rotation",
                    "attck": [],
                    "mbc": [],
                    "addresses": [hex(ROUTINE)],
                }
            ],
            "function_starts": [hex(TEXT_RVA), hex(ROUTINE)],
            "meta": {},
        },
    )


@pytest.fixture(autouse=True)
def _forget_names() -> Any:
    events.forget_resolved_names()
    yield
    events.forget_resolved_names()


def _sample(tmp_path: Path, *, table: bool = True) -> str:
    image = SyntheticPE(
        image_base=X64_BASE,
        functions=[(TEXT_RVA, TEXT_RVA + 0x100), (ROUTINE, ROUTINE + 0x40)],
    )
    for index, name in enumerate((b"VirtualAlloc", b"CreateFileW")):
        image.put("text", 0x20 + 0x10 * index, b"\x68" + struct.pack("<I", routine_output(name)))
    if table:
        sbox = {e.id: e for e in crypto_constants.catalogue()}["aes_sbox"].values
        image.put("data", 0x100, bytes(sbox))
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


def _fake_passes(fake: FakeGhidra, tmp_path: Path) -> GhidraPasses:
    names = tmp_path / "names.json"
    names.write_text(
        '{"dlls": {"kernel32.dll": ["VirtualAlloc", "CreateFileW", "GetTickCount"]},'
        ' "modules": {"names": ["kernel32.dll"]}}',
        encoding="utf-8",
    )
    passes = GhidraPasses(
        base_url="http://ghidra.invalid",
        sample_path="/data/samples/.work/s.exe",
        transport=httpx.MockTransport(fake.handler),
    )
    passes.names_path = str(names)
    return passes


def _line(result: Any, tool: str) -> str:
    entry = next(e for e in result.entries if e.tool == tool)
    return next(
        line
        for line in pack_block(pack_entries(result.entries), 0).splitlines()
        if line.startswith(f"[{entry.id}]")
    )


class TestThePassesComeLast:
    def test_the_constant_scan_follows_every_earlier_step(self, tmp_path: Path) -> None:
        result = _pack(_sample(tmp_path))
        tools = [e.tool for e in result.entries]
        assert tools[-1] == "find_crypto_constants"
        earlier = [tool for tool in tools if tool not in NEW]
        assert earlier[-3:] == [*BEFORE, "api_capability"] or earlier[-2:] == BEFORE
        assert tools.index("find_crypto_constants") > max(tools.index(t) for t in earlier)

    def test_the_ids_before_the_passes_are_unchanged(self, tmp_path: Path) -> None:
        path = _sample(tmp_path)
        plain = _pack(path)
        with_ghidra = _pack(path, ghidra=_fake_passes(FakeGhidra(), tmp_path))
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
        assert "crypto constants:" in line
        assert "AES forward substitution box [table] @ 0x3100" in line

    def test_none_found_is_one_no_line(self, tmp_path: Path) -> None:
        line = _line(_pack(_sample(tmp_path, table=False)), "find_crypto_constants")
        assert "crypto constants: no: none of the" in line


class TestALineOutOfRoom:
    def _place(self, index: int) -> dict[str, Any]:
        return {"offset": hex(index), "rva": hex(0x1000 + index), "function": None}

    def test_each_pass_line_says_how_many_it_shows_and_where_the_rest_are(self) -> None:
        constants = {
            "found": [
                {"algorithm": f"A{i}", "what": "w", "tables": [{"place": self._place(i)}]}
                for i in range(30)
            ],
            "lone": [
                {
                    "algorithm": "L",
                    "what": "v",
                    "matched": 1,
                    "of": 4,
                    "values": [{"value": "0x1", "places": [self._place(i)]}],
                }
                for i in range(30)
            ],
            "sets_searched": 99,
        }
        findings = {
            "findings": [
                {"category": "c", "technique": f"T{i}", "offset": hex(i)} for i in range(30)
            ],
            "total_findings": 30,
        }
        hits = {
            "hits": [
                {
                    "value": f"{i:#010x}",
                    "readings": [{"routine": "0x1", "set": "exports", "name": f"N{i}"}],
                    "occurrences": [self._place(i)],
                }
                for i in range(30)
            ],
            "lone_hits": [
                {"value": f"{i:#010x}", "readings": [], "occurrences": [self._place(i)]}
                for i in range(100, 130)
            ],
            "routines": [{"start": "0x1", "capa_rules": ["r"], "reason": "x"}],
            "names": {"functions": 2, "modules": 1},
        }
        for render, data, lone in (
            (triage_pack._constant_sets, constants, "listed under lone in this entry"),
            (triage_pack._anti_analysis, findings, None),
            (triage_pack._emulated, hits, "listed under lone_hits in this entry"),
        ):
            whole = render(data)
            assert "all 30 shown" in whole
            cut = render(data, max_chars=len(whole) // 2)
            assert cut and len(cut) <= len(whole) // 2
            assert "the rest are in this entry's full output" in cut
            if lone:
                assert lone in cut


class TestGhidraUnavailable:
    def test_each_pass_says_no_and_why_and_the_run_is_not_degraded(self, tmp_path: Path) -> None:
        passes = GhidraPasses(unavailable="Ghidra is switched off (core.static.ghidra.enabled)")
        result = _pack(_sample(tmp_path), ghidra=passes)
        for tool in (ANTI_ANALYSIS_TOOL, EMULATION_TOOL):
            entry = next(e for e in result.entries if e.tool == tool)
            assert entry.ok is False
            assert entry.error.startswith("not run: Ghidra is switched off")
            assert ": no: Ghidra is switched off (core.static.ghidra.enabled)" in _line(
                result, tool
            )
        assert result.failed == []
        assert result.degradation_reasons == []

    def test_an_elf_gets_no_emulation_entry(self, tmp_path: Path) -> None:
        elf = tmp_path / "a.elf"
        elf.write_bytes(b"\x7fELF\x02\x01\x01" + b"\0" * 57)
        tools = [e.tool for e in _pack(str(elf), "elf", GhidraPasses(unavailable="x")).entries]
        assert ANTI_ANALYSIS_TOOL in tools and EMULATION_TOOL not in tools


class TestGhidraAnswers:
    def test_both_passes_are_facts_with_their_ids(self, tmp_path: Path) -> None:
        fake = FakeGhidra(
            findings=[{"category": "c", "technique": "Q", "address": "140001010", "function": "F"}]
        )
        result = _pack(_sample(tmp_path), ghidra=_fake_passes(fake, tmp_path))
        anti = next(e for e in result.entries if e.tool == ANTI_ANALYSIS_TOOL)
        emulated = next(e for e in result.entries if e.tool == EMULATION_TOOL)
        assert anti.ok and emulated.ok
        assert [e.tool for e in result.entries][-2:] == [ANTI_ANALYSIS_TOOL, EMULATION_TOOL]
        assert anti.server == PIPELINE and emulated.server == PIPELINE

        line = _line(result, ANTI_ANALYSIS_TOOL)
        assert "anti-analysis (Ghidra):" in line and "c: Q @ 0x1010 (in F)" in line
        line = _line(result, EMULATION_TOOL)
        value = f"{routine_output(b'VirtualAlloc'):#010x}"
        assert f"{value} = kernel32.dll!VirtualAlloc [routine {hex(ROUTINE)}]" in line
        assert "hash data using a rotation" in line

    def test_the_names_the_emulation_read_are_kept_readable(self, tmp_path: Path) -> None:
        _pack(_sample(tmp_path), ghidra=_fake_passes(FakeGhidra(), tmp_path))
        assert "VirtualAlloc" in events._RESOLVED_NAMES
        assert "CreateFileW" in events._RESOLVED_NAMES

    def test_a_sample_ghidra_cannot_open_fails_both_passes(self, tmp_path: Path) -> None:
        fake = FakeGhidra(load={"error": "File not found: /data/samples/.work/s.exe"})
        result = _pack(_sample(tmp_path), ghidra=_fake_passes(fake, tmp_path))
        for tool in (ANTI_ANALYSIS_TOOL, EMULATION_TOOL):
            entry = next(e for e in result.entries if e.tool == tool)
            assert entry.ok is False and "File not found" in entry.error
            assert ": no: the pass failed: " in _line(result, tool)
        assert triage_pack.failure_reason(ANTI_ANALYSIS_TOOL) in result.degradation_reasons

    def test_no_hashing_routine_is_a_no_line_and_no_emulation(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            rules, "capa", lambda path, **_: {"capabilities": [], "function_starts": [], "meta": {}}
        )
        fake = FakeGhidra()
        result = _pack(_sample(tmp_path), ghidra=_fake_passes(fake, tmp_path))
        entry = next(e for e in result.entries if e.tool == EMULATION_TOOL)
        assert entry.ok is False and entry.error.startswith("not run: capa matched no rule")
        assert fake.emulations == 0
        assert EMULATION_TOOL not in result.failed
        assert ": no: capa matched no rule" in _line(result, EMULATION_TOOL)

    def test_nothing_found_by_either_pass_is_one_no_line_each(self, tmp_path: Path) -> None:
        image = SyntheticPE(
            image_base=X64_BASE,
            functions=[(TEXT_RVA, TEXT_RVA + 0x100), (ROUTINE, ROUTINE + 0x40)],
        )
        target = tmp_path / "plain.exe"
        target.write_bytes(image.build())
        result = _pack(str(target), ghidra=_fake_passes(FakeGhidra(), tmp_path))
        assert _line(result, ANTI_ANALYSIS_TOOL).endswith(
            "anti-analysis (Ghidra): no: Ghidra's scan found no anti-analysis technique"
        )
        assert ": no: no value the file holds equals" in _line(result, EMULATION_TOOL)


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

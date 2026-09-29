"""The Ghidra passes the triage pack makes once per job, against a Ghidra that answers in-process.

The fake speaks the REST endpoints the passes use, with the shapes the Ghidra
server answers in: a load, a switch, an analysis, the program's image base,
the anti-analysis scan, and an emulation that runs a routine of the test's own
(a rotate-and-add over the name's bytes, a scheme none of the platform's
published algorithms is) when it is asked at the routine's address with the
name's address where the test's convention puts it.
"""

from __future__ import annotations

import json
import struct
from pathlib import Path

import httpx
import pytest
from tests.unit.fake_ghidra import (
    ROUTINE,
    X64_BASE,
    X86_BASE,
    FakeGhidra,
    routine_output,
)
from tests.unit.tools.synthetic_pe import TEXT_RVA, SyntheticPE

from maljan.analysis.ghidra_passes import (
    ANTI_ANALYSIS_TOOL,
    CONVENTION_RULE,
    EMULATION_TOOL,
    ROUTINE_RULE,
    GhidraPasses,
    GhidraPassFailed,
    Routine,
    hash_routines,
)


def _passes(fake: FakeGhidra) -> GhidraPasses:
    return GhidraPasses(
        base_url="http://ghidra.invalid",
        token="t",
        sample_path="/data/samples/.work/s.exe",
        transport=httpx.MockTransport(fake.handler),
    )


def _names(tmp_path: Path) -> str:
    target = tmp_path / "names.json"
    target.write_text(
        json.dumps(
            {
                "dlls": {
                    "kernel32.dll": ["VirtualAlloc", "CreateFileW", "GetTickCount"],
                    "user32.dll": ["MessageBoxW"],
                },
                "modules": {"names": ["kernel32.dll"]},
            }
        ),
        encoding="utf-8",
    )
    return str(target)


def _sample(tmp_path: Path, *, is64: bool = True, values: tuple[bytes, ...] = ()) -> str:
    base = X64_BASE if is64 else X86_BASE
    functions = [(TEXT_RVA, TEXT_RVA + 0x100), (ROUTINE, ROUTINE + 0x40)] if is64 else []
    image = SyntheticPE(is64=is64, image_base=base, functions=functions)
    for index, name in enumerate(values):
        image.put("text", 0x20 + 0x10 * index, b"\x68" + struct.pack("<I", routine_output(name)))
    target = tmp_path / "s.exe"
    target.write_bytes(image.build())
    return str(target)


class TestTheRoutinesComeFromCapa:
    def test_a_hashing_or_checksum_rule_names_its_function(self) -> None:
        rows = [
            {
                "namespace": "data-manipulation/hashing/djb2",
                "rule": "hash data using djb2",
                "addresses": ["0x1200"],
            },
            {
                "namespace": "data-manipulation/checksum/crc32",
                "rule": "checksum rule",
                "addresses": ["0x1234"],
            },
            {"namespace": "host-interaction/process", "rule": "other", "addresses": ["0x1300"]},
        ]
        routines, why = hash_routines(rows, ["0x1000", "0x1200"])
        assert why == ""
        assert routines == [Routine(0x1200, ("hash data using djb2", "checksum rule"))]

    def test_no_such_rule_says_so(self) -> None:
        routines, why = hash_routines(
            [{"namespace": "host-interaction", "rule": "x", "addresses": ["0x1"]}], []
        )
        assert routines == [] and "matched no rule" in why

    def test_a_match_with_no_start_before_it_says_so(self) -> None:
        rows = [{"namespace": "data-manipulation/hashing", "rule": "r", "addresses": ["0x10"]}]
        routines, why = hash_routines(rows, ["0x1000"])
        assert routines == [] and "no address with a function start" in why


class TestTheEmulation:
    def test_the_values_the_routine_returns_for_two_names_are_hits(self, tmp_path: Path) -> None:
        fake = FakeGhidra()
        path = _sample(tmp_path, values=(b"VirtualAlloc", b"CreateFileW"))
        answer = _passes(fake).emulate_api_hashes(
            path, [Routine(ROUTINE, ("hash data using djb2",))], names_path=_names(tmp_path)
        )

        assert answer["tool"] == EMULATION_TOOL
        assert answer["how"] == ROUTINE_RULE and answer["conventions"] == CONVENTION_RULE
        assert [row["readings"][0]["name"] for row in answer["hits"]] == [
            "VirtualAlloc",
            "CreateFileW",
        ]
        reading = answer["hits"][0]["readings"][0]
        assert reading == {
            "routine": hex(ROUTINE),
            "set": "exports",
            "name": "VirtualAlloc",
            "encoding": "ascii",
            "dlls": ["kernel32.dll"],
        }
        place = answer["hits"][0]["occurrences"][0]
        assert (place["rva"], place["function"]) == (hex(TEXT_RVA + 0x21), hex(TEXT_RVA))
        routine = answer["routines"][0]
        assert routine["convention"] == "rcx" and routine["address"] == hex(X64_BASE + ROUTINE)
        # Four function names and one module name in two encodings, all emulated.
        assert (routine["names_emulated"], routine["names_returned"]) == (6, 6)
        assert answer["lone_hits"] == [] and answer["total"] == 2

    def test_one_value_alone_is_a_lone_hit(self, tmp_path: Path) -> None:
        path = _sample(tmp_path, values=(b"MessageBoxW",))
        answer = _passes(FakeGhidra()).emulate_api_hashes(
            path, [Routine(ROUTINE, ("r",))], names_path=_names(tmp_path)
        )
        assert answer["hits"] == []
        assert answer["lone_hits"][0]["readings"][0]["name"] == "MessageBoxW"

    def test_an_x86_routine_takes_the_name_on_the_stack(self, tmp_path: Path) -> None:
        fake = FakeGhidra(image_base=X86_BASE, convention="stack")
        path = _sample(tmp_path, is64=False, values=(b"VirtualAlloc", b"GetTickCount"))
        answer = _passes(fake).emulate_api_hashes(
            path, [Routine(ROUTINE, ("r",))], names_path=_names(tmp_path)
        )
        assert answer["routines"][0]["convention"] == "stack argument 1"
        assert answer["total"] == 2

    def test_an_x86_routine_that_reads_ecx_is_tried_second(self, tmp_path: Path) -> None:
        fake = FakeGhidra(image_base=X86_BASE, convention="ecx")
        path = _sample(tmp_path, is64=False, values=(b"VirtualAlloc", b"GetTickCount"))
        answer = _passes(fake).emulate_api_hashes(
            path, [Routine(ROUTINE, ("r",))], names_path=_names(tmp_path)
        )
        assert answer["routines"][0]["conventions_tried"] == ["stack argument 1", "ecx"]
        assert answer["routines"][0]["convention"] == "ecx"

    def test_a_routine_whose_output_does_not_follow_the_name_is_not_used(
        self, tmp_path: Path
    ) -> None:
        fake = FakeGhidra(constant_output=True)
        path = _sample(tmp_path, values=(b"VirtualAlloc",))
        answer = _passes(fake).emulate_api_hashes(
            path, [Routine(ROUTINE, ("r",))], names_path=_names(tmp_path)
        )
        routine = answer["routines"][0]
        assert routine["convention"] is None and "two different values" in routine["reason"]
        assert answer["hits"] == [] and answer["lone_hits"] == []
        # Two probes, and nothing past them.
        assert fake.emulations == 2

    def test_a_request_ghidra_does_not_answer_stops_the_pass(self, tmp_path: Path) -> None:
        fake = FakeGhidra(stall_after=3)
        path = _sample(tmp_path, values=(b"VirtualAlloc",))
        with pytest.raises(GhidraPassFailed, match="did not answer the emulation"):
            _passes(fake).emulate_api_hashes(
                path, [Routine(ROUTINE, ("r",))], names_path=_names(tmp_path)
            )
        assert fake.emulations == 4

    def test_every_request_names_the_program_and_carries_the_key(self, tmp_path: Path) -> None:
        fake = FakeGhidra()
        path = _sample(tmp_path, values=(b"VirtualAlloc",))
        _passes(fake).emulate_api_hashes(
            path, [Routine(ROUTINE, ("r",))], names_path=_names(tmp_path)
        )
        emulations = [r for r in fake.requests if r.url.path == "/emulate_function"]
        assert emulations
        assert all(r.url.params.get("program") == "s.exe" for r in emulations)
        assert all(r.headers.get("authorization") == "Bearer t" for r in fake.requests)


class TestTheAntiAnalysisScan:
    def test_ghidra_s_findings_are_kept_with_their_offsets(self) -> None:
        findings = [
            {
                "category": "c",
                "technique": "T",
                "address": "140001234",
                "function": "FUN_1",
                "severity": "high",
            },
            {"note": "3 additional findings truncated"},
        ]
        answer = _passes(FakeGhidra(findings=findings)).anti_analysis()
        assert answer["tool"] == ANTI_ANALYSIS_TOOL
        assert answer["findings"] == [{**findings[0], "offset": "0x1234"}]
        assert answer["notes"] == ["3 additional findings truncated"]
        assert answer["image_base"] == hex(X64_BASE)

    def test_a_sample_ghidra_did_not_open_fails_both_passes_with_its_words(
        self, tmp_path: Path
    ) -> None:
        fake = FakeGhidra(load={"error": "File not found: /data/samples/.work/s.exe"})
        passes = _passes(fake)
        with pytest.raises(GhidraPassFailed, match="File not found"):
            passes.anti_analysis()
        asked = len(fake.requests)
        with pytest.raises(GhidraPassFailed, match="File not found"):
            passes.emulate_api_hashes(_sample(tmp_path), [Routine(ROUTINE, ("r",))])
        assert len(fake.requests) == asked

    def test_the_sample_is_opened_once_for_both_passes(self, tmp_path: Path) -> None:
        fake = FakeGhidra()
        passes = _passes(fake)
        passes.anti_analysis()
        passes.emulate_api_hashes(
            _sample(tmp_path), [Routine(ROUTINE, ("r",))], names_path=_names(tmp_path)
        )
        assert [r.url.path for r in fake.requests].count("/load_program") == 1
        assert [r.url.path for r in fake.requests].count("/run_analysis") == 1

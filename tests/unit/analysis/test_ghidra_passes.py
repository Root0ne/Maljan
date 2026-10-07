"""Ghidra's anti-analysis scan, made once per job, against a Ghidra that answers in-process.

The scan's answer is kept whole, as Ghidra gave it. What the pack states as a
fact is only the part that is exact: an instruction that is the one Ghidra's
list names (``INT3`` is not ``INT 0x2d``), a TEB/PEB read through the exact
``FS:[0x30]`` or ``FS:[0x18]`` operand. An API call, and every other match, is
counted, not stated.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from tests.unit.fake_ghidra import X64_BASE, FakeGhidra

from maljan.analysis.ghidra_passes import (
    ANTI_ANALYSIS_TOOL,
    SCAN_CHECKS,
    GhidraPasses,
    GhidraPassFailed,
    read_findings,
)


def _passes(fake: FakeGhidra) -> GhidraPasses:
    return GhidraPasses(
        base_url="http://ghidra.invalid",
        token="t",
        sample_path="/data/samples/.work/s.exe",
        transport=httpx.MockTransport(fake.handler),
    )


def _instruction(technique: str, text: str, address: str = "140001010") -> dict[str, Any]:
    return {
        "category": "suspicious_instruction",
        "technique": technique,
        "address": address,
        "offset": hex(int(address, 16) - X64_BASE),
        "function": "F",
        "instruction": text,
    }


def _call(category: str, technique: str, address: str = "140001020") -> dict[str, Any]:
    return {
        "category": category,
        "technique": technique,
        "address": address,
        "offset": hex(int(address, 16) - X64_BASE),
        "function": "G",
    }


def _image(code: dict[int, bytes], functions: list[tuple[int, int]] | None = None) -> Any:
    """A synthetic x64 image with ``code`` written at offsets into ``.text``."""
    from tests.unit.tools.synthetic_pe import TEXT_RVA, SyntheticPE

    from maljan.tools import pe_image

    image = SyntheticPE(image_base=X64_BASE, functions=functions or [(TEXT_RVA, TEXT_RVA + 0x300)])
    for offset, blob in code.items():
        image.put("text", offset, blob)
    return pe_image.parse(image.build())


class TestWhatIsStated:
    def test_an_instruction_is_stated_only_when_it_is_the_listed_one(self) -> None:
        image = _image({0x10: b"\x90\xcc\x90", 0x30: b"\xcd\x2d", 0x50: b"\x0f\x31"})
        read = read_findings(
            [
                _instruction("INT 3", "INT3", "140001011"),
                _instruction("INT 0x2d", "INT3", "140001011"),
                _instruction("INT 0x2d", "INT 0x2d", "140001030"),
                _instruction("STR", "STRD R0", "140001040"),
                _instruction("RDTSC", "RDTSC", "140001050"),
            ],
            image=image,
        )
        assert [(f["what"], f["offset"]) for f in read["stated"]] == [
            ("INT3", "0x1011"),
            ("INT 0x2d", "0x1030"),
            ("RDTSC", "0x1050"),
        ]
        assert read["not_stated"] == 1, "the INT3 filed again as INT 0x2d is the same place"

    def test_int3_padding_and_alignment_runs_are_not_stated(self) -> None:
        from tests.unit.tools.synthetic_pe import TEXT_RVA

        image = _image(
            {0x10: b"\xcc\xcc\xcc", 0x3F: b"\xcc"},
            functions=[(TEXT_RVA, TEXT_RVA + 0x3F), (TEXT_RVA + 0x40, TEXT_RVA + 0x80)],
        )
        read = read_findings(
            [
                _instruction("INT 3", "INT3", "140001011"),
                _instruction("INT 3", "INT3", "14000103f"),
            ],
            image=image,
        )
        assert read["stated"] == [] and read["not_stated"] == 2

    def test_an_int3_with_no_bytes_to_read_is_not_stated(self) -> None:
        read = read_findings([_instruction("INT 3", "INT3")])
        assert read["stated"] == [] and read["not_stated"] == 1

    def test_cpuid_is_stated_only_for_the_hypervisor_leaf_or_the_bit_it_tests(self) -> None:
        image = _image(
            {
                0x10: b"\xb8\x00\x00\x00\x40\x0f\xa2",
                0x30: b"\xb8\x01\x00\x00\x00\x31\xc9\x0f\xa2\x0f\xba\xe1\x1f",
                0x50: b"\xb8\x07\x00\x00\x00\x0f\xa2",
                0x70: b"\xb8\x01\x00\x00\x00\x0f\xa2\x89\xc8",
            }
        )
        read = read_findings(
            [
                _instruction("CPUID", "CPUID", "140001015"),
                _instruction("CPUID", "CPUID", "140001037"),
                _instruction("CPUID", "CPUID", "140001055"),
                _instruction("CPUID", "CPUID", "140001075"),
            ],
            image=image,
        )
        assert [(f["what"], f["offset"]) for f in read["stated"]] == [
            ("CPUID (leaf 0x40000000)", "0x1015"),
            ("CPUID (leaf 1, then ECX bit 31 tested)", "0x1037"),
        ]
        assert read["not_stated"] == 2

    def test_a_teb_read_is_stated_only_through_the_exact_operand(self) -> None:
        peb = {"category": "peb_teb_access", "technique": "Direct PEB/TEB access"}
        read = read_findings(
            [
                {**peb, "address": "140001060", "instruction": "MOV EAX,dword ptr FS:[0x30]"},
                {**peb, "address": "140001070", "instruction": "MOV EAX,dword ptr FS:[EAX + 0x30]"},
            ],
        )
        assert [f["what"] for f in read["stated"]] == ["MOV EAX,dword ptr FS:[0x30]"]
        assert read["not_stated"] == 1

    def test_an_api_call_is_counted_and_never_stated(self) -> None:
        read = read_findings(
            [
                _call("debugger_detection", "IsDebuggerPresent"),
                _call("debugger_detection", "CheckRemoteDebuggerPresent", "140001030"),
                _call("debugger_detection", "OutputDebugString", "140001040"),
                _call("debugger_detection", "CloseHandle", "140001080"),
                _call("vm_detection", "GetSystemFirmwareTable", "140001090"),
            ]
        )
        assert read["stated"] == []
        assert read["not_stated"] == 5

    def test_an_int3_right_after_a_call_jump_or_return_is_not_stated(self) -> None:
        """MSVC puts one ``int 3`` after a call that never returns, and pads after a return."""
        image = _image(
            {
                # mov ecx, 1; call [rip+disp32] (exit); int3; ret
                0x10: bytes.fromhex("b901000000ff1590ef0000cc c3cccc".replace(" ", "")),
                # mov ecx, eax; call rel32; int3; call rel32
                0x40: bytes.fromhex("8bc8e8e1290000cce8f7290000"),
                # call rax; int3
                0x60: bytes.fromhex("90ffd0cc90"),
                # call r8; int3
                0x70: bytes.fromhex("9041ffd0cc90"),
                # call [rsp]; int3
                0x80: bytes.fromhex("90ff1424cc90"),
                # call [rax+8]; int3
                0x90: bytes.fromhex("90ff5008cc90"),
                # nop; int3; nop: a lone trap, stated
                0xA0: bytes.fromhex("9090cc9090"),
                # ret; int3: one byte of padding after a function's return
                0xB0: bytes.fromhex("90c3cc4883"),
                # jmp rel32; int3: nothing falls through to it
                0xC0: bytes.fromhex("e978000000cc55"),
                # jmp rel8; int3
                0xD0: bytes.fromhex("90eb10cc55"),
                # ret 8; int3
                0xE0: bytes.fromhex("90c20800cc55"),
            }
        )
        read = read_findings(
            [
                _instruction("INT 3", "INT3", "14000101b"),
                _instruction("INT 3", "INT3", "140001047"),
                _instruction("INT 3", "INT3", "140001063"),
                _instruction("INT 3", "INT3", "140001074"),
                _instruction("INT 3", "INT3", "140001084"),
                _instruction("INT 3", "INT3", "140001094"),
                _instruction("INT 3", "INT3", "1400010a2"),
                _instruction("INT 3", "INT3", "1400010b2"),
                _instruction("INT 3", "INT3", "1400010c5"),
                _instruction("INT 3", "INT3", "1400010d3"),
                _instruction("INT 3", "INT3", "1400010e4"),
            ],
            image=image,
        )
        assert [(f["what"], f["offset"]) for f in read["stated"]] == [("INT3", "0x10a2")]
        assert read["not_stated"] == 10

    def test_a_cpuid_leaf_moved_into_r8d_or_an_ecx_written_before_the_test_is_not_stated(
        self,
    ) -> None:
        image = _image(
            {
                # mov r8d, 1; cpuid; bt ecx, 31
                0x10: bytes.fromhex("41b8010000000fa20fbae11f"),
                # mov eax, 1; cpuid; mov ecx, edx; bt ecx, 31
                0x30: bytes.fromhex("b8010000000fa289d10fbae11f"),
                # mov eax, 1; cpuid; bt ecx, 31; mov ecx, edx: the test reads CPUID's ECX
                0x50: bytes.fromhex("b8010000000fa20fbae11f89d1"),
            }
        )
        read = read_findings(
            [
                _instruction("CPUID", "CPUID", "140001016"),
                _instruction("CPUID", "CPUID", "140001035"),
                _instruction("CPUID", "CPUID", "140001055"),
            ],
            image=image,
        )
        assert [(f["what"], f["offset"]) for f in read["stated"]] == [
            ("CPUID (leaf 1, then ECX bit 31 tested)", "0x1055"),
        ]
        assert read["not_stated"] == 2

    def test_duplicate_rows_are_stated_and_counted_once(self) -> None:
        image = _image({0x10: b"\x0f\x31"})
        read = read_findings(
            [
                _instruction("RDTSC", "RDTSC"),
                _instruction("RDTSC", "RDTSC"),
                _call("debugger_detection", "CloseHandle"),
                _call("debugger_detection", "CloseHandle"),
            ],
            image=image,
        )
        assert len(read["stated"]) == 1
        assert read["not_stated"] == 1


class TestTheScan:
    def test_ghidra_s_answer_is_kept_and_the_exact_part_is_stated(self) -> None:
        findings = [
            {
                "category": "suspicious_instruction",
                "technique": "INT 0x2d",
                "address": "140001234",
                "function": "FUN_1",
                "instruction": "INT3",
            },
            {
                "category": "debugger_detection",
                "technique": "CloseHandle",
                "address": "140001240",
                "function": "FUN_1",
            },
            {"note": "3 additional findings truncated"},
        ]
        answer = _passes(FakeGhidra(findings=findings)).anti_analysis()
        assert answer["tool"] == ANTI_ANALYSIS_TOOL
        assert answer["checks"] == SCAN_CHECKS
        assert [f["offset"] for f in answer["findings"]] == ["0x1234", "0x1240"]
        assert answer["stated"] == []
        assert answer["not_stated"] == 2
        assert answer["notes"] == ["3 additional findings truncated"]

    def test_a_sample_ghidra_did_not_open_fails_with_ghidra_s_words(self) -> None:
        fake = FakeGhidra(load={"error": "File not found: /data/samples/.work/s.exe"})
        passes = _passes(fake)
        with pytest.raises(GhidraPassFailed, match="File not found"):
            passes.anti_analysis()
        asked = len(fake.requests)
        with pytest.raises(GhidraPassFailed, match="File not found"):
            passes.anti_analysis()
        assert len(fake.requests) == asked

    def test_every_request_carries_the_key_and_the_key_is_not_in_the_repr(self) -> None:
        fake = FakeGhidra()
        passes = _passes(fake)
        passes.anti_analysis()
        assert all(r.headers.get("authorization") == "Bearer t" for r in fake.requests)
        assert "'t'" not in repr(passes) and "token" not in repr(passes)

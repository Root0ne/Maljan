"""An x64 GS read is placed by the file's own function table, and read only where it is one.

The GS reads are read from the code bytes (``ghidra_passes.gs_reads``). Where
the file's ``.pdata`` holds the address, the read must be an instruction's
start in a decode from that range's start, and its agreement with capa is
asked about the function that range belongs to, not the nearest capa start
before it: a library function capa leaves out is not the user function in
front of it. A file whose machine field is not AMD64 is not read, and the same
file bytes mapped twice are one read.
"""

from __future__ import annotations

import struct
from dataclasses import replace
from typing import Any

from tests.unit.tools.synthetic_pe import TEXT_RVA, SyntheticPE

from maljan.analysis.ghidra_passes import gs_reads, read_findings
from maljan.pipeline import triage_pack
from maljan.tools import pe_image

GS_PEB = b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00"


def _built(code: dict[int, bytes], functions: list[tuple[int, int]]) -> SyntheticPE:
    pe = SyntheticPE(functions=functions)
    pe.text[:] = b"\x90" * len(pe.text)
    for offset, blob in code.items():
        pe.put("text", offset, blob)
    return pe


def _image(code: dict[int, bytes], functions: list[tuple[int, int]]) -> Any:
    return pe_image.parse(_built(code, functions).build())


def _places(rows: list[dict[str, Any]]) -> list[tuple[str, str | None]]:
    return [(row["offset"], row.get("owner")) for row in rows]


class TestTheOwner:
    def test_a_read_in_a_function_carries_the_function_its_range_belongs_to(self) -> None:
        image = _image({0x110: GS_PEB}, [(TEXT_RVA, TEXT_RVA + 0x100), (0x1100, 0x1200)])

        assert _places(gs_reads(image)) == [("0x1110", "0x1100")]

    def test_a_read_in_a_library_function_capa_left_out_does_not_agree_with_the_one_before(
        self,
    ) -> None:
        # capa knows the user function at 0x1000 and its PEB access; the read
        # at 0x1110 is in the next .pdata function, which capa left out.
        image = _image({0x110: GS_PEB}, [(TEXT_RVA, TEXT_RVA + 0x100), (0x1100, 0x1200)])
        answer = read_findings([], image=image)
        capa = [{"rule": "PEB access", "namespace": "", "addresses": ["0x1010"]}]

        marked = triage_pack._anti_analysis_with_capa(answer, capa, ["0x1000"])

        assert marked["stated"] == [] and marked["not_stated"] == 1

    def test_a_read_in_the_function_capa_names_agrees(self) -> None:
        image = _image({0x110: GS_PEB}, [(TEXT_RVA, TEXT_RVA + 0x100), (0x1100, 0x1200)])
        answer = read_findings([], image=image)
        capa = [{"rule": "PEB access", "namespace": "", "addresses": ["0x1110"]}]

        marked = triage_pack._anti_analysis_with_capa(answer, capa, ["0x1000", "0x1100"])

        assert [row["offset"] for row in marked["stated"]] == ["0x1110"]
        assert marked["stated"][0]["capa"] == [{"rule": "PEB access", "at": "0x1110"}]

    def test_outside_every_range_the_nearest_capa_start_is_asked_as_before(self) -> None:
        image = _image({0x310: GS_PEB}, [(TEXT_RVA, TEXT_RVA + 0x100)])
        answer = read_findings([], image=image)
        capa = [{"rule": "PEB access", "namespace": "", "addresses": ["0x1300"]}]

        assert _places(answer["beside_capa"]) == [("0x1310", None)]
        marked = triage_pack._anti_analysis_with_capa(answer, capa, ["0x1000", "0x1300"])
        assert [row["offset"] for row in marked["stated"]] == ["0x1310"]


class TestAnInstructionStart:
    def test_the_same_bytes_inside_another_instruction_are_no_read(self) -> None:
        # mov rax, imm64 whose immediate holds the GS read's bytes.
        inside = b"\x48\xb8" + GS_PEB[:8] + b"\x00"
        image = _image({0x10: inside, 0x20: GS_PEB}, [(TEXT_RVA, TEXT_RVA + 0x100)])

        assert _places(gs_reads(image)) == [("0x1020", "0x1000")]

    def test_outside_every_range_the_byte_match_alone_is_read(self) -> None:
        inside = b"\x48\xb8" + GS_PEB[:8] + b"\x00"
        image = _image({0x310: inside}, [(TEXT_RVA, TEXT_RVA + 0x100)])

        assert _places(gs_reads(image)) == [("0x1312", None)]


class TestTheFile:
    def test_a_pe32_plus_whose_machine_is_not_amd64_is_not_read(self) -> None:
        data = bytearray(_built({0x10: GS_PEB}, [(TEXT_RVA, TEXT_RVA + 0x100)]).build())
        (pe_offset,) = struct.unpack_from("<I", data, 0x3C)
        struct.pack_into("<H", data, pe_offset + 4, 0xAA64)  # ARM64

        image = pe_image.parse(bytes(data))

        assert image.is64 and gs_reads(image) == []

    def test_the_same_bytes_mapped_by_two_sections_are_one_read(self) -> None:
        image = _image({0x10: GS_PEB}, [])
        text = image.code_sections()[0]
        image.sections.append(replace(text, name=".alias", rva=0x9000))

        assert _places(gs_reads(image)) == [("0x1010", None)]

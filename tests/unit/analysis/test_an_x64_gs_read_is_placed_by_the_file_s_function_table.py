"""An x64 GS read is placed by the file's own function table, and said where it is no boundary.

The GS reads are read from the code bytes (``ghidra_passes.gs_reads``). Where
the file's ``.pdata`` holds the address, its agreement with capa is asked
about the function that range belongs to, not the nearest capa start before
it: a library function capa leaves out is not the user function in front of
it. A match no decode from a function start lands on is still a row and says
so, since a crafted table could otherwise hide a real read. Each byte of a
section is decoded once however many ranges overlap. A file whose machine
field is not AMD64 is not read, and the same file bytes mapped twice are one
read.
"""

from __future__ import annotations

import struct
from dataclasses import replace
from typing import Any

from tests.unit.tools.synthetic_pe import TEXT_RVA, SyntheticPE

from maljan.analysis.ghidra_passes import GS_OFF_BOUNDARY, gs_reads, read_findings
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
    def test_the_same_bytes_inside_another_instruction_are_a_row_that_says_so(self) -> None:
        # mov rax, imm64 whose immediate holds the GS read's bytes.
        inside = b"\x48\xb8" + GS_PEB[:8] + b"\x00"
        image = _image({0x10: inside, 0x20: GS_PEB}, [(TEXT_RVA, TEXT_RVA + 0x100)])

        rows = gs_reads(image)

        assert _places(rows) == [("0x1012", "0x1000"), ("0x1020", "0x1000")]
        assert rows[0]["what"].endswith(f", {GS_OFF_BOUNDARY}")
        assert rows[1]["what"] == "GS:[0x60] read (65 48 8b 04 25 60 00 00 00)"

    def test_a_range_shaped_to_miss_a_real_read_does_not_hide_it(self) -> None:
        # A range that starts on a B8 byte two before the read: mov eax, imm32
        # swallows the read's first bytes, and the decode never lands on it.
        image = _image({0x1E: b"\xb8", 0x20: GS_PEB}, [(TEXT_RVA + 0x1E, TEXT_RVA + 0x100)])

        rows = gs_reads(image)

        assert _places(rows) == [("0x1020", "0x101e")]
        assert rows[0]["what"].endswith(f", {GS_OFF_BOUNDARY}")

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


class TestTheCostIsLinear:
    """Timed at one size and ten times it: the larger at most ten times the smaller, with margin.

    The images are built as ``pe_image`` holds them, one code section and the
    function table's ranges, since a file laid out with a 50 MB code section
    says nothing more about the scan than its sections do.
    """

    @staticmethod
    def _seconds(call: Any) -> float:
        import time

        best = float("inf")
        for _ in range(2):
            started = time.perf_counter()
            call()
            best = min(best, time.perf_counter() - started)
        return best

    @staticmethod
    def _image(text: bytes, ranges: list[tuple[int, int]]) -> Any:
        section = pe_image.Section(".text", TEXT_RVA, len(text), 0, len(text), 0x60000020)
        ends = dict(ranges)
        starts = sorted(ends)
        return pe_image.Image(
            data=bytes(text),
            image_base=0x140000000,
            is64=True,
            size_of_image=TEXT_RVA + len(text),
            sections=[section],
            function_starts=starts,
            function_ends=[ends[start] for start in starts],
            function_owners=list(starts),
            machine=0x8664,
        )

    def _one_range_of_hits(self, hits: int) -> Any:
        """One range of ``hits`` reads back to back, the range padded to five times their size."""
        text = GS_PEB * hits
        text += b"\x90" * (len(text) * 4)
        return self._image(text, [(TEXT_RVA, TEXT_RVA + len(text))])

    def _overlapping_ranges(self, ranges: int) -> Any:
        """``ranges`` ranges, each a byte after the last, all ending at the section's end."""
        size = ranges * 16
        text = bytearray(b"\x90" * size)
        for at in range(0, size - len(GS_PEB), 64):
            text[at : at + len(GS_PEB)] = GS_PEB
        return self._image(text, [(TEXT_RVA + i, TEXT_RVA + size) for i in range(ranges)])

    @staticmethod
    def _traced(image: Any) -> tuple[list[dict[str, Any]], int]:
        """The rows and the most memory the scan held at once.

        Traced on the smaller input of each pair: tracing every allocation
        makes the scan many times slower, and the timing pair shows it linear.
        """
        import tracemalloc

        tracemalloc.start()
        try:
            rows = gs_reads(image)
            return rows, tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()

    def test_a_50_mb_range_holding_a_million_reads(self) -> None:
        small, large = self._one_range_of_hits(100_000), self._one_range_of_hits(1_000_000)
        assert len(large.data) >= 45_000_000

        rows = gs_reads(large)

        assert len(rows) == 1_000_000
        assert not any(GS_OFF_BOUNDARY in row["what"] for row in rows)
        assert (
            self._seconds(lambda: gs_reads(large))
            <= 10 * self._seconds(lambda: gs_reads(small)) * 1.5 + 0.1
        )
        traced, peak = self._traced(self._one_range_of_hits(10_000))
        # The rows themselves, and one byte per code byte for the starts.
        assert peak < 1_000 * len(traced) + 2 * 10_000 * len(GS_PEB) * 5

    def test_a_hundred_thousand_overlapping_ranges(self) -> None:
        small, large = self._overlapping_ranges(10_000), self._overlapping_ranges(100_000)

        rows = gs_reads(large)

        assert len(rows) == len(range(0, 100_000 * 16 - len(GS_PEB), 64))
        assert (
            self._seconds(lambda: gs_reads(large))
            <= 10 * self._seconds(lambda: gs_reads(small)) * 1.5 + 0.1
        )
        traced, peak = self._traced(small)
        assert peak < 1_000 * len(traced) + 2 * len(small.data)

"""The PE reading stays linear on headers built to make it work hard.

A sample chooses its own import tables, section headers and function table.
Each image here is laid out by the test, on synthetic bytes only: descriptors
that share one lookup table with unterminated names, thousands of section
headers in front of a function table, a constant stored many times behind
thousands of headers, and thousands of distinct hash values. The work is
counted (steps taken, lookups built, bytes allocated), never timed, so the
checks hold on a loaded machine: each count grows with the file, not with a
product of its tables.
"""

from __future__ import annotations

import json
import math
import random
import struct
import tracemalloc
from collections.abc import Callable, Iterator
from functools import partial
from pathlib import Path
from typing import Any

import numpy as np
import pytest

from maljan.pipeline import triage_pack
from maljan.tools import (
    api_hashes,
    artefact_index,
    call_sites,
    crypto_constants,
    pe_image,
    upx,
)
from maljan.tools.pe_image import Image, Section

from .synthetic_pe import TEXT_RVA, SyntheticPE

_BASE64 = 0x140000000


def _headers(buf: bytearray, *, is64: bool, count: int, optional_size: int) -> int:
    """MZ and PE headers in ``buf``; answer the optional header's offset."""
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x40)
    buf[0x40:0x44] = b"PE\0\0"
    machine, flags = (0x8664, 0x22) if is64 else (0x14C, 0x102)
    struct.pack_into("<HHIIIHH", buf, 0x44, machine, count, 0, 0, 0, optional_size, flags)
    optional = 0x58
    struct.pack_into("<H", buf, optional, 0x20B if is64 else 0x10B)
    if is64:
        struct.pack_into("<Q", buf, optional + 24, _BASE64)
        struct.pack_into("<I", buf, optional + 108, 16)
    else:
        struct.pack_into("<I", buf, optional + 28, 0x400000)
        struct.pack_into("<I", buf, optional + 92, 16)
    struct.pack_into("<I", buf, optional + 56, 0x10000000)
    return optional


def _shared_imports(descriptors: int, thunks: int, name_length: int) -> bytes:
    """Descriptors all naming one lookup table whose entries all name one long name."""
    data_off = 0x400
    thunk_off = data_off + (descriptors + 1) * 20
    name_off = thunk_off + (thunks + 1) * 8
    total = name_off + 2 + name_length + 1
    buf = bytearray(total)
    optional = _headers(buf, is64=True, count=1, optional_size=0xF0)

    def rva(offset: int) -> int:
        return 0x1000 + offset - data_off

    struct.pack_into("<II", buf, optional + 112 + 8, rva(data_off), (descriptors + 1) * 20)
    at = optional + 0xF0
    buf[at : at + 8] = b".data\0\0\0"
    struct.pack_into("<IIII", buf, at + 8, total - data_off, 0x1000, total - data_off, data_off)
    struct.pack_into("<I", buf, at + 36, 0xC0000040)
    for index in range(descriptors):
        struct.pack_into(
            "<IIIII",
            buf,
            data_off + index * 20,
            rva(thunk_off),
            0,
            0,
            rva(name_off + 2),
            0x100000 + index * 0x10000,
        )
    for index in range(thunks):
        struct.pack_into("<Q", buf, thunk_off + index * 8, rva(name_off))
    buf[name_off + 2 : name_off + 2 + name_length] = b"A" * name_length
    return bytes(buf)


def _many_headers_and_a_table(sections: int, entries: int) -> bytes:
    """Thousands of section headers, the last one holding an exception directory."""
    header_end = 0x40 + 24 + 0xF0 + sections * 40
    data_off = (header_end + 0xFFF) & ~0xFFF
    pdata_size = entries * 12
    total = data_off + pdata_size + 16
    buf = bytearray(total)
    optional = _headers(buf, is64=True, count=sections, optional_size=0xF0)
    last_rva = 0x1000 * (sections + 1)
    struct.pack_into("<II", buf, optional + 112 + 3 * 8, last_rva, pdata_size)
    table = optional + 0xF0
    for index in range(sections):
        at = table + index * 40
        buf[at : at + 8] = b".sec\0\0\0\0"
        if index == sections - 1:
            struct.pack_into(
                "<IIII", buf, at + 8, total - data_off, last_rva, total - data_off, data_off
            )
        else:
            struct.pack_into("<IIII", buf, at + 8, 0x10, 0x1000 * (index + 1), 0x10, data_off)
        struct.pack_into("<I", buf, at + 36, 0x40000040)
    for index in range(entries):
        struct.pack_into(
            "<III",
            buf,
            data_off + index * 12,
            0x100 + index * 16,
            0x108 + index * 16,
            last_rva + pdata_size,
        )
    return bytes(buf)


def _constant_behind_headers(sections: int, repeats: int) -> bytes:
    """One constant stored ``repeats`` times in code behind ``sections`` headers (x86)."""
    payload = struct.pack("<I", 0x9E3779B9) * repeats
    header_end = 0x40 + 24 + 0xE0 + sections * 40
    data_off = (header_end + 0xFFF) & ~0xFFF
    buf = bytearray(data_off + len(payload))
    optional = _headers(buf, is64=False, count=sections, optional_size=0xE0)
    table = optional + 0xE0
    for index in range(sections):
        at = table + index * 40
        buf[at : at + 8] = b".sec\0\0\0\0"
        if index == sections - 1:
            rva = 0x1000 * (sections + 1)
            struct.pack_into("<IIII", buf, at + 8, len(payload), rva, len(payload), data_off)
        else:
            struct.pack_into("<IIII", buf, at + 8, 0x10, 0x1000 * (index + 1), 0x10, 0x200)
        struct.pack_into("<I", buf, at + 36, 0x60000020)
    buf[data_off:] = payload
    return bytes(buf)


def _distinct_pairs(size: int, name_length: int = 511) -> bytes:
    """An x86 image of about ``size`` bytes whose descriptors and entries all name distinct names.

    Descriptors times entries come near the slot budget; every DLL name and
    every function name is its own string of ``name_length`` bytes.
    """
    count = math.isqrt(size // 4) // 2
    data_off = 0x400
    thunk_off = data_off + (count + 1) * 20
    dll_off = thunk_off + (count + 1) * 4
    function_off = dll_off + count * (name_length + 1)
    buf = bytearray(max(size, function_off + count * (name_length + 3) + 1))
    optional = _headers(buf, is64=False, count=1, optional_size=0xE0)

    def rva(offset: int) -> int:
        return 0x1000 + offset - data_off

    struct.pack_into("<II", buf, optional + 96 + 8, rva(data_off), (count + 1) * 20)
    at = optional + 0xE0
    buf[at : at + 8] = b".data\0\0\0"
    raw = len(buf) - data_off
    struct.pack_into("<IIII", buf, at + 8, raw, 0x1000, raw, data_off)
    struct.pack_into("<I", buf, at + 36, 0xC0000040)
    for index in range(count):
        name = dll_off + index * (name_length + 1)
        struct.pack_into(
            "<IIIII",
            buf,
            data_off + index * 20,
            rva(thunk_off),
            0,
            0,
            rva(name),
            0x2000000 + index * count * 4,
        )
        buf[name : name + name_length] = (b"%08d" % index) + b"D" * (name_length - 8)
    for index in range(count):
        row = function_off + index * (name_length + 3)
        struct.pack_into("<I", buf, thunk_off + index * 4, rva(row))
        buf[row + 2 : row + 2 + name_length] = (b"%08d" % index) + b"F" * (name_length - 8)
    return bytes(buf)


def _cycling_constants(size: int) -> bytes:
    """An x86 code section of ``size`` bytes cycling through every lone-standing constant."""
    sets = [
        entry
        for entry in crypto_constants.catalogue()
        if entry.kind != crypto_constants.TABLE
        and entry.width == 4
        and not entry.requires
        and not entry.halves_of
    ]
    values = list(dict.fromkeys(value for entry in sets for value in entry.values))
    unit = b"".join(struct.pack("<I", value) for value in values)
    payload = (unit * (size // len(unit) + 1))[:size]
    data_off = 0x400
    buf = bytearray(data_off + len(payload))
    optional = _headers(buf, is64=False, count=1, optional_size=0xE0)
    at = optional + 0xE0
    buf[at : at + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", buf, at + 8, len(payload), 0x1000, len(payload), data_off)
    struct.pack_into("<I", buf, at + 36, 0x60000020)
    buf[data_off:] = payload
    return bytes(buf)


def _hash_values(count: int) -> list[int]:
    algorithms = tuple(
        sorted(str(a["id"]) for a in api_hashes.load_algorithms(api_hashes.DEFAULT_ALGORITHMS))
    )
    table = api_hashes._table(
        algorithms, api_hashes.DEFAULT_EXPORT_NAMES, api_hashes.DEFAULT_ALGORITHMS
    )
    return sorted(v for v in table if 0x10000 <= v < _BASE64)[:count]


def _hash_table(values: list[int]) -> bytes:
    """A ``.data`` section holding ``values``, each once."""
    payload = b"".join(struct.pack("<I", v) for v in values)
    data_off = 0x400
    buf = bytearray(data_off + len(payload))
    optional = _headers(buf, is64=True, count=1, optional_size=0xF0)
    struct.pack_into("<I", buf, optional + 56, 0x1000 + len(buf))
    at = optional + 0xF0
    buf[at : at + 8] = b".data\0\0\0"
    struct.pack_into("<IIII", buf, at + 8, len(payload), 0x1000, len(payload), data_off)
    struct.pack_into("<I", buf, at + 36, 0xC0000040)
    buf[data_off:] = payload
    return bytes(buf)


class _Counted:
    """How many section headers the parsed images' lookups step over, in all.

    Every image ``pe_image`` parses gets a section list that counts each header
    an iteration yields, so a walk of every header per lookup shows up as
    headers times lookups.
    """

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.reads = 0
        counter = self

        # A list the image keeps as it is (older readings keep any list).
        base: type = getattr(pe_image, "SectionList", list)

        class _Headers(base):  # type: ignore[valid-type,misc]
            def __iter__(self) -> Iterator[Section]:
                for section in super().__iter__():
                    counter.reads += 1
                    yield section

        class _CountingImage(Image):
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                super().__init__(*args, **kwargs)
                headers: list[Section] = _Headers(self.sections)
                self.sections = headers

        monkeypatch.setattr(pe_image, "Image", _CountingImage)


def _slot_count(data: bytes) -> int:
    return len(pe_image.parse(data).imports_by_slot())


def _peak(work: Callable[[], Any]) -> int:
    tracemalloc.start()
    try:
        work()
        return tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


class TestSharedLookupTables:
    def test_the_slots_read_are_bounded_by_the_file_and_the_cut_is_said(self) -> None:
        data = _shared_imports(200, 200, 20)
        image = pe_image.parse(data)
        slots = image.imports_by_slot()
        assert 0 < len(slots) <= len(data) // 8
        assert "the import tables list more slots than the file can store" in image.imports_note

    def test_the_tables_cost_lookups_linear_in_the_file(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        data = _shared_imports(400, 400, 20)
        image = pe_image.parse(data)
        lookups: list[int] = []
        original = Image.section_at_rva

        def counted(self: Image, rva: int) -> Section | None:
            lookups.append(rva)
            return original(self, rva)

        monkeypatch.setattr(Image, "section_at_rva", counted)
        slots = image.imports_by_slot()
        # A reading of every table per descriptor maps 400 x 400 entries.
        assert len(lookups) <= len(data) // 8 + 3 * 400 + 1
        assert sum(1 for _ in slots) <= len(data) // 8

    def test_distinct_dll_and_name_pairs_hold_memory_linear_in_the_file(self) -> None:
        for size in (800_000, 3_200_000):
            data = _distinct_pairs(size)
            peak = _peak(partial(_slot_count, data))
            # One joined name per slot held 320 times the file.
            assert peak < 8 * size

    def test_a_slot_joins_its_names_when_looked_up(self) -> None:
        image = pe_image.parse(_distinct_pairs(20_000))
        slots = image.imports_by_slot()
        first = next(iter(slots))
        assert slots[first].startswith("00000000") and "!00000000" in slots[first]
        assert len(slots) == sum(1 for _ in slots) == len(dict(slots.items()))
        assert first + 1 not in slots, "a slot between entries names nothing"

    def test_an_unterminated_long_name_does_not_grow_memory_with_the_slots(self) -> None:
        small = _shared_imports(100, 100, 20000)
        large = _shared_imports(200, 200, 20000)
        small_peak = _peak(lambda: pe_image.parse(small).imports_by_slot())
        large_peak = _peak(lambda: pe_image.parse(large).imports_by_slot())
        # The old reading held one copy of the name per slot: 1.5 GB at 26 KB.
        assert large_peak < 64 * len(large)
        assert large_peak < 4 * max(small_peak, len(small))

    def test_a_name_is_read_inside_its_section_up_to_its_bound(self) -> None:
        image = pe_image.parse(_shared_imports(1, 1, pe_image._IMPORT_NAME_BOUND + 1))
        assert image.imports_by_slot() == {}, "a name past its bound is not read"
        assert "1 import entries and 1 import descriptors name no readable" in image.imports_note
        image = pe_image.parse(_shared_imports(1, 1, pe_image._IMPORT_NAME_BOUND))
        name = "A" * pe_image._IMPORT_NAME_BOUND
        assert image.imports_by_slot() == {0x100000: f"{name}!{name}"}

    def test_the_function_index_states_the_cut_where_the_model_reads_it(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "s.exe"
        path.write_bytes(_shared_imports(200, 200, 20))
        answer = artefact_index.function_index(path)
        assert "more slots than the file can store" in answer["imports_cut"]
        assert "imports: the import tables list more slots" in artefact_index.head_text(answer, 0)

    def test_a_call_through_an_unnamed_slot_says_the_tables_were_cut(self) -> None:
        image = pe_image.parse(_shared_imports(200, 200, 20))
        instruction = call_sites.decode(b"\xff\x15\x00\x00\x00\x00", 0, True)
        assert instruction is not None
        callee = call_sites._callee(image, 0x7FFFFFF0, instruction)
        assert callee is not None and "more slots than the file can store" in callee["imports_cut"]
        words = call_sites._callee_words({"callee": callee})
        assert words.startswith("the pointer stored at") and "no import name read" in words

    def test_the_rebuilt_files_import_count_carries_the_cut(self) -> None:
        functions, libraries, cut = upx._import_counts(_shared_imports(200, 200, 20))
        assert functions > 0 and libraries == 1
        assert "more slots than the file can store" in cut
        normal = SyntheticPE()
        normal.imports_at(0x40, {"kernel32.dll": ["Sleep"], "user32.dll": ["MessageBoxA"]})
        assert upx._import_counts(normal.build()) == (2, 2, "")

    def test_normal_imports_carry_no_cut(self) -> None:
        image = SyntheticPE()
        slots = image.imports_at(0x40, {"kernel32.dll": ["CreateFileA", "Sleep"]})
        parsed = pe_image.parse(image.build())
        assert parsed.imports_by_slot() == {
            slot: f"kernel32.dll!{name}" for name, slot in slots.items()
        }
        assert parsed.imports_note == ""


class TestManySectionHeaders:
    def test_the_function_table_is_read_in_steps_linear_in_headers_and_entries(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        counted = _Counted(monkeypatch)
        reads = []
        for sections, entries in ((1000, 5000), (2000, 10000)):
            counted.reads = 0
            image = pe_image.parse(_many_headers_and_a_table(sections, entries))
            assert len(image.function_starts) == entries
            reads.append(counted.reads)
        # A walk of every header per entry reads 5 million at the first size.
        assert reads[0] <= 4 * (1000 + 5000)
        assert reads[1] <= 2.5 * reads[0]

    def test_a_shared_chain_is_followed_once(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls: list[int] = []
        original: Callable[[Image, int], tuple[int, int] | None] = pe_image._chained_to

        def counted(image: Image, unwind: int) -> tuple[int, int] | None:
            calls.append(unwind)
            return original(image, unwind)

        monkeypatch.setattr(pe_image, "_chained_to", counted)
        pe_image.parse(_many_headers_and_a_table(10, 3000))
        assert len(calls) == len(set(calls)) == 1, "every entry names one unwind record"


class TestAConstantStoredManyTimes:
    def test_its_places_cost_lookups_linear_in_places_and_headers(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        counted = _Counted(monkeypatch)
        reads = []
        for sections, repeats in ((500, 5000), (1000, 10000)):
            path = tmp_path / f"c{sections}.bin"
            path.write_bytes(_constant_behind_headers(sections, repeats))
            counted.reads = 0
            answer = crypto_constants.find_crypto_constants(str(path))
            places = sum(len(v["places"]) for row in answer["found"] for v in row.get("values", []))
            assert places == repeats
            reads.append(counted.reads)
        assert reads[0] <= 4 * (500 + 5000)
        assert reads[1] <= 2.5 * reads[0]

    def test_an_answer_over_many_values_stays_bounded_and_says_its_cut_once(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(pe_image, "PLACE_BUDGET", 1000)
        sizes = []
        for size in (100_000, 400_000):
            path = tmp_path / f"cycle{size}.bin"
            path.write_bytes(_cycling_constants(size))
            answer = crypto_constants.find_crypto_constants(str(path))
            rows = [*answer["found"], *answer["lone"]]
            places = sum(len(v["places"]) for row in rows for v in row.get("values", []))
            assert places <= 1000
            assert "the answer lists the first 1000 places in all" in answer["places_cut"]
            assert not any("places_cut" in v for row in rows for v in row.get("values", []))
            sizes.append(len(json.dumps(answer)))
        # Four times the file, the same answer size give or take longer offsets.
        assert sizes[1] < 1.5 * sizes[0]
        line = triage_pack._constant_sets(answer)
        assert "the answer lists the first 1000 places in all" in line


class TestManyHashValues:
    def test_the_file_is_not_scanned_once_per_value(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        scans: list[int] = []
        original: Callable[[Image, int, int], list[int]] = pe_image.Image.occurrences

        def counted(image: Image, value: int, width: int = 4) -> list[int]:
            scans.append(value)
            return original(image, value, width)

        monkeypatch.setattr(pe_image.Image, "occurrences", counted)
        values = _hash_values(2000)
        path = tmp_path / "h.bin"
        path.write_bytes(_hash_table(values))
        answer = api_hashes.resolve_api_hashes(str(path))
        assert answer["total"] == len(values)
        assert all(len(hit["occurrences"]) == 1 for hit in answer["hits"])
        # A scan of the whole file per value made 2000 here.
        assert len(scans) == 0

    def test_the_places_match_a_scan_of_each_value(self) -> None:
        rng = random.Random(7)
        values = [rng.choice([0x11223344, 0x44332211, 0xAAAAAAAA, 0x00000001]) for _ in range(400)]
        blob = b"".join(struct.pack("<I", v) for v in values) + bytes(
            rng.getrandbits(8) for _ in range(301)
        )
        image = Image(data=blob, image_base=0, is64=False, size_of_image=0)
        wanted = {0x11223344, 0x44332211, 0xAAAAAAAA, 0x00000001, 0xDEADBEEF}
        assert image.occurrences_of(wanted) == {v: image.occurrences(v) for v in wanted}

    def test_past_the_place_budget_the_occurrences_are_cut_and_said_once(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(pe_image, "PLACE_BUDGET", 3)
        first, second = _hash_values(2)
        path = tmp_path / "h.bin"
        path.write_bytes(_hash_table([first] * 2 + [second] * 3))
        answer = api_hashes.resolve_api_hashes(str(path), hashes=[first, second])
        assert [len(hit["occurrences"]) for hit in answer["hits"]] == [2, 1]
        assert answer["occurrences_cut"].startswith("2 more places hold the values found")
        line = triage_pack._resolved_hashes(answer)
        assert "(2 more places hold the values found" in line

    def test_the_one_pass_holds_little_beside_the_file(self) -> None:
        peaks = []
        for size in (2_000_000, 8_000_000):
            data = random.Random(3).randbytes(size)
            image = Image(data=data, image_base=0, is64=False, size_of_image=0)
            wanted = list(range(0x10000000, 0x10000000 + 3000))
            peaks.append(_peak(partial(image.occurrences_of, wanted)))
        # Widening every position to 32 bits took eight times the file.
        assert peaks[1] < 8_000_000
        assert peaks[1] < 1.5 * peaks[0], "a stretch at a time: the same however long the file"


def _walk_offset(sections: list[Section], offset: int) -> Section | None:
    for section in sections:
        if section.raw_offset <= offset < section.raw_offset + section.mapped_size:
            return section
    return None


def _walk_rva(sections: list[Section], rva: int) -> Section | None:
    for section in sections:
        if section.rva <= rva < section.rva + max(section.virtual_size, section.raw_size):
            return section
    return None


@pytest.mark.parametrize("seed", range(40))
def test_overlapping_sections_answer_the_first_in_header_order(seed: int) -> None:
    rng = random.Random(seed)
    sections = [
        Section(
            f"s{index}",
            rng.randrange(0, 0x8000, 0x100),
            rng.choice([0, rng.randrange(0, 0x3000)]),
            rng.randrange(0, 0x6000, 0x10),
            rng.choice([0, rng.randrange(0, 0x3000)]),
            0,
        )
        for index in range(rng.randint(1, 30))
    ]
    image = Image(
        data=bytes(0x9000), image_base=0, is64=False, size_of_image=0x10000, sections=sections
    )
    for point in range(-2, 0xC000, 7):
        assert image.section_at_offset(point) is _walk_offset(sections, point)
        assert image.section_at_rva(point) is _walk_rva(sections, point)


def test_a_section_list_that_changes_is_looked_up_afresh() -> None:
    image = Image(data=bytes(0x100), image_base=0, is64=False, size_of_image=0x4000)
    assert image.section_at_rva(0x1000) is None
    image.sections.append(Section(".a", 0x1000, 0x100, 0, 0x100, 0))
    assert image.section_at_rva(0x1000) is image.sections[0]
    image.sections[0] = Section(".b", 0x2000, 0x100, 0, 0x100, 0)
    assert image.section_at_rva(0x1000) is None, "replaced in place, same length"
    assert image.section_at_rva(0x2000) is image.sections[0]
    image.sections = [Section(".c", 0x3000, 0x100, 0, 0x100, 0)]
    assert image.section_at_rva(0x3000) is image.sections[0]


def test_a_name_is_bounded_by_the_section_its_address_falls_in() -> None:
    """Two sections share file bytes; the name's address is in the longer one."""
    data = bytearray(0x800)
    data[0x4F0:0x520] = b"N" * 0x30
    image = Image(data=bytes(data), image_base=0, is64=False, size_of_image=0x3000)
    image.sections = [
        Section(".short", 0x1000, 0x100, 0x400, 0x100, 0),
        Section(".long", 0x2000, 0x400, 0x400, 0x400, 0),
    ]
    slots = pe_image.ImportSlots(image)
    assert slots.name(0x20F0, 512) == "N" * 0x30
    assert slots.name(0x10F0, 512) == "", "no NUL before the short section's bytes end"


def _overlapping_iats(rng: random.Random) -> bytes:
    """An x86 image whose descriptors share thunk arrays and overlapping, misaligned slots."""
    size, data_off = 0x3000, 0x400
    buf = bytearray(size)
    optional = _headers(buf, is64=False, count=1, optional_size=0xE0)
    struct.pack_into("<I", buf, optional + 56, 0x10000)

    def rva(offset: int) -> int:
        return 0x1000 + offset - data_off

    descriptors = rng.randint(1, 6)
    struct.pack_into("<II", buf, optional + 96 + 8, rva(data_off), (descriptors + 1) * 20)
    at = optional + 0xE0
    buf[at : at + 8] = b".data\0\0\0"
    struct.pack_into("<IIII", buf, at + 8, size - data_off, 0x1000, size - data_off, data_off)
    struct.pack_into("<I", buf, at + 36, 0xC0000040)
    for index in range(20):
        row = 0x1000 + index * 16
        name = (b"Fn%d" % index) if rng.random() > 0.15 else b""
        buf[row + 2 : row + 2 + len(name)] = name
    tables = [0x800 + index * 0x80 for index in range(4)]
    for table in tables:
        for entry in range(rng.randint(0, 8)):
            if rng.random() < 0.15:
                value = 0x80000000 | rng.randint(1, 50)
            else:
                value = rva(0x1000 + rng.randrange(20) * 16)
            struct.pack_into("<I", buf, table + 4 * entry, value)
    for index in range(descriptors):
        dll = 0x1400 + index * 16
        buf[dll : dll + 6] = b"d%d.dll" % index
        address = rng.choice([0x5000, 0x5004, 0x5008, 0x5002, 0x5010, 0x6000])
        struct.pack_into(
            "<IIIII", buf, data_off + index * 20, rva(rng.choice(tables)), 0, 0, rva(dll), address
        )
    return bytes(buf)


def _every_write(image: Image) -> dict[int, str]:
    """The slots as writing every named entry, descriptor by descriptor, leaves them."""
    found: dict[int, str] = {}
    data = image.data
    assert image.import_directory is not None
    at = image.offset_of_rva(image.import_directory[0])
    while at is not None and at + 20 <= len(data):
        lookup, _, _, name_rva, address = struct.unpack_from("<IIIII", data, at)
        if not (lookup or name_rva or address):
            break
        at += 20
        name_at = image.offset_of_rva(name_rva)
        dll = data[name_at : data.find(b"\0", name_at)].decode() if name_at is not None else ""
        table = image.offset_of_rva(lookup or address)
        index = 0
        while table is not None and table + 4 * (index + 1) <= len(data):
            (value,) = struct.unpack_from("<I", data, table + 4 * index)
            if not value:
                break
            if value & 0x80000000:
                function = f"#{value & 0xFFFF}"
            else:
                hint = image.offset_of_rva(value & 0x7FFFFFFF)
                function = (
                    data[hint + 2 : data.find(b"\0", hint + 2)].decode() if hint is not None else ""
                )
            if function:
                found[address + 4 * index] = f"{dll}!{function}" if dll else function
            index += 1
    return found


@pytest.mark.parametrize("seed", range(300))
def test_overlapping_and_misaligned_address_tables_read_as_every_write_leaves_them(
    seed: int,
) -> None:
    image = pe_image.parse(_overlapping_iats(random.Random(seed)))
    slots = image.imports_by_slot()
    expected = _every_write(image)
    assert dict(slots) == expected
    assert len(slots) == len(expected)
    for slot in expected:
        assert slots[slot] == expected[slot]


def test_overlapping_address_tables_are_said() -> None:
    image = SyntheticPE(is64=False, image_base=0x400000)
    image.imports_at(0x40, {"a.dll": ["One", "Two"], "b.dll": ["Three"]})
    built = bytearray(image.build())
    parsed = pe_image.parse(bytes(built))
    first, second = parsed.imports_by_slot().records
    # Point the second descriptor's address table at the first one's second slot.
    directory = parsed.offset_of_rva(parsed.import_directory[0])  # type: ignore[index]
    assert directory is not None
    struct.pack_into("<I", built, directory + 20 + 16, first[0] + 4)
    reread = pe_image.parse(bytes(built))
    slots = reread.imports_by_slot()
    assert slots[first[0] + 4] == "b.dll!Three"
    assert "1 descriptors' address tables overlap another's; 1 slots" in reread.imports_note
    assert parsed.imports_by_slot().dll(1) == "b.dll" and second[1] != first[1]


def test_an_image_with_no_imports_has_no_slots() -> None:
    parsed = pe_image.parse(SyntheticPE().build())
    slots = parsed.imports_by_slot()
    assert len(slots) == 0
    assert slots.libraries() == set()
    assert dict(slots) == {}
    assert upx._import_counts(SyntheticPE().build()) == (0, 0, "")


def _distinct_hints(size: int) -> bytes:
    """One descriptor whose thunk array fills the file, every entry a distinct hint address."""
    data_off = 0x400
    buf = bytearray(size)
    optional = _headers(buf, is64=False, count=1, optional_size=0xE0)

    def rva(offset: int) -> int:
        return 0x1000 + offset - data_off

    descriptor, dll = data_off, data_off + 40
    thunk = dll + 16
    struct.pack_into("<II", buf, optional + 96 + 8, rva(descriptor), 40)
    at = optional + 0xE0
    buf[at : at + 8] = b".data\0\0\0"
    struct.pack_into("<IIII", buf, at + 8, size - data_off, 0x1000, size - data_off, data_off)
    struct.pack_into("<I", buf, at + 36, 0xC0000040)
    buf[dll : dll + 8] = b"k32.dll\0"
    count = (size - thunk) // 4 - 1
    for index in range(count):
        struct.pack_into("<I", buf, thunk + 4 * index, rva(thunk + 4 * ((index * 7919) % count)))
    struct.pack_into("<IIIII", buf, descriptor, rva(thunk), 0, 0, rva(dll), 0x2000000)
    return bytes(buf)


def test_distinct_hint_addresses_hold_memory_linear_in_the_file() -> None:
    peaks = []
    for size in (800_000, 3_200_000):
        data = _distinct_hints(size)
        peaks.append(_peak(partial(_slot_count, data)))
        # A name held per hint address held 40 times the file.
        assert peaks[-1] < 12 * size
    assert peaks[1] < 5 * peaks[0]


def test_function_bounds_take_the_next_start_from_elsewhere() -> None:
    image = SyntheticPE(is64=False, image_base=0x400000)
    parsed = pe_image.parse(image.build())
    pe_image.take_function_starts(parsed, [0x1000, 0x1100, 0x1180], "capa")
    assert parsed.function_bounds(0x1120) == (0x1100, 0x1180)
    assert parsed.function_bounds(0x1190) == (0x1180, TEXT_RVA + len(image.text))


def _dll_spam(descriptors: int) -> bytes:
    """``descriptors`` descriptors filling the file, all naming one long DLL name and no entry."""
    data_off = 0x400
    name, zero = data_off, data_off + 520
    first = zero + 8
    size = first + (descriptors + 1) * 20
    buf = bytearray(size)
    optional = _headers(buf, is64=False, count=1, optional_size=0xE0)

    def rva(offset: int) -> int:
        return 0x1000 + offset - data_off

    buf[name : name + 511] = b"D" * 511
    struct.pack_into("<II", buf, optional + 96 + 8, rva(first), (descriptors + 1) * 20)
    at = optional + 0xE0
    buf[at : at + 8] = b".data\0\0\0"
    struct.pack_into("<IIII", buf, at + 8, size - data_off, 0x1000, size - data_off, data_off)
    struct.pack_into("<I", buf, at + 36, 0xC0000040)
    for index in range(descriptors):
        struct.pack_into(
            "<IIIII", buf, first + 20 * index, rva(zero), 0, 0, rva(name), 0x100 + index
        )
    return bytes(buf)


class _Work:
    """The work the import reader does, counted: bytes searched for a NUL, words read.

    Every search for a name's end, scalar or batched, counts the bytes it may
    read; every thunk array walk counts the words it read. The count grows
    with what is read, never with the clock.
    """

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.units = 0
        work = self
        end = pe_image.ImportSlots._end
        first_nuls = pe_image._first_nuls
        run_length = pe_image._run_length

        def counted_end(slots: Any, start: int, stop: int) -> int:
            work.units += max(0, stop - start)
            return end(slots, start, stop)

        def counted_first_nuls(data: bytes, starts: Any, stops: Any) -> Any:
            work.units += int((stops - starts).clip(min=0).sum())
            return first_nuls(data, starts, stops)

        def counted_run_length(data: bytes, table: int, width: int, limit: int) -> int:
            found = run_length(data, table, width, limit)
            work.units += found + 1
            return found

        monkeypatch.setattr(pe_image.ImportSlots, "_end", counted_end)
        monkeypatch.setattr(pe_image, "_first_nuls", counted_first_nuls)
        monkeypatch.setattr(pe_image, "_run_length", counted_run_length)


def _unread_dll_descriptors(descriptors: int) -> bytes:
    """``descriptors`` descriptors of one entry each, every DLL name address outside the file."""
    data_off = 0x400
    hint = data_off + (descriptors + 1) * 20
    thunk = hint + 16
    size = thunk + 8 + 0x100
    buf = bytearray(size)
    optional = _headers(buf, is64=False, count=1, optional_size=0xE0)

    def rva(offset: int) -> int:
        return 0x1000 + offset - data_off

    buf[hint + 2 : hint + 7] = b"a!Fn\0"
    struct.pack_into("<I", buf, thunk, rva(hint))
    struct.pack_into("<II", buf, optional + 96 + 8, rva(data_off), (descriptors + 1) * 20)
    at = optional + 0xE0
    buf[at : at + 8] = b".data\0\0\0"
    struct.pack_into("<IIII", buf, at + 8, size - data_off, 0x1000, size - data_off, data_off)
    struct.pack_into("<I", buf, at + 36, 0xC0000040)
    for index in range(descriptors):
        struct.pack_into(
            "<IIIII",
            buf,
            data_off + 20 * index,
            rva(thunk),
            0,
            0,
            0x7000000 + index,
            0x100000 + 4 * index,
        )
    return bytes(buf)


class TestTheImportReaderWorksInProportion:
    """Ten times the descriptors or lookups is about ten times the work, counted, not a hundred."""

    def test_many_descriptors_naming_one_dll(self, monkeypatch: pytest.MonkeyPatch) -> None:
        work = _Work(monkeypatch)
        units = []
        for descriptors in (5_000, 50_000):
            work.units = 0
            _slot_count(_dll_spam(descriptors))
            units.append(work.units)
        assert 0 < units[1] <= 12 * units[0]

    def test_many_slot_lookups(self, monkeypatch: pytest.MonkeyPatch) -> None:
        units = []
        for size in (80_000, 800_000):
            slots = pe_image.parse(_distinct_hints(size)).imports_by_slot()
            keys = list(slots)
            assert len(keys) > size // 20
            work = _Work(monkeypatch)
            # Ten times the file, ten times the lookups.
            for key in keys[: size // 20]:
                slots[key]
            units.append(work.units)
            monkeypatch.undo()
        assert 0 < units[1] <= 12 * units[0]

    def test_libraries_group_the_slots_once(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Descriptors naming no readable DLL: the slots are grouped once, not scanned per DLL."""
        examined: list[int] = []

        class _CountingNumpy:
            """numpy, counting the elements each search over the slot arrays examines."""

            def __getattr__(self, name: str) -> Any:
                return getattr(np, name)

            def flatnonzero(self, values: Any) -> Any:
                examined.append(np.size(values))
                return np.flatnonzero(values)

            def argsort(self, values: Any, **kwargs: Any) -> Any:
                examined.append(np.size(values))
                return np.argsort(values, **kwargs)

        for descriptors in (2_000, 20_000):
            slots = pe_image.parse(_unread_dll_descriptors(descriptors)).imports_by_slot()
            assert len(slots) == descriptors
            monkeypatch.setattr(pe_image, "np", _CountingNumpy())
            examined.clear()
            assert slots.libraries() == {"a"}, "a name holding a ! names a library, as on dev"
            monkeypatch.undo()
            # One sort and one pass: a search per descriptor examined 20,000 x 20,000.
            assert sum(examined) <= 3 * descriptors


def test_sections_over_the_same_bytes_are_not_scanned_each() -> None:
    """Forty sections map the same bytes; names are read in each, bounded by each."""
    count, size = 40, 0x200000
    header_end = 0x58 + 0xE0 + 40 * count
    data_off = (header_end + 0xFFF) & ~0xFFF
    buf = bytearray(b"A\0" * ((data_off + size) // 2))
    buf[:data_off] = bytes(data_off)
    optional = _headers(buf, is64=False, count=count, optional_size=0xE0)
    struct.pack_into("<I", buf, optional + 56, 0x70000000)
    span = len(buf) - data_off

    def section_rva(index: int) -> int:
        return 0x1000 + index * ((span + 0xFFF) & ~0xFFF)

    for index in range(count):
        at = optional + 0xE0 + 40 * index
        buf[at : at + 8] = b".s\0\0\0\0\0\0"
        struct.pack_into("<IIII", buf, at + 8, span, section_rva(index), span, data_off)
        struct.pack_into("<I", buf, at + 36, 0xC0000040)
    descriptor, dll = data_off, data_off + 40
    thunk = dll + 16
    entries = 4 * count
    buf[descriptor : thunk + 4 * (entries + 1)] = bytes(thunk + 4 * (entries + 1) - descriptor)
    buf[dll : dll + 4] = b"k.d\0"
    for index in range(entries):
        struct.pack_into(
            "<I", buf, thunk + 4 * index, section_rva(index % count) + 0x1000 + 2 * index
        )
    struct.pack_into("<II", buf, optional + 96 + 8, section_rva(0) + descriptor - data_off, 40)
    struct.pack_into(
        "<IIIII",
        buf,
        descriptor,
        section_rva(0) + thunk - data_off,
        0,
        0,
        section_rva(0) + dll - data_off,
        0x60000000,
    )
    data = bytes(buf)
    slots = pe_image.parse(data).imports_by_slot()
    assert len(slots) == entries
    assert set(slots.values()) == {"k.d!A"}
    # No index per section, nor of the file: a scan of every section held
    # forty times the bytes the sections share.
    assert _peak(partial(_slot_count, data)) < len(data)

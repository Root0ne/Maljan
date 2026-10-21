"""The API-hash candidates read each byte once, however many sections cover it."""

from __future__ import annotations

import random
from types import SimpleNamespace

import numpy as np
import pytest

from maljan.tools import api_hashes, pe_image
from maljan.tools.pe_image import Section

_EXEC = 0x20000000
_DATA = 0x40000040


def _image(sections: list[Section], blob: bytes) -> SimpleNamespace:
    def window(s: Section) -> bytes:
        return blob[s.raw_offset : s.raw_offset + s.mapped_size]

    return SimpleNamespace(
        is64=False,
        image_base=0x400000,
        size_of_image=0x10000,
        code_sections=lambda: [s for s in sections if s.executable],
        data_sections=lambda: [s for s in sections if not s.executable],
        section_bytes=window,
        section_view=lambda s: memoryview(window(s)),
        data_bytes=window,
    )


def _each_section_read(image: SimpleNamespace) -> list[int]:
    """The values as the scan read them before: every section on its own."""
    values: set[int] = set()
    for section in image.code_sections():
        values |= api_hashes._code_immediates(image.section_bytes(section), image.is64)
    for section in image.data_sections():
        raw = image.data_bytes(section)
        usable = len(raw) // 4 * 4
        if usable:
            values.update(int(v) for v in np.unique(np.frombuffer(raw[:usable], dtype="<u4")))
    low, high = image.image_base, image.image_base + image.size_of_image
    return sorted(v for v in values if v >= api_hashes._SMALLEST_CANDIDATE and not low <= v < high)


def _blob(seed: int, size: int = 4096) -> bytes:
    rng = random.Random(seed)
    # Weighted to the opcodes the scan reads, so the code ranges give values.
    return bytes(
        rng.choice([0x68, 0xB8, 0x81, 0xC7, 0x3D, 0x00, 0xFF, rng.randrange(256)])
        for _ in range(size)
    )


@pytest.mark.parametrize("seed", range(40))
def test_overlapping_sections_give_the_values_each_read_on_its_own(seed: int) -> None:
    rng = random.Random(seed)
    blob = _blob(seed)
    sections: list[Section] = []
    for _ in range(rng.randrange(1, 14)):
        start = rng.choice([0, 1, 2, 3, 4, 8, 256, 257, 1000, 1001, 2048])
        size = rng.choice([0, 3, 4, 7, 16, 100, 513, 1500, 4096])
        sections.append(
            Section(".s", 0x1000, size, start, size, rng.choice([_EXEC, _DATA, _DATA, 0x60000020]))
        )
    image = _image(sections, blob)

    assert api_hashes.candidate_values(image) == _each_section_read(image)


def test_sections_that_share_a_start_but_differ_in_size_read_the_longest_once(monkeypatch) -> None:  # noqa: ANN001
    blob = _blob(1)
    sections = [Section(f".c{i}", 0x1000, 64 + i * 8, 0, 64 + i * 8, _EXEC) for i in range(200)]
    sections += [Section(f".d{i}", 0x2000, 64 + i * 8, 1024, 64 + i * 8, _DATA) for i in range(200)]
    read: list[int] = []
    real = api_hashes._code_immediates

    def counted(code: bytes, is64: bool) -> set[int]:
        read.append(len(code))
        return real(code, is64)

    monkeypatch.setattr(api_hashes, "_code_immediates", counted)
    image = _image(sections, blob)
    values = api_hashes.candidate_values(image)

    assert read == [64 + 199 * 8]
    assert [r.raw_offset for r in api_hashes._data_ranges(image)] == [1024]
    assert values == _each_section_read(image)


def test_data_ranges_merge_only_within_one_alignment() -> None:
    sections = [
        Section(".a", 0, 100, 0, 100, _DATA),
        Section(".b", 0, 100, 60, 100, _DATA),  # offset 60: same alignment as 0, overlaps .a
        Section(".c", 0, 100, 1, 100, _DATA),  # offset 1: its own alignment
    ]
    ranges = api_hashes._data_ranges(_image(sections, bytes(300)))

    assert sorted((r.raw_offset, r.mapped_size) for r in ranges) == [(0, 160), (1, 100)]


def test_a_built_pe_gives_the_same_values_as_reading_each_section() -> None:
    from tests.unit.tools.synthetic_pe import SyntheticPE

    data = SyntheticPE().build()
    image = pe_image.parse(data)
    values: set[int] = set()
    for section in image.code_sections():
        values |= api_hashes._code_immediates(image.section_bytes(section), image.is64)
    for section in image.data_sections():
        raw = image.data_bytes(section)
        usable = len(raw) // 4 * 4
        if usable:
            values.update(int(v) for v in np.unique(np.frombuffer(raw[:usable], dtype="<u4")))
    low, high = image.image_base, image.image_base + max(image.size_of_image, 1)
    expected = sorted(
        v for v in values if v >= api_hashes._SMALLEST_CANDIDATE and not low <= v < high
    )

    assert api_hashes.candidate_values(image) == expected

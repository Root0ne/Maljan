"""``Image.references`` reads the file once whatever its sections overlap, and finds what it found.

It used to scan every section on its own, so sections shifted one byte from
each other read the file once per section. The bytes under the union of the
sections are now read once; an absolute address is kept where the whole value
lies inside one section, a relative landing is looked up by each section's
own address. The scan it replaced is inlined below and must agree on every
image here. The work is counted (positions read), never timed. Every image is
laid out by the test.
"""

from __future__ import annotations

import random
import struct

import numpy as np
import pytest

from maljan.tools import pe_image
from maljan.tools.pe_image import Image, Section


def _old_references(image: Image, targets: set[int]) -> dict[int, list[int]]:
    found: dict[int, list[int]] = {target: [] for target in targets}
    if not targets:
        return found
    wanted = np.fromiter(sorted(targets), dtype=np.int64)
    for section in image.sections:
        raw = image.section_bytes(section)
        if len(raw) < 4:
            continue
        if image.is64 and section.executable:
            for shift in range(4):
                usable = (len(raw) - shift) // 4 * 4
                if usable <= 0:
                    continue
                disp = np.frombuffer(raw[shift : shift + usable], dtype="<i4").astype(np.int64)
                positions = np.arange(shift, shift + usable, 4, dtype=np.int64)
                landing = section.rva + positions + 4 + disp
                for index in np.nonzero(np.isin(landing, wanted))[0]:
                    found[int(landing[index])].append(section.raw_offset + int(positions[index]))
        width = 8 if image.is64 else 4
        kind = "<u8" if image.is64 else "<u4"
        absolute = {image.image_base + target: target for target in targets}
        wanted_va = np.fromiter(sorted(absolute), dtype=np.uint64)
        for shift in range(width):
            usable = (len(raw) - shift) // width * width
            if usable <= 0:
                continue
            values = np.frombuffer(raw[shift : shift + usable], dtype=kind).astype(np.uint64)
            for index in np.nonzero(np.isin(values, wanted_va))[0]:
                target = absolute[int(values[index])]
                found[target].append(section.raw_offset + shift + int(index) * width)
    for target in found:
        found[target] = sorted(set(found[target]))
    return found


def _image(rng: random.Random, is64: bool) -> tuple[Image, set[int]]:
    """Sections that overlap, repeat, touch, run short or lie apart, with references planted."""
    size = rng.choice([64, 700, 5000])
    base = 0x140000000 if is64 else 0x400000
    data = bytearray(rng.randbytes(size))
    targets = {rng.randrange(0x1000, 0x9000) for _ in range(12)}
    sections = []
    for index in range(rng.randint(1, 10)):
        low = rng.randrange(0, size)
        length = rng.choice([0, 3, 4, 7, 8, 9, rng.randrange(0, size - low + 1)])
        rva = rng.choice([0x1000, 0x1000 + low, 0x2000 * (index + 1)])
        flags = rng.choice([0x60000020, 0x40000040])
        sections.append(Section(f".s{index}", rva, length, low, length, flags))
    for _ in range(40):
        at = rng.randrange(0, max(1, size - 8))
        target = rng.choice(sorted(targets))
        section = rng.choice(sections)
        if rng.random() < 0.5 and is64:
            disp = target - (section.rva + (at - section.raw_offset) + 4)
            data[at : at + 4] = struct.pack("<i", max(-(2**31), min(2**31 - 1, disp)))
        elif is64:
            data[at : at + 8] = struct.pack("<Q", base + target)
        else:
            data[at : at + 4] = struct.pack("<I", base + target)
    image = Image(
        data=bytes(data[:size]),
        image_base=base,
        is64=is64,
        size_of_image=0x100000,
        sections=sections,
    )
    return image, targets


@pytest.mark.parametrize("seed", range(40))
def test_the_references_are_the_ones_the_section_scan_found(seed: int) -> None:
    rng = random.Random(seed)
    image, targets = _image(rng, is64=seed % 3 != 0)
    assert image.references(targets) == _old_references(image, targets)


def test_a_window_smaller_than_the_sections_finds_the_same(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pe_image, "_SCAN_WORDS", 7)
    for seed in range(15):
        image, targets = _image(random.Random(seed), is64=True)
        assert image.references(targets) == _old_references(image, targets)


def test_sections_shifted_one_byte_read_the_file_once() -> None:
    rng = random.Random(9)
    size, count, length = 1 << 16, 300, 1 << 15
    data = rng.randbytes(size)
    sections = [
        Section(f".s{k}", 0x1000 + k * 0x10000, length, k, length, 0x60000020) for k in range(count)
    ]
    image = Image(
        data=data,
        image_base=0x140000000,
        is64=True,
        size_of_image=0x10000000,
        sections=sections,
    )
    targets = {0x1000 + rng.randrange(0, 0x100000) for _ in range(20)}
    pe_image.WORK.clear()
    found = image.references(targets)
    # Once for the absolute values, once for the relative landings.
    assert pe_image.WORK["positions"] <= 2 * size
    assert found == _old_references(image, targets)


def test_shifted_sections_with_one_delta_look_each_place_up_once() -> None:
    """512 executable sections one byte apart, each at its own offset plus one fixed
    difference: every place lands the same way under each, so it is looked up and
    stated once, not once per section."""
    import tracemalloc

    size, count, length = 1 << 16, 512, 1 << 15
    data = bytes(size)  # every displacement zero: a place lands four bytes on
    delta = 0x1000
    sections = [Section(f".t{k}", delta + k, length, k, length, 0x60000020) for k in range(count)]
    image = Image(
        data=data,
        image_base=0x140000000,
        is64=True,
        size_of_image=0x10000000,
        sections=sections,
    )
    targets = {delta + place + 4 for place in range(0, size, 64)}
    pe_image.WORK.clear()
    tracemalloc.start()
    try:
        found = image.references(targets)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    distinct_deltas = 1
    positions = pe_image.WORK["positions"]
    assert positions <= 2 * size
    assert pe_image.WORK["appends"] <= positions * distinct_deltas
    windows = -(-size // pe_image._SCAN_WORDS)
    assert pe_image.WORK["lookups"] <= windows * distinct_deltas * len(targets) * 2
    # The file's working arrays and the places found, not the sections times them.
    assert peak <= 64 * size + 200 * sum(len(v) for v in found.values())
    assert found == _old_references(image, targets)

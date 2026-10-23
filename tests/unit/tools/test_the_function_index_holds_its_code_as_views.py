"""The function index reads its code sections as views of the file and marks only what it walks.

``function_index`` copied every executable section's bytes and made a mark
array of the same size per section for each of its two walks, so N sections
naming a whole file of size S cost about 3 x N x S bytes (200 sections over
4 MB took 1.6 GB). The sections are now views of the file's bytes, a second
section starting at the same address is not viewed (its bytes never answered
for that address), and the marks are made a page at a time where the walk
goes. Memory is counted (bytes held for marks, bytes copied), never timed.
The image is laid out by the test; nothing is a real program.
"""

from __future__ import annotations

import random
from typing import Any

import pytest

from maljan.tools import artefact_index
from maljan.tools.pe_image import Image, Section


def _image(count: int, size: int, same_address: bool = False) -> Image:
    """``count`` executable sections, each naming the whole file, a short function in each."""
    rng = random.Random(count)
    data = bytearray(rng.randbytes(size))
    rvas = [0x1000 if same_address else 0x1000 + index * size for index in range(count)]
    # Every section starts at file offset 0: a load, a call and a return there.
    data[0:16] = b"\x48\x8d\x0d\x00\x00\x00\x00\xe8\x00\x00\x00\x00\x90\x90\x90\xc3"
    sections = [Section(f".t{i}", rva, size, 0, size, 0x60000020) for i, rva in enumerate(rvas)]
    starts = sorted(set(rvas))
    return Image(
        data=bytes(data),
        image_base=0x140000000,
        is64=True,
        size_of_image=max(rvas) + size,
        sections=sections,
        function_starts=starts,
        function_ends=[start + 16 for start in starts],
        function_owners=list[int | None](starts),
    )


def _held(image: Image, monkeypatch: pytest.MonkeyPatch) -> tuple[dict[str, Any], int, list[Any]]:
    """The index of ``image``, the bytes its marks held, and its readers' code."""
    pages = [0]
    readers: list[Any] = []
    real_set = artefact_index._Marks.__setitem__
    real_run = artefact_index._Reader.run

    def counted(self: artefact_index._Marks, at: int, value: int) -> None:
        before = len(self.pages)
        real_set(self, at, value)
        pages[0] += len(self.pages) - before

    def kept(self: artefact_index._Reader) -> object:
        readers.append(self)
        return real_run(self)

    monkeypatch.setattr(artefact_index._Marks, "__setitem__", counted)
    monkeypatch.setattr(artefact_index._Reader, "run", kept)
    answer = artefact_index.index_image(image)
    monkeypatch.undo()
    return answer, pages[0] * artefact_index._MARK_PAGE, readers


def test_many_sections_over_one_file_hold_no_copy_and_mark_what_is_walked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    size = 1 << 20
    one, one_marks, _ = _held(_image(1, size), monkeypatch)
    many, many_marks, readers = _held(_image(64, size), monkeypatch)
    assert one_marks > 0
    # A page per section walked per walk, not the section's size.
    assert many_marks <= 64 * 2 * artefact_index._MARK_PAGE
    assert many_marks < 64 * size // 4
    for code in readers[0].code.values():
        assert isinstance(code, memoryview)
        assert code.obj is readers[0].image.data
    assert many["functions_known"] == 64 * one["functions_known"]


def test_a_section_at_an_address_another_already_holds_is_not_viewed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    answer, _, readers = _held(_image(50, 1 << 16, same_address=True), monkeypatch)
    assert list(readers[0].code) == [0x1000]
    single, _, _ = _held(_image(1, 1 << 16), monkeypatch)
    assert answer == single

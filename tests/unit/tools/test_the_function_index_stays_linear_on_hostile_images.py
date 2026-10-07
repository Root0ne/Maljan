"""The function index stays linear on an image built to make it work hard.

A sample chooses its own function table, its calls and its references. Each
image here is laid out in memory by the test (``Image`` with a ``.text`` and a
``.data`` section; no PE file and no real program): a cyclic call graph, a
chain of call targets no table lists, a wide fan-out, one function holding
many artefacts called from many places, a function table whose ranges all
overlap, and an answer that repeats one place many times. Each must finish,
without recursion, in time that grows with the functions and the calls, not
with their product.
"""

from __future__ import annotations

import struct
import time
from collections.abc import Callable
from typing import Any

from maljan.tools import function_index
from maljan.tools.pe_image import Image, Section

BASE = 0x140000000
TEXT_RVA = 0x1000
TEXT_RAW = 0x400


def _lea(at: int, target: int) -> bytes:
    """``lea rcx, [rip+disp32]`` at ``at`` taking ``target``."""
    return b"\x48\x8d\x0d" + struct.pack("<i", target - (at + 7))


def _call(at: int, target: int) -> bytes:
    return b"\xe8" + struct.pack("<i", target - (at + 5))


def _image(
    sizes: list[int],
    body: Callable[[int, int, Callable[[int], int], int], bytes],
    texts: list[bytes],
    *,
    table: list[tuple[int, int]] | None = None,
) -> Image:
    """An x64 image of functions of ``sizes`` bytes, function i's bytes ``body(i, start, …)``.

    ``body`` is handed the function's index, its start, the start of any
    function by index, and the RVA of ``.data``, where ``texts`` are laid out
    one after another, each ending in NUL. ``table`` is the exception
    directory's ranges; ``None`` lists every function by its own range.
    """
    starts: list[int] = []
    cursor = TEXT_RVA
    for size in sizes:
        starts.append(cursor)
        cursor += size
    code_size = cursor - TEXT_RVA
    data_rva = TEXT_RVA + ((code_size + 0xFFF) // 0x1000) * 0x1000
    code = bytearray()
    for index, size in enumerate(sizes):
        piece = body(index, starts[index], starts.__getitem__, data_rva)
        assert len(piece) <= size
        code += piece + b"\xcc" * (size - len(piece))
    data_bytes = b"".join(text + b"\0" for text in texts)
    data = bytes(TEXT_RAW) + bytes(code) + bytes(data_rva - TEXT_RVA - len(code)) + data_bytes
    sections = [
        Section(".text", TEXT_RVA, len(code), TEXT_RAW, len(code), 0x60000020),
        Section(
            ".data",
            data_rva,
            len(data_bytes),
            TEXT_RAW + data_rva - TEXT_RVA,
            len(data_bytes),
            0x40000040,
        ),
    ]
    ranges = (
        table if table is not None else [(s, s + z) for s, z in zip(starts, sizes, strict=True)]
    )
    ranges = sorted(ranges)
    return Image(
        data=data,
        image_base=BASE,
        is64=True,
        size_of_image=data_rva + 0x1000 + len(data_bytes),
        sections=sections,
        function_starts=[r[0] for r in ranges],
        function_ends=[r[1] for r in ranges],
        function_owners=[r[0] for r in ranges],
    )


def pe_bytes(image: Image) -> bytes:
    """``image`` written out as a PE file: its sections, then its function table as ``.pdata``.

    For the tests that hand a hostile image to a tool through a path. The
    headers are the minimum ``pe_image.parse`` reads; nothing here is a real
    program.
    """
    sections = [(s, image.data[s.raw_offset : s.raw_offset + s.raw_size]) for s in image.sections]
    table = b"".join(
        struct.pack("<III", begin, end, 0)
        for begin, end in zip(image.function_starts, image.function_ends, strict=True)
    )
    last = max(s.rva + max(s.virtual_size, s.raw_size) for s, _ in sections)
    pdata_rva = (last + 0xFFF) // 0x1000 * 0x1000
    named = [(s.name, s.rva, body, s.characteristics) for s, body in sections]
    if table:
        named.append((".pdata", pdata_rva, table, 0x40000040))
    headers = 0x400
    header = bytearray(headers)
    header[0:2] = b"MZ"
    struct.pack_into("<I", header, 0x3C, 0x80)
    struct.pack_into("<4sHHIIIHH", header, 0x80, b"PE\0\0", 0x8664, len(named), 0, 0, 0, 0xF0, 0x22)
    optional = 0x80 + 24
    struct.pack_into("<H", header, optional, 0x20B)
    struct.pack_into("<I", header, optional + 16, image.sections[0].rva)  # entry point
    struct.pack_into("<Q", header, optional + 24, image.image_base)
    struct.pack_into("<II", header, optional + 32, 0x1000, 0x200)
    size = pdata_rva + ((len(table) + 0xFFF) // 0x1000) * 0x1000 + 0x1000
    struct.pack_into("<I", header, optional + 56, size)
    struct.pack_into("<I", header, optional + 60, headers)
    struct.pack_into("<I", header, optional + 108, 16)
    if table:
        struct.pack_into("<II", header, optional + 112 + 3 * 8, pdata_rva, len(table))
    bodies = bytearray()
    raw = headers
    for index, (name, rva, body, flags) in enumerate(named):
        padded = len(body) + (-len(body)) % 0x200
        struct.pack_into(
            "<8sIIIIIIHHI",
            header,
            optional + 0xF0 + 40 * index,
            name.encode(),
            len(body),
            rva,
            padded,
            raw,
            0,
            0,
            0,
            0,
            flags,
        )
        bodies += body + bytes(padded - len(body))
        raw += padded
    return bytes(header) + bytes(bodies)


def _timed(make: Callable[[int], tuple[Image, dict[str, Any]]], n: int) -> tuple[float, Any]:
    image, joined = make(n)
    began = time.perf_counter()
    answer = function_index.index_image(image, **joined)
    return time.perf_counter() - began, answer


def _text_offsets(texts: list[bytes]) -> list[int]:
    offsets, cursor = [], 0
    for text in texts:
        offsets.append(cursor)
        cursor += len(text) + 1
    return offsets


# -- the shapes ---------------------------------------------------------------


def _cycle(n: int) -> tuple[Image, dict[str, Any]]:
    """Function i loads its text, calls i+1 (the last calls the first), calls itself, returns."""
    texts = [f"text of function {i:06d}".encode() for i in range(n)]
    places = _text_offsets(texts)

    def body(i: int, start: int, at: Callable[[int], int], data: int) -> bytes:
        out = _lea(start, data + places[i])
        out += _call(start + 7, at((i + 1) % n))
        out += _call(start + 12, start)
        return out + b"\xc3"

    return _image([18] * n, body, texts), {}


def _chain(n: int) -> tuple[Image, dict[str, Any]]:
    """No table: the entry point calls a function that calls the next, ``n`` deep."""
    texts = [b"a text the chain loads"]

    def body(i: int, start: int, at: Callable[[int], int], data: int) -> bytes:
        out = _lea(start, data)
        if i + 1 < n:
            out += _call(start + 7, at(i + 1))
        return out + b"\xc3"

    image = _image([13] * n, body, texts, table=[])
    return image, {"pe_info": ("ev_0004", {"entry_point": TEXT_RVA, "export_rows": []})}


def _fan_out(n: int) -> tuple[Image, dict[str, Any]]:
    """Function 0 loads a text and calls every other function once; each of those loads it too."""
    texts = [b"a text every callee loads"]

    def body(i: int, start: int, at: Callable[[int], int], data: int) -> bytes:
        if i == 0:
            out = _lea(start, data)
            out += b"".join(_call(start + 2 + 5 * k, at(k)) for k in range(1, n))
            return out + b"\xc3"
        return _lea(start, data) + b"\xc3"

    return _image([5 * n + 8] + [8] * (n - 1), body, texts), {}


def _fan_in(n: int, held: int = 2_000) -> tuple[Image, dict[str, Any]]:
    """Function 0 loads ``held`` distinct texts; every other function loads one and calls it."""
    texts = [f"text {k:05d} the hub holds".encode() for k in range(held)]
    places = _text_offsets(texts)

    def body(i: int, start: int, at: Callable[[int], int], data: int) -> bytes:
        if i == 0:
            out = b"".join(_lea(start + 7 * k, data + places[k]) for k in range(held))
            return out + b"\xc3"
        return _lea(start, data) + _call(start + 7, at(0)) + b"\xc3"

    return _image([7 * held + 1] + [13] * (n - 1), body, texts), {}


def _overlapping(n: int) -> tuple[Image, dict[str, Any]]:
    """``n`` table entries, each from its own start to the end of the code: all overlap."""
    texts = [b"a text every function loads"]

    def body(i: int, start: int, at: Callable[[int], int], data: int) -> bytes:
        return _lea(start, data) + b"\x90"

    end = TEXT_RVA + 8 * n
    table = [(TEXT_RVA + 8 * i, end) for i in range(n)]
    return _image([8] * n, body, texts, table=table), {}


def _dense(n: int, degree: int = 8) -> tuple[Image, dict[str, Any]]:
    """Function i loads a text and calls the ``degree`` functions after it, wrapping around."""
    texts = [b"a text every function loads"]

    def body(i: int, start: int, at: Callable[[int], int], data: int) -> bytes:
        out = _lea(start, data)
        for k in range(1, degree + 1):
            out += _call(start + len(out), at((i + k) % n))
        return out + b"\xc3"

    return _image([8 + 5 * degree] * n, body, texts), {}


def _into_one_run(n: int, length: int = 200_000) -> tuple[Image, dict[str, Any]]:
    """One long printable run; function i loads the address ``i * step`` bytes into it."""
    texts = [b"A" * length]
    step = max(1, length // n)

    def body(i: int, start: int, at: Callable[[int], int], data: int) -> bytes:
        return _lea(start, data + i * step) + b"\xc3"

    return _image([8] * n, body, texts), {}


# -- the tests ----------------------------------------------------------------


class TestEveryShapeFinishes:
    def test_references_into_one_long_text_read_it_once_from_its_start(self) -> None:
        _, answer = _timed(_into_one_run, 20_000)
        # Only the reference to where the text starts reads it; the others
        # point inside it and read nothing.
        assert answer["total"] == 1
        (cells,) = [row["plain_strings"] for row in answer["rows"]]
        assert len(cells[0]["text"]) == 200_000

    def test_a_cyclic_graph_with_self_calls_ends_and_counts_each_callee_once(self) -> None:
        _, answer = _timed(_cycle, 2_000)
        assert answer["total"] == 2_000
        first = answer["rows"][0]
        assert first["callees"] == [hex(BASE + TEXT_RVA), hex(BASE + TEXT_RVA + 18)]
        # Itself is not a callee whose artefacts it reaches.
        assert first["indirect"] == {"artefacts": 1, "through": 1}
        assert first["callers"] == [hex(BASE + TEXT_RVA + 18 * 1_999)]

    def test_a_deep_chain_no_table_lists_is_followed_without_recursion(self) -> None:
        _, answer = _timed(_chain, 30_000)
        assert answer["functions_known"] == 30_000
        assert answer["function_sources"]["call targets the decoder reached"] == 29_999
        assert answer["total"] == 30_000

    def test_a_wide_fan_out_is_one_row_with_every_callee(self) -> None:
        _, answer = _timed(_fan_out, 20_000)
        hub = next(r for r in answer["rows"] if r["offset"] == hex(TEXT_RVA))
        assert len(hub["callees"]) == 19_999
        assert hub["indirect"] == {"artefacts": 19_999, "through": 19_999}

    def test_one_function_holding_many_artefacts_called_from_many_places(self) -> None:
        _, answer = _timed(_fan_in, 20_000)
        hub = answer["rows"][0]
        assert hub["direct"] == 2_000 and len(hub["callers"]) == 19_999
        # Each caller's callee holds 2,000 artefacts: counted once per callee,
        # in one step, not compared text by text with the caller's own.
        assert answer["rows"][1]["indirect"] == {"artefacts": 2_000, "through": 1}
        assert answer["total"] == 20_000

    def test_overlapping_table_ranges_read_each_byte_once(self) -> None:
        _, answer = _timed(_overlapping, 20_000)
        # The first range reads the whole code; every later one starts on a
        # byte already read, and holds what it read itself: nothing.
        assert answer["functions_known"] == 20_000
        assert answer["total"] == 1

    def test_one_place_repeated_many_times_is_one_cell(self) -> None:
        image, _ = _cycle(10)
        place = {"rva": hex(TEXT_RVA + 2), "function": hex(TEXT_RVA)}
        hit = {
            "readings": [{"set": "exports", "name": "OpenThing"}],
            "occurrences": [place] * 20_000,
        }
        answer = function_index.index_image(image, hashes=("ev_0020", {"hits": [hit] * 5}))
        first = next(r for r in answer["rows"] if r["offset"] == hex(TEXT_RVA))
        assert first["resolved"] == [{"name": "OpenThing", "sources": ["ev_0020"]}]


class TestTheCostGrowsWithTheFunctionsAndTheCalls:
    """Ten times the functions take about ten times as long; a quadratic step would be a hundred."""

    def test_a_dense_fan_out_at_one_ten_and_a_hundred_thousand_functions(self) -> None:
        seconds = {n: _timed(_dense, n)[0] for n in (1_000, 10_000, 100_000)}
        print("dense fan-out, 8 calls a function:", {n: round(s, 3) for n, s in seconds.items()})
        assert seconds[100_000] < seconds[10_000] * 30

    def test_many_callers_of_one_function_holding_many_artefacts(self) -> None:
        small = min(_timed(_fan_in, 2_000)[0] for _ in range(2))
        large = _timed(_fan_in, 20_000)[0]
        print("fan-in to a function of 2,000 artefacts:", round(small, 3), round(large, 3))
        assert large < small * 30

    def test_references_into_one_long_text(self) -> None:
        small = min(_timed(_into_one_run, 2_000)[0] for _ in range(2))
        large = _timed(_into_one_run, 20_000)[0]
        print("references into one 200,000-byte text:", round(small, 3), round(large, 3))
        assert large < small * 30

    def test_overlapping_table_ranges(self) -> None:
        small = min(_timed(_overlapping, 2_000)[0] for _ in range(2))
        large = _timed(_overlapping, 20_000)[0]
        print("overlapping table ranges:", round(small, 3), round(large, 3))
        assert large < small * 30

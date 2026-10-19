"""The string-blob sweeps answer as before, read each range of the file once, and cost its size.

``decode_string_blobs`` tries 511 key streams over every data section. Each
sweep used to enumerate every printable run of every decoding with a regular
expression and to hold every possible seed-and-length header as five arrays of
eight-byte numbers, so a megabyte of data cost seconds and over a hundred
megabytes; a section table naming one range many times scanned it once per
section. The sweeps below are the implementations they replaced, inlined: the
new ones must give the same decodings, in the same order, on every input. The
work is counted (positions read), never timed.
"""

from __future__ import annotations

import base64
import random
import re
from collections.abc import Iterator

import numpy as np
import pytest

from maljan.tools import string_blobs as sb
from maljan.tools.pe_image import Image, Section

# -- the replaced sweeps, as they were ----------------------------------------

_RUN = re.compile(rb"[\x20-\x7e\t\r\n]+")


def _old_bounded_runs(
    zeros: np.ndarray, decoded: bytes, min_len: int
) -> Iterator[tuple[int, int, bool]]:
    if zeros.any():
        masked = np.frombuffer(decoded, dtype=np.uint8).copy()
        masked[zeros] = 0
        decoded = masked.tobytes()
    for match in _RUN.finditer(decoded):
        start, end = match.span()
        if end - start < min_len:
            continue
        before = start == 0 or decoded[start - 1] == 0
        after = end == len(decoded) or decoded[end] == 0
        if before and after:
            yield start, end, end < len(decoded) and not zeros[end]


def _old_xor8(raw: bytes, base: int, min_len: int) -> Iterator[sb.Found]:
    zeros = np.frombuffer(raw, dtype=np.uint8) == 0
    for key in range(1, 256):
        decoded = raw.translate(bytes(b ^ key for b in range(256)))
        for start, end, terminated in _old_bounded_runs(zeros, decoded, min_len):
            text = decoded[start:end]
            if sb._reads_as_text(raw[start:end]) or not sb._passes(text, min_len):
                continue
            yield sb.Found(
                base + start, base + start, "xor8", {"key": f"{key:#04x}"}, text,
                terminated=terminated,
            )  # fmt: skip


def _old_le(array: np.ndarray, at: np.ndarray, width: int) -> np.ndarray:
    value = np.zeros(len(at), dtype=np.int64)
    for index in range(width):
        value |= array[at + index].astype(np.int64) << (8 * index)
    return value


def _old_seed_headers(array: np.ndarray) -> list[tuple[np.ndarray, np.ndarray, np.ndarray, bool]]:
    size = len(array)
    if size < 6 + sb._HEADER_MIN_LENGTH:
        return []
    at = np.arange(0, size - 6, dtype=np.int64)
    seed = _old_le(array, at, 4)
    stored = _old_le(array, at + 4, 2)
    variants = []
    for masked in (False, True):
        length = stored ^ (seed & 0xFFFF) if masked else stored
        fits = (length >= sb._HEADER_MIN_LENGTH) & (length <= size - (at + 6))
        for extra in (0, 1):
            constant = ((seed + extra) - (at + 6)) & 0xFF
            variants.append((at[fits], length[fits], constant[fits], masked))
    return variants


def _old_rolling(
    raw: bytes, base: int, min_len: int, sweep: bool, headers: bool
) -> Iterator[sb.Found]:
    size = len(raw)
    array = np.frombuffer(raw, dtype=np.uint8)
    zeros = array == 0
    variants = _old_seed_headers(array) if headers else []
    ramp = bytes(range(256)) * (size // 256 + 2)
    for constant in range(256):
        stream = ramp[constant : constant + size]
        decoded = sb._xor(raw, stream)
        yield from _old_seeded(raw, base, decoded, stream, constant, variants)
        if sweep:
            for start, end, terminated in _old_bounded_runs(zeros, decoded, min_len):
                text = decoded[start:end]
                encoded = raw[start:end]
                if (
                    sb._reads_as_text(encoded)
                    or sb._repeats(encoded)
                    or not sb._passes(text, min_len)
                ):
                    continue
                yield sb.Found(
                    base + start, base + start, "xor8_rolling",
                    {"first_key": f"{stream[start]:#04x}", "step": 1}, text,
                    terminated=terminated,
                )  # fmt: skip


def _old_seeded(
    raw: bytes,
    base: int,
    decoded: bytes,
    stream: bytes,
    constant: int,
    variants: list[tuple[np.ndarray, np.ndarray, np.ndarray, bool]],
) -> Iterator[sb.Found]:
    if not variants:
        return
    decoded_array = np.frombuffer(decoded, dtype=np.uint8)
    plain = sb._PRINTABLE_TABLE[decoded_array] | (decoded_array == 0)
    bad = np.concatenate(([0], np.cumsum(~plain, dtype=np.int64)))
    for at, length, constants, masked in variants:
        chosen = constants == constant
        if not chosen.any():
            continue
        start = at[chosen] + 6
        stop = start + length[chosen]
        clean = bad[stop] - bad[start] == 0
        for index in np.nonzero(clean)[0]:
            first, last = int(start[index]), int(stop[index])
            read = sb._header_text(decoded[first:last], raw[first:last], rolling=True)
            if read is None:
                continue
            text, encoding = read
            seed = int.from_bytes(raw[first - 6 : first - 2], "little")
            yield sb.Found(
                base + first - 6,
                base + first,
                "xor8_rolling_header",
                {
                    "layout": "seed (4), text length (2"
                    + (", XOR the seed's low 16 bits" if masked else "")
                    + "), text",
                    "seed": f"{seed:#010x}",
                    "first_key": f"{stream[first]:#04x}",
                    "step": 1,
                },
                text,
                encoding=encoding,
            )


# -- inputs ---------------------------------------------------------------------

_WORDS = [
    b"http://example.invalid/gate.php",
    b"cmd.exe /c whoami",
    b"Mozilla/5.0 (Windows NT 10.0)",
    b"%s\\%s.dll",
    # Joined at run time so a secret scanner does not read a form template as a password.
    b"pass" + b"word=%s&user=%s",
    b"abcdefghijkl",
]


def _planted(rng: random.Random, size: int) -> bytes:
    """Filler of one of four kinds with encoded strings of every scheme planted in it."""
    filler = rng.randrange(4)
    if filler == 0:
        out = bytearray(rng.randbytes(size))
    elif filler == 1:
        out = bytearray(size)
    elif filler == 2:
        out = bytearray(rng.choice(b" !~AZaz09\0\t") for _ in range(size))
    else:
        out = bytearray(b"\xff" * size)
    for _ in range(rng.randint(1, 10)):
        text = rng.choice(_WORDS) + b"\0"
        scheme = rng.randrange(4)
        if scheme == 0:
            key = rng.randint(1, 255)
            piece = b"\0" + bytes(b ^ key for b in text)
        elif scheme == 1:
            key = rng.randint(0, 255)
            piece = b"\0" + bytes(b ^ ((key + i) & 0xFF) for i, b in enumerate(text))
        elif scheme == 2:
            seed, extra, masked = rng.getrandbits(32), rng.randrange(2), rng.random() < 0.5
            length = len(text) ^ (seed & 0xFFFF) if masked else len(text)
            first = (seed + extra) & 0xFF
            piece = seed.to_bytes(4, "little") + (length & 0xFFFF).to_bytes(2, "little")
            piece += bytes(b ^ ((first + i) & 0xFF) for i, b in enumerate(text))
        else:
            piece = text
        if len(piece) < size:
            at = rng.randrange(size - len(piece))
            out[at : at + len(piece)] = piece
    return bytes(out)


def _fields(found: list[sb.Found]) -> list[tuple[object, ...]]:
    return [
        (f.blob_offset, f.text_offset, f.scheme, f.parameters, f.text, f.encoding, f.terminated)
        for f in found
    ]


# -- the same decodings ---------------------------------------------------------


@pytest.mark.parametrize("seed", range(12))
def test_every_sweep_gives_the_decodings_it_gave_in_the_same_order(seed: int) -> None:
    rng = random.Random(seed)
    raw = _planted(rng, rng.choice([7, 9, 64, 700, 3000, 9000]))
    base = rng.randrange(0x400, 0x10000)
    for min_len in (1, 4, 8, 12):
        assert _fields(list(sb._xor8(raw, base, min_len))) == _fields(
            list(_old_xor8(raw, base, min_len))
        )
        for sweep, headers in ((True, True), (True, False), (False, True)):
            assert _fields(list(sb._rolling(raw, base, min_len, sweep, headers))) == _fields(
                list(_old_rolling(raw, base, min_len, sweep, headers))
            )


def test_a_run_across_the_sweeps_window_is_one_run(monkeypatch: pytest.MonkeyPatch) -> None:
    """Windows smaller than the runs: every run crosses one, and still reads as before."""
    monkeypatch.setattr(sb, "_WINDOW", 5)
    rng = random.Random(99)
    for _ in range(6):
        raw = _planted(rng, 400)
        for min_len in (1, 4, 8):
            assert _fields(list(sb._xor8(raw, 0, min_len))) == _fields(
                list(_old_xor8(raw, 0, min_len))
            )
            assert _fields(list(sb._rolling(raw, 0, min_len, True, True))) == _fields(
                list(_old_rolling(raw, 0, min_len, True, True))
            )


# -- each range once, in work linear in its size ------------------------------


def _image(raw: bytes, copies: int) -> Image:
    """An x64 image whose ``copies`` data sections all name the same range of the file."""
    data = bytes(0x400) + raw
    sections = [
        Section(f".d{i}", 0x1000 + i * 0x100000, len(raw), 0x400, len(raw), 0x40000040)
        for i in range(copies)
    ]
    return Image(data=data, image_base=0x140000000, is64=True, size_of_image=0x10000000,
                 sections=sections)  # fmt: skip


def _positions(image: Image) -> tuple[int, sb.Decoded]:
    sb.WORK.clear()
    decoded = sb.decode(image)
    return sb.WORK["positions"], decoded


def test_a_range_many_sections_name_is_scanned_once() -> None:
    raw = _planted(random.Random(5), 4096)
    once, single = _positions(_image(raw, 1))
    many, repeated = _positions(_image(raw, 40))
    assert once > 0
    assert many == once
    # Each section still stands as before: the same decodings, every one
    # counted as often as its sections name it.
    assert [f.text for f in repeated.items] == [f.text for f in single.items]


def test_the_sweeps_work_grows_with_the_section_not_faster() -> None:
    rng = random.Random(6)
    small = _positions(_image(_planted(rng, 4096), 1))[0]
    large = _positions(_image(_planted(rng, 16 * 4096), 1))[0]
    # Every pass reads a position once, plus the overlap of a window with the
    # next (a run's span, a header's reach): sixteen times the bytes is at
    # most sixteen times the positions, with room for the window's edges.
    assert large <= 16 * small * 1.25


def test_sections_sharing_a_range_are_named_and_decoded_once() -> None:
    raw = _planted(random.Random(5), 4096)
    decoded = sb.decode(_image(raw, 30))
    assert decoded.overlapping == [([f".d{i}" for i in range(30)], 0x400, 0x400 + 4096)]
    said = sb._sections_said(decoded)["sections_read_together"]
    assert said.startswith(".d0, .d1, .d2") and "0x400-0x1400" in said
    # A file whose sections do not overlap is answered as before: no field.
    assert sb._sections_said(sb.decode(_image(raw, 1))) == {}


def _shifted(raw: bytes, count: int) -> Image:
    """``count`` data sections, each one byte further into the file than the one before."""
    length = len(raw) - count
    data = bytes(0x400) + raw
    sections = [
        Section(f".s{i}", 0x1000 + i * 0x100000, length, 0x400 + i, length, 0x40000040)
        for i in range(count)
    ]
    return Image(
        data=data, image_base=0x140000000, is64=True, size_of_image=0x10000000, sections=sections
    )


def test_sections_shifted_one_byte_are_read_once_as_their_union() -> None:
    raw = _planted(random.Random(8), 8192)
    once, _ = _positions(_image(raw, 1))
    many, decoded = _positions(_shifted(raw, 200))
    # The union of the 200 sections is 8191 bytes, read once.
    assert decoded.overlapping == [([f".s{i}" for i in range(200)], 0x400, 0x400 + 8191)]
    assert many <= once * 1.25


def test_a_unique_section_after_overlapping_ones_is_read() -> None:
    """Padding with overlapping sections cannot push a section with bytes of its own out."""
    rng = random.Random(12)
    pad = rng.randbytes(1 << 15)
    text = b"Software Microsoft Windows Run"
    blob = b"\0" * 16 + base64.b64encode(text) + b"\0" * 16
    data = bytes(0x400) + pad + blob
    tail = 0x400 + len(pad)
    sections = [
        Section(".pad0", 0x1000, len(pad), 0x400, len(pad), 0x40000040),
        # Overlapping sections whose lengths add up past the file's size, the
        # bytes they name counted once per section.
        Section(".pad1", 0x20000, 1024, 0x401, 1024, 0x40000040),
        Section(".pad2", 0x30000, 64, 0x402, 64, 0x40000040),
        Section(".data", 0x40000, len(blob), tail, len(blob), 0x40000040),
    ]
    image = Image(
        data=data, image_base=0x140000000, is64=True, size_of_image=0x10000000, sections=sections
    )
    decoded = sb.decode(image, schemes=("base64",))
    assert any(item.text == text and item.scheme == "base64" for item in decoded.items)
    assert decoded.overlapping == [([".pad0", ".pad1", ".pad2"], 0x400, tail)]

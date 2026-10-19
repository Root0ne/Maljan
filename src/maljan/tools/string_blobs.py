"""Text a PE keeps encoded in its data sections, decoded statically by generic schemes.

FLOSS recovers the strings a sample decodes by emulating the sample's own
decoding routines, and when the emulation does not reach a routine — the
routine needs an argument it cannot guess, or the decoded text lands where the
emulator does not look — those strings stay encoded. Many samples encode them
with one of a handful of simple schemes, and those can be undone without
running anything: this tool tries each scheme over the bytes of every
non-executable section and reports what reads as text. Nothing is executed or
emulated; every decoding is arithmetic over the file's bytes.

The schemes, each named in the answer with its parameters:

* ``xor8`` — every byte XOR one key byte (1–255).
* ``xor8_rolling`` — XOR a key byte that increases by one per byte; the
  parameter is the key at the text's first byte.
* ``xor_keyed_header`` — XOR with a repeating key of up to 32 bytes stored in
  front of the text, in one of three layouts: key length (one byte), key, text
  ending at a decoded NUL; key length, key, text length (two bytes), text; key
  length, key, text length (four bytes), text.
* ``xor8_rolling_header`` — the rolling key with a header in front of the text:
  a 32-bit seed followed by a 16-bit text length stored plain or XOR the seed's
  low 16 bits, the key starting at the seed's low byte or one past it. A
  header that states only a length leaves the starting key to be guessed from
  256, and that finds text in random bytes too often to be reported.
* ``base64`` — a base64 run among the plain strings of those sections, and a
  base64 layer on top of any text decoded above (reported under ``layers``).

A header that states the text's length carries structure of its own. When
the stated span ends exactly in the text's own terminator — one NUL, or a NUL
pair for UTF-16LE — and holds no other NUL, the header and the decoded bytes
agree on where the text ends, and the span is accepted when its characters are
printable, at least half letters or digits, not a repeated pattern, changed by
the key at half its bytes or more, and at least three characters long under the
seed-and-length header (tried four ways at each offset) or six under a stored
key (tried at every key length). A format string, a command line or a user
agent passes; none of the vetoes below applies to such a span, because they
exist for text whose ends nothing but the surrounding bytes mark. Measured on
54 benign PEs of this project's host, the rule and the tightened test below
together report six decodings no program wrote.

What reads as text for every other decoding, the stated test it passes before
it is reported:

* printable ASCII (0x20–0x7E, tab, CR, LF) throughout, trailing NULs aside,
  or, where a header states the length, UTF-16LE whose characters are;
* at least ``min_len`` (eight by default) characters when nothing but the
  surrounding bytes marks where the text starts and ends (``xor8``,
  ``xor8_rolling``: the text must be bounded on both sides by a decoded NUL, a
  zero byte or the section's edge; and the stored-key layout that runs to a
  NUL), four under a seed-and-length header and six under a stored key;
* at least half of it letters or digits, at least four distinct characters
  (three for a four-character text), no character more than half of it (a
  third from eight characters on), and, from twelve characters on, no
  three-character sequence at more than a quarter of its positions;
* few changes of character class — lower case, upper case, digit, space and
  punctuation, a capital before lower case not counting — at most one per
  three characters, which is how words, numbers, paths and URLs read and how
  random bytes do not;
* from six characters on, no step between neighbouring characters shared by
  more than a third of them: a counter or an index under a key reads
  "defghijk";
* base64 whose decoded content passes the test is accepted in place of text
  and reported with that content under ``layers``.

And the encoded bytes under the text:

* hold no zero byte (a key over zeros is the key itself; in a sweep a zero byte
  is a boundary);
* do not already hold text — four in five printable, or one readable run over
  half of them. A key below 0x40 moves letters onto other printable
  characters, so plain text under such a key "decodes" as readily as an
  encoded string does and nothing in the bytes says which is the writing. The
  price is stated: such a string whose encoded bytes are printable is not
  decoded here, and is in the ``strings`` tool's answer as it stands;
* under the rolling key, hold no byte three times in a row, which is a
  constant or a fill (the bytes of a floating-point number) and not text.

Discardable sections (debug information, relocations) are not read. Where the
key turns the non-zero byte after a sweep's text into its NUL (the NUL was
encoded with the text), the key explains where the text ends; another key of
the same scheme reads that byte as one more character, and its last character
is the difference between the two keys. Such readings of a span are set aside
when the terminated reading is the only one its scheme makes there and reads
better than each of them by the test's own measures: no more changes of
character class and no fewer letters or digits, better on one, where the
difference is a tab, LF or CR (the keys differ in the low bits and letters stay
letters); better on both where it is any other character but the space; and
never where it is the space, which flips the case of every letter. One reading
that does not read worse holds the whole span. Only a scheme's own terminated
reading sets its readings aside. The other sweep's reading of the same span,
one character longer through that byte, not ending in white space and worse on
both measures, gives way to the terminated reading and is stated under its
``also_read_as``, never dropped. A header found inside a terminated text's
bytes is set aside too. The strings affected are counted under
``outranked_spans``. A span one scheme then still reads as text under two keys
is dropped with every reading of it; setting readings aside settles a scheme's
span only for its terminated reading, and not where the other sweep still
reads that offset under two keys with a terminator or a white-space ending of
its own. Two decodings of overlapping bytes keep the one a header placed, else
the longer; where both sweeps' terminated readings stand on exactly the same
bytes, the row is the one the rules before the terminator rule answered, and
where those answered nothing the span is ambiguous. A decoder that recovered a
reading stated under ``also_read_as`` is said under
``<decoder>_matches_the_alternative``, never as recovering the row's text. The
answer counts the dropped spans under ``ambiguous_spans``.

Each result names the blob's file offset and RVA, the section, the scheme and
its parameters, the decoded text and the code that refers to the blob: the
places a scan for relative and absolute references to the blob's first byte or
its text's first byte finds (``maljan.tools.pe_image``), each with the function
around it when the file's function table says, and the row of a decoder that
recovered the same text at a call site (its decoding routine and call site,
said under the field :func:`decoder_fields` names): the rows the caller hands
in from whichever answer of that kind it holds, else this process's emulated
strings for the file. No reference is stated that the bytes do not hold.

Which decodings are results. The test above still passes on some tables of
numbers under some key, and a file with large tables yields many of them; a
program's encoded string, though, is reached by its address. So ``results``
holds the decodings some code or data refers to, or a decoder recovered too; the
others are counted under ``unreferenced`` and listed only when the caller asks
(``include_unreferenced``), because a string a program walks to from another
one is real and not referred to by address.

Nothing is limited by default: ``limit`` pages the answer only when asked.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

import numpy as np

from maljan.tools import call_sites, emulated_strings, pe_image

TOOL = "decode_string_blobs"

SCHEMES = ("xor8", "xor8_rolling", "xor_keyed_header", "xor8_rolling_header", "base64")

DEFAULT_MIN_LENGTH = 8
# The shortest text a header that states its length may carry.
_HEADER_MIN_LENGTH = 4
# From this length on, text whose characters are mostly evenly spaced is not
# text (``readable``); a shorter one may be a number such as a port or a count.
_PROGRESSION_FROM = 6
# The shortest text a header-stated span that ends in its own terminator may
# carry: under the seed-and-length header, which is tried four ways at each
# offset, and under a stored key with a length, which is tried at every key
# length up to ``LONGEST_KEY`` and so needs a longer text to be told from chance.
_STATED_MIN_LENGTH = {"xor8_rolling_header": 3, "xor_keyed_header": 6}
# The longest repeating key the keyed-header layouts read, stated in every
# answer (``readable_test`` and ``longest_key``): every key length tried is
# another chance for bytes to read as text by accident.
LONGEST_KEY = 32

_PRINTABLE = frozenset(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}
_PRINTABLE_TABLE = np.array([byte in _PRINTABLE for byte in range(256)], dtype=bool)
_RUN = re.compile(rb"[\x20-\x7e\t\r\n]+")
_BASE64 = re.compile(rb"[A-Za-z0-9+/]{12,}={0,2}")

# Stated with the answer, so a reader knows what "reads as text" meant. Kept to
# general words: it reaches every agent that calls the tool.
READABLE_TEST = (
    "a span whose header states its length, ends in the text's own terminator and holds no "
    "other zero: printable characters, at least half letters or digits, none over half the "
    "text (a third from eight characters on), no short pattern repeated through it, the key "
    "changing at least half the bytes, and at least three characters under the seed-and-length "
    "header or six under a stored key; any other text: printable characters throughout (two-byte "
    "characters where a header states the length), at least min_len characters when only the "
    "bytes around it bound it, four under a seed-and-length header and six under a stored key, "
    "at least half letters or digits, at "
    "least four distinct characters, none over half the text (a third from eight characters "
    "on), no short pattern repeated through it, at most one change of character class per "
    "three characters and no evenly spaced run of characters, a text-encoding layer whose "
    "content passes counting as text, and encoded bytes that hold no zero byte and do not "
    "already read as text, so such a string whose encoded bytes are printable is not decoded "
    "here; a stored key is read up to 32 bytes long"
)


def _char_class(byte: int) -> int:
    if 0x61 <= byte <= 0x7A:
        return 0
    if 0x41 <= byte <= 0x5A:
        return 1
    if 0x30 <= byte <= 0x39:
        return 2
    if byte in (0x20, 0x09, 0x0A, 0x0D):
        return 3
    return 4


def class_changes(text: bytes) -> int:
    """How often the character class changes along ``text`` (``READABLE_TEST``).

    Lower case, upper case, digit, space and punctuation; a capital before
    lower case does not count. Words, numbers, paths and URLs change class
    seldom, random bytes often.
    """
    changes = 0
    for before, after in zip(text, text[1:], strict=False):
        first, second = _char_class(before), _char_class(after)
        if first != second and not (first == 1 and second == 0):
            changes += 1
    return changes


def readable(text: bytes, min_len: int) -> bool:
    """Whether ``text`` passes the stated test (``READABLE_TEST``)."""
    text = text.rstrip(b"\0")
    length = len(text)
    if length < max(3, min_len) or any(byte not in _PRINTABLE for byte in text):
        return False
    alnum = sum(1 for byte in text if _char_class(byte) in (0, 1, 2))
    if alnum * 2 < length:
        return False
    distinct = len(set(text))
    if distinct < (3 if length <= 4 else 4):
        return False
    if _repetitive(text):
        return False
    steps: dict[int, int] = {}
    for before, after in zip(text, text[1:], strict=False):
        steps[after - before] = steps.get(after - before, 0) + 1
    if class_changes(text) * 3 > length:
        return False
    # A run of evenly spaced characters is a table of numbers under a key, not
    # text: the bytes of a counter or an index read "defghijk" once decoded.
    return length < _PROGRESSION_FROM or max(steps.values()) * 3 <= length - 1


def _repetitive(text: bytes) -> bool:
    """Whether one character, or one three-character pattern, fills the text.

    A character over half the text (a third from eight characters on), or a
    three-character sequence standing at more than a quarter of the positions
    of a text of twelve or more: the rows of a table read under a key, not
    writing.
    """
    length = len(text)
    most = max(text.count(bytes([byte])) for byte in set(text)) if text else 0
    if most * (3 if length >= 8 else 2) > length:
        return True
    if length >= 12:
        grams: dict[bytes, int] = {}
        for at in range(length - 2):
            gram = text[at : at + 3]
            grams[gram] = grams.get(gram, 0) + 1
        if max(grams.values()) * 4 > length - 2:
            return True
    return False


def _reads_as_text(raw: bytes) -> bool:
    """Whether the encoded bytes already hold text, so no decoding of them is reported.

    Two ways: most of them (four in five) are printable, or one readable run
    covers half of them. A key below 0x40 moves letters onto other printable
    characters, so plain text under such a key "decodes" into other printable
    text as readily as an encoded string does, and nothing in the bytes says
    which of the two is the writing; that text is the ``strings`` tool's and
    FLOSS's. The price is stated: an encoded string whose encoded bytes are
    printable is not decoded here.
    """
    if not raw:
        return False
    if sum(1 for byte in raw if byte in _PRINTABLE) * 5 >= len(raw) * 4:
        return True
    longest = max((match.group(0) for match in _RUN.finditer(raw)), key=len, default=b"")
    return len(longest) * 2 >= len(raw) and readable(longest, _HEADER_MIN_LENGTH)


def _passes(text: bytes, min_len: int) -> bool:
    """Whether decoded text passes the test, or is base64 whose content does."""
    return readable(text, min_len) or (len(text) >= min_len and _unbase64(text) is not None)


@dataclass
class Found:
    """One decoding, before it is given its references."""

    blob_offset: int
    text_offset: int
    scheme: str
    parameters: dict[str, Any]
    text: bytes
    layers: list[dict[str, Any]] = field(default_factory=list)
    encoding: str = "ascii"
    # A sweep's text whose key turns the non-zero byte after it into its NUL:
    # the key explains where the text ends (``_bounded_runs``).
    terminated: bool = False


# ---------------------------------------------------------------------------
# The sweeps: one key stream over a whole section, text bounded by the bytes
# ---------------------------------------------------------------------------


def _xor(raw: bytes, stream: bytes) -> bytes:
    return (int.from_bytes(raw, "little") ^ int.from_bytes(stream, "little")).to_bytes(
        len(raw), "little"
    )


def _bounded_runs(
    zeros: np.ndarray, decoded: bytes, min_len: int
) -> Iterator[tuple[int, int, bool]]:
    """The printable runs of ``decoded`` bounded on both sides as the test says.

    A zero byte of the encoded section is a boundary, never a character: a key
    applied to it gives the key itself, and plain text with its NULs under the
    key 0x20 would otherwise read as the same text in the other case.

    Each run comes with whether its key terminated it: the byte after it is a
    non-zero encoded byte the key turns into a NUL. One key in 256 does that to
    a given byte, so the key then says where the text ends as a header does,
    while a wrong key near the right one reads the same letters as other
    letters and runs on through that byte as one more character.
    """
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


def _xor8(raw: bytes, base: int, min_len: int) -> Iterator[Found]:
    zeros = np.frombuffer(raw, dtype=np.uint8) == 0
    for key in range(1, 256):
        decoded = raw.translate(bytes(b ^ key for b in range(256)))
        for start, end, terminated in _bounded_runs(zeros, decoded, min_len):
            text = decoded[start:end]
            if _reads_as_text(raw[start:end]) or not _passes(text, min_len):
                continue
            yield Found(
                base + start,
                base + start,
                "xor8",
                {"key": f"{key:#04x}"},
                text,
                terminated=terminated,
            )


def _le(array: np.ndarray, at: np.ndarray, width: int) -> np.ndarray:
    """The little-endian unsigned ints of ``width`` bytes starting at each of ``at``."""
    value = np.zeros(len(at), dtype=np.int64)
    for index in range(width):
        value |= array[at + index].astype(np.int64) << (8 * index)
    return value


def _seed_headers(array: np.ndarray) -> list[tuple[np.ndarray, np.ndarray, np.ndarray, bool]]:
    """Every place a seed-and-length header could stand, per variant.

    Each variant is the blob starts, the stated text lengths and, for each, the
    constant ``c`` of the absolute key ramp (key at position ``p`` is
    ``(c + p) & 0xFF``) the header's seed puts the text under.
    """
    size = len(array)
    if size < 6 + _HEADER_MIN_LENGTH:
        return []
    at = np.arange(0, size - 6, dtype=np.int64)
    seed = _le(array, at, 4)
    stored = _le(array, at + 4, 2)
    variants = []
    for masked in (False, True):
        length = stored ^ (seed & 0xFFFF) if masked else stored
        fits = (length >= _HEADER_MIN_LENGTH) & (length <= size - (at + 6))
        for extra in (0, 1):
            constant = ((seed + extra) - (at + 6)) & 0xFF
            variants.append((at[fits], length[fits], constant[fits], masked))
    return variants


def _rolling(raw: bytes, base: int, min_len: int, sweep: bool, headers: bool) -> Iterator[Found]:
    """The rolling key: the bounded sweep, and the seed-and-length headers.

    Both are read off the same pass per ramp constant: with the key rising by
    one per byte, the key at file position ``p`` is ``(c + p) & 0xFF`` for one
    ``c`` whatever the text's first key was, so 256 passes cover every start.
    """
    size = len(raw)
    array = np.frombuffer(raw, dtype=np.uint8)
    zeros = array == 0
    variants = _seed_headers(array) if headers else []
    ramp = bytes(range(256)) * (size // 256 + 2)
    for constant in range(256):
        stream = ramp[constant : constant + size]
        decoded = _xor(raw, stream)
        yield from _seeded(raw, base, decoded, stream, constant, variants)
        if sweep:
            for start, end, terminated in _bounded_runs(zeros, decoded, min_len):
                text = decoded[start:end]
                encoded = raw[start:end]
                if _reads_as_text(encoded) or _repeats(encoded) or not _passes(text, min_len):
                    continue
                yield Found(
                    base + start,
                    base + start,
                    "xor8_rolling",
                    {"first_key": f"{stream[start]:#04x}", "step": 1},
                    text,
                    terminated=terminated,
                )


def _seeded(
    raw: bytes,
    base: int,
    decoded: bytes,
    stream: bytes,
    constant: int,
    variants: list[tuple[np.ndarray, np.ndarray, np.ndarray, bool]],
) -> Iterator[Found]:
    """The seed-and-length headers whose seed puts their text under this ramp constant."""
    if not variants:
        return
    decoded_array = np.frombuffer(decoded, dtype=np.uint8)
    # Printable or zero: a UTF-16LE text has a zero byte after each character.
    plain = _PRINTABLE_TABLE[decoded_array] | (decoded_array == 0)
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
            read = _header_text(decoded[first:last], raw[first:last], rolling=True)
            if read is None:
                continue
            text, encoding = read
            seed = int.from_bytes(raw[first - 6 : first - 2], "little")
            yield Found(
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


# ---------------------------------------------------------------------------
# The keyed header layouts: the key and the length stand in front of the text
# ---------------------------------------------------------------------------


def _repeat_xor(data: bytes, key: bytes) -> bytes:
    stream = (key * (len(data) // len(key) + 1))[: len(data)]
    return _xor(data, stream)


def _terminated(decoded: bytes) -> tuple[bytes, str] | None:
    """The characters of a span that ends in its own terminator and holds no other NUL.

    ASCII ends in one NUL; UTF-16LE in one NUL pair, with a zero high byte
    after every character before it. ``None`` for any other span.
    """
    if len(decoded) >= 2 and decoded[-1] == 0 and 0 not in decoded[:-1]:
        return decoded[:-1], "ascii"
    if (
        len(decoded) >= 4
        and len(decoded) % 2 == 0
        and decoded[-2:] == b"\0\0"
        and not any(decoded[1:-2:2])
        and all(decoded[0:-2:2])
    ):
        return decoded[0:-2:2], "utf-16le"
    return None


def _structural(characters: bytes, decoded: bytes, encoded: bytes, scheme: str) -> bool:
    """The test a header-stated, terminated span passes (``READABLE_TEST``, first half).

    Printable, at least half letters or digits, not a repeated pattern, long
    enough for its scheme, and changed by the key at half its bytes or more:
    a key that leaves the bytes as they were has decoded nothing.
    """
    if len(characters) < _STATED_MIN_LENGTH[scheme]:
        return False
    if any(byte not in _PRINTABLE for byte in characters) or _repetitive(characters):
        return False
    alnum = sum(1 for byte in characters if _char_class(byte) in (0, 1, 2))
    if alnum * 2 < len(characters):
        return False
    changed = sum(1 for clear, stored in zip(decoded, encoded, strict=False) if clear != stored)
    return changed * 2 >= len(decoded)


def _header_text(
    decoded: bytes, encoded: bytes, rolling: bool = False, stated: bool = True
) -> tuple[bytes, str] | None:
    """The text a header-stated span holds and its encoding, when it passes the test.

    A span whose stated length ends exactly in the text's own terminator — one
    NUL, or a NUL pair for UTF-16LE — and holds no other NUL carries its
    structure with it: the header said where the text ends and the decoded
    bytes agree. It is accepted when its characters are printable and at least
    half letters or digits, which is what a format string, a command line or a
    user agent is. The vetoes below are for spans with no such agreement.

    Any other span: ASCII, or UTF-16LE when every second byte is zero (tested
    on its characters); trailing NULs are not the text's; and the encoded bytes
    under the text hold no zero byte (a key over zeros is the key itself), do
    not already read as text, and, under a rising key, repeat no byte three
    times.
    """
    terminated = _terminated(decoded) if stated else None
    if terminated is not None:
        scheme = "xor8_rolling_header" if rolling else "xor_keyed_header"
        return terminated if _structural(terminated[0], decoded, encoded, scheme) else None
    text = decoded.rstrip(b"\0")
    encoding = "ascii"
    if len(text) >= 2 and not any(text[1::2]):
        text = decoded[: len(text) + len(text) % 2]
        characters = text[::2]
        encoding = "utf-16le"
    else:
        characters = text
    encoded = encoded[: len(text)]
    if b"\0" in encoded or _reads_as_text(encoded):
        return None
    if not _passes(characters, _HEADER_MIN_LENGTH) or (rolling and _repeats(encoded)):
        return None
    return characters, encoding


# Three equal bytes in a row under a key that moves every byte are a constant
# or padding (the bytes of a floating-point number, a fill), not text.
_REPEATED = re.compile(rb"(.)\1\1", re.DOTALL)


def _repeats(encoded: bytes) -> bool:
    return _REPEATED.search(encoded) is not None


def _to_nul(raw: bytes, start: int, key: bytes) -> int | None:
    """Where the text a repeating key decodes from ``start`` reaches a decoded NUL."""
    chunk = 256 - 256 % len(key) or len(key)
    at = start
    while at < len(raw):
        piece = _repeat_xor(raw[at : at + chunk], key)
        nul = piece.find(b"\0")
        if nul >= 0:
            return at + nul
        if any(byte not in _PRINTABLE for byte in piece):
            return None
        at += chunk
    return None


def _printable_heads(array: np.ndarray, key_length: int, gap: int) -> np.ndarray:
    """The places a key of ``key_length`` could stand whose text starts printable.

    The places are those holding the byte ``key_length``; the text starts
    ``gap`` bytes after the key, and its first bytes are checked under the key
    in one pass over every such place.
    """
    size = len(array)
    last = size - (1 + key_length + gap + _HEADER_MIN_LENGTH)
    if last < 0:
        return np.zeros(0, dtype=np.int64)
    places: np.ndarray = np.nonzero(array[: last + 1] == key_length)[0].astype(np.int64)
    if not len(places):
        return places
    keep = np.ones(len(places), dtype=bool)
    for index in range(_HEADER_MIN_LENGTH):
        key_byte = array[places + 1 + index % key_length]
        text_byte = array[places + 1 + key_length + gap + index]
        clear = key_byte ^ text_byte
        # A zero may be the high byte of a UTF-16LE character when a length
        # says where the text ends; the text-to-NUL layout is read as ASCII.
        allowed = _PRINTABLE_TABLE[clear] | ((clear == 0) & bool(gap))
        keep &= allowed & (text_byte != 0)
    kept: np.ndarray = places[keep]
    return kept


def _keyed_headers(raw: bytes, base: int, min_len: int) -> Iterator[Found]:
    size = len(raw)
    array = np.frombuffer(raw, dtype=np.uint8)
    for key_length in range(1, LONGEST_KEY + 1):
        # key length, key, text to a decoded NUL.
        for at in _printable_heads(array, key_length, 0).tolist():
            key_end = at + 1 + key_length
            key = raw[at + 1 : key_end]
            end = _to_nul(raw, key_end, key)
            if end is None or end - key_end < _HEADER_MIN_LENGTH:
                continue
            read = _header_text(_repeat_xor(raw[key_end:end], key), raw[key_end:end], stated=False)
            if read is not None and read[1] == "ascii" and len(read[0]) >= min_len:
                text = read[0]
                yield Found(
                    base + at,
                    base + key_end,
                    "xor_keyed_header",
                    {"layout": "key length (1), key, text to NUL", "key": key.hex()},
                    text,
                )
        # key length, key, text length (2 or 4), text.
        for width in (2, 4):
            for at in _printable_heads(array, key_length, width).tolist():
                key_end = at + 1 + key_length
                key = raw[at + 1 : key_end]
                start = key_end + width
                length = int.from_bytes(raw[key_end:start], "little")
                if not _HEADER_MIN_LENGTH <= length <= size - start:
                    continue
                body = raw[start : start + length]
                read = _header_text(_repeat_xor(body, key), body)
                if read is not None and len(read[0]) >= _STATED_MIN_LENGTH["xor_keyed_header"]:
                    text, encoding = read
                    yield Found(
                        base + at,
                        base + start,
                        "xor_keyed_header",
                        {
                            "layout": f"key length (1), key, text length ({width}), text",
                            "key": key.hex(),
                        },
                        text,
                        encoding=encoding,
                    )


# ---------------------------------------------------------------------------
# base64
# ---------------------------------------------------------------------------


def _unbase64(text: bytes) -> bytes | None:
    """``text`` decoded when all of it is base64 and what it holds reads as text."""
    stripped = text.rstrip(b"\0").strip()
    if (
        len(stripped) < 8
        or len(stripped) % 4
        or not re.fullmatch(rb"[A-Za-z0-9+/]+={0,2}", stripped)
    ):
        return None
    try:
        inner = base64.b64decode(stripped, validate=True)
    except (binascii.Error, ValueError):
        return None
    return inner if readable(inner, _HEADER_MIN_LENGTH) else None


def _layers(text: bytes) -> list[dict[str, Any]]:
    layers: list[dict[str, Any]] = []
    current = text
    while True:
        inner = _unbase64(current)
        if inner is None:
            return layers
        layers.append({"scheme": "base64", "text": inner.decode("latin-1")})
        current = inner


def _plain_base64(raw: bytes, base: int) -> Iterator[Found]:
    for match in _BASE64.finditer(raw):
        start, end = match.span()
        inner = _unbase64(raw[start:end])
        if inner is None:
            continue
        found = Found(base + start, base + start, "base64", {}, inner)
        found.layers = _layers(inner)
        yield found


# ---------------------------------------------------------------------------
# The tool
# ---------------------------------------------------------------------------


def _error(message: str) -> dict[str, Any]:
    return {"error": message, "tool": TOOL}


def _remembered_rows(path: str) -> list[dict[str, Any]]:
    """This process's emulated strings for this file, when that tool already ran on it here."""
    try:
        return emulated_strings.remembered_rows(path)
    except Exception:  # noqa: BLE001 - the emulator's absence is not this tool's failure
        return []


# The schemes whose header says where the text is. Where two decodings of the
# same bytes disagree, one of these is preferred to a sweep, and otherwise the
# longer text: a key that is right reads the whole string, and a wrong key
# that happens to pass the test reads a few characters of it.
_HEADER_SCHEMES = frozenset({"xor_keyed_header", "xor8_rolling_header"})
# The schemes that only the bytes around the text bound (``_bounded_runs``).
_SWEEP_SCHEMES = frozenset({"xor8", "xor8_rolling"})
# White space, which a text may end in before a zero byte (``_char_class``).
_WHITE_SPACE = frozenset(byte for byte in range(256) if _char_class(byte) == 3)
# The space: a key that differs from the right one by it flips the case of
# every letter, and the test's measures read either case as well, so a reading
# that ends in a space is never set aside by the case-flipped key's reading.
_CASE_FLIP = ord(" ")


@dataclass
class Decoded:
    """What the schemes found in one image."""

    items: list[Found]
    # Spans where one scheme read text under more than one key.
    ambiguous: int = 0
    # Strings (spans) whose near-key readings, or a header inside them, were
    # set aside (``_through_readings``, ``_headers_inside_terminated_text``).
    outranked: int = 0


def _span_length(item: Found) -> int:
    """How many bytes of the file the decoded text stands on."""
    return len(item.text) * (2 if item.encoding == "utf-16le" else 1)


def letters_or_digits(text: bytes) -> int:
    """How many characters of ``text`` are letters or digits (``READABLE_TEST``)."""
    return sum(1 for byte in text if _char_class(byte) in (0, 1, 2))


def _reads_better(first: bytes, second: bytes, strictly: bool = False) -> bool:
    """Whether ``first`` reads as text better than ``second`` by the test's own measures.

    Two of the measures ``READABLE_TEST`` states for every text: changes of
    character class (fewer reads better) and letters or digits (more reads
    better). ``first`` reads better when it is no worse on either and better on
    one, or, ``strictly``, better on both; otherwise neither does, and nothing
    in the bytes says which is the writing.
    """
    changes = (class_changes(first), class_changes(second))
    letters = (letters_or_digits(first), letters_or_digits(second))
    if strictly:
        return changes[0] < changes[1] and letters[0] > letters[1]
    no_worse = changes[0] <= changes[1] and letters[0] >= letters[1]
    return no_worse and (changes[0] < changes[1] or letters[0] > letters[1])


def _near_key_reading(maker: Found, item: Found) -> bool:
    """Whether ``item`` reads ``maker``'s terminator as one more character under a wrong key.

    Its last character is the difference between the two keys. Below the
    space (tab, LF, CR: the only printable ones) the keys differ in the low
    bits alone, letters stay letters under both, and ``maker`` must read better
    than ``item``'s characters before that byte (``_reads_better``). The space
    flips the case of every letter, which the measures read as well either
    way, so it never decides. Any other difference moves letters off the
    letters under one of the two keys, and ``maker`` must read better on every
    measure (``_reads_better`` with ``strictly``); when it ties on one, nothing
    tells which of the two is the writing.
    """
    difference, before = item.text[-1], item.text[:-1]
    if difference == _CASE_FLIP:
        return False
    return _reads_better(maker.text, before, strictly=difference not in _WHITE_SPACE)


def _through_readings(candidates: Sequence[Found]) -> tuple[set[int], int]:
    """The sweep readings that read another reading's key-made terminator as one more character.

    A reading whose key turns the non-zero byte after its text into the NUL
    (``Found.terminated``) has its end explained by the key; it may set others
    aside only when no other key of its scheme makes a terminator for a
    different text at its offset, and only readings of its own scheme. A
    reading of that scheme at the same offset, not terminated, one character
    longer, whose last character is that very byte, is set aside when it is a
    wrong key's (``_near_key_reading``). One such reading that is not holds the
    whole span, so no partial setting aside dissolves an ambiguity, and a text
    that ends in white space before a zero byte, which reads the same way under
    the near key as under the right one, is left to the rules that follow. A
    terminated reading whose own span then reads as text under two keys sets
    nothing aside, so it lets no third reading through. Returns the indexes set
    aside and how many spans (strings) lost readings to it. Linear: a pass to
    collect, a pass to set aside, and one more where an offset is withdrawn.
    """
    # The terminated readings of each scheme at each offset, by their texts.
    terminated: dict[tuple[str, int], set[bytes]] = {}
    for item in candidates:
        if item.terminated and item.scheme in _SWEEP_SCHEMES:
            terminated.setdefault((item.scheme, item.text_offset), set()).add(item.text)
    # The terminated reading that may set others of its scheme aside, by
    # (scheme, offset, terminator byte).
    makers: dict[tuple[str, int, int], Found] = {}
    for item in candidates:
        if item.terminated and len(terminated.get((item.scheme, item.text_offset), ())) == 1:
            end = item.text_offset + _span_length(item)
            makers.setdefault((item.scheme, item.text_offset, end), item)

    def aside(withdrawn: set[tuple[str, int]]) -> dict[int, tuple[str, int, int]]:
        found: dict[int, tuple[str, int, int]] = {}
        # A span where one through-reading does not read worse sets none aside.
        held: set[tuple[str, int, int]] = set()
        for index, item in enumerate(candidates):
            if (
                item.terminated
                or item.scheme not in _SWEEP_SCHEMES
                or (item.scheme, item.text_offset) in withdrawn
            ):
                continue
            span = (item.scheme, item.text_offset, item.text_offset + _span_length(item) - 1)
            maker = makers.get(span)
            if maker is None:
                continue
            if _near_key_reading(maker, item):
                found[index] = span
            else:
                held.add(span)
        return {index: span for index, span in found.items() if span not in held}

    found = aside(set())
    readings: dict[tuple[str, int], set[bytes]] = {}
    for index, item in enumerate(candidates):
        if index not in found:
            readings.setdefault((item.scheme, item.text_offset), set()).add(item.text)
    withdrawn = {
        (scheme, offset) for (scheme, offset, _end) in makers if len(readings[(scheme, offset)]) > 1
    }
    if withdrawn:
        found = aside(withdrawn)
    return set(found), len({(offset, end) for _scheme, offset, end in found.values()})


def _other_sweep_through_readings(kept: list[Found]) -> list[Found]:
    """The decodings left once the other sweep's reading of a terminator is stated beside it.

    A terminated reading (``Found.terminated``) left as its scheme's only one
    at its offset, and a reading of the other sweep at the same offset, not
    terminated, one character longer, whose last character is the byte the
    first one's key turned into its NUL. When that character is not white
    space, the terminated reading is the row: a text that ends in white space
    before a zero byte is common, so then nothing is decided here, but under
    the key that turns any other character into a NUL the letters before it
    move off the letters and a reading that still passes the test is the
    text. The other reading is not dropped: it is stated under the row's
    ``also_read_as``. Linear: one pass to index, one to match.
    """
    makers: dict[tuple[str, int, int], Found] = {}
    for item in kept:
        if item.terminated:
            makers[(item.scheme, item.text_offset, item.text_offset + _span_length(item))] = item
    left: list[Found] = []
    for item in kept:
        last = item.text_offset + _span_length(item) - 1
        others = _SWEEP_SCHEMES - {item.scheme}
        maker = (
            next(
                (
                    makers[(other, item.text_offset, last)]
                    for other in others
                    if (other, item.text_offset, last) in makers
                ),
                None,
            )
            if item.scheme in _SWEEP_SCHEMES and not item.terminated
            else None
        )
        if (
            maker is not None
            and item.text[-1] not in _WHITE_SPACE
            and _reads_better(maker.text, item.text[:-1])
        ):
            maker.parameters.setdefault("also_read_as", []).append(_alternative(item))
            continue
        left.append(item)
    return left


def _headers_inside_terminated_text(kept: list[Found]) -> tuple[list[Found], int]:
    """The decodings left once a header found inside a key-terminated text is set aside.

    A header is tried at every offset, so a stated length that fits its span
    turns up by chance inside other bytes. When the whole blob, header and text,
    lies inside the bytes of a sweep's text whose key turned the byte after it
    into its NUL (``Found.terminated``) and which no other key of its scheme
    read, those header bytes are characters of that text: the header is set
    aside and counted. A header whose blob reaches outside such a text is kept,
    first, as before. Linear in the length of the terminated texts.
    """
    inside: dict[int, int] = {}
    for item in kept:
        if item.terminated:
            end = item.text_offset + _span_length(item)
            for at in range(item.text_offset, end):
                inside[at] = max(inside.get(at, end), end)
    left: list[Found] = []
    dropped = 0
    for item in kept:
        stop = item.text_offset + _span_length(item)
        if item.scheme in _HEADER_SCHEMES and inside.get(item.blob_offset, -1) >= stop:
            dropped += 1
            continue
        left.append(item)
    return left, dropped


def _same_bytes_other_sweep(holder: Found, item: Found) -> bool:
    """Whether ``item`` is the other sweep's reading of exactly the bytes ``holder`` reads.

    A single key byte and a rising key can both read the same bytes as text.
    Unless both turned the byte after them into their NUL, the row is the one
    the earlier rules kept, as before. When both did, the row is the one those
    rules answered (``_earlier_rules_choose``), and where they answered nothing
    the span is ambiguous. A reading not chosen is stated under the row's
    ``also_read_as``.
    """
    return (
        holder.scheme in _SWEEP_SCHEMES
        and item.scheme in _SWEEP_SCHEMES
        and holder.scheme != item.scheme
        and holder.text_offset == item.text_offset
        and _span_length(holder) == _span_length(item)
    )


def _earlier_rules_choose(
    holder: Found, item: Found, readings: Mapping[tuple[str, int], set[bytes]]
) -> bool:
    """Whether the rules before the terminator rule answered ``holder`` for these bytes.

    They dropped a scheme's reading of a span it read under two keys. When
    only ``item``'s scheme did that, they answered ``holder``; when neither
    did, they answered the reading they met first, which is ``holder`` here
    (the sort keeps their order). When both did, they answered nothing, and
    the span stays ambiguous.
    """
    return len(readings[(holder.scheme, holder.text_offset)]) == 1


def _alternative(item: Found) -> dict[str, Any]:
    """A reading stated under another row's ``also_read_as``."""
    return {
        "scheme": item.scheme,
        "parameters": {k: v for k, v in item.parameters.items() if k != "also_read_as"},
        "text": item.text.decode("latin-1"),
    }


def decode(
    image: pe_image.Image, min_len: int = DEFAULT_MIN_LENGTH, schemes: Sequence[str] = SCHEMES
) -> Decoded:
    """Every decoding the schemes find in the image's non-executable sections.

    Near-key readings of a span whose terminator the right key of the same
    scheme made are set aside first (``_through_readings``), and so are headers
    inside such a text (``_headers_inside_terminated_text``); the other sweep's
    reading through that terminator is stated beside it
    (``_other_sweep_through_readings``). A span one scheme then reads as text
    under two keys is dropped with every reading of it: an encoded string
    decodes under its key, and a table of numbers that reads as text under
    several is a table of numbers. Two decodings of overlapping bytes are one
    too many: the one a header placed, else the longer, is kept, and the other
    is named in its ``also_decoded_by`` when it read the same characters, or
    stated in its ``also_read_as`` when it is the other sweep's reading of
    exactly the same bytes (``_same_bytes_other_sweep``).
    """
    wanted = set(schemes)
    candidates: list[Found] = []
    for section in image.data_sections():
        raw = image.data_bytes(section)
        base = section.raw_offset
        if "xor_keyed_header" in wanted:
            candidates.extend(_keyed_headers(raw, base, min_len))
        if "xor8_rolling" in wanted or "xor8_rolling_header" in wanted:
            candidates.extend(
                _rolling(
                    raw,
                    base,
                    min_len,
                    sweep="xor8_rolling" in wanted,
                    headers="xor8_rolling_header" in wanted,
                )
            )
        if "xor8" in wanted:
            candidates.extend(_xor8(raw, base, min_len))
        if "base64" in wanted:
            candidates.extend(_plain_base64(raw, base))

    outranked, outranked_spans = _through_readings(candidates)
    readings: dict[tuple[str, int], set[bytes]] = {}
    left: dict[tuple[str, int], set[bytes]] = {}
    # The groups whose one reading left is a terminated one.
    terminated_left: set[tuple[str, int]] = set()
    for index, item in enumerate(candidates):
        group = (item.scheme, item.text_offset)
        readings.setdefault(group, set()).add(item.text)
        if index not in outranked:
            left.setdefault(group, set()).add(item.text)
            if item.terminated:
                terminated_left.add(group)
    # Setting readings aside settles a span only for the reading whose key made
    # the terminator: any other group that read text under two keys stays
    # ambiguous, so what is set aside never lets a third reading through.
    ambiguous = {
        group
        for group, texts in readings.items()
        if len(left.get(group, ())) > 1
        or (len(texts) > 1 and not (group in terminated_left and len(left[group]) == 1))
    }
    # A group that setting aside settled stays ambiguous where the other sweep
    # still reads the same offset under two keys and holds evidence of its own
    # there: a key that made a terminator, or a reading that ends in white
    # space before a zero byte, which a text may do. The earlier rules
    # answered nothing there, and neither sweep is chosen.
    contested = {
        (item.scheme, item.text_offset)
        for item in candidates
        if item.terminated or (item.scheme in _SWEEP_SCHEMES and item.text[-1] in _WHITE_SPACE)
    }
    settled = {
        group for group, texts in readings.items() if len(texts) > 1 and group not in ambiguous
    }
    ambiguous |= {
        (scheme, offset)
        for scheme, offset in settled
        if any(
            (other, offset) in ambiguous and (other, offset) in contested
            for other in _SWEEP_SCHEMES - {scheme}
        )
    }
    kept = [
        item
        for index, item in enumerate(candidates)
        if index not in outranked and (item.scheme, item.text_offset) not in ambiguous
    ]
    kept, inside = _headers_inside_terminated_text(kept)
    outranked_spans += inside
    kept = _other_sweep_through_readings(kept)
    # Of two readings of the same bytes that tie, the row is the one the rules
    # before the terminator rule kept: a reading whose scheme read its span
    # under one key only, else the earlier candidate.
    kept.sort(
        key=lambda item: (
            item.scheme not in _HEADER_SCHEMES,
            -len(item.text),
            item.text_offset,
            len(readings[(item.scheme, item.text_offset)]) > 1,
        )
    )

    accepted: dict[tuple[int, bytes], Found] = {}
    # Which accepted decoding covers each byte of the file.
    covered: dict[int, Found] = {}
    # Spans the two sweeps read as two texts, neither reading better.
    tied = 0
    for item in kept:
        key = (item.text_offset, item.text)
        if key in accepted:
            continue
        span = range(item.text_offset, item.text_offset + _span_length(item))
        holder = next((covered[at] for at in span if at in covered), None)
        if holder is not None:
            also = holder.parameters.get("also_decoded_by") or []
            if item.text in holder.text and item.scheme not in (holder.scheme, *also):
                holder.parameters["also_decoded_by"] = [*also, item.scheme]
            elif _same_bytes_other_sweep(holder, item):
                if not (holder.terminated and item.terminated):
                    # Unless both keys made the NUL after the text, the row
                    # is the one the earlier rules kept, as before.
                    holder.parameters.setdefault("also_read_as", []).append(_alternative(item))
                elif _earlier_rules_choose(holder, item, readings):
                    holder.parameters.setdefault("also_read_as", []).append(_alternative(item))
                elif (holder.text_offset, holder.text) in accepted:
                    # Both keys made the NUL and the rules before the
                    # terminator rule chose neither: the span is ambiguous, as
                    # those rules leave it, and nothing else takes its bytes.
                    del accepted[(holder.text_offset, holder.text)]
                    tied += 1
            continue
        if not item.layers and item.scheme != "base64":
            item.layers = _layers(item.text)
        accepted[key] = item
        for at in span:
            covered.setdefault(at, item)
    return Decoded(
        items=sorted(accepted.values(), key=lambda item: item.text_offset),
        ambiguous=len(ambiguous) + tied,
        outranked=outranked_spans,
    )


# The word the answer's fields name a decoder by where its rows came from any
# tool other than the shipped emulator (``decoder_fields``).
DECODER_NEUTRAL = "decoder"
# The kind of answer whose rows this tool compares with.
_DECODER_KIND = "emulated_strings"


def decoder_word(shipped: bool = True) -> str:
    """The word the answer's fields name the decoder it compared with by.

    The shipped emulator's name, which these fields have always carried, where
    every row came from it as the platform runs it, or none came;
    :data:`DECODER_NEUTRAL` where any came from another tool, so the answer
    never names a decoder that did not run (``core.pack_steps.answer_field``).
    """
    from maljan.core.pack_steps import answer_field

    return answer_field("{}", _DECODER_KIND, DECODER_NEUTRAL, shipped=shipped)


def decoder_fields(word: str) -> tuple[str, str, str]:
    """The row's field, the compared count's and the agreeing count's, for ``word``."""
    return word, f"{word}_rows_compared", f"also_recovered_by_{word}"


def decoder_row(row: Mapping[str, Any]) -> Any:
    """A result row's decoder row, under whichever word :func:`decoder_word` gave it."""
    from maljan.core.pack_steps import read_answer_field

    return read_answer_field(row, "{}", _DECODER_KIND, DECODER_NEUTRAL)


def also_recovered(answer: Mapping[str, Any]) -> Any:
    """How many results a decoder recovered too, under whichever word the answer used."""
    from maljan.core.pack_steps import read_answer_field

    return read_answer_field(answer, "also_recovered_by_{}", _DECODER_KIND, DECODER_NEUTRAL)


def decode_string_blobs(
    path: str,
    min_len: int = DEFAULT_MIN_LENGTH,
    schemes: Sequence[str] | None = None,
    offset: int = 0,
    limit: int | None = None,
    include_unreferenced: bool = False,
    function_starts: Sequence[Any] | None = None,
    function_source: str = "",
    recovered: Sequence[Mapping[str, Any]] | None = None,
    decoder: str = "",
) -> dict[str, Any]:
    """Decode the text a PE keeps encoded in its data sections (see the module docstring).

    ``schemes`` keeps some of ``SCHEMES``; with none every one is tried.
    ``offset``/``limit`` page the results when the caller wants pages;
    ``limit`` of ``None`` is every result. A decoding no code refers to and
    no decoder recovered is counted under ``unreferenced`` and listed only
    with ``include_unreferenced``.

    ``recovered`` are the strings another decoder recovered at a call site
    (rows with ``string``, ``kind`` ``decoded``, ``function_rva`` and
    ``called_at_rva``), from whichever answer of that kind the caller holds;
    ``None`` reads this process's emulated strings for the file, when that
    tool ran here. A decoding one of them recovered too is marked and counted
    under the answer's fields for it, named by ``decoder`` (empty: the
    shipped emulator's name, :func:`decoder_word`).
    """
    wanted = tuple(SCHEMES) if not schemes else tuple(str(s).strip() for s in schemes)
    unknown = [scheme for scheme in wanted if scheme not in SCHEMES]
    if unknown:
        return _error(f"unknown schemes {unknown}; known: {', '.join(SCHEMES)}")
    try:
        image = pe_image.load(path)
    except FileNotFoundError:
        return _error(f"no such file: {path}")
    except pe_image.NotAPortableExecutable as exc:
        return _error(f"this tool reads Windows PE images only; {exc}")
    pe_image.take_function_starts(image, function_starts, function_source)
    minimum = max(_HEADER_MIN_LENGTH, int(min_len))
    decoded = decode(image, minimum, wanted)
    items = decoded.items

    row_field, compared_field, also_field = decoder_fields(decoder or decoder_word())
    recovered_by: dict[str, Mapping[str, Any]] = {}
    for recovered_row in _remembered_rows(path) if recovered is None else recovered:
        if (
            isinstance(recovered_row, Mapping)
            and recovered_row.get("kind") == "decoded"
            and recovered_row.get("string")
        ):
            recovered_by.setdefault(str(recovered_row["string"]), recovered_row)

    targets: set[int] = set()
    for item in items:
        for at in (item.blob_offset, item.text_offset):
            rva = image.rva_of_offset(at)
            if rva is not None:
                targets.add(rva)
    references = image.references(targets)

    results: list[dict[str, Any]] = []
    unreferenced: list[dict[str, Any]] = []
    also = 0
    for item in items:
        text = item.text.rstrip(b"\0").decode("latin-1")
        blob_rva = image.rva_of_offset(item.blob_offset)
        text_rva = image.rva_of_offset(item.text_offset)
        section = image.section_at_offset(item.blob_offset)
        sites: list[int] = []
        # Which address each reference takes: the blob's start, or the text's
        # inside it where a header stands before the text.
        takes: dict[int, str] = {}
        for rva in (blob_rva, text_rva):
            if rva is not None:
                for at in references.get(rva, []):
                    sites.append(at)
                    takes.setdefault(at, "text" if rva != blob_rva else "blob")
        ordered = sorted(set(sites))
        places = [image.where(at) for at in ordered]
        # Where the reference loads the address as a call's argument, which
        # call and which argument (``call_sites.passed_to``), said as the
        # address of the encoded bytes it is; absent otherwise.
        calls = [call_sites.passed_to(image, at) for at in ordered]
        for at, call in zip(ordered, calls, strict=True):
            if call is not None:
                call["address_of"] = takes.get(at, "blob")
        row: dict[str, Any] = {
            "offset": hex(item.blob_offset),
            "rva": hex(blob_rva) if blob_rva is not None else None,
            "text_rva": hex(text_rva) if text_rva is not None else None,
            "section": section.name if section else None,
            "scheme": item.scheme,
            "parameters": item.parameters,
            "text": text,
            "encoding": item.encoding,
            "references": [
                {
                    "at": place["rva"],
                    "section": place["section"],
                    "function": place["function"],
                    **{
                        key: place[key]
                        for key in ("after_function_start", "function_source")
                        if key in place
                    },
                    **({"passed_to": call} if call else {}),
                }
                for place, call in zip(places, calls, strict=True)
            ],
        }
        if item.layers:
            row["layers"] = item.layers
        same = recovered_by.get(text) or next(
            (recovered_by[layer["text"]] for layer in item.layers if layer["text"] in recovered_by),
            None,
        )
        if same is not None:
            also += 1
            row[row_field] = {
                "function_rva": same.get("function_rva"),
                "called_at_rva": same.get("called_at_rva"),
            }
        # A decoder that recovered a reading stated beside the row confirms
        # that reading, never the row's text: it is said apart and not counted.
        alternative = next(
            (
                other
                for other in item.parameters.get("also_read_as", [])
                if other["text"] in recovered_by
            ),
            None,
        )
        alternative_field = f"{row_field}_matches_the_alternative"
        if alternative is not None:
            matched = recovered_by[alternative["text"]]
            row[alternative_field] = {
                "text": alternative["text"],
                "scheme": alternative["scheme"],
                "function_rva": matched.get("function_rva"),
                "called_at_rva": matched.get("called_at_rva"),
            }
        if row["references"] or row_field in row or alternative_field in row:
            results.append(row)
        else:
            unreferenced.append(row)

    start = max(0, int(offset or 0))
    page = results[start:] if limit is None else results[start : start + max(0, int(limit))]
    more = start + len(page) < len(results)
    return {
        "tool": TOOL,
        "image_base": hex(image.image_base),
        "function_table": image.function_table,
        "schemes": list(wanted),
        "sections": [s.name for s in image.data_sections()],
        "readable_test": READABLE_TEST,
        "min_len": minimum,
        "longest_key": LONGEST_KEY,
        compared_field: len(recovered_by),
        also_field: also,
        "results": page,
        "total": len(results),
        "page_offset": start,
        "next_offset": start + len(page) if more else None,
        "unreferenced": len(unreferenced),
        "ambiguous_spans": decoded.ambiguous,
        "outranked_spans": decoded.outranked,
        **({"unreferenced_results": unreferenced} if include_unreferenced else {}),
    }

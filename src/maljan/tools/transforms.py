"""Byte-range transforms: a range of a file, through steps the caller names, stated as facts.

A model that finds an encrypted or encoded blob and the key beside it cannot
run the cipher in its head. This module runs it: the caller names a range of
the file (a file offset, or an address the file's own section table resolves)
and an ordered list of steps, each applied to the previous step's output, and
the answer states what came out. The model decides which cipher, which key and
which range; the platform computes and states.

What the answer states, and what it never does:

* **The input range and every step with its parameters**, so the ledger entry
  is a call anyone can repeat. A key or IV the caller wrote is shown as it was
  written; one the caller pointed at in the file is shown as the range it named
  and the bytes read there.
* **The output as facts**: its length, its SHA-256, a hex head, the text it
  reads as in ASCII and in UTF-16LE (each escaped as the pack writes a string),
  the share of printable bytes, its Shannon entropy, and the indicator shapes
  the platform's indicator reader finds in it, each with its offset in the
  output. Never a word for what the output is: whether it is plaintext, a
  configuration or noise is the reader's call.
* **Errors that name the step and why.** An unknown operation, a key of a
  length the cipher does not take, an input that is not whole blocks, padding
  that is not PKCS#7, an alphabet with a repeated character: each stops the
  call with the step's number and the reason. Nothing is guessed and nothing is
  retried with other parameters.

Bounds come from structure: every step but decompression writes at most as
many bytes as it reads, and decompression is held to the platform's sample
upload cap (``core.delivery_limits``), stated in the step when reached: the
stream is fed a slice at a time and asked for no more than the room left, so
the output never holds more than the cap, gzip members one after another
included. A cut decompression ends the chain, and the bytes all the steps write
together are held to the same cap, so the cost of a step list is bounded by
bytes, not by how many steps it names. A range
past the end of the file is cut at the end and says so; a key range past the
end is an error, because a key cut short is another key. Each step is linear
in its buffer. The file is only read; nothing in it is run.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import string
import zlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import numpy as np

from maljan.core.delivery_limits import SAMPLE_UPLOAD_MAX_BYTES
from maljan.llm.context_window import (
    CHARS_PER_TOKEN,
    MAX_BELIEVABLE_WINDOW_TOKENS,
    UNKNOWN_WINDOW_TOOL_OUTPUT_CHARS,
)
from maljan.tools import pe_image
from maljan.tools.errors import BAD_ARGUMENT, tool_error
from maljan.tools.ioc_spans import string_iocs_with_spans
from maljan.utils.written_forms import PACK_ESCAPES, pack_escaped

TOOL = "transform_bytes"

# The most bytes a decompression step writes, and the chain writes in all: the
# platform's fixed sample upload cap, a number here and not the operator's
# upload setting. A decompressed payload is a file of that kind, and a stream
# that inflates past it is cut there, with the cut stated.
DECOMPRESSED_CAP = SAMPLE_UPLOAD_MAX_BYTES

# The most characters the answer spends per two shown bytes, as JSON writes it:
# the ASCII reading writes a byte as at most a backslash, x and two digits, 5
# characters once JSON escapes the backslash; the UTF-16LE reading writes a pair
# as at most a backslash, x and four digits, 7. The hex head is 64 bytes
# whatever is shown, and the indicator rows take what the room leaves
# (``_within_room``).
_CHARS_PER_TWO_BYTES = 2 * 5 + 7


def _bytes_for(room: int) -> int:
    """How many shown bytes the readings carry in ``room`` characters at their most."""
    return room * 2 // _CHARS_PER_TWO_BYTES


# The part shown when the call does not say: what the room the platform gives
# one tool answer when the model's window is not measured carries.
SHOWN_ROOM = UNKNOWN_WINDOW_TOOL_OUTPUT_CHARS
SHOWN_BYTES = _bytes_for(SHOWN_ROOM)
# The most a call is shown: what the largest tool answer any model gets
# carries, the characters of the largest window this platform believes in.
MAX_SHOWN_ROOM = MAX_BELIEVABLE_WINDOW_TOKENS * CHARS_PER_TOKEN
MAX_SHOWN_BYTES = _bytes_for(MAX_SHOWN_ROOM)

# How many leading bytes of the output are shown in hex. The whole output is
# also stated as text in two readings; the head is the raw view of its start.
HEX_HEAD_BYTES = 64

# The indicator kinds stated in the output, as the indicator reader names them.
INDICATOR_KINDS = ("domain", "url", "ip", "path", "registry")

OPERATIONS = (
    "xor",
    "rc4",
    "aes",
    "base64",
    "hex",
    "lznt1",
    "zlib",
    "gzip",
    "deflate",
    "reverse",
    "slice",
)
AES_MODES = ("ecb", "cbc", "ctr")
AES_PADDINGS = ("none", "pkcs7")
BASE64_ALPHABETS = ("standard", "urlsafe")

# The arguments and operations as the capabilities answer states them.
CAPABILITY_FACTS = (
    "Reads one byte range of the file and applies an ordered list of steps to it, each to the "
    "output of the one before. The range is offset (a file offset), rva or va (resolved through "
    "the file's own section table), with length (to the end of the file when left out; a range "
    "past the end is cut there and says so). Operations, each named by its op: `xor` (key, "
    "optional increment added per byte), `rc4` (key), `aes` (mode ecb, cbc or ctr; key; iv for "
    "cbc; nonce, the 16-byte initial counter block, for ctr; padding none or pkcs7), `base64` "
    "(alphabet standard, urlsafe or 64 characters), `hex`, `lznt1`, `zlib`, `gzip`, `deflate`, "
    "`reverse` and `slice` (start, length). A key, iv "
    'or nonce is {"hex": ...}, {"text": ...} or a range of the same file {"offset": ..., '
    '"length": ...}. The answer states the output\'s length, SHA-256, printable share and '
    "entropy over the whole output, and the hex head, ASCII and UTF-16LE readings and the "
    "indicators found with their offsets over the part shown: the first bytes the 6000 "
    "characters of one answer carry beside its other fields (at most 705), or the part "
    "show_offset and show_length name. Decompression, and the bytes a chain writes in all, stop "
    "at the platform's fixed sample upload cap and say so."
)

REMEDIATION = (
    "correct the argument or step the message names and call again; nothing was tried with "
    "other parameters"
)

_STANDARD_ALPHABET = string.ascii_uppercase + string.ascii_lowercase + string.digits + "+/"
_URLSAFE_ALPHABET = string.ascii_uppercase + string.ascii_lowercase + string.digits + "-_"
_BASE64_PAD = "="
_WHITESPACE = b" \t\r\n\v\f"
_WHITESPACE_SET = frozenset(bytes([byte]) for byte in _WHITESPACE)
_AES_BLOCK = 16
_AES_KEY_SIZES = (16, 24, 32)
# The key lengths cryptography's ARC4 takes; any other length is scheduled by
# the same algorithm written out below, and the two agree where both run.
_ARC4_KEY_BYTES = frozenset({5, 7, 8, 10, 16, 20, 24, 32})
_LZNT1_CHUNK = 4096
# How many bytes the xor step works through at once: a working set, not a
# bound on anything the step reads or writes.
_WORKING_SLICE = 1 << 20
# How much compressed input a decompression step is fed at once, at most and
# first. What follows the end of one gzip member is handed back as a copy of the
# rest of the piece it stood in, so the pieces bound what is copied at each
# member's end: a member's pieces double from the first, so the last is at most
# about the member's own size, and never more than the largest.
_INFLATE_PIECE = 1 << 16
_FIRST_PIECE = 1 << 8
_LZNT1_COMPRESSED = 0x8000
_LZNT1_SIGNATURE = 0x3000
_ZLIB_WINDOWS = {"zlib": 15, "gzip": 31, "deflate": -15}
# The two bytes every gzip member starts with: what follows one member is read
# as the next only when it starts with them.
_GZIP_MAGIC = b"\x1f\x8b"
# Printable ASCII and the three whitespace controls text holds.
_PRINTABLE = np.zeros(256, dtype=bool)
_PRINTABLE[0x20:0x7F] = True
_PRINTABLE[[0x09, 0x0A, 0x0D]] = True
# The ASCII reading, one byte to one written form, applied in one pass: the
# pack's escape for the quote and the controls, every printable ASCII byte as
# itself, and every byte past ASCII as ``\xNN``.
_ASCII_FORMS = {
    code: PACK_ESCAPES.get(chr(code))
    or (chr(code) if code < 0x80 and chr(code).isprintable() else f"\\x{code:02x}")
    for code in range(0x100)
}


class TransformError(ValueError):
    """A call that cannot be computed as asked; the message names where and why."""


@dataclass
class _File:
    """The file's bytes and, when it is a PE, its image."""

    data: bytes
    image: pe_image.Image | None
    not_an_image: str


def _number(value: Any, name: str) -> int:
    """An integer as given, or a string: hexadecimal after ``0x``, decimal otherwise."""
    if isinstance(value, bool):
        raise TransformError(f"{name} is a boolean; give a number")
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    text = str(value).strip() if isinstance(value, str) else ""
    # ASCII digits only: ``int`` also reads other scripts' digits and
    # underscores, which no address or length is written with.
    if text.lower().startswith("0x") and _HEX_DIGITS.fullmatch(text[2:]):
        return int(text[2:], 16)
    if _DECIMAL_DIGITS.fullmatch(text):
        return int(text, 10)
    raise TransformError(
        f"{name} is {str(value)[:40]!r}; give an integer, or a string read as hexadecimal after "
        "0x and as decimal otherwise"
    )


_HEX_DIGITS = re.compile(r"[0-9A-Fa-f]+")
_DECIMAL_DIGITS = re.compile(r"[0-9]+")


def _given(value: Any) -> bool:
    return value is not None and not (isinstance(value, str) and not value.strip())


def _load(path: str) -> _File:
    data = Path(path).read_bytes()
    try:
        return _File(data, pe_image.parse(data), "")
    except Exception as exc:  # noqa: BLE001 — a hostile header is a fact about the file
        reason = str(exc) or type(exc).__name__
        return _File(data, None, reason)


def _sections_said(image: pe_image.Image) -> str:
    return (
        ", ".join(
            f"{s.name} {s.rva:#x}-{s.rva + max(s.virtual_size, s.raw_size):#x}"
            for s in image.sections
        )
        or "none"
    )


def _start_of(file: _File, where: Mapping[str, Any], what: str) -> tuple[int, dict[str, Any]]:
    """The file offset a range starts at, and how it was read, from exactly one coordinate."""
    named = [key for key in ("offset", "rva", "va") if _given(where.get(key))]
    if len(named) != 1:
        said = ", ".join(named) if named else "none of them"
        raise TransformError(f"{what} takes exactly one of offset, rva or va; it was given {said}")
    key = named[0]
    value = _number(where[key], f"{what}'s {key}")
    if value < 0:
        raise TransformError(f"{what}'s {key} is negative")
    if key == "offset":
        if value >= len(file.data):
            raise TransformError(
                f"{what}'s offset {value:#x} is at or past the end of the file "
                f"({len(file.data):#x} bytes)"
            )
        return value, {"offset": hex(value)}
    if file.image is None:
        raise TransformError(
            f"{what}'s {key} needs the file's section table, and the file is not a PE image "
            f"this server maps ({file.not_an_image}); give offset instead"
        )
    image = file.image
    rva = value
    if key == "va":
        if value < image.image_base:
            raise TransformError(
                f"{what}'s va {value:#x} is below the image base {image.image_base:#x}"
            )
        rva = value - image.image_base
    section = image.section_at_rva(rva)
    if section is None:
        raise TransformError(
            f"no section holds {what}'s rva {rva:#x}; the sections are {_sections_said(image)}"
        )
    if rva - section.rva >= section.mapped_size:
        raise TransformError(
            f"{what}'s rva {rva:#x} lies in {section.name} past the bytes the file holds for "
            f"it (they end at rva {section.rva + section.mapped_size:#x}); the loader fills "
            "the rest with zeros and the file has nothing there to read"
        )
    offset = section.raw_offset + (rva - section.rva)
    return offset, {key: hex(value), "offset": hex(offset)}


def _place(file: _File, start: int, end: int) -> dict[str, Any]:
    """The range's place in the image: its rva and section, or ``no:`` with the reason."""
    if file.image is None:
        return {
            "rva": None,
            "section": None,
            "place": f"no: the file is not a PE image ({file.not_an_image}), so the range has "
            "no place in an image",
        }
    section = file.image.section_at_offset(start)
    if section is None:
        return {
            "rva": None,
            "section": None,
            "place": f"no: file offset {start:#x} lies in no section's bytes in the file",
        }
    out: dict[str, Any] = {
        "rva": hex(section.rva + (start - section.raw_offset)),
        "section": section.name,
    }
    section_end = section.raw_offset + section.mapped_size
    if end > section_end:
        out["past_section"] = (
            f"the range runs {end - section_end:#x} bytes past the end of {section.name}'s "
            "bytes in the file; those bytes are read as the file lays them out"
        )
    return out


def _input_range(file: _File, where: Mapping[str, Any]) -> tuple[bytes, dict[str, Any]]:
    start, said = _start_of(file, where, "the range")
    asked = {k: where[k] for k in ("offset", "rva", "va", "length") if _given(where.get(k))}
    end = len(file.data)
    stated: dict[str, Any] = {"asked": asked, **said}
    if _given(where.get("length")):
        length = _number(where["length"], "length")
        if length <= 0:
            raise TransformError(f"length {length} reads no bytes; give a length of 1 or more")
        if start + length > len(file.data):
            stated["cut"] = (
                f"the range asked runs {start + length - len(file.data):#x} bytes past the end "
                f"of the file ({len(file.data):#x} bytes); it was cut at the end"
            )
        else:
            end = start + length
    stated["length"] = end - start
    stated["end"] = hex(end)
    stated.update(_place(file, start, end))
    return file.data[start:end], stated


def _key_bytes(file: _File, spec: Any, name: str) -> tuple[bytes, dict[str, Any]]:
    """A key, IV or nonce: literal hex or text, or a range of the same file."""
    if not isinstance(spec, Mapping):
        raise TransformError(
            f'{name} is {type(spec).__name__}; give it as {{"hex": ...}}, {{"text": ...}} '
            'or a range of this file {"offset": ..., "length": ...}'
        )
    forms = [key for key in ("hex", "text") if key in spec]
    ranged = [key for key in ("offset", "rva", "va") if _given(spec.get(key))]
    if len(forms) + (1 if ranged else 0) != 1:
        raise TransformError(f"{name} takes exactly one of hex, text or a range of this file")
    if forms == ["hex"]:
        text = str(spec["hex"])
        try:
            value = bytes.fromhex(text)
        except ValueError as exc:
            raise TransformError(f"{name}'s hex does not read as bytes: {exc}") from exc
        if not value:
            raise TransformError(f"{name} is empty")
        return value, {"hex": text}
    if forms == ["text"]:
        if not str(spec["text"]):
            raise TransformError(f"{name} is empty")
        return str(spec["text"]).encode("utf-8"), {"text": str(spec["text"]), "encoding": "utf-8"}
    if not _given(spec.get("length")):
        raise TransformError(f"{name} as a range of this file needs its length")
    start, said = _start_of(file, spec, name)
    length = _number(spec["length"], f"{name}'s length")
    if length <= 0:
        raise TransformError(f"{name}'s length {length} reads no bytes")
    if start + length > len(file.data):
        raise TransformError(
            f"{name}'s range {start:#x}+{length:#x} runs past the end of the file "
            f"({len(file.data):#x} bytes); a key cut short would be another key"
        )
    value = file.data[start : start + length]
    asked = {k: spec[k] for k in ("offset", "rva", "va", "length") if _given(spec.get(k))}
    return value, {"asked": asked, **said, "length": length, "read": value.hex()}


# -- operations ---------------------------------------------------------------------------


def _xor(data: bytes, file: _File, step: Mapping[str, Any]) -> tuple[bytes, dict[str, Any]]:
    key, said = _key_bytes(file, step.get("key"), "the key")
    increment = _number(step.get("increment", 0), "increment")
    buffer = np.frombuffer(data, dtype=np.uint8)
    keys = np.frombuffer(key, dtype=np.uint8)
    out = np.empty(len(data), dtype=np.uint8)
    # Worked through in slices so the positions are held a slice at a time.
    for start in range(0, len(data), _WORKING_SLICE):
        stop = min(len(data), start + _WORKING_SLICE)
        positions = np.arange(start, stop, dtype=np.int64)
        stream = keys[positions % len(keys)]
        if increment % 256:
            stream = ((stream + (increment % 256) * positions) & 0xFF).astype(np.uint8)
        out[start:stop] = buffer[start:stop] ^ stream
    return out.tobytes(), {
        "key": said,
        "increment": increment,
        "rule": "output byte i is input byte i exclusive-or ((key byte i mod key length + "
        "increment * i) mod 256)",
    }


def _rc4_stream(key: bytes, data: bytes) -> bytes:
    """RC4 written out, for the key lengths cryptography's ARC4 does not take."""
    box = list(range(256))
    j = 0
    for i in range(256):
        j = (j + box[i] + key[i % len(key)]) & 0xFF
        box[i], box[j] = box[j], box[i]
    out = bytearray(len(data))
    i = j = 0
    for n in range(len(data)):
        i = (i + 1) & 0xFF
        j = (j + box[i]) & 0xFF
        box[i], box[j] = box[j], box[i]
        out[n] = box[(box[i] + box[j]) & 0xFF]
    # The keystream is combined with the input in place, then copied out once.
    stream = np.frombuffer(out, dtype=np.uint8)
    stream ^= np.frombuffer(data, dtype=np.uint8)
    return bytes(out)


def _arc4_key(key: bytes) -> bytes | None:
    """A key cryptography's ARC4 takes that schedules exactly as ``key`` does, or ``None``.

    The schedule reads key byte i mod the key's length for i below 256, so a
    key repeated to a length its own length divides schedules the same: the
    shortest such length ARC4 takes is used (1 byte as 5; 2 and 4 as 8; 3, 6
    and 12 as 24).
    """
    for length in sorted(_ARC4_KEY_BYTES):
        if length % len(key) == 0:
            return key * (length // len(key))
    return None


def _arc4(key: bytes, data: bytes) -> bytes | None:
    """``data`` through cryptography's ARC4, or ``None`` where it cannot run this key."""
    taken = _arc4_key(key)
    if taken is None:
        return None
    key = taken
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher

        try:
            from cryptography.hazmat.decrepit.ciphers.algorithms import ARC4
        except ImportError:  # pragma: no cover - releases before the decrepit module
            from cryptography.hazmat.primitives.ciphers.algorithms import (  # type: ignore[attr-defined,no-redef]
                ARC4,
            )
    except ImportError:  # pragma: no cover - cryptography is a core dependency
        return None
    # nosemgrep: python.cryptography.security.insecure-cipher-algorithms-arc4.insecure-cipher-algorithm-arc4 — the sample's own cipher, reproduced to read its bytes  # noqa: E501
    decryptor = Cipher(ARC4(key), mode=None).decryptor()
    return decryptor.update(data) + decryptor.finalize()


def _rc4(data: bytes, file: _File, step: Mapping[str, Any]) -> tuple[bytes, dict[str, Any]]:
    key, said = _key_bytes(file, step.get("key"), "the key")
    if not 1 <= len(key) <= 256:
        raise TransformError(f"the key is {len(key)} bytes; the cipher takes 1 to 256")
    out = _arc4(key, data)
    return (_rc4_stream(key, data) if out is None else out), {"key": said}


def _aes(data: bytes, file: _File, step: Mapping[str, Any]) -> tuple[bytes, dict[str, Any]]:
    from cryptography.hazmat.primitives import padding as paddings
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    mode_name = str(step.get("mode") or "").strip().lower()
    if mode_name not in AES_MODES:
        raise TransformError(
            f"mode is {str(step.get('mode'))[:20]!r}; aes takes {', '.join(AES_MODES)}"
        )
    padding = str(step.get("padding") or "none").strip().lower()
    if padding not in AES_PADDINGS:
        raise TransformError(f"padding is {padding[:20]!r}; aes takes {', '.join(AES_PADDINGS)}")
    key, key_said = _key_bytes(file, step.get("key"), "the key")
    if len(key) not in _AES_KEY_SIZES:
        raise TransformError(f"the key is {len(key)} bytes; AES takes 16, 24 or 32")
    said: dict[str, Any] = {"mode": mode_name, "key": key_said, "padding": padding}
    second = {"cbc": "iv", "ctr": "nonce"}.get(mode_name)
    for other in ("iv", "nonce"):
        if other != second and other in step and step[other] is not None:
            raise TransformError(f"{mode_name} takes no {other}")
    mode: Any
    if second is None:
        mode = modes.ECB()
    else:
        if step.get(second) is None:
            raise TransformError(f"{mode_name} needs its {second}")
        value, said[second] = _key_bytes(file, step[second], f"the {second}")
        if len(value) != _AES_BLOCK:
            raise TransformError(
                f"the {second} is {len(value)} bytes; {mode_name} takes 16"
                + (
                    " (the initial counter block: the nonce followed by the counter, as the "
                    "code builds it)"
                    if second == "nonce"
                    else ""
                )
            )
        mode = modes.CBC(value) if second == "iv" else modes.CTR(value)
    if mode_name != "ctr" and len(data) % _AES_BLOCK:
        raise TransformError(
            f"the input is {len(data)} bytes, not a whole number of 16-byte blocks; {mode_name} "
            "reads whole blocks"
        )
    if mode_name == "ctr" and padding != "none":
        raise TransformError("ctr is a stream mode and has no padding; give padding none")
    decryptor = Cipher(algorithms.AES(key), mode).decryptor()
    out = decryptor.update(data) + decryptor.finalize()
    if padding == "pkcs7":
        if not out:
            raise TransformError("the input is empty, so there is no PKCS#7 padding to remove")
        unpadder = paddings.PKCS7(128).unpadder()
        try:
            out = unpadder.update(out) + unpadder.finalize()
        except ValueError as exc:
            raise TransformError(
                f"the last block does not end in PKCS#7 padding (its last byte is {out[-1]:#04x})"
            ) from exc
    return out, said


def _base64_alphabet(asked: Any) -> tuple[str, str]:
    name = str(asked if asked is not None else "standard")
    if name == "standard":
        return _STANDARD_ALPHABET, name
    if name == "urlsafe":
        return _URLSAFE_ALPHABET, name
    if len(name) != 64:
        raise TransformError(
            f"the alphabet is {len(name)} characters; give standard, urlsafe or 64 characters"
        )
    if not name.isascii():
        raise TransformError("the alphabet holds a character outside ASCII")
    seen: dict[str, int] = {}
    for position, ch in enumerate(name):
        if ch in seen:
            raise TransformError(
                f"the alphabet holds {ch!r} twice, at positions {seen[ch]} and {position}; "
                "each of the 64 characters stands for one value"
            )
        seen[ch] = position
    if _BASE64_PAD in seen:
        raise TransformError("the alphabet holds '=', which is the padding character")
    return name, "custom"


def _base64(data: bytes, file: _File, step: Mapping[str, Any]) -> tuple[bytes, dict[str, Any]]:
    alphabet, kind = _base64_alphabet(step.get("alphabet"))
    said: dict[str, Any] = {"alphabet": alphabet if kind == "custom" else kind}
    if step.get("skip_whitespace"):
        clash = [ch for ch in alphabet if ch.encode("ascii") in _WHITESPACE_SET]
        if clash:
            raise TransformError(
                f"skip_whitespace would drop {clash[0]!r}, which the alphabet holds as a "
                "character; leave skip_whitespace out for this alphabet"
            )
        data = data.translate(None, _WHITESPACE)
        said["skip_whitespace"] = True
    body = data.rstrip(_BASE64_PAD.encode())
    padded = len(data) - len(body)
    allowed = alphabet.encode("ascii")
    stray = re.search(b"[^" + re.escape(allowed) + b"]", body)
    if stray is not None:
        raise TransformError(
            f"the input holds {bytes([body[stray.start()]])!r} at {stray.start():#x}, which is "
            "not in the alphabet"
        )
    if padded > 2:
        raise TransformError(
            f"the input ends in {padded} '=' characters; the encoding pads with 2 at most"
        )
    if len(body) % 4 == 1:
        raise TransformError(
            f"the input holds {len(body)} characters, one past a whole group of four; no "
            "text in this encoding leaves one over"
        )
    if padded and (len(body) + padded) % 4:
        raise TransformError("the input's '=' padding does not complete its last group of four")
    said["padding"] = "present" if padded else ("absent" if len(body) % 4 else "none needed")
    standard = body.translate(bytes.maketrans(allowed, _STANDARD_ALPHABET.encode("ascii")))
    standard += b"=" * (-len(standard) % 4)
    try:
        return base64.b64decode(standard, validate=True), said
    except binascii.Error as exc:  # pragma: no cover - the checks above leave none
        raise TransformError(f"the input does not decode: {exc}") from exc


def _hex(data: bytes, file: _File, step: Mapping[str, Any]) -> tuple[bytes, dict[str, Any]]:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise TransformError(f"the input holds a byte outside ASCII at {exc.start:#x}") from exc
    try:
        return bytes.fromhex(text), {}
    except ValueError as exc:
        raise TransformError(f"the input does not read as hex: {exc}") from exc


def _lznt1(data: bytes, file: _File, step: Mapping[str, Any]) -> tuple[bytes, dict[str, Any]]:
    """LZNT1 as ``RtlDecompressBuffer`` reads it: 4096-byte chunks, each with a two-byte header."""
    out = bytearray()
    said: dict[str, Any] = {}
    at = 0
    chunks = 0
    while at + 2 <= len(data):
        header = data[at] | data[at + 1] << 8
        if header == 0:
            said["end"] = f"a zero chunk header at {at:#x} ends the stream"
            break
        size = (header & 0x0FFF) + 1
        if header & 0x7000 != _LZNT1_SIGNATURE:
            raise TransformError(
                f"the chunk header at {at:#x} is {header:#06x}; an LZNT1 header carries 3 in "
                "bits 12-14"
            )
        body = data[at + 2 : at + 2 + size]
        if len(body) < size:
            raise TransformError(
                f"the chunk at {at:#x} declares {size} bytes and {len(body)} remain"
            )
        chunk = _lznt1_chunk(body, at + 2) if header & _LZNT1_COMPRESSED else body
        chunks += 1
        if len(out) + len(chunk) > DECOMPRESSED_CAP:
            out += chunk[: DECOMPRESSED_CAP - len(out)]
            said["cut"] = _cap_sentence()
            break
        out += chunk
        at += 2 + size
    else:
        if at < len(data):
            said["trailing"] = "one byte after the last chunk was not read"
    said["chunks"] = chunks
    return bytes(out), said


def _lznt1_chunk(body: bytes, base: int) -> bytes:
    out = bytearray()
    i = 0
    while i < len(body):
        flags = body[i]
        i += 1
        if not flags:
            # Eight literals, taken in one slice.
            out += body[i : i + 8]
            i += 8
            if len(out) > _LZNT1_CHUNK:
                raise TransformError(
                    f"the chunk starting at {base - 2:#x} decompresses past {_LZNT1_CHUNK} bytes"
                )
            continue
        for bit in range(8):
            if i >= len(body):
                break
            if not flags >> bit & 1:
                out.append(body[i])
                i += 1
                continue
            if i + 2 > len(body):
                raise TransformError(f"the copy token at {base + i:#x} is cut by the chunk's end")
            token = body[i] | body[i + 1] << 8
            i += 2
            # The offset field widens by one bit each time the position
            # written so far doubles past 16: halve until under 16, counted.
            halvings = max(0, (len(out) - 1).bit_length() - 4)
            length_mask, offset_shift = 0x0FFF >> halvings, 12 - halvings
            length = (token & length_mask) + 3
            back = (token >> offset_shift) + 1
            if back > len(out):
                raise TransformError(
                    f"the copy token at {base + i - 2:#x} reaches {back} bytes back, before "
                    f"the chunk's start ({len(out)} bytes written)"
                )
            start = len(out) - back
            if back >= length:
                out += out[start : start + length]
            else:
                pattern = bytes(out[start:])
                out += (pattern * (length // back + 1))[:length]
            if len(out) > _LZNT1_CHUNK:
                raise TransformError(
                    f"the chunk starting at {base - 2:#x} decompresses past {_LZNT1_CHUNK} bytes"
                )
    return bytes(out)


def _cap_sentence() -> str:
    return (
        f"the output reached {DECOMPRESSED_CAP} bytes, the platform's sample upload cap, and "
        "was cut there"
    )


def _inflate(
    kind: str,
) -> Callable[[bytes, _File, Mapping[str, Any]], tuple[bytes, dict[str, Any]]]:
    def run(data: bytes, file: _File, step: Mapping[str, Any]) -> tuple[bytes, dict[str, Any]]:
        """Fed a slice of input at a time, each call asked for no more than the room left.

        The output never holds more than the cap and one byte, whatever the
        input expands to; gzip members that follow one another are read in
        turn under that one bound.
        """
        view = memoryview(data)
        out = bytearray()
        said: dict[str, Any] = {}
        at = 0
        members = 0
        while True:
            stream = zlib.decompressobj(_ZLIB_WINDOWS[kind])
            members += 1
            # Each member is fed pieces that double from a small first one, so
            # the bytes handed back at its end are at most about its own size.
            size = _FIRST_PIECE
            try:
                while not stream.eof:
                    if stream.unconsumed_tail:
                        piece: bytes | memoryview = stream.unconsumed_tail
                    elif at < len(data):
                        piece = view[at : at + size]
                        at += len(piece)
                        size = min(size * 2, _INFLATE_PIECE)
                    else:
                        break
                    out += stream.decompress(piece, DECOMPRESSED_CAP - len(out) + 1)
                    if len(out) > DECOMPRESSED_CAP:
                        del out[DECOMPRESSED_CAP:]
                        said["cut"] = _cap_sentence()
                        break
            except zlib.error as exc:
                raise TransformError(
                    f"the input is not a {kind} stream"
                    + (f" (member {members})" if members > 1 else "")
                    + f": {exc}"
                ) from exc
            if "cut" in said:
                break
            if not stream.eof:
                said["end"] = "the input ends before the stream's end marker"
                break
            # What the stream did not use is the tail of the last slice fed.
            at -= len(stream.unused_data)
            if kind == "gzip" and data[at : at + 2] == _GZIP_MAGIC:
                continue
            if at < len(data):
                said["trailing"] = (
                    f"{len(data) - at} bytes follow the stream's end and were not read"
                )
            break
        if kind == "gzip":
            said["members"] = members
        return bytes(out), said

    return run


def _reverse(data: bytes, file: _File, step: Mapping[str, Any]) -> tuple[bytes, dict[str, Any]]:
    return data[::-1], {}


def _slice(data: bytes, file: _File, step: Mapping[str, Any]) -> tuple[bytes, dict[str, Any]]:
    start = _number(step.get("start", 0), "start")
    if start < 0 or start >= len(data):
        raise TransformError(f"start {start} is outside the current buffer of {len(data)} bytes")
    said: dict[str, Any] = {"start": start}
    end = len(data)
    if _given(step.get("length")):
        length = _number(step["length"], "length")
        if length <= 0:
            raise TransformError(f"length {length} keeps no bytes")
        said["length"] = length
        if start + length > len(data):
            said["cut"] = (
                f"the slice runs {start + length - len(data)} bytes past the buffer's end; it "
                "was cut there"
            )
        else:
            end = start + length
    return data[start:end], said


_STEPS: dict[str, Callable[[bytes, _File, Mapping[str, Any]], tuple[bytes, dict[str, Any]]]] = {
    "xor": _xor,
    "rc4": _rc4,
    "aes": _aes,
    "base64": _base64,
    "hex": _hex,
    "lznt1": _lznt1,
    "zlib": _inflate("zlib"),
    "gzip": _inflate("gzip"),
    "deflate": _inflate("deflate"),
    "reverse": _reverse,
    "slice": _slice,
}


# -- what the output reads as ------------------------------------------------------------


def _ascii_reading(data: bytes) -> str:
    """The bytes as ASCII, each byte past it written as an escape, in the pack's escaping."""
    out = data.decode("latin-1").translate(_ASCII_FORMS)
    # A backslash that would end the string is written as the pack writes it.
    return out[:-1] + "\\x5c" if out.endswith("\\") else out


@lru_cache(maxsize=1)
def _bmp_escapes() -> dict[int, str]:
    """The pack's written form of every BMP character it escapes, for one translate pass."""
    out: dict[int, str] = {}
    for code in range(0x10000):
        ch = chr(code)
        if ch == '"' or not ch.isprintable():
            out[code] = PACK_ESCAPES.get(ch) or f"\\x{code:02x}"
    return out


_ASTRAL = re.compile("[\U00010000-\U0010ffff]")


def _utf16_reading(data: bytes) -> str:
    """The bytes as UTF-16LE, in the pack's escaping, written in one translate pass.

    Equal to ``pack_escaped`` of the decoded text: the BMP through a table of
    the characters it escapes, the few characters past the BMP a decoded pair
    makes one at a time.
    """
    text = data[: len(data) // 2 * 2].decode("utf-16-le", errors="surrogatepass")
    out = _ASTRAL.sub(lambda m: pack_escaped(m.group()), text.translate(_bmp_escapes()))
    return out[:-1] + "\\x5c" if out.endswith("\\") else out


def _entropy(counts: Any, total: int) -> float:
    if not total:
        return 0.0
    shares = counts[counts > 0] / total
    return round(float(-(shares * np.log2(shares)).sum()), 4)


def _indicators(shown: bytes, start: int) -> tuple[list[dict[str, Any]], int | None]:
    """The indicator reader's rows over the part shown, each at the offset its match stands.

    The offset is the reader's own match (``string_iocs_with_spans``), as an
    offset in the whole output; the second value is the output offset at which
    the reader's run bound stopped it, or ``None``.
    """
    rows, stopped = string_iocs_with_spans(shown, INDICATOR_KINDS)
    found = [
        {
            "kind": row["kind"],
            "value": pack_escaped(str(row["value"])),
            "offset": start + int(row["start"]),
            "encoding": "utf-16le" if row["width"] == 2 else "ascii",
        }
        for row in rows
    ]
    return found, (None if stopped is None else start + stopped)


def _measures(data: bytes) -> tuple[Any, int, int]:
    """Byte counts, and the printable UTF-16LE pairs, over the whole output a slice at a time.

    The working arrays are a slice long, so measuring an output of the cap's
    size holds the output and one slice, not eight bytes of count per byte.
    """
    counts = np.zeros(256, dtype=np.int64)
    wide = 0
    pairs = len(data) // 2
    buffer = np.frombuffer(data, dtype=np.uint8)
    for start in range(0, pairs * 2, _WORKING_SLICE):
        piece = buffer[start : min(start + _WORKING_SLICE, pairs * 2)].reshape(-1, 2)
        wide += int((_PRINTABLE[piece[:, 0]] & (piece[:, 1] == 0)).sum())
    for start in range(0, len(data), _WORKING_SLICE):
        counts += np.bincount(buffer[start : start + _WORKING_SLICE], minlength=256)
    return counts, wide, pairs


def _fixed_output_chars() -> int:
    """The most characters the output's own fields take besides the readings and the rows.

    Every number at ten digits, every sentence the output can carry, the hex
    head at its 64 bytes: the part of the answer that does not grow with the
    part shown.
    """
    big = 10**10 - 1
    most = {
        "length": big,
        "sha256": "0" * 64,
        "printable_share": 0.1234,
        "printable_share_utf16le": 0.1234,
        "entropy_bits_per_byte": 7.1234,
        "shown": {
            "offset": big,
            "end": big,
            "note": _shown_note(big, big, big),
            "cut": _cut_sentence(big),
        },
        "hex_head": "00" * HEX_HEAD_BYTES,
        "utf16le_note": _UTF16_NOTE,
        "indicator_scan_stopped": _scan_stopped_sentence(big),
        "indicators": [],
        "indicators_left_out": _left_out_sentence(big, big),
        "ascii": "",
        "utf16le": "",
    }
    return len(json.dumps(most))


def _shown_window(
    data: bytes, show_offset: Any, show_length: Any, spent: int
) -> tuple[int, int, int, str | None]:
    """The part shown, the characters it was sized for, and a sentence when a request was cut.

    ``spent`` is what the rest of the answer takes (the input range and the
    steps). The room left after it and the output's own fields is what the
    readings may fill, at their most characters per two bytes.
    """
    fixed = spent + _fixed_output_chars()
    start = _number(show_offset, "show_offset") if _given(show_offset) else 0
    if start < 0 or (data and start >= len(data)) or (not data and start):
        raise TransformError(f"show_offset {start} is outside the output of {len(data)} bytes")
    cut = None
    if _given(show_length):
        length = _number(show_length, "show_length")
        if length < 1:
            raise TransformError(f"show_length {length} shows no bytes; give 1 or more")
        most = _bytes_for(max(0, MAX_SHOWN_ROOM - fixed))
        if length > most:
            cut = _cut_sentence(length, most)
            length = most
        # Never less than the room every answer gets, so a short part still
        # has room for its fields and rows.
        room = min(MAX_SHOWN_ROOM, max(SHOWN_ROOM, -(-length * _CHARS_PER_TWO_BYTES // 2) + fixed))
    else:
        length, room = _bytes_for(max(0, SHOWN_ROOM - fixed)), SHOWN_ROOM
    return start, min(len(data), start + length), room, cut


def _cut_sentence(asked: int, most: int = MAX_SHOWN_BYTES) -> str:
    return (
        f"show_length {asked} was cut to {most}, the most bytes the largest tool answer any "
        f"model gets ({MAX_SHOWN_ROOM} characters) carries beside the rest of this answer, "
        "at the readings' most characters a byte"
    )


def _shown_note(start: int, end: int, total: int) -> str:
    return (
        f"the hex head, the readings and the indicators cover output bytes {start} to {end} "
        f"of {total}; the measures above cover all of them, and show_offset and "
        "show_length show another part"
    )


_UTF16_NOTE = "the shown part's last byte is left out of the UTF-16LE reading"


def _within_room(rows: list[dict[str, Any]], left: int) -> list[dict[str, Any]]:
    """The leading rows whose JSON fits in ``left`` characters."""
    kept: list[dict[str, Any]] = []
    for row in rows:
        left -= len(json.dumps(row)) + 2
        if left < 0:
            break
        kept.append(row)
    return kept


def _output_facts(
    data: bytes, show_offset: Any = None, show_length: Any = None, spent: int = 0
) -> dict[str, Any]:
    start, end, room, cut = _shown_window(data, show_offset, show_length, spent)
    counts, wide, pairs = _measures(data)
    printable = int(counts[_PRINTABLE].sum())
    shown = data[start:end]
    said: dict[str, Any] = {"offset": start, "end": end}
    if start or end < len(data):
        said["note"] = _shown_note(start, end, len(data))
    if cut:
        said["cut"] = cut
    readings = {"ascii": _ascii_reading(shown), "utf16le": _utf16_reading(shown)}
    facts: dict[str, Any] = {
        "length": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "printable_share": round(printable / len(data), 4) if data else 0.0,
        "printable_share_utf16le": round(wide / pairs, 4) if pairs else 0.0,
        "entropy_bits_per_byte": _entropy(counts, len(data)),
        "shown": said,
        "hex_head": shown[:HEX_HEAD_BYTES].hex(),
    }
    if len(shown) % 2:
        facts["utf16le_note"] = _UTF16_NOTE
    rows, stopped = _indicators(shown, start)
    if stopped is not None:
        facts["indicator_scan_stopped"] = _scan_stopped_sentence(stopped)
    # The rows take what the part's room leaves after everything else,
    # the sentence saying some were left out included.
    left_out = _left_out_sentence(len(rows), room)
    left = (
        room
        - spent
        - len(json.dumps({**facts, **readings, "indicators": [], "left_out": left_out}))
    )
    kept = _within_room(rows, left)
    facts["indicators"] = kept
    if len(kept) < len(rows):
        facts["indicators_left_out"] = _left_out_sentence(len(rows) - len(kept), room)
    facts.update(readings)
    return facts


def _scan_stopped_sentence(at: int) -> str:
    return (
        "the indicator reader's bound on the runs it reads stopped it at output byte "
        f"{at}; indicators after it are not stated"
    )


def _left_out_sentence(count: int, room: int) -> str:
    return (
        f"{count} more indicators in the part shown are left out: their rows pass the {room} "
        "characters the part was sized for; a smaller show_length or a later show_offset "
        "states them"
    )


def _steps_of(steps: Any) -> list[Mapping[str, Any]]:
    if steps is None:
        return []
    if not isinstance(steps, list | tuple):
        raise TransformError("steps is a list of steps, each an object with its op")
    for number, step in enumerate(steps, 1):
        if not isinstance(step, Mapping):
            raise TransformError(f"step {number} is {type(step).__name__}; give an object with op")
    return list(steps)


def transform_bytes(
    path: str,
    offset: Any = None,
    rva: Any = None,
    va: Any = None,
    length: Any = None,
    steps: Any = None,
    show_offset: Any = None,
    show_length: Any = None,
) -> dict[str, Any]:
    """The range of ``path`` through ``steps``, stated as facts, or an error naming why."""
    try:
        file = _load(path)
        data, input_said = _input_range(
            file, {"offset": offset, "rva": rva, "va": va, "length": length}
        )
        listed = _steps_of(steps)
    except TransformError as exc:
        return tool_error(BAD_ARGUMENT, str(exc), tool=TOOL, remediation=REMEDIATION)
    done: list[dict[str, Any]] = []
    answer: dict[str, Any] = {"input": input_said, "steps": done}
    written = 0
    for number, step in enumerate(listed, 1):
        if done and "cut" in done[-1] and done[-1]["op"] in _DECOMPRESSIONS:
            answer["stopped"] = _stopped(
                number - 1, len(listed), "the output reached the platform's sample upload cap"
            )
            break
        if written >= DECOMPRESSED_CAP:
            answer["stopped"] = _stopped(
                number - 1,
                len(listed),
                f"the steps had written {written} bytes in all, the platform's sample upload cap",
            )
            break
        op = str(step.get("op") or "").strip().lower()
        run = _STEPS.get(op)
        if run is None:
            return tool_error(
                BAD_ARGUMENT,
                f"step {number}: unknown op {str(step.get('op'))[:40]!r}; the operations are "
                + ", ".join(f"`{name}`" for name in OPERATIONS),
                tool=TOOL,
                remediation=REMEDIATION,
            )
        try:
            out, said = run(data, file, step)
        except TransformError as exc:
            return tool_error(
                BAD_ARGUMENT, f"step {number}, op `{op}`: {exc}", tool=TOOL, remediation=REMEDIATION
            )
        done.append(
            {"step": number, "op": op, **said, "in_length": len(data), "out_length": len(out)}
        )
        written += len(out)
        # The input of a step is let go before the next one runs.
        data = out
        del out
    try:
        # What the input range and the steps take, with the key the output sits under.
        spent = len(json.dumps(answer)) + len(', "output": ')
        answer["output"] = _output_facts(data, show_offset, show_length, spent)
    except TransformError as exc:
        return tool_error(BAD_ARGUMENT, str(exc), tool=TOOL, remediation=REMEDIATION)
    return answer


_DECOMPRESSIONS = frozenset({"zlib", "gzip", "deflate", "lznt1"})


def _stopped(last: int, total: int, why: str) -> str:
    """Why the chain ended before its last step, and which step's output is stated."""
    return (
        f"steps {last + 1} to {total} were not run, because {why} after step {last}; the "
        f"output stated is step {last}'s"
    )

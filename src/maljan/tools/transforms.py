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
upload cap (``core.delivery_limits``), stated in the step when reached. A range
past the end of the file is cut at the end and says so; a key range past the
end is an error, because a key cut short is another key. Each step is linear
in its buffer. The file is only read; nothing in it is run.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import string
import zlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np

from maljan.core.delivery_limits import SAMPLE_UPLOAD_MAX_BYTES
from maljan.tools import pe_image
from maljan.tools.errors import BAD_ARGUMENT, tool_error
from maljan.tools.strings import iocs_from_text
from maljan.utils.written_forms import pack_escaped

TOOL = "transform_bytes"

# The most bytes a decompression step writes: the platform's default cap on a
# sample upload. A decompressed payload is a file of that kind, and a stream
# that inflates past it is cut there, with the cut stated.
DECOMPRESSED_CAP = SAMPLE_UPLOAD_MAX_BYTES

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
    '"length": ...}. The answer states the output\'s length, SHA-256, hex head, ASCII and '
    "UTF-16LE readings, printable share, entropy and the indicators found in it with their offsets."
)

REMEDIATION = (
    "correct the argument or step the message names and call again; nothing was tried with "
    "other parameters"
)

_STANDARD_ALPHABET = string.ascii_uppercase + string.ascii_lowercase + string.digits + "+/"
_URLSAFE_ALPHABET = string.ascii_uppercase + string.ascii_lowercase + string.digits + "-_"
_BASE64_PAD = "="
_WHITESPACE = b" \t\r\n\v\f"
_AES_BLOCK = 16
_AES_KEY_SIZES = (16, 24, 32)
# The key lengths cryptography's ARC4 takes; any other length is scheduled by
# the same algorithm written out below, and the two agree where both run.
_ARC4_KEY_BYTES = frozenset({5, 7, 8, 10, 16, 20, 24, 32})
_LZNT1_CHUNK = 4096
# How many bytes the xor step works through at once: a working set, not a
# bound on anything the step reads or writes.
_WORKING_SLICE = 1 << 20
_LZNT1_COMPRESSED = 0x8000
_LZNT1_SIGNATURE = 0x3000
_ZLIB_WINDOWS = {"zlib": 15, "gzip": 31, "deflate": -15}
# Printable ASCII and the three whitespace controls text holds.
_PRINTABLE = np.zeros(256, dtype=bool)
_PRINTABLE[0x20:0x7F] = True
_PRINTABLE[[0x09, 0x0A, 0x0D]] = True
# Each byte of 0x80 and above written as an escape in the ASCII reading, after
# the pack's own escaping (which writes 0x80-0x9f already).
_HIGH_BYTES = {code: f"\\x{code:02x}" for code in range(0xA0, 0x100)}
# The runs the indicator reader is handed, ASCII and UTF-16LE, from five
# characters: the reader's own floor for a host standing alone.
_ASCII_RUN = re.compile(rb"[\x20-\x7e]{5,}")
_WIDE_RUN = re.compile(rb"(?:[\x20-\x7e]\x00){5,}")


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
    try:
        if text.lower().startswith("0x"):
            return int(text[2:], 16)
        if text.isdigit():
            return int(text, 10)
    except ValueError:
        pass
    raise TransformError(
        f"{name} is {str(value)[:40]!r}; give an integer, or a string read as hexadecimal after "
        "0x and as decimal otherwise"
    )


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
    return (
        np.frombuffer(bytes(out), dtype=np.uint8) ^ np.frombuffer(data, dtype=np.uint8)
    ).tobytes()


def _arc4(key: bytes, data: bytes) -> bytes | None:
    """``data`` through cryptography's ARC4, or ``None`` where it cannot run this key."""
    if len(key) not in _ARC4_KEY_BYTES:
        return None
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
            position = len(out) - 1
            length_mask, offset_shift = 0x0FFF, 12
            while position >= 0x10:
                length_mask >>= 1
                offset_shift -= 1
                position >>= 1
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
        stream = zlib.decompressobj(_ZLIB_WINDOWS[kind])
        try:
            out = stream.decompress(data, DECOMPRESSED_CAP)
            said: dict[str, Any] = {}
            if len(out) >= DECOMPRESSED_CAP and not stream.eof:
                if stream.decompress(stream.unconsumed_tail, 1):
                    said["cut"] = _cap_sentence()
        except zlib.error as exc:
            raise TransformError(f"the input is not a {kind} stream: {exc}") from exc
        if "cut" not in said:
            if not stream.eof:
                said["end"] = "the input ends before the stream's end marker"
            elif stream.unused_data:
                said["trailing"] = (
                    f"{len(stream.unused_data)} bytes follow the stream's end and were not read"
                )
        return out, said

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
    return pack_escaped(data.decode("latin-1")).translate(_HIGH_BYTES)


def _utf16_reading(data: bytes) -> str:
    even = data[: len(data) // 2 * 2]
    return pack_escaped(even.decode("utf-16-le", errors="surrogatepass"))


def _entropy(counts: Any, total: int) -> float:
    if not total:
        return 0.0
    shares = counts[counts > 0] / total
    return round(float(-(shares * np.log2(shares)).sum()), 4)


def _indicators(data: bytes) -> list[dict[str, Any]]:
    """The indicator reader's finds, run by run, each at its first offset in the output."""
    found: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for pattern, width, encoding in ((_ASCII_RUN, 1, "ascii"), (_WIDE_RUN, 2, "utf-16le")):
        for run in pattern.finditer(data):
            text = run.group()[::width].decode("ascii")
            cursors: dict[tuple[str, Any], int] = {}
            for row in iocs_from_text(text, list(INDICATOR_KINDS))["iocs"]:
                value = str(row.get("value") or "")
                key = (str(row["kind"]), value.lower())
                if not value or key in seen:
                    continue
                stream = (key[0], row.get("notes"))
                at = text.find(value, cursors.get(stream, 0))
                if at < 0:
                    at = text.find(value)
                if at < 0:
                    continue
                cursors[stream] = at + len(value)
                seen.add(key)
                found.append(
                    {
                        "kind": key[0],
                        "value": pack_escaped(value),
                        "offset": run.start() + at * width,
                        "encoding": encoding,
                    }
                )
    return found


def _output_facts(data: bytes) -> dict[str, Any]:
    buffer = np.frombuffer(data, dtype=np.uint8)
    counts = np.bincount(buffer, minlength=256) if len(data) else np.zeros(256, dtype=np.int64)
    printable = int(counts[_PRINTABLE].sum())
    pairs = buffer[: len(data) // 2 * 2].reshape(-1, 2)
    wide = int((_PRINTABLE[pairs[:, 0]] & (pairs[:, 1] == 0)).sum()) if len(pairs) else 0
    facts: dict[str, Any] = {
        "length": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "hex_head": data[:HEX_HEAD_BYTES].hex(),
        "printable_share": round(printable / len(data), 4) if data else 0.0,
        "printable_share_utf16le": round(wide / len(pairs), 4) if len(pairs) else 0.0,
        "entropy_bits_per_byte": _entropy(counts, len(data)),
        "indicators": _indicators(data),
        "ascii": _ascii_reading(data),
        "utf16le": _utf16_reading(data),
    }
    if len(data) % 2:
        facts["utf16le_note"] = "the output's last byte is left out of the UTF-16LE reading"
    return facts


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
    for number, step in enumerate(listed, 1):
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
        data = out
    return {"input": input_said, "steps": done, "output": _output_facts(data)}

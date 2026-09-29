"""The published constants of ciphers, hash functions and checksums, found in a file's bytes.

An implementation of a standard algorithm carries the algorithm's own numbers:
the substitution table of a block cipher, the round constants and initial
values of a hash function, the table a checksum is computed with. A reader who
finds them knows which algorithm the code around them implements, and where.

Every set a standard derives is computed from that derivation when first asked
for: the AES tables from the field arithmetic that defines them, the SHA
constants from the roots of the primes, the MD5 table from the sine, the
checksum table and polynomial from the polynomial's terms, the Fowler-Noll-Vo
offset basis from its signature string and Blowfish's initial array from the
digits of pi. The few a specification lists without a derivation (the MD5 and
SHA-1 initial values, the MurmurHash3 constants, the Salsa20 and ChaCha key
strings) are written as it prints them. The tests check each against values
the standards print, and run the hash sets as their algorithms.

How the file is searched, stated in every answer (``SCAN_RULE``):

* a **table** set (a substitution box, a lookup table, an initial array) is
  found only whole: all its entries contiguous, as bytes, or as 32-bit words
  little-endian or big-endian, each order said;
* a **values** set (round constants, initial values, magic numbers) is found
  value by value, each stored little-endian anywhere in the file, aligned or
  not — the form an immediate operand and a table in memory both take on the
  processors these samples run on. The round-constant sets are also looked for
  whole, as a table. A set with several values is listed under ``found`` when
  at least two of its distinct values stand in the file, and under ``lone``
  when exactly one does, because one 32-bit value alone matches by chance in a
  large file; a set of one value is found when that value stands.

Each place is the file offset and, for a PE, the offset from the image base,
the section and the function the file's own function table puts around it
(``pe_image``), with no start guessed. Nothing is limited: every place of every
value is listed. The sample is only read; nothing in it is run.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from maljan.tools import pe_image

TOOL = "find_crypto_constants"

SCAN_RULE = (
    "a table set only whole, as bytes or as 32-bit words in either byte order; a values set "
    "value by value, each little-endian anywhere in the file, and the round-constant sets "
    "also whole; a set of several values is found when at least two of its distinct values "
    "stand in the file and lone when exactly one does"
)

TABLE = "table"
VALUES = "values"


@dataclass(frozen=True)
class ConstantSet:
    """One set of published constants: what it is, its values and how it is searched."""

    id: str
    algorithm: str
    what: str
    kind: str
    # 1 for a byte table, 4 or 8 for words, 0 for byte strings.
    width: int
    values: tuple[Any, ...]
    # A values set also looked for whole, as a table.
    also_whole: bool = False


# ---------------------------------------------------------------------------
# The sets, computed from their definitions
# ---------------------------------------------------------------------------


def _gf_multiply(a: int, b: int) -> int:
    """Multiplication in AES's field, GF(2^8) modulo x^8 + x^4 + x^3 + x + 1."""
    product = 0
    while b:
        if b & 1:
            product ^= a
        a = ((a << 1) ^ 0x11B) if a & 0x80 else (a << 1)
        b >>= 1
    return product & 0xFF


def _aes_sbox() -> tuple[int, ...]:
    inverse = [0] * 256
    for a in range(1, 256):
        for b in range(1, 256):
            if _gf_multiply(a, b) == 1:
                inverse[a] = b
                break
    box = []
    for x in range(256):
        s = inverse[x]
        affine = s
        for shift in range(1, 5):
            affine ^= ((s << shift) | (s >> (8 - shift))) & 0xFF
        box.append(affine ^ 0x63)
    return tuple(box)


def _aes_tables() -> dict[str, tuple[int, ...]]:
    sbox = _aes_sbox()
    inverse = [0] * 256
    for index, value in enumerate(sbox):
        inverse[value] = index
    te0 = tuple(
        (_gf_multiply(s, 2) << 24) | (s << 16) | (s << 8) | _gf_multiply(s, 3) for s in sbox
    )
    td0 = tuple(
        (_gf_multiply(s, 0x0E) << 24)
        | (_gf_multiply(s, 0x09) << 16)
        | (_gf_multiply(s, 0x0D) << 8)
        | _gf_multiply(s, 0x0B)
        for s in inverse
    )
    return {"sbox": sbox, "inverse": tuple(inverse), "te0": te0, "td0": td0}


def _primes(count: int) -> list[int]:
    found: list[int] = []
    candidate = 2
    while len(found) < count:
        if all(candidate % p for p in found if p * p <= candidate):
            found.append(candidate)
        candidate += 1
    return found


def _integer_cube_root(value: int) -> int:
    """The largest integer whose cube is at most ``value``."""
    root = 1 << ((value.bit_length() + 2) // 3)
    while True:
        smaller = (2 * root + value // (root * root)) // 3
        if smaller >= root:
            break
        root = smaller
    while root**3 > value:
        root -= 1
    while (root + 1) ** 3 <= value:
        root += 1
    return root


def _fraction_of_root(prime: int, bits: int, cube: bool) -> int:
    """The first ``bits`` bits of the fractional part of the prime's square or cube root."""
    if cube:
        whole = _integer_cube_root(prime << (3 * bits))
    else:
        whole = math.isqrt(prime << (2 * bits))
    return whole & ((1 << bits) - 1)


def _pi_fraction_words(count: int) -> tuple[int, ...]:
    """The first ``count`` 32-bit words of pi's fractional part, by Machin's formula."""
    bits = 32 * count + 64
    unit = 1 << bits

    def arctan_inverse(x: int) -> int:
        total, term, n, sign = 0, unit // x, 1, 1
        square = x * x
        while term:
            total += sign * (term // n)
            term //= square
            n += 2
            sign = -sign
        return total

    pi = 16 * arctan_inverse(5) - 4 * arctan_inverse(239)
    fraction = (pi - 3 * unit) >> 64
    return tuple((fraction >> (32 * (count - 1 - i))) & 0xFFFFFFFF for i in range(count))


def _crc32_table() -> tuple[int, ...]:
    table = []
    for index in range(256):
        value = index
        for _ in range(8):
            value = (value >> 1) ^ 0xEDB88320 if value & 1 else value >> 1
        table.append(value)
    return tuple(table)


@lru_cache(maxsize=1)
def catalogue() -> tuple[ConstantSet, ...]:
    """Every set the scan looks for, in the order the answer lists them."""
    aes = _aes_tables()
    primes = _primes(80)
    sha256_k = tuple(_fraction_of_root(p, 32, cube=True) for p in primes[:64])
    sha512_k = tuple(_fraction_of_root(p, 64, cube=True) for p in primes[:80])
    sha512_init = tuple(_fraction_of_root(p, 64, cube=False) for p in primes[:8])
    sha384_init = tuple(_fraction_of_root(p, 64, cube=False) for p in primes[8:16])
    md5_t = tuple(int(abs(math.sin(i + 1)) * 2**32) & 0xFFFFFFFF for i in range(64))
    md5_init = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)
    sha1_k = tuple(math.isqrt(n << 60) & 0xFFFFFFFF for n in (2, 3, 5, 10))
    return (
        ConstantSet("aes_sbox", "AES", "forward substitution box", TABLE, 1, aes["sbox"]),
        ConstantSet(
            "aes_inverse_sbox", "AES", "inverse substitution box", TABLE, 1, aes["inverse"]
        ),
        ConstantSet("aes_te0", "AES", "encryption round table", TABLE, 4, aes["te0"]),
        ConstantSet("aes_td0", "AES", "decryption round table", TABLE, 4, aes["td0"]),
        ConstantSet(
            "blowfish_p", "Blowfish", "initial subkey array", TABLE, 4, _pi_fraction_words(18)
        ),
        ConstantSet("crc32_table", "CRC-32", "lookup table", TABLE, 4, _crc32_table()),
        ConstantSet("sha256_k", "SHA-256", "round constants", VALUES, 4, sha256_k, also_whole=True),
        ConstantSet(
            "sha256_init",
            "SHA-256",
            "initial hash values",
            VALUES,
            4,
            tuple(_fraction_of_root(p, 32, cube=False) for p in primes[:8]),
        ),
        ConstantSet(
            "sha224_init",
            "SHA-224",
            "initial hash values",
            VALUES,
            4,
            tuple(value & 0xFFFFFFFF for value in sha384_init),
        ),
        ConstantSet("sha512_k", "SHA-512", "round constants", VALUES, 8, sha512_k, also_whole=True),
        ConstantSet("sha512_init", "SHA-512", "initial hash values", VALUES, 8, sha512_init),
        ConstantSet("sha384_init", "SHA-384", "initial hash values", VALUES, 8, sha384_init),
        ConstantSet("md5_t", "MD5", "sine table", VALUES, 4, md5_t, also_whole=True),
        ConstantSet("md5_init", "MD5", "initial chaining values", VALUES, 4, md5_init),
        ConstantSet(
            "sha1_init", "SHA-1", "initial hash values", VALUES, 4, (*md5_init, 0xC3D2E1F0)
        ),
        ConstantSet("sha1_k", "SHA-1", "round constants", VALUES, 4, sha1_k),
        ConstantSet(
            "golden_ratio",
            "TEA, XTEA, RC5, RC6",
            "golden-ratio constant (the TEA and XTEA delta, RC5 and RC6 Q32)",
            VALUES,
            4,
            (0x9E3779B9,),
        ),
        ConstantSet(
            "golden_ratio_negated",
            "TEA, XTEA",
            "golden-ratio constant negated (the delta subtracted instead of added)",
            VALUES,
            4,
            ((-0x9E3779B9) & 0xFFFFFFFF,),
        ),
        ConstantSet("rc5_p32", "RC5, RC6", "P32 magic constant", VALUES, 4, (0xB7E15163,)),
        ConstantSet(
            "salsa_chacha_sigma",
            "Salsa20, ChaCha",
            "32-byte-key constant",
            VALUES,
            0,
            (b"expand 32-byte k",),
        ),
        ConstantSet(
            "salsa_chacha_tau",
            "Salsa20, ChaCha",
            "16-byte-key constant",
            VALUES,
            0,
            (b"expand 16-byte k",),
        ),
        ConstantSet(
            "crc32_polynomial",
            "CRC-32",
            "generator polynomial",
            VALUES,
            4,
            (_CRC32_POLYNOMIAL,),
        ),
        ConstantSet(
            "crc32_polynomial_reversed",
            "CRC-32",
            "generator polynomial, bit-reversed",
            VALUES,
            4,
            (_bit_reversed(_CRC32_POLYNOMIAL, 32),),
        ),
        ConstantSet(
            "fowler_noll_vo_32",
            "Fowler-Noll-Vo 32-bit",
            "offset basis and prime",
            VALUES,
            4,
            _fowler_noll_vo(32),
        ),
        ConstantSet(
            "fowler_noll_vo_64",
            "Fowler-Noll-Vo 64-bit",
            "offset basis and prime",
            VALUES,
            8,
            _fowler_noll_vo(64),
        ),
        ConstantSet(
            "murmur3_32",
            "MurmurHash3 32-bit",
            "multiplication and finalisation constants",
            VALUES,
            4,
            (0xCC9E2D51, 0x1B873593, 0xE6546B64, 0x85EBCA6B, 0xC2B2AE35),
        ),
    )


# CRC-32's generator polynomial, x^32 + x^26 + x^23 + ... + 1, without its top term.
_CRC32_POLYNOMIAL = sum(1 << power for power in (26, 23, 22, 16, 12, 11, 10, 8, 7, 5, 4, 2, 1, 0))


def _bit_reversed(value: int, bits: int) -> int:
    return int(f"{value:0{bits}b}"[::-1], 2)


def _fowler_noll_vo(bits: int) -> tuple[int, int]:
    """The offset basis and the prime of the Fowler-Noll-Vo hash of ``bits`` bits.

    The prime is 2^24 + 2^8 + 0x93 for 32 bits and 2^40 + 2^8 + 0xb3 for 64;
    the offset basis is the FNV-0 hash, basis zero, of the signature string
    its authors define it by.
    """
    prime = (1 << 24) + 0x193 if bits == 32 else (1 << 40) + 0x1B3
    mask = (1 << bits) - 1
    basis = 0
    for byte in b"chongo <Landon Curt Noll> /\\../\\":
        basis = ((basis * prime) & mask) ^ byte
    return basis, prime


# ---------------------------------------------------------------------------
# The scan
# ---------------------------------------------------------------------------


def _offsets(data: bytes, needle: bytes) -> list[int]:
    found: list[int] = []
    start = data.find(needle)
    while start != -1:
        found.append(start)
        start = data.find(needle, start + 1)
    return found


def _packed(values: Sequence[int], width: int, order: str) -> bytes:
    if width == 1:
        return bytes(values)
    return b"".join(int(v).to_bytes(width, order) for v in values)  # type: ignore[arg-type]


def _value_bytes(value: Any, width: int) -> bytes:
    if isinstance(value, bytes):
        return value
    return int(value).to_bytes(width, "little")


def _said(value: Any, width: int) -> str:
    if isinstance(value, bytes):
        return value.decode("latin-1")
    return f"{int(value):#0{2 + 2 * width}x}"


class _Places:
    """Where an offset is, as the answer states it: the image's reading of a PE, else the offset."""

    def __init__(self, data: bytes, image: pe_image.Image | None) -> None:
        self.data = data
        self.image = image

    def where(self, offset: int) -> dict[str, Any]:
        if self.image is None:
            return {"offset": hex(offset)}
        return dict(self.image.where(offset))


def _tables(entry: ConstantSet, places: _Places) -> list[dict[str, Any]]:
    orders = [("", "little")] if entry.width == 1 else [("little-endian", "little")]
    if entry.width > 1:
        orders.append(("big-endian", "big"))
    found: list[dict[str, Any]] = []
    for said, order in orders:
        needle = _packed(entry.values, entry.width, order)
        for offset in _offsets(places.data, needle):
            found.append({"byte_order": said, "place": places.where(offset)})
    return found


def _values(entry: ConstantSet, places: _Places) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[Any] = set()
    for value in entry.values:
        if value in seen:
            continue
        seen.add(value)
        offsets = _offsets(places.data, _value_bytes(value, entry.width))
        if offsets:
            rows.append(
                {
                    "value": _said(value, entry.width),
                    "places": [places.where(offset) for offset in offsets],
                }
            )
    return rows


def _row(entry: ConstantSet, **found: Any) -> dict[str, Any]:
    return {
        "id": entry.id,
        "algorithm": entry.algorithm,
        "what": entry.what,
        "width": entry.width,
        "of": len(set(entry.values)),
        **found,
    }


def find_crypto_constants(path: str) -> dict[str, Any]:
    """Every published constant set of the catalogue that stands in the file at ``path``."""
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except FileNotFoundError:
        return {"error": f"no such file: {path}", "tool": TOOL}
    except OSError as exc:
        return {"error": f"the file could not be read: {exc}", "tool": TOOL}
    try:
        image: pe_image.Image | None = pe_image.load(path)
    except (pe_image.NotAPortableExecutable, ValueError):
        image = None
    places = _Places(data, image)

    found: list[dict[str, Any]] = []
    lone: list[dict[str, Any]] = []
    for entry in catalogue():
        if entry.kind == TABLE:
            tables = _tables(entry, places)
            if tables:
                found.append(_row(entry, matched=len(set(entry.values)), tables=tables))
            continue
        tables = _tables(entry, places) if entry.also_whole else []
        values = _values(entry, places)
        if not values:
            continue
        row = _row(entry, matched=len(values), values=values)
        if tables:
            row["tables"] = tables
        if len(values) >= 2 or row["of"] == 1 or tables:
            found.append(row)
        else:
            lone.append(row)

    answer: dict[str, Any] = {
        "tool": TOOL,
        "how": SCAN_RULE,
        "sets_searched": len(catalogue()),
        "found": found,
        "total": len(found),
        "lone": lone,
    }
    if image is not None:
        answer["image_base"] = hex(image.image_base)
        answer["function_table"] = image.function_table
    return answer

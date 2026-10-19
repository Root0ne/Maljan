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
(``pe_image``), with no start guessed. Every place of every value is listed,
all values together up to what the largest tool answer any model is given holds
(``pe_image.PLACE_BUDGET``); past it the answer says once how many it left out
(``places_cut``). The sample is only read; nothing in
it is run.
"""

from __future__ import annotations

import math
from array import array
from collections.abc import Sequence
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

import numpy as np

from maljan.tools import pe_image

TOOL = "find_crypto_constants"

SCAN_RULE = (
    "a table set only whole, as bytes or as 32-bit words in either byte order; a values set "
    "value by value, each little-endian anywhere in the file, and the round-constant sets "
    "also whole; a set of several values is found when at least two of its distinct values "
    "stand in the file and lone when exactly one does; sets that share values are named only by "
    "a value that tells them apart, standing within 64 bytes of the shared ones"
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
    # The 64-bit set whose high or low 32-bit halves these values are
    # (``half``: "high" or "low"), and the family the two share.
    halves_of: str = ""
    half: str = ""
    family: str = ""
    # Values one of which must stand for the set to be named, within
    # ``REQUIRED_NEAR`` bytes of one of the set's other values (the same run or
    # table); without one, its values are another set's and that set names them.
    requires: tuple[Any, ...] = ()
    # A set whose values are all in another set, dropped when that one is found.
    yields_to: str = ""
    # The capa namespaces (last segment) that name the same algorithm.
    capa: tuple[str, ...] = ()


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
        ConstantSet(
            "aes_sbox", "AES", "forward substitution box", TABLE, 1, aes["sbox"], capa=("aes",)
        ),
        ConstantSet(
            "aes_inverse_sbox",
            "AES",
            "inverse substitution box",
            TABLE,
            1,
            aes["inverse"],
            capa=("aes",),
        ),
        ConstantSet(
            "aes_te0", "AES", "encryption round table", TABLE, 4, aes["te0"], capa=("aes",)
        ),
        ConstantSet(
            "aes_td0", "AES", "decryption round table", TABLE, 4, aes["td0"], capa=("aes",)
        ),
        ConstantSet(
            "blowfish_p",
            "Blowfish",
            "initial subkey array",
            TABLE,
            4,
            _pi_fraction_words(18),
            capa=("blowfish",),
        ),
        ConstantSet(
            "crc32_table", "CRC-32", "lookup table", TABLE, 4, _crc32_table(), capa=("crc32",)
        ),
        ConstantSet(
            "sha256_k",
            "SHA-256",
            "round constants",
            VALUES,
            4,
            sha256_k,
            also_whole=True,
            halves_of="sha512_k",
            half="high",
            family="SHA-2 family",
            capa=("sha256",),
        ),
        ConstantSet(
            "sha256_init",
            "SHA-256",
            "initial hash values",
            VALUES,
            4,
            tuple(_fraction_of_root(p, 32, cube=False) for p in primes[:8]),
            halves_of="sha512_init",
            half="high",
            family="SHA-2 family",
            capa=("sha256",),
        ),
        ConstantSet(
            "sha224_init",
            "SHA-224",
            "initial hash values",
            VALUES,
            4,
            tuple(value & 0xFFFFFFFF for value in sha384_init),
            halves_of="sha384_init",
            half="low",
            family="SHA-2 family",
            capa=("sha224",),
        ),
        ConstantSet(
            "sha512_k",
            "SHA-512",
            "round constants",
            VALUES,
            8,
            sha512_k,
            also_whole=True,
            capa=("sha512", "sha384"),
        ),
        ConstantSet(
            "sha512_init",
            "SHA-512",
            "initial hash values",
            VALUES,
            8,
            sha512_init,
            capa=("sha512",),
        ),
        ConstantSet(
            "sha384_init",
            "SHA-384",
            "initial hash values",
            VALUES,
            8,
            sha384_init,
            capa=("sha384",),
        ),
        ConstantSet("md5_t", "MD5", "sine table", VALUES, 4, md5_t, also_whole=True, capa=("md5",)),
        ConstantSet(
            "md5_sha1_init",
            "MD5/SHA-1 family",
            "initial values MD5 and SHA-1 share",
            VALUES,
            4,
            md5_init,
            yields_to="sha1_init",
            capa=("md5", "sha1"),
        ),
        ConstantSet(
            "sha1_init",
            "SHA-1",
            "initial hash values",
            VALUES,
            4,
            (*md5_init, 0xC3D2E1F0),
            requires=(0xC3D2E1F0,),
            capa=("sha1",),
        ),
        ConstantSet("sha1_k", "SHA-1", "round constants", VALUES, 4, sha1_k, capa=("sha1",)),
        ConstantSet(
            "golden_ratio",
            "golden-ratio constant",
            "0x9e3779b9, the fraction of the golden ratio in 32 bits, which ciphers and hash "
            "tables both use",
            VALUES,
            4,
            (0x9E3779B9,),
        ),
        ConstantSet(
            "golden_ratio_negated",
            "golden-ratio constant",
            "0x61c88647, the same constant negated",
            VALUES,
            4,
            ((-0x9E3779B9) & 0xFFFFFFFF,),
        ),
        ConstantSet(
            "rc5_p32", "RC5, RC6", "P32 magic constant", VALUES, 4, (0xB7E15163,), capa=("rc6",)
        ),
        ConstantSet(
            "salsa_chacha_sigma",
            "Salsa20, ChaCha",
            "32-byte-key constant",
            VALUES,
            0,
            (b"expand 32-byte k",),
            capa=("salsa20",),
        ),
        ConstantSet(
            "salsa_chacha_tau",
            "Salsa20, ChaCha",
            "16-byte-key constant",
            VALUES,
            0,
            (b"expand 16-byte k",),
            capa=("salsa20",),
        ),
        ConstantSet(
            "crc32_polynomial",
            "CRC-32",
            "generator polynomial",
            VALUES,
            4,
            (_CRC32_POLYNOMIAL,),
            capa=("crc32",),
        ),
        ConstantSet(
            "crc32_polynomial_reversed",
            "CRC-32",
            "generator polynomial, bit-reversed",
            VALUES,
            4,
            (_bit_reversed(_CRC32_POLYNOMIAL, 32),),
            capa=("crc32",),
        ),
        ConstantSet(
            "fowler_noll_vo_32",
            "Fowler-Noll-Vo 32-bit",
            "offset basis and prime",
            VALUES,
            4,
            _fowler_noll_vo(32),
            capa=("fnv",),
        ),
        ConstantSet(
            "fowler_noll_vo_64",
            "Fowler-Noll-Vo 64-bit",
            "offset basis and prime",
            VALUES,
            8,
            _fowler_noll_vo(64),
            capa=("fnv",),
        ),
        ConstantSet(
            "murmur3_32",
            "MurmurHash3 32-bit",
            "multiplication and finalisation constants",
            VALUES,
            4,
            (0xCC9E2D51, 0x1B873593, 0xE6546B64, 0x85EBCA6B, 0xC2B2AE35),
            capa=("murmur",),
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


def _offsets(data: bytes, needle: bytes) -> np.ndarray:
    """Every offset of ``needle`` in ``data``, overlapping ones too, ascending."""
    found = array("q")
    start = data.find(needle)
    while start != -1:
        found.append(start)
        start = data.find(needle, start + 1)
    return np.frombuffer(found, dtype=np.int64) if found else _NONE


_NONE = np.empty(0, dtype=np.int64)


def _member(sorted_offsets: np.ndarray, offsets: np.ndarray) -> np.ndarray:
    """Whether each of ``offsets`` is one of ``sorted_offsets``."""
    if not len(sorted_offsets):
        return np.zeros(len(offsets), dtype=bool)
    index = np.minimum(np.searchsorted(sorted_offsets, offsets), len(sorted_offsets) - 1)
    return np.asarray(sorted_offsets[index] == offsets, dtype=bool)


class _Standing:
    """Where every value of the catalogue stands in the file, found in one pass per width.

    A number is looked up in one array per value (``pe_image.value_offsets``);
    a value written as bytes is found by a search of its own.
    """

    def __init__(self, data: bytes, entries: Sequence[ConstantSet]) -> None:
        self.data = data
        wanted: dict[int, set[int]] = {}
        for entry in entries:
            if entry.kind == TABLE:
                continue
            for value in entry.values:
                if not isinstance(value, bytes):
                    wanted.setdefault(entry.width, set()).add(int(value))
            if entry.width == 8:
                # The 32-bit halves the sets that are halves of it look for apart.
                for value in entry.values:
                    wanted.setdefault(4, set()).update((value & 0xFFFFFFFF, value >> 32))
        self.by_width = {
            width: pe_image.value_offsets(data, values, width) for width, values in wanted.items()
        }

    def of(self, value: Any, width: int) -> np.ndarray:
        if isinstance(value, bytes):
            return _offsets(self.data, value)
        held = self.by_width.get(width, {}).get(int(value))
        if held is None:
            return _offsets(self.data, _value_bytes(value, width))
        return held


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
        # The places every value lists, all values together (``pe_image.PlaceBudget``).
        self.budget = pe_image.PlaceBudget()

    def where(self, offset: int) -> dict[str, Any]:
        if self.image is None:
            return {"offset": hex(offset)}
        return dict(self.image.where(offset))

    def listed(self, offsets: Any) -> list[dict[str, Any]]:
        """The places of ``offsets`` while the answer's place budget lasts."""
        return self.budget.take(offsets, self.where)


def _table_offsets(entry: ConstantSet, data: bytes) -> list[tuple[str, np.ndarray]]:
    """Where ``entry``'s values stand whole, by byte order; empty when nowhere."""
    orders = [("", "little")] if entry.width == 1 else [("little-endian", "little")]
    if entry.width > 1:
        orders.append(("big-endian", "big"))
    found: list[tuple[str, np.ndarray]] = []
    for said, order in orders:
        offsets = _offsets(data, _packed(entry.values, entry.width, order))
        if len(offsets):
            found.append((said, offsets))
    return found


def _tables(found: list[tuple[str, np.ndarray]], places: _Places) -> list[dict[str, Any]]:
    """The whole-set places, stated while the answer's place budget lasts."""
    return [
        {"byte_order": said, "place": place}
        for said, offsets in found
        for place in places.listed(offsets)
    ]


def _value_offsets(entry: ConstantSet, standing: _Standing) -> dict[Any, np.ndarray]:
    """Every distinct value of ``entry`` that stands in the file, with its offsets."""
    found: dict[Any, np.ndarray] = {}
    for value in entry.values:
        if value in found:
            continue
        offsets = standing.of(value, entry.width)
        if len(offsets):
            found[value] = offsets
    return found


def _outside_quadwords(
    offsets: dict[Any, np.ndarray], quadwords: np.ndarray, half: str
) -> dict[Any, np.ndarray]:
    """The 32-bit places that are not the ``half`` of a 64-bit value found at ``quadwords``."""
    shift = 4 if half == "high" else 0
    kept: dict[Any, np.ndarray] = {}
    for value, places in offsets.items():
        outside = places[~_member(quadwords, places - shift)]
        if len(outside):
            kept[value] = outside
    return kept


def _other_halves_stand(
    wide: ConstantSet, standing: _Standing, quadwords: np.ndarray, half: str
) -> bool:
    """Whether two or more of ``wide``'s other 32-bit halves stand apart from its 64-bit values."""
    other = [(value & 0xFFFFFFFF) if half == "high" else (value >> 32) for value in wide.values]
    shift = 0 if half == "high" else 4
    count = 0
    for value in set(other):
        places = standing.of(value, 4)
        if len(places) and not _member(quadwords, places - shift).all():
            count += 1
            if count >= 2:
                return True
    return False


# How near a set's distinguishing value must stand to its other values: within
# one table or one run of immediates, not anywhere in the file.
REQUIRED_NEAR = 64


def _required_beside(entry: ConstantSet, offsets: dict[Any, Any]) -> bool:
    """Whether a distinguishing value stands within ``REQUIRED_NEAR`` bytes of another value."""
    parts = [
        np.asarray(places, dtype=np.int64)
        for value, places in offsets.items()
        if value not in entry.requires
    ]
    others = np.sort(np.concatenate(parts)) if parts else _NONE
    if not len(others):
        return False
    for value in entry.requires:
        at = np.asarray(offsets.get(value, []), dtype=np.int64)
        if not len(at):
            continue
        # The nearest other place at or after ``at - REQUIRED_NEAR`` decides.
        index = np.searchsorted(others, at - REQUIRED_NEAR)
        near = others[np.minimum(index, len(others) - 1)] <= at + REQUIRED_NEAR
        if (near & (index < len(others))).any():
            return True
    return False


def _row(entry: ConstantSet, **found: Any) -> dict[str, Any]:
    return {
        "id": entry.id,
        "algorithm": entry.algorithm,
        "what": entry.what,
        "width": entry.width,
        "of": len(set(entry.values)),
        **found,
    }


def find_crypto_constants(
    path: str,
    function_starts: Sequence[Any] | None = None,
    function_source: str = "",
) -> dict[str, Any]:
    """Every published constant set of the catalogue that stands in the file at ``path``.

    ``function_starts`` (offsets from the image base, from ``function_source``)
    stand in for a function table a PE lacks (``pe_image``).
    """
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except FileNotFoundError:
        return {"error": f"no such file: {path}", "tool": TOOL}
    except OSError as exc:
        return {"error": f"the file could not be read: {exc}", "tool": TOOL}
    try:
        image: pe_image.Image | None = pe_image.parse(data)
    except (pe_image.NotAPortableExecutable, ValueError):
        image = None
    if image is not None:
        pe_image.take_function_starts(image, function_starts, function_source)
    places = _Places(data, image)
    sets = {entry.id: entry for entry in catalogue()}
    standing = _Standing(data, catalogue())
    # Where each 64-bit set's values stand, for the sets that are their halves.
    quadwords = {
        entry.id: np.unique(np.concatenate([_NONE, *_value_offsets(entry, standing).values()]))
        for entry in sets.values()
        if entry.width == 8
    }

    found: list[dict[str, Any]] = []
    lone: list[dict[str, Any]] = []
    for entry in catalogue():
        if entry.kind == TABLE:
            whole = _table_offsets(entry, data)
            if whole:
                tables = _tables(whole, places)
                found.append(_row(entry, matched=len(set(entry.values)), tables=tables))
            continue
        offsets = _value_offsets(entry, standing)
        algorithm = entry.algorithm
        if entry.halves_of:
            wide = quadwords.get(entry.halves_of, _NONE)
            offsets = _outside_quadwords(offsets, wide, entry.half)
            if offsets and _other_halves_stand(sets[entry.halves_of], standing, wide, entry.half):
                algorithm = entry.family
        if entry.requires and not _required_beside(entry, offsets):
            continue
        whole = _table_offsets(entry, data) if entry.also_whole else []
        if not offsets:
            continue
        tables = _tables(whole, places)
        # A value listed twice in a set is one value, stated once.
        values: list[dict[str, Any]] = []
        for value in dict.fromkeys(entry.values):
            if value in offsets:
                said = _said(value, entry.width)
                values.append({"value": said, "places": places.listed(offsets[value])})
        row = _row(entry, matched=len(values), values=values)
        row["algorithm"] = algorithm
        if algorithm != entry.algorithm:
            row["shared_with"] = sets[entry.halves_of].algorithm
        if whole:
            row["tables"] = tables
        if len(values) >= 2 or row["of"] == 1 or whole:
            found.append(row)
        else:
            lone.append(row)
    named = {row["id"] for row in found}
    found = [row for row in found if sets[row["id"]].yields_to not in named]

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
    if places.budget.cut:
        answer["places_cut"] = places.budget.cut
    return answer

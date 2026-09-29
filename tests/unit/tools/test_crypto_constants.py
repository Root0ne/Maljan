"""The published constants of ciphers, hash functions and checksums, found in a file's bytes.

Every set in the catalogue is computed from its definition, never typed in, so
each is checked here against values the standards print. The scan is then run
over synthetic images that hold a table, a pair of round constants, a single
one, a table stored the other way round, and nothing at all.
"""

from __future__ import annotations

import hashlib
import struct
import zlib
from pathlib import Path

from maljan.tools import crypto_constants
from maljan.tools.crypto_constants import catalogue, find_crypto_constants

from .synthetic_pe import DATA_RVA, TEXT_RVA, SyntheticPE


def _set(identifier: str) -> crypto_constants.ConstantSet:
    return {entry.id: entry for entry in catalogue()}[identifier]


class TestTheCatalogueMatchesTheStandards:
    def test_the_block_cipher_tables(self) -> None:
        assert _set("aes_sbox").values[:4] == (0x63, 0x7C, 0x77, 0x7B)
        assert _set("aes_sbox").values[-1] == 0x16
        assert _set("aes_inverse_sbox").values[:4] == (0x52, 0x09, 0x6A, 0xD5)
        assert _set("aes_te0").values[0] == 0xC66363A5
        assert _set("aes_td0").values[0] == 0x51F4A750
        blowfish = _set("blowfish_p").values
        assert (blowfish[0], blowfish[1], blowfish[17]) == (0x243F6A88, 0x85A308D3, 0x8979FB1B)

    def test_the_hash_function_constants(self) -> None:
        sha256 = _set("sha256_k").values
        assert (sha256[0], sha256[1], sha256[63], len(sha256)) == (
            0x428A2F98,
            0x71374491,
            0xC67178F2,
            64,
        )
        assert _set("sha256_init").values == (
            0x6A09E667,
            0xBB67AE85,
            0x3C6EF372,
            0xA54FF53A,
            0x510E527F,
            0x9B05688C,
            0x1F83D9AB,
            0x5BE0CD19,
        )
        assert _set("sha224_init").values[0] == 0xC1059ED8
        assert _set("sha224_init").values[-1] == 0xBEFA4FA4
        sha512 = _set("sha512_k").values
        assert (sha512[0], sha512[79], len(sha512)) == (
            0x428A2F98D728AE22,
            0x6C44198C4A475817,
            80,
        )
        assert _set("sha512_init").values[0] == 0x6A09E667F3BCC908
        assert _set("sha384_init").values[0] == 0xCBBB9D5DC1059ED8
        md5 = _set("md5_t").values
        assert (md5[0], md5[63]) == (0xD76AA478, 0xEB86D391)
        assert _set("md5_init").values == (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)
        assert _set("sha1_init").values[-1] == 0xC3D2E1F0
        assert _set("sha1_k").values == (0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6)

    def test_the_checksum_table_and_the_single_values(self) -> None:
        table = _set("crc32_table").values
        assert (table[0], table[1], table[255]) == (0, 0x77073096, 0x2D02EF8D)
        assert _set("golden_ratio").values == (0x9E3779B9,)
        assert _set("golden_ratio_negated").values == (0x61C88647,)
        assert _set("rc5_p32").values == (0xB7E15163,)
        assert _set("salsa_chacha_sigma").values == (b"expand 32-byte k",)
        assert _set("salsa_chacha_tau").values == (b"expand 16-byte k",)
        assert _set("crc32_polynomial").values == (0x04C11DB7,)
        assert _set("crc32_polynomial_reversed").values == (0xEDB88320,)

    def test_the_non_cryptographic_hash_constants(self) -> None:
        assert _set("fowler_noll_vo_32").values == (0x811C9DC5, 0x01000193)
        assert _set("fowler_noll_vo_64").values == (0xCBF29CE484222325, 0x100000001B3)
        assert _set("murmur3_32").values[:2] == (0xCC9E2D51, 0x1B873593)

    def test_every_set_has_an_id_an_algorithm_and_says_what_it_is(self) -> None:
        ids = [entry.id for entry in catalogue()]
        assert len(ids) == len(set(ids))
        for entry in catalogue():
            assert entry.algorithm and entry.what and entry.values


def _rotr(value: int, shift: int, bits: int) -> int:
    mask = (1 << bits) - 1
    return ((value >> shift) | (value << (bits - shift))) & mask


def _sha2(message: bytes, k: tuple[int, ...], init: tuple[int, ...], bits: int) -> bytes:
    """SHA-256 (``bits`` 32) or SHA-512 (``bits`` 64) over the catalogue's constants."""
    mask = (1 << bits) - 1
    block = 16 * bits // 8
    length = (len(message) * 8).to_bytes(2 * bits // 8, "big")
    padded = message + b"\x80"
    padded += b"\0" * ((block - len(length) - len(padded)) % block) + length
    s0, s1, t0, t1 = ((7, 18, 3), (17, 19, 10), (2, 13, 22), (6, 11, 25))
    if bits == 64:
        s0, s1, t0, t1 = ((1, 8, 7), (19, 61, 6), (28, 34, 39), (14, 18, 41))
    state = list(init)
    width = bits // 8
    for start in range(0, len(padded), block):
        w = [
            int.from_bytes(padded[start + i : start + i + width], "big")
            for i in range(0, block, width)
        ]
        for i in range(16, len(k)):
            a = _rotr(w[i - 15], s0[0], bits) ^ _rotr(w[i - 15], s0[1], bits) ^ (w[i - 15] >> s0[2])
            b = _rotr(w[i - 2], s1[0], bits) ^ _rotr(w[i - 2], s1[1], bits) ^ (w[i - 2] >> s1[2])
            w.append((w[i - 16] + a + w[i - 7] + b) & mask)
        a, b, c, d, e, f, g, h = state
        for i in range(len(k)):
            big1 = _rotr(e, t1[0], bits) ^ _rotr(e, t1[1], bits) ^ _rotr(e, t1[2], bits)
            first = (h + big1 + ((e & f) ^ (~e & g)) + k[i] + w[i]) & mask
            big0 = _rotr(a, t0[0], bits) ^ _rotr(a, t0[1], bits) ^ _rotr(a, t0[2], bits)
            second = (big0 + ((a & b) ^ (a & c) ^ (b & c))) & mask
            h, g, f, e, d, c, b, a = g, f, e, (d + first) & mask, c, b, a, (first + second) & mask
        state = [(x + y) & mask for x, y in zip(state, (a, b, c, d, e, f, g, h), strict=True)]
    return b"".join(value.to_bytes(width, "big") for value in state)


def _md5(message: bytes) -> bytes:
    t = _set("md5_t").values
    shifts = [7, 12, 17, 22] * 4 + [5, 9, 14, 20] * 4 + [4, 11, 16, 23] * 4 + [6, 10, 15, 21] * 4
    padded = message + b"\x80"
    padded += b"\0" * ((56 - len(padded)) % 64) + (len(message) * 8).to_bytes(8, "little")
    state = list(_set("md5_init").values)
    for start in range(0, len(padded), 64):
        m = struct.unpack("<16I", padded[start : start + 64])
        a, b, c, d = state
        for i in range(64):
            if i < 16:
                f, g = (b & c) | (~b & d), i
            elif i < 32:
                f, g = (d & b) | (~d & c), (5 * i + 1) % 16
            elif i < 48:
                f, g = b ^ c ^ d, (3 * i + 5) % 16
            else:
                f, g = c ^ (b | (~d & 0xFFFFFFFF)), (7 * i) % 16
            f = (f + a + t[i] + m[g]) & 0xFFFFFFFF
            a, d, c = d, c, b
            b = (b + ((f << shifts[i]) | (f >> (32 - shifts[i])))) & 0xFFFFFFFF
        state = [(x + y) & 0xFFFFFFFF for x, y in zip(state, (a, b, c, d), strict=True)]
    return struct.pack("<4I", *state)


class TestTheSetsComputeTheAlgorithms:
    """Each hash set, used as the algorithm uses it, gives the digest the standard library gives."""

    MESSAGE = b"a message for the digests"

    def test_sha256(self) -> None:
        digest = _sha2(self.MESSAGE, _set("sha256_k").values, _set("sha256_init").values, 32)
        assert digest == hashlib.sha256(self.MESSAGE).digest()

    def test_sha224(self) -> None:
        digest = _sha2(self.MESSAGE, _set("sha256_k").values, _set("sha224_init").values, 32)
        assert digest[:28] == hashlib.sha224(self.MESSAGE).digest()

    def test_sha512_and_sha384(self) -> None:
        k = _set("sha512_k").values
        assert (
            _sha2(self.MESSAGE, k, _set("sha512_init").values, 64)
            == hashlib.sha512(self.MESSAGE).digest()
        )
        assert (
            _sha2(self.MESSAGE, k, _set("sha384_init").values, 64)[:48]
            == hashlib.sha384(self.MESSAGE).digest()
        )

    def test_md5(self) -> None:
        assert _md5(self.MESSAGE) == hashlib.md5(self.MESSAGE, usedforsecurity=False).digest()

    def test_the_checksum_table(self) -> None:
        table = _set("crc32_table").values
        value = 0xFFFFFFFF
        for byte in self.MESSAGE:
            value = table[(value ^ byte) & 0xFF] ^ (value >> 8)
        assert value ^ 0xFFFFFFFF == zlib.crc32(self.MESSAGE)

    def test_the_reversed_polynomial_computes_the_checksum(self) -> None:
        (polynomial,) = _set("crc32_polynomial_reversed").values
        value = 0xFFFFFFFF
        for byte in self.MESSAGE:
            value ^= byte
            for _ in range(8):
                value = (value >> 1) ^ polynomial if value & 1 else value >> 1
        assert value ^ 0xFFFFFFFF == zlib.crc32(self.MESSAGE)

    def test_the_fowler_noll_vo_set_computes_the_platform_s_own_hash(self) -> None:
        from maljan.tools import api_hashes

        basis, prime = _set("fowler_noll_vo_32").values
        value = basis
        for byte in self.MESSAGE:
            value = ((value ^ byte) * prime) & 0xFFFFFFFF
        assert value == api_hashes.PRIMITIVES["fnv1a32"](self.MESSAGE)


def _write(tmp_path: Path, image: SyntheticPE, name: str = "s.exe") -> str:
    target = tmp_path / name
    target.write_bytes(image.build())
    return str(target)


def _found(answer: dict, key: str = "found") -> dict[str, dict]:
    return {row["id"]: row for row in answer[key]}


class TestTheScan:
    def test_a_whole_table_is_found_where_it_stands(self, tmp_path: Path) -> None:
        image = SyntheticPE()
        image.put("data", 0x100, bytes(_set("aes_sbox").values))
        answer = find_crypto_constants(_write(tmp_path, image))

        row = _found(answer)["aes_sbox"]
        assert row["algorithm"] == "AES"
        assert row["tables"] == [
            {
                "byte_order": "",
                "place": {
                    "offset": row["tables"][0]["place"]["offset"],
                    "rva": hex(DATA_RVA + 0x100),
                    "section": ".data",
                    "function": None,
                },
            }
        ]
        assert answer["total"] == len(answer["found"])

    def test_a_word_table_stored_the_other_way_round_says_so(self, tmp_path: Path) -> None:
        image = SyntheticPE()
        table = _set("crc32_table").values
        image.put("data", 0x0, b"".join(struct.pack(">I", value) for value in table))
        row = _found(find_crypto_constants(_write(tmp_path, image)))["crc32_table"]
        assert [entry["byte_order"] for entry in row["tables"]] == ["big-endian"]

    def test_two_round_constants_in_code_are_found_with_their_function(
        self, tmp_path: Path
    ) -> None:
        function = TEXT_RVA + 0x100
        image = SyntheticPE(functions=[(function, TEXT_RVA + 0x200)])
        k = _set("sha256_k").values
        # add eax, imm32 twice: the unrolled rounds keep the constants as immediates.
        image.put("text", 0x110, b"\x05" + struct.pack("<I", k[0]))
        image.put("text", 0x120, b"\x05" + struct.pack("<I", k[5]))
        row = _found(find_crypto_constants(_write(tmp_path, image)))["sha256_k"]

        assert (row["matched"], row["of"]) == (2, 64)
        assert [value["value"] for value in row["values"]] == [hex(k[0]), hex(k[5])]
        place = row["values"][0]["places"][0]
        assert (place["rva"], place["function"]) == (hex(TEXT_RVA + 0x111), hex(function))

    def test_one_value_of_a_set_of_many_is_lone(self, tmp_path: Path) -> None:
        image = SyntheticPE()
        image.put("data", 0x40, struct.pack("<I", _set("md5_t").values[10]))
        answer = find_crypto_constants(_write(tmp_path, image))
        assert "md5_t" not in _found(answer)
        assert _found(answer, "lone")["md5_t"]["matched"] == 1

    def test_a_single_value_set_is_found_on_its_own(self, tmp_path: Path) -> None:
        image = SyntheticPE()
        image.put("text", 0x40, b"\x05" + struct.pack("<I", 0x9E3779B9))
        image.put("data", 0x80, b"expand 32-byte k")
        found = _found(find_crypto_constants(_write(tmp_path, image)))
        assert found["golden_ratio"]["matched"] == 1
        assert found["salsa_chacha_sigma"]["values"][0]["value"] == "expand 32-byte k"

    def test_a_sixty_four_bit_constant_is_read_as_eight_bytes(self, tmp_path: Path) -> None:
        image = SyntheticPE()
        k = _set("sha512_k").values
        image.put("data", 0x0, struct.pack("<QQ", k[0], k[1]))
        row = _found(find_crypto_constants(_write(tmp_path, image)))["sha512_k"]
        assert row["matched"] == 2 and row["width"] == 8

    def test_a_file_with_none_says_it_looked(self, tmp_path: Path) -> None:
        answer = find_crypto_constants(_write(tmp_path, SyntheticPE()))
        assert answer["found"] == [] and answer["total"] == 0
        assert answer["sets_searched"] == len(catalogue())
        assert answer["how"] == crypto_constants.SCAN_RULE

    def test_a_file_that_is_not_a_pe_is_read_by_file_offset(self, tmp_path: Path) -> None:
        target = tmp_path / "blob.bin"
        target.write_bytes(b"\x7fELF" + b"\0" * 60 + bytes(_set("aes_inverse_sbox").values))
        row = _found(find_crypto_constants(str(target)))["aes_inverse_sbox"]
        assert row["tables"] == [{"byte_order": "", "place": {"offset": hex(64)}}]

    def test_a_missing_file_is_an_error(self, tmp_path: Path) -> None:
        answer = find_crypto_constants(str(tmp_path / "absent"))
        assert "error" in answer

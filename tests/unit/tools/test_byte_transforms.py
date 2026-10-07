"""A byte range of a file through the steps the caller names, stated as facts.

Every blob here is built in the test with the same primitives the module
undoes: a key written by the test, a text encrypted or compressed by the test,
laid into a synthetic file. No sample and no run value is read.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import struct
import zlib
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from maljan.tools import transforms
from maljan.tools.transforms import transform_bytes
from tests.unit.tools.synthetic_pe import DATA_RVA, SyntheticPE

PLAIN = b"beacon to http://update.example.test/gate.php every 60s from HKCU\\Software\\Demo"


def _write(tmp_path: Path, blob: bytes, name: str = "s.bin") -> str:
    target = tmp_path / name
    target.write_bytes(blob)
    return str(target)


def _error(answer: dict[str, Any]) -> str:
    assert "error" in answer, answer
    assert answer["error"]["code"] == "bad_argument"
    return str(answer["error"]["message"])


def _out(answer: dict[str, Any]) -> dict[str, Any]:
    assert "error" not in answer, answer
    return dict(answer["output"])


def _rc4_reference(key: bytes, data: bytes) -> bytes:
    """RC4 as its definition reads, written in the test, for the key lengths any library lacks."""
    box = list(range(256))
    j = 0
    for i in range(256):
        j = (j + box[i] + key[i % len(key)]) % 256
        box[i], box[j] = box[j], box[i]
    out = bytearray()
    i = j = 0
    for byte in data:
        i = (i + 1) % 256
        j = (j + box[i]) % 256
        box[i], box[j] = box[j], box[i]
        out.append(byte ^ box[(box[i] + box[j]) % 256])
    return bytes(out)


def _aes_encrypt(key: bytes, mode: Any, data: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES(key), mode).encryptor()
    return encryptor.update(data) + encryptor.finalize()


def _pkcs7(data: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    return padder.update(data) + padder.finalize()


def _lznt1_compress(data: bytes) -> bytes:
    """A plain LZNT1 writer: greedy matches, the length and offset split as the format sets it."""
    out = bytearray()
    for start in range(0, len(data), 4096):
        chunk = data[start : start + 4096]
        body = bytearray()
        i = 0
        while i < len(chunk):
            flags = 0
            group = bytearray()
            for bit in range(8):
                if i >= len(chunk):
                    break
                position, length_mask, offset_shift = i - 1, 0x0FFF, 12
                while position >= 0x10:
                    length_mask >>= 1
                    offset_shift -= 1
                    position >>= 1
                best_length, best_back = 0, 0
                longest = min(length_mask + 3, len(chunk) - i)
                for back in range(1, min(i, 1 << (16 - offset_shift)) + 1):
                    run = 0
                    while run < longest and chunk[i - back + run] == chunk[i + run]:
                        run += 1
                    if run > best_length:
                        best_length, best_back = run, back
                    if run == longest:
                        break
                if best_length >= 3:
                    flags |= 1 << bit
                    token = ((best_back - 1) << offset_shift) | (best_length - 3)
                    group += struct.pack("<H", token)
                    i += best_length
                else:
                    group.append(chunk[i])
                    i += 1
            body.append(flags)
            body += group
        out += struct.pack("<H", 0xB000 | (len(body) - 1)) + body
    return bytes(out)


class TestTheCiphers:
    def test_rc4_with_a_key_of_any_length(self, tmp_path: Path) -> None:
        for key in (b"k", b"k3y!x", b"six-ch", b"0123456789abcdef", bytes(range(256))):
            path = _write(tmp_path, b"\x90" * 8 + _rc4_reference(key, PLAIN))
            answer = transform_bytes(
                path,
                offset=8,
                length=len(PLAIN),
                steps=[{"op": "rc4", "key": {"hex": key.hex()}}],
            )
            out = _out(answer)
            assert out["sha256"] == hashlib.sha256(PLAIN).hexdigest(), len(key)
            assert answer["steps"][0]["key"] == {"hex": key.hex()}

    def test_rc4_written_out_and_the_library_agree_where_both_run(self) -> None:
        for size in sorted(transforms._ARC4_KEY_BYTES):
            key = bytes(range(1, size + 1))
            assert transforms._arc4(key, PLAIN) == transforms._rc4_stream(key, PLAIN)

    def test_aes_in_each_mode(self, tmp_path: Path) -> None:
        key = bytes(range(32))
        iv = bytes(range(16, 32))
        cases = [
            ({"mode": "ecb", "padding": "pkcs7"}, _aes_encrypt(key, modes.ECB(), _pkcs7(PLAIN))),
            (
                {"mode": "cbc", "padding": "pkcs7", "iv": {"hex": iv.hex()}},
                _aes_encrypt(key, modes.CBC(iv), _pkcs7(PLAIN)),
            ),
            ({"mode": "ctr", "nonce": {"hex": iv.hex()}}, _aes_encrypt(key, modes.CTR(iv), PLAIN)),
        ]
        for step, blob in cases:
            path = _write(tmp_path, blob)
            answer = transform_bytes(
                path, offset=0, steps=[{"op": "aes", "key": {"hex": key.hex()}, **step}]
            )
            assert _out(answer)["sha256"] == hashlib.sha256(PLAIN).hexdigest(), step["mode"]

    def test_xor_single_multi_and_rising(self, tmp_path: Path) -> None:
        key = b"\x5a\xa5\x13"
        rising = bytes(b ^ ((key[i % 3] + 7 * i) & 0xFF) for i, b in enumerate(PLAIN))
        path = _write(tmp_path, rising)
        answer = transform_bytes(
            path, offset=0, steps=[{"op": "xor", "key": {"hex": key.hex()}, "increment": 7}]
        )
        assert _out(answer)["sha256"] == hashlib.sha256(PLAIN).hexdigest()
        single = bytes(b ^ 0x41 for b in PLAIN)
        path = _write(tmp_path, single, "single.bin")
        answer = transform_bytes(path, offset=0, steps=[{"op": "xor", "key": {"text": "A"}}])
        assert _out(answer)["sha256"] == hashlib.sha256(PLAIN).hexdigest()


class TestTheEncodingsAndCompressions:
    def test_each_alphabet_of_base64(self, tmp_path: Path) -> None:
        custom = "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba9876543210+/"
        standard = base64.b64encode(PLAIN)
        swapped = standard.translate(
            bytes.maketrans(transforms._STANDARD_ALPHABET.encode(), custom.encode())
        )
        for alphabet, text in (
            ("standard", standard),
            ("urlsafe", base64.urlsafe_b64encode(PLAIN).rstrip(b"=")),
            (custom, swapped),
        ):
            path = _write(tmp_path, text)
            answer = transform_bytes(path, offset=0, steps=[{"op": "base64", "alphabet": alphabet}])
            assert _out(answer)["sha256"] == hashlib.sha256(PLAIN).hexdigest(), alphabet

    def test_hex_reverse_and_slice(self, tmp_path: Path) -> None:
        path = _write(tmp_path, PLAIN[::-1].hex().encode())
        answer = transform_bytes(
            path,
            offset=0,
            steps=[{"op": "hex"}, {"op": "reverse"}, {"op": "slice", "start": 10, "length": 5}],
        )
        assert _out(answer)["ascii"] == PLAIN[10:15].decode()

    def test_zlib_gzip_raw_deflate_and_lznt1(self, tmp_path: Path) -> None:
        raw = zlib.compressobj(9, zlib.DEFLATED, -15)
        deflated = raw.compress(PLAIN * 40) + raw.flush()
        for op, blob in (
            ("zlib", zlib.compress(PLAIN * 40)),
            ("gzip", gzip.compress(PLAIN * 40)),
            ("deflate", deflated),
            ("lznt1", _lznt1_compress(PLAIN * 40)),
        ):
            path = _write(tmp_path, blob)
            answer = transform_bytes(path, offset=0, steps=[{"op": op}])
            assert _out(answer)["sha256"] == hashlib.sha256(PLAIN * 40).hexdigest(), op

    def test_lznt1_by_the_format_s_own_rule(self, tmp_path: Path) -> None:
        # Three literals, then one copy of six bytes from three back: flags 0x08,
        # token (3 - 1) << 12 | (6 - 3); the header holds 3 in bits 12-14 and
        # the compressed bit, and the body's length less one.
        path = _write(tmp_path, b"\x05\xb0\x08abc\x03\x20")
        assert _out(transform_bytes(path, offset=0, steps=[{"op": "lznt1"}]))["ascii"] == (
            "abcabcabc"
        )

    def test_a_key_read_from_a_range_of_the_same_file(self, tmp_path: Path) -> None:
        key = b"range-key-0123"
        blob = key + b"\0\0" + _rc4_reference(key, PLAIN)
        path = _write(tmp_path, blob)
        answer = transform_bytes(
            path,
            offset=len(key) + 2,
            steps=[{"op": "rc4", "key": {"offset": 0, "length": len(key)}}],
        )
        assert _out(answer)["sha256"] == hashlib.sha256(PLAIN).hexdigest()
        said = answer["steps"][0]["key"]
        assert said["offset"] == "0x0" and said["length"] == len(key)
        assert said["read"] == key.hex()

    def test_steps_chain_in_order(self, tmp_path: Path) -> None:
        key = b"chain"
        blob = base64.b64encode(_rc4_reference(key, zlib.compress(PLAIN)))
        path = _write(tmp_path, blob)
        answer = transform_bytes(
            path,
            offset=0,
            steps=[
                {"op": "base64"},
                {"op": "rc4", "key": {"text": "chain"}},
                {"op": "zlib"},
            ],
        )
        assert _out(answer)["sha256"] == hashlib.sha256(PLAIN).hexdigest()
        assert [s["op"] for s in answer["steps"]] == ["base64", "rc4", "zlib"]
        assert answer["steps"][1]["in_length"] == answer["steps"][0]["out_length"]


class TestTheAnswerStatesFacts:
    def test_measures_and_readings(self, tmp_path: Path) -> None:
        wide = "C:\\Users\\Public\\run.exe".encode("utf-16-le")
        # The wide text starts at an even offset, where the UTF-16LE reading of
        # the whole output reads it; the indicator reader finds it at either.
        gap = b"\0" * (2 + len(PLAIN) % 2)
        blob = PLAIN + gap + wide
        path = _write(tmp_path, blob)
        out = _out(transform_bytes(path, offset=0))
        assert out["length"] == len(blob)
        assert out["hex_head"] == blob[: transforms.HEX_HEAD_BYTES].hex()
        assert out["ascii"].startswith(PLAIN[:20].decode())
        assert "\\x00" in out["ascii"]
        assert "C:\\Users\\Public\\run.exe" in out["utf16le"]
        assert 0 < out["printable_share"] < 1
        assert 0 < out["entropy_bits_per_byte"] <= 8
        kinds = {(row["kind"], row["value"]): row for row in out["indicators"]}
        url = kinds[("url", "http://update.example.test/gate.php")]
        assert url["offset"] == PLAIN.index(b"http") and url["encoding"] == "ascii"
        path_row = kinds[("path", "C:\\Users\\Public\\run.exe")]
        assert path_row["offset"] == len(PLAIN) + len(gap)
        assert path_row["encoding"] == "utf-16le"
        shifted = _write(tmp_path, b"\x01" + blob, "shifted.bin")
        rows = _out(transform_bytes(shifted, offset=0))["indicators"]
        assert {"kind": "path", "value": "C:\\Users\\Public\\run.exe"}.items() <= next(
            r for r in rows if r["kind"] == "path"
        ).items()

    def test_the_ascii_reading_is_the_pack_s_escaping_with_high_bytes_written_out(self) -> None:
        from maljan.utils.written_forms import pack_escaped

        every = bytes(range(256)) + b"\\"
        expected = pack_escaped(every.decode("latin-1")).translate(
            {code: f"\\x{code:02x}" for code in range(0xA0, 0x100)}
        )
        assert transforms._ascii_reading(every) == expected
        assert transforms._ascii_reading(b"a\\") == pack_escaped("a\\")

    def test_the_entropy_of_known_buffers(self, tmp_path: Path) -> None:
        path = _write(tmp_path, bytes(range(256)) * 4)
        assert _out(transform_bytes(path, offset=0))["entropy_bits_per_byte"] == 8.0
        path = _write(tmp_path, b"A" * 64, "flat.bin")
        assert _out(transform_bytes(path, offset=0))["entropy_bits_per_byte"] == 0.0

    def test_no_word_says_what_the_output_is(self, tmp_path: Path) -> None:
        path = _write(tmp_path, _rc4_reference(b"k3y!x", PLAIN))
        answer = transform_bytes(path, offset=0, steps=[{"op": "rc4", "key": {"text": "k3y!x"}}])
        keys = " ".join(str(k) for k in answer) + " " + " ".join(answer["output"])
        for word in ("decrypt", "config", "plaintext", "verdict", "malicious"):
            assert word not in keys.lower()


class TestTheRange:
    def test_rva_and_va_resolve_through_the_section_table(self, tmp_path: Path) -> None:
        image = SyntheticPE()
        at = image.put("data", 0x40, _rc4_reference(b"k3y!x", PLAIN))
        path = _write(tmp_path, image.build(), "s.exe")
        for where in ({"rva": hex(at)}, {"va": hex(image.image_base + at)}):
            answer = transform_bytes(
                path, length=len(PLAIN), steps=[{"op": "rc4", "key": {"text": "k3y!x"}}], **where
            )
            assert _out(answer)["sha256"] == hashlib.sha256(PLAIN).hexdigest()
            assert answer["input"]["rva"] == hex(at)
            assert answer["input"]["section"] == ".data"

    def test_a_file_offset_in_an_image_states_its_place(self, tmp_path: Path) -> None:
        image = SyntheticPE()
        path = _write(tmp_path, image.build(), "s.exe")
        from maljan.tools import pe_image

        loaded = pe_image.load(path)
        data = next(s for s in loaded.sections if s.name == ".data")
        answer = transform_bytes(path, offset=data.raw_offset + 0x10, length=4)
        assert answer["input"]["rva"] == hex(DATA_RVA + 0x10)
        header = transform_bytes(path, offset=0, length=2)
        assert header["input"]["rva"] is None
        assert header["input"]["place"].startswith("no: file offset 0x0 lies in no section")

    def test_an_address_no_section_holds_is_an_error_naming_why(self, tmp_path: Path) -> None:
        path = _write(tmp_path, SyntheticPE().build(), "s.exe")
        message = _error(transform_bytes(path, rva="0x90000", length=4))
        assert "no section holds" in message and ".text" in message
        message = _error(transform_bytes(path, va="0x10", length=4))
        assert "below the image base" in message
        flat = _write(tmp_path, b"not an image at all", "flat.bin")
        message = _error(transform_bytes(flat, rva="0x10", length=4))
        assert "not a PE image" in message and "give offset" in message

    def test_a_range_past_the_end_is_cut_and_says_so(self, tmp_path: Path) -> None:
        path = _write(tmp_path, PLAIN)
        answer = transform_bytes(path, offset=4, length=10_000)
        assert answer["input"]["length"] == len(PLAIN) - 4
        assert "cut at the end" in answer["input"]["cut"]
        whole = transform_bytes(path, offset=4)
        assert whole["input"]["length"] == len(PLAIN) - 4 and "cut" not in whole["input"]

    def test_exactly_one_coordinate(self, tmp_path: Path) -> None:
        path = _write(tmp_path, PLAIN)
        assert "exactly one of offset, rva or va" in _error(transform_bytes(path))
        assert "exactly one" in _error(transform_bytes(path, offset=0, rva="0x1000"))

    def test_numbers_as_written(self, tmp_path: Path) -> None:
        path = _write(tmp_path, PLAIN)
        assert transform_bytes(path, offset="0x10", length="4")["input"]["offset"] == "0x10"
        assert transform_bytes(path, offset="16", length=4)["input"]["offset"] == "0x10"
        assert "give an integer" in _error(transform_bytes(path, offset="ten", length=4))


class TestHostileInputs:
    def test_a_zip_bomb_stops_at_the_stated_cap(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(transforms, "DECOMPRESSED_CAP", 1 << 16)
        path = _write(tmp_path, zlib.compress(b"\0" * (1 << 22), 9))
        answer = transform_bytes(path, offset=0, steps=[{"op": "zlib"}])
        assert answer["output"]["length"] == 1 << 16
        assert "cut there" in answer["steps"][0]["cut"]
        lznt = _write(tmp_path, _lznt1_compress(b"\0" * (1 << 17)), "l.bin")
        answer = transform_bytes(lznt, offset=0, steps=[{"op": "lznt1"}])
        assert answer["output"]["length"] == 1 << 16 and "cut there" in answer["steps"][0]["cut"]

    def test_the_default_cap_is_the_platform_s_upload_cap(self) -> None:
        from maljan.core.delivery_limits import SAMPLE_UPLOAD_MAX_BYTES

        assert transforms.DECOMPRESSED_CAP == SAMPLE_UPLOAD_MAX_BYTES

    def test_a_truncated_stream_and_trailing_bytes_are_stated(self, tmp_path: Path) -> None:
        packed = zlib.compress(PLAIN * 10)
        path = _write(tmp_path, packed[:-8])
        answer = transform_bytes(path, offset=0, steps=[{"op": "zlib"}])
        assert "before the stream's end marker" in answer["steps"][0]["end"]
        path = _write(tmp_path, packed + b"tail", "t.bin")
        answer = transform_bytes(path, offset=0, steps=[{"op": "zlib"}])
        assert answer["steps"][0]["trailing"].startswith("4 bytes follow")

    def test_a_zero_length_range(self, tmp_path: Path) -> None:
        path = _write(tmp_path, PLAIN)
        assert "reads no bytes" in _error(transform_bytes(path, offset=0, length=0))
        assert "past the end of the file" in _error(transform_bytes(path, offset=len(PLAIN)))

    def test_a_key_range_past_the_end(self, tmp_path: Path) -> None:
        path = _write(tmp_path, PLAIN)
        message = _error(
            transform_bytes(
                path,
                offset=0,
                steps=[{"op": "rc4", "key": {"offset": len(PLAIN) - 2, "length": 16}}],
            )
        )
        assert message.startswith("step 1, op `rc4`: the key's range")
        assert "a key cut short would be another key" in message

    def test_a_custom_alphabet_with_repeats(self, tmp_path: Path) -> None:
        path = _write(tmp_path, base64.b64encode(PLAIN))
        alphabet = "A" + transforms._STANDARD_ALPHABET[:63]
        message = _error(
            transform_bytes(path, offset=0, steps=[{"op": "base64", "alphabet": alphabet}])
        )
        assert "holds 'A' twice, at positions 0 and 1" in message

    def test_aes_with_a_wrong_iv_length_and_other_misfits(self, tmp_path: Path) -> None:
        path = _write(tmp_path, bytes(48))
        key = {"hex": "00" * 16}

        def aes(**step: Any) -> str:
            return _error(
                transform_bytes(path, offset=0, steps=[{"op": "aes", "key": key, **step}])
            )

        assert "the iv is 8 bytes; cbc takes 16" in aes(mode="cbc", iv={"hex": "00" * 8})
        assert "cbc needs its iv" in aes(mode="cbc")
        assert "ecb takes no iv" in aes(mode="ecb", iv={"hex": "00" * 16})
        assert "aes takes ecb, cbc, ctr" in aes(mode="gcm")
        assert "AES takes 16, 24 or 32" in _error(
            transform_bytes(
                path, offset=0, steps=[{"op": "aes", "mode": "ecb", "key": {"hex": "00" * 15}}]
            )
        )
        odd = _write(tmp_path, bytes(20), "odd.bin")
        assert "not a whole number of 16-byte blocks" in _error(
            transform_bytes(odd, offset=0, steps=[{"op": "aes", "mode": "ecb", "key": key}])
        )
        assert "does not end in PKCS#7 padding" in aes(mode="ecb", padding="pkcs7")

    def test_unknown_operations_and_keys_not_given_as_a_form(self, tmp_path: Path) -> None:
        path = _write(tmp_path, PLAIN)
        message = _error(transform_bytes(path, offset=0, steps=[{"op": "rot13"}]))
        assert message.startswith("step 1: unknown op 'rot13'") and "lznt1" in message
        message = _error(transform_bytes(path, offset=0, steps=[{"op": "xor", "key": "41"}]))
        assert message.startswith("step 1, op `xor`: the key is str")
        message = _error(transform_bytes(path, offset=0, steps=[{"op": "xor", "key": {"hex": ""}}]))
        assert "the key is empty" in message

    def test_bad_encodings_name_where(self, tmp_path: Path) -> None:
        path = _write(tmp_path, b"QUJD*REVG")
        assert "b'*' at 0x4" in _error(transform_bytes(path, offset=0, steps=[{"op": "base64"}]))
        path = _write(tmp_path, b"QUJDR", "one.bin")
        assert "one past a whole group" in _error(
            transform_bytes(path, offset=0, steps=[{"op": "base64"}])
        )
        path = _write(tmp_path, b"4142zz", "hex.bin")
        assert "does not read as hex" in _error(
            transform_bytes(path, offset=0, steps=[{"op": "hex"}])
        )
        path = _write(tmp_path, b"\x05\x00abcdef", "lz.bin")
        assert "carries 3 in bits 12-14" in _error(
            transform_bytes(path, offset=0, steps=[{"op": "lznt1"}])
        )
        path = _write(tmp_path, b"\x02\xb0\x01\x05\x00", "back.bin")
        assert "before the chunk's start" in _error(
            transform_bytes(path, offset=0, steps=[{"op": "lznt1"}])
        )

    def test_each_step_is_linear_in_its_buffer(self, tmp_path: Path) -> None:
        import time

        def timed(size: int) -> float:
            blob = bytes(range(256)) * (size // 256)
            path = _write(tmp_path, base64.b64encode(blob), f"{size}.bin")
            started = time.perf_counter()
            transform_bytes(
                path,
                offset=0,
                steps=[
                    {"op": "base64"},
                    {"op": "xor", "key": {"hex": "5a"}, "increment": 3},
                    {"op": "rc4", "key": {"text": "abc"}},
                ],
            )
            return time.perf_counter() - started

        small, large = timed(1 << 16), timed(1 << 19)
        # Eight times the bytes; a quadratic step would take some sixty times as long.
        assert large < small * 24 + 0.5


CAP = 1 << 18


def _peak(call: Any) -> tuple[Any, int]:
    """The call's answer and the most memory Python and numpy held at once while it ran."""
    import tracemalloc

    tracemalloc.start()
    try:
        answer = call()
        return answer, tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


class TestGrowthIsBounded:
    """Every way the output can grow stops at the cap, says so, and holds memory to it.

    The cap is set to 256 KiB here; each input expands to many times that. The
    answer carries two text readings of the output, each a few characters a
    byte, so the peak is held to a small multiple of the cap and below what the
    input would have expanded to.
    """

    @pytest.fixture(autouse=True)
    def _small_cap(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(transforms, "DECOMPRESSED_CAP", CAP)

    def _bounded(self, answer: dict[str, Any], peak: int, expands_to: int) -> None:
        assert "error" not in answer, answer
        assert answer["output"]["length"] <= CAP
        assert peak < 16 * CAP < expands_to, peak

    def test_a_zlib_bomb(self, tmp_path: Path) -> None:
        path = _write(tmp_path, zlib.compress(b"\0" * (64 * CAP), 9))
        answer, peak = _peak(lambda: transform_bytes(path, offset=0, steps=[{"op": "zlib"}]))
        self._bounded(answer, peak, 64 * CAP)
        assert answer["output"]["length"] == CAP
        assert "sample upload cap, and was cut there" in answer["steps"][0]["cut"]

    def test_a_raw_deflate_bomb(self, tmp_path: Path) -> None:
        raw = zlib.compressobj(9, zlib.DEFLATED, -15)
        path = _write(tmp_path, raw.compress(b"\0" * (64 * CAP)) + raw.flush())
        answer, peak = _peak(lambda: transform_bytes(path, offset=0, steps=[{"op": "deflate"}]))
        self._bounded(answer, peak, 64 * CAP)
        assert "cut" in answer["steps"][0]

    def test_gzip_members_count_toward_one_bound(self, tmp_path: Path) -> None:
        member = gzip.compress(b"\0" * (CAP // 4))
        path = _write(tmp_path, member * 64)
        answer, peak = _peak(lambda: transform_bytes(path, offset=0, steps=[{"op": "gzip"}]))
        self._bounded(answer, peak, 16 * CAP + 1)
        assert answer["output"]["length"] == CAP and "cut" in answer["steps"][0]
        assert answer["steps"][0]["members"] == 5
        small = _write(tmp_path, gzip.compress(b"one ") + gzip.compress(b"two") + b"tail", "g.bin")
        answer = transform_bytes(small, offset=0, steps=[{"op": "gzip"}])
        assert answer["output"]["ascii"] == "one two"
        assert answer["steps"][0]["members"] == 2
        assert answer["steps"][0]["trailing"].startswith("4 bytes follow")

    def test_many_tiny_gzip_members_stay_linear(self, tmp_path: Path) -> None:
        path = _write(tmp_path, gzip.compress(b"ab") * 20_000)
        answer = transform_bytes(path, offset=0, steps=[{"op": "gzip"}])
        assert answer["steps"][0]["members"] == 20_000
        assert answer["output"]["length"] == 40_000

    def test_a_nested_chain_stops_at_the_cap(self, tmp_path: Path) -> None:
        inner = zlib.compress(b"\0" * (64 * CAP), 9)
        path = _write(tmp_path, zlib.compress(zlib.compress(inner, 9), 9))
        steps = [{"op": "zlib"}] * 5
        answer, peak = _peak(lambda: transform_bytes(path, offset=0, steps=steps))
        self._bounded(answer, peak, 64 * CAP)
        assert [s["op"] for s in answer["steps"]] == ["zlib"] * 3
        assert "cut" in answer["steps"][2]
        assert answer["stopped"].startswith("steps 4 to 5 were not run")

    def test_an_lznt1_bomb(self, tmp_path: Path) -> None:
        chunk = _lznt1_compress(b"\0" * 4096)
        path = _write(tmp_path, chunk * 4096)
        answer, peak = _peak(lambda: transform_bytes(path, offset=0, steps=[{"op": "lznt1"}]))
        self._bounded(answer, peak, 16 * CAP + 1)
        assert answer["output"]["length"] == CAP and "cut" in answer["steps"][0]

    def test_ten_thousand_cheap_steps(self, tmp_path: Path) -> None:
        import time

        path = _write(tmp_path, PLAIN[:16])
        steps = [{"op": "reverse"}, {"op": "xor", "key": {"hex": "5a"}}] * 5_000
        started = time.perf_counter()
        answer, peak = _peak(lambda: transform_bytes(path, offset=0, steps=steps))
        assert time.perf_counter() - started < 30
        assert len(answer["steps"]) == 10_000
        assert answer["output"]["sha256"] == hashlib.sha256(PLAIN[:16]).hexdigest()
        assert peak < 16 * CAP

    def test_the_bytes_a_chain_writes_are_held_to_the_cap(self, tmp_path: Path) -> None:
        path = _write(tmp_path, bytes(CAP // 4))
        answer, peak = _peak(
            lambda: transform_bytes(path, offset=0, steps=[{"op": "reverse"}] * 10_000)
        )
        assert len(answer["steps"]) == 4
        assert answer["stopped"].startswith("steps 5 to 10000 were not run, because the steps")
        assert "the platform's sample upload cap" in answer["stopped"]
        assert peak < 16 * CAP

    def test_a_key_range_larger_than_the_file(self, tmp_path: Path) -> None:
        path = _write(tmp_path, PLAIN)
        message = _error(
            transform_bytes(
                path, offset=0, steps=[{"op": "xor", "key": {"offset": 0, "length": 10 * CAP}}]
            )
        )
        assert "runs past the end of the file" in message

    def test_the_linear_steps_hold_to_their_input(self, tmp_path: Path) -> None:
        blob = bytes(range(256)) * (CAP // 1024)
        custom = "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba9876543210+/"
        text = base64.b64encode(blob).translate(
            bytes.maketrans(transforms._STANDARD_ALPHABET.encode(), custom.encode())
        )
        spaced = b" \n".join(blob[i : i + 32].hex().encode() for i in range(0, len(blob), 32))
        cases = [
            (blob, [{"op": "xor", "key": {"hex": "ab" * 4096}, "increment": 5}]),
            (text, [{"op": "base64", "alphabet": custom}]),
            (spaced, [{"op": "hex"}]),
        ]
        for source, steps in cases:
            path = _write(tmp_path, source, "linear.bin")
            answer, peak = _peak(
                lambda path=path, steps=steps: transform_bytes(path, offset=0, steps=steps)
            )
            assert answer["output"]["length"] == len(blob), steps[0]["op"]
            assert peak < 24 * len(blob), (steps[0]["op"], peak)

    def test_a_cap_sized_output_is_measured_whole_and_shown_in_part(self, tmp_path: Path) -> None:
        import json
        import time

        line = b"GET http://host-%04d.example.org/a.php C:\\Users\\x\\f.exe\n"
        text = b"".join(line % i for i in range(CAP // len(line) + 1))[:CAP]
        path = _write(tmp_path, zlib.compress(text * 8, 9))
        started = time.perf_counter()
        answer, peak = _peak(lambda: transform_bytes(path, offset=0, steps=[{"op": "zlib"}]))
        assert time.perf_counter() - started < 20
        out = answer["output"]
        assert out["length"] == CAP and out["sha256"] == hashlib.sha256(text).hexdigest()
        assert out["shown"]["end"] == transforms.SHOWN_BYTES
        assert "show_offset and show_length show another part" in out["shown"]["note"]
        assert len(json.dumps(out)) <= transforms.SHOWN_ROOM
        assert all(row["offset"] < transforms.SHOWN_BYTES for row in out["indicators"])
        assert peak < 16 * CAP


class TestTheShownPart:
    def test_the_default_shows_the_whole_of_a_small_output(self, tmp_path: Path) -> None:
        path = _write(tmp_path, PLAIN)
        out = _out(transform_bytes(path, offset=0))
        assert out["shown"] == {"offset": 0, "end": len(PLAIN)}

    def test_another_part_is_shown_on_request_with_offsets_in_the_output(
        self, tmp_path: Path
    ) -> None:
        filler = b"\0" * (transforms.SHOWN_BYTES * 2)
        path = _write(tmp_path, filler + PLAIN)
        out = _out(transform_bytes(path, offset=0))
        assert out["indicators"] == [] and out["length"] == len(filler) + len(PLAIN)
        later = _out(
            transform_bytes(path, offset=0, show_offset=len(filler), show_length=len(PLAIN))
        )
        assert later["ascii"] == transforms._ascii_reading(PLAIN)
        url = next(row for row in later["indicators"] if row["kind"] == "url")
        assert url["offset"] == len(filler) + PLAIN.index(b"http")
        assert later["hex_head"] == PLAIN[: transforms.HEX_HEAD_BYTES].hex()

    def test_a_window_outside_the_output_is_an_error(self, tmp_path: Path) -> None:
        path = _write(tmp_path, PLAIN)
        assert "outside the output" in _error(
            transform_bytes(path, offset=0, show_offset=len(PLAIN))
        )
        assert "shows no bytes" in _error(transform_bytes(path, offset=0, show_length=0))

    def test_a_request_past_the_largest_answer_is_cut_to_it_and_says_so(
        self, tmp_path: Path
    ) -> None:
        path = _write(tmp_path, PLAIN)
        asked = transforms.MAX_SHOWN_BYTES + 1
        out = _out(transform_bytes(path, offset=0, show_length=asked))
        assert out["shown"]["cut"].startswith(
            f"show_length {asked} was cut to {transforms.MAX_SHOWN_BYTES}"
        )
        assert out["shown"]["end"] == len(PLAIN)

    def test_the_sizes_come_from_the_rooms_and_the_readings_most_characters(self) -> None:
        from maljan.llm.context_window import (
            CHARS_PER_TOKEN,
            MAX_BELIEVABLE_WINDOW_TOKENS,
            UNKNOWN_WINDOW_TOOL_OUTPUT_CHARS,
        )

        assert transforms.SHOWN_BYTES == UNKNOWN_WINDOW_TOOL_OUTPUT_CHARS * 2 // 17
        assert transforms.MAX_SHOWN_BYTES == (
            MAX_BELIEVABLE_WINDOW_TOKENS * CHARS_PER_TOKEN * 2 // 17
        )

    def test_no_byte_or_pair_reads_as_more_characters_than_the_figure(self) -> None:
        import json

        ascii_most = max(
            len(json.dumps(transforms._ascii_reading(bytes([b, 0x41])))) - 3 for b in range(256)
        )
        pair_most = max(
            len(json.dumps(transforms._utf16_reading(code.to_bytes(2, "little") + b"A\x00"))) - 3
            for code in range(0x10000)
        )
        assert ascii_most == 5 and pair_most == 7
        assert 2 * ascii_most + pair_most == transforms._CHARS_PER_TWO_BYTES

    def test_indicator_rows_take_only_the_room_the_readings_leave(self, tmp_path: Path) -> None:
        import json

        hosts = b" ".join(b"h%05d.example.com" % i for i in range(200))
        path = _write(tmp_path, hosts)
        out = _out(transform_bytes(path, offset=0))
        assert out["indicators"], "some rows fit"
        assert "more indicators in the part shown are left out" in out["indicators_left_out"]
        assert len(json.dumps(out)) <= transforms.SHOWN_ROOM

    def test_indicator_offsets_are_the_reader_s_own_matches(self, tmp_path: Path) -> None:
        cases = [
            (b"admin@evil.com then evil.com", "domain", "evil.com", 20),
            (b"bad example.org_x and example.org end", "domain", "example.org", 22),
            (b"version=8.8.4.4 and then 8.8.4.4 here", "ip", "8.8.4.4", 25),
        ]
        for blob, kind, value, offset in cases:
            path = _write(tmp_path, blob, "ind.bin")
            rows = [
                r for r in _out(transform_bytes(path, offset=0))["indicators"] if r["kind"] == kind
            ]
            assert [(r["value"], r["offset"]) for r in rows] == [(value, offset)], blob
        wide = _write(tmp_path, b"\x01" + "x c2.ru".encode("utf-16-le"), "wide.bin")
        rows = _out(transform_bytes(wide, offset=0))["indicators"]
        assert {"kind": "domain", "value": "c2.ru", "offset": 5, "encoding": "utf-16le"} in rows

    def test_the_utf16le_reading_is_the_pack_s_escaping(self) -> None:
        import os

        from maljan.utils.written_forms import pack_escaped

        for blob in (
            os.urandom(1 << 16),
            'a"\\\n\u00a0\U0001f600\U000e0001'.encode("utf-16-le") + b"\x00\xd8",
            "ends in \\".encode("utf-16-le"),
        ):
            text = blob[: len(blob) // 2 * 2].decode("utf-16-le", errors="surrogatepass")
            assert transforms._utf16_reading(blob) == pack_escaped(text)


class TestTheReviewRulings:
    def test_a_repeating_key_takes_the_library_s_path_and_agrees(self) -> None:
        for length, taken in ((1, 5), (2, 8), (3, 24), (4, 8), (6, 24), (12, 24)):
            key = bytes(range(7, 7 + length))
            assert len(transforms._arc4_key(key) or b"") == taken, length
            assert transforms._arc4(key, PLAIN) == _rc4_reference(key, PLAIN), length
        for length in (9, 11, 13, 33, 256):
            key = bytes(range(length))
            assert transforms._arc4_key(key) is None
            assert transforms._rc4_stream(key, PLAIN) == _rc4_reference(key, PLAIN)

    def test_skip_whitespace_with_an_alphabet_holding_whitespace(self, tmp_path: Path) -> None:
        alphabet = " " + transforms._STANDARD_ALPHABET[1:]
        path = _write(tmp_path, b"QUJD")
        message = _error(
            transform_bytes(
                path,
                offset=0,
                steps=[{"op": "base64", "alphabet": alphabet, "skip_whitespace": True}],
            )
        )
        assert "skip_whitespace would drop ' ', which the alphabet holds" in message

    def test_numbers_take_ascii_digits_only(self, tmp_path: Path) -> None:
        path = _write(tmp_path, PLAIN)
        for written in ("１６", "1_6", "0x1_0", "0x１", "٣"):
            assert "give an integer" in _error(transform_bytes(path, offset=written)), written
        assert transform_bytes(path, offset="0X10")["input"]["offset"] == "0x10"

    def test_many_empty_gzip_members_stay_linear(self, tmp_path: Path) -> None:
        import time

        member = gzip.compress(b"", mtime=0)

        def timed(size: int) -> tuple[float, dict[str, Any]]:
            path = _write(tmp_path, member * (size // len(member)), f"{size}.gz")
            started = time.perf_counter()
            answer = transform_bytes(path, offset=0, steps=[{"op": "gzip"}])
            return time.perf_counter() - started, answer

        small, _answer = timed(1 << 19)
        large, answer = timed(5 << 20)
        assert answer["steps"][0]["members"] == (5 << 20) // len(member)
        # Ten times the bytes, well above the largest piece fed at once.
        assert large < small * 30 + 0.5

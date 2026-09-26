"""Text a PE keeps encoded in its data sections is decoded, and tied to the code that uses it.

Every image is built in the test (``synthetic_pe``): each blob is encoded by the
test's own implementation of one scheme, placed in the data section at an
offset the test chose, and taken by a ``lea`` in a function of the image's
function table, so the answer can be checked for the text, the scheme, the key
and the function that refers to it. The texts are invented for the test.
"""

from __future__ import annotations

import base64
import random
import struct
from pathlib import Path

import pytest

from maljan.tools import emulated_strings, string_blobs
from maljan.tools.string_blobs import decode_string_blobs, readable

from .synthetic_pe import DATA_RVA, TEXT_RVA, SyntheticPE


def _xor8(text: bytes, key: int) -> bytes:
    return bytes(byte ^ key for byte in text)


def _rising(text: bytes, first: int) -> bytes:
    return bytes(byte ^ ((first + index) & 0xFF) for index, byte in enumerate(text))


def _repeating(text: bytes, key: bytes) -> bytes:
    return bytes(byte ^ key[index % len(key)] for index, byte in enumerate(text))


FUNCTION = TEXT_RVA + 0x100


def _image() -> SyntheticPE:
    return SyntheticPE(functions=[(TEXT_RVA, FUNCTION), (FUNCTION, TEXT_RVA + 0x300)])


def _with_blob(blob: bytes, at: int = 0x40, referred: bool = True) -> SyntheticPE:
    image = _image()
    rva = image.put("data", at, blob)
    if referred:
        image.lea_to(0x120, rva)
    return image


def _decode(tmp_path: Path, image: SyntheticPE, **arguments) -> dict:
    target = tmp_path / "s.exe"
    target.write_bytes(image.build())
    return decode_string_blobs(str(target), **arguments)


def _only(answer: dict) -> dict:
    assert answer["total"] == 1, answer["results"]
    return answer["results"][0]


def _referred_from_the_function(row: dict) -> None:
    assert row["references"] == [
        {"at": hex(TEXT_RVA + 0x123), "section": ".text", "function": hex(FUNCTION)}
    ]


class TestEachScheme:
    def test_one_key_byte(self, tmp_path: Path) -> None:
        row = _only(_decode(tmp_path, _with_blob(_xor8(b"open the settings file\0", 0x9C))))
        assert row["scheme"] == "xor8"
        assert row["parameters"]["key"] == "0x9c"
        assert row["text"] == "open the settings file"
        assert row["rva"] == hex(DATA_RVA + 0x40)
        _referred_from_the_function(row)

    def test_a_key_byte_that_rises_by_one(self, tmp_path: Path) -> None:
        blob = _rising(b"https://example.invalid/path/to/page\0", 0xB7)
        row = _only(_decode(tmp_path, _with_blob(blob)))
        assert row["scheme"] == "xor8_rolling"
        assert row["parameters"] == {"first_key": "0xb7", "step": 1}
        assert row["text"] == "https://example.invalid/path/to/page"
        _referred_from_the_function(row)

    @pytest.mark.parametrize(
        ("layout", "header"),
        [
            ("key length (1), key, text to NUL", lambda key, text: b""),
            (
                "key length (1), key, text length (2), text",
                lambda key, text: struct.pack("<H", len(text)),
            ),
            (
                "key length (1), key, text length (4), text",
                lambda key, text: struct.pack("<I", len(text)),
            ),
        ],
    )
    def test_a_repeating_key_stored_in_front(self, tmp_path: Path, layout: str, header) -> None:
        key = b"\xa7\x3c\xd1\x88"
        text = b"remote folder name"
        body = _repeating(text + (b"\0" if "NUL" in layout else b""), key)
        blob = bytes([len(key)]) + key + header(key, text) + body
        row = _only(_decode(tmp_path, _with_blob(blob)))
        assert row["scheme"] == "xor_keyed_header"
        assert row["parameters"]["layout"] == layout
        assert row["parameters"]["key"] == key.hex()
        assert row["text"] == "remote folder name"
        _referred_from_the_function(row)

    @pytest.mark.parametrize(("masked", "extra"), [(False, 0), (True, 0), (False, 1), (True, 1)])
    def test_a_seed_and_length_header(self, tmp_path: Path, masked: bool, extra: int) -> None:
        seed = 0x5E6D7C9B
        text = b"version seven build\0"
        stored = len(text) ^ (seed & 0xFFFF) if masked else len(text)
        blob = struct.pack("<IH", seed, stored) + _rising(text, (seed + extra) & 0xFF)
        row = _only(_decode(tmp_path, _with_blob(blob)))
        assert row["scheme"] == "xor8_rolling_header"
        assert row["parameters"]["seed"] == f"{seed:#010x}"
        assert row["parameters"]["first_key"] == f"{(seed + extra) & 0xFF:#04x}"
        assert ("XOR the seed's low 16 bits" in row["parameters"]["layout"]) is masked
        assert row["text"] == "version seven build"
        assert row["rva"] == hex(DATA_RVA + 0x40), "the blob starts at its header"
        _referred_from_the_function(row)

    def test_a_header_stated_text_may_be_utf16(self, tmp_path: Path) -> None:
        seed = 0x0BAD9E0D
        text = "wide file name".encode("utf-16-le") + b"\0\0"
        blob = struct.pack("<IH", seed, len(text)) + _rising(text, seed & 0xFF)
        row = _only(_decode(tmp_path, _with_blob(blob)))
        assert row["text"] == "wide file name"
        assert row["encoding"] == "utf-16le"

    def test_a_text_encoding_layer_on_top_is_read_through(self, tmp_path: Path) -> None:
        inner = b"a layered secret value"
        blob = _xor8(base64.b64encode(inner) + b"\0", 0xA5)
        row = _only(_decode(tmp_path, _with_blob(blob)))
        assert row["scheme"] == "xor8"
        assert row["layers"] == [{"scheme": "base64", "text": inner.decode()}]

    def test_a_plain_text_encoding_run_is_decoded(self, tmp_path: Path) -> None:
        inner = b"a configuration value in the clear"
        row = _only(_decode(tmp_path, _with_blob(base64.b64encode(inner) + b"\0")))
        assert row["scheme"] == "base64"
        assert row["text"] == inner.decode()


class TestAHeaderThatStatesWhereTheTextEnds:
    """A stated length that ends in the text's own terminator is structure enough."""

    def test_a_small_rising_key_that_leaves_the_bytes_printable(self, tmp_path: Path) -> None:
        seed = 0x00000011
        text = b"remote settings folder\0"
        encoded = _rising(text, seed & 0xFF)
        printable = sum(32 <= b < 127 for b in encoded[:-1])
        assert printable * 5 >= (len(text) - 1) * 4, "most of it printable as stored"
        blob = struct.pack("<IH", seed, len(text)) + encoded
        row = _only(_decode(tmp_path, _with_blob(blob)))
        assert row["scheme"] == "xor8_rolling_header"
        assert row["text"] == "remote settings folder"

    @pytest.mark.parametrize(
        "text",
        [
            b"%s\\%s_%x.dat\0",
            b"cmd.exe /c dir /a %TEMP%\0",
            b"Agent/5.0 (Machine; Model 10.0; x64)\0",
        ],
    )
    def test_format_strings_command_lines_and_agent_strings(
        self, tmp_path: Path, text: bytes
    ) -> None:
        seed = 0x3A5C0091
        blob = struct.pack("<IH", seed, len(text)) + _rising(text, (seed + 1) & 0xFF)
        row = _only(_decode(tmp_path, _with_blob(blob)))
        assert row["text"] == text[:-1].decode()

    def test_under_a_stored_key_too(self, tmp_path: Path) -> None:
        key = b"\x01\x02\x03"
        text = b"%s?id=%d\0"
        blob = bytes([len(key)]) + key + struct.pack("<H", len(text)) + _repeating(text, key)
        row = _only(_decode(tmp_path, _with_blob(blob)))
        assert row["scheme"] == "xor_keyed_header"
        assert row["text"] == "%s?id=%d"

    def test_a_key_that_changes_almost_nothing_decodes_nothing(self, tmp_path: Path) -> None:
        key = b"\x00\x00\x00\x01"
        text = b"plain words kept here\0"
        blob = bytes([len(key)]) + key + struct.pack("<H", len(text)) + _repeating(text, key)
        assert _decode(tmp_path, _with_blob(blob))["total"] == 0

    def test_the_stored_key_length_read_is_stated(self, tmp_path: Path) -> None:
        answer = _decode(tmp_path, _image())
        assert answer["longest_key"] == string_blobs.LONGEST_KEY
        assert "32 bytes" in answer["readable_test"]


class TestWhatIsNotReported:
    def test_random_bytes_decode_to_nothing(self, tmp_path: Path) -> None:
        noise = random.Random(11)
        image = _image()
        image.put("data", 0, bytes(noise.randrange(256) for _ in range(0x1000)))
        for offset in range(0, 0x1000, 0x40):
            image.lea_to(0x100 + offset // 0x40 * 8, DATA_RVA + offset)
        answer = _decode(tmp_path, image, include_unreferenced=True)
        assert answer["results"] == []
        assert answer["unreferenced_results"] == []

    def test_plain_text_is_the_strings_tool_s_not_a_decoding(self, tmp_path: Path) -> None:
        image = _with_blob(b"\x11\x03plain import name\0")
        answer = _decode(tmp_path, image, include_unreferenced=True)
        assert answer["total"] == 0 and answer["unreferenced"] == 0

    def test_text_no_code_refers_to_is_counted_and_listed_on_request(self, tmp_path: Path) -> None:
        image = _with_blob(_xor8(b"open the settings file\0", 0x9C), referred=False)
        answer = _decode(tmp_path, image)
        assert answer["results"] == []
        assert answer["unreferenced"] == 1
        assert "unreferenced_results" not in answer
        listed = _decode(tmp_path, image, include_unreferenced=True)
        assert [row["text"] for row in listed["unreferenced_results"]] == ["open the settings file"]

    def test_a_table_of_counters_is_not_text(self) -> None:
        assert not readable(b"defghijklmnop", 6)
        assert readable(b"27183", 4), "a short number is a value"
        assert readable(b"C:\\ProgramData\\folder\\file.dat", 6)


class TestFloss:
    def test_a_text_floss_also_recovered_says_so(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            emulated_strings,
            "remembered_rows",
            lambda path: [
                {
                    "kind": "decoded",
                    "string": "open the settings file",
                    "function_rva": "0x1100",
                    "called_at_rva": "0x1180",
                }
            ],
        )
        answer = _decode(tmp_path, _with_blob(_xor8(b"open the settings file\0", 0x9C)))
        row = _only(answer)
        assert row["floss"] == {"function_rva": "0x1100", "called_at_rva": "0x1180"}
        assert answer["also_recovered_by_floss"] == 1

    def test_the_rows_of_a_remembered_run_are_read_without_running_floss(
        self, tmp_path: Path
    ) -> None:
        target = tmp_path / "s.exe"
        target.write_bytes(_image().build())
        assert emulated_strings.remembered_rows(str(target)) == []
        info = target.stat()
        key = (str(target), info.st_size, info.st_mtime_ns, 4)
        document = {
            "metadata": {"imagebase": 0x140000000},
            "strings": {
                "decoded_strings": [
                    {
                        "string": "x text",
                        "decoding_routine": 0x140001100,
                        "decoded_at": 0x140001180,
                    }
                ]
            },
        }
        emulated_strings._REMEMBERED[key] = document
        try:
            (row,) = emulated_strings.remembered_rows(str(target))
            assert row["string"] == "x text" and row["function_rva"] == "0x1100"
        finally:
            emulated_strings.forget_documents()


def test_every_scheme_is_named_and_an_unknown_one_is_refused(tmp_path: Path) -> None:
    answer = _decode(tmp_path, _image())
    assert answer["schemes"] == list(string_blobs.SCHEMES)
    assert answer["readable_test"] == string_blobs.READABLE_TEST
    assert "error" in _decode(tmp_path, _image(), schemes=["no_such_scheme"])


def test_a_file_that_is_not_a_pe_is_refused(tmp_path: Path) -> None:
    target = tmp_path / "a.txt"
    target.write_text("plain text", encoding="utf-8")
    assert "PE" in decode_string_blobs(str(target))["error"]

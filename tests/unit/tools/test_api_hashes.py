"""A PE's 32-bit values are named as the Windows functions they are hashes of.

Every image here is built in the test (``synthetic_pe``): a code section with
the instructions a lookup loop uses, a data section with a table of values and
an x64 function table, each at an address the test chose. The expected values
are computed in the test by its own implementation of each published
algorithm, so the tool is checked against arithmetic rather than against
itself, and the two values every reference on these algorithms prints are
checked as they are printed.
"""

from __future__ import annotations

import json
import random
import struct
import zlib
from pathlib import Path

import pytest

from maljan.tools import api_hashes
from maljan.tools.api_hashes import DEFAULT_ALGORITHMS, DEFAULT_EXPORT_NAMES, resolve_api_hashes

from .synthetic_pe import DATA_RVA, TEXT_RVA, SyntheticPE

ROOT = Path(__file__).resolve().parents[3]


def _ror13(text: bytes) -> int:
    value = 0
    for byte in text:
        value = ((value >> 13) | (value << 19)) & 0xFFFFFFFF
        value = (value + byte) & 0xFFFFFFFF
    return value


def _algorithm(identifier: str) -> dict:
    return next(a for a in api_hashes.load_algorithms() if a["id"] == identifier)


def _write(tmp_path: Path, image: SyntheticPE, name: str = "s.exe") -> str:
    target = tmp_path / name
    target.write_bytes(image.build())
    return str(target)


class TestTheData:
    def test_the_name_lists_say_where_they_came_from(self) -> None:
        document = json.loads((ROOT / DEFAULT_EXPORT_NAMES).read_text(encoding="utf-8"))
        assert "spec files" in document["source"]
        assert document["tag"]
        assert set(document["sources"]) == set(document["dlls"])
        for source in document["sources"].values():
            assert source["url"].startswith("https://")
            assert len(source["sha256"]) == 64
        assert "kernel32.dll" in document["dlls"] and "ntdll.dll" in document["dlls"]

    def test_the_algorithms_are_data_and_cover_the_published_set(self) -> None:
        document = json.loads((ROOT / DEFAULT_ALGORITHMS).read_text(encoding="utf-8"))
        identifiers = {entry["id"] for entry in document["algorithms"]}
        assert {
            "crc32_ascii",
            "crc32_utf16le",
            "ror13",
            "ror13_module_add",
            "djb2",
            "fnv1a32",
        } <= identifiers
        assert {entry["primitive"] for entry in document["algorithms"]} <= set(
            api_hashes.PRIMITIVES
        )


class TestTheAlgorithms:
    def test_each_matches_an_independent_computation(self) -> None:
        name = "GetProcAddress"
        assert api_hashes.hash_name(_algorithm("crc32_ascii"), name) == zlib.crc32(name.encode())
        assert api_hashes.hash_name(_algorithm("crc32_utf16le"), name) == zlib.crc32(
            name.encode("utf-16-le")
        )
        assert api_hashes.hash_name(_algorithm("crc32_ascii_lower"), name) == zlib.crc32(
            name.lower().encode()
        )
        assert api_hashes.hash_name(_algorithm("ror13"), name) == _ror13(name.encode())
        djb2 = 5381
        fnv = 0x811C9DC5
        for byte in name.encode():
            djb2 = (djb2 * 33 + byte) & 0xFFFFFFFF
            fnv = ((fnv ^ byte) * 0x01000193) & 0xFFFFFFFF
        assert api_hashes.hash_name(_algorithm("djb2"), name) == djb2
        assert api_hashes.hash_name(_algorithm("fnv1a32"), name) == fnv

    def test_the_rotate_forms_give_the_values_the_references_print(self) -> None:
        assert api_hashes.hash_name(_algorithm("ror13"), "LoadLibraryA") == 0xEC0E4E8E
        assert (
            api_hashes.hash_name(_algorithm("ror13_module_add"), "LoadLibraryA", "kernel32.dll")
            == 0x0726774C
        )


def _image_with_hashes() -> tuple[SyntheticPE, dict[str, int]]:
    """Two CRC-32 values compared in code, three rotate values in a data table."""
    image = SyntheticPE(functions=[(TEXT_RVA + 0x40, TEXT_RVA + 0x100)])
    compared = {name: zlib.crc32(name.encode()) for name in ("VirtualAlloc", "CreateFileW")}
    # cmp eax, imm32 at 0x60 and cmp ecx, imm32 (81 F9 imm32) at 0x80.
    image.put("text", 0x60, b"\x3d" + struct.pack("<I", compared["VirtualAlloc"]))
    image.put("text", 0x80, b"\x81\xf9" + struct.pack("<I", compared["CreateFileW"]))
    table = {name: _ror13(name.encode()) for name in ("GetTickCount", "Sleep", "WriteFile")}
    image.put("data", 0x20, b"".join(struct.pack("<I", value) for value in table.values()))
    return image, {**compared, **table}


class TestAScan:
    def test_it_names_each_value_with_the_places_it_stands(self, tmp_path: Path) -> None:
        image, values = _image_with_hashes()
        answer = resolve_api_hashes(_write(tmp_path, image))
        hits = {row["value"]: row for row in answer["hits"]}
        assert set(hits) == {f"{value:#010x}" for value in values.values()}

        virtual_alloc = hits[f"{values['VirtualAlloc']:#010x}"]
        crc = [r for r in virtual_alloc["readings"] if r["algorithm"] == "crc32_ascii"]
        assert crc and crc[0]["name"] == "VirtualAlloc"
        assert "kernel32.dll" in crc[0]["dlls"]
        (place,) = virtual_alloc["occurrences"]
        assert place["rva"] == hex(TEXT_RVA + 0x61)
        assert place["section"] == ".text"
        assert place["function"] == hex(TEXT_RVA + 0x40), "the function table's start"

        create_file = hits[f"{values['CreateFileW']:#010x}"]
        assert create_file["occurrences"][0]["rva"] == hex(TEXT_RVA + 0x82)

        tick_count = hits[f"{values['GetTickCount']:#010x}"]
        assert any(
            r["algorithm"] == "ror13" and r["name"] == "GetTickCount"
            for r in tick_count["readings"]
        )
        (place,) = tick_count["occurrences"]
        assert place["rva"] == hex(DATA_RVA + 0x20)
        assert place["function"] is None, "no function is stated for data"

    def test_it_says_how_it_chose_the_candidates(self, tmp_path: Path) -> None:
        image, _ = _image_with_hashes()
        answer = resolve_api_hashes(_write(tmp_path, image))
        assert answer["candidates"]["scanned"] > 0
        assert "immediates" in answer["candidates"]["how"]
        assert answer["function_table"].startswith("exception directory")

    def test_without_a_function_table_an_address_stands_alone(self, tmp_path: Path) -> None:
        image, values = _image_with_hashes()
        image.functions = []
        answer = resolve_api_hashes(_write(tmp_path, image))
        row = next(r for r in answer["hits"] if r["value"] == f"{values['VirtualAlloc']:#010x}")
        assert row["occurrences"][0]["rva"] == hex(TEXT_RVA + 0x61)
        assert row["occurrences"][0]["function"] is None
        assert answer["function_table"].startswith("none")

    def test_a_32_bit_image_is_read_too(self, tmp_path: Path) -> None:
        image, values = _image_with_hashes()
        image.is64 = False
        image.image_base = 0x400000
        image.functions = []
        answer = resolve_api_hashes(_write(tmp_path, image))
        assert f"{values['CreateFileW']:#010x}" in {row["value"] for row in answer["hits"]}

    def test_random_bytes_name_nothing(self, tmp_path: Path) -> None:
        noise = random.Random(7)
        image = SyntheticPE()
        image.put("data", 0, bytes(noise.randrange(256) for _ in range(0x400)))
        image.put("text", 0, bytes(noise.randrange(256) for _ in range(0x400)))
        answer = resolve_api_hashes(_write(tmp_path, image))
        assert answer["hits"] == []
        assert answer["total"] == 0

    def test_a_lone_coincidence_is_kept_apart_not_dropped(self, tmp_path: Path) -> None:
        image = SyntheticPE()
        image.put("data", 0x10, struct.pack("<I", zlib.crc32(b"CreateFileW")))
        answer = resolve_api_hashes(_write(tmp_path, image))
        assert answer["hits"] == []
        assert [row["value"] for row in answer["lone_hits"]] == [
            f"{zlib.crc32(b'CreateFileW'):#010x}"
        ]


class TestModuleNames:
    """A resolver that walks the loaded-module list hashes the module's name too."""

    def test_a_module_name_hash_is_named_from_the_module_set(self, tmp_path: Path) -> None:
        wide = zlib.crc32("user32.dll".encode("utf-16-le"))
        upper = zlib.crc32("ADVAPI32.DLL".encode("utf-16-le"))
        image = SyntheticPE(functions=[(TEXT_RVA, TEXT_RVA + 0x100)])
        image.put("text", 0x20, b"\x3d" + struct.pack("<I", wide))
        image.put("text", 0x30, b"\x3d" + struct.pack("<I", upper))
        answer = resolve_api_hashes(_write(tmp_path, image))
        rows = {row["value"]: row for row in answer["hits"]}
        user32 = rows[f"{wide:#010x}"]["readings"]
        assert {
            "algorithm": "crc32_utf16le",
            "set": "modules",
            "name": "user32.dll",
            "dlls": [],
        } in (user32)
        assert any(
            r["set"] == "modules"
            and r["name"] == "ADVAPI32.DLL"
            and r["algorithm"] == "crc32_utf16le"
            for r in rows[f"{upper:#010x}"]["readings"]
        )
        assert rows[f"{wide:#010x}"]["occurrences"][0]["function"] == hex(TEXT_RVA)

    def test_every_reading_names_its_set(self, tmp_path: Path) -> None:
        image, _ = _image_with_hashes()
        answer = resolve_api_hashes(_write(tmp_path, image))
        assert {r["set"] for row in answer["hits"] for r in row["readings"]} <= {
            "exports",
            "modules",
        }
        assert answer["names"]["modules"] > 0
        assert "file names" in answer["names"]["modules_source"]
        assert "LGPL" in answer["names"]["license"]


class TestValuesTheCallerGives:
    def test_each_is_resolved_or_said_unresolved(self, tmp_path: Path) -> None:
        image, values = _image_with_hashes()
        wanted = values["Sleep"]
        answer = resolve_api_hashes(
            _write(tmp_path, image), hashes=[hex(wanted), "0x00000123", "not a number"]
        )
        assert [row["value"] for row in answer["hits"]] == [f"{wanted:#010x}"]
        assert answer["unresolved"] == ["0x00000123"]
        assert answer["unreadable"] == ["not a number"]
        assert "lone_hits" not in answer

    def test_a_value_two_algorithms_give_carries_both_readings(self, tmp_path: Path) -> None:
        # An all-lower-case name hashes the same with and without folding.
        value = zlib.crc32(b"strlen")
        image = SyntheticPE()
        image.put("data", 0x40, struct.pack("<I", value))
        answer = resolve_api_hashes(_write(tmp_path, image), hashes=[value])
        (row,) = answer["hits"]
        algorithms = {r["algorithm"] for r in row["readings"] if r["name"] == "strlen"}
        assert {"crc32_ascii", "crc32_ascii_lower"} <= algorithms
        assert row["occurrences"][0]["rva"] == hex(DATA_RVA + 0x40)

    def test_the_algorithms_can_be_narrowed_and_an_unknown_one_is_refused(
        self, tmp_path: Path
    ) -> None:
        image, values = _image_with_hashes()
        path = _write(tmp_path, image)
        answer = resolve_api_hashes(path, hashes=[values["Sleep"]], algorithms=["crc32_ascii"])
        assert answer["hits"] == []
        assert "error" in resolve_api_hashes(path, algorithms=["no_such_algorithm"])

    def test_a_long_answer_pages_only_when_asked(self, tmp_path: Path) -> None:
        image, values = _image_with_hashes()
        path = _write(tmp_path, image)
        whole = resolve_api_hashes(path)
        assert whole["next_offset"] is None and len(whole["hits"]) == len(values)
        page = resolve_api_hashes(path, limit=2)
        assert len(page["hits"]) == 2 and page["next_offset"] == 2
        rest = resolve_api_hashes(path, offset=2)
        assert len(rest["hits"]) == len(values) - 2


def test_a_file_that_is_not_a_pe_is_refused(tmp_path: Path) -> None:
    target = tmp_path / "a.txt"
    target.write_text("plain text", encoding="utf-8")
    answer = resolve_api_hashes(str(target))
    assert "PE" in answer["error"]


@pytest.mark.parametrize("identifier", [a["id"] for a in api_hashes.load_algorithms()])
def test_every_algorithm_names_a_value_it_made(identifier: str, tmp_path: Path) -> None:
    algorithm = _algorithm(identifier)
    value = api_hashes.hash_name(algorithm, "CreateProcessW", "kernel32.dll")
    image = SyntheticPE()
    image.put("data", 0x10, struct.pack("<I", value))
    answer = resolve_api_hashes(_write(tmp_path, image), hashes=[value])
    (row,) = answer["hits"]
    assert any(
        r["algorithm"] == identifier and r["name"] == "CreateProcessW" for r in row["readings"]
    )

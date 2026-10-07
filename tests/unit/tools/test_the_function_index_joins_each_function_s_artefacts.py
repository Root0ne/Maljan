"""Every function the run knows, with the artefacts the run's answers and the decoder place in it.

Each image is synthetic (``synthetic_pe``): the code bytes are written by the test, one
instruction at a time, and no real program is read. The answers joined
(``pe_info``, ``capa``, ``floss``, the hash resolution and the blob decoder) are
written in the shapes those tools answer in, with values the test chooses.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

from maljan.tools import artefact_index

from .synthetic_pe import DATA_RVA, TEXT_RVA, SyntheticPE

FIRST = TEXT_RVA
SECOND = TEXT_RVA + 0x100
LEAF = TEXT_RVA + 0x200
BASE = 0x140000000


class _Code:
    """Code written into ``.text`` at the offsets a test chooses."""

    def __init__(self, image: SyntheticPE, at: int = 0) -> None:
        self.image = image
        self.at = at

    def go(self, rva: int) -> _Code:
        self.at = rva - TEXT_RVA
        return self

    def raw(self, blob: bytes) -> int:
        start = TEXT_RVA + self.at
        self.image.put("text", self.at, blob)
        self.at += len(blob)
        return start

    def lea(self, target: int) -> int:
        """``lea rcx, [rip+disp32]``; answers the RVA of the instruction."""
        end = TEXT_RVA + self.at + 7
        return self.raw(b"\x48\x8d\x0d" + struct.pack("<i", target - end))

    def call(self, target: int) -> int:
        end = TEXT_RVA + self.at + 5
        return self.raw(b"\xe8" + struct.pack("<i", target - end))

    def call_slot(self, slot: int) -> int:
        end = TEXT_RVA + self.at + 6
        return self.raw(b"\xff\x15" + struct.pack("<i", slot - end))

    def ret(self) -> int:
        return self.raw(b"\xc3")


def _x64() -> tuple[SyntheticPE, _Code, dict[str, int]]:
    image = SyntheticPE(functions=[(FIRST, FIRST + 0x40), (SECOND, SECOND + 0x40)])
    slots = image.imports_at(0x100, {"KERNEL32.dll": ["CreateMutexW", "GetLastError"]})
    image.put("data", 0x40, b"a plain setting\0")
    image.put("data", 0x80, "wide text here".encode("utf-16-le") + b"\0\0")
    image.put("data", 0xC0, b"ab\0")  # too short to be a string
    return image, _Code(image), slots


def _load(image: SyntheticPE, tmp_path: Path) -> str:
    target = tmp_path / "s.exe"
    target.write_bytes(image.build())
    return str(target)


def _row(answer: dict[str, Any], offset: int) -> dict[str, Any]:
    return next(row for row in answer["rows"] if row["offset"] == hex(offset))


def _first_two(code: _Code, slots: dict[str, int]) -> dict[str, int]:
    """FIRST: an import call, a plain string, a call to SECOND; SECOND: a wide string."""
    code.go(FIRST)
    places = {"import call": code.call_slot(slots["CreateMutexW"])}
    places["plain load"] = code.lea(DATA_RVA + 0x40)
    places["short load"] = code.lea(DATA_RVA + 0xC0)
    places["second call"] = code.call(SECOND)
    code.ret()
    code.go(SECOND)
    places["wide load"] = code.lea(DATA_RVA + 0x80)
    places["leaf call"] = code.call(LEAF)
    code.ret()
    code.go(LEAF)
    places["leaf body"] = code.raw(b"\x31\xc0")  # xor eax, eax
    code.ret()
    return places


class TestTheDecoderReadsEachFunction:
    def test_imports_strings_callers_and_callees(self, tmp_path: Path) -> None:
        image, code, slots = _x64()
        _first_two(code, slots)
        answer = artefact_index.function_index(_load(image, tmp_path))

        first = _row(answer, FIRST)
        assert first["function"] == hex(BASE + FIRST)
        assert first["imports"] == [{"name": "CreateMutexW", "sources": [artefact_index.SELF]}]
        assert first["plain_strings"] == [
            {"text": "a plain setting", "sources": [artefact_index.SELF]}
        ]
        assert first["callees"] == [hex(BASE + SECOND)]
        assert first["callers"] == []
        second = _row(answer, SECOND)
        assert [c["text"] for c in second["plain_strings"]] == ["wide text here"]
        assert second["callers"] == [hex(BASE + FIRST)]
        assert second["callees"] == [hex(BASE + LEAF)]

    def test_the_artefacts_of_the_callees_are_counted_beyond_the_function_s_own(
        self, tmp_path: Path
    ) -> None:
        image, code, slots = _x64()
        _first_two(code, slots)
        answer = artefact_index.function_index(_load(image, tmp_path))
        assert _row(answer, FIRST)["indirect"] == {"artefacts": 1, "through": 1}
        # The leaf holds nothing, so SECOND's callees hold nothing.
        assert _row(answer, SECOND)["indirect"] == {"artefacts": 0, "through": 0}

    def test_a_call_target_outside_the_table_is_a_function_and_one_with_nothing_no_row(
        self, tmp_path: Path
    ) -> None:
        image, code, slots = _x64()
        _first_two(code, slots)
        answer = artefact_index.function_index(_load(image, tmp_path))
        assert answer["function_sources"]["call targets the decoder reached"] == 2
        assert answer["functions_known"] == 3
        assert hex(LEAF) not in [row["offset"] for row in answer["rows"]]
        assert answer["total"] == 2

    def test_rows_are_ranked_by_their_own_distinct_artefacts_then_by_address(
        self, tmp_path: Path
    ) -> None:
        image, code, slots = _x64()
        _first_two(code, slots)
        answer = artefact_index.function_index(_load(image, tmp_path))
        assert [(row["offset"], row["direct"]) for row in answer["rows"]] == [
            (hex(FIRST), 2),
            (hex(SECOND), 1),
        ]

    def test_ghidra_s_and_radare2_s_lists_are_said_absent_with_the_reason(
        self, tmp_path: Path
    ) -> None:
        image, code, slots = _x64()
        _first_two(code, slots)
        answer = artefact_index.function_index(_load(image, tmp_path))
        assert answer["function_lists"] == artefact_index.FUNCTION_LISTS_ABSENT
        assert "no: " in answer["function_lists"]

    def test_a_byte_the_decoder_does_not_read_is_counted(self, tmp_path: Path) -> None:
        image, code, slots = _x64()
        places = _first_two(code, slots)
        code.go(places["leaf call"] + 6)  # right after its return
        code.raw(b"\x62\x00\x00\x00")  # EVEX: not decoded
        answer = artefact_index.function_index(_load(image, tmp_path))
        assert answer["undecoded_functions"] == 1
        assert answer["undecoded"] == [hex(BASE + SECOND)]

    def test_every_function_is_decoded_and_none_is_listed(self, tmp_path: Path) -> None:
        image, code, slots = _x64()
        _first_two(code, slots)
        answer = artefact_index.function_index(_load(image, tmp_path))
        assert answer["undecoded"] == []
        assert answer["calls_unnamed"] == {}

    def test_calls_that_name_nothing_are_counted_per_function(self, tmp_path: Path) -> None:
        image, code, slots = _x64()
        code.go(FIRST)
        code.call_slot(slots["CreateMutexW"])  # an import: named
        code.call_slot(DATA_RVA + 0x200)  # a slot the import table does not fill
        code.raw(b"\xff\xd0")  # call rax
        code.call(SECOND)  # a function: named
        code.ret()
        code.go(SECOND)
        code.call_slot(slots["GetLastError"])
        code.ret()
        answer = artefact_index.function_index(_load(image, tmp_path))
        assert answer["calls_unnamed"] == {hex(BASE + FIRST): 2}
        # The pack's line for a row says nothing of them.
        line = artefact_index.row_line(_row(answer, FIRST), "ev_0001")
        assert "unnamed" not in line and "2 calls" not in line

    def test_a_row_s_parts_are_its_line_after_the_address(self, tmp_path: Path) -> None:
        image, code, slots = _x64()
        _first_two(code, slots)
        answer = artefact_index.function_index(_load(image, tmp_path))
        row = _row(answer, FIRST)
        assert artefact_index.row_line(row, "ev_0001") == (
            f"- {hex(BASE + FIRST)}: {artefact_index.row_parts(row, 'ev_0001')}"
        )

    def test_a_file_that_is_not_a_pe_is_an_error(self, tmp_path: Path) -> None:
        target = tmp_path / "a.txt"
        target.write_text("plain text\n", encoding="utf-8")
        answer = artefact_index.function_index(str(target))
        assert "error" in answer and answer["tool"] == artefact_index.TOOL


class TestAnX86ImageWithNoTable:
    def test_the_entry_point_is_decoded_along_its_branches(self, tmp_path: Path) -> None:
        image = SyntheticPE(is64=False, image_base=0x400000)
        slots = image.imports_at(0x100, {"KERNEL32.dll": ["CreateMutexA"]})
        image.put("data", 0x40, b"an x86 string\0")
        code = _Code(image).go(FIRST)
        code.raw(b"\x68" + struct.pack("<I", 0x400000 + DATA_RVA + 0x40))  # push offset text
        code.raw(b"\x74\x02")  # je +2
        code.raw(b"\x90\x90")  # nop; nop
        code.raw(b"\xff\x15" + struct.pack("<I", 0x400000 + slots["CreateMutexA"]))
        code.ret()
        info = {"entry_point": FIRST, "export_rows": []}

        answer = artefact_index.function_index(_load(image, tmp_path), pe_info=("ev_0004", info))

        (row,) = answer["rows"]
        assert row["function"] == hex(0x400000 + FIRST)
        assert row["entry_point"] is True and "names" not in row
        assert [c["name"] for c in row["imports"]] == ["CreateMutexA"]
        assert [c["text"] for c in row["plain_strings"]] == ["an x86 string"]
        assert answer["function_sources"] == {"entry point": 1}


class TestEveryStartIsKnownBeforeAnyFunctionIsRead:
    """A jump to another function's start is its tail call, whatever order the calls come in."""

    ENTRY, JUMPER, TARGET, CALLER = TEXT_RVA, TEXT_RVA + 0x100, TEXT_RVA + 0x200, TEXT_RVA + 0x300

    def _image(self, first: int, second: int) -> SyntheticPE:
        image = SyntheticPE(is64=False, image_base=0x400000)
        slots = image.imports_at(0x100, {"KERNEL32.dll": ["CreateMutexA"]})

        def put(rva: int, blob: bytes) -> None:
            image.put("text", rva - TEXT_RVA, blob)

        def call(at: int, target: int) -> bytes:
            return b"\xe8" + struct.pack("<i", target - (at + 5))

        put(self.ENTRY, call(self.ENTRY, first) + call(self.ENTRY + 5, second) + b"\xc3")
        put(self.JUMPER, b"\xe9" + struct.pack("<i", self.TARGET - (self.JUMPER + 5)))
        slot = struct.pack("<I", 0x400000 + slots["CreateMutexA"])
        put(self.TARGET, b"\xff\x15" + slot + b"\xc3")
        put(self.CALLER, call(self.CALLER, self.TARGET) + b"\xc3")
        return image

    def test_the_jumped_to_function_has_its_own_row_in_either_order(self, tmp_path: Path) -> None:
        answers = []
        for order in ((self.JUMPER, self.CALLER), (self.CALLER, self.JUMPER)):
            image = self._image(*order)
            info = ("ev_0004", {"entry_point": self.ENTRY, "export_rows": []})
            answers.append(artefact_index.function_index(_load(image, tmp_path), pe_info=info))
        assert answers[0]["rows"] == answers[1]["rows"]
        (row,) = answers[0]["rows"]
        assert row["offset"] == hex(self.TARGET)
        assert [c["name"] for c in row["imports"]] == ["CreateMutexA"]
        assert row["callers"] == [hex(0x400000 + self.JUMPER), hex(0x400000 + self.CALLER)]


class TestADataAddressIsReadFromTheOperandThatHoldsIt:
    def test_an_x86_store_of_an_address_to_a_global_names_the_stored_text(
        self, tmp_path: Path
    ) -> None:
        image = SyntheticPE(is64=False, image_base=0x400000)
        image.put("data", 0x40, b"a stored text\0")
        image.put("data", 0x80, b"a global slot\0")
        code = _Code(image).go(FIRST)
        # mov dword [abs32 slot], imm32 text: the immediate is the text, the slot a global.
        code.raw(
            b"\xc7\x05"
            + struct.pack("<I", 0x400000 + DATA_RVA + 0x80)
            + struct.pack("<I", 0x400000 + DATA_RVA + 0x40)
        )
        code.ret()
        info = ("ev_0004", {"entry_point": FIRST, "export_rows": []})
        answer = artefact_index.function_index(_load(image, tmp_path), pe_info=info)
        (row,) = answer["rows"]
        assert [c["text"] for c in row["plain_strings"]] == ["a stored text"]


class TestTheRunsAnswersArePlaced:
    def _answers(self, places: dict[str, int]) -> dict[str, tuple[str, dict[str, Any]]]:
        floss = {
            "strings": [
                {
                    "kind": "decoded",
                    "string": "a shared text",
                    "called_at_rva": hex(places["second call"]),
                },
                {"kind": "stack", "string": "built on the stack", "function_rva": hex(SECOND)},
                {"kind": "decoded", "string": "nowhere", "called_at_rva": "0x9000"},
            ]
        }
        blobs = {
            "results": [
                {
                    "text": "a shared text",
                    "references": [{"at": hex(places["plain load"] + 3), "function": hex(FIRST)}],
                }
            ]
        }
        hashes = {
            "hits": [
                {
                    "readings": [
                        {"set": "exports", "name": "VirtualAlloc"},
                        {"set": "modules", "name": "kernel32.dll"},
                    ],
                    "occurrences": [{"rva": hex(places["leaf body"]), "function": None}],
                }
            ]
        }
        capa = {
            "function_starts": [hex(FIRST), hex(SECOND)],
            "capabilities": [
                {"rule": "a rule at a start", "addresses": [hex(SECOND)]},
                {"rule": "a rule inside", "addresses": [hex(places["wide load"] + 2)]},
                {"rule": "a file rule", "addresses": []},
            ],
        }
        return {
            "floss": ("ev_0017", floss),
            "blobs": ("ev_0016", blobs),
            "hashes": ("ev_0020", hashes),
            "capa": ("ev_0008", capa),
        }

    def test_one_text_from_two_answers_is_one_artefact_citing_both(self, tmp_path: Path) -> None:
        image, code, slots = _x64()
        places = _first_two(code, slots)
        answer = artefact_index.function_index(_load(image, tmp_path), **self._answers(places))
        first = _row(answer, FIRST)
        assert first["decoded_strings"] == [
            {"text": "a shared text", "sources": ["ev_0016", "ev_0017"]}
        ]

    def test_a_stack_string_is_in_the_function_floss_names(self, tmp_path: Path) -> None:
        image, code, slots = _x64()
        places = _first_two(code, slots)
        answer = artefact_index.function_index(_load(image, tmp_path), **self._answers(places))
        second = _row(answer, SECOND)
        assert [c["text"] for c in second["decoded_strings"]] == ["built on the stack"]

    def test_a_hash_with_no_stated_function_is_placed_by_the_decoded_instructions(
        self, tmp_path: Path
    ) -> None:
        image, code, slots = _x64()
        places = _first_two(code, slots)
        answer = artefact_index.function_index(_load(image, tmp_path), **self._answers(places))
        leaf = _row(answer, LEAF)
        assert leaf["resolved"] == [{"name": "VirtualAlloc", "sources": ["ev_0020"]}]

    def test_capa_rules_at_a_start_and_inside_a_function(self, tmp_path: Path) -> None:
        image, code, slots = _x64()
        places = _first_two(code, slots)
        answer = artefact_index.function_index(_load(image, tmp_path), **self._answers(places))
        second = _row(answer, SECOND)
        assert [c["rule"] for c in second["capa"]] == ["a rule at a start", "a rule inside"]
        assert all(c["sources"] == ["ev_0008"] for c in second["capa"])

    def test_a_place_no_function_holds_is_counted_and_given_to_none(self, tmp_path: Path) -> None:
        image, code, slots = _x64()
        places = _first_two(code, slots)
        answer = artefact_index.function_index(_load(image, tmp_path), **self._answers(places))
        assert answer["unplaced"] == {"floss": 1}
        texts = [c["text"] for row in answer["rows"] for c in row["decoded_strings"]]
        assert "nowhere" not in texts

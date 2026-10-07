"""A slot the hash resolution fills is named, and a call through it is an API call of that name.

A sample that resolves its imports by hash calls each through a pointer it fills
itself. The index reads, in the straight-line run that holds a hashed value, the
slot that pointer is written to: after the resolver's call, the store of its
return register; or, in a table of records, the one address of the record that
some code calls or jumps through. Each call or jump through a named slot, direct
or through a register loaded from it, is then a row's call of that name, sourced
to the resolution's entry; a slot two names fill is ambiguous and names nothing.

Each image is synthetic (``synthetic_pe``): the code bytes are written by the
test, and every hash value and name is chosen by it.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

from maljan.tools import artefact_index

from .synthetic_pe import DATA_RVA, TEXT_RVA, SyntheticPE

BASE = 0x140000000
BUILDER = TEXT_RVA
RESOLVER = TEXT_RVA + 0x100
USER = TEXT_RVA + 0x200
SLOT_A = DATA_RVA + 0x300
SLOT_B = DATA_RVA + 0x308
MODULE = DATA_RVA + 0x380
HASH_ID = "ev_0020"


class _Code:
    def __init__(self, image: SyntheticPE) -> None:
        self.image = image
        self.at = 0

    def go(self, rva: int) -> _Code:
        self.at = rva - TEXT_RVA
        return self

    def raw(self, blob: bytes) -> int:
        start = TEXT_RVA + self.at
        self.image.put("text", self.at, blob)
        self.at += len(blob)
        return start

    def _rip(self, head: bytes, target: int, tail: bytes = b"") -> int:
        end = TEXT_RVA + self.at + len(head) + 4 + len(tail)
        return self.raw(head + struct.pack("<i", target - end) + tail)

    def hash_in_edx(self, value: int) -> int:
        return self.raw(b"\xba" + struct.pack("<I", value))

    def hash_in_record(self, offset: int, value: int) -> int:
        return self.raw(b"\xc7\x44\x24" + bytes([offset]) + struct.pack("<I", value))

    def lea_rax(self, target: int) -> int:
        return self._rip(b"\x48\x8d\x05", target)

    def rax_to_frame(self, offset: int) -> int:
        return self.raw(b"\x48\x89\x44\x24" + bytes([offset]))

    def call(self, target: int) -> int:
        end = TEXT_RVA + self.at + 5
        return self.raw(b"\xe8" + struct.pack("<i", target - end))

    def store_rax(self, slot: int) -> int:
        return self._rip(b"\x48\x89\x05", slot)

    def load_rax(self, slot: int) -> int:
        return self._rip(b"\x48\x8b\x05", slot)

    def call_slot(self, slot: int) -> int:
        return self._rip(b"\xff\x15", slot)

    def jump_slot(self, slot: int) -> int:
        return self._rip(b"\xff\x25", slot)

    def call_rax(self) -> int:
        return self.raw(b"\xff\xd0")

    def clobber_rax(self) -> int:
        return self.raw(b"\x31\xc0")

    def ret(self) -> int:
        return self.raw(b"\xc3")


def _image() -> tuple[SyntheticPE, _Code]:
    image = SyntheticPE(
        functions=[(BUILDER, BUILDER + 0x80), (RESOLVER, RESOLVER + 0x10), (USER, USER + 0x40)]
    )
    code = _Code(image)
    code.go(RESOLVER).clobber_rax()
    code.ret()
    return image, code


def _hits(*pairs: tuple[int, tuple[str, ...]]) -> dict[str, Any]:
    return {
        "hits": [
            {
                "readings": [{"set": "exports", "name": name} for name in names],
                "occurrences": [{"rva": hex(place)}],
            }
            for place, names in pairs
        ]
    }


def _index(image: SyntheticPE, tmp_path: Path, hashes: dict[str, Any]) -> dict[str, Any]:
    target = tmp_path / "s.exe"
    target.write_bytes(image.build())
    return artefact_index.function_index(str(target), hashes=(HASH_ID, hashes))


def _row(answer: dict[str, Any], offset: int) -> dict[str, Any]:
    return next(row for row in answer["rows"] if row["offset"] == hex(offset))


def _user_calls(code: _Code) -> None:
    code.go(USER)
    code.call_slot(SLOT_A)
    code.load_rax(SLOT_B)
    code.call_rax()
    code.ret()


class TestTheCallAndItsStore:
    def test_the_store_after_the_resolver_s_call_names_the_slot(self, tmp_path: Path) -> None:
        image, code = _image()
        code.go(BUILDER)
        first = code.hash_in_edx(0x1111AAAA)
        code.call(RESOLVER)
        named_a = code.store_rax(SLOT_A)
        second = code.hash_in_edx(0x2222BBBB)
        code.call(RESOLVER)
        named_b = code.store_rax(SLOT_B)
        code.ret()
        _user_calls(code)

        answer = _index(image, tmp_path, _hits((first, ("OpenThingW",)), (second, ("CloseThing",))))

        assert answer["resolved_slots"] == {
            hex(BASE + SLOT_A): "OpenThingW",
            hex(BASE + SLOT_B): "CloseThing",
        }
        user = _row(answer, USER)
        assert user["slot_calls"] == [
            {
                "name": "CloseThing",
                "sources": [HASH_ID],
                "slot": hex(BASE + SLOT_B),
                "named_at": hex(BASE + named_b),
            },
            {
                "name": "OpenThingW",
                "sources": [HASH_ID],
                "slot": hex(BASE + SLOT_A),
                "named_at": hex(BASE + named_a),
            },
        ]
        assert hex(BASE + USER) not in answer["calls_unnamed"]
        line = artefact_index.row_line(user, HASH_ID)
        assert f'{artefact_index.SLOT_CALLS_SAID} "CloseThing", "OpenThingW" ({HASH_ID})' in line

    def test_a_store_after_the_register_is_overwritten_names_nothing(self, tmp_path: Path) -> None:
        image, code = _image()
        code.go(BUILDER)
        first = code.hash_in_edx(0x1111AAAA)
        code.call(RESOLVER)
        code.clobber_rax()
        code.store_rax(SLOT_A)
        code.ret()
        code.go(USER)
        code.call_slot(SLOT_A)
        code.ret()

        answer = _index(image, tmp_path, _hits((first, ("OpenThingW",))))

        assert answer["resolved_slots"] == {}
        assert answer["calls_unnamed"] == {hex(BASE + USER): 1}

    def test_a_slot_two_names_fill_is_ambiguous_and_its_calls_stay_unnamed(
        self, tmp_path: Path
    ) -> None:
        image, code = _image()
        code.go(BUILDER)
        first = code.hash_in_edx(0x1111AAAA)
        code.call(RESOLVER)
        code.store_rax(SLOT_A)
        second = code.hash_in_edx(0x2222BBBB)
        code.call(RESOLVER)
        code.store_rax(SLOT_A)
        code.ret()
        code.go(USER)
        code.call_slot(SLOT_A)
        code.ret()

        answer = _index(image, tmp_path, _hits((first, ("OpenThingW",)), (second, ("CloseThing",))))

        assert answer["resolved_slots"] == {}
        assert answer["ambiguous_slots"] == {hex(BASE + SLOT_A): ["CloseThing", "OpenThingW"]}
        assert answer["calls_unnamed"] == {hex(BASE + USER): 1}

    def test_a_hash_that_reads_as_two_names_names_nothing(self, tmp_path: Path) -> None:
        image, code = _image()
        code.go(BUILDER)
        first = code.hash_in_edx(0x1111AAAA)
        code.call(RESOLVER)
        code.store_rax(SLOT_A)
        code.ret()
        code.go(USER)
        code.call_slot(SLOT_A)
        code.ret()

        answer = _index(image, tmp_path, _hits((first, ("OpenThingW", "OtherThing"))))

        assert answer["resolved_slots"] == {}
        assert hex(BASE + SLOT_A) in answer["ambiguous_slots"]

    def test_a_jump_through_a_named_slot_is_a_call_of_its_name(self, tmp_path: Path) -> None:
        image, code = _image()
        code.go(BUILDER)
        first = code.hash_in_edx(0x1111AAAA)
        code.call(RESOLVER)
        code.store_rax(SLOT_A)
        code.ret()
        code.go(USER)
        code.jump_slot(SLOT_A)

        answer = _index(image, tmp_path, _hits((first, ("OpenThingW",))))

        assert [c["name"] for c in _row(answer, USER)["slot_calls"]] == ["OpenThingW"]


def _record(code: _Code, offset: int, value: int, slot: int) -> int:
    """One record: the hashed value, then the module's address, then the slot's."""
    place = code.hash_in_record(offset, value)
    code.lea_rax(MODULE)
    code.rax_to_frame(offset + 8)
    code.lea_rax(slot)
    code.rax_to_frame(offset + 16)
    return place


class TestATableOfRecords:
    def test_each_record_names_the_one_address_some_code_calls_through(
        self, tmp_path: Path
    ) -> None:
        image, code = _image()
        code.go(BUILDER)
        first = _record(code, 0x30, 0x1111AAAA, SLOT_A)
        second = _record(code, 0x48, 0x2222BBBB, SLOT_B)
        code.ret()
        _user_calls(code)

        answer = _index(image, tmp_path, _hits((first, ("OpenThingW",)), (second, ("CloseThing",))))

        assert answer["resolved_slots"] == {
            hex(BASE + SLOT_A): "OpenThingW",
            hex(BASE + SLOT_B): "CloseThing",
        }
        assert [c["name"] for c in _row(answer, USER)["slot_calls"]] == [
            "CloseThing",
            "OpenThingW",
        ]
        assert answer["calls_unnamed"] == {}

    def test_a_record_whose_slot_nothing_calls_names_nothing(self, tmp_path: Path) -> None:
        image, code = _image()
        code.go(BUILDER)
        first = _record(code, 0x30, 0x1111AAAA, SLOT_A)
        second = _record(code, 0x48, 0x2222BBBB, SLOT_B)
        code.ret()
        code.go(USER)
        code.call_slot(SLOT_A)
        code.ret()

        answer = _index(image, tmp_path, _hits((first, ("OpenThingW",)), (second, ("CloseThing",))))

        assert answer["resolved_slots"] == {hex(BASE + SLOT_A): "OpenThingW"}

    def test_a_run_whose_records_could_run_either_way_names_nothing(self, tmp_path: Path) -> None:
        image, code = _image()
        code.go(BUILDER)
        code.lea_rax(MODULE)  # an address before the first hashed value
        code.rax_to_frame(0x28)
        first = _record(code, 0x30, 0x1111AAAA, SLOT_A)
        second = _record(code, 0x48, 0x2222BBBB, SLOT_B)
        code.ret()
        _user_calls(code)

        answer = _index(image, tmp_path, _hits((first, ("OpenThingW",)), (second, ("CloseThing",))))

        assert answer["resolved_slots"] == {}
        assert answer["calls_unnamed"] == {hex(BASE + USER): 2}

    def test_with_no_hash_resolution_nothing_is_named(self, tmp_path: Path) -> None:
        image, code = _image()
        code.go(BUILDER)
        _record(code, 0x30, 0x1111AAAA, SLOT_A)
        code.ret()
        _user_calls(code)
        target = tmp_path / "s.exe"
        target.write_bytes(image.build())

        answer = artefact_index.function_index(str(target))

        assert answer["resolved_slots"] == {} and answer["ambiguous_slots"] == {}
        assert answer["calls_unnamed"] == {hex(BASE + USER): 2}

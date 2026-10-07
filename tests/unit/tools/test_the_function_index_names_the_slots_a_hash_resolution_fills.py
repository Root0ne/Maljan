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

    def test_an_address_stored_below_the_first_record_belongs_to_none(self, tmp_path: Path) -> None:
        image, code = _image()
        code.go(BUILDER)
        code.lea_rax(SLOT_B)  # stored below the first hashed value's offset
        code.rax_to_frame(0x28)
        first = _record(code, 0x30, 0x1111AAAA, SLOT_A)
        code.ret()
        _user_calls(code)

        answer = _index(image, tmp_path, _hits((first, ("OpenThingW",))))

        assert answer["resolved_slots"] == {hex(BASE + SLOT_A): "OpenThingW"}
        assert answer["calls_unnamed"] == {hex(BASE + USER): 1}

    def test_a_record_holding_two_called_addresses_names_nothing_in_its_run(
        self, tmp_path: Path
    ) -> None:
        image, code = _image()
        code.go(BUILDER)
        first = code.hash_in_record(0x30, 0x1111AAAA)
        code.lea_rax(SLOT_A)
        code.rax_to_frame(0x38)
        code.lea_rax(SLOT_B)
        code.rax_to_frame(0x40)
        second = _record(code, 0x48, 0x2222BBBB, MODULE)
        code.ret()
        _user_calls(code)

        answer = _index(image, tmp_path, _hits((first, ("OpenThingW",)), (second, ("CloseThing",))))

        assert answer["resolved_slots"] == {}

    def test_records_pushed_rather_than_stored_in_the_frame_name_nothing(
        self, tmp_path: Path
    ) -> None:
        image, code = _image()
        code.go(BUILDER)
        place = code.raw(b"\x68" + struct.pack("<I", 0x1111AAAA))  # push hash
        code.lea_rax(SLOT_A)
        code.raw(b"\x50")  # push rax
        code.ret()
        _user_calls(code)

        answer = _index(image, tmp_path, _hits((place, ("OpenThingW",))))

        assert answer["resolved_slots"] == {}

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


OTHER = TEXT_RVA + 0x180


class TestOnlyTheResolverSCallIsTied:
    def test_a_hash_held_outside_the_arguments_ties_no_call(self, tmp_path: Path) -> None:
        image, code = _image()
        image.functions.append((OTHER, OTHER + 0x10))
        code.go(OTHER).clobber_rax()
        code.ret()
        code.go(BUILDER)
        place = code.raw(b"\x41\xbc" + struct.pack("<I", 0x1111AAAA))  # mov r12d, hash
        code.call(OTHER)
        code.store_rax(SLOT_A)  # what the other call answered, not a resolved name
        code.raw(b"\x44\x89\xe2")  # mov edx, r12d: now an argument
        code.call(RESOLVER)
        code.raw(b"\x48\x89\xc3")  # mov rbx, rax: kept in a register, stored nowhere
        code.ret()
        code.go(USER).call_slot(SLOT_A)
        code.ret()

        answer = _index(image, tmp_path, _hits((place, ("OpenThingW",))))

        assert answer["resolved_slots"] == {}
        assert answer["calls_unnamed"] == {hex(BASE + USER): 1}

    def test_two_function_name_hashes_live_at_one_call_tie_nothing(self, tmp_path: Path) -> None:
        image, code = _image()
        code.go(BUILDER)
        first = code.hash_in_edx(0x1111AAAA)
        second = code.raw(b"\x41\xb8" + struct.pack("<I", 0x2222BBBB))  # mov r8d, hash
        code.call(RESOLVER)
        code.store_rax(SLOT_A)
        code.ret()
        code.go(USER).call_slot(SLOT_A)
        code.ret()

        answer = _index(image, tmp_path, _hits((first, ("OpenThingW",)), (second, ("CloseThing",))))

        assert answer["resolved_slots"] == {}

    def test_a_module_hash_beside_the_function_s_does_not_untie_the_call(
        self, tmp_path: Path
    ) -> None:
        image, code = _image()
        code.go(BUILDER)
        module = code.raw(b"\xb9" + struct.pack("<I", 0x3333CCCC))  # mov ecx, module hash
        first = code.hash_in_edx(0x1111AAAA)
        code.call(RESOLVER)
        code.store_rax(SLOT_A)
        code.ret()
        code.go(USER).call_slot(SLOT_A)
        code.ret()

        answer = _index(image, tmp_path, _hits((module, ()), (first, ("OpenThingW",))))

        assert answer["resolved_slots"] == {hex(BASE + SLOT_A): "OpenThingW"}

    def test_a_second_call_after_the_hash_was_consumed_is_untied(self, tmp_path: Path) -> None:
        image, code = _image()
        code.go(BUILDER)
        first = code.hash_in_edx(0x1111AAAA)
        code.call(RESOLVER)
        code.store_rax(SLOT_A)
        code.call(RESOLVER)
        code.store_rax(SLOT_B)
        code.ret()
        _user_calls(code)

        answer = _index(image, tmp_path, _hits((first, ("OpenThingW",))))

        assert answer["resolved_slots"] == {hex(BASE + SLOT_A): "OpenThingW"}


class TestARecordReadsOnlyItsOwnAddresses:
    def test_hashes_written_before_the_addresses_are_read_by_their_offsets(
        self, tmp_path: Path
    ) -> None:
        image, code = _image()
        code.go(BUILDER)
        first = code.hash_in_record(0x30, 0x1111AAAA)
        second = code.hash_in_record(0x48, 0x2222BBBB)
        for offset, slot in ((0x38, MODULE), (0x40, SLOT_A), (0x50, MODULE), (0x58, SLOT_B)):
            code.lea_rax(slot)
            code.rax_to_frame(offset)
        code.ret()
        code.go(USER).call_slot(SLOT_A)
        code.ret()

        answer = _index(image, tmp_path, _hits((first, ("OpenThingW",)), (second, ("CloseThing",))))

        # Only the first record's slot is called: it is named, the second names nothing.
        assert answer["resolved_slots"] == {hex(BASE + SLOT_A): "OpenThingW"}

    def test_addresses_written_before_the_hashes_are_read_by_their_offsets(
        self, tmp_path: Path
    ) -> None:
        image, code = _image()
        code.go(BUILDER)
        code.lea_rax(SLOT_A)
        code.rax_to_frame(0x40)
        code.lea_rax(SLOT_B)
        code.rax_to_frame(0x58)
        first = code.hash_in_record(0x30, 0x1111AAAA)
        second = code.hash_in_record(0x48, 0x2222BBBB)
        code.ret()
        code.go(USER).call_slot(SLOT_B)
        code.ret()

        answer = _index(image, tmp_path, _hits((first, ("OpenThingW",)), (second, ("CloseThing",))))

        assert answer["resolved_slots"] == {hex(BASE + SLOT_B): "CloseThing"}

    def test_records_emitted_out_of_layout_order_name_each_slot_right(self, tmp_path: Path) -> None:
        image, code = _image()
        code.go(BUILDER)
        first = code.hash_in_record(0x00, 0x1111AAAA)
        code.lea_rax(MODULE)
        code.rax_to_frame(0x08)
        code.lea_rax(SLOT_B)  # the second record's slot, emitted early
        code.rax_to_frame(0x28)
        second = code.hash_in_record(0x18, 0x2222BBBB)
        code.lea_rax(SLOT_A)  # the first record's slot, emitted late
        code.rax_to_frame(0x10)
        code.lea_rax(MODULE)
        code.rax_to_frame(0x20)
        code.ret()
        code.go(USER).call_slot(SLOT_A)
        code.call_slot(SLOT_B)
        code.ret()

        answer = _index(image, tmp_path, _hits((first, ("OpenThingW",)), (second, ("CloseThing",))))

        assert answer["resolved_slots"] == {
            hex(BASE + SLOT_A): "OpenThingW",
            hex(BASE + SLOT_B): "CloseThing",
        }

    def test_only_slots_some_code_calls_through_are_stated(self, tmp_path: Path) -> None:
        image, code = _image()
        code.go(BUILDER)
        first = code.hash_in_edx(0x1111AAAA)
        code.call(RESOLVER)
        code.store_rax(SLOT_A)
        code.ret()

        answer = _index(image, tmp_path, _hits((first, ("OpenThingW",))))

        assert answer["resolved_slots"] == {}


X86_BASE = 0x400000
X86_SLOT_A = DATA_RVA + 0x300
X86_SLOT_B = DATA_RVA + 0x304


def _x86(tmp_path: Path, build: Any, hits: Any, called: list[int]) -> dict[str, Any]:
    image = SyntheticPE(is64=False, image_base=X86_BASE)
    code = _Code(image)
    code.go(RESOLVER).raw(b"\x31\xc0\xc3")
    code.go(BUILDER)
    places = build(code)
    code.call(RESOLVER)
    code.call(USER)
    code.ret()
    code.go(USER)
    for slot in called:
        code.raw(b"\xff\x15" + struct.pack("<I", X86_BASE + slot))
    code.ret()
    target = tmp_path / "x.exe"
    target.write_bytes(image.build())
    return artefact_index.function_index(
        str(target),
        pe_info=("ev_0004", {"entry_point": BUILDER, "export_rows": []}),
        hashes=(HASH_ID, hits(places)),
    )


class TestAnX86Image:
    def test_a_pushed_hash_ties_the_call_and_its_moffs_store_names_the_slot(
        self, tmp_path: Path
    ) -> None:
        def build(code: _Code) -> list[int]:
            place = code.raw(b"\x68" + struct.pack("<I", 0x1111AAAA))
            code.call(RESOLVER)
            code.raw(b"\xa3" + struct.pack("<I", X86_BASE + X86_SLOT_A))
            return [place]

        answer = _x86(tmp_path, build, lambda p: _hits((p[0], ("OpenThingW",))), [X86_SLOT_A])
        assert answer["resolved_slots"] == {hex(X86_BASE + X86_SLOT_A): "OpenThingW"}

    def test_a_hash_equal_to_a_slot_s_address_is_no_address(self, tmp_path: Path) -> None:
        def build(code: _Code) -> list[int]:
            place = code.raw(b"\xc7\x44\x24\x00" + struct.pack("<I", X86_BASE + X86_SLOT_B))
            code.raw(b"\xc7\x44\x24\x04" + struct.pack("<I", X86_BASE + X86_SLOT_A))
            return [place]

        answer = _x86(tmp_path, build, lambda p: _hits((p[0], ("OpenThingW",))), [X86_SLOT_B])
        assert answer["resolved_slots"] == {}

    def test_hashes_before_addresses_are_read_by_their_offsets(self, tmp_path: Path) -> None:
        def build(code: _Code) -> list[int]:
            first = code.raw(b"\xc7\x44\x24\x00" + struct.pack("<I", 0x1111AAAA))
            second = code.raw(b"\xc7\x44\x24\x08" + struct.pack("<I", 0x2222BBBB))
            code.raw(b"\xc7\x44\x24\x04" + struct.pack("<I", X86_BASE + X86_SLOT_A))
            code.raw(b"\xc7\x44\x24\x0c" + struct.pack("<I", X86_BASE + X86_SLOT_B))
            return [first, second]

        answer = _x86(
            tmp_path,
            build,
            lambda p: _hits((p[0], ("OpenThingW",)), (p[1], ("CloseThing",))),
            [X86_SLOT_A],
        )
        assert answer["resolved_slots"] == {hex(X86_BASE + X86_SLOT_A): "OpenThingW"}


class TestEveryIndirectJumpNamesNothing:
    def test_jumps_and_calls_through_registers_and_operands_are_counted(
        self, tmp_path: Path
    ) -> None:
        for body in (
            b"\x48\x8b\x43\x08\xff\xe0",  # mov rax, [rbx+8]; jmp rax
            b"\xff\x60\x10",  # jmp [rax+0x10]
            b"\xff\x24\xc5" + struct.pack("<I", DATA_RVA),  # jmp [rax*8+table]
            b"\xff\x50\x10\xc3",  # call [rax+0x10]
            b"\xff\xd0\xc3",  # call rax
        ):
            image, code = _image()
            code.go(BUILDER).call(USER)
            code.ret()
            code.go(USER).raw(body)
            target = tmp_path / "s.exe"
            target.write_bytes(image.build())
            answer = artefact_index.function_index(str(target))
            assert answer["calls_unnamed"] == {hex(BASE + USER): 1}, body.hex()

    def test_the_graph_lists_the_callees_of_functions_that_are_no_row(self, tmp_path: Path) -> None:
        image, code = _image()
        code.go(BUILDER).call(USER)
        code.ret()
        code.go(USER).raw(b"\x31\xc0\xc3")
        target = tmp_path / "s.exe"
        target.write_bytes(image.build())
        answer = artefact_index.function_index(str(target))
        assert answer["other_callees"] == {hex(BASE + BUILDER): [hex(BASE + USER)]}

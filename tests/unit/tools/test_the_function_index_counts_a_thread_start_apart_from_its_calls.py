"""A thread start and an address taken are relations of their own, never a call.

A function that hands another function's address to ``CreateThread`` starts it
on a thread: the started function has no caller, and the index used to say
"called by 0" and nothing more. The index now reads the code address placed in
the start-routine argument of a call to a thread-starting API (an import, or a
slot the hash resolution fills) and states it as a thread start; any other
function start an instruction takes as a value is an address taken. Neither is
counted as a caller or a callee.

Each image is synthetic (``synthetic_pe``): the code bytes are written by the
test, one instruction at a time, and every name and hash value is chosen by it.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

from maljan.tools import artefact_index

from .synthetic_pe import DATA_RVA, TEXT_RVA, SyntheticPE

BASE = 0x140000000
X86_BASE = 0x400000
MAIN = TEXT_RVA
STARTER = TEXT_RVA + 0x80
WORKER = TEXT_RVA + 0x100
RESOLVER = TEXT_RVA + 0x180
SLOT = DATA_RVA + 0x300
PARAMETER = DATA_RVA + 0x200
HASH_ID = "ev_0020"

# The register forms of ``lea reg, [rip+disp32]``.
_LEA = {
    "rcx": b"\x48\x8d\x0d",
    "rdx": b"\x48\x8d\x15",
    "r8": b"\x4c\x8d\x05",
    "r9": b"\x4c\x8d\x0d",
}


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

    def _rip(self, head: bytes, target: int) -> int:
        end = TEXT_RVA + self.at + len(head) + 4
        return self.raw(head + struct.pack("<i", target - end))

    def lea(self, register: str, target: int) -> int:
        return self._rip(_LEA[register], target)

    def call(self, target: int) -> int:
        return self._rip(b"\xe8", target)

    def call_slot(self, slot: int) -> int:
        return self._rip(b"\xff\x15", slot)

    def store_rax(self, slot: int) -> int:
        return self._rip(b"\x48\x89\x05", slot)

    def ret(self) -> int:
        return self.raw(b"\xc3")


def _image(imports: list[str]) -> tuple[SyntheticPE, _Code, dict[str, int]]:
    image = SyntheticPE(
        functions=[
            (MAIN, MAIN + 0x40),
            (STARTER, STARTER + 0x40),
            (WORKER, WORKER + 0x40),
            (RESOLVER, RESOLVER + 0x10),
        ]
    )
    slots = image.imports_at(0x100, {"KERNEL32.dll": [*imports, "GetLastError"]})
    code = _Code(image)
    # The worker holds an artefact of its own, so it is a row.
    code.go(WORKER).call_slot(slots["GetLastError"])
    code.ret()
    code.go(RESOLVER).raw(b"\x31\xc0")
    code.ret()
    code.go(MAIN).call(STARTER)
    code.ret()
    return image, code, slots


def _index(image: SyntheticPE, tmp_path: Path, **joined: Any) -> dict[str, Any]:
    target = tmp_path / "s.exe"
    target.write_bytes(image.build())
    return artefact_index.function_index(str(target), **joined)


def _row(answer: dict[str, Any], offset: int) -> dict[str, Any]:
    return next(row for row in answer["rows"] if row["offset"] == hex(offset))


def _va(rva: int, base: int = BASE) -> str:
    return hex(base + rva)


def _start_thread(code: _Code, call: Any, routine_in: str = "r8") -> int:
    """STARTER: ``CreateThread(NULL, 0, WORKER, PARAMETER, 0, NULL)``; answers the call's RVA."""
    code.go(STARTER)
    code.raw(b"\x33\xd2")  # xor edx, edx
    code.raw(b"\x33\xc9")  # xor ecx, ecx
    code.lea("r9" if routine_in == "r8" else "r8", PARAMETER)
    code.lea(routine_in, WORKER)
    site = call()
    code.ret()
    return site


class TestAThreadStartThroughAnImport:
    def test_the_started_function_names_its_starter_and_keeps_no_caller(
        self, tmp_path: Path
    ) -> None:
        image, code, slots = _image(["CreateThread"])
        site = _start_thread(code, lambda: code.call_slot(slots["CreateThread"]))
        answer = _index(image, tmp_path)

        worker = _row(answer, WORKER)
        assert worker["callers"] == []
        assert worker["started_as_thread_by"] == [
            {"function": _va(STARTER), "through": "CreateThread", "call": _va(site)}
        ]
        starter = _row(answer, STARTER)
        assert starter["callees"] == []
        assert starter["starts_threads"] == [
            {"function": _va(WORKER), "through": "CreateThread", "call": _va(site)}
        ]
        assert "takes_address_of" not in starter, "a thread start is not also an address taken"
        assert answer["thread_starts"] == [
            {
                "starter": _va(STARTER),
                "started": _va(WORKER),
                "through": "CreateThread",
                "call": _va(site),
            }
        ]

    def test_the_row_line_says_the_thread_start_and_that_it_is_no_call(
        self, tmp_path: Path
    ) -> None:
        image, code, slots = _image(["CreateThread"])
        site = _start_thread(code, lambda: code.call_slot(slots["CreateThread"]))
        answer = _index(image, tmp_path)

        line = artefact_index.row_line(_row(answer, WORKER), "ev_0025")
        assert "called by 0, calls 0 functions" in line
        assert (
            f'started as a thread by {_va(STARTER)} through "CreateThread" (call at {_va(site)}) '
            f"{artefact_index.NOT_A_CALL}"
        ) in line
        line = artefact_index.row_line(_row(answer, STARTER), "ev_0025")
        assert f'starts a thread at {_va(WORKER)} through "CreateThread"' in line

    def test_a_row_built_before_the_relations_reads_as_it_did(self) -> None:
        row = {
            "function": _va(WORKER),
            "offset": hex(WORKER),
            "direct": 1,
            "imports": [{"name": "GetLastError", "sources": ["this entry"]}],
            "callers": [],
            "callees": [],
            "indirect": {"artefacts": 0, "through": 0},
        }
        assert artefact_index.row_line(row, "ev_0025") == (
            f'- {_va(WORKER)}: calls "GetLastError" (ev_0025); called by 0, calls 0 functions'
        )

    def test_the_routine_in_another_argument_is_an_address_taken(self, tmp_path: Path) -> None:
        image, code, slots = _image(["CreateThread"])
        # The worker's address in r9, CreateThread's parameter, not its start routine.
        _start_thread(code, lambda: code.call_slot(slots["CreateThread"]), routine_in="r9")
        answer = _index(image, tmp_path)

        assert "thread_starts" not in answer
        worker = _row(answer, WORKER)
        assert "started_as_thread_by" not in worker
        assert worker["address_taken_by"] == [_va(STARTER)]
        assert _row(answer, STARTER)["takes_address_of"] == [_va(WORKER)]
        assert answer["addresses_taken"] == {_va(STARTER): [_va(WORKER)]}

    def test_an_api_that_starts_no_thread_is_an_address_taken(self, tmp_path: Path) -> None:
        image, code, slots = _image(["EnumWindows"])
        _start_thread(code, lambda: code.call_slot(slots["EnumWindows"]))
        answer = _index(image, tmp_path)

        assert "thread_starts" not in answer
        assert _row(answer, WORKER)["address_taken_by"] == [_va(STARTER)]

    def test_a_routine_register_overwritten_before_the_call_is_no_thread_start(
        self, tmp_path: Path
    ) -> None:
        image, code, slots = _image(["CreateThread"])

        def clobbered_call() -> int:
            code.raw(b"\x45\x33\xc0")  # xor r8d, r8d
            return code.call_slot(slots["CreateThread"])

        _start_thread(code, clobbered_call)
        answer = _index(image, tmp_path)

        assert "thread_starts" not in answer
        # The lea still took the address.
        assert _row(answer, WORKER)["address_taken_by"] == [_va(STARTER)]

    def test_an_address_copied_into_the_routine_register_is_read(self, tmp_path: Path) -> None:
        image, code, slots = _image(["CreateThread"])
        code.go(STARTER)
        code._rip(b"\x48\x8d\x05", WORKER)  # lea rax, [rip+WORKER]
        code.raw(b"\x4c\x8b\xc0")  # mov r8, rax
        site = code.call_slot(slots["CreateThread"])
        code.ret()
        answer = _index(image, tmp_path)

        assert _row(answer, WORKER)["started_as_thread_by"] == [
            {"function": _va(STARTER), "through": "CreateThread", "call": _va(site)}
        ]

    def test_the_served_index_names_the_relations_of_an_asked_function(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        image, code, slots = _image(["CreateThread"])
        site = _start_thread(code, lambda: code.call_slot(slots["CreateThread"]))
        target = tmp_path / "s.exe"
        target.write_bytes(image.build())
        from maljan.tools import emulated_strings

        monkeypatch.setattr(emulated_strings, "remembered_rows", lambda path: [])
        served = artefact_index.served_index(str(target), address=_va(WORKER))

        assert served["callers"] == []
        assert served["started_as_thread_by"] == [
            {"function": _va(STARTER), "through": "CreateThread", "call": _va(site)}
        ]
        assert "started as a thread by" in served["row"]


class TestAThreadStartThroughAResolvedSlot:
    def test_a_slot_the_hash_resolution_names_create_thread_starts_the_routine(
        self, tmp_path: Path
    ) -> None:
        image, code, _slots = _image([])
        code.go(MAIN)
        place = code.raw(b"\xba" + struct.pack("<I", 0x1234ABCD))  # mov edx, hash
        code.call(RESOLVER)
        code.store_rax(SLOT)
        code.call(STARTER)
        code.ret()
        site = _start_thread(code, lambda: code.call_slot(SLOT))
        hashes = {
            "hits": [
                {
                    "readings": [{"set": "exports", "name": "CreateThread"}],
                    "occurrences": [{"rva": hex(place)}],
                }
            ]
        }
        answer = _index(image, tmp_path, hashes=(HASH_ID, hashes))

        assert answer["resolved_slots"] == {_va(SLOT): "CreateThread"}
        assert _row(answer, WORKER)["started_as_thread_by"] == [
            {"function": _va(STARTER), "through": "CreateThread", "call": _va(site)}
        ]

    def test_a_slot_nothing_names_starts_nothing(self, tmp_path: Path) -> None:
        image, code, _slots = _image([])
        _start_thread(code, lambda: code.call_slot(SLOT))
        answer = _index(image, tmp_path)

        assert "thread_starts" not in answer
        assert _row(answer, WORKER)["address_taken_by"] == [_va(STARTER)]


class TestAnX86ThreadStart:
    def test_the_pushed_routine_in_the_third_argument_is_the_thread_start(
        self, tmp_path: Path
    ) -> None:
        image = SyntheticPE(is64=False, image_base=X86_BASE)
        slots = image.imports_at(0x100, {"KERNEL32.dll": ["CreateThread", "GetLastError"]})
        code = _Code(image)
        worker_va = X86_BASE + WORKER
        code.go(WORKER).raw(b"\xff\x15" + struct.pack("<I", X86_BASE + slots["GetLastError"]))
        code.ret()
        code.go(MAIN)
        code.call(STARTER)
        code.ret()
        code.go(STARTER)
        code.raw(b"\x6a\x00")  # push 0: thread id
        code.raw(b"\x6a\x00")  # push 0: flags
        code.raw(b"\x68" + struct.pack("<I", X86_BASE + PARAMETER))  # parameter
        code.raw(b"\x68" + struct.pack("<I", worker_va))  # start routine
        code.raw(b"\x6a\x00")  # push 0: stack size
        code.raw(b"\x6a\x00")  # push 0: attributes
        site = code.raw(b"\xff\x15" + struct.pack("<I", X86_BASE + slots["CreateThread"]))
        code.ret()
        target = tmp_path / "s.exe"
        target.write_bytes(image.build())
        answer = artefact_index.function_index(
            str(target), pe_info=("ev_0004", {"entry_point": MAIN, "export_rows": []})
        )

        # No function table on x86 and no call reaches the worker: the thread
        # start names it from the starter's side, and the worker is no function
        # the index lists.
        assert _row(answer, STARTER)["imports"][0]["name"] == "CreateThread"
        assert answer["thread_starts"] == [
            {
                "starter": _va(STARTER, X86_BASE),
                "started": _va(WORKER, X86_BASE),
                "through": "CreateThread",
                "call": _va(site, X86_BASE),
            }
        ]

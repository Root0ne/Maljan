"""A decoded string's address loaded as a call argument is joined to that call.

A decoded text used to be tied to the function that refers to it and nothing
more, so a name passed as the fourth argument of the call that registers a
task could not be told from a trigger string set on another object in the
same function. Now, where the reference loads the address as an argument and
the next transfer of control in the same function is a call, the result names
the callee (the import, or the call target's address) and the argument
position. Anything else is absent: another register written in between, a
jump before the call, a call through a register, no function table.

Every image is synthetic (``synthetic_pe``): the code bytes are written by the
test, one instruction at a time, and no real program is read.
"""

from __future__ import annotations

import struct
from pathlib import Path

from maljan.tools import call_sites, pe_image
from maljan.tools.string_blobs import decode_string_blobs

from .synthetic_pe import DATA_RVA, TEXT_RVA, SyntheticPE

FUNCTION_END = TEXT_RVA + 0x100
CALLEE = TEXT_RVA + 0x200
STRING = DATA_RVA + 0x40


class _Code:
    """x64 code written into ``.text`` from its start, one instruction after another."""

    def __init__(self, image: SyntheticPE, is64: bool = True) -> None:
        self.image = image
        self.at = 0
        self.is64 = is64

    def raw(self, blob: bytes) -> int:
        start = self.at
        self.image.put("text", start, blob)
        self.at += len(blob)
        return start

    def rip(self, prefix: bytes, target: int, tail: bytes = b"") -> int:
        """An instruction whose last four bytes before ``tail`` are a RIP-relative displacement."""
        end = TEXT_RVA + self.at + len(prefix) + 4 + len(tail)
        return self.raw(prefix + struct.pack("<i", target - end) + tail)

    def lea(self, register: str, target: int) -> int:
        """``lea <register>, [rip+disp32]``; answers the file offset of the displacement."""
        encoding = {"rcx": b"\x48\x8d\x0d", "rdx": b"\x48\x8d\x15", "r8": b"\x4c\x8d\x05"}
        encoding["r9"] = b"\x4c\x8d\x0d"
        encoding["rax"] = b"\x48\x8d\x05"
        start = self.rip(encoding[register], target)
        return start + 3

    def call(self, target: int) -> None:
        end = TEXT_RVA + self.at + 5
        self.raw(b"\xe8" + struct.pack("<i", target - end))

    def call_slot(self, slot: int) -> None:
        self.rip(b"\xff\x15", slot)


def _x64() -> tuple[SyntheticPE, _Code]:
    image = SyntheticPE(functions=[(TEXT_RVA, FUNCTION_END), (CALLEE, CALLEE + 0x20)])
    image.put("data", 0x40, b"the task's name\0")
    return image, _Code(image)


def _load(image: SyntheticPE, tmp_path: Path) -> pe_image.Image:
    target = tmp_path / "s.exe"
    target.write_bytes(image.build())
    return pe_image.load(target)


def _site(image: pe_image.Image, text_offset: int) -> int:
    (text,) = image.code_sections()
    return text.raw_offset + text_offset


class TestX64:
    def test_the_fourth_argument_of_a_direct_call(self, tmp_path: Path) -> None:
        image, code = _x64()
        code.raw(b"\x48\x83\xec\x28")  # sub rsp, 0x28
        site = code.lea("r9", STRING)
        code.raw(b"\x33\xc9")  # xor ecx, ecx
        code.lea("rdx", DATA_RVA + 0x80)
        code.raw(b"\x4c\x8b\xc0")  # mov r8, rax
        code.call(CALLEE)

        loaded = _load(image, tmp_path)
        answer = call_sites.passed_to(loaded, _site(loaded, site))

        assert answer == {
            "call_at": hex(TEXT_RVA + 0x17),
            "callee": {"function": hex(CALLEE)},
            "argument": 4,
            "register": "r9",
        }

    def test_a_call_through_an_import_slot_names_the_import(self, tmp_path: Path) -> None:
        image, code = _x64()
        slots = image.imports_at(0x100, {"KERNEL32.dll": ["CreateMutexW", "GetLastError"]})
        site = code.lea("r8", STRING)
        code.raw(b"\x33\xd2")  # xor edx, edx
        code.raw(b"\x33\xc9")  # xor ecx, ecx
        code.call_slot(slots["CreateMutexW"])

        loaded = _load(image, tmp_path)
        answer = call_sites.passed_to(loaded, _site(loaded, site))

        assert answer is not None
        assert answer["callee"] == {
            "import": "KERNEL32.dll!CreateMutexW",
            "slot": hex(slots["CreateMutexW"]),
        }
        assert (answer["argument"], answer["register"]) == (3, "r8")

    def test_a_call_to_a_jump_thunk_names_the_import_it_goes_through(self, tmp_path: Path) -> None:
        image, code = _x64()
        slots = image.imports_at(0x100, {"USER32.dll": ["MessageBoxA"]})
        site = code.lea("rdx", STRING)
        code.call(CALLEE)
        thunk = _Code(image)
        thunk.at = CALLEE - TEXT_RVA
        thunk.rip(b"\xff\x25", slots["MessageBoxA"])  # jmp [rip+slot]

        loaded = _load(image, tmp_path)
        answer = call_sites.passed_to(loaded, _site(loaded, site))

        assert answer is not None
        assert answer["callee"] == {"import": "USER32.dll!MessageBoxA", "function": hex(CALLEE)}
        assert answer["argument"] == 2

    def test_a_slot_the_import_table_does_not_hold_is_named_by_its_address(
        self, tmp_path: Path
    ) -> None:
        image, code = _x64()
        site = code.lea("rcx", STRING)
        code.call_slot(DATA_RVA + 0x200)

        loaded = _load(image, tmp_path)
        answer = call_sites.passed_to(loaded, _site(loaded, site))

        assert answer is not None
        assert answer["callee"] == {"slot": hex(DATA_RVA + 0x200)}
        assert answer["argument"] == 1


class TestNothingIsGuessed:
    def test_the_argument_register_written_before_the_call(self, tmp_path: Path) -> None:
        image, code = _x64()
        site = code.lea("rcx", STRING)
        code.raw(b"\xb9\x05\x00\x00\x00")  # mov ecx, 5
        code.call(CALLEE)

        loaded = _load(image, tmp_path)
        assert call_sites.passed_to(loaded, _site(loaded, site)) is None

    def test_a_jump_before_the_call(self, tmp_path: Path) -> None:
        image, code = _x64()
        site = code.lea("rcx", STRING)
        code.raw(b"\x74\x02")  # je +2
        code.call(CALLEE)

        loaded = _load(image, tmp_path)
        assert call_sites.passed_to(loaded, _site(loaded, site)) is None

    def test_a_call_through_a_register(self, tmp_path: Path) -> None:
        image, code = _x64()
        site = code.lea("rcx", STRING)
        code.raw(b"\xff\xd0")  # call rax

        loaded = _load(image, tmp_path)
        assert call_sites.passed_to(loaded, _site(loaded, site)) is None

    def test_a_load_into_a_register_that_is_no_argument(self, tmp_path: Path) -> None:
        image, code = _x64()
        site = code.lea("rax", STRING)
        code.call(CALLEE)

        loaded = _load(image, tmp_path)
        assert call_sites.passed_to(loaded, _site(loaded, site)) is None

    def test_no_function_table_around_the_load(self, tmp_path: Path) -> None:
        image = SyntheticPE()
        code = _Code(image)
        site = code.lea("rcx", STRING)
        code.call(CALLEE)

        loaded = _load(image, tmp_path)
        assert call_sites.passed_to(loaded, _site(loaded, site)) is None

    def test_load_bytes_inside_another_instruction(self, tmp_path: Path) -> None:
        image, code = _x64()
        # mov rax, imm64 whose immediate holds the bytes of a load.
        code.raw(b"\x48\xb8")
        inner = code.rip(b"\x48\x8d\x0d", STRING, b"\x90")
        code.call(CALLEE)

        loaded = _load(image, tmp_path)
        assert call_sites.passed_to(loaded, _site(loaded, inner + 3)) is None

    def test_the_call_outside_the_function(self, tmp_path: Path) -> None:
        image = SyntheticPE(functions=[(TEXT_RVA, TEXT_RVA + 7), (CALLEE, CALLEE + 0x20)])
        code = _Code(image)
        site = code.lea("rcx", STRING)
        code.call(CALLEE)

        loaded = _load(image, tmp_path)
        assert call_sites.passed_to(loaded, _site(loaded, site)) is None


class TestX86:
    def _image(self) -> tuple[SyntheticPE, _Code, int]:
        image = SyntheticPE(is64=False, image_base=0x400000)
        return image, _Code(image, is64=False), 0x400000

    def test_a_pushed_address_is_the_argument_its_position_says(self, tmp_path: Path) -> None:
        image, code, base = self._image()
        slots = image.imports_at(0x100, {"KERNEL32.dll": ["CreateMutexA"]})
        start = code.raw(b"\x68" + struct.pack("<I", base + STRING))  # push offset string
        code.raw(b"\x6a\x00")  # push 0
        code.raw(b"\x6a\x00")  # push 0
        code.raw(b"\xff\x15" + struct.pack("<I", base + slots["CreateMutexA"]))  # call [slot]

        loaded = _load(image, tmp_path)
        pe_image.take_function_starts(loaded, [TEXT_RVA], "capa")
        answer = call_sites.passed_to(loaded, _site(loaded, start + 1))

        assert answer == {
            "call_at": hex(TEXT_RVA + 9),
            "callee": {"import": "KERNEL32.dll!CreateMutexA", "slot": hex(slots["CreateMutexA"])},
            "argument": 3,
        }

    def test_a_store_to_the_stack_names_its_slot_s_argument(self, tmp_path: Path) -> None:
        image, code, base = self._image()
        start = code.raw(b"\xc7\x44\x24\x04" + struct.pack("<I", base + STRING))
        code.call(CALLEE)

        loaded = _load(image, tmp_path)
        pe_image.take_function_starts(loaded, [TEXT_RVA], "capa")
        answer = call_sites.passed_to(loaded, _site(loaded, start + 4))

        assert answer is not None
        assert answer["argument"] == 2
        assert answer["callee"] == {"function": hex(CALLEE)}

    def test_a_push_after_a_stack_store_moves_the_argument_and_nothing_is_stated(
        self, tmp_path: Path
    ) -> None:
        image, code, base = self._image()
        start = code.raw(b"\xc7\x04\x24" + struct.pack("<I", base + STRING))
        code.raw(b"\x6a\x00")
        code.call(CALLEE)

        loaded = _load(image, tmp_path)
        pe_image.take_function_starts(loaded, [TEXT_RVA], "capa")
        assert call_sites.passed_to(loaded, _site(loaded, start + 3)) is None


def test_decode_string_blobs_states_the_call_beside_the_reference(tmp_path: Path) -> None:
    image, code = _x64()
    # The text itself, kept under a one-byte key so the decoder finds it.
    image.put("data", 0x40, bytes(b ^ 0x9C for b in b"open the settings file\0"))
    code.raw(b"\x48\x83\xec\x28")
    code.lea("r9", STRING)
    code.call(CALLEE)
    target = tmp_path / "s.exe"
    target.write_bytes(image.build())

    answer = decode_string_blobs(str(target))

    (row,) = [r for r in answer["results"] if r["text"] == "open the settings file"]
    (reference,) = row["references"]
    assert reference["passed_to"] == {
        "call_at": hex(TEXT_RVA + 0x0B),
        "callee": {"function": hex(CALLEE)},
        "argument": 4,
        "register": "r9",
    }


def test_the_pack_line_and_the_indicator_provenance_state_the_call() -> None:
    from maljan.pipeline.triage_pack import _blob_item
    from maljan.reporting.renderers.stix_renderer import _decoder_provenance, _recovery_words

    row = {
        "text": "open the settings file",
        "rva": "0x3040",
        "offset": "0xc40",
        "scheme": "xor8",
        "parameters": {"key": "0x9c"},
        "references": [
            {
                "at": "0x1007",
                "function": "0x1000",
                "passed_to": {
                    "call_at": "0x100b",
                    "callee": {"import": "KERNEL32.dll!CreateFileA", "slot": "0x2010"},
                    "argument": 1,
                    "register": "rcx",
                },
            }
        ],
    }
    said = "argument 1 of the call at 0x100b to KERNEL32.dll!CreateFileA"

    assert f"referred to at 0x1007 (in 0x1000) as {said}" in _blob_item(row)
    assert f"passed as {said}" in _recovery_words(_decoder_provenance(row, "ev_0021"))

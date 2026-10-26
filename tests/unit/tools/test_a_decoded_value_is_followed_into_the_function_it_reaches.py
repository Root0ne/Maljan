"""A decoded text handed to a function of the file is followed one function deep.

The decoder's output used to be followed to the next call in the same
function and no further, so a user agent handed to a routine that opens the
HTTP session with it ended at that routine. Now, where that call reaches a
function of the file, the function is read from its first instruction: its
argument spilled to its home slot and read back after the frame is made is
the same value, and the first call that receives it is stated (``inside``).
A write to the frame pointer, or any stack move other than a push or a
``sub rsp``, states nothing.

Every image is synthetic (``synthetic_pe``): the code bytes are written by the
test, one instruction at a time, and no real program is read.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from maljan.tools import call_sites

from .synthetic_pe import TEXT_RVA, SyntheticPE
from .test_a_decoded_string_is_joined_to_its_call import (
    CONSUMER,
    DECODER,
    FUNCTION_END,
    STRING,
    _Code,
    _load,
    _site,
)

CONSUMER_END = CONSUMER + 0x40


def _image() -> tuple[SyntheticPE, _Code, dict[str, int]]:
    image = SyntheticPE(
        functions=[(TEXT_RVA, FUNCTION_END), (DECODER, DECODER + 0x20), (CONSUMER, CONSUMER_END)]
    )
    slots = image.imports_at(0x100, {"WININET.dll": ["InternetOpenW"]})
    return image, _Code(image), slots


def _caller(code: _Code) -> int:
    """The decoder given the encoded bytes and a frame slot, then the slot given to CONSUMER."""
    code.raw(b"\x48\x8d\x54\x24\x40")  # lea rdx, [rsp+0x40]
    site = code.lea("rcx", STRING)
    code.call(DECODER)
    code.raw(b"\x48\x8d\x4c\x24\x40")  # lea rcx, [rsp+0x40]
    code.call(CONSUMER)
    code.raw(b"\xc3")  # ret
    return site


def _consumer(image: SyntheticPE, body: list[bytes], slot: int) -> None:
    """CONSUMER's code; ``None`` in ``body`` stands for ``call [rip+slot]``."""
    at = CONSUMER - TEXT_RVA
    for blob in body:
        if not blob:
            end = TEXT_RVA + at + 6
            blob = b"\xff\x15" + struct.pack("<i", slot - end)
        image.put("text", at, blob)
        at += len(blob)


_SPILL_AND_RELOAD = [
    b"\x48\x89\x4c\x24\x08",  # mov [rsp+8], rcx (its home slot)
    b"\x53",  # push rbx
    b"\x48\x83\xec\x50",  # sub rsp, 0x50
    b"\x45\x33\xc9",  # xor r9d, r9d
    b"\x45\x33\xc0",  # xor r8d, r8d
    b"\x33\xd2",  # xor edx, edx
    b"\x48\x8b\x4c\x24\x60",  # mov rcx, [rsp+0x60] (the home slot, 0x58 bytes lower)
    b"",  # call [rip+InternetOpenW]
    b"\x48\x83\xc4\x50",  # add rsp, 0x50
    b"\x5b",  # pop rbx
    b"\xc3",  # ret
]


def test_an_argument_spilled_to_its_home_slot_is_followed_to_the_import(tmp_path: Path) -> None:
    image, code, slots = _image()
    site = _caller(code)
    _consumer(image, _SPILL_AND_RELOAD, slots["InternetOpenW"])

    loaded = _load(image, tmp_path)
    answer = call_sites.passed_to(loaded, _site(loaded, site))

    assert answer is not None
    then = answer["output_passed_to"]
    assert then["callee"] == {"function": hex(CONSUMER)}
    assert (then["argument"], then["register"]) == (1, "rcx")
    inside = then["inside"]
    assert inside["function"] == hex(CONSUMER)
    assert inside["callee"] == {
        "import": "WININET.dll!InternetOpenW",
        "slot": hex(slots["InternetOpenW"]),
    }
    assert (inside["argument"], inside["register"], inside["fall_through"]) == (1, "rcx", False)
    assert inside["call_at"] == hex(CONSUMER + 23)


def test_the_words_name_the_call_inside_by_the_call_that_reaches_it(tmp_path: Path) -> None:
    image, code, slots = _image()
    site = _caller(code)
    _consumer(image, _SPILL_AND_RELOAD, slots["InternetOpenW"])

    loaded = _load(image, tmp_path)
    answer = call_sites.passed_to(loaded, _site(loaded, site))

    assert answer is not None
    then = answer["output_passed_to"]
    said = call_sites.passed_to_words(answer)
    assert said.endswith(
        f"; it is not followed past that call; inside the function at {hex(CONSUMER)}, which "
        f"the call at {then['call_at']} calls, its argument 1 is argument 1 of the call at "
        f"{hex(CONSUMER + 23)} to WININET.dll!InternetOpenW"
    )


def test_a_frame_pointer_made_inside_states_nothing(tmp_path: Path) -> None:
    image, code, slots = _image()
    site = _caller(code)
    body = [
        b"\x48\x89\x4c\x24\x08",  # mov [rsp+8], rcx
        b"\x55",  # push rbp
        b"\x48\x8b\xec",  # mov rbp, rsp
        b"\x48\x8b\x4d\x10",  # mov rcx, [rbp+0x10]
        b"",  # call [rip+InternetOpenW]
        b"\x5d",  # pop rbp
        b"\xc3",  # ret
    ]
    _consumer(image, body, slots["InternetOpenW"])

    loaded = _load(image, tmp_path)
    answer = call_sites.passed_to(loaded, _site(loaded, site))

    assert answer is not None
    assert "inside" not in answer["output_passed_to"]


def test_a_stack_move_it_cannot_read_states_nothing(tmp_path: Path) -> None:
    image, code, slots = _image()
    site = _caller(code)
    body = [
        b"\x48\x89\x4c\x24\x08",  # mov [rsp+8], rcx
        b"\x48\x83\xe4\xf0",  # and rsp, -16
        b"\x48\x8b\x4c\x24\x08",  # mov rcx, [rsp+8]
        b"",  # call [rip+InternetOpenW]
        b"\xc3",  # ret
    ]
    _consumer(image, body, slots["InternetOpenW"])

    loaded = _load(image, tmp_path)
    answer = call_sites.passed_to(loaded, _site(loaded, site))

    assert answer is not None
    assert "inside" not in answer["output_passed_to"]


def test_a_slot_overwritten_inside_states_nothing(tmp_path: Path) -> None:
    image, code, slots = _image()
    site = _caller(code)
    body = [
        b"\x48\x89\x4c\x24\x08",  # mov [rsp+8], rcx
        b"\x48\x83\xec\x28",  # sub rsp, 0x28
        b"\x33\xc9",  # xor ecx, ecx
        b"\x48\x89\x44\x24\x30",  # mov [rsp+0x30], rax (over the home slot)
        b"\x48\x8b\x4c\x24\x30",  # mov rcx, [rsp+0x30]
        b"",  # call [rip+InternetOpenW]
        b"\xc3",  # ret
    ]
    _consumer(image, body, slots["InternetOpenW"])

    loaded = _load(image, tmp_path)
    answer = call_sites.passed_to(loaded, _site(loaded, site))

    assert answer is not None
    assert "inside" not in answer["output_passed_to"]


def test_a_function_is_read_once_for_every_call_that_reaches_it(tmp_path: Path) -> None:
    image, code, slots = _image()
    site = _caller(code)
    _consumer(image, _SPILL_AND_RELOAD, slots["InternetOpenW"])

    loaded = _load(image, tmp_path)
    first = call_sites.passed_to(loaded, _site(loaded, site))
    held = [key for key in loaded.walks() if isinstance(key, tuple) and key[0] == "parameter"]
    second = call_sites.passed_to(loaded, _site(loaded, site))

    assert first == second
    assert held == [("parameter", CONSUMER, 1)]
    assert [key for key in loaded.walks() if key[0] == "parameter"] == held


# ---------------------------------------------------------------------------
# What is followed must still be what the decoder left in the frame slot.
# ---------------------------------------------------------------------------


def _to_the_api(between: list[bytes], api: str = "CreateMutexW") -> tuple[SyntheticPE, int]:
    """The decoder given a frame slot, ``between`` (``b""`` calls CONSUMER), the slot to ``api``."""
    image = SyntheticPE(
        functions=[(TEXT_RVA, FUNCTION_END), (DECODER, DECODER + 0x20), (CONSUMER, CONSUMER_END)]
    )
    slots = image.imports_at(0x100, {"KERNEL32.dll": [api]})
    code = _Code(image)
    code.raw(b"\x48\x8d\x54\x24\x40")  # lea rdx, [rsp+0x40]
    site = code.lea("rcx", STRING)
    code.call(DECODER)
    for blob in between:
        if blob:
            code.raw(blob)
        else:
            code.call(CONSUMER)
    code.raw(b"\x4c\x8d\x44\x24\x40")  # lea r8, [rsp+0x40]
    code.raw(b"\x33\xd2\x33\xc9")  # xor edx, edx; xor ecx, ecx
    code.call_slot(slots[api])
    code.raw(b"\xc3")  # ret
    image.put("text", DECODER - TEXT_RVA, b"\xc3")
    image.put("text", CONSUMER - TEXT_RVA, b"\xc3")
    return image, site


def _then(between: list[bytes], tmp_path: Path, api: str = "CreateMutexW") -> dict | None:
    image, site = _to_the_api(between, api)
    loaded = _load(image, tmp_path)
    answer = call_sites.passed_to(loaded, _site(loaded, site))
    assert answer is not None
    return answer.get("output_passed_to")


def test_untouched_contents_reach_the_api(tmp_path: Path) -> None:
    then = _then([], tmp_path)

    assert then is not None
    assert (then["callee"]["import"], then["argument"]) == ("KERNEL32.dll!CreateMutexW", 3)
    assert then["contents_unchanged"] is True


_CHANGES = {
    "overwritten": [b"\xc7\x44\x24\x40\x41\x41\x41\x41"],  # mov dword [rsp+0x40], 0x41414141
    "appended": [b"\x66\xc7\x44\x24\x48\x5c\x00"],  # mov word [rsp+0x48], 0x5c
    "inside-address": [b"\x48\x8d\x4c\x24\x42", b""],  # lea rcx, [rsp+0x42]; call CONSUMER
    "frame-address-to-a-call": [b"\x48\x8d\x4c\x24\x30", b""],  # lea rcx, [rsp+0x30]; call
    "held-base": [b"\x48\x8d\x44\x24\x40", b"\xc6\x40\x02\x00"],  # lea rax, [rsp+0x40]; [rax+2]
    "rep-movsb-tail": [
        b"\x48\x8d\x7c\x24\x48",  # lea rdi, [rsp+0x48]
        b"\x48\x8d\x35\x00\x01\x00\x00",  # lea rsi, [rip+0x100]
        b"\xb9\x08\x00\x00\x00",  # mov ecx, 8
        b"\xf3\xa4",  # rep movsb
    ],
    "rep-stosw-whole": [
        b"\x48\x8d\x7c\x24\x40",  # lea rdi, [rsp+0x40]
        b"\x33\xc0",  # xor eax, eax
        b"\xb9\x04\x00\x00\x00",  # mov ecx, 4
        b"\xf3\x66\xab",  # rep stosw
    ],
    "stosw-held": [b"\x48\x8d\x7c\x24\x40", b"\x66\xab"],  # lea rdi, [rsp+0x40]; stosw
    "via-rax-store": [b"\x48\x8d\x44\x24\x40", b"\x66\xc7\x40\x10\x00\x00"],  # [rax+0x10]
    "index-store": [b"\x66\xc7\x44\x44\x40\x5c\x00"],  # mov word [rsp+rax*2+0x40], 0x5c
    "sse-store": [b"\xf3\x0f\x7f\x44\x24\x40"],  # movdqu [rsp+0x40], xmm0
    "local-above": [b"\xc7\x44\x24\x60\x01\x00\x00\x00"],  # mov dword [rsp+0x60], 1
}


@pytest.mark.parametrize("change", sorted(_CHANGES))
def test_a_change_on_the_way_is_flagged_and_the_hop_is_still_stated(
    change: str, tmp_path: Path
) -> None:
    then = _then(_CHANGES[change], tmp_path)

    # The address flow is a fact whatever the code writes: the hop is the one
    # dev states, and only the flag says the contents may have changed.
    assert then is not None
    assert (then["callee"]["import"], then["argument"]) == ("KERNEL32.dll!CreateMutexW", 3)
    assert then["contents_unchanged"] is False


def test_a_local_below_the_slot_leaves_the_contents_unchanged(tmp_path: Path) -> None:
    then = _then([b"\x48\x89\x44\x24\x30"], tmp_path)  # mov [rsp+0x30], rax

    assert then is not None
    assert then["contents_unchanged"] is True


def test_the_stated_hops_are_dev_s_where_locals_above_the_slot_are_written(
    tmp_path: Path,
) -> None:
    # dev stated this hop (the walk follows the address, not the contents);
    # the flag is the only addition.
    then = _then([b"\xc7\x44\x24\x60\x01\x00\x00\x00", b"\x48\x8d\x4c\x24\x70", b""], tmp_path)

    assert then is not None
    assert {key: then[key] for key in then if key != "contents_unchanged"} == {
        "call_at": then["call_at"],
        "callee": then["callee"],
        "argument": 3,
        "register": "r8",
        "followed": "the frame slot [rsp+0x40], given to that call as argument 2,",
        "fall_through": False,
    }
    assert then["callee"]["import"] == "KERNEL32.dll!CreateMutexW"


def _inside_with(body: list[bytes], tmp_path: Path) -> dict:
    image, code, slots = _image()
    site = _caller(code)
    _consumer(image, body, slots["InternetOpenW"])
    loaded = _load(image, tmp_path)
    answer = call_sites.passed_to(loaded, _site(loaded, site))
    assert answer is not None
    return answer["output_passed_to"]["inside"]


def test_the_argument_left_alone_inside_is_unchanged(tmp_path: Path) -> None:
    assert _inside_with(_SPILL_AND_RELOAD, tmp_path)["contents_unchanged"] is True


@pytest.mark.parametrize(
    "change",
    [
        b"\xc6\x41\x03\x00",  # mov byte [rcx+3], 0 (through the parameter)
        b"\x48\x8b\xf9\xab",  # mov rdi, rcx; stosd
        b"\x66\xc7\x44\x44\x30\x00\x00",  # mov word [rsp+rax*2+0x30], 0 (the home slot?)
    ],
    ids=["through-the-parameter", "string-store", "unread-frame-store"],
)
def test_a_write_inside_is_flagged_and_the_call_still_stated(change: bytes, tmp_path: Path) -> None:
    body = [
        b"\x48\x89\x4c\x24\x08",  # mov [rsp+8], rcx
        b"\x48\x83\xec\x28",  # sub rsp, 0x28
        change,
        b"\x48\x8b\x4c\x24\x30",  # mov rcx, [rsp+0x30]
        b"",  # call [rip+InternetOpenW]
        b"\xc3",  # ret
    ]

    inside = _inside_with(body, tmp_path)

    assert inside["callee"]["import"] == "WININET.dll!InternetOpenW"
    assert inside["contents_unchanged"] is False


def test_an_api_call_states_its_constant_stack_arguments(tmp_path: Path) -> None:
    then = _then(
        [
            b"\xc7\x44\x24\x28\x80\x00\x00\x00",  # mov dword [rsp+0x28], 0x80 (argument 6)
            b"\xc7\x44\x24\x20\x02\x00\x00\x00",  # mov dword [rsp+0x20], 2 (argument 5)
        ],
        tmp_path,
        "CreateFileW",
    )

    assert then is not None
    assert then["callee"]["import"] == "KERNEL32.dll!CreateFileW"
    assert then["constants"] == {"5": "0x2", "6": "0x80"}


def test_a_stack_argument_a_register_overwrites_is_no_constant(tmp_path: Path) -> None:
    then = _then(
        [
            b"\xc7\x44\x24\x20\x02\x00\x00\x00",  # mov dword [rsp+0x20], 2
            b"\x89\x5c\x24\x20",  # mov [rsp+0x20], ebx
        ],
        tmp_path,
        "CreateFileW",
    )

    assert then is not None
    assert "constants" not in then


@pytest.mark.parametrize(
    "write",
    [
        b"\x66\xc7\x44\x44\x20\x00\x00",  # mov word [rsp+rax*2+0x20], 0
        b"\x48\x8d\x44\x24\x20\xc6\x00\x03",  # lea rax, [rsp+0x20]; mov byte [rax], 3
        b"\x48\x8b\xfc\xab",  # mov rdi, rsp; stosd
    ],
    ids=["index-store", "through-a-stack-address", "string-store"],
)
def test_a_stack_write_it_cannot_place_states_no_constant(write: bytes, tmp_path: Path) -> None:
    then = _then(
        [b"\xc7\x44\x24\x20\x02\x00\x00\x00", write],  # mov dword [rsp+0x20], 2; write
        tmp_path,
        "CreateFileW",
    )

    assert then is not None
    assert "constants" not in then

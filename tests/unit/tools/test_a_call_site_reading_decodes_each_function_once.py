"""Reading which call a string's address is passed to decodes each function once.

``call_sites.passed_to`` runs for every reference to every decoded string.
It used to decode the whole function from its start for each reference (to
know the load is an instruction), again for each call it followed (to find
the straight run before it), and copied the section's bytes each time: 0.46 s
per reference in a function of a megabyte. Each function is now decoded once
per image, the run before a call is a slice of that decode, an answer is kept
per call, and the section is a view of the file. The two replaced walks are
inlined below; the kept ones must answer as they did. The work is counted
(instructions decoded), never timed. Every image here is laid out by the test.
"""

from __future__ import annotations

import random
import struct

import pytest

from maljan.tools import call_sites
from maljan.tools.call_sites import Instruction, decode
from maljan.tools.pe_image import Image, Section

TEXT_RVA = 0x1000
TEXT_RAW = 0x400

# -- the replaced walks, as they were -----------------------------------------------


def _old_begins_an_instruction(
    code: bytes, section_rva: int, function_start: int, rva: int, is64: bool
) -> bool:
    at = function_start - section_rva
    target = rva - section_rva
    if at < 0 or target < at:
        return False
    while at < target:
        instruction = decode(code, at, is64)
        if instruction is None:
            return False
        at += instruction.length
    return at == target


def _old_straight_run_before(
    code: bytes, section_rva: int, bounds: tuple[int, int], call_rva: int
) -> list[tuple[int, Instruction]] | None:
    at = bounds[0] - section_rva
    end = bounds[1] - section_rva
    decoded: list[tuple[int, Instruction]] = []
    targets: set[int] = set()
    while at < end:
        instruction = decode(code, at, True)
        if instruction is None:
            return None
        rva = section_rva + at
        decoded.append((rva, instruction))
        kind, value = instruction.target
        if kind in ("jump", "branch"):
            targets.add(rva + instruction.length + value)
        at += instruction.length
    run: list[tuple[int, Instruction]] = []
    for rva, instruction in decoded:
        if rva >= call_rva:
            break
        if instruction.kind in ("stop", "call") or rva in targets:
            run = []
            if instruction.kind in ("stop", "call"):
                continue
        run.append((rva, instruction))
    return run if any(rva == call_rva for rva, _ in decoded) else None


# -- images ---------------------------------------------------------------------------


def _code(rng: random.Random, size: int, target: int) -> tuple[bytearray, list[int]]:
    """Code of loads, frame-slot arguments, calls, moves, jumps and filler; the load sites."""
    code = bytearray()
    sites: list[int] = []
    while len(code) < size - 32:
        at = len(code)
        pick = rng.randrange(8)
        if pick == 0:
            register = rng.choice([1, 2, 8, 9])
            rex = 0x48 | (4 if register >= 8 else 0)
            disp = target - (TEXT_RVA + at + 7)
            code += bytes([rex, 0x8D, 0x05 | ((register & 7) << 3)]) + struct.pack("<i", disp)
            sites.append(TEXT_RAW + at + 3)
        elif pick == 1:
            code += b"\x48\x8d\x54\x24" + bytes([rng.choice([0x20, 0x28])])
        elif pick == 2:
            code += b"\xe8" + struct.pack("<i", rng.randrange(-at, size - at) - 5)
        elif pick == 3:
            code += b"\x48\x89\xc1"
        elif pick == 4:
            code += bytes([rng.choice([0xEB, 0x74])]) + bytes([rng.randrange(0, 40)])
        elif pick == 5 and rng.random() < 0.05:
            code += b"\xc3"
        else:
            code += bytes([rng.choice([0x90, 0x50, 0x51, 0x5A])])
    return code + b"\x90" * (size - len(code)), sites


def _image(code: bytes, functions: list[tuple[int, int]]) -> Image:
    data_rva = TEXT_RVA + ((len(code) + 0xFFF) // 0x1000) * 0x1000
    data = bytes(TEXT_RAW) + bytes(code) + bytes(data_rva - TEXT_RVA - len(code)) + bytes(0x100)
    return Image(
        data=data,
        image_base=0x140000000,
        is64=True,
        size_of_image=data_rva + 0x1000,
        sections=[
            Section(".text", TEXT_RVA, len(code), TEXT_RAW, len(code), 0x60000020),
            Section(".data", data_rva, 0x100, TEXT_RAW + data_rva - TEXT_RVA, 0x100, 0x40000040),
        ],
        function_starts=[begin for begin, _ in functions],
        function_ends=[end for _, end in functions],
        function_owners=[begin for begin, _ in functions],
    )


# -- the same answers -----------------------------------------------------------------


@pytest.mark.parametrize("seed", range(8))
def test_the_kept_walks_answer_as_the_walks_they_replaced(seed: int) -> None:
    rng = random.Random(seed)
    code, _ = _code(rng, rng.choice([200, 2000, 6000]), TEXT_RVA + 0x8000)
    size = len(code)
    cut = sorted(rng.sample(range(1, size), 3))
    functions = [(TEXT_RVA, TEXT_RVA + cut[0]), (TEXT_RVA + cut[1], TEXT_RVA + size)]
    image = _image(bytes(code), functions)
    section = image.sections[0]
    view = image.section_view(section)
    places = [TEXT_RVA + rng.randrange(-8, size + 8) for _ in range(400)]
    for bounds in functions:
        decoded = call_sites._Decoded(view, section.rva, bounds)
        for rva in places:
            assert decoded.run_before(view, section.rva, rva) == _old_straight_run_before(
                bytes(code), section.rva, bounds, rva
            )
            assert call_sites._begins(image, section, bounds[0], rva) == (
                _old_begins_an_instruction(bytes(code), section.rva, bounds[0], rva, True)
            )


@pytest.mark.parametrize("seed", range(6))
def test_an_answer_read_twice_is_the_same_and_is_the_callers_own(seed: int) -> None:
    rng = random.Random(seed)
    code, sites = _code(rng, 4000, TEXT_RVA + 0x8000)
    functions = [(TEXT_RVA, TEXT_RVA + len(code))]
    fresh = [call_sites.passed_to(_image(bytes(code), functions), site) for site in sites]
    image = _image(bytes(code), functions)
    kept = [call_sites.passed_to(image, site) for site in reversed(sites)][::-1]
    assert kept == fresh
    for answer in kept:
        if answer is not None:
            answer["address_of"] = "blob"
            answer.get("output_passed_to", {})["changed"] = True
    assert [call_sites.passed_to(image, site) for site in sites] == fresh


# -- each function once -----------------------------------------------------------------


def _decodes(loads: int, monkeypatch: pytest.MonkeyPatch) -> int:
    """Instructions decoded reading ``loads`` references spread over one large function."""
    size = 20_000
    code = bytearray(b"\x90" * size)
    sites = []
    target = TEXT_RVA + 0x8000
    for index in range(1, loads + 1):
        at = index * (size // (loads + 1))
        rva = TEXT_RVA + at
        code[at : at + 7] = b"\x48\x8d\x0d" + struct.pack("<i", target - (rva + 7))
        code[at + 7 : at + 12] = b"\x48\x8d\x54\x24\x20"
        code[at + 12 : at + 17] = b"\xe8" + struct.pack("<i", -(at + 17))
        code[at + 17 : at + 20] = b"\x48\x89\xc1"
        code[at + 20 : at + 25] = b"\xe8" + struct.pack("<i", -(at + 25))
        sites.append(TEXT_RAW + at + 3)
    image = _image(bytes(code), [(TEXT_RVA, TEXT_RVA + size)])
    count = [0]
    real = call_sites.decode

    def counted(*args: object) -> Instruction | None:
        count[0] += 1
        return real(*args)  # type: ignore[arg-type]

    monkeypatch.setattr(call_sites, "decode", counted)
    answers = [call_sites.passed_to(image, site) for site in sites]
    assert all(answer is not None and "output_passed_to" in answer for answer in answers)
    return count[0]


def test_more_references_in_one_function_cost_their_own_walks_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    few = _decodes(4, monkeypatch)
    many = _decodes(64, monkeypatch)
    # The function is decoded whole a bounded number of times whatever the
    # references: the start walk to the furthest load, the decode for the
    # runs, and the walks from each call to the next one that receives its
    # output, which end where the next reference's code begins. Decoding it
    # per reference, as before, cost about 2.5 times its length each.
    assert few < 6 * 20_000
    assert many < 6 * 20_000

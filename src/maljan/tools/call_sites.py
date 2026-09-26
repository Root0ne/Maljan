"""Which call an address loaded as an argument is passed to, read statically from the code.

``decode_string_blobs`` states the places in the code that refer to a decoded
string. This module reads what happens next at such a place, without running
anything: when the reference is the operand of an instruction that loads the
string's address as a call argument, and the next instruction that transfers
control within the same function is a call, the answer is that call's target
and the argument position the address fills.

What counts, and nothing else:

* **The load.** On x64, ``lea`` of a RIP-relative address into ``rcx``,
  ``rdx``, ``r8`` or ``r9``: the first four arguments of the Windows x64
  calling convention, in that order. On x86, ``push`` of the absolute address
  (its argument position is one more than the pushes between it and the call,
  the last push before a call being the first argument), or ``mov`` of the
  address into ``[esp]`` or ``[esp+disp8]`` (argument ``disp8 / 4 + 1``).
  The load is read only inside a function the file states (its function
  table, or function starts handed in from elsewhere for an image without
  one), and only when decoding that function from its start, instruction
  after instruction, lands exactly on it: the same bytes inside another
  instruction are not a load.
* **The walk.** Instruction by instruction from the load, each decoded for its
  length and for the registers it may write. It stops, and nothing is stated,
  at an instruction it cannot decode, at any transfer of control that is not a
  call (a jump, a return, an interrupt), at the end of the function the file's
  own function table puts around the load, or — for a register argument — at
  any instruction that may write that register; for a pushed argument, at any
  instruction that moves the stack pointer other than a push. The first call
  it reaches is the one the argument goes to.
* **The callee.** A direct call names the function at its target, or the
  import a jump thunk there goes through (``jmp [slot]``). A call through a
  memory slot names the import the file's import table puts in that slot, or
  the slot's address when the table has none there (a pointer the program
  fills at runtime). A call through a register, or through any other operand,
  has no callee this reading can state, and nothing is stated.

A pointer loaded into another register and moved into an argument register
later, an argument passed on the x64 stack, or a load in one basic block and
a call in another, are not read: the answer is absent rather than guessed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from maljan.tools.pe_image import Image

# The Windows x64 argument registers, by register number: rcx, rdx, r8, r9.
_X64_ARGUMENTS = {1: 1, 2: 2, 8: 3, 9: 4}
_X64_REGISTER_NAMES = {1: "rcx", 2: "rdx", 8: "r8", 9: "r9"}
_LEGACY_PREFIXES = frozenset({0xF0, 0xF2, 0xF3, 0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65, 0x66, 0x67})
# The stack pointer's register number.
_SP = 4
# Registers an instruction writes that the decoder cannot name: any of them.
_ANY = frozenset(range(16))


@dataclass(frozen=True)
class Instruction:
    """One decoded instruction: its length and what the walk needs to know of it."""

    length: int
    kind: str  # "call", "stop" (another transfer of control), "push", or "other"
    writes: frozenset[int] = field(default_factory=frozenset)
    # For a call: ("rel", target offset from the instruction's end), ("mem", slot
    # displacement) with ``rip_relative`` said, or ("none", 0) for any other operand.
    target: tuple[str, int] = ("none", 0)
    rip_relative: bool = False
    moves_stack: bool = False


def _modrm_length(code: bytes, at: int, is64: bool, address16: bool) -> int | None:
    """The bytes a ModRM operand takes from ``at`` (the ModRM byte itself included)."""
    if at >= len(code) or address16:
        return None
    modrm = code[at]
    mod, rm = modrm >> 6, modrm & 7
    length = 1
    if mod == 3:
        return length
    if rm == 4:
        if at + 1 >= len(code):
            return None
        sib = code[at + 1]
        length += 1
        if mod == 0 and sib & 7 == 5:
            length += 4
    if mod == 1:
        length += 1
    elif mod == 2:
        length += 4
    elif mod == 0 and rm == 5:
        length += 4
    return length


# One-byte opcodes with a ModRM operand.
_ONE_BYTE_MODRM = (
    {op for base in range(0, 0x40, 8) for op in (base, base + 1, base + 2, base + 3)}
    | {0x62, 0x63, 0x69, 0x6B}
    | set(range(0x80, 0x90))
    | {0xC0, 0xC1, 0xC4, 0xC5, 0xC6, 0xC7, 0xD0, 0xD1, 0xD2, 0xD3}
    | set(range(0xD8, 0xE0))
    | {0xF6, 0xF7, 0xFE, 0xFF}
)
# One-byte opcodes that take an 8-bit immediate (beside any ModRM operand).
_ONE_BYTE_IMM8 = (
    {base + 4 for base in range(0, 0x40, 8)}
    | {0x6A, 0x6B, 0x80, 0x82, 0x83, 0xA8, 0xC0, 0xC1, 0xC6, 0xCD, 0xD4, 0xD5}
    | set(range(0xB0, 0xB8))
    | {0xE4, 0xE5, 0xE6, 0xE7}
)
# One-byte opcodes that take a word-or-doubleword immediate.
_ONE_BYTE_IMMZ = {base + 5 for base in range(0, 0x40, 8)} | {0x68, 0x69, 0x81, 0xA9, 0xC7}
# Two-byte (0F) opcodes with no ModRM operand.
_TWO_BYTE_PLAIN = (
    {0x05, 0x06, 0x07, 0x08, 0x09, 0x0B, 0x0E, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x37}
    | {0x77, 0xA0, 0xA1, 0xA2, 0xA8, 0xA9, 0xAA}
    | set(range(0xC8, 0xD0))
)
_TWO_BYTE_IMM8 = {0x70, 0x71, 0x72, 0x73, 0xA4, 0xAC, 0xBA, 0xC2, 0xC4, 0xC5, 0xC6}
# Two-byte opcodes that may write no general register: stores, compares, tests.
_TWO_BYTE_NO_GPR_WRITE = {0x11, 0x13, 0x17, 0x29, 0x2B, 0x2E, 0x2F, 0xA3, 0xE7, 0xD6}


def decode(code: bytes, at: int, is64: bool) -> Instruction | None:
    """The instruction at ``at``, or ``None`` when it is not one this reading decodes."""
    start = at
    operand16 = address16 = rep = False
    rex = 0
    while at < len(code) and code[at] in _LEGACY_PREFIXES:
        operand16 |= code[at] == 0x66
        address16 |= code[at] == 0x67 and not is64
        rep |= code[at] in (0xF2, 0xF3)
        at += 1
        if at - start > 14:
            return None
    if is64 and at < len(code) and 0x40 <= code[at] <= 0x4F:
        rex = code[at]
        at += 1
    if at >= len(code):
        return None
    op = code[at]
    at += 1
    rex_w, rex_r, rex_b = bool(rex & 8), (rex >> 2) & 1, rex & 1
    immz = 2 if operand16 else 4

    if op == 0x0F:
        return _decode_two_byte(code, start, at, is64, rex, address16, operand16)
    if op in (0xC4, 0xC5) and (is64 or (at < len(code) and code[at] >> 6 == 3)):
        return _decode_vex(code, start, at, is64, op)
    if op == 0x62 and is64:
        return None  # EVEX: not decoded here.
    if not is64 and op in (0x9A, 0xEA):
        return None  # far pointers
    if op in (0xE8, 0xE9):
        if at + 4 > len(code):
            return None
        rel = int.from_bytes(code[at : at + 4], "little", signed=True)
        length = at + 4 - start
        if op == 0xE8:
            return Instruction(length, "call", _ANY, ("rel", rel))
        return Instruction(length, "stop")
    if op == 0xEB or 0x70 <= op <= 0x7F or 0xE0 <= op <= 0xE3:
        return Instruction(at + 1 - start, "stop")
    if op in (0xC2, 0xCA):
        return Instruction(at + 2 - start, "stop")
    if op in (0xC3, 0xCB, 0xCC, 0xCE, 0xCF, 0xF1, 0xF4):
        return Instruction(at - start, "stop")
    if op == 0xCD:
        return Instruction(at + 1 - start, "stop")
    if op == 0xC8:
        return Instruction(at + 3 - start, "other", frozenset({_SP, 5}), moves_stack=True)
    if op == 0xC9:
        return Instruction(at - start, "other", frozenset({_SP, 5}), moves_stack=True)
    if op in (0xA0, 0xA1, 0xA2, 0xA3):
        width = 8 if is64 else 4
        return Instruction(
            at + width - start, "other", frozenset({0}) if op < 0xA2 else frozenset()
        )
    if 0xB8 <= op <= 0xBF:
        width = 8 if rex_w else immz
        return Instruction(at + width - start, "other", frozenset({(op & 7) | (rex_b << 3)}))
    if 0xB0 <= op <= 0xB7:
        return Instruction(at + 1 - start, "other", frozenset({(op & 7) | (rex_b << 3)}))
    if 0x50 <= op <= 0x57:
        return Instruction(at - start, "push", frozenset({_SP}), moves_stack=True)
    if 0x58 <= op <= 0x5F:
        written = frozenset({(op & 7) | (rex_b << 3), _SP})
        return Instruction(at - start, "other", written, moves_stack=True)
    if op in (0x68, 0x6A):
        width = immz if op == 0x68 else 1
        return Instruction(at + width - start, "push", frozenset({_SP}), moves_stack=True)
    if op in (0x9C,):
        return Instruction(at - start, "push", frozenset({_SP}), moves_stack=True)
    if op in (0x9D, 0x60, 0x61):
        return Instruction(at - start, "other", _ANY, moves_stack=True)
    if 0x90 <= op <= 0x97:
        register = (op & 7) | (rex_b << 3)
        written = frozenset() if register == 0 else frozenset({0, register})
        return Instruction(at - start, "other", written)
    if op in (0x98, 0x99):
        return Instruction(at - start, "other", frozenset({0} if op == 0x98 else {2}))
    if 0xA4 <= op <= 0xAF:
        imm = 1 if op == 0xA8 else immz if op == 0xA9 else 0
        written = frozenset({0}) if op in (0xA8, 0xA9) else frozenset({0, 1, 6, 7})
        return Instruction(at + imm - start, "other", written if not rep else written | {1})
    if op in (0x9B, 0x9E, 0x9F, 0xF5, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xD7, 0x6C, 0x6D):
        return Instruction(at - start, "other", frozenset({0, 7}))
    if op in (0x6E, 0x6F, 0xEC, 0xED, 0xEE, 0xEF):
        return Instruction(at - start, "other", frozenset({0, 6}))
    if op in (0x37, 0x3F, 0x27, 0x2F) and not is64:
        return Instruction(at - start, "other", frozenset({0}))
    if (op in (0x06, 0x0E, 0x16, 0x1E) or op in (0x07, 0x17, 0x1F)) and not is64:
        return Instruction(at - start, "other", frozenset({_SP}), moves_stack=True)
    if 0x40 <= op <= 0x4F and not is64:
        return Instruction(at - start, "other", frozenset({op & 7}))
    if op in _ONE_BYTE_IMM8 and op not in _ONE_BYTE_MODRM:
        written = frozenset({0}) if op < 0x40 or op in (0xE4, 0xE5, 0xD4, 0xD5) else frozenset()
        return Instruction(at + 1 - start, "other", written)
    if op in _ONE_BYTE_IMMZ and op not in _ONE_BYTE_MODRM:
        written = frozenset({0}) if op < 0x40 else frozenset()
        return Instruction(at + immz - start, "other", written)
    if op not in _ONE_BYTE_MODRM:
        return None
    modrm_length = _modrm_length(code, at, is64, address16)
    if modrm_length is None:
        return None
    modrm = code[at]
    mod, reg_field, rm_field = modrm >> 6, (modrm >> 3) & 7, modrm & 7
    reg = reg_field | (rex_r << 3)
    rm = rm_field | (rex_b << 3)
    end = at + modrm_length
    rip_relative = mod == 0 and rm_field == 5
    displacement = (
        int.from_bytes(code[at + 1 : at + 5], "little", signed=is64) if rip_relative else 0
    )
    if op in (0x80, 0x82, 0x83, 0xC0, 0xC1, 0xC6, 0x6B):
        end += 1
    elif op in (0x81, 0xC7, 0x69):
        end += immz
    elif op == 0xF6 and reg_field in (0, 1):
        end += 1
    elif op == 0xF7 and reg_field in (0, 1):
        end += immz
    if end > len(code):
        return None
    length = end - start
    rm_register = frozenset({rm}) if mod == 3 else frozenset()

    if op == 0xFF:
        if reg_field == 2:
            if rip_relative:
                return Instruction(length, "call", _ANY, ("mem", displacement), rip_relative=is64)
            return Instruction(length, "call", _ANY, ("none", 0))
        if reg_field in (3, 4, 5):
            return Instruction(length, "stop")
        if reg_field == 6:
            return Instruction(length, "push", frozenset({_SP}), moves_stack=True)
        return Instruction(length, "other", rm_register)
    if op == 0x8F:
        return Instruction(length, "other", rm_register | {_SP}, moves_stack=True)
    if op in (0xF6, 0xF7):
        if reg_field in (0, 1):
            return Instruction(length, "other")
        if reg_field in (2, 3):
            return Instruction(length, "other", rm_register)
        return Instruction(length, "other", frozenset({0, 2}))
    if op in (0x80, 0x81, 0x82, 0x83):
        written = frozenset() if reg_field == 7 else rm_register
        return Instruction(length, "other", written, moves_stack=_SP in written)
    if op < 0x40:
        if op & 0x38 == 0x38:
            return Instruction(length, "other")
        written = frozenset({reg}) if op & 2 else rm_register
        return Instruction(length, "other", written, moves_stack=_SP in written)
    if op in (0x84, 0x85):
        return Instruction(length, "other")
    if op in (0x88, 0x89, 0x8C, 0xC6, 0xC7, 0xC0, 0xC1, 0xD0, 0xD1, 0xD2, 0xD3, 0xFE):
        return Instruction(length, "other", rm_register, moves_stack=_SP in rm_register)
    if op in (0x8A, 0x8B, 0x8D, 0x63, 0x69, 0x6B):
        return Instruction(length, "other", frozenset({reg}), moves_stack=reg == _SP)
    if op in (0x86, 0x87):
        written = frozenset({reg}) | rm_register
        return Instruction(length, "other", written, moves_stack=_SP in written)
    # Floating point and anything else with an operand: every register it names.
    written = frozenset({reg}) | rm_register
    return Instruction(length, "other", written, moves_stack=_SP in written)


def _decode_two_byte(
    code: bytes,
    start: int,
    at: int,
    is64: bool,
    rex: int,
    address16: bool,
    operand16: bool,
) -> Instruction | None:
    if at >= len(code):
        return None
    op = code[at]
    at += 1
    rex_r, rex_b = (rex >> 2) & 1, rex & 1
    if 0x80 <= op <= 0x8F:
        return Instruction(at + (2 if operand16 else 4) - start, "stop")
    if op in (0x05, 0x34, 0x07, 0x35, 0x0B):
        return Instruction(at - start, "stop")
    if op == 0x0F:
        return None  # 3DNow!
    if op in _TWO_BYTE_PLAIN:
        written: frozenset[int]
        if 0xC8 <= op <= 0xCF:
            written = frozenset({(op & 7) | (rex_b << 3)})
        elif op in (0xA0, 0xA8):
            return Instruction(at - start, "push", frozenset({_SP}), moves_stack=True)
        elif op in (0xA1, 0xA9):
            return Instruction(at - start, "other", frozenset({_SP}), moves_stack=True)
        else:
            written = frozenset({0, 1, 2, 3})
        return Instruction(at - start, "other", written)
    imm = 1 if op in _TWO_BYTE_IMM8 else 0
    if op in (0x38, 0x3A):
        if at >= len(code):
            return None
        imm = 1 if op == 0x3A else 0
        at += 1
    modrm_length = _modrm_length(code, at, is64, address16)
    if modrm_length is None:
        return None
    modrm = code[at]
    mod = modrm >> 6
    reg = ((modrm >> 3) & 7) | (rex_r << 3)
    rm = (modrm & 7) | (rex_b << 3)
    end = at + modrm_length + imm
    if end > len(code):
        return None
    if op in _TWO_BYTE_NO_GPR_WRITE:
        return Instruction(end - start, "other")
    written = frozenset({reg}) | (frozenset({rm}) if mod == 3 else frozenset())
    return Instruction(end - start, "other", written, moves_stack=_SP in written)


def _decode_vex(code: bytes, start: int, at: int, is64: bool, op: int) -> Instruction | None:
    """A VEX-encoded instruction: every register its operands name may be written."""
    prefix_bytes = 1 if op == 0xC5 else 2
    if at + prefix_bytes >= len(code):
        return None
    first = code[at]
    table = 1 if op == 0xC5 else first & 0x1F
    extend_r = 0 if first & 0x80 else 1
    extend_b = 0 if op == 0xC5 or first & 0x20 else 1
    at += prefix_bytes
    opcode = code[at]
    at += 1
    if table == 1 and opcode == 0x77:
        return Instruction(at - start, "other")
    if table not in (1, 2, 3):
        return None
    modrm_length = _modrm_length(code, at, is64, False)
    if modrm_length is None:
        return None
    modrm = code[at]
    end = at + modrm_length + (1 if table == 3 else 0)
    if end > len(code):
        return None
    reg = ((modrm >> 3) & 7) | (extend_r << 3)
    rm = (modrm & 7) | (extend_b << 3)
    written = frozenset({reg}) | (frozenset({rm}) if modrm >> 6 == 3 else frozenset())
    return Instruction(end - start, "other", written)


def _load_at(image: Image, site: int) -> tuple[int, int, str | int] | None:
    """``(instruction offset, instruction length, argument)`` for the load at a reference.

    ``site`` is the file offset of the bytes that refer to the string. The
    argument is the register number of an x64 argument register, or, on x86,
    ``"push"`` for a pushed address and an argument position for a store to
    the stack.
    """
    data = image.data
    if image.is64:
        start = site - 3
        if start < 0:
            return None
        rex, opcode, modrm = data[start], data[start + 1], data[start + 2]
        if rex & 0xF8 != 0x48 or opcode != 0x8D or modrm & 0xC7 != 0x05:
            return None
        register = ((modrm >> 3) & 7) | (((rex >> 2) & 1) << 3)
        if register not in _X64_ARGUMENTS:
            return None
        return start, 7, register
    if site >= 1 and data[site - 1] == 0x68:
        return site - 1, 5, "push"
    if site >= 3 and data[site - 3 : site] == b"\xc7\x04\x24":
        return site - 3, 7, 1
    if site >= 4 and data[site - 4 : site - 1] == b"\xc7\x44\x24":
        displacement = data[site - 1]
        if displacement % 4 == 0 and displacement < 0x80:
            return site - 4, 8, displacement // 4 + 1
    return None


def _thunk_slot(image: Image, target_rva: int) -> int | None:
    """The slot a jump thunk at ``target_rva`` goes through (``jmp [slot]``), or ``None``."""
    offset = image.offset_of_rva(target_rva)
    if offset is None or offset + 6 > len(image.data):
        return None
    if image.data[offset : offset + 2] != b"\xff\x25":
        return None
    displacement = int.from_bytes(image.data[offset + 2 : offset + 6], "little", signed=image.is64)
    if image.is64:
        return target_rva + 6 + displacement
    return displacement - image.image_base


def _callee(image: Image, call_rva: int, instruction: Instruction) -> dict[str, str] | None:
    """What the call at ``call_rva`` calls, as the file states it, or ``None``."""
    kind, value = instruction.target
    after = call_rva + instruction.length
    imports = image.imports_by_slot()
    if kind == "rel":
        target = after + value
        slot = _thunk_slot(image, target)
        if slot is not None and slot in imports:
            return {"import": imports[slot], "function": hex(target)}
        return {"function": hex(target)}
    if kind == "mem":
        slot = after + value if instruction.rip_relative else value - image.image_base
        if slot in imports:
            return {"import": imports[slot], "slot": hex(slot)}
        return {"slot": hex(slot)}
    return None


def passed_to_words(joined: Any) -> str:
    """``argument 4 of the call at 0x1210 to KERNEL32.dll!CreateMutexW``, or ``""``.

    The one wording of a ``passed_to`` answer, for every place that prints one.
    """
    if not isinstance(joined, dict):
        return ""
    stated = joined.get("callee")
    callee: dict[str, Any] = stated if isinstance(stated, dict) else {}
    named = (
        str(callee.get("import") or "")
        or (f"the function at {callee['function']}" if callee.get("function") else "")
        or (f"the pointer stored at {callee['slot']}" if callee.get("slot") else "")
    )
    if not named or not joined.get("argument") or not joined.get("call_at"):
        return ""
    return f"argument {joined['argument']} of the call at {joined['call_at']} to {named}"


def _begins_an_instruction(
    code: bytes, section_rva: int, function_start: int, rva: int, is64: bool
) -> bool:
    """Whether decoding from the function's start lands on ``rva`` as an instruction's start.

    The bytes of a load can also be the middle of another instruction; the
    load is read as one only when a decode of the function from its start,
    instruction after instruction, arrives at it exactly. A byte the decode
    cannot read on the way leaves the question unanswered, and no load is read.
    """
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


def passed_to(image: Image, site: int) -> dict[str, Any] | None:
    """The call a string's address is passed to from the reference at file offset ``site``.

    ``{"call_at", "argument", "callee"}`` (with ``"register"`` for an x64
    register argument), or ``None`` whenever any part of it is not what the
    module docstring says is read.
    """
    load = _load_at(image, site)
    if load is None:
        return None
    start, length, argument = load
    section = image.section_at_offset(start)
    if section is None or not section.executable:
        return None
    load_rva = image.rva_of_offset(start)
    if load_rva is None:
        return None
    bounds = image.function_bounds(load_rva)
    if bounds is None:
        return None
    code = image.section_bytes(section)
    if not _begins_an_instruction(code, section.rva, bounds[0], load_rva, image.is64):
        return None
    at = start - section.raw_offset + length
    pushes = 0
    while at < len(code):
        rva = section.rva + at
        if not bounds[0] <= rva < bounds[1]:
            return None
        instruction = decode(code, at, image.is64)
        if instruction is None:
            return None
        if instruction.kind == "call":
            callee = _callee(image, rva, instruction)
            if callee is None:
                return None
            answer: dict[str, Any] = {"call_at": hex(rva), "callee": callee}
            if isinstance(argument, int) and image.is64:
                answer["argument"] = _X64_ARGUMENTS[argument]
                answer["register"] = _X64_REGISTER_NAMES[argument]
            elif argument == "push":
                answer["argument"] = pushes + 1
            else:
                answer["argument"] = argument
            return answer
        if instruction.kind == "stop":
            return None
        if isinstance(argument, int) and image.is64:
            if argument in instruction.writes:
                return None
        elif instruction.kind == "push" and argument == "push":
            pushes += 1
        elif instruction.moves_stack or instruction.kind == "push":
            return None
        at += instruction.length
    return None

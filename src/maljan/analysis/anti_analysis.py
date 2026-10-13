"""The triage pack's anti-analysis pass, as any static provider's scan answers it.

A static provider that can scan a program for anti-analysis code offers the
pass through ``StaticProvider.anti_analysis_scan`` (``providers.base``): an
object that says why there is no scan (``unavailable``), or scans the job's
sample once and answers in the shape this module reads. The pack records that
answer under its own step name (``SCAN_TOOL``) and states only its exact part.

What is here is the part no scanner owns:

* the answer's row vocabulary: a stated row is ``{category, what, offset}``,
  with ``function`` and ``owner`` where known, and a TEB/PEB read is a row of
  ``TEB_CATEGORY``;
* the readings of the file's own bytes a scanner's matches are checked
  against: an ``INT3`` that is a trap and not padding (``int3_is_a_trap``), a
  ``CPUID`` that asks the hypervisor question (``cpuid_leaf_said``), and the
  x64 GS reads of the TEB and PEB, which a scan looking for FS does not see
  (``gs_reads``);
* which rule of a capability-rule tool (a tool of declared kind
  ``capability_rules``) agrees with a stated row, by the rule's namespace and
  name (``rule_agrees``).
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Sequence
from typing import Any, Protocol

from maljan.core.logger import logger

# The renderer of the pack's step for the pass (``core.pack_steps``).
SCAN_RENDERER = "anti_analysis_scan"


def _scan_tool() -> str:
    """The tool the pack's shipped step of :data:`SCAN_RENDERER` calls: the one name.

    The name the pass's entries are recorded under, and that its declaration
    (``builtin_declarations._PACK_TOOLS``) names, read from the shipped step
    list rather than written down a second time.
    """
    from maljan.core.pack_steps import shipped_tools_of

    (tool,) = shipped_tools_of(SCAN_RENDERER)
    return tool


# The pack's step name for the pass, the name its entries are recorded under.
SCAN_TOOL = _scan_tool()
# The kind its entries are declared under.
SCAN_KIND = "anti_analysis_scan"

# The kind of tool whose rules a stated row is compared with.
RULE_KIND = "capability_rules"


class PassFailed(RuntimeError):
    """A pass that was made and did not complete, with what happened.

    A scanner's own failure class derives from this one, and its name ends in
    ``PassFailed``: the pack's line drops the class name the failure was
    recorded with and keeps the scanner's words.
    """


# The class name a failure was recorded with (``<Name>PassFailed: words``).
PASS_FAILED_PREFIX = re.compile(r"\A[A-Za-z_][A-Za-z0-9_]*PassFailed: ")


class AntiAnalysisScan(Protocol):
    """One job's anti-analysis scan, as a static provider hands it to the pack.

    ``provider`` is the id of the provider that scans, ``formats`` the routed
    formats its scan reads, ``sample_path`` the copy of the sample it reads.
    ``unavailable`` is the sentence the pack records when nothing can be
    scanned; nothing is called then. ``anti_analysis`` makes the scan and
    answers in this module's shape (``read_findings``-style ``stated``,
    ``beside_capa`` and ``not_stated``), raising a :class:`PassFailed` when it
    did not complete.
    """

    provider: str
    formats: frozenset[str]
    sample_path: str
    unavailable: str

    def anti_analysis(
        self, host_path: str = "", function_starts: Sequence[Any] = ()
    ) -> dict[str, Any]: ...

    def close(self) -> None: ...


def run_pass(call: Callable[[], dict[str, Any]], what: str) -> dict[str, Any]:
    """``call()``, logging a failure before it is handed on."""
    try:
        return call()
    except PassFailed as failure:
        logger.warning("Pass %s did not complete: %s", what, type(failure).__name__)
        raise


INSTRUCTION_CATEGORY = "suspicious_instruction"
TEB_CATEGORY = "peb_teb_access"
# x64's TEB is reached through GS: the PEB pointer at GS:[0x60], the TEB's
# self pointer at GS:[0x30]. A scan that looks for FS only misses these, so
# they are read from an x64 file's code bytes (``gs_reads``), in the two forms
# a compiler writes: ``mov r64, gs:[disp32]`` (GS prefix, REX.W with or without
# REX.R, 8B, a ModRM of mod 00 and rm 100 with any register, SIB 25, the
# address) and ``mov rax, gs:[moffs64]`` (GS prefix, REX.W, A1, the address in
# eight bytes).
_AMD64_MACHINE = 0x8664
_GS_READ = re.compile(
    rb"\x65[\x48\x4c]\x8b[\x04\x0c\x14\x1c\x24\x2c\x34\x3c]\x25([\x30\x60])\x00\x00\x00"
    rb"|\x65\x48\xa1([\x30\x60])\x00{7}",
)

# What each stated row is, for matching it to a rule (``scan_kind``): the
# instruction's mnemonic, ``INT`` by its operand, and a TEB/PEB read by the
# structure it reads (a PEB read through FS:[0x30] on x86 and GS:[0x60] on
# x64, the TEB's self pointer through FS:[0x18] and GS:[0x30]).
_PEB_OPERAND = re.compile(r"\b(?:FS:\[0x30\]|GS:\[0x60\])", re.IGNORECASE)
_TEB_SELF_OPERAND = re.compile(r"\b(?:FS:\[0x18\]|GS:\[0x30\])", re.IGNORECASE)

# Which stated rows a rule agrees with, by what the rule itself says it is:
# its namespace, and for a rule outside the anti-analysis namespaces its name.
# Read off capa's rule set, whose namespaces a capability-rule tool shares:
#
# * ``anti-analysis/anti-debugging/debugger-detection`` is where capa files
#   ``execute anti-debugging instructions`` (two RDTSC, or ICEBP), ``check for
#   software breakpoints`` (an INT3 compared for) and the PEB flag reads
#   (``check for PEB BeingDebugged flag``, ``check for PEB NtGlobalFlag
#   flag``, each a ``match: PEB access``): a debugger question.
# * ``anti-analysis/anti-vm/vm-detection`` is the virtual machine question
#   the scan's other instructions ask: a CPUID at the hypervisor leaf, and
#   SIDT, SGDT, SLDT and STR, which read where a hypervisor moved the
#   descriptor tables and the task register.
# * The other anti-analysis namespaces capa uses (anti-av, debugger evasion,
#   anti-disasm, anti-emulation, anti-forensic, anti-llm, obfuscation,
#   packer) state something none of the scan's rows is: a stack string is not
#   an SIDT.
# * ``PEB access`` is a ``lib/`` rule with no namespace (an FS:[0x30] or
#   GS:[0x60] read, or WoW64's FS access less 0x2000), and ``access PEB
#   ldr_data`` (``linking/runtime-linking``) is a ``match: PEB access``: both
#   say the function reads the PEB.
#
# A rule in ``anti-analysis`` with no sub-namespace, or in one this table does
# not name, states no kind and agrees with every row in its function, as every
# anti-analysis rule did before; a row whose kind the table does not name
# agrees with every anti-analysis rule. A namespace is matched with its own
# sub-namespaces (``anti-analysis/packer`` holds ``anti-analysis/packer/upx``).
_DEBUGGER_KINDS = ("rdtsc", "int3", "int 0x2d", "peb", "teb")
_VM_KINDS = ("cpuid", "sidt", "sgdt", "sldt", "str")
RULE_NAMESPACE_KINDS: dict[str, tuple[str, ...]] = {
    "anti-analysis/anti-debugging/debugger-detection": _DEBUGGER_KINDS,
    "anti-analysis/anti-vm/vm-detection": _VM_KINDS,
    "anti-analysis/anti-av": (),
    "anti-analysis/anti-debugging/debugger-evasion": (),
    "anti-analysis/anti-disasm": (),
    "anti-analysis/anti-emulation": (),
    "anti-analysis/anti-forensic": (),
    "anti-analysis/anti-llm": (),
    "anti-analysis/obfuscation": (),
    "anti-analysis/packer": (),
}
RULE_NAME_KINDS: dict[str, tuple[str, ...]] = {
    "PEB access": ("peb", "teb"),
    "access PEB ldr_data": ("peb", "teb"),
}
# Every kind a stated row can have.
SCAN_KINDS = frozenset(_DEBUGGER_KINDS + _VM_KINDS)


def operand_value(text: str) -> int | None:
    """An instruction operand's number, read the way an assembler writes it, or ``None``."""
    try:
        return int(text, 0)
    except ValueError:
        return None


def scan_kind(row: dict[str, Any]) -> str | None:
    """What a stated row reads or runs, as ``RULE_NAMESPACE_KINDS`` names it, or ``None``."""
    what = str(row.get("what") or "").strip()
    if str(row.get("category") or "") == TEB_CATEGORY:
        if _PEB_OPERAND.search(what):
            return "peb"
        return "teb" if _TEB_SELF_OPERAND.search(what) else None
    words = what.upper().split(None, 1)
    if not words:
        return None
    if words[0] in ("INT3", "INT"):
        operand = operand_value(words[1].split(None, 1)[0]) if len(words) > 1 else None
        if words[0] == "INT3" or operand == 3:
            return "int3"
        return "int 0x2d" if operand == 0x2D else None
    kind = words[0].lower()
    return kind if kind in SCAN_KINDS else None


def rule_kinds(rule: str, namespace: str) -> frozenset[str] | None:
    """The kinds of stated row a rule states, or ``None`` for a rule that states none."""
    named = RULE_NAME_KINDS.get(str(rule))
    if named is not None:
        return frozenset(named)
    space = str(namespace or "")
    for prefix, kinds in RULE_NAMESPACE_KINDS.items():
        if space == prefix or space.startswith(prefix + "/"):
            return frozenset(kinds)
    return None


def may_agree(rule: str, namespace: str) -> bool:
    """Whether a rule could agree with some stated row: an anti-analysis rule, or one named."""
    return str(namespace or "").startswith("anti-analysis") or str(rule) in RULE_NAME_KINDS


def rule_agrees(rule: str, namespace: str, row_kind: str | None) -> bool:
    """Whether a rule in a row's function agrees with the row, of ``row_kind`` (``scan_kind``).

    A rule outside the anti-analysis namespaces agrees only where
    ``RULE_NAME_KINDS`` names it and its kind; an anti-analysis rule that
    states no kind agrees with every row, and one that states kinds with the
    rows of those kinds and with a row of no kind.
    """
    anti = str(namespace or "").startswith("anti-analysis")
    if not anti and str(rule) not in RULE_NAME_KINDS:
        return False
    kinds = rule_kinds(rule, namespace)
    if kinds is None:
        return True
    if row_kind is None:
        return anti
    return row_kind in kinds


# The CPUID leaves a hypervisor answers, and the bytes around a CPUID read.
_HYPERVISOR_LEAVES = range(0x40000000, 0x40000100)
_CLEAR_ECX = (b"\x31\xc9", b"\x33\xc9")
# bt ecx, 31; test ecx, 0x80000000; and ecx, 0x80000000; test ecx, ecx then js.
_ECX_BIT_31 = (
    b"\x0f\xba\xe1\x1f",
    b"\xf7\xc1\x00\x00\x00\x80",
    b"\x81\xe1\x00\x00\x00\x80",
    b"\x85\xc9\x78",
    b"\x85\xc9\x0f\x88",
)
# How far past a CPUID the test of ECX's bit 31 is looked for.
_BIT_TEST_WINDOW = 32
# The first bytes of an instruction that writes ECX: mov ecx, imm32; mov or
# xor or sub ecx with a register; pop rcx. A test after one reads another value.
_WRITES_ECX = (
    b"\xb9",
    b"\x89\xc1",
    b"\x89\xd1",
    b"\x89\xd9",
    b"\x89\xf1",
    b"\x89\xf9",
    b"\x31\xc9",
    b"\x33\xc9",
    b"\x29\xc9",
    b"\x2b\xc9",
    b"\x8b\xc8",
    b"\x8b\xca",
    b"\x8b\xcb",
    b"\x8b\xce",
    b"\x8b\xcf",
    b"\x59",
)


class Code:
    """The file's bytes around an instruction a scanner named, when the file is a PE image."""

    def __init__(self, image: Any, function_starts: Iterable[int]) -> None:
        self.image = image
        starts = set(function_starts)
        if image is not None:
            starts.update(int(start) for start in image.function_starts)
        self.starts = starts

    def at(self, offset: str) -> int | None:
        """The file offset of an offset from the image base, or ``None``."""
        if self.image is None:
            return None
        try:
            found = self.image.offset_of_rva(int(offset, 16))
        except (TypeError, ValueError):
            return None
        return int(found) if found is not None else None

    def byte(self, at: int) -> int | None:
        data: bytes = self.image.data
        return data[at] if 0 <= at < len(data) else None


def _modrm_length(modrm: int, sib: int | None) -> int:
    """The length of an ``FF /r`` instruction from its ModRM (and SIB) byte, opcode included."""
    mod, rm = modrm >> 6, modrm & 7
    if mod == 3:
        return 2
    length = 2
    if rm == 4:
        length += 1
        if mod == 0 and sib is not None and sib & 7 == 5:
            length += 4
    elif mod == 0 and rm == 5:
        length += 4
    return length + {0: 0, 1: 1, 2: 4}[mod]


# The ``FF /r`` forms that transfer control: /2 is a near call, /4 a near jump.
_FF_TRANSFERS = frozenset({2, 4})


def _ends_a_transfer(data: bytes, at: int) -> bool:
    """Whether the bytes just before ``at`` are a whole near call, jump or return.

    The encodings: ``E8 rel32`` (call), ``E9 rel32`` and ``EB rel8`` (jump),
    ``C3`` and ``C2 imm16`` (return), and ``FF /2`` or ``FF /4`` in every
    ModRM form (through a register, ``FF D0`` and with a REX prefix
    ``41 FF D0``; through memory, ``FF 15 disp32`` and the rest), the length
    read from the ModRM. A byte sequence that only looks like one makes the
    check say yes, which leaves an ``INT3`` unstated rather than stated wrongly.
    """
    if at >= 5 and data[at - 5] in (0xE8, 0xE9):
        return True
    if at >= 2 and data[at - 2] == 0xEB:
        return True
    if at >= 1 and data[at - 1] == 0xC3:
        return True
    if at >= 3 and data[at - 3] == 0xC2:
        return True
    for length in range(2, 8):
        begin = at - length
        if begin < 0 or data[begin] != 0xFF:
            continue
        modrm = data[begin + 1]
        if (modrm >> 3) & 7 not in _FF_TRANSFERS:
            continue
        sib = data[begin + 2] if begin + 2 < at else None
        if _modrm_length(modrm, sib) == length:
            return True
    return False


def int3_is_a_trap(code: Code, offset: str) -> bool:
    """A one-byte ``INT3`` not in a run, not before a function, not right after a transfer.

    Compilers put one ``int 3`` after a call that never returns, and pad with
    one after a function's last return or jump, where nothing falls through.
    """
    at = code.at(offset)
    if at is None or code.byte(at) != 0xCC:
        return False
    if code.byte(at - 1) == 0xCC or code.byte(at + 1) == 0xCC:
        return False
    if _ends_a_transfer(code.image.data, at):
        return False
    return int(offset, 16) + 1 not in code.starts


# What a GS row says when the file's function table holds its address and no
# decode from a function start there lands on it: the bytes may be the middle
# of another instruction, or the table may be shaped to hide the read. The row
# is kept and says so.
GS_OFF_BOUNDARY = "not on an instruction boundary decoded from the function start"


def _instruction_starts(code: bytes, at: int, starts: bytearray, limit: int) -> None:
    """Mark the instruction starts a decode from ``at`` reaches, up to one already marked.

    The decode runs on to ``limit`` (just past the section's last GS match,
    after which no start is asked about) or the first byte it cannot read, so
    a start marked earlier has every start after it on its own path marked
    too, and stopping there loses nothing. Each byte is marked at most once, so
    every decode of a section together reads it once: overlapping or nested
    ranges decode no byte twice.
    """
    from maljan.tools.call_sites import decode

    while 0 <= at < limit and not starts[at]:
        starts[at] = 1
        instruction = decode(code, at, True)
        if instruction is None:
            return
        at += instruction.length


def gs_reads(image: Any) -> list[dict[str, Any]]:
    """The GS:[0x60] and GS:[0x30] reads in an AMD64 file's code bytes, as TEB/PEB rows.

    Each is a ``peb_teb_access`` row as a scanner's FS read is: its ``what`` the
    operand and the bytes read (``GS:[0x60] read (65 48 8b 04 25 60 00 00
    00)``) and its offset from the image base. Where the file's own function
    table (``.pdata``) holds the address, the row carries the function that
    range belongs to (``owner``), the function its agreement with a rule is
    asked about, and the range is decoded from its start
    (``_instruction_starts``, one bitmap of starts per section, each byte
    decoded once): a match no decode lands on is still a row, its ``what``
    ending in ``GS_OFF_BOUNDARY``. Outside every range the byte match is read
    and the row names no owner. The same file bytes mapped by two sections are
    one row. No row for a file whose machine field is not AMD64, or for no
    image.
    """
    if image is None or getattr(image, "machine", 0) != _AMD64_MACHINE:
        return []
    rows: list[dict[str, Any]] = []
    seen: set[int] = set()
    for section in image.code_sections():
        code = image.section_bytes(section)
        starts: bytearray | None = None
        limit = 0
        for match in _GS_READ.finditer(code):
            limit = match.start() + 1
        for match in _GS_READ.finditer(code):
            raw = section.raw_offset + match.start()
            if raw in seen:
                continue
            seen.add(raw)
            rva = section.rva + match.start()
            owner = image.function_at(rva)
            bounds = image.function_bounds(rva) if owner is not None else None
            on_a_boundary = True
            if bounds is not None:
                if starts is None:
                    starts = bytearray(len(code))
                _instruction_starts(code, bounds[0] - section.rva, starts, limit)
                on_a_boundary = bool(starts[match.start()])
            address = (match.group(1) or match.group(2))[0]
            said = match.group().hex(" ")
            what = f"GS:[{address:#x}] read ({said})"
            row = {
                "category": TEB_CATEGORY,
                "what": what if on_a_boundary else f"{what}, {GS_OFF_BOUNDARY}",
                "offset": hex(rva),
            }
            if owner is not None:
                row["owner"] = hex(owner)
            rows.append(row)
    return rows


def cpuid_leaf_said(code: Code, offset: str) -> str:
    """What the code around a CPUID shows it asks, when it shows the hypervisor question."""
    at = code.at(offset)
    if at is None:
        return ""
    data = code.image.data
    if data[at : at + 2] != b"\x0f\xa2":
        return ""
    before = at
    if data[before - 2 : before] in _CLEAR_ECX:
        before -= 2
    if before < 5 or data[before - 5] != 0xB8:
        return ""
    # A REX prefix makes ``B8`` a move into r8d, not eax.
    if before >= 6 and 0x40 <= data[before - 6] <= 0x4F:
        return ""
    leaf = int.from_bytes(data[before - 4 : before], "little")
    if leaf in _HYPERVISOR_LEAVES:
        return f"CPUID (leaf {leaf:#x})"
    if leaf == 1 and _tests_ecx_bit_31(data[at + 2 : at + 2 + _BIT_TEST_WINDOW]):
        return "CPUID (leaf 1, then ECX bit 31 tested)"
    return ""


def _tests_ecx_bit_31(after: bytes) -> bool:
    """Whether ``after`` tests ECX's bit 31 before anything listed writes ECX.

    The window is cut at the first place an ECX write's bytes begin, so a test
    that may read another value is not taken. The cut is by byte pattern, and
    errs toward stating nothing.
    """
    tests = [i for p in _ECX_BIT_31 if (i := after.find(p)) >= 0]
    if not tests:
        return False
    writes = [i for p in _WRITES_ECX if (i := after.find(p)) >= 0]
    return min(tests) < min(writes, default=len(after))


def image_of(path: str) -> Any:
    """The PE image at ``path`` as ``tools.pe_image`` maps it, or ``None``."""
    if not path:
        return None
    from maljan.tools import pe_image

    try:
        return pe_image.load(path)
    except (OSError, ValueError):
        return None


def starts_of(values: Sequence[Any]) -> list[int]:
    """Function starts written as hex offsets, as numbers; one that is not hex is left out."""
    starts: list[int] = []
    for value in values:
        try:
            starts.append(int(str(value), 16))
        except ValueError:
            continue
    return starts

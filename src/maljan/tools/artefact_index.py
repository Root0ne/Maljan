"""The function index: for every function of a PE the run knows, the artefacts it holds.

A reverser on a local model decompiles the functions it happens to pick. The
facts that say which functions hold the run's artefacts are already on the
ledger, spread over five answers: FLOSS's rows name the call site of each
decoded string, the hash resolution and the blob decoder name the function
around each place, capa names where each rule matched, and the file's own
tables list the functions. This module joins them per function, and adds what
the platform's x86 decoder (``tools.call_sites``) reads in each function: the
calls it makes, and the data it loads the address of.

What it states, and nothing else:

* **The functions.** The starts of the file's exception directory (x64, a
  chained fragment counted for the function it belongs to), its exports, its
  entry point, the function starts capa listed, and every direct call target
  the decoder reaches in an executable section. Ghidra's and radare2's lists
  are not read here: the pack runs before any analyst opens them, and the
  answer says so.
* **What a function calls.** Every function start is collected first (a walk
  that adds each direct call target it reaches), then each function is read
  from its start with all of them known. A function in the exception
  directory is decoded instruction after instruction across its stated range;
  any other is decoded from its start along every branch, up to a return, a
  jump it cannot follow, another function's start, or the end of its section.
  An unconditional jump to another function's start is that function's tail
  call: a callee, not more of the function the jump is in. A byte the decoder
  does not read ends that path, and the answer counts the functions where
  that happened, and lists them (``undecoded``). A call names the import its
  slot or its jump thunk goes through (``imports``), or the function at its
  target (``callees``); a call through a register, or through a slot the
  import table does not fill, names nothing, and the answer counts those per
  function (``calls_unnamed``).
* **The strings it refers to.** An instruction that takes an address in a
  data section (x64: RIP-relative; x86: an absolute address as a memory
  operand or an immediate) refers to the text there when the bytes from that
  address read as printable ASCII or UTF-16LE of at least six characters up to
  their terminator, and the address is where that text starts: a plain
  string. A reference into the middle of a text reads nothing, so texts are
  disjoint and all of them are read in one pass of the section. A decoded
  string is one the blob decoder states this function refers to, or one
  FLOSS decoded at a call site inside it (a stack or tight string: in the
  function FLOSS names).
* **The names its hashes resolve to** where the hash resolution states the
  place inside it, and **the capa rules** that matched at its start or at an
  address inside it.
* **The calls it makes through slots the hash resolution fills.** In the
  straight-line run of code holding a hashed value (up to a transfer of
  control), the slot that value's name is stored to: after a call exactly one
  function-name hash reaches as an argument, a store of its return register
  before the register is overwritten; or, in a table of records laid out by
  frame offsets, the one record address some code calls or jumps through
  (``_name_slots``). The tie is read from what the code places, not from what
  the call does: a hash left live in an argument register across an unrelated
  call ties that call, and a store of its return value names the slot after
  the hash; the run's stores alone cannot tell the two calls apart. A call or
  jump through a named slot, direct or through a register a straight-line
  load from it set, is a call of that name (``slot_calls``), and leaves the
  count of calls that name nothing. A slot two names fill is ambiguous
  (``ambiguous_slots``) and names nothing. A table names nothing when a store
  of a pointer's width or more (or of a width not read, or a pop into the
  frame) lies outside its records; a narrower store (a loop counter, a flag)
  is no record's, except where a record's called pointer would sit one stride
  outside the table, where a store of any width makes it name nothing. On x86
  a 32-bit counter is a pointer's width, so a counter stored beside an x86
  table makes it name nothing.
* **Callers and callees**, and the **indirect artefacts**: how many of its
  direct callees hold artefacts of their own, and how many those are, each
  callee's own distinct count added. One call deep and added per callee, so
  the count costs one step per call: a union of the callees' artefacts would
  cost a callee's artefacts once per caller, which a file with one function
  holding many artefacts and called from many places makes quadratic. An
  artefact two callees, or the function and a callee, both hold is counted
  for each, and the answer says so.

Every walk is bounded by the file: in each of the two walks each instruction
start is decoded at most once, whichever functions, ranges and branches lead
to it (an instruction start another function's decoding already read ends the
path, so code two functions share is read for the first in the second walk's
order); a section is found by bisection; every list is built from the answers'
own entries and the decoder's calls, and stored once per distinct value.
Nothing recurses.

A place is inside a function when an instruction the decoder read in that
function covers it, or else when the exception directory's range holds it; a
place no function holds is counted under ``unplaced`` by its source and given
to none. An artefact is counted once per function as a distinct value (an
import by its name, a string by its text, a rule by its name), and every entry
that states it is cited. A function with no artefact of its own is not a row.

The sample is only read; nothing in it is run.
"""

from __future__ import annotations

import heapq
import re
from bisect import bisect_left, bisect_right
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from maljan.tools import pe_image
from maljan.tools.call_sites import (
    _LEGACY_PREFIXES,
    _ONE_BYTE_MODRM,
    _TWO_BYTE_PLAIN,
    Instruction,
    _frame_ref,
    _frame_store,
    decode,
)
from maljan.tools.pe_image import Image, Section

__all__ = [
    "FUNCTION_LISTS_ABSENT",
    "SELF",
    "TOOL",
    "function_index",
    "index_image",
]

TOOL = "function_index"

# How a cell names this answer itself as its source: the entry's own id is not
# known until the entry is written, and the pack line puts it in.
SELF = "this entry"

# Said in every answer for the function lists the pack does not read.
FUNCTION_LISTS_ABSENT = (
    "Ghidra's and radare2's function lists: no: the pack runs before any analyst opens them"
)

# The shortest run of characters taken as a plain string, as the pack's strings head reads one.
TEXT_MIN_CHARS = 6

# The sources of the functions, in the order the answer names them.
_EXCEPTION_DIRECTORY = "exception directory"
_EXPORTS = "exports"
_ENTRY_POINT = "entry point"
_CAPA = "capa function starts"
_CALL_TARGETS = "call targets the decoder reached"

_HEX = re.compile(r"\s*0x([0-9a-fA-F]{1,16})\s*")


def _hex(value: Any) -> int | None:
    match = _HEX.fullmatch(str(value or ""))
    return int(match.group(1), 16) if match else None


def _short_import(name: str) -> str:
    """``KERNEL32.dll!CreateMutexW`` as ``CreateMutexW``; an ordinal keeps its library."""
    library, _, function = name.rpartition("!")
    if not library or function.startswith("#"):
        return name
    return function


@dataclass
class _Function:
    start: int
    sources: list[str] = field(default_factory=list)
    callees: set[int] = field(default_factory=set)
    imports: set[str] = field(default_factory=set)
    data_refs: set[int] = field(default_factory=set)
    undecoded: bool = False
    # Calls the decoder read whose target names neither an import nor a
    # function nor a slot the hash resolution fills: through a register no
    # straight-line load names, or through a slot nothing names.
    unnamed_calls: int = 0
    # Calls and jumps through a slot the import table does not fill, by slot:
    # directly, or through a register a load from the slot set in straight-line
    # code. Named after the walk where the hash resolution fills the slot.
    slot_calls: dict[int, int] = field(default_factory=dict)


@dataclass
class _Graph:
    functions: dict[int, _Function] = field(default_factory=dict)
    # For each place asked about, the functions whose decoded instructions cover it.
    covered: dict[int, set[int]] = field(default_factory=dict)
    # The section lookup the walk used, for the readers of the data sections.
    sections: Any = None
    # Each straight-line run of code that holds a hashed name, as its events
    # (``_SlotReading``), for the slots the resolution fills.
    runs: list[list[tuple[Any, ...]]] = field(default_factory=list)


# -- reading the code -------------------------------------------------------


class _Sections:
    """Which section holds an RVA, answered by bisection rather than by a scan of every section.

    The same answer ``pe_image.Image.section_at_rva`` gives (the first section
    in the header's order whose range, the larger of its virtual and raw size,
    holds the RVA), computed once: the ranges are cut into the intervals
    between their ends, each interval given the first section that covers it,
    with a sweep over the sorted ends. Building it costs the sections times
    their logarithm, and each lookup the logarithm of the intervals, so the
    walk costs calls plus sections, not their product.
    """

    def __init__(self, image: Image) -> None:
        self.image = image
        spans = [
            (s.rva, s.rva + max(s.virtual_size, s.raw_size), index)
            for index, s in enumerate(image.sections)
            if max(s.virtual_size, s.raw_size) > 0
        ]
        ends = sorted({point for lo, hi, _ in spans for point in (lo, hi)})
        by_start = sorted(spans)
        self.starts: list[int] = []
        self.owners: list[int | None] = []
        active: list[tuple[int, int]] = []  # (header index, end), a heap by index
        position = 0
        for point in ends:
            while position < len(by_start) and by_start[position][0] == point:
                lo, hi, index = by_start[position]
                heapq.heappush(active, (index, hi))
                position += 1
            while active and active[0][1] <= point:
                heapq.heappop(active)
            # A section whose end is passed but is not on top stays in the heap;
            # it is dropped when it reaches the top, before it can answer.
            self.starts.append(point)
            self.owners.append(active[0][0] if active else None)

    def at(self, rva: int) -> Section | None:
        position = bisect_right(self.starts, rva) - 1
        if position < 0:
            return None
        index = self.owners[position]
        if index is None:
            return None
        section = self.image.sections[index]
        if section.rva <= rva < section.rva + max(section.virtual_size, section.raw_size):
            return section
        return None

    def offset(self, rva: int) -> int | None:
        """``pe_image.Image.offset_of_rva``, through the same lookup."""
        section = self.at(rva)
        if section is None or rva - section.rva >= section.mapped_size:
            return None
        return section.raw_offset + (rva - section.rva)


def _data_address(image: Image, code: bytes, at: int, ins: Instruction, rva_end: int) -> int | None:
    """The RVA an instruction takes the address of, when it names one the bytes state.

    x64: a RIP-relative memory operand. x86: an absolute ``[disp32]`` memory
    operand, a ``push imm32``, a ``mov r32, imm32``, or the immediate of a
    ``mov r/m32, imm32`` (``C7``), whose value is a virtual address inside the
    image; a ``C7`` store's destination is a global written, not a text
    referred to, and an x64 ``C7`` immediate is sign-extended and names none.
    Anything else: ``None``.
    """
    end = at + ins.length
    i = at
    operand16 = False
    while i < end and code[i] in _LEGACY_PREFIXES:
        operand16 |= code[i] == 0x66
        i += 1
    rex = 0
    if image.is64 and i < end and 0x40 <= code[i] <= 0x4F:
        rex = code[i]
        i += 1
    if i >= end:
        return None
    op = code[i]
    i += 1
    if op == 0xC7:
        if image.is64 or operand16 or end - i < 5:
            return None
        return _virtual(image, int.from_bytes(code[end - 4 : end], "little"))
    modrm_at: int | None = None
    if op == 0x0F:
        if i >= end:
            return None
        second = code[i]
        i += 1
        if 0x80 <= second <= 0x8F or second in _TWO_BYTE_PLAIN:
            return None
        if second in (0x38, 0x3A):
            i += 1
        modrm_at = i
    elif op in _ONE_BYTE_MODRM and op not in (0xC4, 0xC5, 0x62):
        modrm_at = i
    elif not image.is64 and not operand16 and (op == 0x68 or 0xB8 <= op <= 0xBF):
        if end - i == 4:
            return _virtual(image, int.from_bytes(code[i:end], "little"))
        return None
    elif image.is64 and rex & 8 and 0xB8 <= op <= 0xBF and end - i == 8:
        return _virtual(image, int.from_bytes(code[i:end], "little"))
    else:
        return None
    if modrm_at >= end:
        return None
    modrm = code[modrm_at]
    mod, rm = modrm >> 6, modrm & 7
    if mod == 0 and rm == 5 and modrm_at + 5 <= end:
        displacement = int.from_bytes(
            code[modrm_at + 1 : modrm_at + 5], "little", signed=image.is64
        )
        if image.is64:
            return rva_end + displacement
        return _virtual(image, displacement)
    return None


def _virtual(image: Image, value: int) -> int | None:
    rva = value - image.image_base
    return rva if 0 <= rva < image.size_of_image else None


class _Reader:
    """The decoder's walks over every function.

    Two walks. The first finds every function start: the stated ones and every
    direct call target the decoding reaches, whichever order the functions are
    read in. The second, with every start known, reads each function from its
    start and attributes what it reads: a path ends at another function's
    start, and an unconditional jump to one is that function's tail call (a
    callee), not more of the function the jump is in. Each walk decodes each
    instruction start at most once (a shared mark per code byte), so code two
    functions share is read for the first of them in the second walk's order:
    the functions of the exception directory, then the others, each by
    address.
    """

    def __init__(
        self,
        image: Image,
        wanted: set[int],
        hashed: Mapping[int, tuple[str, ...]] | None = None,
    ) -> None:
        self.image = image
        self.sections = _Sections(image)
        self.imports = image.imports_by_slot()
        self.wanted = wanted
        # The places of the hash resolution's values, with the names each reads.
        self.hashed = dict(hashed or {})
        # The straight-line run being read: its events, whether it holds a
        # hashed value, and the registers a load from a slot set in it.
        self.events: list[tuple[Any, ...]] = []
        self.holds_hash = False
        self.loaded: dict[int, int] = {}
        # The hashed values live in registers, and (x86) pushed or stored as
        # stack arguments, since the run began or the last call consumed them:
        # each ``(names, place)``.
        self.live: dict[int, tuple[tuple[str, ...], int]] = {}
        self.stacked: list[tuple[tuple[str, ...], int]] = []
        # The registers that hold an address taken in the run, for a store of
        # one to a frame slot.
        self.addressed: dict[int, int] = {}
        # The bytes pushed (less those popped) since the run began: an
        # ``[rsp+x]`` store's offset is read against the stack pointer the run
        # began with.
        self.pushed = 0
        self.graph = _Graph()
        self.queue: list[int] = []
        self.sorted_starts: list[int] = []
        self.known: set[int] = set()
        self.ranges_of: dict[int, list[tuple[int, int]]] = {}
        self.code = {section.rva: image.section_bytes(section) for section in image.code_sections()}
        self.attributing = False
        self.read: dict[int, bytearray] = {}
        self.graph.sections = self.sections

    def add(self, start: int, source: str) -> None:
        function = self.graph.functions.get(start)
        if function is None:
            function = _Function(start)
            self.graph.functions[start] = function
            self.known.add(start)
            self.queue.append(start)
        if source not in function.sources:
            function.sources.append(source)

    def run(self) -> _Graph:
        # The first walk: every start, its call targets added as they are reached.
        self._walk()
        # The second walk: every start known before any function is read.
        self.attributing = True
        self.sorted_starts = sorted(self.known)
        stated = sorted(self.ranges_of)
        others = [start for start in self.sorted_starts if start not in self.ranges_of]
        self.queue = [*stated, *others]
        for function in self.graph.functions.values():
            function.callees.clear()
        self._walk()
        return self.graph

    def _walk(self) -> None:
        self.read = {rva: bytearray(len(code)) for rva, code in self.code.items()}
        if not self.attributing:
            self.sorted_starts = sorted(self.known)
        index = 0
        while index < len(self.queue):
            start = self.queue[index]
            index += 1
            function = self.graph.functions[start]
            ranges = self.ranges_of.get(start)
            if ranges:
                for begin, end in ranges:
                    self._sweep(function, begin, end)
            else:
                self._descend(function)

    def _section(self, rva: int) -> tuple[int, bytes] | None:
        section = self.sections.at(rva)
        if section is None or not section.executable or section.rva not in self.code:
            return None
        return section.rva, self.code[section.rva]

    def _callee(self, rva: int, ins: Instruction) -> tuple[str, Any] | None:
        """What a call names: ``("import", name)``, ``("function", rva)``, or ``None``.

        As ``call_sites`` reads a callee (a slot the import table fills, or a
        jump thunk through one; a direct target), with the sections looked up
        by bisection.
        """
        kind, value = ins.target
        after = rva + ins.length
        if kind == "rel":
            target = after + value
            slot = self._thunk_slot(target)
            if slot is not None and slot in self.imports:
                return "import", self.imports[slot]
            return "function", target
        if kind == "mem":
            slot = after + value if ins.rip_relative else value - self.image.image_base
            if slot in self.imports:
                return "import", self.imports[slot]
        return None

    def _thunk_slot(self, target: int) -> int | None:
        offset = self.sections.offset(target)
        data = self.image.data
        if offset is None or offset + 6 > len(data) or data[offset : offset + 2] != b"\xff\x25":
            return None
        displacement = int.from_bytes(
            data[offset + 2 : offset + 6], "little", signed=self.image.is64
        )
        return (
            target + 6 + displacement if self.image.is64 else displacement - self.image.image_base
        )

    def _note(self, function: _Function, rva: int, ins: Instruction, code: bytes, at: int) -> None:
        """What one decoded instruction says: its call, and in the second walk the rest."""
        if ins.kind == "call":
            callee = self._callee(rva, ins)
            if callee is not None and callee[0] == "function":
                target = int(callee[1])
                if self._section(target) is not None:
                    if self.attributing:
                        function.callees.add(target)
                    else:
                        self.add(target, _CALL_TARGETS)
            elif callee is not None and self.attributing:
                function.imports.add(str(callee[1]))
            if self.attributing and callee is None:
                slot = self._through(code, at, rva, ins)
                if slot is not None:
                    function.slot_calls[slot] = function.slot_calls.get(slot, 0) + 1
                else:
                    function.unnamed_calls += 1
            elif self.attributing and callee is not None and callee[0] == "function":
                if self._section(int(callee[1])) is None:
                    function.unnamed_calls += 1
        if not self.attributing:
            return
        if ins.kind == "stop" and _indirect_jump(code, at, self.image.is64):
            slot = self._through(code, at, rva, ins, jump=True)
            if slot is not None:
                function.slot_calls[slot] = function.slot_calls.get(slot, 0) + 1
            elif self._slot_of(code, at, rva, ins) not in self.imports or not _through_slot(
                code, at, self.image.is64, jump=True
            ):
                # Every indirect jump that goes through no named slot and no
                # import's slot is a call that names nothing: through a
                # register, a base and displacement, or an index.
                function.unnamed_calls += 1
        hashed: list[tuple[tuple[str, ...], int]] = []
        if self.wanted:
            for place in range(rva, rva + ins.length):
                if place in self.wanted:
                    self.graph.covered.setdefault(place, set()).add(function.start)
                    names = self.hashed.get(place)
                    if names is not None:
                        self.events.append(("hash", names, place))
                        self.holds_hash = True
                        hashed.append((names, place))
        self._read_events(code, at, rva, ins, hashed)
        if ins.kind != "call":
            data_target = _data_address(self.image, code, at, ins, rva + ins.length)
            if data_target is not None:
                function.data_refs.add(data_target)
        if ins.kind == "stop":
            self._end_run()

    def _slot_of(self, code: bytes, at: int, rva: int, ins: Instruction) -> int | None:
        """The slot an instruction's memory operand names, by offset, or ``None``."""
        found = _memory_operand(code, at, self.image.is64)
        if found is None:
            return None
        displacement = found
        if self.image.is64:
            return rva + ins.length + displacement
        slot = (displacement & 0xFFFFFFFF) - self.image.image_base
        return slot if slot >= 0 else None

    def _through(
        self, code: bytes, at: int, rva: int, ins: Instruction, *, jump: bool = False
    ) -> int | None:
        """The slot a call or jump goes through when the import table does not fill it:
        its memory operand, or the register a straight-line load from a slot set."""
        through = _through_slot(code, at, self.image.is64, jump=jump)
        if through is None:
            return None
        kind, value = through
        if kind == "register":
            return self.loaded.get(value)
        slot = self._slot_of(code, at, rva, ins)
        if slot is None or slot in self.imports:
            return None
        return slot

    def _read_events(
        self,
        code: bytes,
        at: int,
        rva: int,
        ins: Instruction,
        hashed: Sequence[tuple[tuple[str, ...], int]] = (),
    ) -> None:
        """What one instruction adds to the straight-line run.

        A call, tied to the one function-name hash live in an argument (x64:
        ``rcx``, ``rdx``, ``r8``, ``r9``; x86: a pushed or ``[esp+x]`` stack
        argument) when exactly one is, and to nothing otherwise; an address
        taken, unless the instruction holds a hashed value; a store or an
        overwrite of the return register; the slot a register is loaded from;
        and where each hashed value is live.
        """
        is64 = self.image.is64
        if ins.kind == "call":
            arguments = (
                [self.live[r] for r in _ARGUMENT_REGISTERS if r in self.live] if is64 else []
            )
            if not is64:
                arguments = list(self.stacked)
            named = [held for held in arguments if held[0]]
            tied = named[0] if len(named) == 1 else None
            self.events.append(("call", tied))
            if not is64:
                # An x86 callee may pop its own arguments: the stack pointer
                # after the call is not one the run can read.
                self.events.append(("frame moved", 4))
            self.loaded.clear()
            self.live.clear()
            self.stacked.clear()
            # A call may overwrite every volatile register: an address one held
            # is no longer known to be there.
            self.addressed.clear()
            return
        shape = _slot_shape(code, at, is64, ins.length)
        slot = None
        if shape is not None:
            absolute = shape[2]
            slot = (
                absolute - self.image.image_base
                if absolute is not None
                else self._slot_of(code, at, rva, ins)
            )
        moved = _register_copy(code, at, is64)
        carried = self.live.get(moved[1]) if moved is not None else None
        frame = self._frame_events(code, at, rva, ins, hashed)
        for register in ins.writes:
            self.loaded.pop(register, None)
            self.live.pop(register, None)
            self.addressed.pop(register, None)
        if carried is not None and moved is not None:
            self.live[moved[0]] = carried
        for held in hashed:
            if ins.kind == "push" or (not is64 and _stack_store(code, at)):
                self.stacked.append(held)
            elif len(ins.writes) == 1:
                self.live[next(iter(ins.writes))] = held
        if shape is not None and slot is not None and 0 <= slot < self.image.size_of_image:
            kind, named_register = shape[0], shape[1]
            if kind == "store" and named_register == 0:
                self.events.append(("store", slot, rva))
            elif kind == "load" and named_register is not None:
                self.loaded[named_register] = slot
            elif kind == "address" and named_register is not None and not hashed:
                if self._section(slot) is None:
                    self.addressed[named_register] = slot
        self.events.extend(frame)
        self._move_frame(code, at, ins)
        if 0 in ins.writes:
            self.events.append(("overwrite",))

    def _move_frame(self, code: bytes, at: int, ins: Instruction) -> None:
        """Follow what one instruction does to the frame's base registers.

        A push or a pop of a whole word moves the stack pointer by that word,
        and later ``[rsp+x]`` offsets are read against the pointer the run began
        with. Any other write of the stack pointer, and any write of the frame
        pointer, moves the frame by an amount the run cannot read: it is marked
        (``frame moved``), and a table whose stores it falls between names
        nothing.
        """
        word = 8 if self.image.is64 else 4
        found = _operand_bytes(code, at, self.image.is64)
        if ins.kind == "push":
            if found is None:
                self.events.append(("frame moved", 4))
            else:
                self.pushed += word
        elif found is not None and 0x58 <= found[0] <= 0x5F:
            self.pushed -= word
            if (found[0] & 7) | ((found[1] & 1) << 3) == 5:
                self.events.append(("frame moved", 5))
        else:
            for base in (4, 5):
                if base in ins.writes or (base == 4 and ins.moves_stack):
                    self.events.append(("frame moved", base))

    def _frame_events(
        self,
        code: bytes,
        at: int,
        rva: int,
        ins: Instruction,
        hashed: Sequence[tuple[tuple[str, ...], int]],
    ) -> list[tuple[Any, ...]]:
        """A store to a frame slot (``[rsp+x]``, ``[rbp+x]``, x86 ``esp``/``ebp``): its
        offset, and the hashed value or the address it stores there (an ``[rsp+x]``
        offset read against the stack pointer the run began with).

        Read with ``call_sites._frame_ref`` and ``call_sites._frame_store``; a
        store that carries no frame offset (a push, an absolute slot) is none.
        """
        is64 = self.image.is64
        if not is64 and at < len(code) and 0x40 <= code[at] <= 0x4F:
            return []
        stored = _frame_store(code, at)
        found = _operand_bytes(code, at, is64)
        if found is not None and found[0] == 0x8F:
            # A pop into the frame writes a whole word there, whatever width
            # ``_frame_store`` reads for it, at an address read after the pop
            # has moved the stack pointer.
            popped = _frame_ref(code, at)
            if popped is None or popped[2] & 7:
                return []
            word = 8 if is64 else 4
            base, displacement = popped[3], popped[4]
            moved = self.pushed - word if base == 4 else 0
            return [("frame store", base, displacement - moved)]
        if stored is None:
            return []
        # A store of a pointer's width or more, or of a width not read (or a
        # record's own hash or address), is where a table's records may lie:
        # one outside them means they are not a table. A narrower store (a
        # loop counter, a flag) is no record's.
        word = 8 if is64 else 4
        store = ("frame store", stored[0], stored[1] - (self.pushed if stored[0] == 4 else 0))
        wide = stored[2] is None or stored[2] >= word
        # A narrower store is still read where it lies: at a record's pointer's
        # place one stride outside the table, it says the table's phase is
        # not what its hashed values say (``_name_slots``).
        out: list[tuple[Any, ...]] = [store] if wide else [("frame narrow", *store[1:])]
        reference = _frame_ref(code, at)
        if reference is None:
            return out
        _rex, op, register, base, displacement = reference
        if base == 4:
            displacement -= self.pushed
        if op == 0x89:
            if register in self.live:
                names, place = self.live[register]
                out.append(("frame hash", base, displacement, names, place))
            elif register in self.addressed:
                out.append(("frame address", base, displacement, self.addressed[register], rva))
        elif op == 0xC7:
            if hashed:
                for names, place in hashed:
                    out.append(("frame hash", base, displacement, names, place))
            elif not is64 and ins.length >= 4:
                value = int.from_bytes(code[at + ins.length - 4 : at + ins.length], "little")
                slot = value - self.image.image_base
                if 0 <= slot < self.image.size_of_image and self._section(slot) is None:
                    out.append(("frame address", base, displacement, slot, rva))
        if not wide and any(event[0] in ("frame hash", "frame address") for event in out):
            # A record's own hash or address counts whatever its width.
            out = [store, *out[1:]]
        return out

    def _end_run(self) -> None:
        """End the straight-line run: kept when it holds a hashed value."""
        if self.holds_hash:
            self.graph.runs.append(self.events)
        self.events = []
        self.holds_hash = False
        self.loaded.clear()
        self.live.clear()
        self.stacked.clear()
        self.addressed.clear()
        self.pushed = 0

    def _tail_call(self, function: _Function, target: int) -> bool:
        """An unconditional jump to another function's start, recorded as its callee."""
        if not self.attributing or target == function.start or target not in self.known:
            return False
        function.callees.add(target)
        return True

    def _sweep(self, function: _Function, begin: int, end: int) -> None:
        """Decode a stated range instruction after instruction, to its end or an unread byte."""
        found = self._section(begin)
        if found is None:
            return
        base, code = found
        read = self.read[base]
        at = begin - base
        self._end_run()
        while base + at < end and at < len(code):
            if read[at]:
                self._end_run()
                return
            read[at] = 1
            ins = decode(code, at, self.image.is64)
            if ins is None:
                function.undecoded |= self.attributing
                self._end_run()
                return
            self._note(function, base + at, ins, code, at)
            if ins.kind == "stop" and ins.target[0] == "jump":
                target = base + at + ins.length + ins.target[1]
                if not begin <= target < end:
                    self._tail_call(function, target)
            at += ins.length
        self._end_run()

    def _descend(self, function: _Function) -> None:
        """Decode from the start along every branch, within the function's own bound."""
        found = self._section(function.start)
        if found is None:
            return
        base, code = found
        later = bisect_right(self.sorted_starts, function.start)
        bound = min(
            self.sorted_starts[later] if later < len(self.sorted_starts) else base + len(code),
            base + len(code),
        )
        read = self.read[base]
        pending = [function.start]
        while pending:
            rva = pending.pop()
            self._end_run()
            while base <= rva < base + len(code) and not read[rva - base]:
                if rva != function.start and rva in self.known:
                    break
                if not function.start <= rva < bound:
                    break
                at = rva - base
                read[at] = 1
                ins = decode(code, at, self.image.is64)
                if ins is None:
                    function.undecoded |= self.attributing
                    break
                self._note(function, rva, ins, code, at)
                after = rva + ins.length
                if ins.kind == "stop":
                    kind, value = ins.target
                    if kind == "branch":
                        pending.append(after + value)
                    elif kind == "jump":
                        if self._tail_call(function, after + value):
                            break
                        rva = after + value
                        continue
                    break
                rva = after
        self._end_run()


# -- the slots a hash resolution fills ----------------------------------------


def _operand_bytes(code: bytes, at: int, is64: bool) -> tuple[int, int, int] | None:
    """``(opcode, rex, index after the opcode)`` with legacy prefixes and REX read off; ``None``
    for an operand-size or address-size prefix, which no pointer store or load carries."""
    i = at
    while i < len(code) and code[i] in _LEGACY_PREFIXES:
        if code[i] in (0x66, 0x67):
            return None
        i += 1
    rex = 0
    if is64 and i < len(code) and 0x40 <= code[i] <= 0x4F:
        rex = code[i]
        i += 1
    if i >= len(code):
        return None
    return code[i], rex, i + 1


# The registers the first four integer arguments travel in (x64): rcx, rdx, r8, r9.
_ARGUMENT_REGISTERS = (1, 2, 8, 9)


def _register_copy(code: bytes, at: int, is64: bool) -> tuple[int, int] | None:
    """``(destination, source)`` of a register-to-register ``mov`` of 32 or 64 bits.

    ``call_sites._register_move`` reads the 64-bit form only; a hashed value is
    a 32-bit one and is moved as one (``mov edx, r12d``).
    """
    found = _operand_bytes(code, at, is64)
    if found is None:
        return None
    op, rex, after = found
    if op not in (0x89, 0x8B) or after >= len(code) or code[after] >> 6 != 3:
        return None
    modrm = code[after]
    reg = ((modrm >> 3) & 7) | (((rex >> 2) & 1) << 3)
    rm = (modrm & 7) | ((rex & 1) << 3)
    return (rm, reg) if op == 0x89 else (reg, rm)


def _stack_store(code: bytes, at: int) -> bool:
    """Whether an x86 instruction stores an immediate to ``[esp+x]``."""
    found = _operand_bytes(code, at, False)
    if found is None:
        return False
    op, _rex, after = found
    if op != 0xC7 or after + 1 >= len(code):
        return False
    modrm = code[after]
    return modrm >> 6 in (0, 1, 2) and modrm & 7 == 4 and code[after + 1] & 7 == 4


def _indirect_jump(code: bytes, at: int, is64: bool) -> bool:
    """Whether the instruction at ``at`` is an indirect jump, through any operand."""
    found = _operand_bytes(code, at, is64)
    if found is None:
        return False
    op, _rex, after = found
    return op == 0xFF and after < len(code) and (code[after] >> 3) & 7 in (4, 5)


def _memory_operand(code: bytes, at: int, is64: bool) -> int | None:
    """The 32-bit displacement of a ModRM operand that is rip-relative (x64) or an absolute
    address (x86): mod 00, r/m 101."""
    found = _operand_bytes(code, at, is64)
    if found is None:
        return None
    _op, _rex, after = found
    if after + 5 > len(code):
        return None
    modrm = code[after]
    if modrm >> 6 != 0 or modrm & 7 != 5:
        return None
    return int.from_bytes(code[after + 1 : after + 5], "little", signed=is64)


def _through_slot(
    code: bytes, at: int, is64: bool, *, jump: bool = False
) -> tuple[str, int] | None:
    """What an indirect call (or, with ``jump``, an indirect jump) goes through: ``("memory",
    0)`` for a slot at a rip-relative or absolute address, ``("register", r)``; else ``None``."""
    found = _operand_bytes(code, at, is64)
    if found is None:
        return None
    op, rex, after = found
    if op != 0xFF or after >= len(code):
        return None
    modrm = code[after]
    if (modrm >> 3) & 7 != (4 if jump else 2):
        return None
    if modrm >> 6 == 3:
        return ("register", (modrm & 7) | ((rex & 1) << 3))
    if modrm >> 6 == 0 and modrm & 7 == 5:
        return ("memory", 0)
    return None


def _slot_shape(
    code: bytes, at: int, is64: bool, length: int
) -> tuple[str, int | None, int | None] | None:
    """``(kind, register, absolute address)`` of an instruction that stores a register to a
    slot, loads one from a slot, or takes an address: ``store``, ``load`` or ``address``.

    The slot is a rip-relative or absolute memory operand, or the absolute
    address an x86 immediate or ``moffs`` carries (then given). Anything else
    is ``None``.
    """
    found = _operand_bytes(code, at, is64)
    if found is None:
        return None
    op, rex, after = found
    if op in (0xA1, 0xA3):
        width = 8 if is64 else 4
        if after + width > len(code):
            return None
        value = int.from_bytes(code[after : after + width], "little")
        return ("load" if op == 0xA1 else "store", 0, value)
    if not is64 and (op == 0x68 or 0xB8 <= op <= 0xBF):
        if after + 4 > len(code):
            return None
        target = (op & 7) if op != 0x68 else None
        return ("address", target, int.from_bytes(code[after : after + 4], "little"))
    if after >= len(code):
        return None
    modrm = code[after]
    reg = ((modrm >> 3) & 7) | (((rex >> 2) & 1) << 3)
    memory = modrm >> 6 == 0 and modrm & 7 == 5
    if op == 0x89 and memory:
        return ("store", reg, None)
    if op == 0x8B and memory:
        return ("load", reg, None)
    if op == 0x8D and memory:
        return ("address", reg, None)
    return None


def _name_slots(
    runs: Sequence[Sequence[tuple[Any, ...]]], called: set[int]
) -> tuple[dict[int, tuple[str, int]], dict[int, list[str]]]:
    """The slots the hash resolution fills, ``{slot: (name, where it is named)}``, and the
    ones two names fill, ``{slot: names}``.

    Read in each straight-line run that holds a hashed value, two ways:

    * **The call and its store.** A call is tied to a hashed value only when
      exactly one function-name hash is live in an argument at it, placed
      there in the same run (``_Reader._read_events``). After a tied call, a
      store of the return register to a slot, before the register is
      overwritten or another call is made, names that slot.
    * **A table of records.** With no tied call stored in the run, the records
      are read from frame offsets alone (``_frame_records``): each record's
      extent is the table's stride, the equal spacing between consecutive
      hashed values stored to the frame, and the addresses stored to the frame
      fall in the record their offset lies in, whatever order the stores were
      emitted in. A record names the one address in it some code calls or
      jumps through; one with none names nothing and lends nothing. A record
      holding two such addresses, records naming addresses at different
      offsets within them, fewer than two hashed values, spacings that
      differ, a store of a pointer's width (or a hashed value or an address)
      outside every record, records of different layouts,
      or a frame moved between the stores by an amount the run cannot read,
      mean the offsets do not lay out a table, and it names nothing. Stores
      with no frame offset (pushes, absolute slots) make no records.

    A hashed value whose readings give two names, and a slot two names fill,
    are ambiguous and name nothing.
    """
    filled: dict[int, dict[str, tuple[str, int]]] = {}
    ambiguous: dict[int, set[str]] = {}

    def fill(slot: int, names: Sequence[str], where: int) -> None:
        distinct = {name.lower(): name for name in names}
        if len(distinct) == 1:
            ((key, name),) = distinct.items()
            filled.setdefault(slot, {}).setdefault(key, (name, where))
        elif distinct:
            ambiguous.setdefault(slot, set()).update(distinct.values())

    for run in runs:
        stored = False
        for k, event in enumerate(run):
            if event[0] != "call" or event[1] is None:
                continue
            names = event[1][0]
            j = k + 1
            while j < len(run):
                later = run[j]
                if later[0] == "store":
                    fill(int(later[1]), names, int(later[2]))
                    stored = True
                    break
                if later[0] in ("overwrite", "call"):
                    break
                j += 1
        if stored or any(e[0] == "call" and e[1] is not None for e in run):
            continue
        for records, phases in _frame_records(run).values():
            # A record names the one address in it some code calls through. One
            # with none names nothing (a name resolved and never called) and
            # lends nothing: its bounds are the table's stride. One with two, or
            # records whose called addresses sit at different offsets within
            # them, mean the records are not what the offsets say, and the table
            # names nothing.
            chosen = [
                {(slot, where, within) for slot, where, within in inside if slot in called}
                for _names, inside in records
            ]
            if any(len({slot for slot, _w, _i in found}) > 1 for found in chosen):
                continue
            places = {within for found in chosen for _s, _w, within in found}
            if len(places) > 1:
                continue
            # A store of any width where a record's called pointer would sit one
            # stride before the first record or after the last: the records may
            # begin at the pointer, not at the hash, and the table names nothing.
            if places & phases:
                continue
            for (names, _inside), found in zip(records, chosen, strict=True):
                if found:
                    slot, where, _within = min(found)
                    fill(slot, names, where)
    named: dict[int, tuple[str, int]] = {}
    for slot, by_name in filled.items():
        if len(by_name) == 1 and slot not in ambiguous:
            named[slot] = next(iter(by_name.values()))
        else:
            ambiguous.setdefault(slot, set()).update(n for n, _w in by_name.values())
    return named, {slot: sorted(names) for slot, names in ambiguous.items()}


def _frame_records(
    run: Sequence[tuple[Any, ...]],
) -> dict[int, tuple[list[tuple[tuple[str, ...], list[tuple[int, int, int]]]], frozenset[int]]]:
    """Per frame base, each record of a run's table: its hashed value's names and the
    addresses stored inside it, ``(slot, where, offset within the record)``; and the
    offsets within a record, modulo the stride, at which a store narrower than a
    pointer lies outside every record.

    Read from frame offsets alone, in whatever order the stores were emitted.
    A record's extent is the table's stride, read from the equal spacing
    between consecutive hashed values, ``[h_k, h_k + stride)``, the last record
    included. A base names nothing when its hashed values are fewer than two
    (no stride to read), when their spacings differ, when any store to the
    base's frame of a pointer's width (or of a hashed value or an address) lies
    before the first record or past the last one's end, when an address lies on
    a hashed value's own offset, when the records
    do not all hold their addresses at the same offsets within them (a table's
    records share one layout), or when the frame moved by an amount the run
    cannot read between its stores (``_Reader._move_frame``).
    """
    hashes: dict[int, list[tuple[int, tuple[str, ...]]]] = {}
    addresses: dict[int, list[tuple[int, int, int]]] = {}
    stores: dict[int, list[int]] = {}
    offsets_stored: dict[int, list[int]] = {}
    narrow: dict[int, list[int]] = {}
    moved: dict[int, list[int]] = {}
    for k, event in enumerate(run):
        if event[0] == "frame hash":
            hashes.setdefault(event[1], []).append((int(event[2]), tuple(event[3])))
        elif event[0] == "frame address":
            addresses.setdefault(event[1], []).append((int(event[2]), int(event[3]), int(event[4])))
        elif event[0] == "frame store":
            offsets_stored.setdefault(event[1], []).append(int(event[2]))
            stores.setdefault(event[1], []).append(k)
        elif event[0] == "frame narrow":
            narrow.setdefault(event[1], []).append(int(event[2]))
        elif event[0] == "frame moved":
            moved.setdefault(event[1], []).append(k)
    out: dict[
        int, tuple[list[tuple[tuple[str, ...], list[tuple[int, int, int]]]], frozenset[int]]
    ] = {}
    for base, held in hashes.items():
        first_store, last_store = stores[base][0], stores[base][-1]
        if any(first_store < k < last_store for k in moved.get(base, ())):
            continue
        held.sort()
        offsets = [offset for offset, _names in held]
        spacings = {later - earlier for earlier, later in zip(offsets, offsets[1:], strict=False)}
        if len(spacings) != 1:
            continue
        (stride,) = spacings
        if stride <= 0:
            continue
        end = offsets[-1] + stride
        if any(not offsets[0] <= offset < end for offset in offsets_stored.get(base, ())):
            continue
        records: list[tuple[tuple[str, ...], list[tuple[int, int, int]]]] = [
            (names, []) for _offset, names in held
        ]
        fits = True
        for offset, slot, where in addresses.get(base, ()):
            k, within = divmod(offset - offsets[0], stride)
            if not 0 <= k < len(records) or within == 0:
                fits = False
                break
            records[k][1].append((slot, where, within))
        if not fits:
            continue
        layouts = {tuple(sorted(within for _s, _w, within in inside)) for _n, inside in records}
        if len(layouts) != 1 or len(set(next(iter(layouts)))) != len(next(iter(layouts))):
            continue
        phases = frozenset(
            (offset - offsets[0]) % stride
            for offset in narrow.get(base, ())
            if not offsets[0] <= offset < end
        )
        out[base] = (records, phases)
    return out


def _read_code(
    image: Image,
    seeds: Mapping[str, Iterable[int]],
    wanted: set[int],
    hashed: Mapping[int, tuple[str, ...]] | None = None,
) -> _Graph:
    reader = _Reader(image, wanted, hashed)
    for begin, end, owner in zip(
        image.function_starts, image.function_ends, image.function_owners, strict=False
    ):
        start = owner if owner is not None else begin
        reader.ranges_of.setdefault(start, []).append((begin, end))
    for start in sorted(reader.ranges_of):
        reader.add(start, _EXCEPTION_DIRECTORY)
    for source, starts in seeds.items():
        for start in sorted(set(starts)):
            if reader._section(start) is not None:
                reader.add(start, source)
    return reader.run()


# A printable run up to its terminator, ASCII and UTF-16LE: read only as far as
# the text goes, so a reference into bytes that are not text costs nothing more.
_ASCII_TEXT = re.compile(rb"[\x20-\x7e\t\r\n]*\x00")
_WIDE_TEXT = re.compile(rb"(?:[\x20-\x7e\t\r\n]\x00)*\x00\x00")


def _text_at(sections: _Sections, rva: int) -> str | None:
    """The text at ``rva`` in a data section: printable ASCII or UTF-16LE up to its terminator."""
    section = sections.at(rva)
    if section is None or section.executable:
        return None
    offset = sections.offset(rva)
    if offset is None:
        return None
    limit = section.raw_offset + section.mapped_size
    data = sections.image.data
    first = section.raw_offset
    # Only a reference to where a text starts reads it: the byte (or, for
    # UTF-16LE, the character) before is not part of the same text. Texts
    # are then disjoint runs, so all of them together are read in one pass of
    # the section, however many references point into one long run.
    if offset == first or not _printable(data[offset - 1]):
        found = _ASCII_TEXT.match(data, offset, limit)
        if found is not None and found.end() - 1 - offset >= TEXT_MIN_CHARS:
            return data[offset : found.end() - 1].decode("ascii")
    if offset - 2 < first or not (_printable(data[offset - 2]) and data[offset - 1] == 0):
        found = _WIDE_TEXT.match(data, offset, limit)
        if found is not None and (found.end() - 2 - offset) // 2 >= TEXT_MIN_CHARS:
            return data[offset : found.end() - 2].decode("utf-16-le")
    return None


def _printable(byte: int) -> bool:
    return 0x20 <= byte < 0x7F or byte in (9, 10, 13)


# -- joining the run's answers ------------------------------------------------


@dataclass
class _Cell:
    """One artefact of one function, and the entries that state it."""

    kind: str  # "import", "slot", "name", "decoded", "plain" or "capa"
    value: str
    sources: list[str] = field(default_factory=list)
    # For a call through a slot the hash resolution fills: the slot, and the
    # instruction that names it (the store, or the record's address).
    slot: int | None = None
    named_at: int | None = None


class _Rows:
    """The artefacts per function start, distinct by value within a kind group."""

    def __init__(self) -> None:
        self.cells: dict[int, dict[tuple[str, str], _Cell]] = {}

    def add(
        self,
        start: int,
        kind: str,
        value: str,
        source: str,
        slot: tuple[int, int] | None = None,
    ) -> None:
        group = _GROUP[kind]
        cells = self.cells.setdefault(start, {})
        cell = cells.get((group, value))
        if cell is None:
            cells[(group, value)] = _Cell(
                kind, value, [source], *(slot if slot is not None else (None, None))
            )
            return
        if kind == "decoded" and cell.kind == "plain":
            cell.kind = "decoded"
        if source not in cell.sources:
            cell.sources.append(source)


# An import called and a name a hash resolves to are one artefact when they are
# one name; a plain and a decoded string are one when they are one text.
_GROUP = {
    "import": "api",
    "name": "api",
    "slot": "slot",
    "plain": "text",
    "decoded": "text",
    "capa": "capa",
}


def _source(pair: tuple[str, Mapping[str, Any]] | None) -> tuple[str, Mapping[str, Any]]:
    if not pair:
        return "", {}
    entry_id, data = pair
    return str(entry_id or ""), data if isinstance(data, Mapping) else {}


def _places_wanted(
    capa: Mapping[str, Any],
    floss: Mapping[str, Any],
    hashes: Mapping[str, Any],
    blobs: Mapping[str, Any],
    base: int,
) -> set[int]:
    wanted: set[int] = set()
    for row in capa.get("capabilities") or []:
        if isinstance(row, Mapping):
            wanted.update(a for a in map(_hex, row.get("addresses") or []) if a is not None)
    for row in floss.get("strings") or []:
        if isinstance(row, Mapping):
            for place in _floss_places(row, base):
                wanted.add(place)
    for hit in hashes.get("hits") or []:
        for place in (hit.get("occurrences") or []) if isinstance(hit, Mapping) else []:
            rva = _hex(place.get("rva")) if isinstance(place, Mapping) else None
            if rva is not None:
                wanted.add(rva)
    for result in blobs.get("results") or []:
        for place in (result.get("references") or []) if isinstance(result, Mapping) else []:
            rva = _hex(place.get("at")) if isinstance(place, Mapping) else None
            if rva is not None:
                wanted.add(rva)
    return wanted


def _floss_places(row: Mapping[str, Any], base: int) -> list[int]:
    """The offset a FLOSS row is placed by: a decoded string's call site, another's routine."""
    if str(row.get("kind") or "") == "decoded":
        keys = ("called_at_rva", "called_at")
    else:
        keys = ("function_rva", "function")
    value = _hex(row.get(keys[0]))
    if value is None:
        value = _hex(row.get(keys[1]))
        if value is not None and value >= base > 0:
            value -= base
        elif value is not None:
            return []
    return [value] if value is not None else []


class _Placer:
    """The function that holds a place: decoded instructions first, then the stated range."""

    def __init__(self, image: Image, graph: _Graph) -> None:
        self.image = image
        self.graph = graph

    def holders(self, rva: int) -> list[int]:
        covered = self.graph.covered.get(rva)
        if covered:
            return sorted(covered)
        owner = self.image.function_at(rva)
        if owner is not None and owner in self.graph.functions:
            return [owner]
        return []

    def stated(self, value: Any) -> list[int]:
        """A function an answer stated around a place, when the run knows it as one."""
        start = _hex(value)
        if start is not None and start in self.graph.functions:
            return [start]
        return []


def index_image(
    image: Image,
    *,
    pe_info: tuple[str, Mapping[str, Any]] | None = None,
    capa: tuple[str, Mapping[str, Any]] | None = None,
    floss: tuple[str, Mapping[str, Any]] | None = None,
    hashes: tuple[str, Mapping[str, Any]] | None = None,
    blobs: tuple[str, Mapping[str, Any]] | None = None,
    absent: Mapping[str, str] | None = None,
    addresses: Sequence[tuple[str, int]] = (),
    function_lists: str = FUNCTION_LISTS_ABSENT,
    ranges_into: dict[str, list[list[str]]] | None = None,
) -> dict[str, Any]:
    """The index of ``image`` joined with the run's answers, each given as ``(entry id, data)``.

    ``ranges_into``, when given, is filled with :func:`function_ranges`: a
    fact the caller keeps beside the answer, never in it.

    ``absent`` is the ``no: <reason>`` of each source the caller could not
    join, by source; the answer and its head state each. ``addresses`` are
    the readings of one asked address, in the order they are tried, each
    ``(how it was read, offset from the image base)``: the first that is a
    function's start, or that an instruction decoded in a function or a
    function's stated range holds, answers, and the answer says which reading
    it was and whether the address is the start or inside. Its row is under
    ``function``, callers and callees included, with no artefacts when it
    holds none; with no reading answering, ``function`` is a ``no:`` sentence.
    """
    _, info = _source(pe_info)
    capa_id, capa_data = _source(capa)
    floss_id, floss_data = _source(floss)
    hash_id, hash_data = _source(hashes)
    blob_id, blob_data = _source(blobs)
    base = image.image_base

    seeds: dict[str, list[int]] = {}
    names: dict[int, list[str]] = {}
    entry_points: set[int] = set()
    exports = [row for row in info.get("export_rows") or [] if isinstance(row, Mapping)]
    for row in exports:
        rva = _hex(row.get("rva"))
        if rva is None:
            continue
        seeds.setdefault(_EXPORTS, []).append(rva)
        if row.get("name"):
            names.setdefault(rva, []).append(str(row["name"]))
    entry = info.get("entry_point")
    if isinstance(entry, int) and entry > 0:
        seeds[_ENTRY_POINT] = [entry]
        entry_points = {entry}
    starts = [s for s in map(_hex, capa_data.get("function_starts") or []) if s is not None]
    if starts:
        seeds[_CAPA] = starts

    wanted = _places_wanted(capa_data, floss_data, hash_data, blob_data, base)
    wanted.update(offset for _, offset in addresses)
    graph = _read_code(image, seeds, wanted, _hashed_places(hash_data))
    placer = _Placer(image, graph)
    rows = _Rows()
    unplaced: dict[str, int] = {}
    # The slots the hash resolution fills, and each call through one: an API
    # call of that name, sourced to the resolution's entry. A call through a
    # slot nothing names, or two names fill, stays a call that names nothing.
    called = {slot for f in graph.functions.values() for slot in f.slot_calls}
    filled, ambiguous = _name_slots(graph.runs, called) if hash_id else ({}, {})
    for start, function in graph.functions.items():
        for slot, count in sorted(function.slot_calls.items()):
            if slot in filled:
                name, named_at = filled[slot]
                rows.add(start, "slot", name, hash_id, (slot, named_at))
            else:
                function.unnamed_calls += count

    def place(where: list[int], kind: str, value: str, source: str, what: str) -> None:
        if not where:
            unplaced[what] = unplaced.get(what, 0) + 1
            return
        for start in where:
            rows.add(start, kind, value, source)

    texts: dict[int, str | None] = {}
    for start, function in graph.functions.items():
        for name in sorted(function.imports):
            rows.add(start, "import", _short_import(name), SELF)
        for target in sorted(function.data_refs):
            if target not in texts:
                texts[target] = _text_at(graph.sections, target)
            text = texts[target]
            if text is not None:
                rows.add(start, "plain", text, SELF)

    for hit in hash_data.get("hits") or []:
        if not isinstance(hit, Mapping):
            continue
        resolved = [
            str(reading.get("name") or "")
            for reading in hit.get("readings") or []
            if isinstance(reading, Mapping)
            and reading.get("set") != "modules"
            and reading.get("name")
        ]
        for occurrence in hit.get("occurrences") or []:
            if not isinstance(occurrence, Mapping) or not resolved:
                continue
            rva = _hex(occurrence.get("rva"))
            where = placer.stated(occurrence.get("function")) or (
                placer.holders(rva) if rva is not None else []
            )
            for name in dict.fromkeys(resolved):
                place(where, "name", name, hash_id, "resolve_api_hashes")

    for result in blob_data.get("results") or []:
        if not isinstance(result, Mapping) or not result.get("text"):
            continue
        for reference in result.get("references") or []:
            if not isinstance(reference, Mapping):
                continue
            rva = _hex(reference.get("at"))
            where = placer.stated(reference.get("function")) or (
                placer.holders(rva) if rva is not None else []
            )
            place(where, "decoded", str(result["text"]), blob_id, "decode_string_blobs")

    for row in floss_data.get("strings") or []:
        if not isinstance(row, Mapping) or not row.get("string"):
            continue
        where = [h for rva in _floss_places(row, base) for h in placer.holders(rva)]
        place(where, "decoded", str(row["string"]), floss_id, "floss")

    for capability in capa_data.get("capabilities") or []:
        if not isinstance(capability, Mapping) or not capability.get("rule"):
            continue
        for address in map(_hex, capability.get("addresses") or []):
            if address is None:
                continue
            where = placer.stated(hex(address)) or placer.holders(address)
            place(where, "capa", str(capability["rule"]), capa_id, "capa")

    data = _answer(image, graph, rows, names, unplaced, entry_points)
    # Only the slots some code calls or jumps through are stated.
    data["resolved_slots"] = {
        hex(base + slot): name for slot, (name, _w) in sorted(filled.items()) if slot in called
    }
    data["ambiguous_slots"] = {
        hex(base + slot): names for slot, names in sorted(ambiguous.items()) if slot in called
    }
    # The callees of every function that is no row, so the call graph is whole.
    data["other_callees"] = {
        hex(base + start): [hex(base + c) for c in sorted(function.callees)]
        for start, function in sorted(graph.functions.items())
        if start not in rows.cells and function.callees
    }
    if ranges_into is not None:
        ranges_into.update(function_ranges(image, graph.functions))
    data["function_lists"] = function_lists
    data["absent"] = dict(absent or {})
    if addresses:
        data.update(_asked(image, graph, placer, rows, names, entry_points, addresses))
    return data


def function_ranges(image: Image, starts: Iterable[int]) -> dict[str, list[list[str]]]:
    """The exception directory's ranges that hold no other known function start.

    By the function each belongs to (a chained fragment under its owner), as
    offsets from the image base, end exclusive: where a place inside a
    function is that function (``analysis.evidence_roots``). ``starts`` are
    every function start the index knows (the exception directory, exports,
    the entry point, capa, call targets); a range holding one other than its
    own function's is left out, since the table that states it does not
    agree with the code.
    """
    held = set(starts)
    known = sorted(held)
    out: dict[str, list[list[str]]] = {}
    for begin, end, owner in zip(
        image.function_starts, image.function_ends, image.function_owners, strict=False
    ):
        start = owner if owner is not None else begin
        inside = bisect_left(known, end) - bisect_left(known, begin)
        if begin <= start < end and start in held:
            inside -= 1
        if end > begin and inside <= 0:
            out.setdefault(hex(start), []).append([hex(begin), hex(end)])
    return out


def _asked(
    image: Image,
    graph: _Graph,
    placer: _Placer,
    rows: _Rows,
    names: Mapping[int, list[str]],
    entry_points: Iterable[int],
    addresses: Sequence[tuple[str, int]],
) -> dict[str, Any]:
    """The function an asked address names, by the first reading that names one."""
    base = image.image_base
    for how, offset in addresses:
        if offset in graph.functions:
            start, where = offset, "the start of"
        else:
            holders = placer.holders(offset)
            if not holders:
                continue
            start, where = holders[0], "inside"
        row = _answer(image, graph, rows, names, {}, entry_points, only=start)["function"]
        asked = hex(base + offset) if how == _AS_VIRTUAL else hex(offset)
        said = f"{asked} read as {how}: {where} the function at {hex(base + start)}"
        return {"function": row, "address_read": said}
    tried = ", ".join(
        f"as {how} {hex(base + offset) if how == _AS_VIRTUAL else hex(offset)}"
        for how, offset in addresses
    )
    return {
        "function": (
            f"no: no function the run knows starts at or holds the address (read {tried}; "
            f"{_SOURCES_SAID})"
        )
    }


def _answer(
    image: Image,
    graph: _Graph,
    rows: _Rows,
    names: Mapping[int, list[str]],
    unplaced: Mapping[str, int],
    entry_points: Iterable[int] = (),
    only: int | None = None,
) -> dict[str, Any]:
    base = image.image_base
    entries = set(entry_points)
    callers: dict[int, set[int]] = {}
    for start, function in graph.functions.items():
        for callee in function.callees:
            if callee != start:
                callers.setdefault(callee, set()).add(start)

    def va(rva: int) -> str:
        return hex(base + rva)

    def row_of(start: int, cells: Mapping[tuple[str, str], _Cell]) -> dict[str, Any]:
        held = graph.functions.get(start)
        reached = 0
        through = 0
        for callee in held.callees if held else ():
            theirs = len(rows.cells.get(callee, ())) if callee != start else 0
            if theirs:
                through += 1
                reached += theirs
        listed = sorted(cells.values(), key=lambda c: (_KIND_ORDER[c.kind], c.value))
        row: dict[str, Any] = {
            "function": va(start),
            "offset": hex(start),
            "direct": len(cells),
            "imports": [_cell(c, base) for c in listed if c.kind == "import"],
            "slot_calls": [_cell(c, base) for c in listed if c.kind == "slot"],
            "resolved": [_cell(c, base) for c in listed if c.kind == "name"],
            "decoded_strings": [_cell(c, base) for c in listed if c.kind == "decoded"],
            "plain_strings": [_cell(c, base) for c in listed if c.kind == "plain"],
            "capa": [_cell(c, base) for c in listed if c.kind == "capa"],
            "callers": [va(c) for c in sorted(callers.get(start, ()))],
            "callees": [va(c) for c in sorted(held.callees if held else ())],
            "indirect": {"artefacts": reached, "through": through},
        }
        if names.get(start):
            row["names"] = list(dict.fromkeys(names[start]))
        if start in entries:
            row["entry_point"] = True
        return row

    out = [] if only is not None else [row_of(start, c) for start, c in rows.cells.items()]
    out.sort(key=lambda r: (-int(r["direct"]), int(r["offset"], 16)))

    sources: dict[str, int] = {}
    for function in graph.functions.values():
        for source in function.sources:
            sources[source] = sources.get(source, 0) + 1
    if only is not None:
        return {"function": row_of(only, rows.cells.get(only, {}))}
    return {
        "tool": TOOL,
        "image_base": hex(base),
        "functions_known": len(graph.functions),
        "function_sources": {s: sources[s] for s in _SOURCE_ORDER if s in sources},
        "function_lists": FUNCTION_LISTS_ABSENT,
        "undecoded_functions": sum(1 for f in graph.functions.values() if f.undecoded),
        # Per function, by address: which the decoder stopped in, and how many
        # calls each makes that name nothing. The pack's lines do not print
        # them; they say where an absent call or string is not a fact.
        "undecoded": [va(s) for s, f in sorted(graph.functions.items()) if f.undecoded],
        "calls_unnamed": {
            va(s): f.unnamed_calls for s, f in sorted(graph.functions.items()) if f.unnamed_calls
        },
        "unplaced": dict(sorted(unplaced.items())),
        "total": len(out),
        "rows": out,
    }


_SOURCE_ORDER = (_EXCEPTION_DIRECTORY, _EXPORTS, _ENTRY_POINT, _CAPA, _CALL_TARGETS)
_SOURCES_SAID = "functions come from " + ", ".join(_SOURCE_ORDER)
_KIND_ORDER = {"import": 0, "slot": 1, "name": 2, "decoded": 3, "plain": 4, "capa": 5}


def _cell(cell: _Cell, base: int = 0) -> dict[str, Any]:
    key = "rule" if cell.kind == "capa" else "text" if cell.kind in ("plain", "decoded") else "name"
    out: dict[str, Any] = {key: cell.value, "sources": list(cell.sources)}
    if cell.slot is not None and cell.named_at is not None:
        out["slot"] = hex(base + cell.slot)
        out["named_at"] = hex(base + cell.named_at)
    return out


def _hashed_places(hashes: Mapping[str, Any]) -> dict[int, tuple[str, ...]]:
    """Each place the hash resolution states a value at, with the function names it reads.

    A module's name is no function name: a place reading only modules is kept
    with no names, so a table's records stay counted as records.
    """
    places: dict[int, tuple[str, ...]] = {}
    for hit in hashes.get("hits") or []:
        if not isinstance(hit, Mapping):
            continue
        names = tuple(
            dict.fromkeys(
                str(reading.get("name") or "")
                for reading in hit.get("readings") or []
                if isinstance(reading, Mapping)
                and reading.get("set") != "modules"
                and reading.get("name")
            )
        )
        for occurrence in hit.get("occurrences") or []:
            rva = _hex(occurrence.get("rva")) if isinstance(occurrence, Mapping) else None
            if rva is not None:
                places[rva] = tuple(dict.fromkeys([*places.get(rva, ()), *names]))
    return places


def function_index(
    path: str | Path,
    *,
    pe_info: tuple[str, Mapping[str, Any]] | None = None,
    capa: tuple[str, Mapping[str, Any]] | None = None,
    floss: tuple[str, Mapping[str, Any]] | None = None,
    hashes: tuple[str, Mapping[str, Any]] | None = None,
    blobs: tuple[str, Mapping[str, Any]] | None = None,
    absent: Mapping[str, str] | None = None,
    ranges_into: dict[str, list[list[str]]] | None = None,
) -> dict[str, Any]:
    """The function index of the PE at ``path`` (see the module docstring).

    ``ranges_into`` is filled as :func:`index_image` says.
    """
    try:
        image = pe_image.load(path)
    except FileNotFoundError:
        return {"error": f"no such file: {path}", "tool": TOOL}
    except pe_image.NotAPortableExecutable as exc:
        return {"error": f"this tool reads Windows PE images only; {exc}", "tool": TOOL}
    return index_image(
        image,
        pe_info=pe_info,
        capa=capa,
        floss=floss,
        hashes=hashes,
        blobs=blobs,
        absent=absent,
        ranges_into=ranges_into,
    )


def rows_of(data: Mapping[str, Any]) -> Sequence[Mapping[str, Any]]:
    """The rows of an index answer, the readable ones only."""
    return [row for row in data.get("rows") or [] if isinstance(row, Mapping)]


# -- the table, as the pack and the analysis server write it ----------------------

# Said wherever the index is named to a model: where the whole of it is.
SERVED_BY = "the analysis server's function_index tool serves it whole or by address"

# How the callees' artefacts are counted, said beside the count.
PER_CALLEE = "counted per callee"

# How a row names the calls it makes through slots the hash resolution fills.
SLOT_CALLS_SAID = "calls through slots the hash resolution fills"

_ADDRESS = re.compile(r"0x[0-9a-f]{1,16}")


def sample_text(value: Any) -> str:
    """A value the sample wrote (a name from its tables), quoted with the pack's escaping."""
    from maljan.utils.written_forms import pack_escaped

    return f'"{pack_escaped(str(value or ""))}"'


def head_text(data: Mapping[str, Any], rows: int) -> str:
    """What the index is: how many functions hold artefacts, where the functions come from."""
    known = int(data.get("functions_known") or 0)
    sources = data.get("function_sources") or {}
    listed = ", ".join(f"{name} {count}" for name, count in sources.items())
    said = f"{rows} of the {known} functions the run knows hold artefacts of their own"
    said += f" (functions from {listed}; " if listed else " ("
    said += f"{data.get('function_lists') or FUNCTION_LISTS_ABSENT})"
    for source, reason in (data.get("absent") or {}).items():
        said += f"; {source}: {reason}"
    undecoded = int(data.get("undecoded_functions") or 0)
    if undecoded:
        said += (
            f"; in {undecoded} functions the decoder stopped at a byte it does not read, so "
            "their calls and strings past it are absent"
        )
    unplaced = data.get("unplaced") or {}
    if unplaced:
        counted = ", ".join(f"{tool} {n}" for tool, n in unplaced.items())
        said += f"; places no function holds, not counted: {counted}"
    if not rows:
        return said
    return (
        f"{said}; address = image base {data.get('image_base')} + offset, as Ghidra and radare2 "
        "take it; ranked by distinct artefacts of their own, then by address:"
    )


def _ids(cells: Any, entry_id: str) -> list[str]:
    ids: list[str] = []
    for cell in cells or []:
        for source in cell.get("sources") or [] if isinstance(cell, Mapping) else []:
            said = entry_id if source == SELF else str(source)
            if said and said not in ids:
                ids.append(said)
    return ids


def row_line(row: Mapping[str, Any], entry_id: str) -> str:
    """``- 0x…: calls "A" (ev_…); refers to 2 decoded strings (ev_…); capa: r (ev_…); …``.

    Names the sample wrote (imports, resolved names, exports) are quoted with
    the pack's escaping, as every recovered string is, so they read as data;
    the strings a function refers to are counted, never shown.
    """
    said = [f"export {sample_text(n)}" for n in row.get("names") or []]
    if row.get("entry_point"):
        said.append("entry point")
    stated = str(row.get("function") or "")
    where = stated if _ADDRESS.fullmatch(stated) else sample_text(stated)
    if said:
        where += f" ({', '.join(said)})"
    return f"- {where}: {row_parts(row, entry_id)}"


def row_parts(row: Mapping[str, Any], entry_id: str) -> str:
    """What :func:`row_line` says a function holds, after its address."""
    parts: list[str] = []

    def named(key: str, verb: str, field: str) -> None:
        cells = [c for c in row.get(key) or [] if isinstance(c, Mapping)]
        if cells:
            names = ", ".join(sample_text(c.get(field)) for c in cells)
            parts.append(f"{verb} {names} ({', '.join(_ids(cells, entry_id))})")

    named("imports", "calls", "name")
    named("slot_calls", SLOT_CALLS_SAID, "name")
    named("resolved", "resolves", "name")
    texts = []
    for key, one, many in (
        ("decoded_strings", "decoded string", "decoded strings"),
        ("plain_strings", "plain string", "plain strings"),
    ):
        cells = [c for c in row.get(key) or [] if isinstance(c, Mapping)]
        if cells:
            noun = one if len(cells) == 1 else many
            texts.append(f"{len(cells)} {noun} ({', '.join(_ids(cells, entry_id))})")
    if texts:
        parts.append("refers to " + ", ".join(texts))
    capa = [c for c in row.get("capa") or [] if isinstance(c, Mapping)]
    if capa:
        rules = ", ".join(str(c.get("rule") or "") for c in capa)
        parts.append(f"capa: {rules} ({', '.join(_ids(capa, entry_id))})")
    callers, callees = len(row.get("callers") or []), len(row.get("callees") or [])
    parts.append(
        f"called by {callers}, calls {callees} {'function' if callees == 1 else 'functions'}"
    )
    indirect = row.get("indirect") or {}
    reached, through = int(indirect.get("artefacts") or 0), int(indirect.get("through") or 0)
    if reached:
        parts.append(
            f"{through} {'callee holds' if through == 1 else 'callees hold'} {reached} "
            f"{'artefact' if reached == 1 else 'artefacts'} of their own, {PER_CALLEE}"
        )
    return "; ".join(parts)


# -- the analysis server's tool --------------------------------------------------

# What the served index says of capa, which it never runs.
CAPA_NOT_JOINED = (
    "no: this tool does not run capa, which takes minutes; the triage pack's function_index "
    "entry joins capa's answer"
)

# What the served index says of a source it ran that raised, or answered an error.
FAILED_HERE = "no: it failed here ({})"
ERROR_HERE = "no: it answered an error here ({})"
# What it says when FLOSS's remembered rows for the file could not be read.
FLOSS_UNREADABLE = "no: FLOSS's rows for this file could not be read ({})"

# What the served index says of FLOSS when this server holds no FLOSS answer for the file.
FLOSS_NOT_REMEMBERED = "no: FLOSS has not run on this file in this server"

# Why the served index has no disassembler's function list.
SERVED_FUNCTION_LISTS = (
    "Ghidra's and radare2's function lists: no: the analysis server has no disassembler of its own"
)

# The name a cell of the served answer gives its own decoding.
THIS_ANSWER = "this answer"

# An address as the pack prints one: hexadecimal, with or without ``0x``, at most 64 bits.
_AS_VIRTUAL = "a virtual address"
_ADDRESS_TEXT = re.compile(r"(?:0[xX])?([0-9a-fA-F]{1,16})")


def address_readings(address: Any, base: int) -> list[tuple[str, int]] | str:
    """The readings of an asked address to try, in order, or a ``no:`` sentence.

    Hexadecimal, with or without ``0x``: the pack and the disassemblers print
    addresses in hex, so a bare number is hex, never decimal. A value at or
    above the image base is tried first as a virtual address (its offset is
    the value less the base), then as an offset; a value below it is an
    offset only.
    """
    if isinstance(address, int) and not isinstance(address, bool):
        value = address
    else:
        text = str(address).strip()
        match = _ADDRESS_TEXT.fullmatch(text)
        if match is None:
            shown = text if len(text) <= 40 else text[:39] + "…"
            return (
                f"no: {shown!r} is not an address (hexadecimal, with or without 0x, at most "
                "16 digits)"
            )
        value = int(match.group(1), 16)
    if value < 0:
        return f"no: {value} is not an address"
    readings: list[tuple[str, int]] = []
    if base > 0 and value >= base:
        readings.append((_AS_VIRTUAL, value - base))
    readings.append(("an offset from the image base", value))
    return readings


def served_index(path: str | Path, address: Any = None) -> dict[str, Any]:
    """The index of the PE at ``path`` from the file alone, as the analysis server serves it.

    Joined with the server's own answers for the file: ``pe_info`` for the
    exports and the entry point, ``resolve_api_hashes`` and
    ``decode_string_blobs`` run here in-process (they read only the bytes),
    and the rows FLOSS answered for the file in this server when it ran on
    it. Each source not joined is stated with its reason under ``absent``;
    capa is never run here (``CAPA_NOT_JOINED``). With no address, the whole
    table in the pack's row form; with one, read as ``address_readings`` says,
    that function's row with its callers and callees and the reading that
    answered.
    """
    from maljan.tools import api_hashes, binary, emulated_strings, string_blobs

    try:
        image = pe_image.load(path)
    except FileNotFoundError:
        return {"error": f"no such file: {path}", "tool": TOOL}
    except pe_image.NotAPortableExecutable as exc:
        return {"error": f"this tool reads Windows PE images only; {exc}", "tool": TOOL}
    readings: list[tuple[str, int]] = []
    if address not in (None, ""):
        read = address_readings(address, image.image_base)
        if isinstance(read, str):
            return {"tool": TOOL, "row": read}
        readings = read
    answers: dict[str, Any] = {}
    absent: dict[str, str] = {}
    for name, call in (
        (
            "pe_info",
            lambda: binary.pe_info(
                str(path), sections=False, imports=False, resources=False, overlay=False, pdb=False
            ),
        ),
        ("resolve_api_hashes", lambda: api_hashes.resolve_api_hashes(str(path))),
        ("decode_string_blobs", lambda: string_blobs.decode_string_blobs(str(path))),
    ):
        try:
            value = call()
        except Exception as exc:  # noqa: BLE001 - stated under ``absent``, never lost
            absent[name] = FAILED_HERE.format(f"{type(exc).__name__}: {exc}")
            continue
        if isinstance(value, dict) and not value.get("error"):
            answers[name] = (name, value)
        else:
            said = value.get("error") if isinstance(value, dict) else value
            if isinstance(said, dict):
                said = said.get("message") or said
            absent[name] = ERROR_HERE.format(said)
    try:
        floss_rows = emulated_strings.remembered_rows(str(path))
    except Exception as exc:  # noqa: BLE001 - stated under ``absent``, never lost
        floss_rows = []
        absent["floss"] = FLOSS_UNREADABLE.format(exc)
    if floss_rows:
        answers["floss"] = ("floss", {"strings": floss_rows})
    elif "floss" not in absent:
        absent["floss"] = FLOSS_NOT_REMEMBERED
    absent["capa"] = CAPA_NOT_JOINED
    data = index_image(
        image,
        pe_info=answers.get("pe_info"),
        floss=answers.get("floss"),
        hashes=answers.get("resolve_api_hashes"),
        blobs=answers.get("decode_string_blobs"),
        absent=absent,
        addresses=readings,
        function_lists=SERVED_FUNCTION_LISTS,
    )
    data["joined"] = sorted(answers)
    rows = rows_of(data)
    out = {key: data[key] for key in _SERVED_KEYS}
    if not readings:
        table = [head_text(data, len(rows)), *(row_line(row, THIS_ANSWER) for row in rows)]
        return out | {"table": "\n".join(table)}
    asked = data.get("function")
    if isinstance(asked, Mapping):
        out["address_read"] = data.get("address_read", "")
        out["row"] = row_line(asked, THIS_ANSWER)
        out["callers"] = list(asked.get("callers") or [])
        out["callees"] = list(asked.get("callees") or [])
    else:
        out["row"] = str(asked)
    return out


_SERVED_KEYS = (
    "tool",
    "image_base",
    "functions_known",
    "function_sources",
    "function_lists",
    "absent",
    "joined",
    "undecoded_functions",
    "unplaced",
    "total",
)

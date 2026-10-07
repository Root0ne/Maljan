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
  that happened. A call names the import its slot or its jump thunk goes
  through (``imports``), or the function at its target (``callees``); a call
  through a register, or through a slot the import table does not fill, names
  nothing.
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
from bisect import bisect_right
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


@dataclass
class _Graph:
    functions: dict[int, _Function] = field(default_factory=dict)
    # For each place asked about, the functions whose decoded instructions cover it.
    covered: dict[int, set[int]] = field(default_factory=dict)
    # The section lookup the walk used, for the readers of the data sections.
    sections: Any = None


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

    def __init__(self, image: Image, wanted: set[int]) -> None:
        self.image = image
        self.sections = _Sections(image)
        self.imports = image.imports_by_slot()
        self.wanted = wanted
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
        if not self.attributing:
            return
        if self.wanted:
            for place in range(rva, rva + ins.length):
                if place in self.wanted:
                    self.graph.covered.setdefault(place, set()).add(function.start)
        if ins.kind != "call":
            data_target = _data_address(self.image, code, at, ins, rva + ins.length)
            if data_target is not None:
                function.data_refs.add(data_target)

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
        while base + at < end and at < len(code):
            if read[at]:
                return
            read[at] = 1
            ins = decode(code, at, self.image.is64)
            if ins is None:
                function.undecoded |= self.attributing
                return
            self._note(function, base + at, ins, code, at)
            if ins.kind == "stop" and ins.target[0] == "jump":
                target = base + at + ins.length + ins.target[1]
                if not begin <= target < end:
                    self._tail_call(function, target)
            at += ins.length

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


def _read_code(image: Image, seeds: Mapping[str, Iterable[int]], wanted: set[int]) -> _Graph:
    reader = _Reader(image, wanted)
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

    kind: str  # "import", "name", "decoded", "plain" or "capa"
    value: str
    sources: list[str] = field(default_factory=list)


class _Rows:
    """The artefacts per function start, distinct by value within a kind group."""

    def __init__(self) -> None:
        self.cells: dict[int, dict[tuple[str, str], _Cell]] = {}

    def add(self, start: int, kind: str, value: str, source: str) -> None:
        group = _GROUP[kind]
        cells = self.cells.setdefault(start, {})
        cell = cells.get((group, value))
        if cell is None:
            cells[(group, value)] = _Cell(kind, value, [source])
            return
        if kind == "decoded" and cell.kind == "plain":
            cell.kind = "decoded"
        if source not in cell.sources:
            cell.sources.append(source)


# An import called and a name a hash resolves to are one artefact when they are
# one name; a plain and a decoded string are one when they are one text.
_GROUP = {"import": "api", "name": "api", "plain": "text", "decoded": "text", "capa": "capa"}


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
) -> dict[str, Any]:
    """The index of ``image`` joined with the run's answers, each given as ``(entry id, data)``.

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
    graph = _read_code(image, seeds, wanted)
    placer = _Placer(image, graph)
    rows = _Rows()
    unplaced: dict[str, int] = {}

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
    data["function_lists"] = function_lists
    data["absent"] = dict(absent or {})
    if addresses:
        data.update(_asked(image, graph, placer, rows, names, entry_points, addresses))
    return data


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
            "imports": [_cell(c) for c in listed if c.kind == "import"],
            "resolved": [_cell(c) for c in listed if c.kind == "name"],
            "decoded_strings": [_cell(c) for c in listed if c.kind == "decoded"],
            "plain_strings": [_cell(c) for c in listed if c.kind == "plain"],
            "capa": [_cell(c) for c in listed if c.kind == "capa"],
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
        "unplaced": dict(sorted(unplaced.items())),
        "total": len(out),
        "rows": out,
    }


_SOURCE_ORDER = (_EXCEPTION_DIRECTORY, _EXPORTS, _ENTRY_POINT, _CAPA, _CALL_TARGETS)
_SOURCES_SAID = "functions come from " + ", ".join(_SOURCE_ORDER)
_KIND_ORDER = {"import": 0, "name": 1, "decoded": 2, "plain": 3, "capa": 4}


def _cell(cell: _Cell) -> dict[str, Any]:
    key = "rule" if cell.kind == "capa" else "text" if cell.kind in ("plain", "decoded") else "name"
    return {key: cell.value, "sources": list(cell.sources)}


def function_index(
    path: str | Path,
    *,
    pe_info: tuple[str, Mapping[str, Any]] | None = None,
    capa: tuple[str, Mapping[str, Any]] | None = None,
    floss: tuple[str, Mapping[str, Any]] | None = None,
    hashes: tuple[str, Mapping[str, Any]] | None = None,
    blobs: tuple[str, Mapping[str, Any]] | None = None,
    absent: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """The function index of the PE at ``path`` (see the module docstring)."""
    try:
        image = pe_image.load(path)
    except FileNotFoundError:
        return {"error": f"no such file: {path}", "tool": TOOL}
    except pe_image.NotAPortableExecutable as exc:
        return {"error": f"this tool reads Windows PE images only; {exc}", "tool": TOOL}
    return index_image(
        image, pe_info=pe_info, capa=capa, floss=floss, hashes=hashes, blobs=blobs, absent=absent
    )


def rows_of(data: Mapping[str, Any]) -> Sequence[Mapping[str, Any]]:
    """The rows of an index answer, the readable ones only."""
    return [row for row in data.get("rows") or [] if isinstance(row, Mapping)]


# -- the table, as the pack and the analysis server write it ----------------------

# Said wherever the index is named to a model: where the whole of it is.
SERVED_BY = "the analysis server's function_index tool serves it whole or by address"

# How the callees' artefacts are counted, said beside the count.
PER_CALLEE = "counted per callee"

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
    parts: list[str] = []

    def named(key: str, verb: str, field: str) -> None:
        cells = [c for c in row.get(key) or [] if isinstance(c, Mapping)]
        if cells:
            names = ", ".join(sample_text(c.get(field)) for c in cells)
            parts.append(f"{verb} {names} ({', '.join(_ids(cells, entry_id))})")

    named("imports", "calls", "name")
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
    said = [f"export {sample_text(n)}" for n in row.get("names") or []]
    if row.get("entry_point"):
        said.append("entry point")
    stated = str(row.get("function") or "")
    where = stated if _ADDRESS.fullmatch(stated) else sample_text(stated)
    if said:
        where += f" ({', '.join(said)})"
    return f"- {where}: {'; '.join(parts)}"


# -- the analysis server's tool --------------------------------------------------

# What the served index says of capa, which it never runs.
CAPA_NOT_JOINED = (
    "no: this tool does not run capa, which takes minutes; the triage pack's function_index "
    "entry joins capa's answer"
)

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
            absent[name] = f"no: it failed here ({type(exc).__name__}: {exc})"
            continue
        if isinstance(value, dict) and not value.get("error"):
            answers[name] = (name, value)
        else:
            said = value.get("error") if isinstance(value, dict) else value
            if isinstance(said, dict):
                said = said.get("message") or said
            absent[name] = f"no: it answered an error here ({said})"
    try:
        floss_rows = emulated_strings.remembered_rows(str(path))
    except Exception as exc:  # noqa: BLE001 - stated under ``absent``, never lost
        floss_rows = []
        absent["floss"] = f"no: FLOSS's rows for this file could not be read ({exc})"
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

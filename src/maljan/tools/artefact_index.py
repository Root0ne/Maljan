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
* **What a function calls.** A function in the exception directory is decoded
  instruction after instruction across its stated range; any other is decoded
  from its start along every branch, up to a return, a jump it cannot follow,
  the next function start it knows, or the end of its section. A byte the
  decoder does not read ends that path, and the answer counts the functions
  where that happened. A call names the import its slot or its jump thunk
  goes through (``imports``), or the function at its target (``callees``); a
  call through a register, or through a slot the import table does not fill,
  names nothing.
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

Every walk is bounded by the file: each code byte is decoded at most once in
all, whichever functions, ranges and branches lead to it (a byte another
function's decoding already read ends the path, so code two functions share is
read for the first); every list is built from the answers' own entries and
the decoder's calls, and stored once per distinct value. Nothing recurses.

A place is inside a function when an instruction the decoder read in that
function covers it, or else when the exception directory's range holds it; a
place no function holds is counted under ``unplaced`` by its source and given
to none. An artefact is counted once per function as a distinct value (an
import by its name, a string by its text, a rule by its name), and every entry
that states it is cited. A function with no artefact of its own is not a row.

The sample is only read; nothing in it is run.
"""

from __future__ import annotations

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
    _callee,
    decode,
)
from maljan.tools.pe_image import Image

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


# -- reading the code -------------------------------------------------------


def _data_address(image: Image, code: bytes, at: int, ins: Instruction, rva_end: int) -> int | None:
    """The RVA an instruction takes the address of, when it names one the bytes state.

    x64: a RIP-relative memory operand. x86: an absolute ``[disp32]`` memory
    operand, a ``push imm32``, a ``mov r32, imm32`` or a ``mov r/m32, imm32``
    whose value is a virtual address inside the image. Anything else: ``None``.
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
    if modrm_at is None or modrm_at >= end:
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
    if not image.is64 and not operand16 and op == 0xC7 and end - at >= 4:
        # ``mov r/m32, imm32``: the value is the instruction's last four bytes.
        return _virtual(image, int.from_bytes(code[end - 4 : end], "little"))
    return None


def _virtual(image: Image, value: int) -> int | None:
    rva = value - image.image_base
    return rva if 0 <= rva < image.size_of_image else None


class _Reader:
    """The decoder's walk over every function, adding call targets as it reaches them."""

    def __init__(self, image: Image, wanted: set[int]) -> None:
        self.image = image
        self.wanted = wanted
        self.graph = _Graph()
        self.queue: list[int] = []
        self.sorted_seeds: list[int] = []
        self.known: set[int] = set()
        self.ranges_of: dict[int, list[tuple[int, int]]] = {}
        self.code = {section.rva: image.section_bytes(section) for section in image.code_sections()}
        # One mark per code byte: an instruction start any function's decoding
        # already read. Each byte is decoded once in all, so the walk is linear
        # in the code however the starts, ranges and branches overlap.
        self.read = {rva: bytearray(len(code)) for rva, code in self.code.items()}

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
        self.sorted_seeds = sorted(self.known)
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
        return self.graph

    def _section(self, rva: int) -> tuple[int, bytes] | None:
        section = self.image.section_at_rva(rva)
        if section is None or not section.executable or section.rva not in self.code:
            return None
        return section.rva, self.code[section.rva]

    def _note(self, function: _Function, rva: int, ins: Instruction, code: bytes, at: int) -> None:
        """What one decoded instruction says: the places it covers, its call, its data."""
        if self.wanted:
            for place in range(rva, rva + ins.length):
                if place in self.wanted:
                    self.graph.covered.setdefault(place, set()).add(function.start)
        if ins.kind == "call":
            callee = _callee(self.image, rva, ins)
            if callee is not None:
                if callee.get("import"):
                    function.imports.add(str(callee["import"]))
                elif callee.get("function"):
                    target = int(callee["function"], 16)
                    if self._section(target) is not None:
                        function.callees.add(target)
                        self.add(target, _CALL_TARGETS)
            return
        data_target = _data_address(self.image, code, at, ins, rva + ins.length)
        if data_target is not None:
            function.data_refs.add(data_target)

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
                function.undecoded = True
                return
            self._note(function, base + at, ins, code, at)
            at += ins.length

    def _descend(self, function: _Function) -> None:
        """Decode from the start along every branch, within the function's own bound."""
        found = self._section(function.start)
        if found is None:
            return
        base, code = found
        later = bisect_right(self.sorted_seeds, function.start)
        bound = min(
            self.sorted_seeds[later] if later < len(self.sorted_seeds) else base + len(code),
            base + len(code),
        )
        read = self.read[base]
        pending = [function.start]
        while pending:
            rva = pending.pop()
            while function.start <= rva < bound and not read[rva - base]:
                if rva != function.start and rva in self.known:
                    break
                at = rva - base
                read[at] = 1
                ins = decode(code, at, self.image.is64)
                if ins is None:
                    function.undecoded = True
                    break
                self._note(function, rva, ins, code, at)
                after = rva + ins.length
                if ins.kind == "stop":
                    kind, value = ins.target
                    if kind == "branch":
                        pending.append(after + value)
                    elif kind == "jump":
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


def _text_at(image: Image, rva: int) -> str | None:
    """The text at ``rva`` in a data section: printable ASCII or UTF-16LE up to its terminator."""
    section = image.section_at_rva(rva)
    if section is None or section.executable:
        return None
    offset = image.offset_of_rva(rva)
    if offset is None:
        return None
    limit = section.raw_offset + section.mapped_size
    data = image.data
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
    address: int | None = None,
) -> dict[str, Any]:
    """The index of ``image`` joined with the run's answers, each given as ``(entry id, data)``.

    With ``address`` (an offset from the image base), the answer also holds
    that function's row under ``function``, its callers and callees included,
    a row with no artefacts when it holds none, or a ``no:`` sentence when the
    run knows no function starting there.
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
                texts[target] = _text_at(image, target)
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

    return _answer(image, graph, rows, names, unplaced, entry_points, address)


def _answer(
    image: Image,
    graph: _Graph,
    rows: _Rows,
    names: Mapping[int, list[str]],
    unplaced: Mapping[str, int],
    entry_points: Iterable[int] = (),
    address: int | None = None,
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

    out = [row_of(start, cells) for start, cells in rows.cells.items()]
    out.sort(key=lambda r: (-int(r["direct"]), int(r["offset"], 16)))

    sources: dict[str, int] = {}
    for function in graph.functions.values():
        for source in function.sources:
            sources[source] = sources.get(source, 0) + 1
    asked: dict[str, Any] = {}
    if address is not None:
        asked["function"] = (
            row_of(address, rows.cells.get(address, {}))
            if address in graph.functions
            else f"no: the run knows no function starting at {va(address)} ({_SOURCES_SAID})"
        )
    return {
        **asked,
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
) -> dict[str, Any]:
    """The function index of the PE at ``path`` (see the module docstring)."""
    try:
        image = pe_image.load(path)
    except FileNotFoundError:
        return {"error": f"no such file: {path}", "tool": TOOL}
    except pe_image.NotAPortableExecutable as exc:
        return {"error": f"this tool reads Windows PE images only; {exc}", "tool": TOOL}
    return index_image(image, pe_info=pe_info, capa=capa, floss=floss, hashes=hashes, blobs=blobs)


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
    if data.get("capa"):
        said += f"; {data['capa']}"
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
    "capa: no: this tool does not run capa, which takes minutes; the triage pack's "
    "function_index entry joins capa's answer"
)

# The name a cell of the served answer gives its own decoding.
THIS_ANSWER = "this answer"


def _address_offset(address: Any, base: int) -> int | None:
    """An address as an offset from the image base: a virtual address or an offset already."""
    if isinstance(address, int) and not isinstance(address, bool):
        value: int | None = address
    else:
        text = str(address or "").strip().lower()
        value = _hex(text) if text.startswith("0x") else (int(text) if text.isdigit() else None)
    if value is None:
        return None
    return value - base if value >= base > 0 else value


def served_index(path: str | Path, address: Any = None) -> dict[str, Any]:
    """The index of the PE at ``path`` from the file alone, as the analysis server serves it.

    Joined with the server's own answers for the file: ``pe_info`` for the
    exports and the entry point, ``resolve_api_hashes`` and
    ``decode_string_blobs`` run here in-process (they read only the bytes),
    and the rows FLOSS answered for the file in this server when it ran on
    it. capa is never run here (``CAPA_NOT_JOINED``). With no address, the
    whole table in the pack's row form; with one (a virtual address or an
    offset), that function's row with its callers and callees.
    """
    from maljan.tools import api_hashes, binary, emulated_strings, string_blobs

    try:
        image = pe_image.load(path)
    except FileNotFoundError:
        return {"error": f"no such file: {path}", "tool": TOOL}
    except pe_image.NotAPortableExecutable as exc:
        return {"error": f"this tool reads Windows PE images only; {exc}", "tool": TOOL}
    wanted: int | None = None
    if address not in (None, ""):
        wanted = _address_offset(address, image.image_base)
        if wanted is None:
            return {"error": f"address {address!r} is not a number", "tool": TOOL}
    answers: dict[str, Any] = {}
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
        except Exception:  # noqa: BLE001 - an answer that cannot be joined is left out
            continue
        if isinstance(value, dict) and not value.get("error"):
            answers[name] = (name, value)
    try:
        floss_rows = emulated_strings.remembered_rows(str(path))
    except Exception:  # noqa: BLE001 - FLOSS's absence is not this tool's failure
        floss_rows = []
    if floss_rows:
        answers["floss"] = ("floss", {"strings": floss_rows})
    data = index_image(
        image,
        pe_info=answers.get("pe_info"),
        floss=answers.get("floss"),
        hashes=answers.get("resolve_api_hashes"),
        blobs=answers.get("decode_string_blobs"),
        address=wanted,
    )
    data["capa"] = CAPA_NOT_JOINED
    data["joined"] = sorted(answers)
    rows = rows_of(data)
    head = head_text(data, len(rows))
    if wanted is None:
        table = [head, *(row_line(row, THIS_ANSWER) for row in rows)]
        return {key: data[key] for key in _SERVED_KEYS} | {"table": "\n".join(table)}
    asked = data.get("function")
    out = {key: data[key] for key in _SERVED_KEYS}
    if isinstance(asked, Mapping):
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
    "capa",
    "joined",
    "undecoded_functions",
    "unplaced",
    "total",
)

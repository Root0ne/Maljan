"""Where each piece of evidence comes from: the roots of a ledger entry's facts.

Two analysts that both cite the same string at the same place in the file are
two layers and one piece of evidence. Counting layers alone counts that
string twice. This module states, for every ledger entry, the places in the
sample its facts were read from, so a capability can say how many distinct
places stand behind it beside how many layers named it.

A root is derived from what the entry already holds, never guessed:

* **a place in the image**, written as its offset from the image base and the
  section that holds it (``0x1a40 in .text``): a ``strings`` row's file
  offset, a FLOSS row's call site, a ``decode_string_blobs`` row's blob, a
  ``resolve_api_hashes`` occurrence, a capa match address, a function index
  row, an address a decompile, disassembly or memory read was given, an
  address a Ghidra IOC row states, the start of the range a
  ``transform_bytes`` call read (or the ``no:`` sentence its answer states
  for a range no section holds), the start of the compressed data an
  ``unpack_upx`` call read (or the ``no:`` sentence of a file it did not
  unpack). A FLOSS row whose call site and decoded
  text the blob decoder states for a blob (``floss.called_at_rva``) has the
  blob as its root, so the two tools reading one encoded string are one root;
  a call site holding blobs none of which decodes to the row's text gives
  that row no root;
* **a function**, for a place inside a range the file's own exception
  directory states (the function index carries the ranges beside its answer,
  ``LedgerEntry.function_ranges``), when the range lies inside one section
  and holds no other function start the run knows;
* **a table of the file**: the PE header, the import table, the export
  table, the resource table, the debug directory, the overlay, a section by
  name (``pe_info``, and a disassembler's import or export listing);
* **a sandbox process** (``sandbox process 84``), the one process a Sigma
  match's command line or a LOLBin hit's command line belongs to;
* **a network flow** (``network flow tcp to 192.0.2.1:443``), the same label
  whether the sandbox or the capture states it and for both directions of
  one connection, and a DNS query by name;
* **an item of the sandbox report** a statement cites by its id
  (``analysis.sandbox_sections``): a process item's root is that sandbox
  process, a TCP or UDP item's its flow, a DNS item's its query; the row of a
  network item is read from a ``sandbox_items`` answer or the whole
  ``sandbox_network`` answer of the same ledger, and an item id is read only
  in a run whose ledger holds the section index, against that index;
* **the whole file**: hashes, file identification, signing, a file
  reputation answer.

Each file has its own layout: an entry is about the sample only when the
path it names is the sample's, or it names no path and its server's program
is the sample (``_Files``); an entry about any other file is placed against
that file's own section table and image base, and its roots name the file.
An entry whose root cannot be read has none, and says why in a ``no:``
sentence: a reference lookup reads nothing of the sample, a failed call read
nothing, a tool whose answer carries no offset, address, section, event or
flow has nothing to place, a file offset with no section table to place it
against the file's addresses.

A statement's roots are those of the entries it cites. An entry holding one
root gives it. An entry holding several gives the ones the statement picks
out: by a number it writes, read in the coordinate the entry's rows state,
or by a quoted value or a name written as one that only one of the entry's
roots holds. A name or value several of them hold, or a prose word, picks out
none.
A statement that picks out none of them gives no root for that entry and
says so: which row it read is not a fact.

Every pass is linear in the entries and their rows: roots are kept in dicts
keyed by address, value and name, never compared pairwise, and the whole
reading is done once per step that owns the run, from that run's ledger alone.
"""

from __future__ import annotations

import bisect
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from maljan.analysis.sandbox_sections import (
    ITEMS_TOOL,
    NETWORK_KINDS,
    SECTION_OF_PREFIX,
    ItemIndex,
    item_ids_in,
    item_index_of,
)
from maljan.schemas.evidence import repeat_holders

WHOLE_FILE = "the whole file"
PE_HEADER = "the PE header"
IMPORT_TABLE = "the import table"
EXPORT_TABLE = "the export table"
RESOURCE_TABLE = "the resource table"
DEBUG_DIRECTORY = "the debug directory"
OVERLAY = "the overlay"

# How each kind of root is written. A name the sample wrote (a section's, a
# host's, a queried name) is escaped as the pack writes one, so a root stays
# one line wherever it is shown.
PLACE_IN_SECTION = "{address} in {section}"
PLACE_OUTSIDE = "{address} outside every section"
FUNCTION_ROOT = "function {place}"
SECTION_ROOT = "section {name}"
PROCESS_ROOT = "sandbox process {pid}"
FLOW_ROOT = "network flow {proto} to {host}:{port}"
DNS_ROOT = "DNS query {name}"
FILE_OFFSET_ROOT = "file offset {offset}"
FILE_ROOT = "{root} of file {file}"
WHOLE_OTHER_FILE = "the whole of file {file}"

NO_ENTRY = "no: {entry} is not an entry of this run's ledger"
NO_CITATION = "no: the statement cites no ledger entry"
FAILED = "no: the call failed, so it read nothing"
REFERENCE = "no: {tool} is a reference lookup and reads nothing of the sample"
NOTHING_TO_PLACE = "no: {tool}'s answer carries no offset, address, section, event or flow to place"
BY_NAME_ONLY = "no: the call names its function by name, not by address"
REPEAT_LOOP = "no: {entry} repeats an entry that holds no answer"
SIGNATURE_UNPLACED = "no: a sandbox signature names no process or event"
MATCH_UNPLACED = "no: the match names no command line of a process the sandbox recorded"
SHARED_COMMAND = "no: more than one process the sandbox recorded has this command line"
NAMES_NO_ROW = "no: the statement names none of {entry}'s rows"
NO_ROW_NAMES_TECHNIQUE = "no: no row of {entry} that gives a root names the technique"
FILE_UNTOLD = "no: the call's carved_path names no one file"
OUTSIDE_PROGRAM = "no: the address lies outside the program the server last named"
OFFSET_UNPLACED = (
    "no: the file states an image base and no section table, so a file offset cannot be "
    "placed against its addresses"
)
NO_ITEM = "no: {item} is not an item of this run's sandbox report"
ITEM_ROW_UNREAD = "no: no answer in this run's ledger holds the row of {item}"
ITEM_UNPLACED = "no: a sandbox `{section}` item names no process, flow or query to place"
ITEM_NO_PID = "no: the report states no pid for this process"
BLOB_UNMATCHED = (
    "no: the call site holds blobs the blob decoder read, and none of them decodes to this text"
)

# The tools whose fact is about the file as a whole.
_WHOLE_FILE_TOOLS = frozenset({"hashes", "identify_file", "signing_info", "get_file_report"})
# The tools that answer what something is rather than read the sample.
_REFERENCE_TOOLS = frozenset(
    {
        "api_capability",
        "attck_validate",
        "attck_lookup",
        "resolve_technique",
        "family_lookup",
        "similar_cases",
        "get_ip_report",
        "get_domain_report",
        "get_url_report",
        "capabilities",
        "knowledge__capabilities",
    }
)
_IMPORT_LISTINGS = frozenset({"list_imports", "get_imports"})
_EXPORT_LISTINGS = frozenset({"list_exports", "get_exports"})
# The argument names a call gives one address under, and a list of them under.
_ADDRESS_ARGS = (
    "address",
    "addr",
    "function_address",
    "ea",
    "va",
    "start_address",
    "entry_address",
)
_ADDRESS_LIST_ARGS = ("functions", "addresses")
_NAME_ARGS = ("name", "function_name", "function", "symbol")
# The argument that names a file the run carved, and the tool that carves.
_CARVED_ARG = "carved_path"
_CARVE_TOOL = "carve_payloads"
# The tool that writes the program a UPX-packed file holds out as a file of its own.
_UNPACK_TOOL = "unpack_upx"


_WORD = re.compile(r"[A-Za-z_.$?@][\w.$?@]*")
# A word of prose: small letters alone. A name a statement writes as an
# identifier carries a capital, a digit or one of ``_.$?@``.
_PROSE_WORD = re.compile(r"[a-z]+")
_QUOTED = re.compile(r"`([^`\n]+)`|\"([^\"\n]+)\"|“([^”\n]+)”|'([^'\n]{2,})'")
# A capture's packet line and a DNS name line, as the network server writes them.
_PACKET_LINE = re.compile(
    r"^Packet \d+: (?P<src>\S+) -> (?P<dst>\S+) "
    r"\((?P<proto>[A-Za-z]+) (?P<sport>\d+)->(?P<port>\d+)\)"
)
_DNS_NAME_LINE = re.compile(r"^(?P<name>(?:[A-Za-z0-9_-]+\.)+[A-Za-z0-9_-]+)\.?$")
_HEX_TEXT = re.compile(r"\s*(?:0x)?([0-9a-fA-F]{1,16})\s*")
# A row of the function index as the analysis server serves it: its address,
# then the names it holds, each quoted with the pack's escaping.
_SERVED_ROW = re.compile(r"^- (0x[0-9a-fA-F]{1,16})\b(.*)$")
_SERVED_NAME = re.compile(r"\"((?:[^\"\\]|\\.)*)\"")
# An image base sits on a 64 KiB boundary.
_BASE_ALIGNMENT = 0x10000


def _hex(value: Any) -> int | None:
    """An address as a tool writes it: an integer as it is, a string as hex."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    match = _HEX_TEXT.fullmatch(str(value or ""))
    return int(match.group(1), 16) if match else None


def _fold(text: Any) -> str:
    return str(text or "").strip().casefold()


def _written(text: Any) -> str:
    """A name the sample wrote, escaped as the pack writes it, without quotes."""
    from maljan.utils.written_forms import pack_escaped

    return pack_escaped(str(text or ""))


@dataclass(frozen=True)
class _Section:
    name: str
    rva: int
    size: int
    raw: int
    raw_size: int


@dataclass
class Layout:
    """One file's section table, image bases and function ranges, as its answers state them."""

    sections: tuple[_Section, ...] = ()
    bases: tuple[int, ...] = ()
    # ``(begin, end, function start)`` per range the file's own exception
    # directory states, offsets from the image base, end exclusive. A sample
    # can shape its own table, so a range is used only when it lies inside
    # one section and holds no other function start the run knows.
    functions: tuple[tuple[int, int, int], ...] = ()
    # Every function start the run knows in this file, offsets from the base.
    starts: tuple[int, ...] = ()
    # The image's size as an answer states it, 0 when none does; with none,
    # the section table's span stands for it.
    extent: int = 0
    _starts: list[int] = field(default_factory=list)
    _raw_starts: list[int] = field(default_factory=list)
    _by_raw: list[_Section] = field(default_factory=list)
    # The kept ranges cut into disjoint segments, each with the one function
    # every range holding it names, or ``None`` where ranges of two functions
    # overlap: ``_cuts[i]`` begins segment ``i``, ``_owners[i]`` owns it.
    _cuts: list[int] = field(default_factory=list)
    _owners: list[int | None] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.sections = tuple(sorted(self.sections, key=lambda s: s.rva))
        self.bases = tuple(sorted(set(self.bases)))
        self._starts = [s.rva for s in self.sections]
        self._by_raw = sorted((s for s in self.sections if s.raw_size > 0), key=lambda s: s.raw)
        self._raw_starts = [s.raw for s in self._by_raw]
        known = sorted({*self.starts, *(start for _b, _e, start in self.functions)})
        self.functions = tuple(
            sorted(
                {
                    r
                    for r in self.functions
                    if self._inside_a_section(r[0], r[1]) and not _holds_another(known, *r)
                }
            )
        )
        self._cut_segments()

    def _inside_a_section(self, begin: int, end: int) -> bool:
        """Whether ``[begin, end)`` lies inside one section, no larger than it."""
        if end <= begin:
            return False
        section = self.section_at(begin)
        return section is not None and section is self.section_at(end - 1)

    def _cut_segments(self) -> None:
        """One sweep over the range ends: O(n log n) to build, O(log n) to look up."""
        events: list[tuple[int, int, int]] = []
        for begin, end, start in self.functions:
            events.append((begin, 1, start))
            events.append((end, -1, start))
        events.sort()
        active: dict[int, int] = {}
        index = 0
        while index < len(events):
            at = events[index][0]
            while index < len(events) and events[index][0] == at:
                _at, step, start = events[index]
                held = active.get(start, 0) + step
                if held:
                    active[start] = held
                else:
                    active.pop(start, None)
                index += 1
            owner = next(iter(active)) if len(active) == 1 else None
            if self._cuts and self._cuts[-1] == at:
                self._owners[-1] = owner
            else:
                self._cuts.append(at)
                self._owners.append(owner)

    def function_at(self, rva: int) -> int | None:
        """The start of the function a kept range puts ``rva`` in, or ``None``.

        A place kept ranges of two different functions both hold is in
        neither, since which one is not a fact.
        """
        index = bisect.bisect_right(self._cuts, rva) - 1
        return self._owners[index] if index >= 0 else None

    def section_at(self, rva: int) -> _Section | None:
        index = bisect.bisect_right(self._starts, rva) - 1
        if index < 0:
            return None
        section = self.sections[index]
        return section if rva < section.rva + max(section.size, section.raw_size, 1) else None

    def rva_of_offset(self, offset: int) -> int | None:
        index = bisect.bisect_right(self._raw_starts, offset) - 1
        if index < 0:
            return None
        section = self._by_raw[index]
        if offset < section.raw + section.raw_size:
            return section.rva + offset - section.raw
        return None

    def holds(self, value: int) -> bool:
        """Whether ``value`` can lie in this image, read as an address or an offset.

        As an address, at or above the image base and, where the image's size
        is stated or its section table spans it, below the end; as an offset,
        below that size. With no base stated nothing is ruled out.
        """
        if not self.bases:
            return True
        size = self.extent or max(
            (s.rva + max(s.size, s.raw_size) for s in self.sections), default=0
        )
        base = self.bases[0]
        if size:
            return value < size or base <= value < base + size
        return value >= base

    def offsets_unplaceable(self) -> bool:
        """Whether a file offset cannot be placed: a base is stated and no section table."""
        return not self.sections and bool(self.bases)

    def rvas_of(self, value: int) -> list[int]:
        """The offsets from the image base ``value`` reads as, the virtual reading first.

        A value at or above a base the file states reads as a virtual address
        against the nearest such base, found by bisection. With a section
        table, a reading lying in no section is dropped when the other lies
        in one.
        """
        readings: list[int] = []
        index = bisect.bisect_right(self.bases, value) - 1
        if index >= 0:
            readings.append(value - self.bases[index])
        if not readings or readings[0] != value:
            readings.append(value)
        if self.sections:
            placed = [r for r in readings if self.section_at(r) is not None]
            if placed:
                return placed
        return readings

    def _place_label(self, rva: int) -> str:
        if not self.sections:
            return f"{rva:#x}"
        section = self.section_at(rva)
        if section is None:
            return PLACE_OUTSIDE.format(address=f"{rva:#x}")
        return PLACE_IN_SECTION.format(address=f"{rva:#x}", section=_written(section.name))

    def label(self, rva: int) -> str:
        """A place as its root is written: the offset from the image base and its section.

        A place inside a function a kept range holds is that function:
        ``function 0x2c10 in .text``. Two places in one function with no
        range kept stay two roots.
        """
        start = self.function_at(rva)
        if start is not None:
            return FUNCTION_ROOT.format(place=self._place_label(start))
        return self._place_label(rva)


def _holds_another(known: list[int], begin: int, end: int, start: int) -> bool:
    """Whether ``[begin, end)`` holds a known function start other than its own."""
    held = bisect.bisect_left(known, end) - bisect.bisect_left(known, begin)
    if begin <= start < end:
        held -= 1
    return held > 0


@dataclass
class EntryRoots:
    """One entry's roots, and how a statement citing it can name each."""

    roots: list[str] = field(default_factory=list)
    reason: str = ""
    by_rva: dict[int, str] = field(default_factory=dict)
    by_value: dict[str, set[str]] = field(default_factory=dict)
    by_word: dict[str, set[str]] = field(default_factory=dict)
    # The same names as written, for a statement naming one as an identifier.
    by_name: dict[str, set[str]] = field(default_factory=dict)
    # The coordinate the entry's rows state a place in: ``offset`` for a
    # file offset (strings, YARA), ``address`` otherwise.
    coordinate: str = "address"
    by_technique: dict[str, set[str]] = field(default_factory=dict)
    # The techniques a row names that the row gives no root for, with why.
    unplaced: dict[str, str] = field(default_factory=dict)
    # The values of rows that give no root, with why.
    unplaced_values: dict[str, str] = field(default_factory=dict)
    # Each root's position in ``roots``: membership and order by dict.
    order: dict[str, int] = field(default_factory=dict)
    # The first reason a row gave no root, the entry's own when none gives one.
    first_reason: str = ""
    # The file the entry is about: its layout, and how its roots name it.
    layout: Layout = field(default_factory=Layout)
    file: str = ""
    # Placed by its server's last named program rather than by a path.
    by_program: bool = False

    def ordered(self, roots: set[str]) -> list[str]:
        """``roots`` in the order this entry holds them."""
        return sorted(roots, key=lambda r: self.order.get(r, len(self.order)))

    def named(self, root: str) -> str:
        """``root`` as this entry's file writes it: as it is for the sample, else naming it."""
        if not self.file:
            return root
        if root == WHOLE_FILE:
            return WHOLE_OTHER_FILE.format(file=self.file)
        return FILE_ROOT.format(root=root, file=self.file)

    def add(
        self,
        root: str,
        *,
        rva: int | None = None,
        values: Iterable[Any] = (),
        words: Iterable[Any] = (),
        techniques: Iterable[str] = (),
    ) -> None:
        root = self.named(root)
        if root not in self.order:
            self.order[root] = len(self.roots)
            self.roots.append(root)
        if rva is not None:
            self.by_rva.setdefault(rva, root)
        for value in values:
            folded = _fold(value)
            if folded:
                self.by_value.setdefault(folded, set()).add(root)
        for word in words:
            folded = _fold(word)
            if folded:
                self.by_word.setdefault(folded, set()).add(root)
                self.by_name.setdefault(str(word).strip(), set()).add(root)
        for tid in techniques:
            self.by_technique.setdefault(tid, set()).add(root)

    def unplace(
        self, reason: str, *, values: Iterable[Any] = (), techniques: Iterable[str] = ()
    ) -> None:
        """A row that gives no root: its values and techniques say why when named."""
        for value in values:
            folded = _fold(value)
            if folded:
                self.unplaced_values.setdefault(folded, reason)
        for tid in techniques:
            self.unplaced.setdefault(tid, reason)
        self.first_reason = self.first_reason or reason


def _structured(entry: Any) -> Any:
    return getattr(entry, "structured", None)


def _tool(entry: Any) -> str:
    return str(getattr(entry, "tool", "") or "").rsplit("__", 1)[-1]


def _rows(data: Any, key: str) -> list[Mapping[str, Any]]:
    rows = data.get(key) if isinstance(data, Mapping) else None
    return [row for row in rows or [] if isinstance(row, Mapping)]


def _row_techniques(row: Any) -> set[str]:
    from maljan.pipeline.evidence_summary import _technique_ids

    return _technique_ids(row)


def _usable(entry: Any) -> bool:
    return getattr(entry, "ok", True) is not False and not getattr(entry, "repeated_of", None)


# -- which file an entry is about ------------------------------------------------


def _unquoted(value: str) -> str:
    from maljan.tools.arguments import unquoted

    return unquoted(value).strip()


# The tools that state which program a disassembler's server holds, and the
# answer keys and arguments that name its file.
_PROGRAM_TOOLS = frozenset(
    {"get_current_program_info", "get_program_info", "program_info", "get_current_program"}
)
_OPEN_TOOLS = frozenset({"open_file", "open_program", "load_program"})
_PROGRAM_KEYS = ("path", "executable_path", "file_path", "program_path", "name", "program")
_PATH_ARGS = ("path", "file_path", "file", "filename", "binary_path")
_PIPELINE = "pipeline"


def _basename(path: str) -> str:
    return re.split(r"[\\/]", path)[-1]


class _Files:
    """Which file each entry is about: the sample, or another file the run read.

    The sample is ``""``. An entry is about the sample when the path it names
    is the sample's (the path the triage pack states, or with no pack entry
    the first path the ledger states; or a path whose file name is the
    sample's, or whose stem is the sample's SHA-256), or when it names no
    path and its server's program is the sample: the program a server holds
    is the one its latest program statement or open names, the sample until
    one names another file, read in the order the calls were made. Any other
    file is named by the leading digits of the SHA-256 the run states for it
    (a carving's, an unpacking's or a hash answer's), or by its path, quoted. A call whose
    ``carved_path`` is not one path is about no file that can be told
    (``None``).
    """

    def __init__(self, entries: Sequence[Any]) -> None:
        self._digest: dict[str, str] = {}
        for entry in entries:
            if not _usable(entry):
                continue
            data = _structured(entry)
            if _tool(entry) == _CARVE_TOOL:
                for row in _rows(data, "payloads"):
                    digest = str(row.get("sha256") or "").strip().lower()
                    for key in ("carved_path", "path"):
                        if digest and isinstance(row.get(key), str) and row[key].strip():
                            self._digest.setdefault(_unquoted(row[key]), digest)
            elif _tool(entry) == _UNPACK_TOOL and isinstance(data, Mapping):
                child = data.get("child")
                child = child if isinstance(child, Mapping) else {}
                digest = str(child.get("sha256") or "").strip().lower()
                for key in ("carved_path", "path"):
                    if digest and isinstance(child.get(key), str) and child[key].strip():
                        self._digest.setdefault(_unquoted(child[key]), digest)
            elif _tool(entry) == "hashes" and isinstance(data, Mapping):
                digest = str(data.get("sha256") or "").strip().lower()
                path = self._path_named(entry)
                if digest and path:
                    self._digest.setdefault(path, digest)
        stated = [p for e in entries if (p := self._path_named(e))]
        pack = [
            p
            for e in entries
            if str(getattr(e, "agent", "") or "") == _PIPELINE and (p := self._path_named(e))
        ]
        self._sample_paths = set(pack or stated[:1])
        self._sample_names = {_basename(p) for p in self._sample_paths}
        self._sample_digests = {self._digest[p] for p in self._sample_paths if p in self._digest}
        self._file: dict[int, str | None] = {}
        # The entries placed by their server's stated program, not by a path.
        self.by_program: set[int] = set()
        program: dict[Any, str | None] = {}
        # The order the calls were made in: ``seq``, then the start time, then
        # the ledger's own order.
        made = sorted(
            enumerate(entries),
            key=lambda pair: (
                int(getattr(pair[1], "seq", 0) or 0),
                float(getattr(pair[1], "started_at", 0.0) or 0.0),
                pair[0],
            ),
        )
        for _index, entry in made:
            server = getattr(entry, "server", None)
            held = self._program_named(entry)
            if held is not None:
                program[server] = held
                self._file[id(entry)] = held
                continue
            names, said = self._named(entry)
            self._file[id(entry)] = said if names else program.get(server, "")
            if not names and program.get(server):
                self.by_program.add(id(entry))

    @staticmethod
    def _path_named(entry: Any) -> str:
        args = getattr(entry, "args", None) or {}
        for key in _PATH_ARGS:
            if isinstance(args.get(key), str) and args[key].strip():
                return _unquoted(args[key])
        return ""

    def _file_of_path(self, path: str) -> str:
        """The file a path names: ``""`` for the sample, else its digest or the path quoted."""
        digest = self._digest.get(path, "")
        stem = _basename(path).split(".", 1)[0].lower()
        if (
            path in self._sample_paths
            or _basename(path) in self._sample_names
            or (digest and digest in self._sample_digests)
            or (stem and stem in self._sample_digests)
        ):
            return ""
        if digest:
            return f"sha256 {digest[:12]}"
        return f'"{_written(path)}"'

    def _program_named(self, entry: Any) -> str | None:
        """The file a program statement or open names, or ``None`` for any other entry."""
        tool = _tool(entry)
        if tool in _PROGRAM_TOOLS and _usable(entry):
            data = _structured(entry)
            for key in _PROGRAM_KEYS:
                value = data.get(key) if isinstance(data, Mapping) else None
                if isinstance(value, str) and value.strip():
                    return self._file_of_path(_unquoted(value))
        if tool in _OPEN_TOOLS and _usable(entry):
            path = self._path_named(entry)
            if path:
                return self._file_of_path(path)
        return None

    def _named(self, entry: Any) -> tuple[bool, str | None]:
        """Whether the entry's own arguments name a file, and the file they name."""
        args = getattr(entry, "args", None) or {}
        carved = args.get(_CARVED_ARG)
        if carved not in (None, ""):
            if not isinstance(carved, str):
                return True, None
            path = _unquoted(carved)
            if path and path.casefold() != "null":
                return True, self._file_of_path(path)
        path = self._path_named(entry)
        return (True, self._file_of_path(path)) if path else (False, "")

    def of(self, entry: Any) -> str | None:
        if id(entry) in self._file:
            return self._file[id(entry)]
        return self._named(entry)[1]


# -- each file's layout ------------------------------------------------------------


@dataclass
class _Stated:
    """What the run's answers state of one file's layout, gathered in one pass."""

    sections: dict[str, _Section] = field(default_factory=dict)
    bases: dict[int, None] = field(default_factory=dict)
    ranges: list[tuple[int, int, int]] = field(default_factory=list)
    starts: dict[int, None] = field(default_factory=dict)
    # Function starts written as virtual addresses, read against the bases.
    virtual_starts: list[int] = field(default_factory=list)
    extent: int = 0


def _gather(entry: Any, stated: _Stated) -> None:
    data = _structured(entry)
    tool = _tool(entry)
    for start, spans in (getattr(entry, "function_ranges", None) or {}).items():
        first = _hex(start)
        for span in spans if isinstance(spans, list) else ():
            if first is not None and isinstance(span, list | tuple) and len(span) == 2:
                begin, end = _hex(span[0]), _hex(span[1])
                if begin is not None and end is not None and end > begin:
                    stated.ranges.append((begin, end, first))
    if not isinstance(data, Mapping):
        return
    for holder in (data, data.get("meta")):
        if not isinstance(holder, Mapping):
            continue
        for key in ("image_base", "imagebase"):
            base = _hex(holder.get(key)) if holder.get(key) is not None else None
            if base and base % _BASE_ALIGNMENT == 0:
                stated.bases.setdefault(base, None)
        for key in ("size_of_image", "image_size"):
            size = holder.get(key)
            if isinstance(size, int) and not isinstance(size, bool) and size > 0:
                stated.extent = max(stated.extent, size)
    if tool == "pe_info":
        for row in _rows(data, "sections"):
            rva = _hex(row.get("virtual_address"))
            name = str(row.get("name") or "").strip()
            if rva is None or not name or name in stated.sections:
                continue
            stated.sections[name] = _Section(
                name=name,
                rva=rva,
                size=int(row.get("virtual_size") or 0),
                raw=int(row.get("raw_offset") or 0),
                raw_size=int(row.get("raw_size") or 0),
            )
        for row in _rows(data, "export_rows"):
            rva = _hex(row.get("rva"))
            if rva is not None:
                stated.starts.setdefault(rva, None)
        entry_point = data.get("entry_point")
        if isinstance(entry_point, int) and not isinstance(entry_point, bool) and entry_point > 0:
            stated.starts.setdefault(entry_point, None)
    elif tool == "function_index":
        for row in _rows(data, "rows"):
            rva = _hex(row.get("offset"))
            if rva is not None:
                stated.starts.setdefault(rva, None)
        callees = data.get("other_callees")
        for start, called in callees.items() if isinstance(callees, Mapping) else ():
            stated.virtual_starts.extend(
                v
                for v in (_hex(start), *map(_hex, called if isinstance(called, list) else ()))
                if v is not None
            )
        for key in ("callers", "callees"):
            stated.virtual_starts.extend(
                v
                for v in map(_hex, data.get(key) or [] if isinstance(data.get(key), list) else [])
                if v is not None
            )


def layouts_of(entries: Iterable[Any], files: _Files) -> dict[str, Layout]:
    """Each file's layout as the ledger states it, read once: the sample under ``""``."""
    stated: dict[str, _Stated] = {}
    for entry in entries:
        if not _usable(entry):
            continue
        file = files.of(entry)
        if file is None:
            continue
        _gather(entry, stated.setdefault(file, _Stated()))
    out: dict[str, Layout] = {}
    for file, held in stated.items():
        plain = Layout(sections=tuple(held.sections.values()), bases=tuple(held.bases))
        starts = dict(held.starts)
        for value in held.virtual_starts:
            starts.setdefault(plain.rvas_of(value)[0], None)
        out[file] = Layout(
            sections=plain.sections,
            bases=plain.bases,
            functions=tuple(held.ranges),
            starts=tuple(starts),
            extent=held.extent,
        )
    return out


def layout_of(entries: Iterable[Any]) -> Layout:
    """The sample's layout as the ledger states it."""
    listed = list(entries)
    return layouts_of(listed, _Files(listed)).get("") or Layout()


# -- facts one answer states that place another's rows ------------------------------


@dataclass
class _Joins:
    """Facts one answer states that place another's rows: read in a first pass."""

    # ``(file, call site, decoded text)`` to the blob the decoder read there.
    blob_of: dict[tuple[str, int, str], int] = field(default_factory=dict)
    # ``(file, call site)`` for every call site the decoder ties to a blob.
    blob_calls: set[tuple[str, int]] = field(default_factory=set)
    # A command line to every process the sandbox recorded with it.
    processes_of_command: dict[str, dict[int, None]] = field(default_factory=dict)
    # A connection, its two ends in either order, to the end it was first seen going to.
    flow_ends: dict[tuple[str, tuple[str, str], tuple[str, str]], tuple[str, str]] = field(
        default_factory=dict
    )
    # A sandbox network item's id to its kind and row, as an answer in the ledger holds it.
    network_items: dict[str, tuple[str, Any]] = field(default_factory=dict)


def _flow_key(
    proto: Any, src: Any, sport: Any, dst: Any, dport: Any
) -> tuple[str, tuple[str, str], tuple[str, str]] | None:
    if src in (None, "") or sport in (None, "") or dst in (None, "") or dport in (None, ""):
        return None
    one, other = (str(src), str(sport)), (str(dst), str(dport))
    return (str(proto or "").lower(), min(one, other), max(one, other))


def _flow_rows(entry: Any) -> list[dict[str, Any]]:
    """The connections one answer states, as ``proto, src, sport, dst, dport`` rows."""
    tool = _tool(entry)
    data = _structured(entry)
    if tool in ("sandbox_network", "pcap_summary"):
        rows = [dict(r) for r in _rows(data, "conversations")]
        rows += [{**r, "proto": "tcp"} for r in _rows(data, "tcp")]
        rows += [{**r, "proto": "udp"} for r in _rows(data, "udp")]
        return rows
    if tool == "read_pcap_summary":
        out: list[dict[str, Any]] = []
        for line in str(getattr(entry, "output", "") or "").splitlines():
            match = _PACKET_LINE.match(line.strip())
            if match:
                out.append(
                    {
                        "proto": match["proto"],
                        "src": match["src"],
                        "sport": match["sport"],
                        "dst": match["dst"],
                        "dport": match["port"],
                    }
                )
        return out
    return []


def _joins(entries: Iterable[Any], files: _Files) -> _Joins:
    found = _Joins()
    for entry in entries:
        if not _usable(entry):
            continue
        tool = _tool(entry)
        data = _structured(entry)
        if tool == "decode_string_blobs":
            file = files.of(entry)
            if file is None:
                continue
            for row in _rows(data, "results"):
                link = row.get("floss")
                call = _hex(link.get("called_at_rva")) if isinstance(link, Mapping) else None
                blob = _hex(row.get("rva"))
                if call is not None and blob is not None:
                    found.blob_calls.add((file, call))
                    found.blob_of.setdefault((file, call, _fold(row.get("text"))), blob)
        elif tool == "sandbox_processes":
            for row in _rows(data, "processes"):
                command = str(row.get("command_line") or "").strip()
                if command and isinstance(row.get("pid"), int):
                    found.processes_of_command.setdefault(command, {})[int(row["pid"])] = None
        if tool == ITEMS_TOOL and isinstance(data, Mapping) and data.get("section") == "network":
            for row in _rows(data, "items"):
                if isinstance(row.get("id"), str):
                    found.network_items.setdefault(
                        row["id"].lower(), (str(row.get("kind") or ""), row.get("fields"))
                    )
        elif tool == "sandbox_network" and _whole_network_answer(entry):
            number = 0
            for kind in NETWORK_KINDS:
                rows = data.get(kind)
                for row in rows if isinstance(rows, list) else ():
                    number += 1
                    found.network_items.setdefault(f"net:{number}", (kind, row))
        for row in _flow_rows(entry):
            key = _flow_key(
                row.get("proto"), row.get("src"), row.get("sport"), row.get("dst"), row.get("dport")
            )
            if key is not None:
                found.flow_ends.setdefault(key, (str(row["dst"]), str(row["dport"])))
    return found


def _whole_network_answer(entry: Any) -> bool:
    """Whether a ``sandbox_network`` answer lists every row: asked for no page, and cut nowhere."""
    data = _structured(entry)
    args = getattr(entry, "args", None) or {}
    if not isinstance(data, Mapping) or args.get("offset") or args.get("limit"):
        return False
    return not any(str(key).endswith(("_total", "_next_offset", "shortened")) for key in data)


def _item_root(item: str, joins: _Joins) -> tuple[str, str]:
    """``(root, "")`` for a sandbox item id the run's index holds, or ``("", why none)``."""
    prefix, _, rest = item.partition(":")
    section = SECTION_OF_PREFIX.get(prefix, "")
    if section == "processes":
        pid = rest.split(".", 1)[0]
        return (_process(pid), "") if pid.isdigit() else ("", ITEM_NO_PID)
    if section == "signatures":
        return "", SIGNATURE_UNPLACED
    if section != "network":
        return "", ITEM_UNPLACED.format(section=section)
    held = joins.network_items.get(item)
    if held is None:
        return "", ITEM_ROW_UNREAD.format(item=item)
    kind, row = held
    if not isinstance(row, Mapping):
        return "", ITEM_UNPLACED.format(section=section)
    if kind in ("tcp", "udp"):
        label = _flow_of({**row, "proto": kind}, joins)
        return (label, "") if label else ("", ITEM_UNPLACED.format(section=section))
    if kind == "dns":
        name = str(row.get("request") or row.get("query") or row.get("name") or "").rstrip(".")
        return (
            (DNS_ROOT.format(name=_written(name)), "")
            if name
            else (
                "",
                ITEM_UNPLACED.format(section=section),
            )
        )
    return "", ITEM_UNPLACED.format(section=section)


def _process(pid: Any) -> str:
    return PROCESS_ROOT.format(pid=pid)


def _flow(proto: Any, dst: Any, port: Any) -> str:
    return FLOW_ROOT.format(proto=str(proto or "").lower(), host=_written(dst), port=port)


def _flow_of(row: Mapping[str, Any], joins: _Joins) -> str | None:
    """The flow a connection row belongs to: one label for both of its directions."""
    key = _flow_key(
        row.get("proto"), row.get("src"), row.get("sport"), row.get("dst"), row.get("dport")
    )
    if key is not None and key in joins.flow_ends:
        host, port = joins.flow_ends[key]
        return _flow(row.get("proto"), host, port)
    if row.get("dst") and row.get("dport") not in (None, ""):
        return _flow(row.get("proto"), row["dst"], row["dport"])
    return None


def _place(found: EntryRoots, rva: int, **kwargs: Any) -> None:
    found.add(found.layout.label(rva), rva=rva, **kwargs)


def _address_root(found: EntryRoots, value: Any, **kwargs: Any) -> bool:
    """Add the root of an address a tool wrote, read as its file's coordinates allow."""
    number = _hex(value)
    if number is None:
        return False
    # An entry placed by its server's last named program, at an address that
    # program cannot hold, is about some other program: no root of this one.
    if found.by_program and not found.layout.holds(number):
        found.unplace(
            OUTSIDE_PROGRAM,
            values=kwargs.get("values", ()),
            techniques=kwargs.get("techniques", ()),
        )
        return False
    _place(found, found.layout.rvas_of(number)[0], **kwargs)
    return True


def _offset_root(found: EntryRoots, offset: int, **kwargs: Any) -> bool:
    """Add the root of a file offset, or say why it has none. ``True`` when placed."""
    layout = found.layout
    rva = layout.rva_of_offset(offset)
    if rva is not None:
        _place(found, rva, **kwargs)
        return True
    if layout.offsets_unplaceable():
        found.unplace(
            OFFSET_UNPLACED,
            values=kwargs.get("values", ()),
            techniques=kwargs.get("techniques", ()),
        )
        return False
    found.add(FILE_OFFSET_ROOT.format(offset=f"{offset:#x}"), **kwargs)
    return True


def _read_pe_info(found: EntryRoots, data: Mapping[str, Any]) -> None:
    found.add(PE_HEADER)
    imports = _rows(data, "imports")
    if imports:
        found.add(
            IMPORT_TABLE,
            words=[r.get("function") for r in imports] + [r.get("dll") for r in imports],
        )
    exports = [e for e in data.get("exports") or [] if isinstance(e, str | Mapping)]
    if exports:
        found.add(
            EXPORT_TABLE,
            words=[e.get("name") if isinstance(e, Mapping) else e for e in exports],
        )
    for row in _rows(data, "sections"):
        name = str(row.get("name") or "").strip()
        if name:
            found.add(SECTION_ROOT.format(name=_written(name)), words=(name,))
    resources = data.get("resources") or []
    if resources:
        found.add(
            RESOURCE_TABLE,
            words=[r.get("name") if isinstance(r, Mapping) else r for r in resources],
        )
    if data.get("pdb_path"):
        found.add(DEBUG_DIRECTORY, values=(data.get("pdb_path"),))
    overlay = data.get("overlay")
    if isinstance(overlay, Mapping) and overlay.get("present"):
        found.add(OVERLAY)


def _read_function_index(found: EntryRoots, data: Any) -> None:
    """The pack's index answer by its rows; the served one by the rows its lines state."""
    for row in _rows(data, "rows"):
        rva = _hex(row.get("offset"))
        if rva is None:
            continue
        words = list(row.get("names") or [])
        values: list[Any] = []
        for key in ("imports", "slot_calls", "resolved"):
            words += [c.get("name") for c in _rows(row, key)]
        for key in ("decoded_strings", "plain_strings"):
            values += [c.get("text") for c in _rows(row, key)]
        _place(found, rva, words=words, values=values)
    if not isinstance(data, Mapping):
        return
    lines: list[str] = []
    for key in ("table", "row"):
        if isinstance(data.get(key), str):
            lines += data[key].splitlines()
    for line in lines:
        match = _SERVED_ROW.match(line.strip())
        if match is None:
            continue
        address = _hex(match.group(1))
        if address is None:
            continue
        # The names as the row quotes them, in the pack's escaping.
        names = _SERVED_NAME.findall(match.group(2))
        _place(found, found.layout.rvas_of(address)[0], words=names, values=names)


def _read_transform(found: EntryRoots, data: Any) -> None:
    """A byte transform's root: where its input range starts, or the sentence saying why none.

    The answer states the range's offset from the image base when a section
    holds its start, and a ``no:`` sentence when none does or the file is not
    an image; the steps and the output add no place of their own.
    """
    held = data.get("input") if isinstance(data, Mapping) else None
    if not isinstance(held, Mapping):
        return
    rva = _hex(held.get("rva")) if held.get("rva") is not None else None
    if rva is not None:
        _place(found, rva)
        return
    place = held.get("place")
    if isinstance(place, str) and place.startswith("no:"):
        found.reason = place


def _read_unpack(found: EntryRoots, data: Any) -> None:
    """An unpacking's root: where the compressed data it read starts, or why it read none.

    The packed file's own layout places the offset (in the section UPX wrote
    the stream to); the unpacked program is a file of its own, named by the
    digest the answer states, and adds no place to this entry. A file the
    reader did not unpack gives the ``no:`` sentence its answer states.
    """
    if not isinstance(data, Mapping):
        return
    header = data.get("pack_header")
    offset = _hex(header.get("compressed_data_offset")) if isinstance(header, Mapping) else None
    if offset is not None:
        _offset_root(found, offset)
        return
    said = data.get("unpacked")
    if isinstance(said, str) and said.startswith("no:"):
        found.reason = said


def _command_root(
    found: EntryRoots, command: str, joins: _Joins, techniques: Iterable[str]
) -> None:
    """The one process a command line belongs to, or why it gives none."""
    pids = list(joins.processes_of_command.get(command, ()))
    if len(pids) == 1:
        found.add(_process(pids[0]), values=(command,), techniques=techniques)
    elif pids:
        found.unplace(SHARED_COMMAND, values=(command,), techniques=techniques)
    else:
        found.unplace(MATCH_UNPLACED, values=(command,), techniques=techniques)


def _read_entry(entry: Any, found: EntryRoots, joins: _Joins) -> EntryRoots:
    """One entry's roots, read from its own answer and arguments against its file's layout."""
    tool = _tool(entry)
    if getattr(entry, "ok", True) is False:
        found.reason = FAILED
        return found
    if tool in _REFERENCE_TOOLS:
        found.reason = REFERENCE.format(tool=tool)
        return found
    if tool in _WHOLE_FILE_TOOLS:
        found.add(WHOLE_FILE)
        return found
    data = _structured(entry)
    args = getattr(entry, "args", None) or {}
    if tool == "pe_info" and isinstance(data, Mapping):
        _read_pe_info(found, data)
    elif tool in _IMPORT_LISTINGS:
        found.add(IMPORT_TABLE, words=_WORD.findall(str(getattr(entry, "output", "") or "")))
    elif tool in _EXPORT_LISTINGS:
        found.add(EXPORT_TABLE, words=_WORD.findall(str(getattr(entry, "output", "") or "")))
    elif tool == "strings":
        found.coordinate = "offset"
        for row in _rows(data, "strings"):
            offset = _hex(row.get("offset"))
            if offset is not None:
                _offset_root(found, offset, values=(row.get("text"),))
    elif tool == "floss":
        for row in _rows(data, "strings"):
            text = row.get("string")
            call = _hex(row.get("called_at_rva"))
            if call is not None:
                blob = joins.blob_of.get((found.file, call, _fold(text)))
                if blob is not None:
                    _place(found, blob, values=(text,))
                elif (found.file, call) in joins.blob_calls:
                    found.unplace(BLOB_UNMATCHED, values=(text,))
                else:
                    _place(found, call, values=(text,))
                continue
            at = _hex(row.get("function_rva"))
            if at is not None:
                _place(found, at, values=(text,))
    elif tool == "decode_string_blobs":
        for row in _rows(data, "results"):
            blob = _hex(row.get("rva"))
            if blob is not None:
                _place(found, blob, values=(row.get("text"),))
    elif tool == "resolve_api_hashes":
        for hit in _rows(data, "hits"):
            names = [r.get("name") for r in _rows(hit, "readings")]
            for place in _rows(hit, "occurrences"):
                rva = _hex(place.get("rva"))
                if rva is not None:
                    _place(found, rva, words=names)
    elif tool == "capa":
        for row in _rows(data, "capabilities"):
            tids = _row_techniques(row)
            rule = (row.get("rule"),)
            placed = False
            for address in row.get("addresses") or []:
                if _address_root(found, address, values=rule, techniques=tids):
                    placed = True
            if not placed:
                found.unplace(NOTHING_TO_PLACE.format(tool=tool), values=rule, techniques=tids)
    elif tool == "function_index":
        _read_function_index(found, data)
    elif tool == "transform_bytes":
        _read_transform(found, data)
    elif tool == _UNPACK_TOOL:
        _read_unpack(found, data)
    elif tool == "extract_iocs_with_context":
        for row in _rows(data, "iocs"):
            _address_root(found, row.get("address"), values=(row.get("value"),))
    elif tool == "sandbox_processes":
        for row in _rows(data, "processes"):
            if row.get("pid") is not None:
                found.add(_process(row["pid"]), values=(row.get("command_line"), row.get("name")))
    elif tool in ("sandbox_network", "pcap_summary", "read_pcap_summary"):
        for row in _flow_rows(entry):
            label = _flow_of(row, joins)
            if label is not None:
                found.add(label, values=(row.get("dst"),))
        for row in _rows(data, "dns"):
            name = str(row.get("request") or row.get("query") or row.get("name") or "")
            if name:
                said = name.rstrip(".")
                found.add(DNS_ROOT.format(name=_written(said)), values=(said,))
    elif tool == "extract_dns":
        for line in str(getattr(entry, "output", "") or "").splitlines():
            match = _DNS_NAME_LINE.match(line.strip())
            if match:
                found.add(DNS_ROOT.format(name=match["name"]), values=(match["name"],))
    elif tool in ("sigma_match_sandbox", "sigma_match"):
        for row in _rows(data, "matches"):
            fields = row.get("matched_fields")
            command = (
                str(fields.get("CommandLine") or "").strip() if isinstance(fields, Mapping) else ""
            )
            _command_root(found, command, joins, _row_techniques(row))
    elif tool == "lolbin_lookup":
        tids = _row_techniques(data)
        for command in args.get("command_lines") or []:
            _command_root(found, str(command or "").strip(), joins, tids)
    elif tool == "sandbox_signatures":
        found.reason = SIGNATURE_UNPLACED
    elif tool == ITEMS_TOOL:
        for row in _rows(data, "items"):
            item = str(row.get("id") or "").lower()
            fields = row.get("fields")
            values = (
                [fields.get(key) for key in ("command_line", "name", "process_name")]
                if isinstance(fields, Mapping)
                else []
            )
            label, reason = _item_root(item, joins)
            if label:
                found.add(label, values=[item, *values])
            else:
                found.unplace(reason or ITEM_UNPLACED.format(section="report"), values=[item])
    elif tool == "yara_scan":
        found.coordinate = "offset"
        for row in _rows(data, "matches"):
            tids = _row_techniques(row)
            rule = (row.get("rule"),)
            offsets = 0
            for hit in _rows(row, "strings"):
                for instance in [hit, *_rows(hit, "instances")]:
                    offset = _hex(instance.get("offset"))
                    if offset is None:
                        continue
                    offsets += 1
                    _offset_root(found, offset, values=rule, techniques=tids)
            if not offsets:
                found.add(WHOLE_FILE, values=rule, techniques=tids)
        if not found.roots and not found.first_reason:
            found.add(WHOLE_FILE)
    else:
        placed = False
        for key in _ADDRESS_ARGS:
            if args.get(key) not in (None, "") and _address_root(found, args[key]):
                placed = True
                break
        if not placed:
            for key in _ADDRESS_LIST_ARGS:
                items = args.get(key)
                items = items if isinstance(items, list | tuple) else str(items or "").split(",")
                for item in items:
                    placed = _address_root(found, item) or placed
                if placed:
                    break
        if not placed and any(args.get(key) for key in _NAME_ARGS):
            found.reason = BY_NAME_ONLY
            return found
    if not found.roots and not found.reason:
        found.reason = found.first_reason or NOTHING_TO_PLACE.format(tool=tool or "the tool")
    return found


@dataclass
class RootCount:
    """The distinct roots behind a set of statements, and why the rest gave none.

    ``not_read`` holds one ``<entry id>: no: <reason>`` per cited entry that
    gave no root, and the one sentence for a statement citing nothing.
    """

    roots: list[str] = field(default_factory=list)
    not_read: list[str] = field(default_factory=list)
    _held: set[str] = field(default_factory=set, repr=False, compare=False)
    _said: set[str] = field(default_factory=set, repr=False, compare=False)

    def add(self, roots: Iterable[str], reasons: Iterable[str]) -> None:
        for root in roots:
            if root not in self._held:
                self._held.add(root)
                self.roots.append(root)
        for reason in reasons:
            if reason not in self._said:
                self._said.add(reason)
                self.not_read.append(reason)


class RunRoots:
    """Every entry's roots for one ledger, read once."""

    def __init__(self, ledger: Sequence[Any] | None) -> None:
        entries = list(ledger or ())
        files = _Files(entries)
        self.layouts = layouts_of(entries, files)
        self.layout = self.layouts.get("") or Layout()
        joins = _joins(entries, files)
        self._joins = joins
        # The run's sandbox section index: an item id is read only against it.
        self.items: ItemIndex | None = item_index_of(entries)
        self.entries: dict[str, EntryRoots] = {}
        for entry in entries:
            eid = str(getattr(entry, "id", "") or "").strip().lower()
            if not eid or getattr(entry, "repeated_of", None):
                continue
            file = files.of(entry)
            if file is None:
                self.entries[eid] = EntryRoots(reason=FILE_UNTOLD)
                continue
            found = EntryRoots(
                layout=self.layouts.get(file) or Layout(),
                file=file,
                by_program=id(entry) in files.by_program,
            )
            self.entries[eid] = _read_entry(entry, found, joins)
        for repeat, holder in repeat_holders(entries).items():
            held = self.entries.get(holder) if holder else None
            self.entries[repeat] = held or EntryRoots(reason=REPEAT_LOOP.format(entry=repeat))

    def of_entry(self, entry_id: str) -> EntryRoots:
        eid = str(entry_id or "").strip().lower()
        return self.entries.get(eid) or EntryRoots(reason=NO_ENTRY.format(entry=eid))

    def _named(self, text: str, found: EntryRoots) -> tuple[set[str], list[str]]:
        """The roots ``text`` picks out of ``found``, and why the rows it names give none.

        A number written is read in the coordinate the entry's rows state (a
        file offset for a strings or YARA row, an address otherwise); one that
        names one row so and another in the other coordinate names neither.
        A quoted or backticked value or name, or a name written as an
        identifier in its own case, picks out a root only when that root
        alone holds it; a prose word picks out nothing.
        """
        hits: set[str] = set()
        reasons: dict[str, None] = {}
        layout = found.layout
        if found.by_rva or found.coordinate == "offset":
            from maljan.pipeline.validation import _addresses_written

            for value in _addresses_written(text):
                by_address = {
                    label
                    for rva in layout.rvas_of(value)
                    if (label := found.named(layout.label(rva))) in found.order
                }
                by_offset: set[str] = set()
                offset = layout.rva_of_offset(value)
                for label in (
                    found.named(layout.label(offset)) if offset is not None else "",
                    found.named(FILE_OFFSET_ROOT.format(offset=f"{value:#x}")),
                ):
                    if label and label in found.order:
                        by_offset.add(label)
                primary, other = (
                    (by_offset, by_address)
                    if found.coordinate == "offset"
                    else (by_address, by_offset)
                )
                if primary and not other - primary:
                    hits |= primary
        if found.by_value or found.by_word or found.unplaced_values:
            for match in _QUOTED.finditer(text):
                said = _fold(next(g for g in match.groups() if g is not None))
                held = found.by_value.get(said, set()) | found.by_word.get(said, set())
                unplaced = found.unplaced_values.get(said)
                if len(held) == 1 and unplaced is None:
                    hits |= held
                elif not held and unplaced is not None:
                    reasons[unplaced] = None
        if found.by_name:
            for word in _WORD.findall(text):
                word = word.rstrip(".")
                if _PROSE_WORD.fullmatch(word):
                    continue
                held = found.by_name.get(word, set())
                if len(held) == 1:
                    hits |= held
        return hits, list(reasons)

    def of_item(self, item: str) -> tuple[str, str]:
        """``(root, "")`` for a sandbox item id this run's index holds, or ``("", why none)``."""
        found = str(item or "").strip().lower()
        if self.items is None or not self.items.known(found):
            return "", NO_ITEM.format(item=found)
        return _item_root(found, self._joins)

    def of_statement(self, text: str, entry_ids: Iterable[str]) -> tuple[list[str], list[str]]:
        """``(roots, no: reasons)`` for one statement citing ``entry_ids``.

        The sandbox item ids the statement writes are its citations too, in a
        run whose ledger holds the section index.
        """
        ids = list(dict.fromkeys(str(i).strip().lower() for i in entry_ids if str(i).strip()))
        items = item_ids_in(text) if self.items is not None else []
        if not ids and not items:
            return [], [NO_CITATION]
        roots: dict[str, None] = {}
        reasons: list[str] = []
        for item in items:
            label, reason = self.of_item(item)
            if label:
                roots[label] = None
            else:
                reasons.append(f"{item}: {reason}")
        for eid in ids:
            found = self.of_entry(eid)
            if not found.roots:
                reasons.append(f"{eid}: {found.reason or NOTHING_TO_PLACE.format(tool=eid)}")
                continue
            # An entry of one root, every row of it placed, gives that root.
            if len(found.roots) == 1 and not found.unplaced_values and not found.unplaced:
                roots.update(dict.fromkeys(found.roots))
                continue
            # Otherwise the statement picks its rows out; one picking none out
            # gives no root for the entry: which row it read is not a fact.
            named, unplaced = self._named(text, found)
            roots.update(dict.fromkeys(found.ordered(named)))
            reasons += [f"{eid}: {reason}" for reason in unplaced]
            if not named and not unplaced:
                reasons.append(f"{eid}: {NAMES_NO_ROW.format(entry=eid)}")
        return list(roots), reasons

    def of_assertion(self, entry_id: str, technique_id: str) -> tuple[list[str], list[str]]:
        """``(roots, no: reasons)`` for the rows of an asserting entry that name the technique."""
        found = self.of_entry(entry_id)
        tid = str(technique_id).upper()
        eid = str(entry_id).lower()
        held = found.by_technique.get(tid)
        unplaced = found.unplaced.get(tid)
        if held:
            return found.ordered(held), [f"{eid}: {unplaced}"] if unplaced else []
        if not found.roots:
            return [], [f"{eid}: {found.reason}"]
        if len(found.roots) == 1 and not found.unplaced_values and not unplaced:
            return list(found.roots), []
        return [], [f"{eid}: {unplaced or NO_ROW_NAMES_TECHNIQUE.format(entry=eid)}"]


def run_roots(ledger: Sequence[Any] | None) -> RunRoots:
    """The roots of ``ledger``'s entries, read from that ledger alone.

    No module-level cache: a worker serves many jobs in one process, and entry
    ids repeat across jobs, so nothing read for one job may be handed to
    another. The caller that owns the run reads it once and keeps the result
    for as long as its step lasts; it dies with the step.
    """
    return RunRoots(list(ledger or ()))


def roots_phrase(roots: Sequence[str], not_read: Sequence[str]) -> str:
    """The roots as a row states them: ``one evidence root (0x1a40 in .text)``, or ``""``.

    One root says so in those words and names it; several are counted, and
    listed only in the record (``evidence_roots``); the cited entries whose
    root could not be read are counted beside them. Nothing is said for a row
    with neither.
    """
    if not roots and not not_read:
        return ""
    unread = len(not_read)
    unread_words = f"{unread} citation{'' if unread == 1 else 's'} whose root could not be read"
    if not roots:
        return f"no evidence root read ({unread_words})"
    if len(roots) == 1:
        said = f"one evidence root ({roots[0]})"
    else:
        said = f"{len(roots)} evidence roots"
    return f"{said}, and {unread_words}" if unread else said


def layers_and_roots(layers: int, roots: Sequence[str], not_read: Sequence[str]) -> str:
    """``2 layers, one evidence root (0x1a40 in .text)``: the layer count beside the roots."""
    phrase = roots_phrase(roots, not_read)
    if not phrase:
        return ""
    return f"{layers} layer{'' if layers == 1 else 's'}, {phrase}"

"""Where each piece of evidence comes from: the roots of a ledger entry's facts.

Two analysts that both cite the same string at the same place in the file are
two layers and one piece of evidence. Counting layers alone counts that
string twice. This module states, for every ledger entry, the places in the
sample its facts were read from, so a capability can say how many distinct
places stand behind it beside how many layers named it.

A root is derived from what the entry already holds, never guessed:

* **a place in the image**, written as its offset from the image base and the
  section that holds it (``0x4f58 in .text``): a ``strings`` row's file
  offset, a FLOSS row's call site, a ``decode_string_blobs`` row's blob, a
  ``resolve_api_hashes`` occurrence, a capa match address, a function index
  row, an address a decompile, disassembly or memory read was given, an
  address a Ghidra IOC row states. A FLOSS row whose call site the blob
  decoder ties to a blob (``floss.called_at_rva``) has the blob as its root,
  so the two tools reading one encoded string are one root;
* **a table of the file**: the PE header, the import table, the export
  table, the resource table, the debug directory, the overlay, a section by
  name (``pe_info``, and a disassembler's import or export listing);
* **a sandbox process** (``sandbox process 84``), the process a Sigma match's
  command line or a LOLBin hit's command line belongs to;
* **a network flow** (``network flow tcp to 192.0.2.1:443``), the same label
  whether the sandbox or the capture states it, and a DNS query by name;
* **the whole file**: hashes, file identification, signing, a file
  reputation answer.

An entry whose root cannot be read has none, and says why in a ``no:``
sentence: a reference lookup reads nothing of the sample, a failed call read
nothing, a tool whose answer carries no offset, address, section, event or
flow has nothing to place.

A statement's roots are those of the entries it cites. An entry holding one
root gives it. An entry holding several gives the ones the statement names:
by an address it writes, by a quoted value equal to a row's text, or by a
name a row carries (an import, an export, a section, a resolved Windows
name). One that names none of them has shown one row of the entry, which
one unknown: its root is ``an unnamed row of ev_0007``, the same for every
statement citing the entry so, and never the entry's whole set of rows.

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

from maljan.schemas.evidence import repeat_holders

WHOLE_FILE = "the whole file"
PE_HEADER = "the PE header"
IMPORT_TABLE = "the import table"
EXPORT_TABLE = "the export table"
RESOURCE_TABLE = "the resource table"
DEBUG_DIRECTORY = "the debug directory"
OVERLAY = "the overlay"

NO_ENTRY = "no: {entry} is not an entry of this run's ledger"
NO_CITATION = "no: the statement cites no ledger entry"
FAILED = "no: the call failed, so it read nothing"
REFERENCE = "no: {tool} is a reference lookup and reads nothing of the sample"
NOTHING_TO_PLACE = "no: {tool}'s answer carries no offset, address, section, event or flow to place"
BY_NAME_ONLY = "no: the call names its function by name, not by address"
REPEAT_LOOP = "no: {entry} repeats an entry that holds no answer"
SIGNATURE_UNPLACED = "no: a sandbox signature names no process or event"
MATCH_UNPLACED = "no: the match names no command line of a process the sandbox recorded"

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


_WORD = re.compile(r"[A-Za-z_.$?@][\w.$?@]*")
_QUOTED = re.compile(r"`([^`\n]+)`|\"([^\"\n]+)\"|“([^”\n]+)”|'([^'\n]{2,})'")
# A capture's packet line and a DNS name line, as the network server writes them.
_PACKET_LINE = re.compile(
    r"^Packet \d+: (?P<src>\S+) -> (?P<dst>\S+) \((?P<proto>[A-Za-z]+) \d+->(?P<port>\d+)\)"
)
_DNS_NAME_LINE = re.compile(r"^(?P<name>(?:[A-Za-z0-9_-]+\.)+[A-Za-z0-9_-]+)\.?$")
_HEX_TEXT = re.compile(r"\s*(?:0x)?([0-9a-fA-F]{1,16})\s*")
# An image base sits on a 64 KiB boundary.
_BASE_ALIGNMENT = 0x10000
# A disassembler's function header: the function's size in bytes, then its name.
_SIZE_HEADER = re.compile(r"^[^\w\n]*(\d+): [^\s(]+ \(", re.MULTILINE)


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


@dataclass(frozen=True)
class _Section:
    name: str
    rva: int
    size: int
    raw: int
    raw_size: int


@dataclass
class Layout:
    """The section table and the image bases the run's answers state."""

    sections: tuple[_Section, ...] = ()
    bases: tuple[int, ...] = ()
    # ``(begin, end, function start)`` per range a reader states, offsets from
    # the image base, end exclusive: the function index's exception-directory
    # ranges, a disassembler's stated function size, Ghidra's function hash.
    # A sample can shape what a reader states, so a range is used only when
    # it lies inside one section of the section table (``_inside_a_section``).
    functions: tuple[tuple[int, int, int], ...] = ()
    _starts: list[int] = field(default_factory=list)
    _raw_starts: list[int] = field(default_factory=list)
    _by_raw: list[_Section] = field(default_factory=list)
    # The ranges cut into disjoint segments, each with the one function every
    # range holding it names, or ``None`` where ranges of two functions
    # overlap: ``_cuts[i]`` begins segment ``i``, ``_owners[i]`` owns it.
    _cuts: list[int] = field(default_factory=list)
    _owners: list[int | None] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.sections = tuple(sorted(self.sections, key=lambda s: s.rva))
        self._starts = [s.rva for s in self.sections]
        self._by_raw = sorted((s for s in self.sections if s.raw_size > 0), key=lambda s: s.raw)
        self._raw_starts = [s.raw for s in self._by_raw]
        self.functions = tuple(
            sorted({r for r in self.functions if self._inside_a_section(r[0], r[1])})
        )
        self._cut_segments()

    def _inside_a_section(self, begin: int, end: int) -> bool:
        """Whether ``[begin, end)`` lies inside one section, no larger than it."""
        if end <= begin:
            return False
        section = self.section_at(begin)
        return section is not None and section is self.section_at(end - 1)

    def _cut_segments(self) -> None:
        """One sweep over the range ends: O(n log n) to build, O(log n) to look up.

        The cost of a lookup does not depend on how long a stated range is.
        """
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
        """The start of the function a stated range puts ``rva`` in, or ``None``.

        Found by bisection over the cut segments. A place ranges of two
        different functions both hold, wholly or in part, is in neither, since
        which one is not a fact.
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

    def rvas_of(self, value: int) -> list[int]:
        """The offsets from the image base ``value`` reads as, the virtual readings first.

        A value at or above a base the run stated reads as a virtual address.
        With a section table, a reading lying in no section is dropped when
        another reading does lie in one.
        """
        readings = [value - base for base in self.bases if value >= base]
        readings.append(value)
        if self.sections:
            placed = [r for r in readings if self.section_at(r) is not None]
            if placed:
                return list(dict.fromkeys(placed))
        return list(dict.fromkeys(readings))

    def _place_label(self, rva: int) -> str:
        if not self.sections:
            return f"{rva:#x}"
        section = self.section_at(rva)
        return f"{rva:#x} in {section.name}" if section else f"{rva:#x} outside every section"

    def label(self, rva: int) -> str:
        """A place as its root is written: the offset from the image base and its section.

        A place inside a function a reader states the range of is that
        function: ``function 0x3868 in .text``. Two places in one function with
        no range stated stay two roots.
        """
        start = self.function_at(rva)
        if start is not None:
            return f"function {self._place_label(start)}"
        return self._place_label(rva)


@dataclass
class EntryRoots:
    """One entry's roots, and how a statement citing it can name each."""

    roots: list[str] = field(default_factory=list)
    reason: str = ""
    by_rva: dict[int, str] = field(default_factory=dict)
    by_value: dict[str, set[str]] = field(default_factory=dict)
    by_word: dict[str, set[str]] = field(default_factory=dict)
    by_technique: dict[str, set[str]] = field(default_factory=dict)
    # The techniques a row names that the row gives no root for, with why.
    unplaced: dict[str, str] = field(default_factory=dict)
    # Each root's position in ``roots``: membership and order by dict.
    order: dict[str, int] = field(default_factory=dict)

    def ordered(self, roots: set[str]) -> list[str]:
        """``roots`` in the order this entry holds them."""
        return sorted(roots, key=lambda r: self.order.get(r, len(self.order)))

    def add(
        self,
        root: str,
        *,
        rva: int | None = None,
        values: Iterable[Any] = (),
        words: Iterable[Any] = (),
        techniques: Iterable[str] = (),
    ) -> None:
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
        for tid in techniques:
            self.by_technique.setdefault(tid, set()).add(root)


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


def layout_of(entries: Iterable[Any]) -> Layout:
    """The section table and image bases the ledger states, read once."""
    sections: dict[str, _Section] = {}
    bases: list[int] = []
    # Ranges as the tools wrote them: (begin, end, start), each an address.
    stated: list[tuple[int, int, int]] = []
    for entry in entries:
        if getattr(entry, "ok", True) is False or getattr(entry, "repeated_of", None):
            continue
        stated.extend(_stated_ranges(entry))
        data = _structured(entry)
        if not isinstance(data, Mapping):
            continue
        for holder in (data, data.get("meta")):
            if not isinstance(holder, Mapping):
                continue
            for key in ("image_base", "imagebase"):
                base = _hex(holder.get(key)) if holder.get(key) is not None else None
                if base and base % _BASE_ALIGNMENT == 0 and base not in bases:
                    bases.append(base)
        if _tool(entry) != "pe_info":
            continue
        for row in _rows(data, "sections"):
            rva = _hex(row.get("virtual_address"))
            name = str(row.get("name") or "").strip()
            if rva is None or not name or name in sections:
                continue
            sections[name] = _Section(
                name=name,
                rva=rva,
                size=int(row.get("virtual_size") or 0),
                raw=int(row.get("raw_offset") or 0),
                raw_size=int(row.get("raw_size") or 0),
            )
    plain = Layout(sections=tuple(sections.values()), bases=tuple(bases))
    functions: list[tuple[int, int, int]] = []
    for begin, end, start in stated:
        offset = plain.rvas_of(start)[0]
        shift = start - offset
        if end > begin and begin - shift >= 0:
            functions.append((begin - shift, end - shift, offset))
    return Layout(sections=plain.sections, bases=plain.bases, functions=tuple(functions))


def _stated_ranges(entry: Any) -> list[tuple[int, int, int]]:
    """The function ranges one entry states, as ``(begin, end, start)`` addresses.

    The function index's ``function_ranges`` (the exception directory's
    ranges, by function); Ghidra's function hash (its address and size in
    bytes); a disassembly of a function whose header states the function's
    size, from the address the call was given.
    """
    tool = _tool(entry)
    data = _structured(entry)
    out: list[tuple[int, int, int]] = []
    if tool == "function_index" and isinstance(data, Mapping):
        ranges = data.get("function_ranges")
        for start, spans in ranges.items() if isinstance(ranges, Mapping) else ():
            first = _hex(start)
            for span in spans if isinstance(spans, list) else ():
                if first is not None and isinstance(span, list | tuple) and len(span) == 2:
                    begin, end = _hex(span[0]), _hex(span[1])
                    if begin is not None and end is not None:
                        out.append((begin, end, first))
    elif tool == "get_function_hash" and isinstance(data, Mapping):
        start = _hex(data.get("address"))
        size = data.get("size_bytes")
        if start is not None and isinstance(size, int) and size > 1:
            out.append((start, start + size, start))
    elif tool == "disassemble_function":
        args = getattr(entry, "args", None) or {}
        start = next((_hex(args[k]) for k in _ADDRESS_ARGS if args.get(k) not in (None, "")), None)
        match = _SIZE_HEADER.search(str(getattr(entry, "output", "") or "")[:4000])
        if start is not None and match:
            out.append((start, start + int(match.group(1)), start))
    return out


@dataclass
class _Joins:
    """Facts one answer states that place another's rows: read in a first pass."""

    blob_of_call: dict[int, int] = field(default_factory=dict)
    process_of_command: dict[str, int] = field(default_factory=dict)


def _joins(entries: Iterable[Any]) -> _Joins:
    found = _Joins()
    for entry in entries:
        tool = _tool(entry)
        data = _structured(entry)
        if tool == "decode_string_blobs":
            for row in _rows(data, "results"):
                link = row.get("floss")
                call = _hex(link.get("called_at_rva")) if isinstance(link, Mapping) else None
                blob = _hex(row.get("rva"))
                if call is not None and blob is not None:
                    found.blob_of_call.setdefault(call, blob)
        elif tool == "sandbox_processes":
            for row in _rows(data, "processes"):
                command = str(row.get("command_line") or "").strip()
                if command and isinstance(row.get("pid"), int):
                    found.process_of_command.setdefault(command, int(row["pid"]))
    return found


def _process(pid: Any) -> str:
    return f"sandbox process {pid}"


def _flow(proto: Any, dst: Any, port: Any) -> str:
    return f"network flow {str(proto or '').lower()} to {dst}:{port}"


def _place(found: EntryRoots, layout: Layout, rva: int, **kwargs: Any) -> None:
    found.add(layout.label(rva), rva=rva, **kwargs)


def _address_root(found: EntryRoots, layout: Layout, value: Any, **kwargs: Any) -> bool:
    """Add the root of an address a tool wrote, read as its own coordinates allow."""
    number = _hex(value)
    if number is None:
        return False
    readings = layout.rvas_of(number)
    _place(found, layout, readings[0], **kwargs)
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
            found.add(f"section {name}", words=(name,))
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


def _read_entry(entry: Any, layout: Layout, joins: _Joins) -> EntryRoots:
    """One entry's roots, read from its own answer and arguments."""
    found = EntryRoots()
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
        for row in _rows(data, "strings"):
            offset = _hex(row.get("offset"))
            rva = layout.rva_of_offset(offset) if offset is not None else None
            if rva is not None:
                _place(found, layout, rva, values=(row.get("text"),))
            elif offset is not None:
                found.add(f"file offset {offset:#x}", values=(row.get("text"),))
    elif tool == "floss":
        for row in _rows(data, "strings"):
            call = _hex(row.get("called_at_rva"))
            blob = joins.blob_of_call.get(call) if call is not None else None
            at = blob if blob is not None else call
            if at is None:
                at = _hex(row.get("function_rva"))
            if at is not None:
                _place(found, layout, at, values=(row.get("string"),))
    elif tool == "decode_string_blobs":
        for row in _rows(data, "results"):
            blob = _hex(row.get("rva"))
            if blob is not None:
                _place(found, layout, blob, values=(row.get("text"),))
    elif tool == "resolve_api_hashes":
        for hit in _rows(data, "hits"):
            names = [r.get("name") for r in _rows(hit, "readings")]
            for place in _rows(hit, "occurrences"):
                rva = _hex(place.get("rva"))
                if rva is not None:
                    _place(found, layout, rva, words=names)
    elif tool == "capa":
        for row in _rows(data, "capabilities"):
            tids = _row_techniques(row)
            rule = (row.get("rule"),)
            placed = False
            for address in row.get("addresses") or []:
                if _address_root(found, layout, address, values=rule, techniques=tids):
                    placed = True
            if not placed:
                for tid in tids:
                    found.unplaced.setdefault(tid, NOTHING_TO_PLACE.format(tool=tool))
    elif tool == "function_index":
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
            _place(found, layout, rva, words=words, values=values)
    elif tool == "extract_iocs_with_context":
        for row in _rows(data, "iocs"):
            _address_root(found, layout, row.get("address"), values=(row.get("value"),))
    elif tool == "sandbox_processes":
        for row in _rows(data, "processes"):
            if row.get("pid") is not None:
                found.add(_process(row["pid"]), values=(row.get("command_line"), row.get("name")))
    elif tool in ("sandbox_network", "pcap_summary"):
        rows = _rows(data, "conversations")
        rows = [*rows, *({**r, "proto": "tcp"} for r in _rows(data, "tcp"))]
        rows = [*rows, *({**r, "proto": "udp"} for r in _rows(data, "udp"))]
        for row in rows:
            port = row.get("dport")
            if row.get("dst") and port is not None:
                found.add(_flow(row.get("proto"), row["dst"], port), values=(row["dst"],))
        for row in _rows(data, "dns"):
            name = str(row.get("request") or row.get("query") or row.get("name") or "")
            if name:
                found.add(f"DNS query {name.rstrip('.')}", values=(name.rstrip("."),))
    elif tool == "read_pcap_summary":
        for line in str(getattr(entry, "output", "") or "").splitlines():
            match = _PACKET_LINE.match(line.strip())
            if match:
                found.add(
                    _flow(match["proto"], match["dst"], match["port"]), values=(match["dst"],)
                )
    elif tool == "extract_dns":
        for line in str(getattr(entry, "output", "") or "").splitlines():
            match = _DNS_NAME_LINE.match(line.strip())
            if match:
                found.add(f"DNS query {match['name']}", values=(match["name"],))
    elif tool in ("sigma_match_sandbox", "sigma_match"):
        for row in _rows(data, "matches"):
            fields = row.get("matched_fields")
            command = (
                str(fields.get("CommandLine") or "").strip() if isinstance(fields, Mapping) else ""
            )
            pid = joins.process_of_command.get(command)
            if pid is not None:
                found.add(_process(pid), values=(command,), techniques=_row_techniques(row))
            else:
                for tid in _row_techniques(row):
                    found.unplaced.setdefault(tid, MATCH_UNPLACED)
        if not found.roots:
            found.reason = MATCH_UNPLACED
    elif tool == "lolbin_lookup":
        tids = _row_techniques(data)
        for command in args.get("command_lines") or []:
            pid = joins.process_of_command.get(str(command or "").strip())
            if pid is not None:
                found.add(_process(pid), values=(command,), techniques=tids)
        if not found.roots:
            found.reason = MATCH_UNPLACED
    elif tool == "sandbox_signatures":
        found.reason = SIGNATURE_UNPLACED
    elif tool == "yara_scan":
        for row in _rows(data, "matches"):
            tids = _row_techniques(row)
            placed = False
            for hit in _rows(row, "strings"):
                for instance in [hit, *_rows(hit, "instances")]:
                    offset = _hex(instance.get("offset"))
                    if offset is None:
                        continue
                    rva = layout.rva_of_offset(offset)
                    label = layout.label(rva) if rva is not None else f"file offset {offset:#x}"
                    found.add(label, rva=rva, values=(row.get("rule"),), techniques=tids)
                    placed = True
            if not placed:
                found.add(WHOLE_FILE, values=(row.get("rule"),), techniques=tids)
        if not found.roots:
            found.add(WHOLE_FILE)
    else:
        placed = False
        for key in _ADDRESS_ARGS:
            if args.get(key) not in (None, "") and _address_root(found, layout, args[key]):
                placed = True
                break
        if not placed:
            for key in _ADDRESS_LIST_ARGS:
                items = args.get(key)
                items = items if isinstance(items, list | tuple) else str(items or "").split(",")
                for item in items:
                    placed = _address_root(found, layout, item) or placed
                if placed:
                    break
        if not placed and any(args.get(key) for key in _NAME_ARGS):
            found.reason = BY_NAME_ONLY
            return found
    if not found.roots and not found.reason:
        found.reason = NOTHING_TO_PLACE.format(tool=tool or "the tool")
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
        self.layout = layout_of(entries)
        joins = _joins(entries)
        self.entries: dict[str, EntryRoots] = {}
        for entry in entries:
            eid = str(getattr(entry, "id", "") or "").strip().lower()
            if eid and not getattr(entry, "repeated_of", None):
                self.entries[eid] = _read_entry(entry, self.layout, joins)
        for repeat, holder in repeat_holders(entries).items():
            held = self.entries.get(holder) if holder else None
            self.entries[repeat] = held or EntryRoots(reason=REPEAT_LOOP.format(entry=repeat))

    def of_entry(self, entry_id: str) -> EntryRoots:
        eid = str(entry_id or "").strip().lower()
        return self.entries.get(eid) or EntryRoots(reason=NO_ENTRY.format(entry=eid))

    def _named(self, text: str, found: EntryRoots) -> set[str]:
        hits: set[str] = set()
        if found.by_rva:
            from maljan.pipeline.validation import _addresses_written

            for value in _addresses_written(text):
                candidates = [*self.layout.rvas_of(value)]
                offset = self.layout.rva_of_offset(value)
                if offset is not None:
                    candidates.append(offset)
                for rva in candidates:
                    # The root this address is: a place, or the function it is in.
                    label = self.layout.label(rva)
                    if label in found.order:
                        hits.add(label)
        if found.by_value:
            for match in _QUOTED.finditer(text):
                said = next(g for g in match.groups() if g is not None)
                hits |= found.by_value.get(_fold(said), set())
        if found.by_word:
            for word in _WORD.findall(text):
                hits |= found.by_word.get(_fold(word.rstrip(".")), set())
        return hits

    def of_statement(self, text: str, entry_ids: Iterable[str]) -> tuple[list[str], list[str]]:
        """``(roots, no: reasons)`` for one statement citing ``entry_ids``."""
        ids = list(dict.fromkeys(str(i).strip().lower() for i in entry_ids if str(i).strip()))
        if not ids:
            return [], [NO_CITATION]
        roots: dict[str, None] = {}
        reasons: list[str] = []
        for eid in ids:
            found = self.of_entry(eid)
            if not found.roots:
                reasons.append(f"{eid}: {found.reason or NOTHING_TO_PLACE.format(tool=eid)}")
                continue
            # A statement naming some of the entry's places by an address, a
            # quoted value or a name gives those; naming none, it has shown one
            # piece of the entry, which one unknown: one root, the same for
            # every statement citing the entry so.
            if len(found.roots) == 1:
                roots.update(dict.fromkeys(found.roots))
                continue
            named = self._named(text, found)
            roots.update(dict.fromkeys(found.ordered(named) if named else [unnamed_row(eid)]))
        return list(roots), reasons

    def of_assertion(self, entry_id: str, technique_id: str) -> tuple[list[str], list[str]]:
        """``(roots, no: reasons)`` for the rows of an asserting entry that name the technique."""
        found = self.of_entry(entry_id)
        held = found.by_technique.get(str(technique_id).upper())
        if held:
            return found.ordered(held), []
        eid = str(entry_id).lower()
        if not found.roots:
            return [], [f"{eid}: {found.reason}"]
        if len(found.roots) == 1 and str(technique_id).upper() not in found.unplaced:
            return list(found.roots), []
        # A row naming the technique that gives no place (a capa rule with no
        # address, a Sigma match with no process joined), or no row tied to it:
        # one unnamed row of the entry.
        return [unnamed_row(eid)], []


UNNAMED_ROW = "an unnamed row of {entry}"


def unnamed_row(entry_id: str) -> str:
    """The root of a citation of a many-row entry that names none of its rows."""
    return UNNAMED_ROW.format(entry=str(entry_id).strip().lower())


def run_roots(ledger: Sequence[Any] | None) -> RunRoots:
    """The roots of ``ledger``'s entries, read from that ledger alone.

    No module-level cache: a worker serves many jobs in one process, and entry
    ids repeat across jobs, so nothing read for one job may be handed to
    another. The caller that owns the run reads it once and keeps the result
    for as long as its step lasts; it dies with the step.
    """
    return RunRoots(list(ledger or ()))


def roots_phrase(roots: Sequence[str], not_read: Sequence[str]) -> str:
    """The roots as a row states them: ``one evidence root (0x4f58 in .text)``, or ``""``.

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
    """``2 layers, one evidence root (0x4f58 in .text)``: the layer count beside the roots."""
    phrase = roots_phrase(roots, not_read)
    if not phrase:
        return ""
    return f"{layers} layer{'' if layers == 1 else 's'}, {phrase}"

"""The job's sandbox report as sections of items, each item with an id a claim can cite.

The report the run holds — the CAPE-shaped dict every sandbox reader takes,
whichever sandbox produced it (``providers.cape_view``) — is read into fixed
sections: the processes, their API calls, the file operations, the registry
operations, the network rows, the signatures, the dropped files, the mutexes,
the executed commands, the services, the generic events, the per-process API
counts, the platform channels, the screenshots, and the blocks a raw CAPE
report adds (its extracted configurations and payloads, the resolved API
names, the Suricata alerts and the process dumps; its process tree gives
parent links, not items of its own). Nothing is summarised,
ranked or labelled: an item is one row of the report, answered with the
report's own fields and the path it came from.

Each item has an id that is stable for one report:

* a process is ``proc:<pid>``, its pid as the report writes it (``pid``, or
  ``process_id`` where the report names it so); the second process with the
  same pid is ``proc:<pid>.2`` and so on, and a process with no pid the report
  states is ``proc:p<position>`` (in a report the platform rendered from its
  normalised model, a pid or parent of 0 is the model's "not stated");
* every other item is ``<prefix>:<n>``, its 1-based position in the section,
  the section's report lists read in a fixed order (``net:3`` is the third
  network row, counting the DNS rows first, then the hosts, the HTTP requests,
  the TCP and UDP endpoints, the domains, the ICMP and the TLS rows: the order
  the ``sandbox_network`` view lists them in, so its rows and the items agree).

A section the report does not carry has no count but a ``no:`` sentence
saying why: the report lists it as unavailable from its sandbox (a Triage
report has no registry timeline and no API calls), or the report holds none
of the lists the section is read from, or the reader that produced the
report can fill none of them (``schemas.sandbox_report.normaliser_reading``).
A carried section with no rows counts zero; that is what the sandbox reported.

An item id is read only where it is cited: in brackets, or in a citing field
(:data:`ITEM_ID_RE` needs a token boundary on both sides, so the tail of a
host and port such as ``c2.example.net:443`` is never one). A report check
cites an item through :class:`ItemCitations`, which holds the item's own
text, so a value said under an item citation is looked for in that item.

The index (:func:`section_index`) is one ledger entry the triage pack records
once per run, before the analysts start (``SECTIONS_TOOL``). It states each
section's count, or its ``no:``, and the process ids, so an item id a claim
cites can be checked against the run (:class:`ItemIndex`) from the ledger
alone. Items are read one at a time from the report's own lists, never
copied as a whole: counting a section is a sum of list lengths, an item is
found by its position, and a filtered read is one pass over the section.
"""

from __future__ import annotations

import bisect
import re
from collections.abc import Collection, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

# The tool name of the pack's index entry, and of the query tool beside it.
SECTIONS_TOOL = "sandbox_sections"
ITEMS_TOOL = "sandbox_items"

# The sections, their id prefixes, in the order the index lists them.
SECTION_PREFIXES: dict[str, str] = {
    "processes": "proc",
    "api_calls": "call",
    "files": "file",
    "registry": "reg",
    "network": "net",
    "signatures": "sig",
    "dropped": "drop",
    "mutexes": "mutex",
    "commands": "cmd",
    "services": "svc",
    "events": "event",
    "apistats": "apistat",
    "channels": "chan",
    "screenshots": "shot",
    "cape": "cape",
    "resolved_apis": "rapi",
    "alerts": "alert",
    "procdumps": "dump",
}
SECTION_OF_PREFIX: dict[str, str] = {prefix: name for name, prefix in SECTION_PREFIXES.items()}

# An item id as a claim writes it. The process form takes the pid, a repeat's
# ``.k`` and the positional ``p<n>`` of a process with no pid.
# Nothing that continues a name, a path, a URL's query or fragment may stand
# before it (a word character, ``.``, ``/``, ``\``, ``@``, ``-``, ``:``, ``?``,
# ``#``, ``&``, ``=`` or ``%``), and no word character, ``:`` or ``.<digit>``
# after it: ``http://h/?a=net:4`` and ``C:\Users\x\file:3`` hold no item.
ITEM_ID_RE = re.compile(
    r"(?<![\w./\\@:\-?#&=%])(?:proc:(?:\d{1,20}(?:\.\d{1,9})?|p\d{1,9})"
    r"|(?:" + "|".join(p for p in SECTION_PREFIXES.values() if p != "proc") + r"):\d{1,12})"
    r"(?![\w:]|\.\d)",
    re.IGNORECASE,
)

# The name a sandbox report gives a section in its own ``unavailable`` list
# (``TriageSandboxProvider.UNAVAILABLE``), for the sections it can name.
_UNAVAILABLE_NAMES: dict[str, str] = {
    "api_calls": "calls",
    "registry": "registry",
    "events": "generic_events",
    "apistats": "apistats",
    "screenshots": "screenshots",
}

# The ``behavior.summary`` lists each summary-read section is read from, in order.
_SUMMARY_LISTS: dict[str, tuple[str, ...]] = {
    "files": (
        "files",
        "read_files",
        "write_files",
        "delete_files",
        "modified_files",
        "wrote_files",
    ),
    "registry": ("keys", "read_keys", "write_keys", "delete_keys"),
    "mutexes": ("mutexes",),
    "commands": ("executed_commands",),
    "services": ("created_services", "started_services"),
}

# The network lists, in the order ``sandbox_tools.sandbox_network`` lists them.
NETWORK_KINDS: tuple[str, ...] = ("dns", "hosts", "http", "tcp", "udp", "domains", "icmp", "tls")

# The fields a process's own id and its parent's are read from.
_PID_KEYS = ("pid", "process_id")
_PPID_KEYS = ("ppid", "parent_id")
# The fields an item of each section names its process by, for the pid filter.
_PID_FIELDS: dict[str, tuple[str, ...]] = {
    "processes": _PID_KEYS,
    "api_calls": ("pid", "process_id"),
    "network": ("pid", "procid", "process_id"),
    "events": ("pid", "process_id", "procid"),
    "apistats": ("pid",),
    "channels": ("pid", "process_id"),
    "dropped": ("pids", "pid"),
    "procdumps": ("pid", "process_id"),
}

# The raw CAPE blocks the model does not carry, as the reader declarations name
# them (``schemas.sandbox_report.CAPE_RAW_BLOCKS``).
RAW_PROCESSTREE = "raw.behavior.processtree"

# The model list fields (``schemas.sandbox_report.REPORT_LIST_FIELDS``) each
# section is read from, for a report a known normaliser produced.
SECTION_FIELDS: dict[str, tuple[str, ...]] = {
    "processes": ("processes",),
    "api_calls": ("processes.calls",),
    "files": (
        "summary.files",
        "summary.write_files",
        "summary.modified_files",
        "summary.wrote_files",
        "file_writes",
    ),
    "registry": ("registry",),
    "network": tuple(f"network.{kind}" for kind in NETWORK_KINDS),
    "signatures": ("signatures",),
    "dropped": ("dropped_files",),
    "mutexes": ("summary.mutexes",),
    "commands": ("summary.executed_commands",),
    "services": ("summary.created_services", "summary.started_services"),
    "events": ("generic_events",),
    "apistats": ("apistats",),
    "channels": ("channels",),
    "screenshots": ("screenshots",),
    "cape": ("raw.CAPE",),
    "resolved_apis": ("raw.behavior.summary.resolved_apis",),
    "alerts": ("raw.suricata.alerts",),
    "procdumps": ("raw.procdump",),
}

# The ``no:`` sentences.
NO_UNAVAILABLE = "no: the report lists `{name}` as unavailable from its sandbox"
NO_LISTS = "no: the report holds none of {paths}"
NO_LIST = "no: the report holds no `{path}`"
NO_NORMALISED = "no: the {provider} report as normalised here carries no `{section}`"
NO_OVERVIEW = (
    "no: the {provider} report, read from the Triage overview alone, carries no `{section}`"
)
NO_PID_ROWS = "no: the `{section}` rows name no process"


@dataclass(frozen=True)
class _Reader:
    """What the reader behind a report can fill, and how its reports reach the sections."""

    provider: str
    fills: frozenset[str]
    overview_only: bool
    # Rendered from the normalised model rather than handed over as raw CAPE.
    rendered: bool

    def no(self, section: str) -> str:
        said = NO_OVERVIEW if self.overview_only else NO_NORMALISED
        return said.format(provider=self.provider, section=section)


def _reader(normalised_by: Sequence[str] | None) -> _Reader | None:
    """The reader ``(provider, source_format[, read_from])`` names, or ``None`` when unknown.

    ``read_from`` is what the reader read (``SandboxReport.read_from``,
    ``schemas.sandbox_report.reader_of``): the Triage overview alone or with
    its task reports, a CAPE report's own dict or the model.
    """
    if not normalised_by or len(normalised_by) not in (2, 3):
        return None
    from maljan.schemas.sandbox_report import normaliser_reading

    provider, source_format, *rest = (str(part or "").strip() for part in normalised_by)
    reading = normaliser_reading(source_format, provider, rest[0] if rest else "")
    if reading is None:
        return None
    return _Reader(
        provider=provider or source_format,
        fills=reading.fills,
        overview_only=reading.overview_only,
        rendered=reading.rendered,
    )


def _listed(paths: Sequence[str]) -> str:
    """Report paths as a ``no:`` sentence names them: each as an identifier."""
    return ", ".join(f"`{path}`" for path in paths)


def _digits(value: Any) -> str | None:
    """A pid as the report states it, in digits, or ``None`` where it states none."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return str(value) if 0 <= value < 10**20 else None
    if isinstance(value, str):
        text = value.strip()
        if text.isascii() and text.isdigit() and len(text) <= 20:
            return str(int(text))
    return None


def _first(row: Any, keys: Sequence[str]) -> Any:
    if not isinstance(row, Mapping):
        return None
    for key in keys:
        if row.get(key) not in (None, ""):
            return row.get(key)
    return None


@dataclass(frozen=True)
class _Part:
    """One report list a section reads, under the name the report gives it."""

    kind: str
    path: str
    rows: Sequence[Any]
    # For calls nested under a process: the process item id they belong to.
    process: str = ""


@dataclass
class Section:
    """One section: the report lists it reads, or why it is not carried."""

    name: str
    parts: list[_Part] = field(default_factory=list)
    no: str = ""
    # Process sections only: each row's id, in row order.
    ids: list[str] = field(default_factory=list)

    @property
    def prefix(self) -> str:
        return SECTION_PREFIXES[self.name]

    @property
    def count(self) -> int:
        return self.starts[-1] if self.parts else 0

    @property
    def starts(self) -> list[int]:
        """Each part's first item number less one, then the section's count: read once."""
        held = self.__dict__.get("_starts")
        if held is None or len(held) != len(self.parts) + 1:
            held = [0]
            for part in self.parts:
                held.append(held[-1] + len(part.rows))
            self.__dict__["_starts"] = held
        return held

    def place(self, number: int) -> tuple[int, int] | None:
        """``(part, row)`` of the ``number``-th item, by bisection over the parts."""
        starts = self.starts
        if number < 1 or number > starts[-1]:
            return None
        part = bisect.bisect_left(starts, number) - 1
        return part, number - starts[part] - 1


class Sections:
    """Every section of one report, read once, the rows left where they are.

    ``normalised_by`` is ``(provider, source_format)`` of the reader that
    produced the report (the container's ``sandbox_normalised``). A section
    none of whose lists that reader can fill (``schemas.sandbox_report
    .normaliser_reading``) is not carried, whatever the dict holds: the reader
    writes those lists empty for every report, so a count of them would read
    as an observed absence. ``None`` reads the dict as it stands.
    """

    def __init__(
        self, report: Mapping[str, Any], normalised_by: Sequence[str] | None = None
    ) -> None:
        self.report = report
        self._reading = _reader(normalised_by)
        behavior = report.get("behavior")
        self._behavior: Mapping[str, Any] = behavior if isinstance(behavior, Mapping) else {}
        summary = self._behavior.get("summary")
        self._summary: Mapping[str, Any] = summary if isinstance(summary, Mapping) else {}
        unavailable = report.get("unavailable")
        self._unavailable = (
            {str(name) for name in unavailable or () if isinstance(name, str)}
            if isinstance(unavailable, list)
            else set()
        )
        self.sections: dict[str, Section] = {}
        self._process_rows: dict[str, int] = {}
        self._parent: dict[int, str] = {}
        # Built on the first query that needs them, then kept with the sections.
        self._pid_index: dict[str, dict[str, list[int]]] = {}
        self._signature_index: dict[str, list[int]] | None = None
        for name in SECTION_PREFIXES:
            self.sections[name] = self._read(name)

    # -- reading ---------------------------------------------------------

    def _read(self, name: str) -> Section:
        section = Section(name)
        listed = _UNAVAILABLE_NAMES.get(name)
        if listed and listed in self._unavailable:
            section.no = NO_UNAVAILABLE.format(name=listed)
            return section
        if self._reading is not None and not self._reading.fills.intersection(SECTION_FIELDS[name]):
            section.no = self._reading.no(name)
            return section
        reader = getattr(self, f"_read_{name}", None)
        if reader is not None:
            reader(section)
        else:
            self._read_summary(section)
        return section

    def _list(self, value: Any) -> list[Any] | None:
        return value if isinstance(value, list) else None

    def _read_summary(self, section: Section) -> None:
        keys = _SUMMARY_LISTS[section.name]
        for key in keys:
            rows = self._list(self._summary.get(key))
            if rows is not None:
                section.parts.append(_Part(key, f"behavior.summary.{key}", rows))
        if section.name == "files":
            for key in ("file_writes", "files_written"):
                rows = self._list(self.report.get(key))
                if rows is not None:
                    section.parts.append(_Part(key, key, rows))
                    break
        if not section.parts:
            paths = [f"behavior.summary.{key}" for key in keys]
            if section.name == "files":
                paths.append("file_writes")
            section.no = (
                NO_LIST.format(path=paths[0])
                if len(paths) == 1
                else NO_LISTS.format(paths=_listed(paths))
            )

    def _read_processes(self, section: Section) -> None:
        rows = self._list(self._behavior.get("processes"))
        if rows is None:
            section.no = NO_LIST.format(path="behavior.processes")
            return
        section.parts.append(_Part("processes", "behavior.processes", rows))
        seen: dict[str, int] = {}
        holders: dict[str, list[str]] = {}
        own: list[str | None] = []
        for position, row in enumerate(rows):
            pid = self._stated(_first(row, _PID_KEYS))
            own.append(pid)
            if pid is None:
                item = f"proc:p{position + 1}"
            else:
                seen[pid] = seen.get(pid, 0) + 1
                item = f"proc:{pid}" if seen[pid] == 1 else f"proc:{pid}.{seen[pid]}"
                holders.setdefault(pid, []).append(item)
            section.ids.append(item)
            self._process_rows[item] = position
        # A parent is named only where exactly one process holds its pid, and a
        # process is never its own parent. Where a row states no parent, the
        # report's process tree may: a child nested under exactly one parent.
        tree = self._tree_parents()
        for position, row in enumerate(rows):
            ppid = self._stated(_first(row, _PPID_KEYS))
            if ppid is None and own[position] is not None:
                ppid = tree.get(own[position] or "")
            if ppid is None or ppid == own[position]:
                continue
            if len(holders.get(ppid, ())) == 1:
                self._parent[position] = holders[ppid][0]

    def _stated(self, value: Any) -> str | None:
        """A pid the report states: in digits, and not the rendered model's 0 for "none"."""
        pid = _digits(value)
        if pid == "0" and self._reading is not None and self._reading.rendered:
            return None
        return pid

    def _tree_parents(self) -> dict[str, str]:
        """Each pid the process tree nests under exactly one parent, to that parent; one walk."""
        tree = self._list(self._behavior.get("processtree"))
        if not tree:
            return {}
        if self._reading is not None and RAW_PROCESSTREE not in self._reading.fills:
            return {}
        parents: dict[str, set[str]] = {}
        stack: list[tuple[Any, str | None]] = [(node, None) for node in tree]
        while stack:
            node, parent = stack.pop()
            if not isinstance(node, Mapping):
                continue
            pid = _digits(_first(node, _PID_KEYS))
            if pid is not None and parent is not None and parent != pid:
                parents.setdefault(pid, set()).add(parent)
            children = node.get("children")
            if isinstance(children, list):
                stack.extend((child, pid) for child in children)
        return {pid: next(iter(held)) for pid, held in parents.items() if len(held) == 1}

    def _read_api_calls(self, section: Section) -> None:
        """Each process's own calls, under its id; the flat list only where no process has any.

        A report rendered from the normalised model carries both, and only the
        per-process lists say which process made a call.
        """
        flat = self._list(self._behavior.get("calls"))
        processes = self.sections.get("processes")
        rows = self._list(self._behavior.get("processes"))
        nested = rows is not None and any(
            isinstance(row, Mapping) and self._list(row.get("calls")) for row in rows
        )
        if not nested or rows is None or processes is None or not processes.ids:
            if flat is not None:
                section.parts.append(_Part("calls", "behavior.calls", flat))
            elif rows is None:
                paths = _listed(["behavior.calls", "behavior.processes"])
                section.no = NO_LISTS.format(paths=paths)
            return
        for position, row in enumerate(rows):
            calls = self._list(row.get("calls")) if isinstance(row, Mapping) else None
            if calls:
                section.parts.append(
                    _Part(
                        "calls",
                        f"behavior.processes[{position}].calls",
                        calls,
                        process=processes.ids[position],
                    )
                )

    def _read_network(self, section: Section) -> None:
        network = self.report.get("network")
        if not isinstance(network, Mapping):
            section.no = NO_LIST.format(path="network")
            return
        for kind in NETWORK_KINDS:
            rows = self._list(network.get(kind))
            if rows is not None:
                section.parts.append(_Part(kind, f"network.{kind}", rows))

    def _read_signatures(self, section: Section) -> None:
        rows = self._list(self.report.get("signatures"))
        if rows is None:
            section.no = NO_LIST.format(path="signatures")
            return
        section.parts.append(_Part("signatures", "signatures", rows))

    def _read_dropped(self, section: Section) -> None:
        for key in ("dropped", "dropped_files"):
            rows = self._list(self.report.get(key))
            if rows is not None:
                section.parts.append(_Part(key, key, rows))
                return
        section.no = NO_LISTS.format(paths=_listed(["dropped", "dropped_files"]))

    def _read_events(self, section: Section) -> None:
        rows = self._list(self._behavior.get("generic"))
        if rows is None:
            section.no = NO_LIST.format(path="behavior.generic")
            return
        section.parts.append(_Part("generic", "behavior.generic", rows))

    def _read_apistats(self, section: Section) -> None:
        stats = self._behavior.get("apistats")
        if not isinstance(stats, Mapping):
            section.no = NO_LIST.format(path="behavior.apistats")
            return
        rows = [{"pid": str(pid), "counts": counts} for pid, counts in stats.items()]
        section.parts.append(_Part("apistats", "behavior.apistats", rows))

    def _read_channels(self, section: Section) -> None:
        channels = self.report.get("channels")
        if not isinstance(channels, Mapping):
            section.no = NO_LIST.format(path="channels")
            return
        for name in sorted(str(key) for key in channels):
            rows = self._list(channels.get(name))
            if rows is not None:
                section.parts.append(_Part(name, f"channels[{len(section.parts)}]", rows))

    def _read_screenshots(self, section: Section) -> None:
        rows = self._list(self.report.get("screenshots"))
        if rows is None:
            section.no = NO_LIST.format(path="screenshots")
            return
        section.parts.append(_Part("screenshots", "screenshots", rows))

    def _read_cape(self, section: Section) -> None:
        """The ``CAPE`` block: its lists (configurations, payloads) by name, or the list it is."""
        block = self.report.get("CAPE")
        if isinstance(block, list):
            section.parts.append(_Part("CAPE", "CAPE", block))
            return
        if isinstance(block, Mapping):
            for key in sorted(str(k) for k in block):
                rows = self._list(block.get(key))
                if rows is not None:
                    section.parts.append(_Part(key, f"CAPE.{key}", rows))
            if section.parts:
                return
        section.no = NO_LIST.format(path="CAPE")

    def _read_resolved_apis(self, section: Section) -> None:
        rows = self._list(self._summary.get("resolved_apis"))
        if rows is None:
            section.no = NO_LIST.format(path="behavior.summary.resolved_apis")
            return
        section.parts.append(_Part("resolved_apis", "behavior.summary.resolved_apis", rows))

    def _read_alerts(self, section: Section) -> None:
        suricata = self.report.get("suricata")
        rows = self._list(suricata.get("alerts")) if isinstance(suricata, Mapping) else None
        if rows is None:
            section.no = NO_LIST.format(path="suricata.alerts")
            return
        section.parts.append(_Part("alerts", "suricata.alerts", rows))

    def _read_procdumps(self, section: Section) -> None:
        rows = self._list(self.report.get("procdump"))
        if rows is None:
            section.no = NO_LIST.format(path="procdump")
            return
        section.parts.append(_Part("procdump", "procdump", rows))

    # -- items -----------------------------------------------------------

    def _item(self, section: Section, part: _Part, index: int, number: int) -> dict[str, Any]:
        """One item: its id, the report list it came from, and the row's own fields."""
        row = part.rows[index]
        if section.name == "processes":
            item_id = section.ids[index]
        else:
            item_id = f"{section.prefix}:{number}"
        if section.name == "apistats":
            source = part.path
        elif section.name == "channels":
            source = f"channels.{part.kind}[{index}]"
        else:
            source = f"{part.path}[{index}]"
        item: dict[str, Any] = {"id": item_id, "kind": part.kind, "source": source}
        if isinstance(row, Mapping):
            fields = dict(row)
            if section.name == "processes":
                # A process's calls are the api_calls section's items.
                fields.pop("calls", None)
            item["fields"] = fields
        else:
            item["fields"] = {"value": row}
        if part.process:
            item["process"] = part.process
        if section.name == "processes" and index in self._parent:
            item["parent"] = self._parent[index]
        return item

    def _at(self, section: Section, number: int) -> dict[str, Any] | None:
        placed = section.place(number)
        if placed is None:
            return None
        part, index = placed
        return self._item(section, section.parts[part], index, number)

    def items(self, name: str) -> Iterator[dict[str, Any]]:
        """Every item of the section ``name``, in id order."""
        section = self.sections[name]
        number = 0
        for part in section.parts:
            for index in range(len(part.rows)):
                number += 1
                yield self._item(section, part, index, number)

    def _numbers_of_pid(self, name: str) -> dict[str, list[int]]:
        """Each pid to the numbers of the items of ``name`` that are its: built once per section."""
        held = self._pid_index.get(name)
        if held is not None:
            return held
        section = self.sections[name]
        keys = _PID_FIELDS.get(name, ("pid",))
        index: dict[str, list[int]] = {}
        number = 0
        for part in section.parts:
            owner = part.process.removeprefix("proc:").split(".", 1)[0] if part.process else ""
            for row in part.rows:
                number += 1
                pids = {owner} if owner.isdigit() else set()
                if isinstance(row, Mapping):
                    for key in keys:
                        value = row.get(key)
                        for one in value if isinstance(value, list) else [value]:
                            found = self._stated(one)
                            if found is not None:
                                pids.add(found)
                for pid in pids:
                    index.setdefault(pid, []).append(number)
        self._pid_index[name] = index
        return index

    def _numbers_of_signature(self, mark: str) -> list[int]:
        """The numbers of the signatures ``mark`` names, by item id or by name: indexed once."""
        section = self.sections["signatures"]
        if mark.startswith(f"{section.prefix}:"):
            rest = mark.partition(":")[2]
            if rest.isdigit() and len(rest) <= 12 and section.place(int(rest)) is not None:
                return [int(rest)]
            return []
        if self._signature_index is None:
            names: dict[str, list[int]] = {}
            number = 0
            for part in section.parts:
                for row in part.rows:
                    number += 1
                    if not isinstance(row, Mapping):
                        continue
                    for key in ("name", "signature"):
                        value = row.get(key)
                        if isinstance(value, str):
                            numbers = names.setdefault(value.strip().lower(), [])
                            if not numbers or numbers[-1] != number:
                                numbers.append(number)
            self._signature_index = names
        return list(self._signature_index.get(mark, ()))

    def _number_of(self, section: Section, item_id: str) -> int | None:
        """The item number ``item_id`` names in ``section``, or ``None``."""
        prefix, _, rest = item_id.partition(":")
        if prefix != section.prefix or not rest:
            return None
        if section.name == "processes":
            position = self._process_rows.get(item_id)
            return None if position is None else position + 1
        if not rest.isdigit() or len(rest) > 12:
            return None
        number = int(rest)
        return number if section.place(number) is not None else None

    def query(
        self,
        name: str,
        *,
        pid: str | None = None,
        contains: str = "",
        signature: str = "",
        ids: Sequence[str] = (),
    ) -> Query:
        """The items of ``name`` every given filter keeps.

        Bounds, all in the section's own size: asked ``ids`` are read until as
        many distinct ids as the section has items were read, each found by
        its position, and the rest are counted, not read; a pid or a
        signature is looked up in an index built once per section; only the
        substring filter reads rows, once each, and only the candidates the
        other filters left. An item's dict is built for a kept row only.
        """
        section = self.sections[name]
        found = Query()
        candidates: Collection[int] | None = None
        if ids:
            numbers: dict[int, None] = {}
            seen: set[str] = set()
            # As many distinct ids as the section has items, and one more so an
            # empty section names an id it does not hold.
            budget = max(section.count, 1)
            for position, raw in enumerate(ids):
                if len(seen) >= budget:
                    if section.count:
                        found.not_read = len(ids) - position
                    else:
                        # The section holds nothing, so every id left is missing.
                        found.missing_more = len(ids) - position
                    break
                item_id = str(raw).strip().lower()
                if not item_id or item_id in seen:
                    continue
                seen.add(item_id)
                number = self._number_of(section, item_id)
                if number is None:
                    found.missing.append(item_id)
                else:
                    numbers[number] = None
            candidates = numbers
        if pid is not None:
            held = self._numbers_of_pid(name).get(pid, [])
            candidates = held if candidates is None else [n for n in held if n in candidates]
        mark = signature.strip().lower()
        if mark:
            held = self._numbers_of_signature(mark)
            if candidates is None:
                candidates = held
            else:
                kept = set(candidates)
                candidates = [n for n in held if n in kept]
        needle = contains.lower()
        for number in candidates if candidates is not None else range(1, section.count + 1):
            placed = section.place(number)
            if placed is None:
                continue
            part, index = placed
            row = section.parts[part].rows[index]
            if needle and not _holds_text(_searched(section.name, row), needle):
                continue
            found.items.append(self._item(section, section.parts[part], index, number))
        return found

    def item(self, item_id: str) -> dict[str, Any] | None:
        """The item ``item_id`` names in this report, or ``None``."""
        text = str(item_id or "").strip().lower()
        name = SECTION_OF_PREFIX.get(text.partition(":")[0])
        if name is None:
            return None
        section = self.sections[name]
        number = self._number_of(section, text)
        return None if number is None else self._at(section, number)


@dataclass
class Query:
    """What a query kept, the asked ids the section does not hold, and the asked ids not read."""

    items: list[dict[str, Any]] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    # Asked ids past the one named, of a section that holds no item: missing too.
    missing_more: int = 0
    not_read: int = 0


def _searched(section: str, row: Any) -> Any:
    """What the substring filter reads of a row; a process's calls are their own section's."""
    if section == "processes" and isinstance(row, Mapping):
        return [value for key, value in row.items() if key != "calls"]
    return row


def _holds_text(value: Any, needle: str) -> bool:
    """Whether a string anywhere in ``value`` contains ``needle``, case not counted; one walk."""
    stack = [value]
    while stack:
        current = stack.pop()
        if isinstance(current, str):
            if needle in current.lower():
                return True
        elif isinstance(current, Mapping):
            stack.extend(current.values())
        elif isinstance(current, list | tuple):
            stack.extend(current)
    return False


def names_processes(section: str) -> bool:
    """Whether the rows of ``section`` name the process they belong to, for the pid filter."""
    return section in _PID_FIELDS


def pid_of(value: Any) -> str | None:
    """A pid argument in the digits the items are matched in, or ``None`` when it is none."""
    return _digits(value)


def section_index(
    report: Mapping[str, Any], normalised_by: Sequence[str] | None = None
) -> dict[str, Any]:
    """The index the pack records: each section's count, or its ``no:``, and the process ids."""
    found = Sections(report, normalised_by)
    sections: dict[str, Any] = {}
    for name, section in found.sections.items():
        if section.no:
            sections[name] = {"no": section.no}
            continue
        row: dict[str, Any] = {"items": section.count, "prefix": section.prefix}
        if name == "processes":
            row.update(_compact_process_ids(section.ids))
        sections[name] = row
    return {"sections": sections, "tool": ITEMS_TOOL}


def _ranges(numbers: Iterable[int]) -> list[list[int]]:
    """Sorted numbers as ``[first, last]`` runs of consecutive ones."""
    runs: list[list[int]] = []
    for number in sorted(set(numbers)):
        if runs and number == runs[-1][1] + 1:
            runs[-1][1] = number
        else:
            runs.append([number, number])
    return runs


def _compact_process_ids(ids: Sequence[str]) -> dict[str, Any]:
    """The process ids as runs of consecutive pids and the exceptions to them.

    ``pids`` are the stated pids as ``[first, last]`` runs; ``repeats`` names
    each pid more than one process holds with how many (``proc:<pid>.2`` up to
    that count); ``unstated`` are the positions of the processes with no pid
    as runs (``proc:p<n>``). Every id is one of these, so the index stays the
    size of the runs, not of the processes.
    """
    pids: dict[int, int] = {}
    unstated: list[int] = []
    for item in ids:
        rest = item.removeprefix("proc:")
        if rest.startswith("p"):
            unstated.append(int(rest[1:]))
            continue
        pid = int(rest.split(".", 1)[0])
        pids[pid] = pids.get(pid, 0) + 1
    out: dict[str, Any] = {"pids": _ranges(pids)}
    repeats = [[pid, count] for pid, count in sorted(pids.items()) if count > 1]
    if repeats:
        out["repeats"] = repeats
    if unstated:
        out["unstated"] = _ranges(unstated)
    return out


def process_id_forms(row: Mapping[str, Any]) -> list[str]:
    """The process ids an index row states, as a reader writes them: ``proc:84``, runs, repeats."""
    forms: list[str] = []
    for first, last in _runs_of(row.get("pids")):
        forms.append(f"proc:{first}" if first == last else f"proc:{first} to proc:{last}")
    for pid, count in _pairs_of(row.get("repeats")):
        forms.append(f"proc:{pid}.2" if count == 2 else f"proc:{pid}.2 to proc:{pid}.{count}")
    for first, last in _runs_of(row.get("unstated")):
        forms.append(f"proc:p{first}" if first == last else f"proc:p{first} to proc:p{last}")
    return forms


def _int_pair(value: Any) -> tuple[int, int] | None:
    if (
        isinstance(value, list | tuple)
        and len(value) == 2
        and all(isinstance(v, int) and not isinstance(v, bool) and v >= 0 for v in value)
    ):
        return int(value[0]), int(value[1])
    return None


def _runs_of(value: Any) -> list[tuple[int, int]]:
    pairs = [_int_pair(v) for v in value] if isinstance(value, list) else []
    return [pair for pair in pairs if pair is not None and pair[0] <= pair[1]]


def _pairs_of(value: Any) -> list[tuple[int, int]]:
    pairs = [_int_pair(v) for v in value] if isinstance(value, list) else []
    return [pair for pair in pairs if pair is not None]


def item_ids_in(text: str) -> list[str]:
    """The item ids written in ``text``, lower-cased, once each, in order.

    For a citing field (``evidence_ref``, ``evidence_refs``) only; a statement's
    own words are read for bracketed citations (:func:`cited_item_ids`).
    """
    return list(dict.fromkeys(found.lower() for found in ITEM_ID_RE.findall(text or "")))


_BRACKETED_RE = re.compile(r"\[([^\[\]\n]{1,200})\]")


def cited_item_ids(text: str) -> list[str]:
    """The item ids ``text`` cites in brackets (``[proc:84]``, ``[net:3, ev_0004]``)."""
    found: dict[str, None] = {}
    for group in _BRACKETED_RE.findall(text or ""):
        for part in re.split(r"[,;]", group):
            item = part.strip().lower()
            if is_item_id(item):
                found[item] = None
    return list(found)


def is_item_id(text: str) -> bool:
    """Whether ``text`` is written as an item id."""
    return bool(ITEM_ID_RE.fullmatch(str(text or "").strip()))


@dataclass
class ItemIndex:
    """What a run's index entry says exists: each section's count and the process ids.

    The process ids are held as the index states them, compactly: runs of
    pids, the repeats and the runs of positions with no pid. A lookup is a
    bisection over the runs.
    """

    counts: dict[str, int] = field(default_factory=dict)
    pid_runs: tuple[tuple[int, int], ...] = ()
    repeats: dict[int, int] = field(default_factory=dict)
    unstated_runs: tuple[tuple[int, int], ...] = ()

    @classmethod
    def from_answer(cls, data: Any) -> ItemIndex | None:
        """The index the ``sandbox_sections`` answer ``data`` states, or ``None`` unread."""
        sections = data.get("sections") if isinstance(data, Mapping) else None
        if not isinstance(sections, Mapping):
            return None
        counts: dict[str, int] = {}
        found = cls(counts)
        for name, row in sections.items():
            if name not in SECTION_PREFIXES or not isinstance(row, Mapping):
                continue
            items = row.get("items")
            if isinstance(items, int) and not isinstance(items, bool) and items >= 0:
                counts[str(name)] = items
            if name == "processes":
                found.pid_runs = tuple(sorted(_runs_of(row.get("pids"))))
                found.repeats = dict(_pairs_of(row.get("repeats")))
                found.unstated_runs = tuple(sorted(_runs_of(row.get("unstated"))))
        return found

    @staticmethod
    def _in_runs(runs: tuple[tuple[int, int], ...], number: int) -> bool:
        at = bisect.bisect_right(runs, (number, float("inf"))) - 1
        return at >= 0 and runs[at][0] <= number <= runs[at][1]

    def _process_known(self, rest: str) -> bool:
        if rest.startswith("p"):
            position = rest[1:]
            return position.isdigit() and self._in_runs(self.unstated_runs, int(position))
        pid, _, repeat = rest.partition(".")
        if not pid.isdigit() or len(pid) > 20 or not self._in_runs(self.pid_runs, int(pid)):
            return False
        if not repeat:
            return True
        return repeat.isdigit() and 2 <= int(repeat) <= self.repeats.get(int(pid), 1)

    def known(self, item_id: str) -> bool:
        """Whether ``item_id`` names an item of the run's report."""
        text = str(item_id or "").strip().lower()
        prefix, _, rest = text.partition(":")
        name = SECTION_OF_PREFIX.get(prefix)
        if name is None:
            return False
        if name == "processes":
            return self._process_known(rest)
        if not rest.isdigit() or len(rest) > 12:
            return False
        return 1 <= int(rest) <= self.counts.get(name, 0)

    @property
    def holds_items(self) -> bool:
        """Whether the report has any item to cite."""
        return any(self.counts.values())

    def ids(self) -> Iterator[str]:
        """Every item id the index states, section by section, the processes by pid."""
        for name, prefix in SECTION_PREFIXES.items():
            if name == "processes":
                for first, last in self.pid_runs:
                    for pid in range(first, last + 1):
                        yield f"proc:{pid}"
                        for repeat in range(2, self.repeats.get(pid, 1) + 1):
                            yield f"proc:{pid}.{repeat}"
                for first, last in self.unstated_runs:
                    for position in range(first, last + 1):
                        yield f"proc:p{position}"
                continue
            for number in range(1, self.counts.get(name, 0) + 1):
                yield f"{prefix}:{number}"


def index_entry(entries: Iterable[Any]) -> Any | None:
    """The run's readable ``sandbox_sections`` entry, or ``None``."""
    for entry in entries or ():
        if str(getattr(entry, "tool", "") or "") != SECTIONS_TOOL:
            continue
        if getattr(entry, "ok", True) is False:
            continue
        if isinstance(getattr(entry, "structured", None), Mapping):
            return entry
    return None


def item_index_of(entries: Iterable[Any]) -> ItemIndex | None:
    """The run's item index, read off its ledger, or ``None`` where it holds none."""
    entry = index_entry(entries)
    return ItemIndex.from_answer(entry.structured) if entry is not None else None


class ItemCitations:
    """The run's items as a report check cites them: by the index, read through the report.

    An item is accepted as a citation only where the index states it and its
    own text can be read from the report in hand; its text is what a value
    stated under the citation is looked for in, as an entry's is. Texts are
    read for the ids cited, once each.
    """

    def __init__(self, index: ItemIndex, sections: Sections | None) -> None:
        self.index = index
        self.sections = sections
        self._texts: dict[str, str | None] = {}

    @property
    def holds_items(self) -> bool:
        return self.index.holds_items

    def item(self, item_id: str) -> dict[str, Any] | None:
        text = str(item_id or "").strip().lower()
        if self.sections is None or not self.index.known(text):
            return None
        return self.sections.item(text)

    def text(self, item_id: str) -> str | None:
        """The item's own text, lower-cased, as an entry's is held; ``None`` when unread."""
        key = str(item_id or "").strip().lower()
        if key not in self._texts:
            import json

            found = self.item(key)
            # The row's own fields and the process and parent it names; not the
            # platform's id, kind and source, which no value is read from.
            said = (
                {k: found[k] for k in ("fields", "process", "parent") if k in found}
                if found
                else None
            )
            self._texts[key] = json.dumps(said, default=str).lower() if said else None
        return self._texts[key]

    def known(self, item_id: str) -> bool:
        return self.text(item_id) is not None

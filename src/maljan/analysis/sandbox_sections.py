"""The job's sandbox report as sections of items, each item with an id a claim can cite.

The report the run holds — the CAPE-shaped dict every sandbox reader takes,
whichever sandbox produced it (``providers.cape_view``) — is read into fixed
sections: the processes, their API calls, the file operations, the registry
operations, the network rows, the signatures, the dropped files, the mutexes,
the executed commands, the services, the generic events, the per-process API
counts, the platform channels and the screenshots. Nothing is summarised,
ranked or labelled: an item is one row of the report, answered with the
report's own fields and the path it came from.

Each item has an id that is stable for one report:

* a process is ``proc:<pid>``, its pid as the report writes it (``pid``, or
  ``process_id`` where the report names it so); the second process with the
  same pid is ``proc:<pid>.2`` and so on, and a process with no pid the report
  states is ``proc:p<position>``;
* every other item is ``<prefix>:<n>``, its 1-based position in the section,
  the section's report lists read in a fixed order (``net:3`` is the third
  network row, counting the DNS rows first, then the hosts, the HTTP requests,
  the TCP and UDP endpoints, the domains, the ICMP and the TLS rows: the order
  the ``sandbox_network`` view lists them in, so its rows and the items agree).

A section the report does not carry has no count but a ``no:`` sentence
saying why: the report lists it as unavailable from its sandbox (a Triage
report has no registry timeline and no API calls), or the report holds none
of the lists the section is read from. A carried section with no rows counts
zero; that is what the sandbox reported.

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
}
SECTION_OF_PREFIX: dict[str, str] = {prefix: name for name, prefix in SECTION_PREFIXES.items()}

# An item id as a claim writes it. The process form takes the pid, a repeat's
# ``.k`` and the positional ``p<n>`` of a process with no pid.
ITEM_ID_RE = re.compile(
    r"(?<![\w:])(?:proc:(?:\d{1,20}(?:\.\d{1,9})?|p\d{1,9})"
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
}

# The ``no:`` sentences.
NO_UNAVAILABLE = "no: the report lists `{name}` as unavailable from its sandbox"
NO_LISTS = "no: the report holds none of {paths}"
NO_LIST = "no: the report holds no `{path}`"


def _listed(paths: Sequence[str]) -> str:
    """Report paths as a ``no:`` sentence names them: each as an identifier."""
    return ", ".join(f"`{path}`" for path in paths)


def _digits(value: Any) -> str | None:
    """A pid as the report states it, in digits, or ``None`` where it states none."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return str(value) if value >= 0 else None
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
    """Every section of one report, read once, the rows left where they are."""

    def __init__(self, report: Mapping[str, Any]) -> None:
        self.report = report
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
        for position, row in enumerate(rows):
            pid = _digits(_first(row, _PID_KEYS))
            if pid is None:
                item = f"proc:p{position + 1}"
            else:
                seen[pid] = seen.get(pid, 0) + 1
                item = f"proc:{pid}" if seen[pid] == 1 else f"proc:{pid}.{seen[pid]}"
                holders.setdefault(pid, []).append(item)
            section.ids.append(item)
            self._process_rows[item] = position
        # A parent is named only where exactly one process holds its pid.
        for position, row in enumerate(rows):
            ppid = _digits(_first(row, _PPID_KEYS))
            if ppid is not None and len(holders.get(ppid, ())) == 1:
                self._parent[position] = holders[ppid][0]

    def _read_api_calls(self, section: Section) -> None:
        flat = self._list(self._behavior.get("calls"))
        if flat:
            section.parts.append(_Part("calls", "behavior.calls", flat))
            return
        processes = self.sections.get("processes")
        rows = self._list(self._behavior.get("processes"))
        if rows is None or processes is None:
            if flat is not None:
                section.parts.append(_Part("calls", "behavior.calls", flat))
            else:
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
                        found = _digits(row.get(key))
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
            budget = section.count
            for position, raw in enumerate(ids):
                if len(seen) >= budget:
                    found.not_read = len(ids) - position
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


def pid_of(value: Any) -> str | None:
    """A pid argument in the digits the items are matched in, or ``None`` when it is none."""
    return _digits(value)


def section_index(report: Mapping[str, Any]) -> dict[str, Any]:
    """The index the pack records: each section's count, or its ``no:``, and the process ids."""
    found = Sections(report)
    sections: dict[str, Any] = {}
    for name, section in found.sections.items():
        if section.no:
            sections[name] = {"no": section.no}
            continue
        row: dict[str, Any] = {"items": section.count, "prefix": section.prefix}
        if name == "processes":
            row["ids"] = list(section.ids)
        sections[name] = row
    return {"sections": sections, "tool": ITEMS_TOOL}


def item_ids_in(text: str) -> list[str]:
    """The item ids written in ``text``, lower-cased, once each, in order."""
    return list(dict.fromkeys(found.lower() for found in ITEM_ID_RE.findall(text or "")))


def is_item_id(text: str) -> bool:
    """Whether ``text`` is written as an item id."""
    return bool(ITEM_ID_RE.fullmatch(str(text or "").strip()))


@dataclass
class ItemIndex:
    """What a run's index entry says exists: each section's count and the process ids."""

    counts: dict[str, int] = field(default_factory=dict)
    processes: frozenset[str] = frozenset()
    process_order: tuple[str, ...] = ()

    @classmethod
    def from_answer(cls, data: Any) -> ItemIndex | None:
        """The index the ``sandbox_sections`` answer ``data`` states, or ``None`` unread."""
        sections = data.get("sections") if isinstance(data, Mapping) else None
        if not isinstance(sections, Mapping):
            return None
        counts: dict[str, int] = {}
        order: list[str] = []
        for name, row in sections.items():
            if name not in SECTION_PREFIXES or not isinstance(row, Mapping):
                continue
            items = row.get("items")
            if isinstance(items, int) and not isinstance(items, bool) and items >= 0:
                counts[str(name)] = items
            if name == "processes":
                order = [str(i).lower() for i in row.get("ids") or [] if isinstance(i, str)]
        return cls(counts, frozenset(order), tuple(order))

    def known(self, item_id: str) -> bool:
        """Whether ``item_id`` names an item of the run's report."""
        text = str(item_id or "").strip().lower()
        prefix, _, rest = text.partition(":")
        name = SECTION_OF_PREFIX.get(prefix)
        if name is None:
            return False
        if name == "processes":
            return text in self.processes
        if not rest.isdigit() or len(rest) > 12:
            return False
        return 1 <= int(rest) <= self.counts.get(name, 0)

    @property
    def holds_items(self) -> bool:
        """Whether the report has any item to cite."""
        return any(self.counts.values()) or bool(self.processes)

    def ids(self) -> Iterator[str]:
        """Every item id the index states, in index order."""
        for name, prefix in SECTION_PREFIXES.items():
            if name == "processes":
                yield from self.process_order
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

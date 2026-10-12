"""The neutral sandbox report as the one document every consumer reads.

``SandboxReport`` (``schemas.sandbox_report``) is the neutral form: every
reader fills it, whichever sandbox produced the report. This module lays that
form out as one JSON document, the dict the analysts' inputs, the sandbox
tools, the pack's sections and the rule events read. Where each part of the
form sits in the document is declared once, here (:data:`PLACES`), and a
consumer reads a part through :func:`place` by the part's name, never by a
sandbox's own key.

Two ways a report reaches the document:

* A reader that read a source whose own arrangement is the document's (the
  report a sandbox wrote already uses the document's section names) keeps that
  arrangement: each part as the source published it (``SandboxReport.published``),
  every block with no part of its own under the source's name
  (``SandboxReport.extras``), and the order the source listed them in
  (``SandboxReport.arrangement``). :func:`decompose` cuts a source that way and
  :func:`compose` lays it back out, and the two are each other's inverse: a
  source cut and laid out again is the same document, key for key and in the
  same order (the golden test proves it on every stored report).
* Any other reader fills the parts from what it read, and the document is laid
  out from the form's own fields in the order :func:`compose` declares.

A reader that keeps its source's arrangement
(``ReportReader.keeps_source_arrangement``) cuts its source with
``ReportReader.keep_source``. Where the source names a block by another word
than the document does, the reader declares the rename
(``ReportReader.renames``) and the block reaches the document under the
document's word, in the place the source listed it.
"""

from __future__ import annotations

import bisect
import logging
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from maljan.schemas.sandbox_report import SandboxReport

logger = logging.getLogger(__name__)

Path = tuple[str, ...]

# The behaviour summary's lists, each a part of its own under ``behavior.summary``:
# the eight every document lays out, then the five a document lays out where a
# reader filled them.
SUMMARY_ALWAYS: tuple[str, ...] = (
    "files",
    "write_files",
    "modified_files",
    "wrote_files",
    "mutexes",
    "executed_commands",
    "created_services",
    "started_services",
)
SUMMARY_WHEN_FILLED: tuple[str, ...] = (
    "read_files",
    "delete_files",
    "read_keys",
    "write_keys",
    "delete_keys",
)
SUMMARY_KEYS: tuple[str, ...] = (*SUMMARY_ALWAYS, *SUMMARY_WHEN_FILLED)
NETWORK_KINDS: tuple[str, ...] = ("dns", "http", "tcp", "udp", "hosts", "domains", "tls", "icmp")

# Every part of the form, by name, and where the document holds it.
PLACES: dict[str, Path] = {
    "target": ("target",),
    "processes": ("behavior", "processes"),
    "process_tree": ("behavior", "processtree"),
    "apistats": ("behavior", "apistats"),
    "generic_events": ("behavior", "generic"),
    "calls": ("behavior", "calls"),
    "registry": ("behavior", "summary", "keys"),
    **{f"summary.{key}": ("behavior", "summary", key) for key in SUMMARY_KEYS},
    "resolved_apis": ("behavior", "summary", "resolved_apis"),
    "signatures": ("signatures",),
    **{f"network.{kind}": ("network", kind) for kind in NETWORK_KINDS},
    "network.pcap_local_path": ("network", "pcap_local_path"),
    "dropped_files": ("dropped",),
    "screenshots": ("screenshots",),
    "cti": ("cti",),
    "ttp_tags": ("ttp_tags",),
    "unavailable": ("unavailable",),
    "file_writes": ("file_writes",),
    "synthetic": ("synthetic",),
    "recorded_fixture": ("recorded_fixture",),
    "channels": ("channels",),
    "run_limit": ("run_limit",),
    # What the sandbox extracted from the sample's memory or files: its
    # configurations and payloads, as the sandbox lists them.
    "extracted": ("extracted",),
    # The process memory dumps, and the regions of process memory the sandbox
    # recorded.
    "procdumps": ("procdumps",),
    "memory": ("memory",),
    # The alerts an intrusion detection engine raised on the run's traffic;
    # the engine's other logs stay beside them under ``ids``.
    "ids_alerts": ("ids", "alerts"),
}
_PATH_PLACES: dict[Path, str] = {path: name for name, path in PLACES.items()}

# The places a reader fills with rows as its sandbox published them, with no
# row shape of the platform's own to coerce them into: what a mapping
# (``sandbox.rest.mapping.places``) may point a JSONPath at beside its fixed
# channels.
OPEN_PLACES: tuple[str, ...] = (
    "process_tree",
    "resolved_apis",
    "extracted",
    "procdumps",
    "memory",
    "ids_alerts",
)

# The document's dicts that hold parts, which a source cut by :func:`decompose`
# keeps the order of. Every other value is one part or one extra block, whole.
CONTAINERS: frozenset[Path] = frozenset(
    {(), ("behavior",), ("behavior", "summary"), ("network",), ("ids",)}
)

# What the document holds where a report's sandbox marked it: the platform's
# keys, written by the readers and the providers, never by a sandbox.
SYNTHETIC_KEY = "synthetic"
FIXTURE_KEY = "recorded_fixture"


def _at(document: Any, path: Path) -> tuple[bool, Any]:
    node = document
    for key in path:
        if not isinstance(node, Mapping) or key not in node:
            return False, None
        node = node[key]
    return True, node


# A channel row that holds a whole block a reader kept by reference
# (``{<labels>..., GROUP_ROWS_KEY: <block>}``): read as the block's items, each
# with the row's labels, built one item at a time when it is read
# (:func:`channel_rows`).
GROUP_ROWS_KEY = "block_rows"


def _is_group(row: Any) -> bool:
    return isinstance(row, Mapping) and GROUP_ROWS_KEY in row


class GroupedRows(Sequence[Any]):
    """A channel's rows with each kept block read as its items, built when read.

    Holds the channel's rows by reference and, per row, where its items start:
    one pass over the channel's rows, never over a block's items. An item of a
    kept block is its labels with the item's own fields (or its value), built
    only for the index or slice asked; a plain row is itself.
    """

    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows
        self._starts: list[int] = []
        total = 0
        for row in rows:
            self._starts.append(total)
            total += len(self._block(row)) if _is_group(row) else 1
        self._total = total

    @staticmethod
    def _block(row: Mapping[str, Any]) -> list[Any]:
        block = row[GROUP_ROWS_KEY]
        return block if isinstance(block, list) else [block]

    def __len__(self) -> int:
        return self._total

    def _one(self, index: int) -> Any:
        if index < 0:
            index += self._total
        if not 0 <= index < self._total:
            raise IndexError(index)
        at = bisect.bisect_right(self._starts, index) - 1
        row = self._rows[at]
        if not _is_group(row):
            return row
        item = self._block(row)[index - self._starts[at]]
        labels = {k: v for k, v in row.items() if k != GROUP_ROWS_KEY}
        return {**labels, **item} if isinstance(item, Mapping) else {**labels, "value": item}

    def __getitem__(self, index: Any) -> Any:
        if isinstance(index, slice):
            return [self._one(i) for i in range(*index.indices(self._total))]
        return self._one(int(index))


def channel_rows(held: Any) -> Sequence[Any] | None:
    """A channel's rows as read: a list as it is, a kept block as its items, one block whole.

    ``None`` for nothing held. A list with no kept block is returned as it is.
    """
    if held is None:
        return None
    if not isinstance(held, list):
        return [held]
    if any(_is_group(row) for row in held):
        return GroupedRows(held)
    return held


# A DNS request with several questions is written once: its first question's
# row carries the request's answers (each with the name it answers and its
# type) and other fields and the request's id (``DNS_REQUEST_KEY``), and each
# later question's row names that id (``SAME_REQUEST_KEY``). Every reader reads
# a row's answers through :class:`DnsAnswers`, in memory, so the written report
# stays linear in its size.
#
# The two link keys are the platform's own and no reader writes them: the
# document's one chokepoint (:func:`compose`, through :func:`dns_rows` and
# :func:`_network_without_links`) removes them from the rows of every declared
# network kind (:data:`NETWORK_KINDS`) a reader filled, whatever the reader,
# and mints them itself for the requests a reader expresses structurally
# (``schemas.sandbox_report.SandboxDnsRequest``); a reader that keeps its
# source's arrangement removes them too (:func:`kept_source`). The resolver
# honours a link only in the exact form the chokepoint writes it, and only on
# a row of the DNS rows it was built over, never on any other row. A report
# can never make one name read another's answers.
DNS_REQUEST_KEY = "@dns_request"
SAME_REQUEST_KEY = "@same_request_as"
_LINK_KEYS = (DNS_REQUEST_KEY, SAME_REQUEST_KEY)
# Where the network block keeps, as the source wrote it, a source's DNS value
# that is not a list and that no DNS row reader can read (a status word, a
# number, a boolean, an object naming no name), when the structural requests'
# rows take ``network.dns``: kept in the document and read by no view, parser
# or projection (the raw section tool shows it as written), as such a value is
# under ``network.dns`` where there is no request. A null holds no value and
# is not kept. The platform's own key, reserved as the link keys are: a value
# a source wrote under it is removed wherever the document is built
# (:func:`_network_without_links`), so the key only ever holds what the
# platform put there.
DNS_AS_WRITTEN_KEY = "@dns_as_written"
# The platform's own keys in a document's network block, never a source's.
_RESERVED_NETWORK_KEYS = (DNS_AS_WRITTEN_KEY,)
# The fields a DNS row's name is read from, in this order, the first naming a
# name: an object with none is no DNS row. Every reader of a DNS row's name
# reads it through :func:`dns_row_name`.
DNS_NAME_KEYS = ("request", "query", "hostname", "domain", "name")
# The record type an answer that points one name at another carries, and the
# types whose value is an address.
_ALIAS_TYPE = "cname"
ADDRESS_TYPES = frozenset({"a", "aaaa"})


def _lower(value: Any) -> str:
    return str(value or "").strip().rstrip(".").lower()


def without_dns_links(rows: Any) -> Any:
    """``rows`` with any field under a platform link key removed from a source's DNS row.

    The same list where no row holds one (nothing is copied); otherwise a new
    list in which each row that held one is copied without it. One pass.
    """
    if not isinstance(rows, list):
        return rows
    if not any(isinstance(row, Mapping) and any(k in row for k in _LINK_KEYS) for row in rows):
        return rows
    return [
        {k: v for k, v in row.items() if k not in _LINK_KEYS}
        if isinstance(row, Mapping) and any(k in row for k in _LINK_KEYS)
        else row
        for row in rows
    ]


def _network_without_links(network: dict[str, Any]) -> None:
    """``network``'s rows of every kind with no platform link key, in place.

    One pass over each kind's rows (:func:`without_dns_links`); a kind whose
    rows hold none keeps its list. A value a source wrote under one of the
    platform's own network keys is removed, as a link key is.
    """
    for kind in NETWORK_KINDS:
        if kind in network:
            network[kind] = without_dns_links(network[kind])
    for key in _RESERVED_NETWORK_KEYS:
        network.pop(key, None)


def dns_row_name(row: Any) -> str:
    """The name a DNS row names: the first non-blank string under :data:`DNS_NAME_KEYS`.

    Stripped of surrounding whitespace; empty for a row naming none, or for
    anything that is not an object. The one reading of a DNS row's name.
    """
    if not isinstance(row, Mapping):
        return ""
    for key in DNS_NAME_KEYS:
        name = row.get(key)
        if isinstance(name, str) and name.strip():
            return name.strip()
    return ""


def reads_as_dns_row(value: Any) -> bool:
    """Whether ``value`` is an object a DNS row reader reads: one naming a name.

    A name is what :func:`dns_row_name` reads.
    """
    return bool(dns_row_name(value))


def dns_requests_have_place(report: SandboxReport) -> bool:
    """Whether ``report``'s document can hold the rows of its structural DNS requests.

    A report laid out from the form always can, and so can a kept source with
    no network block (one is made) or with a network object. A kept source
    whose network block is some other value has no place for them.
    """
    arrangement = report.arrangement or {}
    top = arrangement.get("")
    if not top or "network" not in top:
        return True
    return "network" in arrangement or "network" not in report.extras


def dns_rows(rows: Any, requests: Any) -> Any:
    """The document's DNS rows: a reader's own rows with no link key, then each request's rows.

    The one place the platform's request links are written. ``rows`` are the
    rows a reader filled, any link key removed (the same list where none holds
    one); ``requests`` the requests it expressed structurally, each written as
    one row per asked name: the first carries the request's answers and other
    fields, and, where the request asked several names, the request's id
    (``DNS_REQUEST_KEY``), which each later name's row names
    (``SAME_REQUEST_KEY``). Ids count the report's multi-name requests from 0.
    A source's DNS value that is not a list stays as the source wrote it where
    there is no request; where there is, an object a DNS row reader reads
    (:func:`reads_as_dns_row`) is kept as the first row, before the requests'
    rows, and any other value is no row (:func:`compose` keeps it under
    :data:`DNS_AS_WRITTEN_KEY`). Linear in the rows, the names and the
    answers, each held once.
    """
    if requests and not isinstance(rows, list):
        rows = [rows] if reads_as_dns_row(rows) else []
    stripped = without_dns_links(rows)
    if not requests:
        return stripped
    out = list(stripped) if isinstance(stripped, list) else []
    next_id = 0
    for request in requests:
        asked = [
            q
            for q in getattr(request, "questions", None) or []
            if isinstance(q, Mapping) and str(q.get("request") or "")
        ]
        if not asked:
            continue
        request_id: int | None = None
        if len(asked) > 1:
            request_id, next_id = next_id, next_id + 1
        for position, question in enumerate(asked):
            row = {k: v for k, v in question.items() if k not in _LINK_KEYS}
            if position == 0:
                row["answers"] = getattr(request, "answers", None) or []
                extra = getattr(request, "extra", None)
                if extra:
                    row["extra"] = extra
                if request_id is not None:
                    row[DNS_REQUEST_KEY] = request_id
            else:
                row[SAME_REQUEST_KEY] = request_id
            out.append(row)
    return out


def _link(value: Any) -> int | None:
    """A link value in the form a reader writes it: a whole number, never a boolean."""
    return value if isinstance(value, int) and not isinstance(value, bool) else None


class DnsAnswers:
    """The answers each DNS row's name resolved to, read over one list of DNS rows.

    A row of a request with one question has its own answers, as written. A
    question of a request with several is given the answers that answer its
    own name and the names its alias chain leads to, and every answer that
    names no name (which belongs to the whole request, as dev read it), each
    value once.

    A link is honoured only in the exact form the platform writes it: a
    whole-number id held by exactly one first row (``DNS_REQUEST_KEY``), named
    by the later rows (``SAME_REQUEST_KEY``), and never both on one row; and
    only on a row of ``rows`` itself, the DNS rows the object was built over.
    Any other row, a row of another kind or list included, reads its own
    answers, as dev read every row.

    Linear in the rows: one pass finds each request's answers, each request's
    answers are indexed by name once, when first asked, and the work every
    question of a request may cost together, with what it yields, is bounded
    by the request's own size (``_work_left``). A request whose questions share
    more than that (many names aliasing one target, many answers naming no
    name) stops giving answers once the bound is spent: a name is then given
    fewer addresses, never a wrong one, and :meth:`withheld` says how many of
    its request's answers it was not given.
    """

    def __init__(self, rows: Any) -> None:
        firsts: dict[int, int] = {}
        for row in rows if isinstance(rows, list) else []:
            if isinstance(row, Mapping) and SAME_REQUEST_KEY not in row:
                request = _link(row.get(DNS_REQUEST_KEY))
                if request is not None:
                    firsts[request] = firsts.get(request, 0) + 1
        self._records: dict[int, list[Any]] = {}
        self._questions: dict[int, int] = {}
        # The linked rows of ``rows``, by identity; ``rows`` is held so no
        # identity is reused while the object lives.
        self._rows = rows
        self._members: set[int] = set()
        for row in rows if isinstance(rows, list) else []:
            request = self._request_of(row, firsts)
            if request is None:
                continue
            self._members.add(id(row))
            self._questions[request] = self._questions.get(request, 0) + 1
            if DNS_REQUEST_KEY in row:
                answers = row.get("answers")
                self._records[request] = answers if isinstance(answers, list) else []
        self._valid = set(self._records)
        self._index: dict[int, tuple[dict[str, list[Any]], list[Any]]] = {}
        self._work_left = {
            request: 2 * (len(records) + self._questions.get(request, 0)) + 16
            for request, records in self._records.items()
        }
        self._withheld: dict[int, int] = {}
        self.cut = False

    @staticmethod
    def _request_of(row: Any, firsts: Mapping[int, int]) -> int | None:
        """The request id ``row`` is linked by, in the exact form a reader writes, else ``None``."""
        if not isinstance(row, Mapping):
            return None
        first, later = DNS_REQUEST_KEY in row, SAME_REQUEST_KEY in row
        if first == later:
            return None
        request = _link(row.get(DNS_REQUEST_KEY if first else SAME_REQUEST_KEY))
        return request if request is not None and firsts.get(request) == 1 else None

    def _indexed(self, request: int) -> tuple[dict[str, list[Any]], list[Any]]:
        held = self._index.get(request)
        if held is None:
            by_name: dict[str, list[Any]] = {}
            unnamed: list[Any] = []
            for record in self._records.get(request, []):
                name = _lower(record.get("name")) if isinstance(record, Mapping) else ""
                if name:
                    by_name.setdefault(name, []).append(record)
                else:
                    unnamed.append(record)
            held = self._index[request] = (by_name, unnamed)
        return held

    def _linked(self, row: Mapping[str, Any]) -> int | None:
        if id(row) not in self._members:
            return None
        if (DNS_REQUEST_KEY in row) == (SAME_REQUEST_KEY in row):
            return None
        request = _link(row.get(DNS_REQUEST_KEY if DNS_REQUEST_KEY in row else SAME_REQUEST_KEY))
        return request if request in self._valid else None

    def of(self, row: Any) -> list[Any]:
        """The answers ``row``'s name resolved to, each value once, with its type if it has one."""
        if not isinstance(row, Mapping):
            return []
        request = self._linked(row)
        if request is None:
            own = row.get("answers")
            return own if isinstance(own, list) else []
        by_name, unnamed = self._indexed(request)
        found: list[Any] = []
        values: set[str] = set()
        names: set[str] = set()
        read = 0
        stack = [_lower(dns_row_name(row))]

        def keep(record: Any) -> None:
            value = str(record.get("data") or "") if isinstance(record, Mapping) else ""
            if value and value not in values:
                values.add(value)
                kind = record.get("type") if isinstance(record, Mapping) else None
                found.append({"data": value, **({"type": kind} if kind else {})})

        while stack:
            name = stack.pop()
            if not name or name in names:
                continue
            names.add(name)
            for record in by_name.get(name, ()):
                if not self._spend(request):
                    self._withhold(row, request, read)
                    return found
                read += 1
                if _lower(record.get("type")) == _ALIAS_TYPE:
                    stack.append(_lower(record.get("data")))
                keep(record)
        for record in unnamed:
            if not self._spend(request):
                self._withhold(row, request, read)
                return found
            read += 1
            keep(record)
        return found

    def _withhold(self, row: Mapping[str, Any], request: int, read: int) -> None:
        self.cut = True
        self._withheld[id(row)] = max(0, len(self._records.get(request, [])) - read)

    def withheld(self, row: Any) -> int:
        """How many of its request's answers ``row``'s name was not given, the size bound spent."""
        return self._withheld.get(id(row), 0)

    def _spend(self, request: int) -> bool:
        left = self._work_left.get(request, 0)
        if left <= 0:
            return False
        self._work_left[request] = left - 1
        return True


def place(document: Any, name: str, default: Any = None) -> Any:
    """The part ``name`` of ``document``, or ``default`` where the document holds none."""
    found, value = _at(document, PLACES[name])
    return value if found else default


def place_path(name: str) -> str:
    """Where the document holds the part ``name``, as the dotted path a sentence names."""
    return ".".join(PLACES[name])


def renamed(source: Mapping[str, Any], renames: Mapping[str, str]) -> dict[str, Any]:
    """``source`` with each top-level key ``renames`` names under its document word, in place.

    A source that already holds the document's word for a renamed block keeps
    its own block under it, and the renamed one is left under the source's word.
    """
    if not renames:
        return source if isinstance(source, dict) else dict(source)
    taken = set(source)
    out: dict[str, Any] = {}
    for key, value in source.items():
        target = renames.get(key)
        if target is not None and target not in taken:
            out[target] = value
        else:
            out[key] = value
    return out


def kept_source(
    source: Mapping[str, Any], renames: Mapping[str, str]
) -> tuple[dict[str, Any], dict[str, Any], dict[str, list[str]]]:
    """A source cut as :func:`decompose` cuts it, its renamed blocks under the document's words,
    its network rows of every kind with no platform link key (:func:`without_dns_links`).

    What every reader that keeps its source's arrangement uses.
    """
    published, extras, arrangement = decompose(renamed(source, renames))
    for kind in NETWORK_KINDS:
        if f"network.{kind}" in published:
            published[f"network.{kind}"] = without_dns_links(published[f"network.{kind}"])
    return published, extras, arrangement


def decompose(
    source: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, list[str]]]:
    """``(published, extras, arrangement)`` of a source that uses the document's arrangement.

    ``published`` holds each part the source carries, the source's own value;
    ``extras`` every other block, nested as the source nests it in the
    document's dicts; ``arrangement`` the order of the keys of each of those
    dicts. One pass over the source's dicts that hold parts: linear in their
    key count, and no value is copied.
    """
    published: dict[str, Any] = {}
    arrangement: dict[str, list[str]] = {}

    def cut(node: Mapping[str, Any], path: Path) -> dict[str, Any]:
        arrangement[".".join(path)] = list(node)
        rest: dict[str, Any] = {}
        for key, value in node.items():
            at = (*path, key)
            name = _PATH_PLACES.get(at)
            if at in CONTAINERS and isinstance(value, Mapping):
                rest[key] = cut(value, at)
            elif name is not None:
                published[name] = value
            else:
                rest[key] = value
        return rest

    extras = cut(source, ())
    return published, extras, arrangement


def compose(report: SandboxReport) -> dict[str, Any]:
    """The document of ``report``: its source's arrangement where its reader kept one.

    A source with no block at all has no arrangement to keep, and its report is
    laid out from the form like any other.
    """
    if report.arrangement and report.arrangement.get(""):
        document = _arranged(report.published, report.extras, report.arrangement, ())
        if report.recorded_fixture:
            document[FIXTURE_KEY] = True
        # The chokepoint: the network rows with no link key a reader wrote,
        # then the requests it expressed structurally, linked here. A source
        # with no network block gets one to hold them.
        requests = report.network.dns_requests
        have_place = dns_requests_have_place(report)
        if requests and "network" not in document:
            document["network"] = {}
        network = document.get("network")
        if requests and not have_place:
            # One source of truth for whether the rows have a place.
            logger.warning(
                "sandbox report: the source's network block is not an object, so the "
                "reader's %d structural DNS requests have no place in the document.",
                len(requests),
            )
        elif isinstance(network, dict):
            _network_without_links(network)
            if "dns" in network or requests:
                held = network.get("dns", [])
                if (
                    requests
                    and held is not None
                    and not isinstance(held, list)
                    and not reads_as_dns_row(held)
                ):
                    # No row and no fact: kept as written, read by nothing.
                    network[DNS_AS_WRITTEN_KEY] = held
                network["dns"] = dns_rows(held, requests)
        return document
    return _laid_out(report)


def _arranged(
    published: Mapping[str, Any],
    extras: Mapping[str, Any],
    arrangement: Mapping[str, list[str]],
    path: Path,
) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key in arrangement.get(".".join(path), ()):
        at = (*path, key)
        if at in CONTAINERS and ".".join(at) in arrangement:
            inner = extras.get(key)
            out[key] = _arranged(
                published, inner if isinstance(inner, Mapping) else {}, arrangement, at
            )
            continue
        name = _PATH_PLACES.get(at)
        if name is not None and name in published:
            out[key] = published[name]
        elif key in extras:
            out[key] = extras[key]
    return out


def _process_row(process: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "pid": process.pid,
        "ppid": process.ppid,
        "process_name": process.name,
        "command_line": process.command_line,
        "first_seen": process.first_seen,
        "calls": list(process.calls),
    }
    if process.extra:
        row["extra"] = dict(process.extra)
    return row


def _signature_row(signature: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "name": signature.name,
        "description": signature.description,
        "severity": signature.severity,
        "marks": list(signature.marks),
        "ttp_tags": list(signature.ttp_tags),
    }
    if signature.extra:
        row["extra"] = dict(signature.extra)
    return row


def _target(report: SandboxReport) -> dict[str, Any]:
    target = report.target
    row: dict[str, Any] = {
        "sha256": target.sha256,
        "md5": target.md5,
        "name": target.name,
        "file": {"type": target.mime_type, "size": target.size},
    }
    for key in ("sha1", "sha512", "ssdeep"):
        value = getattr(target, key)
        if value:
            row[key] = value
    return row


def _merge_extras(document: dict[str, Any], extras: Mapping[str, Any], path: Path) -> None:
    """``extras`` into ``document``: inside the document's dicts, never over a part."""
    for key, value in extras.items():
        at = (*path, key)
        held = document.get(key)
        if at in CONTAINERS and isinstance(held, dict) and isinstance(value, Mapping):
            _merge_extras(held, value, at)
        elif key not in document:
            document[key] = value


def _laid_out(report: SandboxReport) -> dict[str, Any]:
    """The document of a report read into the form's fields, in the platform's own order.

    The parts every document lays out come first and always, an empty one
    included, because a part missing from the document reads exactly like a
    sandbox that saw nothing; the parts a reader fills only for some sandboxes
    follow, each only where it holds something.
    """
    summary: dict[str, Any] = {"keys": list(report.registry)}
    for key in SUMMARY_ALWAYS:
        summary[key] = list(report.summary.get(key, []))
    for key in SUMMARY_WHEN_FILLED:
        if report.summary.get(key):
            summary[key] = list(report.summary[key])
    if report.resolved_apis:
        summary["resolved_apis"] = list(report.resolved_apis)
    behavior: dict[str, Any] = {
        "processes": [_process_row(p) for p in report.processes],
        "apistats": {pid: dict(stats) for pid, stats in report.apistats.items()},
        "generic": list(report.generic_events),
        "calls": [c for p in report.processes for c in p.calls],
        "summary": summary,
    }
    if report.process_tree:
        behavior["processtree"] = list(report.process_tree)
    network = report.network
    document: dict[str, Any] = {
        "target": _target(report),
        "behavior": behavior,
        "signatures": [_signature_row(s) for s in report.signatures],
        "network": {
            # The chokepoint: no reader's link key on any row, the platform's
            # own links on the DNS rows.
            kind: (
                dns_rows(list(network.dns), network.dns_requests)
                if kind == "dns"
                else without_dns_links(list(getattr(network, kind)))
            )
            for kind in NETWORK_KINDS
        },
        "dropped": list(report.dropped_files),
        "screenshots": list(report.screenshots),
        "cti": dict(report.cti),
        "ttp_tags": sorted({t for s in report.signatures for t in s.ttp_tags}),
        # Named because an empty section from a sandbox that cannot produce it
        # reads exactly like a clean sample; the report renderers say so.
        "unavailable": list(report.unavailable),
        "file_writes": list(report.file_writes),
    }
    if report.synthetic:
        document[SYNTHETIC_KEY] = True
    elif report.recorded_fixture:
        document[FIXTURE_KEY] = True
    if report.channels:
        # Each channel as the reader holds it: a block kept whole stays one block.
        document["channels"] = dict(report.channels)
    if network.pcap_local_path:
        document["network"]["pcap_local_path"] = network.pcap_local_path
    # The run-time limit the sandbox set for the task, where its report says:
    # a limit, not a measured time.
    if report.run_limit_seconds is not None:
        document["run_limit"] = {
            "seconds": int(report.run_limit_seconds),
            "set_by": report.provider,
        }
    for name in ("extracted", "procdumps", "memory"):
        value = getattr(report, name)
        if value:
            document[name] = value
    if report.ids_alerts:
        document["ids"] = {"alerts": report.ids_alerts}
    if report.extras:
        _merge_extras(document, report.extras, ())
        # A reader's extras never hold one of the platform's own network keys.
        for key in _RESERVED_NETWORK_KEYS:
            document["network"].pop(key, None)
    return document


def sandbox_document(report: SandboxReport) -> dict[str, Any]:
    """The document every consumer of ``report`` reads (:func:`compose`)."""
    return compose(report)

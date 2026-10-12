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
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from maljan.schemas.sandbox_report import SandboxReport

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
        "network": {kind: list(getattr(network, kind)) for kind in NETWORK_KINDS},
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
    return document


def sandbox_document(report: SandboxReport) -> dict[str, Any]:
    """The document every consumer of ``report`` reads (:func:`compose`)."""
    return compose(report)

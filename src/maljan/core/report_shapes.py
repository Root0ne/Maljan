"""What a list of rows looks like it holds, read from its rows' keys alone: the shape test.

A sandbox nobody declared still writes its processes, its connections, its DNS
questions and the files it dropped as lists of objects with telling keys. This
module names, for one list, which of those it looks like and which of its keys
plays each part (a process id, its parent, its name ...), from the keys the
list's rows carry and the list's own name. It is used only to *propose* a
declaration (``core.report_proposals`` for an uploaded report,
``core.declaration_proposals`` for a tool's answer): applied silently it would
mint observed facts from a guess, since a list of the guest's processes with
``pid`` keys is not the sample's tree. Nothing a run reads imports it.

Keys are compared without regard to case; the key a part is read from is
returned as the rows write it. Constant work per key.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field

# Each part a row of a kind holds, the consumer's own field name first, then
# the spellings sandboxes write it under (lower case).
_PROCESS_PARTS: dict[str, tuple[str, ...]] = {
    "pid": ("pid", "process_id", "processid"),
    "ppid": (
        "ppid",
        "parent_pid",
        "parent_id",
        "parentid",
        "parentpid",
        "parent_process_id",
        "parentprocessid",
        "parent",
    ),
    "name": ("name", "process_name", "processname", "image", "image_name", "filename"),
    "command_line": ("command_line", "commandline", "cmdline", "cmd", "command"),
}
_FLOW_PARTS: dict[str, tuple[str, ...]] = {
    "dst": (
        "dst",
        "dst_ip",
        "dest_ip",
        "destination_ip",
        "dstip",
        "destip",
        "remote_ip",
        "dest",
        "destination",
    ),
    "dport": (
        "dport",
        "dst_port",
        "dest_port",
        "destination_port",
        "dstport",
        "destport",
        "remote_port",
    ),
}
_PROTOCOL_KEYS = ("protocol", "proto", "transport")
_DNS_PARTS: dict[str, tuple[str, ...]] = {
    "request": ("request", "query", "qname", "domain", "hostname", "name"),
    "type": ("type", "qtype", "query_type", "record_type"),
    "answers": ("answers", "answer", "response", "responses", "resolved", "addresses", "ips"),
}
_DROPPED_PARTS: dict[str, tuple[str, ...]] = {
    "sha256": ("sha256", "sha_256"),
    "name": ("name", "filename", "file_name", "path", "filepath", "file_path"),
    "size": ("size", "file_size", "filesize", "size_bytes"),
}

# The parts a list's rows must all name for it to read as each kind.
_REQUIRED: dict[str, tuple[str, ...]] = {
    "processes": ("pid", "ppid", "name"),
    "dropped_files": ("sha256", "name", "size"),
    "flows": ("dst", "dport"),
    "dns": ("request",),
}
_PARTS: dict[str, dict[str, tuple[str, ...]]] = {
    "processes": _PROCESS_PARTS,
    "dropped_files": _DROPPED_PARTS,
    "flows": _FLOW_PARTS,
    "dns": _DNS_PARTS,
}
# Tried in this order: the most specific key sets first.
KINDS: tuple[str, ...] = ("processes", "dropped_files", "flows", "dns")

_WORD = re.compile(r"[a-z0-9]+")
# DNS rows name a name under keys other lists use too (``name``, ``domain``):
# without a question type or an answer, the list's own name must say DNS.
_DNS_LIST_WORDS = frozenset({"dns", "queries", "query", "lookups", "resolutions"})


@dataclass
class RowShape:
    """What one list of rows reads as: its kind, the key each part is read from, how sure."""

    kind: str
    parts: dict[str, str] = field(default_factory=dict)
    confidence: str = "medium"
    # For flows: the protocol key, and the spelling each of tcp and udp is written in.
    protocol_key: str = ""
    protocols: dict[str, str] = field(default_factory=dict)


def _words(name: str) -> set[str]:
    return set(_WORD.findall(name.lower()))


def row_shape(list_name: str, keys: Iterable[str]) -> RowShape | None:
    """The kind a list named ``list_name`` whose rows carry ``keys`` reads as, or ``None``.

    ``high`` where every part is under the consumer's own field name, ``medium``
    where some part is under another spelling, ``low`` for a DNS list
    recognised by its name alone.
    """
    by_lower: dict[str, str] = {}
    for key in keys:
        if isinstance(key, str):
            by_lower.setdefault(key.lower(), key)
    for kind in KINDS:
        parts: dict[str, str] = {}
        for part, spellings in _PARTS[kind].items():
            found = next((by_lower[s] for s in spellings if s in by_lower), None)
            if found is not None:
                parts[part] = found
        if not all(part in parts for part in _REQUIRED[kind]):
            continue
        if kind == "dns" and not ({"type", "answers"} & set(parts)):
            if not (_words(list_name) & _DNS_LIST_WORDS):
                continue
            shape = RowShape(kind, parts, "low")
        else:
            exact = all(parts[part] == part for part in parts)
            shape = RowShape(kind, parts, "high" if exact else "medium")
        if kind == "processes" and parts["ppid"] == parts["name"]:
            continue
        if kind == "flows":
            shape.protocol_key = next((by_lower[k] for k in _PROTOCOL_KEYS if k in by_lower), "")
        return shape
    return None


def protocol_spelling(value: object) -> tuple[str, str] | None:
    """``("tcp" | "udp", value as written)`` for a protocol value naming one, else ``None``."""
    if isinstance(value, str) and value.strip().lower() in ("tcp", "udp"):
        return value.strip().lower(), value
    return None

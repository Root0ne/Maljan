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

from maljan.schemas.sandbox_document import DNS_NAME_KEYS

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
    # The keys every DNS row reader reads a name under, and one more spelling.
    "request": (*DNS_NAME_KEYS, "qname"),
    "type": ("type", "qtype", "query_type", "record_type", "rrtype"),
    "answers": ("answers", "answer", "resolved", "resolutions", "addresses", "ips"),
}
# The keys a DNS row's question type is written under (lower case).
DNS_TYPE_KEYS = frozenset(_DNS_PARTS["type"])
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
# A name and a type are what many lists hold (functions, sections, rules,
# classifications), and a digest, a name and a size what every archive or
# resource listing holds. Such rows read as DNS questions, or as files a run
# dropped, only with evidence of their own: the words of a name the list sits
# under (its own, the block holding it, the tool answering it), a key only
# DNS rows write, an answer, or (where the values are seen) a question type
# that is a DNS record type.
_DNS_WORDS = frozenset({"dns", "lookups", "resolutions", "queries"})
_DNS_KEYS = frozenset({"qname", "qtype", "query_type", "record_type", "rrtype", "rrname", "rdata"})
_DNS_RECORD_TYPES = frozenset(
    {"a", "aaaa", "cname", "mx", "ns", "ptr", "soa", "srv", "txt", "caa", "any", "https", "svcb"}
)
_DROPPED_WORDS = frozenset({"dropped", "drop", "drops", "droppedfiles", "written", "created"})


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


def _named(names: Iterable[str], kind_words: frozenset[str]) -> bool:
    return any(_words(name) & kind_words for name in names if isinstance(name, str))


def is_record_type(value: object) -> bool:
    """Whether ``value`` is a DNS record type's name (``A``, ``AAAA``, ``CNAME`` ...)."""
    return isinstance(value, str) and value.strip().lower() in _DNS_RECORD_TYPES


def row_shape(
    list_name: str | Iterable[str],
    keys: Iterable[str],
    *,
    record_types: bool = False,
) -> RowShape | None:
    """The kind a list whose rows carry ``keys`` reads as, or ``None``.

    ``list_name`` is the list's own name, or the names the list sits under,
    its own first (the block holding it, the tool answering it).
    ``record_types`` says every value seen under the rows' question-type key is
    a DNS record type. ``high`` where every part is under the consumer's own
    field name, ``medium`` where some part is under another spelling, ``low``
    for a DNS list recognised by its name alone. A list whose evidence fits
    another kind better reads as none: a name and a type are not a DNS
    question, a digest, a name and a size not a dropped file, without evidence
    of their own (see :data:`_DNS_WORDS`).
    """
    names = (list_name,) if isinstance(list_name, str) else tuple(list_name)
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
        confidence = "high" if all(parts[part] == part for part in parts) else "medium"
        if kind == "dns":
            dns_key = bool(_DNS_KEYS & set(by_lower)) or any("dns" in _words(k) for k in by_lower)
            if "answers" in parts or dns_key or (record_types and "type" in parts):
                pass
            elif _named(names, _DNS_WORDS):
                confidence = "low" if "type" not in parts else confidence
            else:
                continue
        if kind == "dropped_files" and not _named(names, _DROPPED_WORDS):
            continue
        if kind == "processes" and parts["ppid"] == parts["name"]:
            continue
        shape = RowShape(kind, parts, confidence)
        if kind == "flows":
            shape.protocol_key = next((by_lower[k] for k in _PROTOCOL_KEYS if k in by_lower), "")
        return shape
    return None


def protocol_spelling(value: object) -> tuple[str, str] | None:
    """``("tcp" | "udp", value as written)`` for a protocol value naming one, else ``None``."""
    if isinstance(value, str) and value.strip().lower() in ("tcp", "udp"):
        return value.strip().lower(), value
    return None

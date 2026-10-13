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
# classifications), a name and its addresses what interfaces, hosts files,
# name servers and embedded configurations hold, and a digest, a name and a
# size what every archive or resource listing holds. Such rows read as DNS
# questions, or as files a run dropped, only with evidence of their own. For
# DNS that is DNS-specific evidence: the question named as a request or a
# query, its answers named as answers, a key only DNS rows write, or (where
# the values are seen) a question type that is a DNS record type; failing
# those, the words of a name the list sits under (its own, the block holding
# it, the tool answering it), read with low confidence. A name with
# addresses (``addresses``, ``ips``, ``resolved``) is no DNS evidence.
_DNS_WORDS = frozenset({"dns", "lookups", "resolutions", "queries"})
_DNS_KEYS = frozenset({"qname", "qtype", "query_type", "record_type", "rrtype", "rrname", "rdata"})
# The question's spellings that say request or query, and the answers'
# spellings that say answer: the DNS-specific ones among each part's.
_DNS_REQUEST_KEYS = frozenset({"request", "query", "qname", "rrname"})
_DNS_ANSWER_KEYS = frozenset({"answers", "answer"})
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
    # How many signals of its own kind the list carries beyond its parts (a
    # DNS-only key, record types, a name the list sits under that says so):
    # where two lists read as one kind, the one with the stronger evidence is
    # the kind's (:attr:`strength`).
    evidence: int = 0
    # For flows: the protocol key, and the spelling each of tcp and udp is written in.
    protocol_key: str = ""
    protocols: dict[str, str] = field(default_factory=dict)

    @property
    def strength(self) -> tuple[int, int, int]:
        """How strong the reading is: its confidence, its own evidence, then its parts."""
        return (_CONFIDENCE_RANK.get(self.confidence, 0), self.evidence, len(self.parts))


_CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}


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
    record_types: bool | None = None,
) -> RowShape | None:
    """The kind a list whose rows carry ``keys`` reads as, or ``None``.

    ``list_name`` is the list's own name, or the names the list sits under,
    its own first (the block holding it, the tool answering it).
    ``record_types`` says every value seen under the rows' question-type key is
    a DNS record type (``True``), that the values seen are not (``False``, which
    no name the list sits under outweighs), or that none was seen (``None``).
    ``high`` where every part is under the consumer's own field name,
    ``medium`` where some part is under another spelling, ``low`` for a DNS
    list recognised by its name alone. A list whose evidence fits another
    kind better reads as none: a name and a type, or a name and its
    addresses, are not a DNS question, a digest, a name and a size not a
    dropped file, without evidence of their own (see :data:`_DNS_WORDS`).
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
        evidence = 0
        if kind == "dns":
            signals = (
                parts["request"].lower() in _DNS_REQUEST_KEYS,
                parts.get("answers", "").lower() in _DNS_ANSWER_KEYS,
                bool(_DNS_KEYS & set(by_lower)),
                bool(record_types) and "type" in parts,
            )
            # A key or a name saying "dns" adds to the evidence, never makes
            # it: an interface lists its DNS servers.
            said = any("dns" in _words(k) for k in by_lower)
            evidence = sum(signals) + said + _named(names, _DNS_WORDS)
            if any(signals):
                pass
            elif _named(names, _DNS_WORDS) and record_types is not False:
                confidence = "low"
            else:
                continue
        if kind == "dropped_files":
            if not _named(names, _DROPPED_WORDS):
                continue
            evidence = 1
        if kind == "processes" and parts["ppid"] == parts["name"]:
            continue
        shape = RowShape(kind, parts, confidence, evidence=evidence)
        if kind == "flows":
            shape.protocol_key = next((by_lower[k] for k in _PROTOCOL_KEYS if k in by_lower), "")
        return shape
    return None


def protocol_spelling(value: object) -> tuple[str, str] | None:
    """``("tcp" | "udp", value as written)`` for a protocol value naming one, else ``None``."""
    if isinstance(value, str) and value.strip().lower() in ("tcp", "udp"):
        return value.strip().lower(), value
    return None

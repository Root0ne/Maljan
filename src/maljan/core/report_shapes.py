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
from collections.abc import Iterable, Mapping
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
# DNS that is DNS-specific evidence: a key only DNS rows write, (where the
# values are seen) a question type that is a DNS record type, or the DNS
# row's structure (a question, its type and its answers named as answers);
# failing those, the words of a name the list sits under (its own, the block
# holding it, the tool answering it), read with low confidence. A name with
# addresses (``addresses``, ``ips``, ``resolved``) is no DNS evidence.
_DNS_WORDS = frozenset({"dns", "lookups", "resolutions", "queries"})
# The words of those that say DNS on their own: ``queries`` is also what a
# database, a WMI or an LDAP log holds.
_DNS_ONLY_WORDS = frozenset({"dns", "lookups", "resolutions"})
_DNS_KEYS = frozenset({"qname", "qtype", "query_type", "record_type", "rrtype", "rrname", "rdata"})
# The question's generic spellings: a request or a query is also what an HTTP
# log, a WMI, LDAP, registry or database log writes. A list whose question is
# spelled so reads as DNS only beside a second DNS signal: one of the above,
# a name it sits under that says DNS on its own, a key saying ``dns``, or
# (where the values are seen) question values shaped like host names.
_GENERIC_QUESTION_KEYS = frozenset({"request", "query"})
_DNS_ANSWER_KEYS = frozenset({"answers", "answer"})
_DNS_RECORD_TYPES = frozenset(
    {"a", "aaaa", "cname", "mx", "ns", "ptr", "soa", "srv", "txt", "caa", "any", "https", "svcb"}
)
# The keys a request of another protocol, or an endpoint, is written with: a
# row holding one is no DNS question unless it carries a key only DNS rows
# write or record types (``port``: a configured server, a connection).
_NOT_A_QUESTION_KEYS = frozenset(
    {
        "method",
        "http_method",
        "verb",
        "url",
        "uri",
        "path",
        "status",
        "status_code",
        "response_code",
        "user_agent",
        "useragent",
        "port",
    }
)
# What a host name holds none of: white space, a path or a query's
# punctuation, brackets or quotes.
_NOT_IN_A_HOST_NAME = re.compile(r"[\s/\\()=?&;,'\"<>{}\[\]|*%@!#$^`~+]")
_DROPPED_WORDS = frozenset({"dropped", "drop", "drops", "droppedfiles", "written", "created"})
# The keys a DNS row's question is written under (lower case).
_QUESTION_KEYS = frozenset(_DNS_PARTS["request"])


def host_name_shape(value: object) -> tuple[bool, bool] | None:
    """``(shaped like a host name, holds a dot)`` for a question value, ``None`` for none.

    An empty value or ``None`` says nothing; any other value that is no text,
    or a text holding white space, a slash, a backslash, brackets, quotes or a
    query's punctuation, is no host name. Linear in the value's length.
    """
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        return False, False
    text = value.strip()
    if not text:
        return None
    return _NOT_IN_A_HOST_NAME.search(text) is None, "." in text.strip(".")


def note_question_value(held: dict[str, list[int]], key: str, value: object) -> None:
    """Fold one row value into ``held[key]`` where ``key`` spells a DNS question.

    ``held[key]`` is ``[values seen, values shaped like a host name, shaped
    values holding a dot]``; :func:`host_names` reads it. Constant work per
    value beside the value's length.
    """
    if key.lower() not in _QUESTION_KEYS:
        return
    seen = host_name_shape(value)
    if seen is None:
        return
    entry = held.setdefault(key, [0, 0, 0])
    entry[0] += 1
    if seen[0]:
        entry[1] += 1
        entry[2] += seen[1]


# The share of a question's values that must be shaped like host names for
# the values to read as host names: a clear majority, so one odd lookup a
# sample made (a wildcard, a value with a space) never vetoes a list. Of
# those, at least half must hold a dot, as most names a run looks up do: a
# list of function names with one module name among them is no host list.
_HOST_NAME_SHARE = (3, 4)


def host_names(held: Mapping[str, list[int]]) -> dict[str, bool]:
    """``row_shape``'s ``host_names`` from what :func:`note_question_value` folded.

    A key's values read as host names where at least three in four of them
    are shaped like one and at least half of those (and one at the least)
    hold a dot.
    """
    part, whole = _HOST_NAME_SHARE
    return {
        key: shaped * whole >= seen * part and dotted > 0 and dotted * 2 >= shaped
        for key, (seen, shaped, dotted) in held.items()
    }


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
    host_names: Mapping[str, bool] | None = None,
) -> RowShape | None:
    """The kind a list whose rows carry ``keys`` reads as, or ``None``.

    ``list_name`` is the list's own name, or the names the list sits under,
    its own first (the block holding it, the tool answering it).
    ``record_types`` says every value seen under the rows' question-type key is
    a DNS record type (``True``), that the values seen are not (``False``, which
    no name the list sits under outweighs), or that none was seen (``None``).
    ``host_names`` maps a key, as the rows write it, to whether the values
    seen under it read as host names (at least three in four shaped like a
    host name, at least half of those holding a dot, :func:`host_names`); a key absent
    had no value seen. A question whose values are no host names is no DNS
    question unless a key only DNS rows write says it is, or record types do
    beside the DNS row's structure or a name the list sits under that says
    DNS on its own (a list of typed lookups of ``wpad`` and ``localhost``
    still reads as DNS; a list of names typed ``A`` and nothing more, as an
    import table writes, does not).
    ``high`` where every part is under the consumer's own field name,
    ``medium`` where some part is under another spelling or where the
    question is spelled generically (``request``, ``query``) with only one
    more DNS signal, ``low`` for a DNS list recognised by its name alone. A
    list whose evidence fits another kind better reads as none: a name and a
    type, or a name and its addresses, are not a DNS question, a digest, a
    name and a size not a dropped file, without evidence of their own (see
    :data:`_DNS_WORDS`).
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
            keyset = set(by_lower)
            dns_only = bool(_DNS_KEYS & keyset)
            typed = bool(record_types) and "type" in parts
            structure = "type" in parts and parts.get("answers", "").lower() in _DNS_ANSWER_KEYS
            hosts = None if host_names is None else host_names.get(parts["request"])
            # Record types outweigh question values that are no host names
            # only beside a second DNS sign of the same strength: a name and
            # a type ``A`` alone is what an import table writes.
            dns_named = _named(names, _DNS_ONLY_WORDS)
            if hosts is False and not (dns_only or (typed and (structure or dns_named))):
                continue
            if _NOT_A_QUESTION_KEYS & keyset and not (dns_only or typed):
                continue
            # A key or a name saying "dns" adds to the evidence; it makes it
            # only for a question spelled as a request or a query.
            said = any("dns" in _words(k) for k in by_lower)
            named = _named(names, _DNS_WORDS)
            specific = (dns_only, typed, structure)
            evidence = sum(specific) + bool(hosts) + said + named
            if parts["request"].lower() in _GENERIC_QUESTION_KEYS:
                second = (*specific, bool(hosts), said, dns_named)
                if not any(second):
                    continue
                if sum((*specific, bool(hosts))) < 2:
                    confidence = "medium"
            elif any(specific):
                pass
            elif named and record_types is not False:
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

"""Proposed tool declarations, read from what a tool server says about its own tools.

A server nobody declared is used at full strength once its tools are declared
(``core.tool_declarations.ToolFacts``). Most of what a declaration says, the
server already said when it listed its tools:

* the MCP ``inputSchema``: which argument takes a path, a hash, an address or
  an indicator, read from each property's name, ``format``, ``pattern``,
  length and description;
* the MCP ``outputSchema``: where the answer's rows are, which row fields hold
  a place or a value, and where it names ATT&CK techniques or reputation
  counts;
* the MCP ``annotations`` and ``execution``: the tool's own title and whether
  its work runs long;
* the description, and the ``facts`` and budget cells of the server's own
  ``capabilities`` manifest (``tools.capabilities``);
* optionally, one answer per tool to a harmless call (a path that does not
  exist, the digest of empty input, a documentation address), made only when
  the operator asks for it: the row shape of an answer that has no
  ``outputSchema``, the auto-name prefixes a listing writes and the text the
  server answers a missing file with;
* for a server declared a sandbox source (its ``roles`` hold ``sandbox``)
  and only for one, the shape test of a sandbox report
  (``core.report_shapes``): rows whose keys
  say process id, parent and name propose a sandbox's process kind, with the
  process id as the place a run root is read from; rows naming a destination
  and its port, or a DNS question, a sandbox's network kind (read as a flow
  table where the answer lays its rows out as one); rows naming a digest, a
  name and a size, a sandbox's dropped-file kind. An accepted sandbox kind
  gives a live sandbox server's answers what the built-in sandbox tools'
  answers get: observed steps and ``run`` roots.

This module turns that into a *proposal*: per tool, a ``ToolFacts`` that
validates, and per field the parts of the schema or answer it was read from
and how sure the reading is (``high``: the server named it outright, such as a
``format`` or the manifest's own budget; ``medium``: a property's name or a
description says it; ``low``: a guess an operator should check). Nothing here
is applied: the settings probe returns the proposal, the console shows it,
and only a field the operator accepts is saved, as an ordinary declaration,
through the settings path every declaration takes. No run reads a proposal.

Everything read here is supplied by the server, so it is data, never trusted:
schemas are walked without recursion and each node is visited once (time and
memory linear in what the server sent), no description text is copied into a
proposal (evidence names the schema location, never quotes it), and a name
that is not a plain identifier is never turned into a path or an argument.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError

from maljan.analysis.technique_ids import SIGMA_TAG_RE, is_technique_id
from maljan.core.report_shapes import (
    DNS_TYPE_KEYS,
    host_names,
    is_record_type,
    note_question_value,
    row_shape,
)
from maljan.core.reputation import HASH_ARGUMENT, NETWORK_INDICATOR_ARGUMENTS
from maljan.core.tool_declarations import (
    KIND_DEPENDENT_FIELDS,
    SANDBOX_ROLE,
    ErrorPattern,
    ToolFacts,
    check_auto_name_prefixes,
    check_tool_name,
    fullmatch_pattern,
    strict_declarations,
)
from maljan.core.undeclared_tools import (
    ADDRESS_ARGUMENTS,
    DEFAULT_AUTO_NAME_WORDS,
    code_strings,
    code_text,
    holds_code,
    undeclared_code_kind,
)

PROPOSALS_VERSION = 1

HIGH = "high"
MEDIUM = "medium"
LOW = "low"
_RANK = {LOW: 0, MEDIUM: 1, HIGH: 2}


def _rank(confidence: str) -> int:
    return _RANK[confidence]


# A tool nothing it says names a kind for is proposed no kind: a declaration
# may state its other facts without one (``ToolFacts.kind``), and a tool of
# no kind keeps every reading an undeclared tool gets.

# A name this module will put into a path or an argument: the argument-name
# rule of ``ToolFacts.arguments``, without the dot and dash a path segment
# could misread.
_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")

# The longest title proposed as a display name, in characters: a title is a
# label, and a longer text is more likely a sentence than a name.
_TITLE_CHARS = 80

# The probe's harmless arguments. The path is under a directory that does not
# exist, so no server can open it; the digests are of empty input, the one
# content every reputation service knows to be benign; the indicators are the
# addresses and names reserved for documentation (RFC 5737, RFC 2606).
_PROBE_PATH_DIR = "/nonexistent-maljan-probe"
_PROBE_DOMAIN = "example.invalid"
_PROBE_IP = "192.0.2.1"
_PROBE_URL_SCHEME = "https"


def probe_path() -> str:
    """A path no server can open, fresh per call."""
    return f"{_PROBE_PATH_DIR}/{uuid.uuid4().hex}/missing.bin"


def _empty_digest(name: str) -> str:
    """The digest of empty input under the algorithm ``name`` says (sha256 by default)."""
    lowered = name.lower()
    if "md5" in lowered:
        return hashlib.md5(b"", usedforsecurity=False).hexdigest()
    if "sha1" in lowered:
        # nosemgrep: python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1
        return hashlib.sha1(b"", usedforsecurity=False).hexdigest()
    return hashlib.sha256(b"").hexdigest()


# ---------------------------------------------------------------------------
# Words read in names and descriptions
# ---------------------------------------------------------------------------

# Fixed vocabulary, searched for case-insensitively in a description: the set
# of words found is all that is kept of the text.
_DESCRIPTION_WORDS: tuple[str, ...] = (
    "path",
    "file",
    "hash",
    "sha256",
    "sha1",
    "md5",
    "digest",
    "address",
    "offset",
    "domain",
    "hostname",
    "url",
    "ip",
    "rule",
    "rules",
    "signature",
    "match",
    "matched",
    "matches",
    "capability",
    "capabilities",
    "event",
    "events",
    "sigma",
    "att&ck",
    "attack",
    "technique",
    "techniques",
    "reputation",
    "detections",
    "decompile",
    "decompiled",
    "decompiles",
    "disassemble",
    "disassembly",
    "strings",
)
_DESCRIPTION_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:"
    + "|".join(re.escape(word) for word in sorted(_DESCRIPTION_WORDS, key=len, reverse=True))
    + r")(?![A-Za-z0-9])",
    re.IGNORECASE,
)


def _words_in(text: Any) -> frozenset[str]:
    """The vocabulary words ``text`` holds, lowercased; nothing for a value that is not text."""
    if not isinstance(text, str) or not text:
        return frozenset()
    return frozenset(found.lower() for found in _DESCRIPTION_RE.findall(text))


def _tokens(name: str) -> tuple[str, ...]:
    """A name's words: split at ``_``, digits kept with their word, camelCase split."""
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    return tuple(part for part in spaced.lower().split("_") if part)


# ---------------------------------------------------------------------------
# A schema or an answer, as one shape
# ---------------------------------------------------------------------------


@dataclass
class _Shape:
    """One node of a schema or an answer: what is kept of it, never its text."""

    kind: str = "scalar"  # "object" | "array" | "scalar"
    type: str = ""
    fmt: str = ""
    regex: str = ""
    min_length: int | None = None
    max_length: int | None = None
    words: frozenset[str] = frozenset()
    value_hint: str = ""  # "attck" | "sigma_tag" | ""
    props: dict[str, _Shape] = field(default_factory=dict)
    items: _Shape | None = None


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _alternatives(node: Mapping[str, Any]) -> list[Any]:
    out: list[Any] = []
    for key in ("anyOf", "oneOf", "allOf"):
        held = node.get(key)
        if isinstance(held, list):
            out.extend(alt for alt in held if isinstance(alt, Mapping))
    return out


def shape_of_schema(schema: Any) -> _Shape:
    """A JSON Schema as a shape, each node visited once, with no recursion.

    ``properties`` give an object's fields, ``items`` an array's element (the
    first schema of a tuple form), and ``anyOf``/``oneOf``/``allOf`` are read
    into the node that holds them. ``$ref`` is not followed: a proposal reads
    what the schema says where it says it.
    """
    root = _Shape()
    stack: list[tuple[Any, _Shape]] = [(schema, root)]
    seen: set[int] = set()
    while stack:
        node, shape = stack.pop()
        if not isinstance(node, Mapping) or id(node) in seen:
            continue
        seen.add(id(node))
        declared = node.get("type")
        if isinstance(declared, list):
            declared = next((t for t in declared if isinstance(t, str) and t != "null"), "")
        if isinstance(declared, str) and declared and not shape.type:
            shape.type = declared
        shape.fmt = shape.fmt or _text(node.get("format"))
        shape.regex = shape.regex or _text(node.get("pattern"))
        shape.min_length = (
            shape.min_length if shape.min_length is not None else _int(node.get("minLength"))
        )
        shape.max_length = (
            shape.max_length if shape.max_length is not None else _int(node.get("maxLength"))
        )
        shape.words = (
            shape.words | _words_in(node.get("description")) | _words_in(node.get("title"))
        )
        props = node.get("properties")
        if isinstance(props, Mapping):
            shape.kind = "object"
            for name, sub in props.items():
                if not isinstance(name, str) or not _NAME_RE.match(name):
                    continue
                child = shape.props.get(name)
                if child is None:
                    child = shape.props[name] = _Shape()
                stack.append((sub, child))
        items = node.get("items")
        if isinstance(items, list):
            items = next((i for i in items if isinstance(i, Mapping)), None)
        if isinstance(items, Mapping):
            shape.kind = "array"
            if shape.items is None:
                shape.items = _Shape()
            stack.append((items, shape.items))
        if shape.type == "object" and shape.kind == "scalar":
            shape.kind = "object"
        if shape.type == "array" and shape.kind == "scalar":
            shape.kind = "array"
        stack.extend((alt, shape) for alt in _alternatives(node))
    return root


def shape_of_value(value: Any) -> _Shape:
    """An answer as a shape, each node visited once, with no recursion.

    A list is read by its first object, else its first element; a text is
    kept only as whether it reads as a technique id or a Sigma tag.
    """
    root = _Shape()
    stack: list[tuple[Any, _Shape]] = [(value, root)]
    while stack:
        node, shape = stack.pop()
        if isinstance(node, Mapping):
            shape.kind, shape.type = "object", "object"
            for name, sub in node.items():
                if isinstance(name, str) and _NAME_RE.match(name):
                    child = shape.props[name] = _Shape()
                    stack.append((sub, child))
        elif isinstance(node, list | tuple):
            shape.kind, shape.type = "array", "array"
            if node:
                element = next((e for e in node if isinstance(e, Mapping)), node[0])
                shape.items = _Shape()
                stack.append((element, shape.items))
        elif isinstance(node, str):
            shape.type = "string"
            text = node.strip()
            if len(text) <= 32:
                # A technique id as ATT&CK writes it, and a Sigma tag naming one.
                if is_technique_id(text):
                    shape.value_hint = "attck"
                elif SIGMA_TAG_RE.match(text):
                    shape.value_hint = "sigma_tag"
        elif isinstance(node, bool):
            shape.type = "boolean"
        elif isinstance(node, int | float):
            shape.type = "number"
    return root


# How deep under the answer's root a proposal reads, in path segments: a
# declaration names a field within a few levels (the built-ins read within
# eight), and holding every node's path to a fixed depth keeps the walk linear
# however deeply a hostile schema nests.
READ_DEPTH = 16


def _nodes(root: _Shape) -> list[tuple[tuple[str, ...], _Shape]]:
    """Every node within :data:`READ_DEPTH` of ``root`` with its path segments, breadth first.

    An array element's segment is ``*``.
    """
    queue: list[tuple[tuple[str, ...], _Shape]] = [((), root)]
    index = 0
    while index < len(queue):
        segments, shape = queue[index]
        index += 1
        if len(segments) >= READ_DEPTH:
            continue
        for name, child in shape.props.items():
            queue.append(((*segments, name), child))
        if shape.items is not None:
            queue.append(((*segments, "*"), shape.items))
    return queue


def _path(segments: Sequence[str]) -> str:
    return "/" + "/".join(segments)


def _where(origin: str, segments: Sequence[str]) -> str:
    """A schema location as evidence names it: ``outputSchema.matches[].rule``."""
    out = origin
    for segment in segments:
        out = f"{out}[]" if segment == "*" else f"{out}.{segment}"
    return out


# ---------------------------------------------------------------------------
# A proposed field
# ---------------------------------------------------------------------------


@dataclass
class Proposed:
    """One proposed declaration field: its value, where it was read and how sure it is."""

    value: Any
    evidence: list[str]
    confidence: str
    requires: tuple[str, ...] = ()
    # Fields only the operator can say, without which the value does less than
    # it seems to; the console accepts it only once they are declared.
    incomplete: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "value": self.value,
            "evidence": list(self.evidence),
            "confidence": self.confidence,
        }
        if self.requires:
            out["requires"] = list(self.requires)
        if self.incomplete:
            out["incomplete"] = list(self.incomplete)
        return out


# ---------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------

_HEX_LENGTHS = {32, 40, 64}
_HEX_DIGITS = "0a1b2c3d4e5f6789"


def _counts_a_hex_class(regex: str) -> bool:
    """Whether ``regex`` takes a hash's hex digits and nothing near them.

    Decided by what it does, not by how it is written: it must match a hex
    string of 32, 40 or 64 characters whole, and refuse the same string with a
    non-hex character swapped in (first and last place), with one character
    more and with one fewer. A pattern the platform's engine cannot run is none.
    """
    try:
        for n in sorted(_HEX_LENGTHS):
            digits = (_HEX_DIGITS * 4)[:n]
            if fullmatch_pattern(regex, digits) is None:
                continue
            if any(
                fullmatch_pattern(regex, bad) is not None
                for bad in (
                    "g" + digits[1:],
                    digits[:-1] + "g",
                    digits + "a",
                    digits[:-1],
                )
            ):
                continue
            return True
    except ValueError:
        return False
    return False


def _argument_role(name: str, shape: _Shape) -> tuple[str, str, str] | None:
    """``(role, confidence, what said it)`` for one input property, or ``None``."""
    tokens = _tokens(name)
    lowered = name.lower()
    words = shape.words
    fmt = shape.fmt.lower()
    if any(algo in lowered for algo in ("sha256", "sha1", "md5")) or {"hash", "digest"} & set(
        tokens
    ):
        return "hash", HIGH, "name"
    if shape.regex and _counts_a_hex_class(shape.regex):
        return "hash", HIGH, "pattern"
    if (
        shape.min_length == shape.max_length
        and shape.min_length in _HEX_LENGTHS
        and ({"hash", "sha256", "sha1", "md5", "digest"} & words)
    ):
        return "hash", MEDIUM, "length and description"
    if fmt in ("ipv4", "ipv6"):
        return "ip", HIGH, "format"
    if {"ip", "ipv4", "ipv6"} & set(tokens):
        return "ip", HIGH, "name"
    if fmt in ("hostname", "idn-hostname"):
        return "domain", HIGH, "format"
    if {"domain", "hostname", "fqdn"} & set(tokens):
        return "domain", HIGH, "name"
    if {"url", "uri"} & set(tokens) or fmt in ("uri", "iri"):
        return "url", HIGH, "format" if fmt in ("uri", "iri") else "name"
    if lowered in ADDRESS_ARGUMENTS or {"addr", "address"} & set(tokens):
        return "address", HIGH, "name"
    if {"ea", "va"} & set(tokens):
        return "address", MEDIUM, "name"
    if (
        "address" in words
        and shape.type in ("string", "integer", "")
        and (not {"path", "file", "ip", "url", "domain"} & set(tokens))
    ):
        return "address", LOW, "description"
    if fmt in ("path", "file-path", "filepath", "uri-reference"):
        return "path", HIGH, "format"
    if {"path", "filepath", "filename"} & set(tokens):
        return "path", HIGH, "name"
    if tokens in (("file",), ("sample",), ("binary",)) and shape.type in ("string", ""):
        return "path", MEDIUM, "name"
    if "path" in words and shape.type in ("string", ""):
        return "path", LOW, "description"
    return None


# The role order an argument is claimed in: the most specific first.
_ROLE_ORDER = ("hash", "ip", "domain", "url", "address", "path")


@dataclass
class _ArgumentReading:
    roles: dict[str, Proposed] = field(default_factory=dict)
    required: tuple[str, ...] = ()
    names: tuple[str, ...] = ()


def _read_arguments(input_schema: Any) -> _ArgumentReading:
    shape = shape_of_schema(input_schema)
    required_raw = input_schema.get("required") if isinstance(input_schema, Mapping) else None
    required = tuple(
        name
        for name in (required_raw if isinstance(required_raw, list) else [])
        if isinstance(name, str)
    )
    candidates: dict[str, list[tuple[int, int, int, str, str, str]]] = {}
    for position, (name, prop) in enumerate(shape.props.items()):
        found = _argument_role(name, prop)
        if found is None:
            continue
        role, confidence, said = found
        # A required argument before an optional one; a surer reading first;
        # then the schema's own order.
        candidates.setdefault(role, []).append(
            (0 if name in required else 1, -_RANK[confidence], position, name, confidence, said)
        )
    reading = _ArgumentReading(required=required, names=tuple(shape.props))
    claimed: set[str] = set()
    for role in _ROLE_ORDER:
        held = sorted(candidates.get(role, []))
        held = [c for c in held if c[3] not in claimed]
        if not held:
            continue
        _req, _conf, _pos, name, confidence, said = held[0]
        if len(held) > 1 and confidence == HIGH:
            # Two arguments read as the same role: the operator picks.
            confidence = MEDIUM
        claimed.add(name)
        reading.roles[role] = Proposed(
            value=name,
            evidence=[f"inputSchema.properties.{name} ({said})"],
            confidence=confidence,
        )
    return reading


# ---------------------------------------------------------------------------
# The answer: rows, places, values, techniques, reputation
# ---------------------------------------------------------------------------

_PLACE_NAMES: dict[str, str] = {
    "offset": "offset",
    "file_offset": "offset",
    "rva": "rva",
    "address": "address",
    "addr": "address",
    "va": "address",
    "ea": "address",
    "addresses": "addresses",
    "call_site": "call_site",
    "called_at": "call_site",
    "function_address": "function",
    "function_rva": "function",
    "pid": "pid",
    "process_id": "pid",
    "command_line": "command_line",
    "cmdline": "command_line",
    "commandline": "command_line",
}
_VALUE_NAMES: dict[str, str] = {
    "rule": "rule",
    "rule_name": "rule",
    "title": "title",
    "namespace": "namespace",
    "text": "text",
    "string": "text",
    "value": "value",
    "name": "name",
}
_TECHNIQUE_NAMES: dict[str, str] = {
    "technique_id": "attck",
    "technique_ids": "attck",
    "techniques": "attck",
    "attck": "attck",
    "attack_id": "attck",
    "attack_ids": "attck",
    "mitre_attack": "attck",
    "tags": "sigma_tag",
}
_REPUTATION_COUNTS: dict[str, str] = {
    "malicious": "malicious",
    "positives": "malicious",
    "suspicious": "suspicious",
    "total": "total",
}
# The words a date of a reputation answer is named by beside "first" or
# "last", and the words a label list and a link are named by: generic words,
# read in a field's name tokens, never one service's field names.
_WHEN_WORDS = frozenset({"seen", "submission", "submitted", "analysis", "scan", "date", "time"})
_LABEL_WORDS = frozenset({"label", "labels", "family", "families"})
_LINK_WORDS = frozenset({"link", "url"})


def _reputation_list(name: str) -> str:
    """The list field of ``ReputationFacts`` a field named ``name`` is read as, or ``""``."""
    tokens = set(_tokens(name))
    if tokens & _LABEL_WORDS:
        return "labels"
    if "first" in tokens and tokens & _WHEN_WORDS:
        return "first_seen"
    if "last" in tokens and tokens & _WHEN_WORDS:
        return "last_seen"
    if tokens & _LINK_WORDS or name.lower().endswith("link"):
        return "link"
    return ""


@dataclass
class _AnswerReading:
    rows: Proposed | None = None
    places: dict[str, str] = field(default_factory=dict)
    places_evidence: list[str] = field(default_factory=list)
    values: dict[str, str] = field(default_factory=dict)
    values_evidence: list[str] = field(default_factory=list)
    techniques: list[dict[str, str]] = field(default_factory=list)
    techniques_evidence: list[str] = field(default_factory=list)
    reputation: dict[str, Any] = field(default_factory=dict)
    reputation_evidence: list[str] = field(default_factory=list)
    confidence: str = MEDIUM
    # The first list of objects: its path segments (the list's own) and its row's keys.
    row_list: tuple[str, ...] = ()
    row_keys: tuple[str, ...] = ()


def _read_answer(root: _Shape, origin: str, confidence: str) -> _AnswerReading:
    reading = _AnswerReading(confidence=confidence)
    nodes = _nodes(root)
    by_path = dict(nodes)
    row_at: tuple[str, ...] | None = None
    row: _Shape | None = None
    for segments, shape in nodes:
        if shape.kind == "array" and shape.items is not None and shape.items.props:
            row_at, row = (*segments, "*"), shape.items
            reading.row_list, reading.row_keys = tuple(segments), tuple(shape.items.props)
            reading.rows = Proposed(
                value=_path(row_at),
                evidence=[f"{_where(origin, segments)} (a list of objects)"],
                confidence=confidence,
            )
            break
    if row_at is not None and row is not None:
        for segments, shape in _nodes(row):
            if not segments or shape.kind != "scalar" and segments[-1] != "addresses":
                continue
            # A row field, or a field of a list of objects inside the row.
            if sum(1 for s in segments if s == "*") > 1 or len(segments) > 3:
                continue
            name = segments[-1].lower()
            place = _PLACE_NAMES.get(name)
            if place is not None and place not in reading.places:
                reading.places[place] = _path(segments)
                reading.places_evidence.append(_where(origin, (*row_at, *segments)))
                continue
            value = _VALUE_NAMES.get(name)
            if value is not None and value not in reading.values and len(segments) == 1:
                reading.values[value] = _path(segments)
                reading.values_evidence.append(_where(origin, (*row_at, *segments)))
    for segments, shape in nodes:
        if not segments or segments[-1] == "*":
            continue
        name = segments[-1].lower()
        fmt = _TECHNIQUE_NAMES.get(name)
        hint = shape.value_hint or (shape.items.value_hint if shape.items else "")
        if fmt is None and hint:
            fmt = hint
        if fmt is None and {"technique", "techniques", "att&ck"} & shape.words:
            fmt = "attck"
        if fmt is None:
            continue
        if hint:
            fmt = hint
        depth = len(segments) - 1
        path = f"/**{depth}/{segments[-1]}" if depth else f"/{segments[-1]}"
        held = {"path": path, "format": fmt}
        if held not in reading.techniques:
            reading.techniques.append(held)
            reading.techniques_evidence.append(_where(origin, segments))
    for segments, shape in nodes:
        if not segments or "*" in segments:
            continue
        name = segments[-1].lower()
        count = _REPUTATION_COUNTS.get(name)
        if count is not None and shape.kind == "scalar" and count not in reading.reputation:
            reading.reputation[count] = _path(segments)
            reading.reputation_evidence.append(_where(origin, segments))
            if len(segments) > 1 and "stats" not in reading.reputation:
                parent = segments[:-1]
                parent_shape = by_path.get(parent)
                if parent_shape is not None and len(parent_shape.props) >= 2:
                    reading.reputation["stats"] = _path(parent)
            continue
        key = _reputation_list(segments[-1])
        if key and key not in reading.reputation:
            reading.reputation[key] = [_path(segments)]
            reading.reputation_evidence.append(_where(origin, segments))
    if "malicious" not in reading.reputation:
        reading.reputation = {}
        reading.reputation_evidence = []
    return reading


# ---------------------------------------------------------------------------
# One tool
# ---------------------------------------------------------------------------

_RULE_KIND_BY_WORD: tuple[tuple[frozenset[str], str], ...] = (
    (frozenset({"capability", "capabilities"}), "capability_rules"),
    (frozenset({"event", "events", "sigma"}), "event_rules"),
)
_RULE_WORDS = frozenset({"rule", "rules", "signature", "match", "matched", "matches"})
_RULE_KINDS = frozenset({"signature_rules", "capability_rules", "event_rules"})


def _get(definition: Any, key: str) -> Any:
    if isinstance(definition, Mapping):
        return definition.get(key)
    return getattr(definition, key, None)


def _plain(value: Any) -> Any:
    """A pydantic object (an MCP ``ToolAnnotations``) as a mapping, extra fields kept."""
    if value is None or isinstance(value, Mapping):
        return value
    dump = getattr(value, "model_dump", None)
    if callable(dump):
        try:
            return dump(by_alias=True)
        except Exception:  # noqa: BLE001 — a field the server sent oddly proposes nothing
            return None
    return None


def _title_of(definition: Any, annotations: Mapping[str, Any] | None) -> str:
    for held in (_get(definition, "title"), (annotations or {}).get("title")):
        if isinstance(held, str):
            text = held.strip()
            if text and len(text) <= _TITLE_CHARS and text.isprintable():
                return text
    return ""


@dataclass
class ToolProposal:
    """What one tool's definition, manifest cell and probe answer propose."""

    tool: str
    fields: dict[str, Proposed] = field(default_factory=dict)
    facts: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    roles: dict[str, str] = field(default_factory=dict)
    required: tuple[str, ...] = ()
    read_only: bool | None = None
    destructive: bool | None = None
    open_world: bool | None = None
    # The rows pass the sandbox shape test on a server not declared a sandbox
    # source: no kind is proposed, and the server's answer says how to have
    # one proposed (:func:`propose`). Not part of the tool's proposal.
    run_shaped: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "facts": dict(self.facts),
            "fields": {name: held.as_dict() for name, held in self.fields.items()},
            **({"notes": list(self.notes)} if self.notes else {}),
        }


# The fields a field needs beside it to be a declaration that validates.
_REQUIRES: dict[str, tuple[str, ...]] = {
    "places": ("rows",),
    "values": ("rows",),
    "asserts_techniques": ("techniques",),
}
# Dropped in this order until the facts validate (a field read wrongly is
# never worth the rest of the proposal).
_DROP_ORDER = (
    "reader",
    "asserts_techniques",
    "places",
    "values",
    "techniques",
    "reputation",
    "rows",
    "display_name",
    "arguments",
    "timeout_seconds",
)


_WRAPPED_ORIGIN = "probe answer (the text the outputSchema's one string field wraps)"


def _wrapping_field(schema: Any) -> str | None:
    """The one field of an ``outputSchema`` that only wraps a text answer, or ``None``.

    An object schema with a single property typed ``string`` and nothing under
    it says no more than "the answer is a text": what an MCP server writes for
    a tool that returns a string (``{"result": <the text>}``). Whatever the
    field is called; any second field, a structure under it or a type other
    than a string makes it a schema that says something, read as one.
    """
    if not isinstance(schema, Mapping):
        return None
    props = schema.get("properties")
    if not isinstance(props, Mapping) or len(props) != 1:
        return None
    if schema.get("type") not in (None, "object"):
        return None
    name, sub = next(iter(props.items()))
    if not isinstance(name, str) or not isinstance(sub, Mapping):
        return None
    declared = sub.get("type")
    if isinstance(declared, list):
        declared = [t for t in declared if t != "null"]
        declared = declared[0] if len(declared) == 1 else None
    if declared != "string":
        return None
    if any(key in sub for key in ("properties", "items", "anyOf", "oneOf", "allOf", "$ref")):
        return None
    return name


def _wrapped_answer(schema: Any, answer: Any) -> Any:
    """The confirmed answer inside a wrapping schema's one text field, when its text is JSON.

    ``answer`` is the probe answer as :func:`_parsed` gives it: the wrapper
    object the server returned (``{field: <text>}``), the text, or the text's
    JSON already. ``None`` when the schema says something of its own
    (:func:`_wrapping_field`), there is no answer, the text is not a JSON
    object or list, or the answer reports a failure (:func:`_an_error_answer`):
    the schema is then read as before.
    """
    from maljan.schemas.evidence import parse_structured

    field_name = _wrapping_field(schema)
    if field_name is None or answer is None or _an_error_answer(answer):
        return None
    if isinstance(answer, Mapping) and set(answer) == {field_name}:
        answer = answer[field_name]
    if isinstance(answer, str):
        answer = parse_structured(answer)
    if not isinstance(answer, Mapping | list) or _an_error_answer(answer):
        return None
    return answer


# The fields an answer that only reports a failure is made of.
_ERROR_ONLY_FIELDS = frozenset({"error", "message", "detail", "code", "status"})


def _an_error_answer(answer: Any) -> bool:
    """Whether a probe answer reports a failure rather than the tool's data.

    An MCP ``isError`` reply, any shape the platform reads as a failure
    (``tools.errors.error_parts``: ``{"error": …}``, the client's
    ``tool_error`` marker), or an object holding only an error or a message
    and the fields such a report carries (``{"message": "…"}``). Its shape is
    the failure's, never the tool's answer's, so a wrapping schema is read as
    before.
    """
    from maljan.tools.errors import error_parts

    if not isinstance(answer, Mapping):
        return False
    if answer.get("isError") is True or answer.get("is_error") is True:
        return True
    if error_parts(dict(answer)) is not None:
        return True
    keys = {str(key) for key in answer}
    return bool(keys) and keys <= _ERROR_ONLY_FIELDS and bool(keys & {"error", "message"})


def propose_tool(
    definition: Any,
    *,
    manifest_cell: Mapping[str, Any] | None = None,
    answer: Any = None,
    sandbox_source: bool = False,
) -> ToolProposal | None:
    """The proposal for one tool, or ``None`` for one whose name a declaration cannot hold.

    ``definition`` is the MCP ``Tool`` (or a mapping of its fields);
    ``manifest_cell`` the tool's cell of the server's ``capabilities``
    manifest; ``answer`` the parsed answer of a harmless probe call, read for
    the answer's shape when the definition has no ``outputSchema`` or one that
    only wraps a text whose answer is JSON (:func:`_wrapped_answer`).
    ``sandbox_source`` says the server is declared a sandbox source (its
    ``roles`` hold :data:`~maljan.core.tool_declarations.SANDBOX_ROLE`): only
    then are its rows read by the sandbox shape test, since rows shaped like
    a run's (processes, connections, DNS questions, dropped files) are also
    what a memory image, a capture, a live resolver or an intelligence lookup
    answers with, and a sandbox kind makes them observed run facts.
    """
    name = _get(definition, "name")
    if not isinstance(name, str):
        return None
    try:
        check_tool_name(name)
    except ValueError:
        return None
    proposal = ToolProposal(tool=name)
    annotations = _plain(_get(definition, "annotations"))
    annotations = annotations if isinstance(annotations, Mapping) else {}
    execution = _plain(_get(definition, "execution"))
    execution = execution if isinstance(execution, Mapping) else {}
    cell = manifest_cell if isinstance(manifest_cell, Mapping) else {}
    read_only = annotations.get("readOnlyHint")
    destructive = annotations.get("destructiveHint")
    open_world = annotations.get("openWorldHint")
    proposal.read_only = read_only if isinstance(read_only, bool) else None
    proposal.destructive = destructive if isinstance(destructive, bool) else None
    proposal.open_world = open_world if isinstance(open_world, bool) else None

    words = _words_in(_get(definition, "description")) | _words_in(cell.get("facts"))
    word_origin = "description" + (" and capabilities manifest facts" if cell.get("facts") else "")

    # Arguments.
    input_schema = _get(definition, "inputSchema")
    arguments = _read_arguments(input_schema if isinstance(input_schema, Mapping) else {})
    proposal.required = arguments.required
    proposal.roles = {role: str(held.value) for role, held in arguments.roles.items()}
    if arguments.roles:
        proposal.fields["arguments"] = Proposed(
            value=dict(proposal.roles),
            evidence=[e for held in arguments.roles.values() for e in held.evidence],
            confidence=min((h.confidence for h in arguments.roles.values()), key=_rank),
        )

    # The answer.
    output_schema = _get(definition, "outputSchema")
    wrapped = _wrapped_answer(output_schema, answer)
    if wrapped is not None:
        # The schema only wraps a text, and the confirmed answer's text is
        # JSON: the answer is read, as the run reads it (the text's JSON wins
        # over a structure that only wraps it, ``schemas.evidence``).
        answer = wrapped
        reading = _read_answer(shape_of_value(answer), _WRAPPED_ORIGIN, LOW)
    elif isinstance(output_schema, Mapping) and output_schema:
        reading = _read_answer(shape_of_schema(output_schema), "outputSchema", MEDIUM)
    elif answer is not None and not isinstance(answer, str):
        reading = _read_answer(shape_of_value(answer), "probe answer", LOW)
    else:
        reading = _AnswerReading()
    if reading.rows is not None:
        proposal.fields["rows"] = reading.rows
    if reading.places:
        proposal.fields["places"] = Proposed(
            dict(reading.places), list(reading.places_evidence), reading.confidence
        )
    if reading.values:
        proposal.fields["values"] = Proposed(
            dict(reading.values), list(reading.values_evidence), reading.confidence
        )
    if reading.techniques:
        proposal.fields["techniques"] = Proposed(
            list(reading.techniques), list(reading.techniques_evidence), reading.confidence
        )

    # The kind, when something the server said names one; a sandbox's rows, by
    # the shape test, only for a server declared a sandbox source and where
    # nothing else names a kind, with the parts a run reads.
    found_kind = _kind_of(name, words, word_origin, proposal, reading, answer)
    # A tool asked about an address, a domain or a URL describes that subject
    # (a lookup, a resolution), not what a run did, whatever server serves it.
    subject = bool(_SUBJECT_ROLES & set(proposal.roles))
    sandbox = _sandbox_kind(name, reading, answer) if found_kind is None and not subject else None
    if sandbox is not None and not sandbox_source:
        proposal.run_shaped = True
        sandbox = None
    if sandbox is not None:
        kind, extra = sandbox
        found_kind = kind, extra["_kind"].confidence, list(extra["_kind"].evidence)
        for key, held in extra.items():
            if key != "_kind":
                proposal.fields[key] = held
    if found_kind is not None:
        kind, kind_confidence, kind_evidence = found_kind
        if kind in _RULE_KINDS and reading.techniques:
            proposal.fields["asserts_techniques"] = Proposed(
                True,
                [*kind_evidence, *reading.techniques_evidence],
                LOW,
            )
        if reading.reputation and kind in ("reputation", "indicator_reputation"):
            proposal.fields["reputation"] = Proposed(
                dict(reading.reputation), list(reading.reputation_evidence), reading.confidence
            )
        proposal.fields = {
            "kind": Proposed(kind, kind_evidence, kind_confidence),
            **proposal.fields,
        }

    # What the server says about running it.
    long_evidence: list[str] = []
    long_confidence = LOW
    if cell.get("long_running") is True:
        long_evidence.append("capabilities manifest long_running")
        long_confidence = HIGH
    if execution.get("taskSupport") in ("required", "optional"):
        long_evidence.append("execution.taskSupport")
        long_confidence = max(long_confidence, MEDIUM, key=_rank)
    if annotations.get("longRunningHint") is True:
        long_evidence.append("annotations.longRunningHint")
        long_confidence = max(long_confidence, MEDIUM, key=_rank)
    if long_evidence:
        proposal.fields["long_running"] = Proposed(True, long_evidence, long_confidence)
    timeout = cell.get("timeout_s")
    if isinstance(timeout, int | float) and not isinstance(timeout, bool) and timeout > 0:
        proposal.fields["timeout_seconds"] = Proposed(
            float(timeout), ["capabilities manifest timeout_s"], HIGH
        )
    if annotations.get("openWorldHint") is True and "path" in proposal.roles:
        proposal.fields["discloses_sample"] = Proposed(
            True,
            ["annotations.openWorldHint", *arguments.roles["path"].evidence],
            LOW,
        )
    title = _title_of(definition, annotations)
    if title:
        proposal.fields["display_name"] = Proposed(title, ["title"], HIGH)

    # A field read only through a kind is offered only with that kind: it
    # requires it, and with no kind proposed it is not offered at all.
    if "kind" not in proposal.fields:
        dropped = [name for name in KIND_DEPENDENT_FIELDS if name in proposal.fields]
        for name in dropped:
            proposal.fields.pop(name)
        if dropped:
            proposal.notes.append(
                f"{', '.join(dropped)} not offered: read only through a kind, and nothing "
                "the server said names one"
            )
    for held_name, held in proposal.fields.items():
        needs_kind = ("kind",) if held_name in KIND_DEPENDENT_FIELDS else ()
        held.requires = (*needs_kind, *_REQUIRES.get(held_name, ()))
    _settle(proposal)
    return proposal


def _kind_of(
    name: str,
    words: frozenset[str],
    word_origin: str,
    proposal: ToolProposal,
    reading: _AnswerReading,
    answer: Any = None,
) -> tuple[str, str, list[str]] | None:
    """The proposed kind, how sure, and what said it; ``None`` when nothing names one.

    A code-listing kind read from the description's words alone (the tool's
    name says no such thing) is proposed only when the confirmed probe
    ``answer`` holds code (``undeclared_tools.holds_code``): a search over
    decompiled code is described with the word too, and its hits are no
    listing. With no answer, or one holding no code, no code kind is proposed.
    """
    roles = proposal.roles
    counts = f"a malicious count in the answer ({reading.reputation.get('malicious', '')})"
    if reading.reputation and HASH_ARGUMENT in roles:
        return "reputation", MEDIUM, [counts, "inputSchema hash argument"]
    if reading.reputation and _SUBJECT_ROLES & set(roles):
        return "indicator_reputation", MEDIUM, [counts, "inputSchema indicator argument"]
    if "reputation" in words or "detections" in words:
        if HASH_ARGUMENT in roles:
            return "reputation", LOW, [f"{word_origin} (reputation)", "inputSchema hash argument"]
        if _SUBJECT_ROLES & set(roles):
            return (
                "indicator_reputation",
                LOW,
                [f"{word_origin} (reputation)", "inputSchema indicator argument"],
            )
    if reading.rows is not None and reading.techniques and _RULE_WORDS & words:
        for kind_words, kind in _RULE_KIND_BY_WORD:
            if kind_words & words:
                return (
                    kind,
                    LOW,
                    [f"{word_origin} ({kind.replace('_', ' ')})", "rows with techniques"],
                )
        return "signature_rules", LOW, [f"{word_origin} (rule match)", "rows with techniques"]
    code = undeclared_code_kind(name)
    if code:
        return code, LOW, ["tool name"]
    answered_code = _answer_holds_code(answer)
    if {"decompile", "decompiled", "decompiles"} & words and answered_code:
        return "decompile", LOW, [f"{word_origin} (decompile)", "probe answer holds code"]
    if {"disassemble", "disassembly"} & words and "address" in roles and answered_code:
        return (
            "function_disassembly",
            LOW,
            [f"{word_origin} (disassembly)", "probe answer holds code"],
        )
    if "strings" in words and "text" in reading.values:
        return "strings", LOW, [f"{word_origin} (strings)", "rows with a text value"]
    return None


def _answer_holds_code(answer: Any) -> bool:
    """Whether a probe answer (its text, or the object parsed from it) holds a code listing."""
    if answer is None:
        return False
    if isinstance(answer, str):
        return bool(code_text(answer)) and holds_code(code_text(answer))
    if isinstance(answer, Mapping | list):
        return bool(code_strings(answer))
    return False


# The argument roles that name a subject to describe rather than a run or its
# sample: a tool taking one is never read by the sandbox shape test.
_SUBJECT_ROLES = frozenset(NETWORK_INDICATOR_ARGUMENTS)
# The top-level keys a flow table lays its rows out under
# (``analysis.evidence_roots``: reader ``flow_table``).
_FLOW_TABLE_KEYS = frozenset({"tcp", "udp", "conversations", "dns"})
_SANDBOX_KIND_OF_SHAPE = {
    "processes": "sandbox_processes",
    "flows": "sandbox_network",
    "dns": "sandbox_network",
    "dropped_files": "sandbox_dropped_files",
}


def _answer_rows(answer: Any, segments: Sequence[str]) -> list[Mapping[str, Any]]:
    """The rows of ``answer`` at the list ``segments`` names (``*`` an element), each once."""
    nodes: list[Any] = [answer]
    for segment in segments:
        nxt: list[Any] = []
        for node in nodes:
            if segment == "*" and isinstance(node, list | tuple):
                nxt.extend(node)
            elif isinstance(node, Mapping) and segment in node:
                nxt.append(node[segment])
        nodes = nxt
    rows: list[Mapping[str, Any]] = []
    for node in nodes:
        if isinstance(node, list | tuple):
            rows.extend(row for row in node if isinstance(row, Mapping))
    return rows


def _row_values(answer: Any, reading: _AnswerReading) -> dict[str, Any]:
    """``row_shape``'s value evidence from a probe answer's rows; empty without an answer.

    Whether every question type seen is a DNS record type, and whether the
    question values read as host names: what an uploaded report's rows give
    the same test.
    """
    if answer is None or isinstance(answer, str):
        return {}
    rows = _answer_rows(answer, reading.row_list)
    if not rows:
        return {}
    record_types: dict[str, bool] = {}
    hosts: dict[str, list[int]] = {}
    for row in rows:
        for key, value in row.items():
            if not isinstance(key, str):
                continue
            if key.lower() in DNS_TYPE_KEYS:
                record_types[key] = record_types.get(key, True) and is_record_type(value)
            note_question_value(hosts, key, value)
    return {
        "record_types": any(record_types.values()) if record_types else None,
        "host_names": host_names(hosts),
    }


def _sandbox_kind(
    name: str, reading: _AnswerReading, answer: Any = None
) -> tuple[str, dict[str, Proposed]] | None:
    """A sandbox kind for an answer whose rows pass the shape test, with the fields it reads.

    ``("sandbox_processes", {...})`` gives the row's process id as the place
    a ``run`` root is read from and its name and command line as values; a
    network answer laid out as a flow table gets that reader. The returned
    mapping's ``_kind`` entry is the kind's own evidence; every other entry is
    a field to propose. ``None`` where the rows pass no shape test. The names
    the rows sit under, for the test's evidence, are the list's own, the
    block's holding it and the tool's (``name``); a probe ``answer``'s rows
    add the values' evidence (record types, host names). Asked only where
    nothing else the server said names a kind (:func:`_kind_of` first).
    """
    if reading.rows is None or not reading.row_keys:
        return None
    names = [s for s in reversed(reading.row_list) if s != "*"][:2]
    shape = row_shape([*names, name], reading.row_keys, **_row_values(answer, reading))
    if shape is None:
        return None
    kind = _SANDBOX_KIND_OF_SHAPE[shape.kind]
    origin = reading.rows.evidence[0] if reading.rows.evidence else "rows"
    parts = ", ".join(sorted(shape.parts.values()))
    confidence = LOW if reading.confidence == LOW else MEDIUM
    extra: dict[str, Proposed] = {
        "_kind": Proposed(
            kind, [f"{origin} ({parts})", "the sandbox report shape test"], confidence
        )
    }
    if shape.kind == "processes":
        extra["places"] = Proposed(
            {"pid": f"/{shape.parts['pid']}"}, [f"{origin}.{shape.parts['pid']}"], confidence
        )
        values = {"name": f"/{shape.parts['name']}"}
        if "command_line" in shape.parts:
            values["command_line"] = f"/{shape.parts['command_line']}"
        extra["values"] = Proposed(values, [f"{origin} ({parts})"], confidence)
    elif (
        shape.kind in ("flows", "dns")
        and len(reading.row_list) == 1
        and reading.row_list[0] in _FLOW_TABLE_KEYS
        and all(shape.parts.get(p) == p for p in ("dst", "dport") if p in shape.parts)
    ):
        extra["reader"] = Proposed(
            "flow_table", [f"{origin} (laid out as a flow table)"], confidence
        )
    return kind, extra


def _settle(proposal: ToolProposal) -> None:
    """Make ``facts`` a declaration that validates, dropping what will not."""
    facts = {name: held.value for name, held in proposal.fields.items()}
    if not facts:
        proposal.facts = {}
        return
    for drop in (None, *_DROP_ORDER):
        if drop is not None and drop in facts:
            facts.pop(drop)
            proposal.fields.pop(drop, None)
            proposal.notes.append(f"{drop} left out: the declaration would not validate with it")
        try:
            # A proposal is what an operator will save: held to the edit rules.
            with strict_declarations():
                ToolFacts.model_validate(facts)
        except (ValidationError, ValueError):
            continue
        proposal.facts = facts
        return
    proposal.facts = {}
    proposal.fields = {}
    proposal.notes.append("nothing proposed: no field validated")


# ---------------------------------------------------------------------------
# The probe calls
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ProbeCall:
    """One harmless call the probe may make, and what it fills.

    ``remote`` says the tool may reach a service of its own (its server does
    not mark it ``openWorldHint: false``, MCP's default being open).
    """

    tool: str
    arguments: dict[str, Any]
    bogus_path: str = ""
    remote: bool = True

    def as_dict(self) -> dict[str, Any]:
        return {"tool": self.tool, "arguments": dict(self.arguments), "remote": self.remote}


def harmless_call(proposal: ToolProposal) -> ProbeCall | None:
    """The harmless call for ``proposal``'s tool, or ``None`` when there is none.

    Only a tool its own server marks ``readOnlyHint: true`` and does not mark
    destructive is ever called: an unannotated tool may write, submit or
    rescan, and nothing about it says otherwise. Every required argument must
    be one this module can fill with a value that names no sample: a path
    under a directory that does not exist, the digest of empty input, a
    documentation address. A read-only tool that takes no argument is called
    with none.
    """
    if proposal.read_only is not True or proposal.destructive is True:
        return None
    by_name = {name: role for role, name in proposal.roles.items()}
    arguments: dict[str, Any] = {}
    bogus = ""
    for name in proposal.required:
        role = by_name.get(name)
        if role == "path":
            bogus = bogus or probe_path()
            arguments[name] = bogus
        elif role == "hash":
            arguments[name] = _empty_digest(name)
        elif role == "ip":
            arguments[name] = _PROBE_IP
        elif role == "domain":
            arguments[name] = _PROBE_DOMAIN
        elif role == "url":
            arguments[name] = f"{_PROBE_URL_SCHEME}://{_PROBE_DOMAIN}/"
        else:
            return None
    return ProbeCall(
        tool=proposal.tool,
        arguments=arguments,
        bogus_path=bogus,
        remote=proposal.open_world is not False,
    )


# RE2's metacharacters, escaped when a probe answer becomes a pattern.
_RE2_SPECIAL = frozenset("\\.^$|?*+()[]{}")


def _escaped(text: str) -> str:
    return "".join(f"\\{ch}" if ch in _RE2_SPECIAL else ch for ch in text)


def error_pattern_from(call: ProbeCall, text: str) -> Proposed | None:
    """The error pattern a prose answer to a missing-file call proposes, or ``None``.

    Only a call that sent a path no server can open is read: any answer it
    gets is the server saying it could not, and an answer the platform does
    not already read as an error (a ``tool_error`` marker, ``{"error": …}``)
    is one it would file as a finding. A one-line prose answer becomes a full
    match of that line, the path written as "any text".
    """
    if not call.bogus_path or not isinstance(text, str):
        return None
    stripped = text.strip()
    if not stripped or "\n" in stripped or "\r" in stripped:
        return None
    from maljan.schemas.evidence import parse_structured
    from maljan.schemas.tool_evidence import MAX_OUTPUT_CHARS
    from maljan.tools.errors import error_parts

    # Longer than a captured output is kept: not a line a pattern should copy.
    if len(stripped) > MAX_OUTPUT_CHARS:
        return None
    if parse_structured(stripped) is not None or error_parts(stripped) is not None:
        return None
    parts = stripped.split(call.bogus_path)
    evidence = [f"probe answer of {call.tool} to a path that does not exist"]
    if len(parts) == 1:
        # The same line may be the tool's answer to a file it opened and
        # found nothing in: only an admin who knows the tool can tell.
        match = _escaped(stripped)
        evidence.append("the answer does not name the path it could not open")
        confidence = LOW
    else:
        match = ".+".join(_escaped(part) for part in parts)
        confidence = MEDIUM
    pattern = {"match": match, "tools": [call.tool]}
    try:
        ErrorPattern.model_validate(pattern)
    except (ValidationError, ValueError):
        return None
    return Proposed(pattern, evidence, confidence)


_AUTO_NAME_RE = re.compile(
    r"(?<![A-Za-z0-9_])([A-Za-z][A-Za-z0-9]{1,7}[_.])[0-9a-fA-F]{4,16}(?![0-9A-Za-z_])"
)


def auto_name_prefixes_in(texts: Iterable[str]) -> Proposed | None:
    """The auto-name prefixes probe answers write at least twice, beyond the defaults."""
    counts: dict[str, int] = {}
    for text in texts:
        if not isinstance(text, str):
            continue
        for found in _AUTO_NAME_RE.finditer(text):
            prefix = found.group(1)
            counts[prefix] = counts.get(prefix, 0) + 1
    picked = [
        prefix
        for prefix, count in counts.items()
        if count >= 2 and prefix.rstrip("_.").lower() not in DEFAULT_AUTO_NAME_WORDS
    ]
    if not picked:
        return None
    try:
        check_auto_name_prefixes(picked)
    except ValueError:
        return None
    return Proposed(sorted(picked), ["probe answers (names written before an address)"], LOW)


# A required argument that names a file on disk.
_PATH_ARGUMENT = re.compile(r"path|^file(?:name)?$|^sample$", re.IGNORECASE)
# A required argument that names a place in code, never what was opened.
_PLACE_ARGUMENT = re.compile(r"addr|func|location|offset", re.IGNORECASE)


# A word saying a tool opens or loads what it is given.
_OPENS_WORD = re.compile(r"\b(?:open|load|import|analy[sz]e)(?:s|es|ed|ing)?\b")
# A description saying the tool opens, loads or imports the thing analysed:
# a binary, an executable, a sample or an image; a program or a file only
# when it says the opening is for analysis (``Opens a binary file with ... for
# analysis``, ``Import a binary into the project from a file path``). A
# program opened from a project is no sample.
_OPENS_SAMPLE = re.compile(
    r"\b(?:open|load|import)(?:s|ed|ing)?\b[^.;]{0,40}?"
    r"\b(?:binar(?:y|ies)|executables?|samples?|images?)\b"
)
_OPENS_FOR_ANALYSIS = re.compile(
    r"\b(?:open|load|import)(?:s|ed|ing)?\b[^.;]{0,40}?\b(?:programs?|files?)\b"
    r"[^.;]{0,80}?\b(?:for analy[sz]is|to analy[sz]e)\b"
)
# A word saying a tool changes what is on disk or what its server holds, runs
# something, lists a directory, or works on something other than the sample
# (a configuration, settings, a plugin, a URL): such a tool is never the one
# that opens the sample.
_CHANGES_WORD = re.compile(
    r"\b(?:write|delete|remove|export|save|wipe|erase|overwrite|truncate|destroy|unlink"
    r"|shred|rename|move|upload|patch|apply|update|edit|install|uninstall|modify|set"
    r"|kill|clear|create|add|append|insert|replace|reset|commit|push|send|post|run"
    r"|exec|execute|script|start|stop|close|director(?:y|ies)|folders?|dir|ls"
    r"|config|configs|configuration|settings?|preferences?|plugins?|extensions?|urls?)"
    r"(?:s|es|ed|ing|d)?\b"
)
# A path argument naming where something is written, never what is read.
_OUTPUT_ARGUMENT = re.compile(r"out|dest|save|target|export", re.IGNORECASE)


def _words(text: str) -> str:
    """``text`` lowered with its name separators and case changes read as spaces."""
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", text)
    return re.sub(r"[_\-.]+", " ", spaced).lower()


def _opens_read_only(name: str, definition: Any, annotations: Any) -> bool:
    """Whether a path-only tool shows it opens the sample for analysis and changes nothing.

    Positive evidence only, one of two kinds:

    * the server marks it read-only (``readOnlyHint`` true) and its name or
      description says it opens, loads, imports or analyses; or
    * the server gives no annotations and its description (its name alone is
      not enough) says it opens, loads or imports a binary, an executable, a
      sample or an image, or a program or a file for analysis.

    Either way, a tool whose name, description or annotation title names a
    changing verb (write, delete, export, save, patch, apply, update, edit,
    install, run, …), a directory, or another object than the sample (a
    configuration, settings, a plugin, a URL) is never proposed, and so is
    one marked destructive or not read-only.
    """
    hints = annotations if isinstance(annotations, Mapping) else {}
    if hints.get("destructiveHint") is True or hints.get("readOnlyHint") is False:
        return False
    raw = _get(definition, "description")
    description = _words(raw) if isinstance(raw, str) else ""
    title = hints.get("title")
    text = " ".join(_words(t) for t in (name, title) if isinstance(t, str) and t)
    text = f"{text} {description}"
    if _CHANGES_WORD.search(text):
        return False
    if hints.get("readOnlyHint") is True:
        return bool(_OPENS_WORD.search(text))
    if hints:
        return False
    # ``_words`` reads a sentence's full stop as a separator: the description
    # is read for the object with its own punctuation.
    plain = raw.lower() if isinstance(raw, str) else ""
    return bool(_OPENS_SAMPLE.search(plain) or _OPENS_FOR_ANALYSIS.search(plain))


def sample_open_in(definitions: Iterable[Any]) -> Proposed | None:
    """The ``sample_open`` the tool schemas suggest, or ``None``.

    Proposed when exactly one tool that shows it opens the file and changes
    nothing (:func:`_opens_read_only`) takes a path that is not an output as
    its only required argument, and at least two other tools share
    one required argument that is neither a path nor a place in code: the one
    tool opens the file, and the others are given the name of what it opened.
    Only ``open_tool`` and ``path_argument`` are proposed; what names the
    opened thing is the operator's to declare. Low confidence: read from the
    schemas alone.
    """
    openers: list[tuple[str, str]] = []
    shared: dict[str, list[str]] = {}
    for definition in definitions:
        name = _get(definition, "name")
        if not isinstance(name, str):
            continue
        annotations = _plain(_get(definition, "annotations"))
        if isinstance(annotations, Mapping) and annotations.get("destructiveHint") is True:
            continue
        schema = _get(definition, "inputSchema")
        required = schema.get("required") if isinstance(schema, Mapping) else None
        required = [str(r) for r in required or [] if isinstance(r, str)]
        if len(required) == 1 and _PATH_ARGUMENT.search(required[0]):
            if not _OUTPUT_ARGUMENT.search(required[0]) and _opens_read_only(
                name, definition, annotations
            ):
                openers.append((name, required[0]))
            continue
        for argument in required:
            if not _PATH_ARGUMENT.search(argument) and not _PLACE_ARGUMENT.search(argument):
                shared.setdefault(argument, []).append(name)
    if len(openers) != 1:
        return None
    named = sorted((arg for arg, tools in shared.items() if len(tools) >= 2), key=str)
    if not named:
        return None
    tool, argument = openers[0]
    users = shared[named[0]]
    return Proposed(
        {"open_tool": tool, "path_argument": argument},
        [
            f"{tool} takes only {argument}",
            f"{len(users)} other tools take {named[0]}: {', '.join(sorted(users))}",
        ],
        LOW,
    )


# ---------------------------------------------------------------------------
# A server
# ---------------------------------------------------------------------------


# The hint a probe of a server not declared a sandbox source answers with
# when some of its tools' rows read like a sandbox run's.
ROLE_HINT = (
    "The rows of {tools} read like a sandbox run's (processes, connections, DNS questions or "
    "dropped files), but this server is not declared a sandbox source, so no sandbox kind is "
    "proposed. If it is a sandbox, declare roles: [{role}] on the server and test the "
    "connection again to have sandbox kinds proposed; a server that is no sandbox (a memory "
    "image, a capture, a lookup) needs nothing."
)


# The note for a server at an address other jobs share whose schemas suggest a
# ``sample_open``: offered incomplete, because only the operator can say which tools
# name an opened program and which read nothing a job opened.
SHARED_OPEN_INCOMPLETE = ("program_arguments", "job_safe_tools")
SHARED_OPEN_NOTE = (
    "sample_open is incomplete: {tool} opens a file and other tools take what it opened, but "
    "this server is reached at an address other jobs share, and a declaration without "
    "program_arguments and job_safe_tools would offer only the tools that take a path. "
    "Declare program_arguments and job_safe_tools beside it before accepting it."
)


def propose(
    definitions: Iterable[Any],
    *,
    capabilities: Mapping[str, Any] | None = None,
    answers: Mapping[str, tuple[ProbeCall, Any]] | None = None,
    skip: Iterable[str] = (),
    sandbox_source: bool = False,
    remote: bool = False,
) -> dict[str, Any]:
    """The proposals for every tool ``definitions`` lists, as JSON the console reads.

    ``{"v": 1, "tools": {tool: {"facts", "fields", "notes"?}}, "server":
    {field: proposed}, "planned"?: [{tool, arguments, remote}], "failed"?:
    {tool: reason}, "notes"?: [text]}``. ``planned`` lists the harmless calls the operator may
    confirm; ``failed`` the tools whose schema could not be read, each losing
    only its own proposal. ``answers`` are the harmless calls made and what
    each returned (the text, or the parsed object); ``skip`` names tools
    proposed for nothing (the manifest tool itself); ``sandbox_source`` says
    the server is declared a sandbox source (:func:`propose_tool`). ``notes``
    holds the hint, for a server that is not, that names the tools whose rows
    read like a sandbox run's (:data:`ROLE_HINT`): nothing is proposed from
    them, since such rows are also what a memory image, a capture or a lookup
    answers with, and the admin knows which this server is. ``remote`` says the
    server is reached at an address other jobs share: a ``sample_open`` read
    from the schemas names no ``program_arguments`` and no ``job_safe_tools``,
    and accepted there it would offer only the tools that take a path, so it is
    offered marked ``incomplete`` (``program_arguments``, ``job_safe_tools``),
    with a note that says what to declare (:data:`SHARED_OPEN_NOTE`).
    """
    definitions = list(definitions)
    cells = _manifest_cells(capabilities)
    skipped = set(skip)
    answered = dict(answers or {})
    tools: dict[str, Any] = {}
    failed: dict[str, str] = {}
    planned: list[dict[str, Any]] = []
    texts: list[str] = []
    errors: list[dict[str, Any]] = []
    error_evidence: list[str] = []
    error_confidence = MEDIUM
    shaped: list[str] = []
    for definition in definitions:
        name = _get(definition, "name")
        if not isinstance(name, str) or name in skipped:
            continue
        try:
            held = answered.get(name)
            answer = _parsed(held[1]) if held is not None else None
            proposal = propose_tool(
                definition,
                manifest_cell=cells.get(name),
                answer=answer,
                sandbox_source=sandbox_source,
            )
            if proposal is None:
                continue
            if proposal.run_shaped:
                shaped.append(name)
            call = harmless_call(proposal)
            if held is not None:
                made, raw = held
                text = raw if isinstance(raw, str) else ""
                texts.append(text)
                found = error_pattern_from(made, text)
                if found is not None:
                    errors.append(found.value)
                    error_evidence.extend(found.evidence)
                    error_confidence = min(error_confidence, found.confidence, key=_rank)
        except Exception as exc:  # noqa: BLE001 — one tool's schema costs only its proposal
            failed[name] = f"no proposal: reading its schema raised {type(exc).__name__}"
            continue
        tools[name] = proposal.as_dict()
        if call is not None:
            planned.append(call.as_dict())
    server: dict[str, Any] = {}
    if errors:
        server["error_patterns"] = Proposed(errors, error_evidence, error_confidence).as_dict()
    prefixes = auto_name_prefixes_in(texts)
    if prefixes is not None:
        server["auto_name_prefixes"] = prefixes.as_dict()
    named = [d for d in definitions if isinstance(_get(d, "name"), str)]
    opens = sample_open_in(d for d in named if _get(d, "name") not in skipped)
    notes: list[str] = []
    if opens is not None and remote:
        opens.incomplete = SHARED_OPEN_INCOMPLETE
        notes.append(SHARED_OPEN_NOTE.format(tool=opens.value["open_tool"]))
    if opens is not None:
        server["sample_open"] = opens.as_dict()
    out: dict[str, Any] = {"v": PROPOSALS_VERSION, "tools": tools, "server": server}
    if shaped:
        notes.append(ROLE_HINT.format(tools=", ".join(shaped), role=SANDBOX_ROLE))
    if notes:
        out["notes"] = notes
    if planned:
        out["planned"] = planned
    if failed:
        out["failed"] = failed
    return out


def _manifest_cells(capabilities: Mapping[str, Any] | None) -> dict[str, Mapping[str, Any]]:
    cells = (capabilities or {}).get("tools") if isinstance(capabilities, Mapping) else None
    out: dict[str, Mapping[str, Any]] = {}
    for cell in cells if isinstance(cells, list) else []:
        if isinstance(cell, Mapping) and isinstance(cell.get("name"), str):
            out.setdefault(cell["name"], cell)
    return out


def _parsed(raw: Any) -> Any:
    """A probe answer as the object it carries: the server's structure, else its JSON text."""
    from maljan.agents.mcp_client import structured_content_of
    from maljan.schemas.evidence import parse_structured

    content = structured_content_of(raw)
    if content is not None:
        return content
    if isinstance(raw, str):
        return parse_structured(raw)
    return raw


def plan_calls(definitions: Iterable[Any], *, skip: Iterable[str] = ()) -> list[ProbeCall]:
    """The harmless calls a probe makes when the operator asks for them, one per callable tool."""
    skipped = set(skip)
    calls: list[ProbeCall] = []
    for definition in definitions:
        name = _get(definition, "name")
        if not isinstance(name, str) or name in skipped:
            continue
        try:
            proposal = propose_tool(definition)
            call = harmless_call(proposal) if proposal is not None else None
        except Exception:  # noqa: BLE001 — a schema that cannot be read plans no call
            continue
        if call is not None:
            calls.append(call)
    return calls


__all__ = [
    "HIGH",
    "LOW",
    "MEDIUM",
    "PROPOSALS_VERSION",
    "ProbeCall",
    "Proposed",
    "ToolProposal",
    "auto_name_prefixes_in",
    "error_pattern_from",
    "harmless_call",
    "plan_calls",
    "probe_path",
    "propose",
    "propose_tool",
    "shape_of_schema",
    "shape_of_value",
]

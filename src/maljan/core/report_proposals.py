"""A proposed report format declaration, read from the shape of a report no format recognises.

An operator who allows it (``"unread"`` in ``sandbox.upload.allowed_formats``)
may attach a report no declared format and no registered reader recognises. It
is stored and reaches the run unread: its top-level blocks are raw
``report.<block>`` channels the dynamic analyst reads, and no observed fact is
minted from it. Beside it, the upload answers with a *proposal*: a format
declaration (``core.report_formats.ReportFormat``) that would read it through
the JSONPath mapping reader, built from the report's shape alone:

* ``detect``: one group testing each top-level block the report holds, by its
  type, so the declaration recognises reports shaped as this one;
* ``task_id_paths`` and ``target_sha256_paths``: a near-top field whose name
  says task (or analysis, job, submission) id, and a 64-hex value under a name
  holding ``sha256``;
* ``mapping``: where the processes, the connections, the DNS questions and the
  dropped files sit (``core.report_shapes``: lists of objects whose keys say
  so), with the renames from the report's own key names to the consumers'.

Each field carries its value, the place in the report it was read from
(``evidence``, a path, never report text) and how sure the reading is
(``confidence``), the proposal shape tool declarations use
(``core.declaration_proposals``). Nothing here is applied: the console shows
the proposal, the operator accepts or edits it, and only then is it saved as an
ordinary declaration; until then the report stays unread. No run reads a
proposal.

The report is untrusted: it is walked once with a stack (no recursion), each
node visited once, to :data:`READ_DEPTH` path segments below the top; a key
that cannot be written plainly in a path is never put into one; no report text
is copied into the proposal except the key names its paths are made of.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from typing import Any

from pydantic import ValidationError

from maljan.core.report_shapes import RowShape, protocol_spelling, row_shape

PROPOSAL_VERSION = 1

HIGH, MEDIUM, LOW = "high", "medium", "low"

# How deep below the report's top a proposal reads, in path segments: a
# sandbox puts its processes and connections within a few levels, and a fixed
# horizon keeps the walk linear however deeply a hostile report nests.
READ_DEPTH = 16

# How deep the task id and the target hash are looked for: near the top, outside
# any list.
_ID_DEPTH = 5

# A key a proposal writes into a path: no quote, backslash, slash, star or
# control character, so it reads the same in a JSONPath and a field path.
_SAFE_KEY = re.compile(r"^[A-Za-z0-9_@$][A-Za-z0-9_@$.\- ]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
_ID_KEYS = frozenset(
    {"task_id", "taskid", "analysis_id", "analysisid", "job_id", "jobid", "submission_id"}
)
_ID_WORDS = frozenset({"task", "analysis", "job", "submission", "run"})
_TARGET_WORDS = frozenset({"target", "sample", "file", "submission", "subject"})
_WORD = re.compile(r"[a-z0-9]+")

_TYPE_OF = {dict: "object", list: "array", str: "string", bool: "boolean"}


def _type_name(value: Any) -> str:
    if value is None:
        return "null"
    for kind, name in _TYPE_OF.items():
        if isinstance(value, kind):
            return name
    return "number" if isinstance(value, int | float) else ""


def _field(value: Any, evidence: list[str], confidence: str, *requires: str) -> dict[str, Any]:
    out: dict[str, Any] = {"value": value, "evidence": evidence, "confidence": confidence}
    if requires:
        out["requires"] = list(requires)
    return out


def _jsonpath(segments: tuple[str, ...]) -> str:
    return "$" + "".join("[*]" if s == "*" else f"['{s}']" for s in segments)


def _where(segments: tuple[str, ...]) -> str:
    """A report location as evidence names it: ``report.network.flows[]``."""
    out = "report"
    for segment in segments:
        out = f"{out}[]" if segment == "*" else f"{out}.{segment}"
    return out


class _Walk:
    """What one pass over the report finds: the lists of objects by path, and near-top scalars."""

    def __init__(self) -> None:
        # Each list of objects, by the path segments of the list: its rows' keys,
        # its row count and, per protocol key seen, the spellings of tcp and udp.
        self.lists: dict[tuple[str, ...], dict[str, Any]] = {}
        self.scalars: list[tuple[tuple[str, ...], Any]] = []

    def run(self, payload: Mapping[str, Any]) -> None:
        stack: list[tuple[Any, tuple[str, ...]]] = [(payload, ())]
        seen: set[int] = set()
        while stack:
            node, path = stack.pop()
            if isinstance(node, dict | list):
                if id(node) in seen:
                    continue
                seen.add(id(node))
            if len(path) >= READ_DEPTH:
                continue
            if isinstance(node, dict):
                for key, value in node.items():
                    if not isinstance(key, str) or not _SAFE_KEY.match(key):
                        continue
                    at = (*path, key)
                    if isinstance(value, dict | list):
                        stack.append((value, at))
                    elif len(at) <= _ID_DEPTH and "*" not in at:
                        self.scalars.append((at, value))
            elif isinstance(node, list):
                rows = [item for item in node if isinstance(item, dict)]
                if rows:
                    held = self.lists.setdefault(path, {"keys": {}, "rows": 0, "protocols": {}})
                    held["rows"] += len(rows)
                    keys: dict[str, None] = held["keys"]
                    for row in rows:
                        for key, value in row.items():
                            if isinstance(key, str) and _SAFE_KEY.match(key):
                                keys.setdefault(key, None)
                                spelled = protocol_spelling(value)
                                if spelled is not None:
                                    held["protocols"].setdefault(key, {}).setdefault(*spelled)
                at = (*path, "*")
                stack.extend((item, at) for item in node if isinstance(item, dict | list))


def _containers(node: Mapping[str, Any], prefix: str) -> list[tuple[str, str]]:
    return [
        (f"{prefix}/{key}", _type_name(value))
        for key, value in node.items()
        if isinstance(key, str) and _SAFE_KEY.match(key) and isinstance(value, dict | list)
    ]


def _detect(payload: Mapping[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    """One detect group: each plainly named top-level block, by its type.

    A report of one block is recognised by that block's own blocks too, so the
    test is no looser than the report's shape. With no block at all, its
    plainly named top-level values by type.
    """
    blocks = _containers(payload, "")
    if len(blocks) == 1:
        only = payload[blocks[0][0][1:]]
        if isinstance(only, dict):
            blocks += _containers(only, blocks[0][0])
    if not blocks:
        blocks = [
            (f"/{key}", _type_name(value))
            for key, value in payload.items()
            if isinstance(key, str) and _SAFE_KEY.match(key) and _type_name(value)
        ]
    ordered = sorted(blocks)
    tests = [{"path": path, "types": [kind]} for path, kind in ordered]
    return tests, [f"report{path.replace('/', '.')} ({kind})" for path, kind in ordered]


def _words(name: str) -> set[str]:
    return set(_WORD.findall(name.lower()))


def _task_id(walk: _Walk) -> dict[str, Any] | None:
    for path, value in sorted(walk.scalars, key=lambda item: len(item[0])):
        if isinstance(value, bool) or not isinstance(value, str | int) or value == "":
            continue
        name = path[-1].lower()
        words = _words(name)
        if name in _ID_KEYS:
            return _field(["/" + "/".join(path)], [_where(path)], MEDIUM)
        if "id" in words and words & _ID_WORDS:
            return _field(["/" + "/".join(path)], [_where(path)], LOW)
    return None


def _target(walk: _Walk) -> tuple[dict[str, Any], tuple[str, ...]] | None:
    candidates = [
        (path, value)
        for path, value in walk.scalars
        if isinstance(value, str) and _SHA256.match(value) and "sha256" in path[-1].lower()
    ]
    if not candidates:
        return None
    # A hash under a name saying target or sample first, then the shallowest.
    candidates.sort(
        key=lambda item: (
            not any(_words(segment) & _TARGET_WORDS for segment in item[0][:-1]),
            len(item[0]),
        )
    )
    path = candidates[0][0]
    named = any(_words(segment) & _TARGET_WORDS for segment in path[:-1])
    return _field(["/" + "/".join(path)], [_where(path)], MEDIUM if named else LOW), path


# The consumer fields each mapped channel's rows are read by.
_CONSUMER_FIELDS: dict[str, tuple[str, ...]] = {
    "processes": ("pid", "ppid", "name", "command_line"),
    "dropped_files": ("name", "sha256", "size"),
    "tcp": ("dst", "dport"),
    "udp": ("dst", "dport"),
    "dns": ("request", "type", "answers"),
}


def _filtered(segments: tuple[str, ...], key: str, value: str) -> str:
    """The list's JSONPath with its rows filtered to those whose ``key`` is ``value``."""
    escaped = value.replace("\\", "\\\\").replace("'", "\\'")
    return _jsonpath(segments) + f"[?@['{key}']=='{escaped}']"


def _channels(walk: _Walk) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    """``(channel paths, field renames)``, each a proposed field, for the first list of each kind.

    Lists are tried shallowest first, then in path order, so the proposal is
    the same for the same report.
    """
    channels: dict[str, dict[str, Any]] = {}
    renames: dict[str, dict[str, Any]] = {}
    for path in sorted(walk.lists, key=lambda p: (len(p), p)):
        held = walk.lists[path]
        name = next((s for s in reversed(path) if s != "*"), "")
        shape = row_shape(name, held["keys"])
        if shape is None:
            continue
        where = _where((*path, "*"))
        evidence = [f"{where} ({', '.join(sorted(shape.parts.values()))})"]
        for channel, expression, confidence in _channel_paths(shape, path, held):
            if channel in channels:
                continue
            channels[channel] = _field(expression, evidence, confidence)
            for part, key in shape.parts.items():
                if part in _CONSUMER_FIELDS[channel] and key != part:
                    renames[f"{channel}.{part}"] = _field(
                        key, [f"{where}.{key}"], confidence, f"mapping.{channel}"
                    )
    return channels, renames


def _channel_paths(
    shape: RowShape, path: tuple[str, ...], held: Mapping[str, Any]
) -> list[tuple[str, str, str]]:
    rows = _jsonpath((*path, "*"))
    if shape.kind != "flows":
        return [(shape.kind, rows, shape.confidence)]
    words = _words(next((s for s in reversed(path) if s != "*"), ""))
    for proto in ("tcp", "udp"):
        if proto in words:
            return [(proto, rows, shape.confidence)]
    spellings = held["protocols"].get(shape.protocol_key, {}) if shape.protocol_key else {}
    if spellings:
        return [
            (proto, _filtered(path, shape.protocol_key, spellings[proto]), MEDIUM)
            for proto in ("tcp", "udp")
            if proto in spellings
        ]
    # Connections with no protocol named: read as TCP, the guess to check.
    return [("tcp", rows, LOW)]


def _kept_blocks(
    payload: Mapping[str, Any], walk: _Walk, paths: list[str], mapping: Mapping[str, Any]
) -> dict[str, dict[str, Any]]:
    """An operator channel for each block a mapped path's top-level block holds that no path reads.

    The mapping reader keeps a top-level block no path starts in whole, as a
    raw ``report.<block>`` channel; a block a path starts in is read only
    through its paths. So each direct child of such a block that no path
    reaches is proposed as a channel of its own, kept for the analyst to read
    raw: no fact is drawn from it.
    """
    starts = [*paths, str(mapping.get("target_sha256") or "")]
    named: dict[str, list[str]] = {}
    for path in starts:
        found = re.match(r"^\$\['([^']*)'\](?:\['([^']*)'\])?", path)
        if found:
            named.setdefault(found.group(1), []).append(found.group(2) or "")
    out: dict[str, dict[str, Any]] = {}
    for block, children in sorted(named.items()):
        held = payload.get(block)
        if not isinstance(held, dict) or "" in children:
            continue
        for key, value in held.items():
            if key in children or not isinstance(key, str) or not _SAFE_KEY.match(key):
                continue
            if value in (None, "", [], {}):
                continue
            segments = (block, key, "*") if isinstance(value, list) else (block, key)
            out[f"{block}.{key}"] = _field(
                _jsonpath(segments),
                [f"{_where((block, key))} (read by no proposed path)"],
                MEDIUM,
            )
    return out


def _name_for(payload: Mapping[str, Any]) -> str:
    """A format name for the proposal, the same for reports shaped alike."""
    keys = "\n".join(sorted(k for k in payload if isinstance(k, str)))
    return "sandbox_" + hashlib.sha256(keys.encode("utf-8", "replace")).hexdigest()[:8]


def propose_format(payload: Mapping[str, Any]) -> dict[str, Any]:
    """The proposed declaration of the format of ``payload``, with each field's evidence.

    ``{"v": 1, "fields": {...}, "declaration": {...}}``; ``declaration`` is the
    proposal as one ``ReportFormat`` that validates, or absent with ``failed``
    saying why none could be made. Never raises on what the report holds.
    """
    from maljan.core.report_formats import ReportFormat

    fields: dict[str, dict[str, Any]] = {}
    walk = _Walk()
    walk.run(payload)
    tests, detect_evidence = _detect(payload)
    if tests:
        fields["detect"] = _field([tests], detect_evidence, MEDIUM)
    fields["reader"] = _field(
        "generic", ["no declared format and no registered reader recognises the report"], HIGH
    )
    task = _task_id(walk)
    if task is not None:
        fields["task_id_paths"] = task
    target = _target(walk)
    mapping: dict[str, Any] = {"target_sha256": ""}
    if target is not None:
        fields["target_sha256_paths"], target_path = target
        mapping["target_sha256"] = _jsonpath(target_path)
        fields["mapping.target_sha256"] = _field(
            mapping["target_sha256"], fields["target_sha256_paths"]["evidence"], MEDIUM
        )
    channels, renames = _channels(walk)
    for channel, proposed in channels.items():
        fields[f"mapping.{channel}"] = proposed
        mapping[channel] = proposed["value"]
    kept = _kept_blocks(payload, walk, [p["value"] for p in channels.values()], mapping)
    if kept:
        mapping["channels"] = {name: proposed["value"] for name, proposed in kept.items()}
        for name, proposed in kept.items():
            fields[f"mapping.channels.{name}"] = proposed
    if renames:
        mapping["field_names"] = {k: v["value"] for k, v in renames.items()}
        for key, proposed in renames.items():
            fields[f"mapping.field_names.{key}"] = proposed
    out: dict[str, Any] = {"v": PROPOSAL_VERSION, "fields": fields}
    if not tests:
        out["failed"] = "no top-level block is named plainly enough to recognise the report by"
        return out
    declaration: dict[str, Any] = {
        "name": _name_for(payload),
        "detect": [tests],
        "reader": "generic",
        "mapping": mapping,
    }
    for key in ("task_id_paths", "target_sha256_paths"):
        if key in fields:
            declaration[key] = fields[key]["value"]
    try:
        ReportFormat.model_validate(declaration)
    except ValidationError as exc:
        out["failed"] = f"the proposal does not validate ({exc.error_count()} errors)"
        return out
    out["declaration"] = declaration
    return out

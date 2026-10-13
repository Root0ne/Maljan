"""A proposed report format declaration, read from the shape of a report no format recognises.

An operator who allows it (``"unread"`` in ``sandbox.upload.allowed_formats``)
may attach a report no declared format and no registered reader recognises. It
is stored and reaches the run unread: its top-level blocks are raw
``report.<block>`` channels the dynamic analyst reads, and no observed fact is
minted from it. Beside it, the upload answers with a *proposal*: a format
declaration (``core.report_formats.ReportFormat``) that would read it through
the JSONPath mapping reader, built from the report's shape alone:

* ``detect``: one group testing, by type, the blocks the proposed paths start
  in (each path's first two named blocks), so the declaration recognises
  reports shaped as this one where it reads them;
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

Each top-level block a proposed path starts in is also kept whole, as the
raw ``report.<block>`` channel the unread read gave it, so nothing the
analyst read unread is lost once the declaration is accepted.

The report is untrusted: it is walked once with a stack (no recursion), each
node visited once, to :data:`READ_DEPTH` path segments below the top; a key
that cannot be written plainly in a path is never put into one; no report text
is copied into the proposal except the key names its paths are made of. The
two are the proposer's reading horizons, not limits on what a run reads (an
accepted declaration's paths are read at any depth): where either leaves
something unread, the proposal's ``notes`` say how much. The proposal's size
follows the declaration's own fields, never the report's block count: blocks
no path reads are counted in one evidence entry, never listed.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from typing import Any

from pydantic import ValidationError

from maljan.core.report_shapes import (
    DNS_TYPE_KEYS,
    RowShape,
    is_record_type,
    protocol_spelling,
    row_shape,
)

PROPOSAL_VERSION = 1

HIGH, MEDIUM, LOW = "high", "medium", "low"

# How deep below the report's top a proposal looks for lists, in path segments:
# a sandbox puts its processes and connections within a few levels. A reading
# horizon of the proposer, announced in the proposal's notes where it leaves
# something unread; an accepted declaration's paths are read at any depth.
READ_DEPTH = 16
# The longest key a proposal writes into a path, likewise a reading horizon.
KEY_HORIZON = 128

# How deep the task id and the target hash are looked for: near the top, outside
# any list.
_ID_DEPTH = 5

# A key a proposal writes into a path: no quote, backslash, slash, star or
# control character, so it reads the same in a JSONPath and a field path.
_SAFE_KEY = re.compile(r"^[A-Za-z0-9_@$][A-Za-z0-9_@$.\- ]*$")
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


def _plain_key(key: Any) -> bool:
    return isinstance(key, str) and len(key) <= KEY_HORIZON and bool(_SAFE_KEY.match(key))


class _Walk:
    """What one pass over the report finds: the lists of objects by path, and near-top scalars."""

    def __init__(self) -> None:
        # Each list of objects, by the path segments of the list: its rows' keys,
        # its row count, per protocol key seen the spellings of tcp and udp, and
        # per question-type key whether every value is a DNS record type.
        self.lists: dict[tuple[str, ...], dict[str, Any]] = {}
        self.scalars: list[tuple[tuple[str, ...], Any]] = []
        # What the reading horizons left unread: containers below READ_DEPTH,
        # and keys no path can be written with (too long, or not plain).
        self.too_deep = 0
        self.unwritable_keys = 0

    def _key(self, key: Any) -> bool:
        if _plain_key(key):
            return True
        self.unwritable_keys += 1
        return False

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
                self.too_deep += 1
                continue
            if isinstance(node, dict):
                for key, value in node.items():
                    if not self._key(key):
                        continue
                    at = (*path, key)
                    if isinstance(value, dict | list):
                        stack.append((value, at))
                    elif len(at) <= _ID_DEPTH and "*" not in at:
                        self.scalars.append((at, value))
            elif isinstance(node, list):
                rows = [item for item in node if isinstance(item, dict)]
                if rows:
                    held = self.lists.setdefault(
                        path, {"keys": {}, "rows": 0, "protocols": {}, "record_types": {}}
                    )
                    held["rows"] += len(rows)
                    keys: dict[str, None] = held["keys"]
                    record_types: dict[str, bool] = held["record_types"]
                    for row in rows:
                        for key, value in row.items():
                            if not self._key(key):
                                continue
                            keys.setdefault(key, None)
                            spelled = protocol_spelling(value)
                            if spelled is not None:
                                held["protocols"].setdefault(key, {}).setdefault(*spelled)
                            if key.lower() in DNS_TYPE_KEYS:
                                held_type = record_types.get(key, True)
                                record_types[key] = held_type and is_record_type(value)
                at = (*path, "*")
                stack.extend((item, at) for item in node if isinstance(item, dict | list))

    def notes(self) -> list[str]:
        """What the reading horizons left unread, in words; empty where they left nothing."""
        out: list[str] = []
        if self.too_deep:
            out.append(
                f"{self.too_deep} containers nested more than {READ_DEPTH} path segments "
                "below the top were not looked into for lists (the proposer's reading horizon; "
                "a declaration's paths are read at any depth)"
            )
        if self.unwritable_keys:
            out.append(
                f"{self.unwritable_keys} keys longer than {KEY_HORIZON} characters or holding "
                "a quote, slash, star or control character were not put into a path "
                "(the proposer's reading horizon; a declaration may name them)"
            )
        return out


def _named_prefix(expression: str) -> tuple[str, ...]:
    """The named blocks a proposed JSONPath starts with, before its first list or filter."""
    return tuple(re.findall(r"\['([^']*)'\]", expression.split("[*]", 1)[0].split("[?", 1)[0]))


def _detect(
    payload: Mapping[str, Any], starts: list[tuple[str, ...]]
) -> tuple[list[dict[str, Any]], list[str]]:
    """One detect group: by type, the first two named blocks of each place the proposal reads.

    ``starts`` are the named segments each proposed path (and the task id and
    target hash) starts with. The group is as large as the declaration's own
    fields, never the report's block count.
    """
    tests: dict[str, str] = {}
    for start in starts:
        node: Any = payload
        for depth, segment in enumerate(start[:2]):
            if not isinstance(node, Mapping) or segment not in node:
                break
            node = node[segment]
            if not isinstance(node, dict | list):
                break
            tests.setdefault("/" + "/".join(start[: depth + 1]), _type_name(node))
    ordered = sorted(tests.items())
    return (
        [{"path": path, "types": [kind]} for path, kind in ordered],
        [f"report{path.replace('/', '.')} ({kind})" for path, kind in ordered],
    )


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
    """``(channel paths, field renames)``, each a proposed field, for each kind's strongest list.

    Every list is read; per channel the list whose reading is strongest
    (:attr:`core.report_shapes.RowShape.strength`: its confidence, the
    evidence of its own kind it carries, then how many parts it names) is
    the channel's, so a decoy list that only resembles a kind never takes it
    from a list that is plainly of it. Equal readings go to the shallowest,
    then the first in path order, so the proposal is the same for the same
    report.
    """
    best: dict[str, tuple[tuple[int, int, int], RowShape, tuple[str, ...], str, str]] = {}
    for path in sorted(walk.lists, key=lambda p: (len(p), p)):
        held = walk.lists[path]
        names = [s for s in reversed(path) if s != "*"][:2]
        seen = held["record_types"]
        record_types = any(seen.values()) if seen else None
        shape = row_shape(names, held["keys"], record_types=record_types)
        if shape is None:
            continue
        for channel, expression, confidence in _channel_paths(shape, path, held):
            strength = (_RANK[confidence], *shape.strength[1:])
            if channel not in best or strength > best[channel][0]:
                best[channel] = (strength, shape, path, expression, confidence)
    channels: dict[str, dict[str, Any]] = {}
    renames: dict[str, dict[str, Any]] = {}
    chosen = sorted(best.items(), key=lambda item: (len(item[1][2]), item[1][2], item[0]))
    for channel, (_strength, shape, path, expression, confidence) in chosen:
        where = _where((*path, "*"))
        evidence = [f"{where} ({', '.join(sorted(shape.parts.values()))})"]
        channels[channel] = _field(expression, evidence, confidence)
        for part, key in shape.parts.items():
            if part in _CONSUMER_FIELDS[channel] and key != part:
                renames[f"{channel}.{part}"] = _field(
                    key, [f"{where}.{key}"], confidence, f"mapping.{channel}"
                )
    return channels, renames


_RANK = {LOW: 0, MEDIUM: 1, HIGH: 2}


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
    payload: Mapping[str, Any], starts: list[tuple[str, ...]]
) -> dict[str, dict[str, Any]]:
    """The raw ``report.<block>`` channel for each top-level block a proposed path starts in.

    The mapping reader keeps a top-level block no path starts in whole, as a
    raw ``report.<block>`` channel; a block a path starts in is read only
    through its paths. So each such block is proposed kept whole as the same
    channel the unread read gave it, for the analyst to read raw beside the
    facts read from it: nothing the unread read showed is lost, and no fact is
    drawn from the channel. One entry per block, whatever the block holds; its
    evidence counts the blocks it holds that no proposed path starts in.
    """
    named: dict[str, set[str]] = {}
    for start in starts:
        if start:
            named.setdefault(start[0], set()).update(start[1:2])
    out: dict[str, dict[str, Any]] = {}
    for block, children in sorted(named.items()):
        held = payload.get(block)
        if not isinstance(held, dict) or not held:
            continue
        unread = sum(
            1 for key, value in held.items() if key not in children and value not in _EMPTY
        )
        if not unread:
            continue
        out[f"report.{block}"] = _field(
            _jsonpath((block,)),
            [
                f"report.{block} kept whole, as the unread read kept it: it holds {unread} "
                "blocks no proposed path reads"
            ],
            MEDIUM,
        )
    return out


_EMPTY: tuple[Any, ...] = (None, "", [], {})


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
    starts = [_named_prefix(str(p["value"])) for p in channels.values()]
    starts += [_named_prefix(mapping["target_sha256"])] if mapping["target_sha256"] else []
    if task is not None:
        starts += [tuple(task["value"][0].strip("/").split("/"))]
    kept = _kept_blocks(payload, starts)
    if kept:
        mapping["channels"] = {name: proposed["value"] for name, proposed in kept.items()}
        for name, proposed in kept.items():
            fields[f"mapping.channels.{name}"] = proposed
    if renames:
        mapping["field_names"] = {k: v["value"] for k, v in renames.items()}
        for key, proposed in renames.items():
            fields[f"mapping.field_names.{key}"] = proposed
    out: dict[str, Any] = {"v": PROPOSAL_VERSION, "fields": fields}
    notes = walk.notes()
    if notes:
        out["notes"] = notes
    read = {p for p in fields if p.startswith("mapping.") and p.count(".") == 1}
    read -= {"mapping.target_sha256"}
    tests, detect_evidence = _detect(payload, starts)
    if tests:
        fields["detect"] = _field([tests], detect_evidence, MEDIUM)
    if not read:
        out["failed"] = (
            "no list in the report reads as processes, connections, DNS questions or dropped "
            "files, so a declaration would read nothing the unread read does not"
        )
        return out
    if not tests:
        out["failed"] = "no block a proposed path starts in can be tested to recognise the report"
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

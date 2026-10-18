"""What a replay record is, read without importing the platform.

A record carries the version of its schema (``schema``) and lists every part
it could not replay under ``not_replayed``. A part that raised is listed there
marked ``"error": true``; a crash is not a decision, so a replay or a
comparison with one ends with status 2. A record written before records
carried a schema (version 1) named a part that raised by where it raised, and
is read by those words.

From version 3 a record carries no value from the run unless it was asked for
the text (``show_text``): codes, ids, kinds, counts and digests only. A
finding's subject that is not an ATT&CK id or a ledger or sandbox item id is
its kind and a digest of its value (:func:`value_free_subject`), an
indicator's publish answer is its head (``yes``, ``no``) and a digest of the
whole answer (:func:`answer_head`), and every model-written word is a digest.
``--show-text`` adds the words beside them, in fields of their own
(``*_text``, ``message``, ``claim``, ``value``), so the record has the same
value-free fields either way and two records compare on those.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Mapping
from typing import Any

# The version of the record a replay writes. Two records of different versions
# are compared on what both define, the rest is listed as not compared, and a
# comparison that left a part out is partial (status 2).
REPLAY_SCHEMA = 4

# The record's own keys, which say how and where it was made: never compared.
BOOKKEEPING_KEYS: frozenset[str] = frozenset(
    {"schema", "format", "run", "rules", "stored", "show_text", "against_stored"}
)

# How a version-1 record named a part that raised:
# ``<Exception> at <file>.py:<line> (<function>)``.
_OLD_ERROR_RE = re.compile(r"^\w+ at [\w.-]+\.py:\d+ \(")

# A subject that is an id and is shown as it is: an ATT&CK technique or a
# ledger entry. A sandbox item id (``proc:84``) is told by the platform's own
# reader, which the caller passes (``is_item``): a shape alone would let
# ``port:4444`` through.
_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)
_ENTRY_RE = re.compile(r"^ev_\d+$")
# A subject that names its kind before its value (``domain:host.example``).
_KIND_RE = re.compile(r"^([a-z][a-z0-9_-]{0,31}):(.+)$", re.DOTALL)
# An object's label as a finding's path quotes it (``objects[3] 'malware--x'``).
_LABEL_RE = re.compile(r"'([^']*)'")
# The id part of a STIX id that carries no value: a number or a UUID.
_PLAIN_ID_RE = re.compile(
    r"^(?:\d{1,9}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$", re.IGNORECASE
)
# The head of a publish answer: one word before its reason.
_HEAD_RE = re.compile(r"^([a-z]+)(?::|$)")


def schema_of(record: Mapping[str, Any]) -> int:
    """The schema version a record was written in (1 for one that states none)."""
    try:
        return int(record.get("schema") or 1)
    except (TypeError, ValueError):
        return 1


def errors(record: Mapping[str, Any]) -> list[dict[str, Any]]:
    """The parts of a replay record that raised."""
    rows = [row for row in record.get("not_replayed") or [] if isinstance(row, dict)]
    if schema_of(record) < 2:
        return [row for row in rows if _OLD_ERROR_RE.match(str(row.get("why") or ""))]
    return [row for row in rows if row.get("error")]


def digest(text: Any) -> str:
    """Twelve hex characters of the text's SHA-256: the same text, the same digest."""
    return hashlib.sha256(str(text).encode("utf-8", "replace")).hexdigest()[:12]


def value_free_subject(subject: Any, is_item: Callable[[str], bool] | None = None) -> str:
    """A finding's subject without the value in it; the same subject, the same result.

    An ATT&CK technique and a ledger entry are ids and stay as they are, and so
    does a sandbox item id when ``is_item`` says it is one. One that names its
    kind (``domain:host.example``) keeps the kind and digests the value; any
    other is ``sha256:`` and its digest. A subject is never passed for its
    shape alone: a value that looks like a digest is digested too.
    """
    said = str(subject or "")
    if not said or _TECHNIQUE_RE.match(said) or _ENTRY_RE.match(said):
        return said
    if is_item is not None and is_item(said):
        return said
    kind = _KIND_RE.match(said)
    if kind:
        return f"{kind.group(1)}:{digest(kind.group(2))}"
    return f"sha256:{digest(said)}"


def value_free_label(label: str) -> str:
    """An object's label without a value: its STIX type kept, an id part that is not a number
    or a UUID digested (``malware--x`` is ``malware--<12 hex>``)."""
    kind, dashes, rest = label.partition("--")
    if not dashes:
        return f"sha256:{digest(label)}" if label else label
    return label if _PLAIN_ID_RE.match(rest) else f"{kind}--{digest(rest)}"


def value_free_path(
    path: str, subject: str = "", is_item: Callable[[str], bool] | None = None
) -> str:
    """A finding's path without a value: the subject it writes and each quoted label, value-free."""
    shown = value_free_subject(subject, is_item)
    if subject and shown != subject:
        path = path.replace(subject, shown)
    return _LABEL_RE.sub(lambda found: f"'{value_free_label(found.group(1))}'", path)


def answer_head(answer: Any) -> str:
    """The head of a publish answer (``yes``, ``no``), or ``""`` when it has none."""
    found = _HEAD_RE.match(str(answer or ""))
    return found.group(1) if found else ""

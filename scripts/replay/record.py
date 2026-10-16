"""What a replay record is, read without importing the platform.

A record carries the version of its schema (``schema``) and lists every part
it could not replay under ``not_replayed``. A part that raised is listed there
marked ``"error": true``; a crash is not a decision, so a replay or a
comparison with one ends with status 2. A record written before records
carried a schema (version 1) named a part that raised by where it raised, and
is read by those words.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

# The version of the record a replay writes. Two records of different versions
# are compared on what both define, and the comparison says so.
REPLAY_SCHEMA = 2

# How a version-1 record named a part that raised:
# ``<Exception> at <file>.py:<line> (<function>)``.
_OLD_ERROR_RE = re.compile(r"^\w+ at [\w.-]+\.py:\d+ \(")


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

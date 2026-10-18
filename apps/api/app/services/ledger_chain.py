"""The evidence ledger's digests and hash chain, over the rows as they are stored.

Every stored ledger row gets a digest over a canonical serialisation of every
column it persists, and a chain value: the SHA-256 of the previous row's chain
value and its own digest, in ``seq`` order, starting from a genesis value bound
to the job. Both are computed from the row as the worker builds it, after the
last structure pass and after each ``spilled`` reference states how its upload
ended, which is exactly what a reader later reads back: a verifier recomputes
the chain from the rows alone.

The canonical form (version 1):

- every column :data:`DIGESTED` names, by column name, in a JSON object with
  sorted keys and compact separators, UTF-8, no NaN or infinity;
- a JSON column's value as the driver writes and reads it (one ``json``
  round trip), with numbers as JSONB hands them back: an integral float is the
  exact integer of its shortest decimal text (``1.0`` is ``1``), any other
  float keeps its shortest text;
- a timestamp as UTC ISO-8601 with microseconds; a value with no zone (SQLite)
  is UTC.

Left out are the row's bookkeeping: its random primary key, ``job_id`` (bound
once, in the genesis value), ``updated_at`` and the two chain columns.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

CHAIN_VERSION = 1
_ENTRY_TAG = b"maljan-evidence-entry/1\n"
_GENESIS_TAG = b"maljan-evidence-ledger/1\n"

# Every column of ``evidence_entries`` the digest covers, by column name.
DIGESTED: tuple[str, ...] = (
    "entry_id",
    "seq",
    "stage",
    "agent",
    "server",
    "tool",
    "ok",
    "error",
    "remediation",
    "duration_ms",
    "args",
    "args_repaired",
    "args_raw",
    "model",
    "output",
    "structured",
    "function_ranges",
    "truncated",
    "chars_dropped",
    "repeated_of",
    "symbol",
    "started_at",
    "created_at",
    "source",
    "facts",
    "reputation",
    "pack_step",
    "structured_from_server",
    "agent_role",
    "agent_tab",
    "spilled",
)
# The JSON columns: their values are read back through the driver's ``json``.
_JSON_COLUMNS = frozenset(
    {"args", "structured", "function_ranges", "facts", "reputation", "pack_step", "spilled"}
)
# The row's bookkeeping, never digested: named so a new column is a decision.
BOOKKEEPING: tuple[str, ...] = ("id", "job_id", "updated_at", "digest", "chain")


def _number(value: float) -> int | float:
    """A float as JSONB hands it back: an integral one is an exact integer."""
    if not math.isfinite(value):
        raise ValueError("a ledger value cannot be NaN or infinite")
    if value.is_integer():
        return int(Decimal(repr(value)))
    return value


def _normalised(value: Any) -> Any:
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return value
    if isinstance(value, float):
        return _number(value)
    if isinstance(value, int):
        return value
    if isinstance(value, Mapping):
        return {str(k): _normalised(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_normalised(v) for v in value]
    return value


def json_value(value: Any) -> Any:
    """``value`` as a JSON column stores and returns it, normalised."""
    if value is None:
        return None
    return _normalised(json.loads(json.dumps(value, allow_nan=False)))


def timestamp(value: Any) -> str | None:
    """A stored timestamp in its canonical text: UTC, microseconds."""
    if value is None:
        return None
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if not isinstance(value, datetime):
        raise TypeError(f"not a timestamp: {type(value).__name__}")
    moment: datetime = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def canonical(document: Any) -> bytes:
    """The one serialisation every digest here is taken over."""
    return json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _read(row: Any, name: str) -> Any:
    if isinstance(row, Mapping):
        return row.get(name)
    return getattr(row, name, None)


def entry_fields(row: Any) -> dict[str, Any]:
    """The digested columns of ``row`` (a row object or a mapping), canonical."""
    out: dict[str, Any] = {}
    for name in DIGESTED:
        value = _read(row, name)
        if name in _JSON_COLUMNS:
            out[name] = json_value(value)
        elif name == "created_at":
            out[name] = timestamp(value)
        elif isinstance(value, float):
            out[name] = _number(value)
        else:
            out[name] = value
    return out


def entry_digest(row: Any) -> str:
    """The SHA-256 of ``row``'s canonical form, as hex."""
    return hashlib.sha256(_ENTRY_TAG + canonical(entry_fields(row))).hexdigest()


def genesis(job_id: Any) -> str:
    """The chain value before the job's first row."""
    return hashlib.sha256(
        _GENESIS_TAG + canonical({"job_id": str(job_id), "version": CHAIN_VERSION})
    ).hexdigest()


def link(previous: str, digest: str) -> str:
    """The chain value after a row with ``digest`` that follows ``previous``."""
    return hashlib.sha256(f"{previous}:{digest}".encode("ascii")).hexdigest()


def chain_rows(job_id: Any, rows: Iterable[Any]) -> str:
    """Set ``digest`` and ``chain`` on each row object, in ``seq`` order; the head.

    ``rows`` are the row objects about to be inserted. The head is the last
    row's chain value, or the genesis value for a job with no row.
    """
    head = genesis(job_id)
    for row in sorted(rows, key=lambda r: int(_read(r, "seq") or 0)):
        digest = entry_digest(row)
        head = link(head, digest)
        row.digest = digest
        row.chain = head
    return head

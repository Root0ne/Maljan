"""The evidence ledger's digests and hash chain, over the rows as they are stored.

Every stored ledger row gets a digest over a canonical serialisation of every
column it persists (SHA-256), and a chain value: the HMAC-SHA256 of the
previous row's chain value and its own digest, in ``seq`` order, starting from
a genesis value bound to the job. Both are computed from the row as the worker
builds it, after the last structure pass and after each ``spilled`` reference
states how its upload ended, which is exactly what a reader later reads back: a
verifier recomputes the chain from the rows alone.

The chain, the seal and its amendments are keyed (:class:`ChainKey`): the key
is derived from the settings encryption key the platform already holds. They
prove integrity against anyone who can write the database but does not hold
that secret; someone who holds it can recompute everything. Anchoring the seal
outside the platform is the step that closes that (``operations.mdx``).

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
import hmac
import json
import math
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

CHAIN_VERSION = 1
_ENTRY_TAG = b"maljan-evidence-entry/1\n"
_GENESIS_TAG = b"maljan-evidence-ledger/1\n"
_LINK_TAG = b"maljan-evidence-link/1\n"
# The HKDF purpose label the chain key is derived under.
KEY_LABEL = b"maljan-ledger-chain-v1"

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


@dataclass(frozen=True)
class ChainKey:
    """The key the chain and its records are computed under, and its public id.

    Derived with HKDF-SHA256 from the settings encryption key the platform
    already holds (``SETTINGS_ENCRYPTION_KEY``), under a fixed purpose label,
    so no new secret exists and no other use of that key can produce these
    values. ``key_id`` is a short hash of the derived key, stored beside the
    seal so a verifier holding another key says so rather than calling the
    rows changed. The key itself is never logged or served.
    """

    key: bytes = field(repr=False)
    key_id: str


# What a stored ledger is chained under when the platform holds no settings
# key: the empty key, said on the seal (``key_id`` ``None``) and by every
# verification, because a chain anyone can recompute proves only that nothing
# changed by accident.
UNKEYED = ChainKey(key=b"", key_id="")


def derive_key(secret: str) -> ChainKey:
    """The chain key derived from ``secret`` (the settings encryption key's text)."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=KEY_LABEL).derive(
        secret.encode("utf-8")
    )
    key_id = hashlib.sha256(b"maljan-ledger-chain-key-id/1\n" + key).hexdigest()[:16]
    return ChainKey(key=key, key_id=key_id)


def platform_key() -> ChainKey:
    """The key derived from the platform's settings encryption key; :data:`UNKEYED` without one."""
    import os

    secret = ""
    try:
        from app.config import settings

        secret = settings.settings_encryption_key.get_secret_value().strip()
    except Exception:  # noqa: BLE001 — the environment is read below
        secret = ""
    if not secret:
        from maljan.core.settings_secrets import ENV_VAR

        secret = os.environ.get(ENV_VAR, "").strip()
    return derive_key(secret) if secret else UNKEYED


def keyed(key: ChainKey, tag: bytes, message: bytes) -> str:
    """HMAC-SHA256 of ``message`` under ``key``, domain-separated by ``tag``, as hex."""
    return hmac.new(key.key, tag + message, hashlib.sha256).hexdigest()


def genesis(job_id: Any, key: ChainKey) -> str:
    """The chain value before the job's first row."""
    return keyed(key, _GENESIS_TAG, canonical({"job_id": str(job_id), "version": CHAIN_VERSION}))


def link(previous: str, digest: str, key: ChainKey) -> str:
    """The chain value after a row with ``digest`` that follows ``previous``."""
    return keyed(key, _LINK_TAG, f"{previous}:{digest}".encode("ascii"))


def chain_rows(job_id: Any, rows: Iterable[Any], key: ChainKey) -> str:
    """Set ``digest`` and ``chain`` on each row object, in ``seq`` order; the head.

    ``rows`` are the row objects about to be inserted. The head is the last
    row's chain value, or the genesis value for a job with no row.
    """
    head = genesis(job_id, key)
    for row in sorted(rows, key=lambda r: int(_read(r, "seq") or 0)):
        digest = entry_digest(row)
        head = link(head, digest, key)
        row.digest = digest
        row.chain = head
    return head


# ── The seal ─────────────────────────────────────────────────────

# Where the seal and the amendments after it are kept, in the stored report
# payload and in the run summary column alike.
SEAL_KEY = "ledger_seal"
AMENDMENTS_KEY = "ledger_amendments"
_SEAL_KEYS = frozenset({SEAL_KEY, AMENDMENTS_KEY})
_REPORT_TAG = b"maljan-stored-report/1\n"
_RECORD_TAG = b"maljan-ledger-record/1\n"


def _without_seal(document: Any) -> Any:
    if isinstance(document, Mapping):
        document = {k: v for k, v in document.items() if k not in _SEAL_KEYS}
    return json_value(document)


def report_digest(malware_report: Any, run_summary: Any, stix_bundle: Any) -> str:
    """The SHA-256 of the stored report's three documents, each without its seal.

    The report payload, the run summary column and the STIX bundle column, as
    they are stored; the seal and amendment keys are left out of the first
    two, so the digest a seal records is the one recomputed after it is
    written.
    """
    document = {
        "malware_report": _without_seal(malware_report),
        "run_summary": _without_seal(run_summary),
        "stix_bundle": json_value(stix_bundle),
    }
    return hashlib.sha256(_REPORT_TAG + canonical(document)).hexdigest()


def record_digest(record: Mapping[str, Any], key: ChainKey) -> str:
    """The HMAC of a seal or an amendment under ``key``, over every key but its own ``digest``."""
    body = {k: json_value(v) for k, v in record.items() if k != "digest"}
    return keyed(key, _RECORD_TAG, canonical(body))


def seal(
    job_id: Any,
    rows: list[Any],
    head: str,
    *,
    report_sha256: str,
    sealed_at: datetime,
    key: ChainKey,
) -> dict[str, Any]:
    """The seal of a stored ledger: the chain head, what it covers, the key id, and its digest.

    ``key_id`` is ``None`` when the platform held no settings key and the
    chain was computed under :data:`UNKEYED`.
    """
    seqs = [int(_read(row, "seq") or 0) for row in rows]
    record: dict[str, Any] = {
        "version": CHAIN_VERSION,
        "algorithm": "hmac-sha256",
        "key_id": key.key_id or None,
        "job_id": str(job_id),
        "entries": len(rows),
        "first_seq": min(seqs) if seqs else None,
        "last_seq": max(seqs) if seqs else None,
        "head": head,
        "report_sha256": report_sha256,
        "sealed_at": timestamp(sealed_at),
    }
    record["digest"] = record_digest(record, key)
    return record


def amendment(
    previous: Mapping[str, Any],
    *,
    number: int,
    kind: str,
    before: str,
    after: str,
    at: datetime,
    key: ChainKey,
) -> dict[str, Any]:
    """An amendment to a sealed report, chained onto ``previous`` (the seal or the last amendment).

    It records what changed the stored report (``kind``), the report digest
    before and after, and the key it was computed under; it never touches a
    ledger row.
    """
    record: dict[str, Any] = {
        "number": number,
        "kind": kind,
        "prev": previous.get("digest"),
        "report_sha256_before": before,
        "report_sha256_after": after,
        "at": timestamp(at),
        "key_id": key.key_id or None,
    }
    record["digest"] = record_digest(record, key)
    return record


def amend(
    stored_payload: Mapping[str, Any],
    stored_summary: Any,
    payload: dict[str, Any],
    summary: Any,
    stix_bundle: Any,
    *,
    seal_record: Any,
    kind: str,
    key: ChainKey,
    at: datetime,
) -> tuple[dict[str, Any], Any, dict[str, Any] | None]:
    """The payload and run summary to write over a sealed report, with the amendment it needs.

    ``stored_*`` are the documents as stored, ``payload`` and ``summary`` what
    is about to replace them (``summary`` ``None`` leaves the stored one). A
    report without a seal, or a change that leaves the report digest as it
    was, is written as it is and needs no amendment (``None``). Otherwise an
    amendment chained onto the last record is appended to both documents.
    """
    if not isinstance(seal_record, Mapping) or not seal_record.get("digest"):
        return payload, summary, None
    next_summary = summary if summary is not None else stored_summary
    before = report_digest(stored_payload, stored_summary, stix_bundle)
    after = report_digest(payload, next_summary, stix_bundle)
    if before == after:
        return payload, summary, None
    held = stored_payload.get(AMENDMENTS_KEY)
    amendments = [dict(a) for a in held if isinstance(a, Mapping)] if isinstance(held, list) else []
    record = amendment(
        amendments[-1] if amendments else seal_record,
        number=len(amendments) + 1,
        kind=kind,
        before=before,
        after=after,
        at=at,
        key=key,
    )
    amendments.append(record)
    payload = {**payload, AMENDMENTS_KEY: amendments}
    if isinstance(next_summary, Mapping):
        next_summary = {**next_summary, AMENDMENTS_KEY: amendments}
    return payload, next_summary, record


def with_seal(document: Any, record: Mapping[str, Any]) -> Any:
    """A copy of a stored document with the seal written in; ``None`` stays ``None``."""
    if not isinstance(document, Mapping):
        return document
    return {**document, SEAL_KEY: dict(record)}

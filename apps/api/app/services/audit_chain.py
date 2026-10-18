"""The audit log's hash chain: rows that record the ledger's seal and its amendments.

A chained row is appended inside the caller's transaction, so it commits with
what it records (the seal with the stored ledger, an amendment with the report
it changes) or not at all. It takes the next ``chain_seq``, a SHA-256 digest
of its columns in canonical form (``ledger_chain.canonical``) and a chain value:
the HMAC of the previous chained row's chain value and its own digest, under
the ledger's key (``ledger_chain.ChainKey``), with that key's id beside it.

Appends are serialised by a PostgreSQL transaction-scoped advisory lock taken
inside a savepoint, and ``chain_seq`` is unique, so two writers can never fork
the chain. The append is best effort like every audit write
(``services.audit``): a failure rolls back the savepoint only, never the
transaction it sits in, and is logged at ERROR and counted in
``audit_write_failures``. Ordinary audit rows are not chained.
"""

from __future__ import annotations

import hashlib
import ipaddress
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app import observability
from app.logging_config import get_logger
from app.services import ledger_chain

logger = get_logger("api.audit_chain")

# The advisory lock every chained append takes, one 64-bit id for the chain.
AUDIT_CHAIN_LOCK = 0x6D616C6A616E4143  # "maljanAC"
_ENTRY_TAG = b"maljan-audit-entry/1\n"
_GENESIS_TAG = b"maljan-audit-chain/1\n"
_LINK_TAG = b"maljan-audit-link/1\n"

# The actions written onto the chain.
LEDGER_SEAL = "ledger.seal"
REPORT_AMEND = "report.amend"

DIGESTED: tuple[str, ...] = (
    "chain_seq",
    "user_id",
    "action",
    "resource_type",
    "resource_id",
    "details",
    "ip_address",
    "created_at",
    "chain_key_id",
)


def _read(row: Any, name: str) -> Any:
    return row.get(name) if isinstance(row, Mapping) else getattr(row, name, None)


def _ip(value: Any) -> str | None:
    if value is None or value == "":
        return None
    try:
        return ipaddress.ip_interface(str(value)).ip.compressed
    except ValueError:
        return str(value)


def audit_fields(row: Any) -> dict[str, Any]:
    """The digested columns of an audit row, canonical."""
    user = _read(row, "user_id")
    return {
        "chain_seq": _read(row, "chain_seq"),
        "user_id": str(user) if user is not None else None,
        "action": _read(row, "action"),
        "resource_type": _read(row, "resource_type"),
        "resource_id": _read(row, "resource_id"),
        "details": ledger_chain.json_value(_read(row, "details")),
        "ip_address": _ip(_read(row, "ip_address")),
        "created_at": ledger_chain.timestamp(_read(row, "created_at")),
        "chain_key_id": _read(row, "chain_key_id"),
    }


def audit_digest(row: Any) -> str:
    """The SHA-256 of an audit row's canonical form, as hex."""
    return hashlib.sha256(_ENTRY_TAG + ledger_chain.canonical(audit_fields(row))).hexdigest()


def audit_genesis(key: ledger_chain.ChainKey) -> str:
    """The chain value before the first chained audit row."""
    return ledger_chain.keyed(key, _GENESIS_TAG, b"")


def audit_link(previous: str, digest: str, key: ledger_chain.ChainKey) -> str:
    """The chain value after a chained audit row with ``digest``."""
    return ledger_chain.keyed(key, _LINK_TAG, f"{previous}:{digest}".encode("ascii"))


def _is_postgres(db: Any) -> bool:
    try:
        return bool(db.get_bind().dialect.name == "postgresql")
    except Exception:  # noqa: BLE001 — no bind, no lock to take
        return False


async def append(
    db: Any,
    *,
    action: str,
    resource_type: str,
    resource_id: str | None,
    details: dict[str, Any],
    key: ledger_chain.ChainKey,
    user_id: uuid.UUID | None = None,
) -> Any:
    """Add one chained audit row to ``db``'s transaction; the row, or ``None`` when it failed."""
    from sqlalchemy import select, text

    from app.models.audit import AuditLog

    try:
        async with db.begin_nested():
            if _is_postgres(db):
                await db.execute(
                    text("SELECT pg_advisory_xact_lock(:lock)"), {"lock": AUDIT_CHAIN_LOCK}
                )
            last = (
                await db.execute(
                    select(AuditLog.chain_seq, AuditLog.chain)
                    .where(AuditLog.chain_seq.is_not(None))
                    .order_by(AuditLog.chain_seq.desc())
                    .limit(1)
                )
            ).first()
            previous_seq = int(last[0]) if last is not None else 0
            previous = str(last[1]) if last is not None else audit_genesis(key)
            row = AuditLog(
                user_id=user_id,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                details=details,
                ip_address=None,
                created_at=datetime.now(UTC),
                chain_seq=previous_seq + 1,
                chain_key_id=key.key_id or None,
            )
            row.digest = audit_digest(row)
            row.chain = audit_link(previous, row.digest, key)
            db.add(row)
            await db.flush()
        return row
    except Exception as exc:  # noqa: BLE001 — audit is best effort, but never silent
        observability.counters.audit_write_failures += 1
        logger.error("Chained audit write failed (action=%s): %s", action, type(exc).__name__)
        return None


@dataclass
class AuditChainCheck:
    """What recomputing the audit chain found."""

    rows: int
    broken_at: int | None = None
    reason: str | None = None
    other_key_rows: list[int] = field(default_factory=list)


def verify_audit_chain(rows: Iterable[Any], key: ledger_chain.ChainKey) -> AuditChainCheck:
    """Recompute the chained audit rows in ``chain_seq`` order; the first that breaks.

    A row chained under another key than ``key`` cannot have its link checked:
    it is listed under ``other_key_rows``, its digest is still checked, and its
    stored chain value carries the walk on.
    """
    ordered = sorted(rows, key=lambda r: int(_read(r, "chain_seq") or 0))
    check = AuditChainCheck(rows=len(ordered))
    previous = audit_genesis(key)
    expected_seq = 1
    for row in ordered:
        seq = int(_read(row, "chain_seq") or 0)
        if seq != expected_seq:
            check.broken_at = expected_seq
            check.reason = f"chained audit row {expected_seq} is missing"
            return check
        if audit_digest(row) != _read(row, "digest"):
            check.broken_at = seq
            check.reason = f"chained audit row {seq} differs from its digest"
            return check
        if (_read(row, "chain_key_id") or "") != key.key_id:
            check.other_key_rows.append(seq)
        elif audit_link(previous, str(_read(row, "digest")), key) != _read(row, "chain"):
            check.broken_at = seq
            check.reason = f"chained audit row {seq} does not link to the row before it"
            return check
        previous = str(_read(row, "chain"))
        expected_seq += 1
    return check

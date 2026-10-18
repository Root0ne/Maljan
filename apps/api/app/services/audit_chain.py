"""The audit log's hash chain: rows that record the ledger's seal and its amendments.

A chained row is appended inside the caller's transaction, so it commits with
what it records (the seal with the stored ledger, an amendment with the report
it changes) or not at all. It takes the next ``chain_seq``, a SHA-256 digest
of its columns in canonical form (``ledger_chain.canonical``) and a chain value:
the HMAC of the previous chained row's chain value and its own digest, under
the ledger's key (``ledger_chain.ChainKey``), with that key's id beside it.
The chain's head record (``AuditChainHead``: last ``chain_seq``, chain value,
key id and a MAC over them) is rewritten in the same savepoint, so rows cut off
the end of the log are found.

Appends are serialised by a PostgreSQL transaction-scoped advisory lock taken
inside a savepoint, and ``chain_seq`` is unique, so two writers can never fork
the chain. The append is best effort like every audit write
(``services.audit``): a failure rolls back the savepoint only, never the
transaction it sits in, and is logged at ERROR and counted in
``audit_write_failures``. Ordinary audit rows are not chained.

The limit, stated: the chain proves integrity against a database writer who
does not hold the settings encryption key. Someone who holds it can rewrite the
chain and its head, and a writer who kept an earlier head record can put it
back after cutting the rows that followed it; an anchor outside the database
is what rules those out.
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
_HEAD_TAG = b"maljan-audit-head/1\n"
HEAD_NAME = "audit"

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


def head_mac(chain_seq: int, chain: str, key: ledger_chain.ChainKey) -> str:
    """The keyed MAC of the audit chain's head record."""
    return ledger_chain.keyed(
        key, _HEAD_TAG, ledger_chain.canonical({"chain": chain, "chain_seq": int(chain_seq)})
    )


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
    """Add one chained audit row to ``db``'s transaction; the row, or ``None`` when it failed.

    The chain's head record is rewritten in the same savepoint, under ``key``.
    """
    from sqlalchemy import select, text

    from app.models.audit import AuditChainHead, AuditLog

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
            head = await db.get(AuditChainHead, HEAD_NAME)
            if head is None:
                head = AuditChainHead(name=HEAD_NAME)
                db.add(head)
            head.chain_seq = previous_seq + 1
            head.chain = row.chain
            head.key_id = key.key_id or None
            head.mac = head_mac(previous_seq + 1, row.chain, key)
            await db.flush()
        return row
    except Exception as exc:  # noqa: BLE001 — audit is best effort, but never silent
        observability.counters.audit_write_failures += 1
        logger.error("Chained audit write failed (action=%s): %s", action, type(exc).__name__)
        return None


@dataclass
class AuditChainCheck:
    """What recomputing the audit chain found: ``broken_at`` is ``None`` only when it holds.

    ``unverifiable`` lists the chained rows before the current key's first row
    that were chained under a key the platform cannot derive: never verified
    and never broken. ``unverifiable_span`` is their first and last seq.
    """

    rows: int
    broken_at: int | None = None
    reason: str | None = None
    head_seq: int | None = None
    unverifiable: list[int] = field(default_factory=list)
    head_unverifiable: bool = False

    @property
    def unverifiable_span(self) -> tuple[int, int] | None:
        return (self.unverifiable[0], self.unverifiable[-1]) if self.unverifiable else None


def verify_audit_chain(
    rows: Iterable[Any],
    keys: Mapping[str, ledger_chain.ChainKey],
    head: Any,
    current: str | None = None,
) -> AuditChainCheck:
    """Recompute the chained audit rows in ``chain_seq`` order against the head; the first break.

    ``current`` is the id of the key the platform chains under now (by
    default the one key in ``keys`` when there is one). The walk is split at
    the rotation boundary, the first row under the current key:

    - from the boundary on, every row must carry the current key id and
      verify under it; an older or unknown key id there is a break, so recent
      rows cannot be relabelled, and an older row placed after a current-key
      row is a break;
    - before the boundary, a row under a key the platform can derive is
      verified with it; a row under a key it cannot derive is unverifiable,
      listed in ``unverifiable``, never verified and never broken;
    - every row links to the stored chain value of the row before it, so the
      first current-key row joins the older history and it cannot be swapped
      out underneath.

    The walk must end at the head record, whose MAC is checked under the key
    it names: a row cut off the end, a missing head or a head that does not
    match is a break. A head under a key the platform cannot derive (nothing
    appended since a rotation) is reported as unverifiable, not as a break.
    """
    if current is None and len(keys) == 1:
        current = next(iter(keys))
    ordered = sorted(rows, key=lambda r: int(_read(r, "chain_seq") or 0))
    check = AuditChainCheck(rows=len(ordered))

    def _broken(seq: int, reason: str) -> AuditChainCheck:
        check.broken_at = seq
        check.reason = reason
        return check

    boundary_seen = False
    previous: str | None = None
    expected_seq = 1
    for row in ordered:
        seq = int(_read(row, "chain_seq") or 0)
        if seq != expected_seq:
            return _broken(expected_seq, f"chained audit row {expected_seq} is missing")
        if audit_digest(row) != _read(row, "digest"):
            return _broken(seq, f"chained audit row {seq} differs from its digest")
        key_id = _read(row, "chain_key_id") or ""
        if current is not None and key_id == current:
            boundary_seen = True
        elif boundary_seen:
            return _broken(
                seq,
                f"chained audit row {seq} names key {key_id or '(none)'} after rows under "
                "the current key",
            )
        key = keys.get(key_id)
        if key is None:
            check.unverifiable.append(seq)
        else:
            start = previous if previous is not None else audit_genesis(key)
            if audit_link(start, str(_read(row, "digest")), key) != _read(row, "chain"):
                return _broken(seq, f"chained audit row {seq} does not link to the row before it")
        previous = str(_read(row, "chain"))
        expected_seq += 1
    last_seq = expected_seq - 1
    if head is None:
        if ordered:
            return _broken(last_seq, "the audit chain has rows but no head record")
        return check
    head_seq = int(_read(head, "chain_seq") or 0)
    check.head_seq = head_seq
    head_key_id = _read(head, "key_id") or ""
    head_key = keys.get(head_key_id)
    head_chain = str(_read(head, "chain"))
    if head_key is None:
        if boundary_seen:
            return _broken(
                last_seq + 1, "the audit chain's head names a key other than the current one"
            )
        check.head_unverifiable = True
        return check
    if head_mac(head_seq, head_chain, head_key) != _read(head, "mac"):
        return _broken(last_seq + 1, "the audit chain's head record does not verify")
    if current is not None and head_key_id == current and ordered and not boundary_seen:
        return _broken(
            last_seq + 1, "the audit chain's head is under the current key but no row is"
        )
    if head_seq > last_seq:
        return _broken(
            last_seq + 1,
            f"chained audit rows {last_seq + 1} to {head_seq} are missing: cut off the end",
        )
    if head_seq < last_seq:
        return _broken(head_seq + 1, f"chained audit rows after {head_seq} are past the head")
    if head_chain != previous:
        return _broken(last_seq, f"the head's chain value differs from row {last_seq}")
    return check

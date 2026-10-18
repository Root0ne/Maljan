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


def head_mac(
    chain_seq: int, chain: str, rotated_at_seq: int | None, key: ledger_chain.ChainKey
) -> str:
    """The keyed MAC of the audit chain's head record, its rotation boundary included."""
    return ledger_chain.keyed(
        key,
        _HEAD_TAG,
        ledger_chain.canonical(
            {"chain": chain, "chain_seq": int(chain_seq), "rotated_at_seq": rotated_at_seq}
        ),
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
    Its ``rotated_at_seq`` stays where it is while the key stays the same; the
    first append under a new key (or onto a missing head) sets it to the new
    row's seq, and it is 1 for a chain that starts here.
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
            seq = previous_seq + 1
            row = AuditLog(
                user_id=user_id,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                details=details,
                ip_address=None,
                created_at=datetime.now(UTC),
                chain_seq=seq,
                chain_key_id=key.key_id or None,
            )
            row.digest = audit_digest(row)
            row.chain = audit_link(previous, row.digest, key)
            db.add(row)
            head = await db.get(AuditChainHead, HEAD_NAME)
            same_key = (
                head is not None
                and (head.key_id or "") == key.key_id
                and head.rotated_at_seq is not None
            )
            if head is None:
                head = AuditChainHead(name=HEAD_NAME)
                db.add(head)
            rotated_at = int(head.rotated_at_seq) if same_key else seq
            head.chain_seq = seq
            head.chain = row.chain
            head.key_id = key.key_id or None
            head.rotated_at_seq = rotated_at
            head.mac = head_mac(seq, row.chain, rotated_at, key)
            await db.flush()
        return row
    except Exception as exc:  # noqa: BLE001 — audit is best effort, but never silent
        observability.counters.audit_write_failures += 1
        logger.error("Chained audit write failed (action=%s): %s", action, type(exc).__name__)
        return None


@dataclass
class AuditChainCheck:
    """What recomputing the audit chain found: ``broken_at`` is ``None`` only when it holds.

    ``verified`` lists the chained rows whose link was checked under a key the
    platform holds; ``unverifiable`` the rows before the rotation boundary
    chained under a key it cannot derive (never verified, never broken).
    ``head_unverifiable`` says the head is under a key other than the current
    one (nothing appended since a rotation), so no boundary and no tail could
    be checked: nothing read through this check is then verified.
    """

    rows: int
    broken_at: int | None = None
    reason: str | None = None
    head_seq: int | None = None
    rotated_at_seq: int | None = None
    verified: list[int] = field(default_factory=list)
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
    default the one key in ``keys`` when there is one). The rotation boundary
    is read only from the head, and only from a head that verifies under the
    current key (``rotated_at_seq``, covered by its MAC); never from a row's
    own key id:

    - every row at or after the boundary must carry the current key id and
      verify under it, or it is broken at its seq;
    - a row before the boundary that claims the current key is broken; one
      under another key the platform can derive is verified with it; one under
      a key it cannot derive is unverifiable, never verified and never broken;
    - every row links to the stored chain value of the row before it, so the
      first current-key row joins the older history.

    A head that fails its MAC is a break. A head under a key other than the
    current one leaves the boundary and the tail unknown: the rows the
    platform can check are checked, the rest are unverifiable, and
    ``head_unverifiable`` is set. The walk must end at the head: rows cut off
    the end, or a missing head, are a break.
    """
    if current is None and len(keys) == 1:
        current = next(iter(keys))
    ordered = sorted(rows, key=lambda r: int(_read(r, "chain_seq") or 0))
    check = AuditChainCheck(rows=len(ordered))

    def _broken(seq: int, reason: str) -> AuditChainCheck:
        check.broken_at = seq
        check.reason = reason
        return check

    if head is None:
        if ordered:
            return _broken(
                int(_read(ordered[-1], "chain_seq") or 0),
                "the audit chain has rows but no head record",
            )
        return check
    head_seq = int(_read(head, "chain_seq") or 0)
    head_chain = str(_read(head, "chain"))
    head_key_id = _read(head, "key_id") or ""
    rotated = _read(head, "rotated_at_seq")
    check.head_seq = head_seq
    boundary: int | None = None
    if current is not None and head_key_id == current:
        if rotated is None or head_mac(head_seq, head_chain, rotated, keys[current]) != _read(
            head, "mac"
        ):
            return _broken(head_seq + 1, "the audit chain's head record does not verify")
        boundary = int(rotated)
        if not 1 <= boundary <= max(head_seq, 1):
            return _broken(head_seq + 1, "the audit chain's head names an impossible boundary")
        check.rotated_at_seq = boundary
    else:
        older = keys.get(head_key_id)
        if older is not None and head_mac(head_seq, head_chain, rotated, older) != _read(
            head, "mac"
        ):
            return _broken(head_seq + 1, "the audit chain's head record does not verify")
        check.head_unverifiable = True

    previous: str | None = None
    expected_seq = 1
    for row in ordered:
        seq = int(_read(row, "chain_seq") or 0)
        if seq != expected_seq:
            return _broken(expected_seq, f"chained audit row {expected_seq} is missing")
        if audit_digest(row) != _read(row, "digest"):
            return _broken(seq, f"chained audit row {seq} differs from its digest")
        key_id = _read(row, "chain_key_id") or ""
        if boundary is not None and seq >= boundary and key_id != current:
            return _broken(
                seq,
                f"chained audit row {seq} names key {key_id or '(none)'} at or after the "
                f"rotation boundary (seq {boundary}), where only the current key may chain",
            )
        if boundary is not None and seq < boundary and key_id == current:
            return _broken(
                seq,
                f"chained audit row {seq} claims the current key before the rotation "
                f"boundary (seq {boundary})",
            )
        key = keys.get(key_id)
        if key is None:
            check.unverifiable.append(seq)
        else:
            start = previous if previous is not None else audit_genesis(key)
            if audit_link(start, str(_read(row, "digest")), key) != _read(row, "chain"):
                return _broken(seq, f"chained audit row {seq} does not link to the row before it")
            check.verified.append(seq)
        previous = str(_read(row, "chain"))
        expected_seq += 1
    if check.head_unverifiable:
        return check
    last_seq = expected_seq - 1
    if head_seq > last_seq:
        return _broken(
            last_seq + 1,
            f"chained audit rows {last_seq + 1} to {head_seq} are missing: cut off the end",
        )
    if head_seq < last_seq:
        return _broken(head_seq + 1, f"chained audit rows after {head_seq} are past the head")
    if last_seq and head_chain != previous:
        return _broken(last_seq, f"the head's chain value differs from row {last_seq}")
    return check

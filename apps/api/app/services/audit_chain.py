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

# The id of the PostgreSQL advisory lock every chained append takes
# (``pg_advisory_xact_lock``): one 64-bit number for the one chain, the ASCII of
# "maljanAC", chosen so no other lock in the application can share it.
AUDIT_CHAIN_LOCK = 0x6D616C6A616E4143  # "maljanAC"
_ENTRY_TAG = b"maljan-audit-entry/1\n"
_GENESIS_TAG = b"maljan-audit-chain/1\n"
_LINK_TAG = b"maljan-audit-link/1\n"
_HEAD_TAG = b"maljan-audit-head/1\n"
HEAD_NAME = "audit"


# Said wherever a head fails its MAC: appends are refused from then on, and an
# operator repairs it after the full walk.
HEAD_REFUSED = (
    "the audit head does not verify, so every chained append is refused until an operator "
    "repairs it (python -m scripts.ledger.verify --repair-head); a repair can hide rows cut "
    "off the end of the chain, so check the chain (--audit-chain) before repairing"
)


class HeadRefused(RuntimeError):
    """The stored head cannot be carried forward without re-signing what was never checked."""


# The actions written onto the chain.
LEDGER_SEAL = "ledger.seal"
REPORT_AMEND = "report.amend"
REPORT_DELETE = "report.delete"
HEAD_REPAIR = "audit.head_repair"

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


async def _boundary_for_append(
    db: Any, head: Any, last: Any, key: ledger_chain.ChainKey, seq: int
) -> int:
    """The ``rotated_at_seq`` the head takes with the row at ``seq``; :class:`HeadRefused` if none.

    ``last`` is the last chained row as ``(chain_seq, chain, chain_key_id)``.
    A head under ``key`` is carried forward only when its MAC verifies and it
    points at the last row. A head under another key is accepted as a real
    rotation only when no row already carries ``key`` (the key is new), the
    head points at the last row by seq and chain, the last row was chained
    under the head's key, and the head's MAC verifies under that key when the
    platform can derive it. Anything else is refused and nothing is re-signed.
    """
    from sqlalchemy import select

    from app.models.audit import AuditLog

    if head is None:
        if last is not None:
            raise HeadRefused("chained rows exist but the head record is missing")
        return seq
    points_at_last = last is not None and (
        int(head.chain_seq) == int(last[0]) and head.chain == last[1]
    )
    if (head.key_id or "") == key.key_id:
        if (
            not points_at_last
            or head_mac(head.chain_seq, head.chain, head.rotated_at_seq, key) != head.mac
        ):
            raise HeadRefused("the stored head record does not verify under the key")
        return int(head.rotated_at_seq)
    already = (
        await db.execute(
            select(AuditLog.chain_seq).where(AuditLog.chain_key_id == key.key_id).limit(1)
        )
    ).first()
    if already is not None:
        raise HeadRefused("the head names another key although rows carry the current one")
    if not points_at_last:
        raise HeadRefused("the head under another key does not point at the last row")
    if (last[2] or "") != (head.key_id or ""):
        raise HeadRefused("the last row was not chained under the head's key")
    older = ledger_chain.known_keys().get(head.key_id or "")
    if (
        older is not None
        and head_mac(head.chain_seq, head.chain, head.rotated_at_seq, older) != head.mac
    ):
        raise HeadRefused("the head does not verify under the key it names")
    return seq


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
    Its ``rotated_at_seq`` is carried forward only from a head whose MAC
    verifies under ``key`` and that points at the last row; a head that does
    not, or a missing head over existing rows, refuses the append (logged and
    counted, never re-signed). A head written under another key is a real
    rotation: the boundary becomes the new row's seq. A chain that starts here
    starts at 1.
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
                    select(AuditLog.chain_seq, AuditLog.chain, AuditLog.chain_key_id)
                    .where(AuditLog.chain_seq.is_not(None))
                    .order_by(AuditLog.chain_seq.desc())
                    .limit(1)
                )
            ).first()
            previous_seq = int(last[0]) if last is not None else 0
            previous = str(last[1]) if last is not None else audit_genesis(key)
            seq = previous_seq + 1
            head = await db.get(AuditChainHead, HEAD_NAME)
            rotated_at = await _boundary_for_append(db, head, last, key, seq)
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
            if head is None:
                head = AuditChainHead(name=HEAD_NAME)
                db.add(head)
            head.chain_seq = seq
            head.chain = row.chain
            head.key_id = key.key_id or None
            head.rotated_at_seq = rotated_at
            head.mac = head_mac(seq, row.chain, rotated_at, key)
            await db.flush()
        return row
    except HeadRefused as exc:
        observability.counters.audit_write_failures += 1
        logger.error("Chained audit write refused (action=%s): %s", action, exc)
        return None
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
    current one is a break when any row is under the current key, and otherwise
    leaves the boundary and the tail unknown: the rows the
    platform can check are checked, the rest are unverifiable, and
    ``head_unverifiable`` is set. The walk must end at the head: rows cut off
    the end, or a missing head, are a break.
    """
    if current is None and len(keys) == 1:
        current = next(iter(keys))
    rows_list = list(rows)
    ordered = sorted(rows_list, key=lambda r: int(_read(r, "chain_seq") or 0))
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
            return _broken(head_seq + 1, HEAD_REFUSED)
        boundary = int(rotated)
        if not 1 <= boundary <= max(head_seq, 1):
            return _broken(head_seq + 1, "the audit chain's head names an impossible boundary")
        check.rotated_at_seq = boundary
    else:
        older = keys.get(head_key_id)
        if older is not None and head_mac(head_seq, head_chain, rotated, older) != _read(
            head, "mac"
        ):
            return _broken(head_seq + 1, HEAD_REFUSED)
        current_rows = [
            int(_read(r, "chain_seq") or 0)
            for r in rows_list
            if current is not None and (_read(r, "chain_key_id") or "") == current
        ]
        if current_rows:
            return _broken(
                min(current_rows),
                "the audit chain's head is not under the current key although rows are",
            )
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


def verify_job_rows(
    own: Iterable[Any],
    predecessors: Mapping[int, str],
    keys: Mapping[str, ledger_chain.ChainKey],
    head: Any,
    current: str | None,
    successors: Mapping[int, Any] | None = None,
) -> AuditChainCheck:
    """Check one job's own chained audit rows locally; the first that breaks.

    ``own`` are the job's chained rows; ``predecessors`` maps each row's
    ``chain_seq - 1`` to the chain value stored there, and ``successors`` each
    row's ``chain_seq + 1`` to that whole row, checked as any row is, so
    every link into and out of the job's rows is checked without reading the
    rest of the chain; a row of the job's that is the head must end the head.
    The head record gives the rotation boundary under the same rules as
    :func:`verify_audit_chain`. The cost follows the job; a break elsewhere in
    the chain does not touch it. Reasons name the job's rows by what they
    record, never by their place in the platform's chain. A row cut off the
    end of the whole chain is found only by the full walk
    (``python -m scripts.ledger.verify --audit-chain``).
    """
    successors = successors or {}
    ordered = sorted(own, key=lambda r: int(_read(r, "chain_seq") or 0))
    check = AuditChainCheck(rows=len(ordered))
    own_seqs = {int(_read(r, "chain_seq") or 0) for r in ordered}
    job_resource = str(_read(ordered[0], "resource_id")) if ordered else ""

    def _broken(seq: int, reason: str) -> AuditChainCheck:
        check.broken_at = seq
        check.reason = reason
        return check

    if not ordered:
        return check
    if head is None:
        return _broken(int(_read(ordered[0], "chain_seq")), "the audit chain has no head record")
    head_seq = int(_read(head, "chain_seq") or 0)
    head_key_id = _read(head, "key_id") or ""
    rotated = _read(head, "rotated_at_seq")
    boundary: int | None = None
    if current is not None and head_key_id == current:
        if rotated is None or head_mac(
            head_seq, str(_read(head, "chain")), rotated, keys[current]
        ) != _read(head, "mac"):
            return _broken(int(_read(ordered[0], "chain_seq")), HEAD_REFUSED)
        boundary = int(rotated)
    elif any((_read(r, "chain_key_id") or "") == current for r in ordered if current):
        return _broken(
            int(_read(ordered[0], "chain_seq")),
            "the audit head is not under the current key although this job's rows are",
        )
    else:
        check.head_unverifiable = True
    for row in ordered:
        seq = int(_read(row, "chain_seq") or 0)
        action = _read(row, "action")
        if seq > head_seq:
            return _broken(seq, f"this job's {action} audit row lies past the audit head")
        if audit_digest(row) != _read(row, "digest"):
            return _broken(seq, f"this job's {action} audit row differs from its digest")
        key_id = _read(row, "chain_key_id") or ""
        if boundary is not None and seq >= boundary and key_id != current:
            return _broken(
                seq, f"this job's {action} audit row names a key the chain no longer allows there"
            )
        if boundary is not None and seq < boundary and key_id == current:
            return _broken(
                seq, f"this job's {action} audit row claims the current key before the rotation"
            )
        key = keys.get(key_id)
        if key is None:
            check.unverifiable.append(seq)
            continue
        if seq == 1:
            previous = audit_genesis(key)
        elif seq - 1 in predecessors:
            previous = predecessors[seq - 1]
        else:
            return _broken(seq, f"the audit row before this job's {action} row is missing")
        if audit_link(previous, str(_read(row, "digest")), key) != _read(row, "chain"):
            return _broken(seq, f"this job's {action} audit row does not link to the row before it")
        # The row after must link onto this one, or this one is the head: a
        # deleted row of this job leaves a gap or a dangling successor here.
        # The successor is checked as any row is: its own digest, the
        # boundary rules for its key, and, when it names this job, its place
        # among the job's rows.
        if seq == head_seq:
            if not check.head_unverifiable and _read(head, "chain") != _read(row, "chain"):
                return _broken(seq, f"the audit head does not end on this job's {action} row")
            check.verified.append(seq)
            continue
        following = successors.get(seq + 1)
        if following is None:
            return _broken(seq, f"the audit row after this job's {action} row is missing")
        if audit_digest(following) != _read(following, "digest"):
            return _broken(
                seq, f"the audit row after this job's {action} row differs from its digest"
            )
        if str(_read(following, "resource_id")) == job_resource and seq + 1 not in own_seqs:
            return _broken(
                seq,
                f"the audit row after this job's {action} row names this job but is not its row",
            )
        next_key_id = _read(following, "chain_key_id") or ""
        if boundary is not None and seq + 1 >= boundary and next_key_id != current:
            return _broken(
                seq, f"the audit row after this job's {action} row names a key the chain forbids"
            )
        if boundary is not None and seq + 1 < boundary and next_key_id == current:
            return _broken(
                seq,
                f"the audit row after this job's {action} row claims the current key before "
                "the rotation",
            )
        next_key = keys.get(next_key_id)
        if next_key is None:
            # Before the boundary, or with no boundary known: the link out of
            # this row cannot be checked, so the row is not verified.
            check.unverifiable.append(seq)
            continue
        if audit_link(str(_read(row, "chain")), str(_read(following, "digest")), next_key) != _read(
            following, "chain"
        ):
            return _broken(
                seq, f"the audit row after this job's {action} row does not link onto it"
            )
        check.verified.append(seq)
    return check


def repaired_head(
    rows: Iterable[Any],
    keys: Mapping[str, ledger_chain.ChainKey],
    current: str | None,
    boundary: int | None = None,
) -> tuple[dict[str, Any], list[int]]:
    """The head the whole chain supports, and the rows it could not check; or :class:`HeadRefused`.

    The operator's repair after a head was refused, under the rules a
    verification uses. Every row must recompute to its digest and the chain
    must have no gap. The boundary is the first row under the current key;
    from it on, every row must carry the current key and link to the stored
    chain value of the row before it, so the boundary row joins the history
    and no older-key row may follow it. Before it, a row under a key the
    platform can derive must link under that key, and one under a key it
    cannot derive is counted unverifiable (returned) and allowed. The head is
    rebuilt from the walk: the last row's seq and chain value and the boundary
    as ``rotated_at_seq``, keyed under the current key. Anything else is
    refused with the first break; nothing is signed. ``boundary``, when given,
    is the boundary an old head vouches for: every row at or after it must be
    under the current key and verify, and none before it may claim that key.
    """
    if current is None or current not in keys:
        raise HeadRefused("no current key to sign a head with")
    key = keys[current]
    ordered = sorted(rows, key=lambda r: int(_read(r, "chain_seq") or 0))
    if not ordered:
        raise HeadRefused("there is no chained row to rebuild a head from")
    previous: str | None = None
    rotated_at: int | None = None
    unverifiable: list[int] = []
    for expected, row in enumerate(ordered, start=1):
        seq = int(_read(row, "chain_seq") or 0)
        if seq != expected:
            raise HeadRefused(f"chained audit row {expected} is missing")
        if audit_digest(row) != _read(row, "digest"):
            raise HeadRefused(f"chained audit row {seq} differs from its digest")
        key_id = _read(row, "chain_key_id") or ""
        if boundary is not None:
            if seq >= boundary and key_id != current:
                raise HeadRefused(
                    f"chained audit row {seq} is under another key at or after the rotation "
                    f"boundary (seq {boundary}) the old head vouches for"
                )
            if seq < boundary and key_id == current:
                raise HeadRefused(
                    f"chained audit row {seq} claims the current key before the rotation "
                    f"boundary (seq {boundary}) the old head vouches for"
                )
        if rotated_at is not None and key_id != current:
            raise HeadRefused(
                f"chained audit row {seq} is under another key after the rotation boundary "
                f"(seq {rotated_at})"
            )
        if key_id == current and rotated_at is None:
            rotated_at = seq
        row_key = keys.get(key_id)
        if row_key is None:
            unverifiable.append(seq)
        else:
            start = previous if previous is not None else audit_genesis(row_key)
            if audit_link(start, str(_read(row, "digest")), row_key) != _read(row, "chain"):
                raise HeadRefused(f"chained audit row {seq} does not link to the row before it")
        previous = str(_read(row, "chain"))
    if rotated_at is None:
        raise HeadRefused("no chained row is under the current key")
    last_seq = int(_read(ordered[-1], "chain_seq"))
    head = {
        "name": HEAD_NAME,
        "chain_seq": last_seq,
        "chain": previous,
        "key_id": current,
        "rotated_at_seq": rotated_at,
        "mac": head_mac(last_seq, str(previous), rotated_at, key),
    }
    return head, unverifiable


def head_for_repair(
    rows: Iterable[Any], keys: Mapping[str, ledger_chain.ChainKey], current: str | None
) -> dict[str, Any]:
    """The head :func:`repaired_head` rebuilds, without the unverifiable rows."""
    return repaired_head(rows, keys, current)[0]


def plan_repair(
    rows: Iterable[Any],
    keys: Mapping[str, ledger_chain.ChainKey],
    current: str | None,
    old_head: Any,
    *,
    accept_truncation_at: int | None = None,
    accept_boundary_at: int | None = None,
    at: datetime | None = None,
) -> dict[str, Any]:
    """The chained repair row and the head that points at it; :class:`HeadRefused` if none.

    The rotation boundary never comes from the rows' own labels alone. An old
    head under the current key whose MAC verifies vouches for its
    ``rotated_at_seq``, and the walk (:func:`repaired_head`) holds every row to
    it. An old head that cannot vouch (missing, failing its MAC, or under
    another key) leaves only the boundary the rows suggest, and the repair is
    refused unless ``accept_boundary_at`` equals that seq, the operator's
    acknowledgement, recorded on the repair row. The old head is then compared
    with the walk: a
    head whose seq lies beyond the last row, or whose chain differs from the
    chain at its seq, says rows were cut off the end, and re-signing would hide
    that. Such a repair is refused unless ``accept_truncation_at`` equals the
    old head's seq, the operator's acknowledgement of exactly that cut. The
    repair itself is a chained ``audit.head_repair`` row after the last row,
    naming the old head, the head the walk supports and any acknowledged
    truncation; the new head points at that row.
    """
    from app.models.audit import AuditLog

    rows = list(rows)
    if current is None or current not in keys:
        raise HeadRefused("no current key to sign a head with")
    vouched: int | None = None
    if old_head is not None and (_read(old_head, "key_id") or "") == current:
        rotated = _read(old_head, "rotated_at_seq")
        if rotated is not None and head_mac(
            int(_read(old_head, "chain_seq") or 0),
            str(_read(old_head, "chain")),
            rotated,
            keys[current],
        ) == _read(old_head, "mac"):
            vouched = int(rotated)
    acknowledged: int | None = None
    if vouched is not None:
        if accept_boundary_at is not None and accept_boundary_at != vouched:
            raise HeadRefused(
                f"--accept-boundary-at {accept_boundary_at} differs from the boundary the old "
                f"head vouches for ({vouched})"
            )
        walked, unverifiable = repaired_head(rows, keys, current, boundary=vouched)
    else:
        walked, unverifiable = repaired_head(rows, keys, current)
        derived = int(walked["rotated_at_seq"])
        if accept_boundary_at is None:
            raise HeadRefused(
                "the old head cannot vouch for the rotation boundary (missing, failing its "
                f"check, or under another key); the rows put it at seq {derived}: re-run with "
                f"--accept-boundary-at {derived} only after checking it"
            )
        if accept_boundary_at != derived:
            raise HeadRefused(
                f"--accept-boundary-at {accept_boundary_at} does not name the boundary the rows "
                f"put at seq {derived}"
            )
        acknowledged = derived
    key = keys[str(current)]
    by_seq = {int(_read(r, "chain_seq") or 0): r for r in rows}
    old_seq = int(_read(old_head, "chain_seq") or 0) if old_head is not None else None
    old_chain = _read(old_head, "chain") if old_head is not None else None
    truncated = old_seq is not None and (
        old_seq > walked["chain_seq"]
        or (old_seq in by_seq and _read(by_seq[old_seq], "chain") != old_chain)
    )
    if accept_truncation_at is not None and accept_truncation_at != old_seq:
        raise HeadRefused(
            f"--accept-truncation-at {accept_truncation_at} does not name the old head's seq "
            f"({old_seq})"
        )
    if truncated and accept_truncation_at is None:
        raise HeadRefused(
            f"the old head names seq {old_seq}, past or apart from the last row "
            f"({walked['chain_seq']}): rows were cut off the end; re-run with "
            f"--accept-truncation-at {old_seq} only after checking what was lost"
        )
    seq = int(walked["chain_seq"]) + 1
    row = AuditLog(
        id=uuid.uuid4(),
        user_id=None,
        action=HEAD_REPAIR,
        resource_type="audit_chain",
        resource_id=HEAD_NAME,
        details={
            "old_head_seq": old_seq,
            "old_head_chain": old_chain,
            "walked_head_seq": walked["chain_seq"],
            "walked_head_chain": walked["chain"],
            "rotated_at_seq": walked["rotated_at_seq"],
            "truncation_acknowledged_at": accept_truncation_at if truncated else None,
            "boundary_vouched_by_old_head": vouched is not None,
            "boundary_acknowledged_at": acknowledged,
            "unverifiable": [unverifiable[0], unverifiable[-1]] if unverifiable else None,
        },
        ip_address=None,
        created_at=at or datetime.now(UTC),
        chain_seq=seq,
        chain_key_id=key.key_id,
    )
    row.digest = audit_digest(row)
    row.chain = audit_link(str(walked["chain"]), row.digest, key)
    rotated_at = int(walked["rotated_at_seq"])
    head = {
        "name": HEAD_NAME,
        "chain_seq": seq,
        "chain": row.chain,
        "key_id": key.key_id,
        "rotated_at_seq": rotated_at,
        "mac": head_mac(seq, row.chain, rotated_at, key),
    }
    values = {c.name: getattr(row, c.name) for c in AuditLog.__table__.columns}
    return {
        "row": values,
        "head": head,
        "unverifiable": unverifiable,
        "truncated": truncated,
    }


async def record_report_deletion(db: Any, report: Any, *, user_id: uuid.UUID | None = None) -> Any:
    """Write a chained ``report.delete`` row for ``report`` into ``db``'s transaction.

    Every path that deletes a stored report calls this before the delete: the
    owner's ``DELETE /reports/{id}`` and a re-run superseding its report. It
    names the report, its job and the digest of the seal it carried (``None``
    for a report stored before sealing), so a verification of a sealed job
    whose report row is gone can tell a deletion by its owner from tampering.
    Without a settings key nothing can be chained; that is logged and ``None``
    answered. With a key, an append that does not land raises
    :class:`DeletionNotChained`: the caller decides, and the owner's delete is
    refused rather than done without its record.
    """
    key, no_key = ledger_chain.platform_key_status()
    seal = getattr(report, "ledger_seal", None)
    if key is None:
        logger.warning("The deletion of report %s is not chained: %s.", report.id, no_key)
        return None
    row = await append(
        db,
        action=REPORT_DELETE,
        resource_type="job",
        resource_id=str(report.job_id),
        details={
            "report_id": str(report.id),
            "seal_digest": seal.get("digest") if isinstance(seal, Mapping) else None,
            # The core seal the audit chain holds, which a verifier of a job
            # whose report is gone reads the seal from.
            "core_digest": seal.get("core_digest") if isinstance(seal, Mapping) else None,
        },
        key=key,
        user_id=user_id,
    )
    if row is None:
        raise DeletionNotChained(report.id)
    return row


class DeletionNotChained(RuntimeError):
    """A report's deletion could not be written onto the audit chain."""

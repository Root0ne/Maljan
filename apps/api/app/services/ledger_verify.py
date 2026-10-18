"""Verify a job's stored ledger: recompute the chain from the rows and check it against the seal.

One function, :func:`verify_ledger`, read by the API route
(``GET /jobs/{id}/evidence/verify``) and the developer command
(``python -m scripts.ledger.verify``). It answers one of five statuses and
always says why:

- ``verified``: every row recomputes to its digest and links to the one before
  it under the seal's key, the head and the counts equal the seal, every copy
  of the seal agrees, the stored report equals the seal's report digest or the
  last amendment chained onto it, and the audit chain (where it was read)
  holds the seal and every amendment and verifies to its head.
- ``broken``: the first thing that failed, with the first broken ``seq`` when
  a row is to blame.
- ``other_key``: the seal or an amendment names a key the platform's settings
  cannot derive (a rotated settings key, or a relabelled record). The chain
  cannot be checked with the keys held; the rows' own digests are still
  checked, and a row that fails them is ``broken``.
- ``unverifiable``: the audit chain's head is under a key other than the
  current one (nothing appended since a rotation), or one of the job's own
  chained audit rows sits in the segment before the rotation under a key the
  platform cannot derive. Never ``verified``, never ``broken``.
- ``not_sealed``: no seal exists anywhere and no row carries a digest: the run
  predates sealing, or nothing was stored for it.

A job is sealed when any copy of its seal exists (the report row, the report
payload, the run summary, the audit chain) or any of its rows carries a digest
or a chain value: from then on a NULL digest, a missing, extra or reordered
row and a changed row count are each a break.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from app.services import ledger_chain
from app.services.audit_chain import AuditChainCheck

VERIFIED = "verified"
BROKEN = "broken"
OTHER_KEY = "other_key"
NOT_SEALED = "not_sealed"
UNVERIFIABLE = "unverifiable"

OWN_ROWS_UNVERIFIABLE = (
    "This job's own chained audit rows were chained under a key the platform's settings "
    "cannot derive (before a key rotation): they can be neither verified nor called broken."
)
HEAD_UNVERIFIABLE = (
    "The audit chain's head is under a key other than the current one: nothing was appended "
    "since a key rotation, so the rotation boundary and a cut tail cannot be checked."
)

PREDATES = (
    "This run predates ledger sealing: its rows carry no digest and no seal was stored for it."
)
NOTHING_STORED = "Nothing was stored for this job: no ledger row, no report and no seal."


def _read(row: Any, name: str) -> Any:
    return row.get(name) if isinstance(row, Mapping) else getattr(row, name, None)


def _seq(row: Any) -> int:
    return int(_read(row, "seq") or 0)


class _Result:
    def __init__(self, job_id: Any) -> None:
        self.body: dict[str, Any] = {
            "job_id": str(job_id),
            "status": VERIFIED,
            "reason": None,
            "first_broken_seq": None,
            "entries": 0,
            "head": None,
            "seal": None,
            "amendments": 0,
            "checks": [],
            "notes": [],
        }
        self.done = False

    def check(self, text: str) -> None:
        self.body["checks"].append(text)

    def note(self, text: str) -> None:
        self.body["notes"].append(text)

    def end(self, status: str, reason: str, seq: int | None = None) -> dict[str, Any]:
        self.body["status"] = status
        self.body["reason"] = reason
        self.body["first_broken_seq"] = seq
        self.done = True
        return self.body


def verify_ledger(
    job_id: Any,
    rows: Sequence[Any],
    *,
    report_seal: Any = None,
    malware_report: Any = None,
    run_summary: Any = None,
    stix_bundle: Any = None,
    report_stored: bool = False,
    audit_seals: Sequence[Mapping[str, Any]] | None = None,
    audit_amendments: Sequence[Mapping[str, Any]] | None = None,
    audit_check: AuditChainCheck | None = None,
    audit_own_unverifiable: bool = False,
    keys: Mapping[str, ledger_chain.ChainKey] | None = None,
) -> dict[str, Any]:
    """The verification of one job's stored ledger, as a JSON-ready dict.

    ``rows`` are the job's ledger rows (row objects or mappings with the
    column names, as the evidence page serves them). ``report_seal`` is the
    report row's ``ledger_seal``; ``malware_report``, ``run_summary`` and
    ``stix_bundle`` the stored documents, with ``report_stored`` saying a
    report row exists. ``audit_seals`` and ``audit_amendments`` are the seal
    and amendment records the job's chained audit rows carry, and
    ``audit_check`` the audit chain's own verification; ``None`` for each
    means the audit log was not read, which the answer says. Only rows that
    verified may be handed in as ``audit_seals`` and ``audit_amendments``;
    ``audit_own_unverifiable`` says one of the job's own chained rows could not
    be verified, and the job then reads ``unverifiable``. ``keys`` defaults to
    the keys the platform's settings can derive.
    """
    keys = dict(keys) if keys is not None else ledger_chain.known_keys()
    result = _Result(job_id)
    ordered = sorted(rows, key=_seq)
    result.body["entries"] = len(ordered)

    payload = malware_report if isinstance(malware_report, Mapping) else None
    summary = run_summary if isinstance(run_summary, Mapping) else None
    copies: dict[str, Any] = {
        "report row": report_seal if isinstance(report_seal, Mapping) else None,
        "report payload": (payload or {}).get(ledger_chain.SEAL_KEY),
        "run summary": (summary or {}).get(ledger_chain.SEAL_KEY),
    }
    if audit_seals:
        copies["audit chain"] = audit_seals[-1]
    present = {name: dict(seal) for name, seal in copies.items() if isinstance(seal, Mapping)}
    chained_rows = [r for r in ordered if _read(r, "digest") or _read(r, "chain")]

    if not present and audit_own_unverifiable:
        return result.end(UNVERIFIABLE, OWN_ROWS_UNVERIFIABLE)
    if not present and not chained_rows:
        if audit_seals is None:
            result.note("The audit log was not read, so no ledger.seal row was looked for.")
        if not ordered and not report_stored:
            return result.end(NOT_SEALED, NOTHING_STORED)
        return result.end(NOT_SEALED, PREDATES)
    if not present:
        first = _seq(chained_rows[0])
        return result.end(
            BROKEN,
            "Rows of this job carry digests, but no seal is stored for it anywhere.",
            first,
        )

    seal = next(iter(present.values()))
    result.body["seal"] = seal
    # A broken audit chain is a break before anything the job's own records
    # say: a relabelled seal copied onto the audit log breaks that row there.
    if audit_check is not None and audit_check.broken_at is not None:
        return result.end(
            BROKEN,
            f"The audit chain is broken at chained row {audit_check.broken_at}: "
            f"{audit_check.reason}",
        )
    disagreeing = [name for name, copy in present.items() if copy != seal]
    if disagreeing:
        return result.end(
            BROKEN,
            "The copies of the seal disagree: " + ", ".join(sorted(present)) + ".",
        )
    if report_stored and "report row" not in present:
        return result.end(BROKEN, "The report is stored, but its row carries no seal.")
    for name in ("report payload", "run summary"):
        document = payload if name == "report payload" else summary
        if report_stored and document is not None and name not in present:
            return result.end(BROKEN, f"The {name} carries no seal although the report row does.")
    result.check("every stored copy of the seal agrees: " + ", ".join(sorted(present)))

    key_id = seal.get("key_id") or ""
    key = keys.get(key_id)
    # A row whose content no longer matches its own digest is changed whatever
    # key the chain was made under.
    for row in ordered:
        if not _read(row, "digest"):
            return result.end(
                BROKEN, f"Row seq {_seq(row)} of a sealed job carries no digest.", _seq(row)
            )
        if ledger_chain.entry_digest(row) != _read(row, "digest"):
            return result.end(BROKEN, f"Row seq {_seq(row)} differs from its digest.", _seq(row))
    result.check(f"all {len(ordered)} rows recompute to their digests")

    if key is None:
        said = f"key {key_id}" if key_id else "no key"
        return result.end(
            OTHER_KEY,
            f"The ledger was sealed under {said}, which the platform's settings cannot derive "
            "(a rotated settings key, or a relabelled seal); the chain cannot be checked with "
            "the keys held.",
        )
    if not key_id:
        result.note("Sealed without a key: the chain proves only that nothing changed by accident.")
    if ledger_chain.record_digest(seal, key) != seal.get("digest"):
        return result.end(BROKEN, "The seal does not verify under its key.")
    if str(seal.get("job_id")) != str(job_id):
        return result.end(BROKEN, "The seal names another job.")
    result.check("the seal verifies under its key")

    head = ledger_chain.genesis(job_id, key)
    for row in ordered:
        head = ledger_chain.link(head, str(_read(row, "digest")), key)
        if head != _read(row, "chain"):
            return result.end(
                BROKEN,
                f"Row seq {_seq(row)} does not link to the row before it: a row before it is "
                "missing, changed or out of order, or it was chained without the key.",
                _seq(row),
            )
    result.body["head"] = head
    last_seq = seal.get("last_seq")
    beyond = [r for r in ordered if last_seq is not None and _seq(r) > int(last_seq)]
    if beyond or (last_seq is None and ordered):
        extra = _seq(beyond[0]) if beyond else _seq(ordered[0])
        return result.end(BROKEN, f"Row seq {extra} lies past the sealed ledger.", extra)
    if ordered and last_seq is not None and _seq(ordered[-1]) < int(last_seq):
        missing = _seq(ordered[-1]) + 1
        return result.end(
            BROKEN,
            f"Rows after seq {_seq(ordered[-1])} are missing: the seal covers up to {last_seq}.",
            missing,
        )
    if not ordered and int(seal.get("entries") or 0) > 0:
        sealed_first = seal.get("first_seq")
        return result.end(
            BROKEN,
            "Every row of the sealed ledger is missing.",
            int(sealed_first) if sealed_first else None,
        )
    if len(ordered) != int(seal.get("entries") or 0):
        return result.end(
            BROKEN,
            f"The job holds {len(ordered)} rows; the seal covers {seal.get('entries')}.",
        )
    if head != seal.get("head"):
        return result.end(BROKEN, "The chain recomputed from the rows ends on another head.")
    result.check(f"the chain over {len(ordered)} rows ends on the sealed head")

    if report_stored:
        outcome = _check_report(result, seal, payload, summary, stix_bundle, keys)
        if outcome is not None:
            return outcome
    else:
        result.note("No report is stored for this job; the seal was read from the audit chain.")

    if audit_own_unverifiable:
        return result.end(UNVERIFIABLE, OWN_ROWS_UNVERIFIABLE)
    if audit_check is not None and audit_check.head_unverifiable:
        return result.end(UNVERIFIABLE, HEAD_UNVERIFIABLE)
    if audit_seals is None:
        result.note("The audit log was not read: the seal and amendments were not checked there.")
    else:
        if not audit_seals:
            return result.end(BROKEN, "No ledger.seal row for this job is on the audit chain.")
        result.check("the seal is on the audit chain")
        recorded = {str(a.get("digest")) for a in audit_amendments or ()}
        for record in (payload or {}).get(ledger_chain.AMENDMENTS_KEY) or ():
            if isinstance(record, Mapping) and str(record.get("digest")) not in recorded:
                return result.end(
                    BROKEN,
                    f"Amendment {record.get('number')} is not on the audit chain.",
                )
    if audit_check is not None:
        span = audit_check.unverifiable_span
        verified_rows = audit_check.rows - len(audit_check.unverifiable)
        result.check(f"the audit chain verifies over {verified_rows} of {audit_check.rows} rows")
        if span is not None:
            result.note(
                f"{len(audit_check.unverifiable)} chained audit row(s), seq {span[0]} to "
                f"{span[1]}, were chained under a key the platform's settings cannot derive "
                "(before a key rotation): unverifiable, neither verified nor broken."
            )
    return result.end(VERIFIED, "The ledger, its seal and the stored report verify.")


async def verify_job(db: Any, job_id: Any) -> dict[str, Any]:
    """Read one job's ledger, report and chained audit rows through ``db`` and verify them.

    ``db`` is an ``AsyncSession`` or an ``AsyncConnection``: only Core
    ``SELECT``\\s are issued, so a read-only transaction serves it. The whole
    audit chain is read, because its head can only be checked from its first
    row.
    """
    from sqlalchemy import select

    from app.models.audit import AuditChainHead, AuditLog
    from app.models.evidence import EvidenceEntry
    from app.models.report import AnalysisReport
    from app.services import audit_chain

    evidence = EvidenceEntry.__table__
    rows = (
        (
            await db.execute(
                select(evidence).where(evidence.c.job_id == job_id).order_by(evidence.c.seq)
            )
        )
        .mappings()
        .all()
    )
    reports = AnalysisReport.__table__
    report = (
        (await db.execute(select(reports).where(reports.c.job_id == job_id))).mappings().first()
    )
    log = AuditLog.__table__
    chained = (
        (
            await db.execute(
                select(log).where(log.c.chain_seq.is_not(None)).order_by(log.c.chain_seq)
            )
        )
        .mappings()
        .all()
    )
    heads = AuditChainHead.__table__
    head = (
        (await db.execute(select(heads).where(heads.c.name == audit_chain.HEAD_NAME)))
        .mappings()
        .first()
    )
    keys = ledger_chain.known_keys()
    check = audit_chain.verify_audit_chain(chained, keys, head, ledger_chain.platform_key().key_id)
    # Only rows that verified are read for the job's seal and amendments; one
    # of its own that could not be verified makes the job unverifiable.
    verified = set(check.verified)
    own = [
        r
        for r in chained
        if str(r["resource_id"]) == str(job_id)
        and r["action"] in (audit_chain.LEDGER_SEAL, audit_chain.REPORT_AMEND)
    ]
    mine = [r for r in own if int(r["chain_seq"]) in verified]
    return verify_ledger(
        job_id,
        [dict(r) for r in rows],
        report_seal=report["ledger_seal"] if report is not None else None,
        malware_report=report["malware_report"] if report is not None else None,
        run_summary=report["run_summary"] if report is not None else None,
        stix_bundle=report["stix_bundle"] if report is not None else None,
        report_stored=report is not None,
        audit_seals=[
            (r["details"] or {}).get("seal") or {}
            for r in mine
            if r["action"] == audit_chain.LEDGER_SEAL
        ],
        audit_amendments=[
            (r["details"] or {}).get("amendment") or {}
            for r in mine
            if r["action"] == audit_chain.REPORT_AMEND
        ],
        audit_check=check,
        audit_own_unverifiable=check.broken_at is None
        and any(int(r["chain_seq"]) not in verified for r in own),
        keys=keys,
    )


def _check_report(
    result: _Result,
    seal: Mapping[str, Any],
    payload: Mapping[str, Any] | None,
    summary: Mapping[str, Any] | None,
    stix_bundle: Any,
    keys: Mapping[str, ledger_chain.ChainKey],
) -> dict[str, Any] | None:
    """Walk the amendments from the seal to the stored report; the failure, or ``None``."""
    held = (payload or {}).get(ledger_chain.AMENDMENTS_KEY) or []
    if summary is not None and (summary.get(ledger_chain.AMENDMENTS_KEY) or []) != held:
        return result.end(
            BROKEN, "The amendments in the report payload and the run summary differ."
        )
    previous_digest = seal.get("digest")
    expected = seal.get("report_sha256")
    for index, record in enumerate(held, start=1):
        if not isinstance(record, Mapping):
            return result.end(BROKEN, f"Amendment {index} is not a record.")
        key = keys.get(record.get("key_id") or "")
        if key is None:
            return result.end(
                OTHER_KEY,
                f"Amendment {index} was made under key {record.get('key_id') or '(none)'}, "
                "which the platform's settings cannot derive.",
            )
        if ledger_chain.record_digest(record, key) != record.get("digest"):
            return result.end(BROKEN, f"Amendment {index} does not verify under its key.")
        if record.get("number") != index or record.get("prev") != previous_digest:
            return result.end(
                BROKEN, f"Amendment {index} does not chain onto the record before it."
            )
        if record.get("report_sha256_before") != expected:
            return result.end(
                BROKEN,
                f"The stored report changed before amendment {index} without an amendment.",
            )
        previous_digest = record.get("digest")
        expected = record.get("report_sha256_after")
    result.body["amendments"] = len(held)
    current = ledger_chain.report_digest(payload, summary, stix_bundle)
    if current != expected:
        return result.end(
            BROKEN, "The stored report changed after the seal and no amendment records it."
        )
    result.check(
        f"the stored report equals the seal's report digest after {len(held)} amendment(s)"
    )
    return None

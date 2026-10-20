"""Verify a job's stored ledger: recompute the chain from the rows and check it against the seal.

One function, :func:`verify_ledger`, read by the API route
(``GET /jobs/{id}/evidence/verify``) and the developer command
(``python -m scripts.ledger.verify``). It answers one of six statuses and
always says why:

- ``verified``: every row recomputes to its digest and links to the one before
  it under the seal's key, the head and the counts equal the seal, every copy
  of the seal agrees, the stored report row (every column the seal covers,
  :data:`ledger_chain.REPORT_DIGESTED`) equals the seal's report digest or the
  last amendment chained onto it, the payload's amendments are exactly the
  ones the audit chain records for this seal, and the job's own audit rows
  verify. The per-agent findings and the transcript are not covered.
- ``broken``: the first thing that failed, with the first broken ``seq`` when
  a ledger row is to blame.
- ``deleted``: the report row is gone and a verified ``report.delete`` audit
  row records its deletion by its owner; the ledger still verifies against the
  seal.
- ``other_key``: the seal names a key the platform's settings cannot derive (a
  rotated settings key, or a relabelled seal). The rows' own digests are still
  checked, and a row that fails them is ``broken``.
- ``unverifiable``: something the verdict needs could not be checked although
  nothing failed: the audit append for this seal or an amendment did not land,
  the job's own audit rows lie before a key rotation under a key the platform
  cannot derive, or the audit head is under another key (nothing appended
  since a rotation).
- ``not_sealed``: no seal exists anywhere and no row carries a digest: the run
  predates sealing, or nothing was stored for it.

A job is sealed when any copy of its seal exists (the report row, the report
payload, the run summary, a verified ``ledger.seal`` audit row) or any of its
rows carries a digest or a chain value: from then on a NULL digest, a missing,
extra or reordered row and a changed row count are each a break.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from app.services import ledger_chain
from app.services.audit_chain import AuditChainCheck

VERIFIED = "verified"
BROKEN = "broken"
DELETED = "deleted"
OTHER_KEY = "other_key"
UNVERIFIABLE = "unverifiable"
NOT_SEALED = "not_sealed"

PREDATES = (
    "This run predates ledger sealing: its rows carry no digest and no seal was stored for it."
)
NOTHING_STORED = "Nothing was stored for this job: no ledger row, no report and no seal."
OWN_ROWS_UNVERIFIABLE = (
    "This job's own chained audit rows were chained under a key the platform's settings "
    "cannot derive (before a key rotation): they can be neither verified nor called broken."
)
HEAD_UNVERIFIABLE = (
    "The audit chain's head is under a key other than the current one: nothing was appended "
    "since a key rotation, so the rotation boundary cannot be checked."
)
SEAL_NOT_ANCHORED = (
    "The audit append for this seal did not land: no ledger.seal audit row records it, so the "
    "seal cannot be confirmed against the audit chain."
)
SEAL_SUPERSEDED = (
    "The audit chain holds a seal for this job that the stored report does not carry: the "
    "report it sealed was superseded and no report.delete audit row records its deletion."
)
VERIFIED_REASON = (
    "The ledger, its seal and the stored report row verify. The per-agent findings and the "
    "transcript are not covered by the seal."
)


@dataclass
class JobAudit:
    """What the job's own chained audit rows say, as :func:`verify_job` reads them.

    ``seals``, ``amendments`` and ``deletes`` hold the ``details`` of the
    job's ``ledger.seal``, ``report.amend`` and ``report.delete`` rows that
    verified, in chain order; ``check`` is the local check of all of them.
    """

    check: AuditChainCheck
    seals: list[dict[str, Any]] = field(default_factory=list)
    amendments: list[dict[str, Any]] = field(default_factory=list)
    deletes: list[dict[str, Any]] = field(default_factory=list)
    # What is wrong with the audit chain as a whole, when it is not contiguous
    # up to its head: rows are gone from it, and whether they were this job's
    # own cannot be told from the rows that are left.
    chain_gap: str | None = None

    @property
    def unverifiable_own(self) -> bool:
        return self.check.broken_at is None and bool(self.check.unverifiable)


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
        self.pending: str | None = None

    def check(self, text: str) -> None:
        self.body["checks"].append(text)

    def note(self, text: str) -> None:
        self.body["notes"].append(text)

    def end(self, status: str, reason: str, seq: int | None = None) -> dict[str, Any]:
        self.body["status"] = status
        self.body["reason"] = reason
        self.body["first_broken_seq"] = seq
        return self.body


def verify_ledger(
    job_id: Any,
    rows: Sequence[Any],
    *,
    report: Mapping[str, Any] | None = None,
    audit: JobAudit | None = None,
    keys: Mapping[str, ledger_chain.ChainKey] | None = None,
) -> dict[str, Any]:
    """The verification of one job's stored ledger, as a JSON-ready dict.

    ``rows`` are the job's ledger rows (row objects or mappings with the
    column names, as the evidence page serves them). ``report`` is the stored
    report row as a mapping of its columns, ``None`` when there is none.
    ``audit`` is what the job's own chained audit rows say (:class:`JobAudit`),
    ``None`` when the audit log was not read, which the answer says. ``keys``
    defaults to the keys the platform's settings can derive.
    """
    keys = dict(keys) if keys is not None else ledger_chain.known_keys()
    result = _Result(job_id)
    ordered = sorted(rows, key=_seq)
    result.body["entries"] = len(ordered)
    chained_rows = [r for r in ordered if _read(r, "digest") or _read(r, "chain")]

    if audit is not None and audit.check.broken_at is not None:
        return result.end(BROKEN, f"The audit chain is broken: {audit.check.reason}.")
    if audit is None:
        result.note("The audit log was not read: the seal and amendments were not checked there.")

    if report is not None:
        seal_or_end = _seal_of_the_report(result, report, ordered, chained_rows, audit)
    else:
        seal_or_end = _seal_without_a_report(result, ordered, chained_rows, audit)
    if "status" in seal_or_end and "job_id" in seal_or_end:
        return seal_or_end
    seal = seal_or_end
    result.body["seal"] = seal

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

    key_id = seal.get("key_id") or ""
    key = keys.get(key_id)
    if key is None:
        said = f"key {key_id}" if key_id else "no key"
        return result.end(
            OTHER_KEY,
            f"The ledger was sealed under {said}, which the platform's settings cannot derive "
            "(a rotated settings key, or a relabelled seal); the chain cannot be checked with "
            "the keys held.",
        )
    if ledger_chain.record_digest(seal, key) != seal.get("digest"):
        return result.end(BROKEN, "The seal does not verify under its key.")
    if str(seal.get("job_id")) != str(job_id):
        return result.end(BROKEN, "The seal names another job.")
    result.check("the seal verifies under its key")

    ended = _check_the_chain(result, job_id, ordered, seal, key)
    if ended is not None:
        return ended

    if report is not None:
        ended = _check_report(result, seal, report, audit, keys)
        if ended is not None:
            return ended
    else:
        return _check_the_deletion(result, seal, audit)
    return _final(result, audit)


def _final(result: _Result, audit: JobAudit | None) -> dict[str, Any]:
    if audit is not None:
        if audit.check.head_unverifiable:
            return result.end(UNVERIFIABLE, HEAD_UNVERIFIABLE)
        if audit.unverifiable_own:
            return result.end(UNVERIFIABLE, OWN_ROWS_UNVERIFIABLE)
        result.check(f"this job's {len(audit.check.verified)} audit row(s) verify")
    if result.pending is not None:
        return result.end(UNVERIFIABLE, result.pending)
    return result.end(VERIFIED, VERIFIED_REASON)


def _seal_of_the_report(
    result: _Result,
    report: Mapping[str, Any],
    ordered: list[Any],
    chained_rows: list[Any],
    audit: JobAudit | None,
) -> dict[str, Any]:
    """The seal of a stored report, or the verdict that ends the verification."""
    payload = report.get("malware_report")
    summary = report.get("run_summary")
    copies: dict[str, Any] = {
        "report row": report.get("ledger_seal"),
        "report payload": payload.get(ledger_chain.SEAL_KEY)
        if isinstance(payload, Mapping)
        else None,
        "run summary": summary.get(ledger_chain.SEAL_KEY) if isinstance(summary, Mapping) else None,
    }
    present = {name: dict(seal) for name, seal in copies.items() if isinstance(seal, Mapping)}
    report_id = str(report.get("id"))
    for_report = [d for d in (audit.seals if audit else []) if str(d.get("report_id")) == report_id]
    if not present:
        if chained_rows:
            return result.end(
                BROKEN,
                "Rows of this job carry digests, but the stored report carries no seal.",
                _seq(chained_rows[0]),
            )
        if for_report:
            return result.end(
                BROKEN, "The audit chain records a seal for this report; the report carries none."
            )
        if audit is not None and audit.unverifiable_own:
            return result.end(UNVERIFIABLE, OWN_ROWS_UNVERIFIABLE)
        # A verified seal of this job on the audit chain that no report.delete
        # accounts for belongs to a report that is no longer stored: a re-run
        # replaced it and its deletion was not recorded (no key then), or the
        # report row was removed. Neither is a run that predates sealing.
        if audit is not None:
            deleted = {d.get("core_digest") for d in audit.deletes if d.get("core_digest")}
            if [d for d in audit.seals if _digest_of(d.get("seal")) not in deleted]:
                return result.end(UNVERIFIABLE, SEAL_SUPERSEDED)
        if audit is not None and audit.chain_gap:
            return result.end(UNVERIFIABLE, audit.chain_gap)
        return result.end(NOT_SEALED, PREDATES)
    seal = present.get("report row") or next(iter(present.values()))
    if any(copy != seal for copy in present.values()):
        return result.end(
            BROKEN, "The copies of the seal disagree: " + ", ".join(sorted(present)) + "."
        )
    if "report row" not in present:
        return result.end(BROKEN, "The report is stored, but its row carries no seal.")
    for name, document in (("report payload", payload), ("run summary", summary)):
        if isinstance(document, Mapping) and name not in present:
            return result.end(BROKEN, f"The {name} carries no seal although the report row does.")
    result.check("every stored copy of the seal agrees: " + ", ".join(sorted(present)))
    if str(seal.get("report_id")) != report_id:
        return result.end(BROKEN, "The seal was made for another report row.")
    if audit is not None:
        core = ledger_chain.core_of(seal)
        matching = [
            d.get("seal") for d in for_report if _digest_of(d.get("seal")) == core["digest"]
        ]
        if matching:
            if matching[-1] != core:
                return result.end(BROKEN, "The audit chain's seal for this report differs.")
            result.check("the seal is on the audit chain")
        elif for_report:
            return result.end(
                BROKEN, "The audit chain records another seal for this report than it carries."
            )
        elif audit.unverifiable_own:
            result.pending = OWN_ROWS_UNVERIFIABLE
        elif seal.get("audit_anchored") is True:
            return result.end(
                BROKEN,
                "The seal says its audit row was written, and the job's audit rows do not hold "
                "it: the row was removed.",
            )
        else:
            result.pending = SEAL_NOT_ANCHORED
    return seal


def _seal_without_a_report(
    result: _Result,
    ordered: list[Any],
    chained_rows: list[Any],
    audit: JobAudit | None,
) -> dict[str, Any]:
    """The seal of a job whose report row is gone, or the verdict that ends the verification.

    A report.delete row names the core seal of the report it deleted; that seal
    is the one the rows are checked against, never simply the latest.
    """
    if audit is not None and audit.deletes:
        named = {d.get("core_digest") for d in audit.deletes if d.get("core_digest")}
        held = [d.get("seal") for d in audit.seals if _digest_of(d.get("seal")) in named]
        if held and isinstance(held[-1], Mapping):
            result.note("No report is stored for this job; the seal was read from the audit chain.")
            return dict(held[-1])
        if named:
            return result.end(
                UNVERIFIABLE,
                "The report was deleted by its owner, but the audit append for its seal did not "
                "land, so the seal its rows are checked against is not on the audit chain.",
            )
    if audit is not None and audit.seals:
        seal = audit.seals[-1].get("seal")
        if isinstance(seal, Mapping):
            result.note("No report is stored for this job; the seal was read from the audit chain.")
            return dict(seal)
    if audit is not None and audit.unverifiable_own:
        return result.end(UNVERIFIABLE, OWN_ROWS_UNVERIFIABLE)
    if chained_rows:
        if audit is None:
            return result.end(
                UNVERIFIABLE,
                "Rows of this job carry digests, but no report is stored and the audit log was "
                "not read, so no seal could be found.",
            )
        return result.end(
            BROKEN,
            "Rows of this job carry digests, but no seal is stored for it anywhere.",
            _seq(chained_rows[0]),
        )
    if audit is not None and audit.chain_gap:
        return result.end(UNVERIFIABLE, audit.chain_gap)
    if not ordered:
        return result.end(NOT_SEALED, NOTHING_STORED)
    return result.end(NOT_SEALED, PREDATES)


def _digest_of(seal: Any) -> Any:
    return seal.get("digest") if isinstance(seal, Mapping) else None


def _check_the_chain(
    result: _Result,
    job_id: Any,
    ordered: list[Any],
    seal: Mapping[str, Any],
    key: ledger_chain.ChainKey,
) -> dict[str, Any] | None:
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
    return None


def _check_the_deletion(
    result: _Result, seal: Mapping[str, Any], audit: JobAudit | None
) -> dict[str, Any]:
    """A sealed job whose report row is gone: deleted by its owner, or broken."""
    records = [
        d for d in (audit.deletes if audit else []) if d.get("core_digest") == seal.get("digest")
    ]
    if not records:
        return result.end(
            BROKEN, "The report row is gone and no report.delete audit row records its deletion."
        )
    if audit is not None and audit.check.head_unverifiable:
        return result.end(UNVERIFIABLE, HEAD_UNVERIFIABLE)
    return result.end(
        DELETED,
        "The report was deleted by its owner (a verified report.delete audit row records it); "
        "the ledger still verifies against its seal.",
    )


def _audit_amendments(
    seal: Mapping[str, Any],
    report_id: str,
    audit: JobAudit,
    keys: Mapping[str, ledger_chain.ChainKey],
) -> list[dict[str, Any]]:
    """The amendments the audit chain records for this seal, in their chain order."""
    held = [
        dict(d["amendment"])
        for d in audit.amendments
        if str(d.get("report_id")) == report_id and isinstance(d.get("amendment"), Mapping)
    ]
    chain: list[dict[str, Any]] = []
    previous = seal.get("digest")
    while True:
        following = [
            a
            for a in held
            if a.get("prev") == previous
            and (k := keys.get(a.get("key_id") or "")) is not None
            and ledger_chain.record_digest(a, k) == a.get("digest")
        ]
        if not following:
            return chain
        chain.append(following[0])
        previous = following[0].get("digest")


def _check_report(
    result: _Result,
    seal: Mapping[str, Any],
    report: Mapping[str, Any],
    audit: JobAudit | None,
    keys: Mapping[str, ledger_chain.ChainKey],
) -> dict[str, Any] | None:
    """Walk the amendments from the seal to the stored report row; the failure, or ``None``."""
    payload = report.get("malware_report")
    summary = report.get("run_summary")
    held = (payload or {}).get(ledger_chain.AMENDMENTS_KEY) if isinstance(payload, Mapping) else []
    held = held or []
    if isinstance(summary, Mapping) and (summary.get(ledger_chain.AMENDMENTS_KEY) or []) != held:
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
    if audit is not None:
        recorded = _audit_amendments(seal, str(report.get("id")), audit, keys)
        for index, record in enumerate(recorded, start=1):
            if index > len(held):
                return result.end(
                    BROKEN,
                    f"Amendment {index}, recorded on the audit chain for this seal, is missing "
                    "from the stored report.",
                )
            if dict(held[index - 1]) != record:
                return result.end(
                    BROKEN, f"Amendment {index} differs from the one the audit chain records."
                )
        if len(held) > len(recorded) and result.pending is None:
            result.pending = (
                f"The audit append for amendment {len(recorded) + 1} did not land: the audit "
                "chain does not record it, so it cannot be confirmed."
            )
        result.check(f"the {len(recorded)} audited amendment(s) are the stored ones, in order")
    current = ledger_chain.report_digest(report)
    if current != expected:
        return result.end(
            BROKEN, "The stored report changed after the seal and no amendment records it."
        )
    result.check(
        f"the stored report row equals the seal's report digest after {len(held)} amendment(s)"
    )
    return None


async def verify_job(
    db: Any,
    job_id: Any,
    *,
    preloaded: tuple[Sequence[Mapping[str, Any]], Mapping[str, Any] | None] | None = None,
) -> dict[str, Any]:
    """Read one job's ledger, report and own chained audit rows through ``db`` and verify them.

    ``preloaded`` is the job's ledger rows and report row when the caller has
    already read them in the same transaction (the job package): they are
    used as they are rather than read and held a second time.

    ``db`` is an ``AsyncSession`` or an ``AsyncConnection``: only Core
    ``SELECT``\\s are issued, so a read-only transaction serves it. Only this
    job's chained audit rows are read, with the chain value of the row before
    each and the head record, so the cost follows the job
    (``audit_chain.verify_job_rows``).
    """
    from sqlalchemy import func, select

    from app.models.audit import AuditChainHead, AuditLog
    from app.models.evidence import EvidenceEntry
    from app.models.report import AnalysisReport
    from app.services import audit_chain

    rows: Sequence[Mapping[str, Any]]
    report: Mapping[str, Any] | None
    if preloaded is not None:
        rows, report = preloaded
    else:
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
    # The head first: it is rewritten in the same transaction as each chained
    # row, so every row up to its seq is committed, and a row another job
    # appends while this verification runs lies past it and is not read.
    heads = AuditChainHead.__table__
    head = (
        (await db.execute(select(heads).where(heads.c.name == audit_chain.HEAD_NAME)))
        .mappings()
        .first()
    )
    gap: str | None = None
    if head is not None:
        expected = int(head["chain_seq"])
        present = (
            await db.execute(
                select(func.count()).select_from(log).where(log.c.chain_seq <= expected)
            )
        ).scalar()
        if int(present or 0) != expected:
            gap = (
                f"The audit chain is not contiguous up to its head: {expected} rows should "
                f"exist and {int(present or 0)} do, so rows were removed from it; a job with "
                "no audit rows of its own cannot be told from one whose rows were among them."
            )
    within = (
        log.c.chain_seq <= int(head["chain_seq"])
        if head is not None
        else log.c.chain_seq.is_not(None)
    )
    own = (
        (
            await db.execute(
                select(log)
                .where(log.c.chain_seq.is_not(None), log.c.resource_id == str(job_id), within)
                .order_by(log.c.chain_seq)
            )
        )
        .mappings()
        .all()
    )
    # The chain value of the row before each of the job's rows, and the row
    # after each: O(the job's rows), whatever the length of the chain.
    seqs = {int(r["chain_seq"]) for r in own}
    neighbours = sorted({s - 1 for s in seqs if s > 1} | {s + 1 for s in seqs})
    predecessors: dict[int, str] = {}
    successors: dict[int, dict[str, Any]] = {}
    if neighbours:
        found = (
            (await db.execute(select(log).where(log.c.chain_seq.in_(neighbours), within)))
            .mappings()
            .all()
        )
        for neighbour in found:
            predecessors[int(neighbour["chain_seq"])] = str(neighbour["chain"])
            successors[int(neighbour["chain_seq"])] = dict(neighbour)
    keys = ledger_chain.known_keys()
    current = ledger_chain.platform_key()
    check = audit_chain.verify_job_rows(
        own,
        predecessors,
        keys,
        head,
        current.key_id if current is not None else None,
        successors=successors,
    )
    verified = set(check.verified)

    def _details(action: str) -> list[dict[str, Any]]:
        return [
            dict(r["details"] or {})
            for r in own
            if r["action"] == action and int(r["chain_seq"]) in verified
        ]

    audit = JobAudit(
        check=check,
        seals=_details(audit_chain.LEDGER_SEAL),
        amendments=_details(audit_chain.REPORT_AMEND),
        deletes=_details(audit_chain.REPORT_DELETE),
        chain_gap=gap,
    )
    return verify_ledger(
        job_id,
        rows if preloaded is not None else [dict(r) for r in rows],
        report=dict(report) if report is not None else None,
        audit=audit,
        keys=keys,
    )

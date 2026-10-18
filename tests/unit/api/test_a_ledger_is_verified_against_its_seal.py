"""A job's stored ledger is verified against its seal, and says what it found.

The chain is recomputed from the rows. A sealed job reads as tampered when a
row changed, a row was deleted or added, a digest is NULL, the count changed,
the chain was recomputed without the key, a copy of the seal is missing or
disagrees, any column of the report row the seal covers changed with no
amendment, or the payload lacks an amendment the audit chain records; the first
broken ``seq`` is named where a row is to blame. A report its owner deleted
reads ``deleted``; one gone without a record is broken. A missing audit row
reads ``unverifiable``, never verified and never broken. A seal made under a
key the platform cannot derive is reported as such. A run stored before
sealing reads as not sealed, and so does a job that stored nothing.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from fastapi import HTTPException
from scripts.ledger import verify as cli

from app.models.report import AnalysisReport
from app.services import ledger_chain, ledger_verify
from app.services.audit_chain import AuditChainCheck
from app.services.ledger_verify import JobAudit
from app.worker.analysis_worker import _evidence_row
from maljan.schemas.evidence import LedgerEntry

KEY = ledger_chain.derive_key("verify-test-material")
OTHER = ledger_chain.derive_key("verify-test-rotated-material")
KEYS = {KEY.key_id: KEY}
NOW = datetime(2026, 10, 18, 9, 0, tzinfo=UTC)


def _report_row(job_id: uuid.UUID) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "job_id": str(job_id),
        "verdict": "Malicious",
        "overall_confidence": 0.85,
        "malware_category": "loader",
        "stix_bundle": {"type": "bundle", "objects": []},
        "judge_stix_bundle": None,
        "mitre_techniques": ["T1055"],
        "agent_reports": {"static": "a packed loader"},
        "negotiation_log": {"discussion_history": []},
        "run_summary": {"evidence": {"entries": 4}},
        "malware_report": {"verdict": "Malicious", "network": {"domains": []}},
        "incomplete_reason": None,
        "ledger_seal": None,
    }


def _audit(*seals: dict[str, Any], **extra: Any) -> JobAudit:
    count = len(seals) + len(extra.get("amendments", [])) + len(extra.get("deletes", []))
    check = extra.pop("check", None) or AuditChainCheck(
        rows=count, head_seq=count, rotated_at_seq=1, verified=list(range(1, count + 1))
    )
    return JobAudit(check=check, seals=list(seals), **extra)


def _sealed(count: int = 4, key: ledger_chain.ChainKey = KEY) -> dict[str, Any]:
    job_id = uuid.uuid4()
    rows = [
        _evidence_row(
            LedgerEntry(
                id=f"ev_{seq:04d}", tool="pe_info", seq=seq, output=f"answer {seq}"
            ).model_dump(mode="json"),
            job_id=job_id,
            written_at=NOW,
        )
        for seq in range(1, count + 1)
    ]
    head = ledger_chain.chain_rows(job_id, rows, key)
    report = _report_row(job_id)
    core = _seal_into(report, job_id, rows, head, key)
    return {
        "job_id": job_id,
        "rows": [
            ledger_chain.entry_fields(r) | {"digest": r.digest, "chain": r.chain} for r in rows
        ],
        "report": report,
        "audit": _audit({"report_id": report["id"], "seal": core}),
    }


def _seal_into(
    report: dict[str, Any],
    job_id: Any,
    rows: list[Any],
    head: str,
    key: ledger_chain.ChainKey = KEY,
    *,
    landed: bool = True,
) -> dict[str, Any]:
    """Seal ``report`` as the worker does; the core seal the audit chain holds."""
    core = ledger_chain.seal(
        job_id,
        rows,
        head,
        report_sha256=ledger_chain.report_digest(report),
        sealed_at=NOW,
        key=key,
        report_id=report["id"],
    )
    seal = ledger_chain.anchored(core, landed=landed, key=key)
    report["ledger_seal"] = seal
    report["malware_report"] = ledger_chain.with_seal(report["malware_report"], seal)
    report["run_summary"] = ledger_chain.with_seal(report["run_summary"], seal)
    return core


def _verify(job: dict[str, Any], keys: dict[str, Any] = KEYS, **changes: Any) -> dict[str, Any]:
    given = {**job, **changes}
    return ledger_verify.verify_ledger(
        given["job_id"], given["rows"], report=given["report"], audit=given["audit"], keys=keys
    )


def _seal(job: dict[str, Any]) -> dict[str, Any]:
    return dict(job["report"]["ledger_seal"])


def _core(job: dict[str, Any]) -> dict[str, Any]:
    return ledger_chain.core_of(_seal(job))


def test_an_untouched_sealed_ledger_verifies():
    job = _sealed()
    verdict = _verify(job)
    assert verdict["status"] == "verified", verdict
    assert verdict["head"] == _seal(job)["head"]
    assert verdict["first_broken_seq"] is None
    assert "findings and the transcript are not covered" in verdict["reason"]


def test_a_changed_row_is_tampering_at_its_seq():
    job = _sealed()
    job["rows"][2]["output"] = "something else"
    verdict = _verify(job)
    assert (verdict["status"], verdict["first_broken_seq"]) == ("broken", 3)
    assert "differs from its digest" in verdict["reason"]


def test_a_row_rechained_without_the_key_is_tampering():
    job = _sealed()
    row = job["rows"][1]
    row["output"] = "rewritten"
    row["digest"] = ledger_chain.entry_digest(row)
    row["chain"] = ledger_chain.link(job["rows"][0]["chain"], row["digest"], ledger_chain.UNKEYED)
    verdict = _verify(job)
    assert (verdict["status"], verdict["first_broken_seq"]) == ("broken", 2)
    assert "does not link" in verdict["reason"]


def test_a_whole_chain_and_seal_recomputed_without_the_key_is_tampering():
    job = _sealed()
    forged = _sealed(key=ledger_chain.UNKEYED)
    seal = dict(
        forged["report"]["ledger_seal"],
        job_id=str(job["job_id"]),
        report_id=job["report"]["id"],
        key_id=KEY.key_id,
    )
    report = dict(job["report"], ledger_seal=seal)
    report["malware_report"] = ledger_chain.with_seal(report["malware_report"], seal)
    report["run_summary"] = ledger_chain.with_seal(report["run_summary"], seal)
    audit = _audit({"report_id": report["id"], "seal": ledger_chain.core_of(seal)})
    verdict = _verify(job, report=report, audit=audit)
    assert verdict["status"] == "broken"
    assert "does not verify under its key" in verdict["reason"]


def test_a_deleted_row_is_tampering_at_the_next_seq():
    job = _sealed()
    del job["rows"][1]
    assert (_verify(job)["status"], _verify(job)["first_broken_seq"]) == ("broken", 3)


def test_a_deleted_last_row_is_tampering_named_by_its_seq():
    job = _sealed()
    del job["rows"][-1]
    verdict = _verify(job)
    assert (verdict["status"], verdict["first_broken_seq"]) == ("broken", 4)
    assert "missing" in verdict["reason"]


def test_an_extra_row_is_tampering():
    job = _sealed()
    extra = dict(job["rows"][-1], entry_id="ev_0005", seq=5)
    extra["digest"] = ledger_chain.entry_digest(extra)
    extra["chain"] = "0" * 64
    job["rows"].append(extra)
    verdict = _verify(job)
    assert (verdict["status"], verdict["first_broken_seq"]) == ("broken", 5)


def test_a_null_digest_on_a_sealed_job_is_tampering():
    job = _sealed()
    job["rows"][0]["digest"] = None
    verdict = _verify(job)
    assert (verdict["status"], verdict["first_broken_seq"]) == ("broken", 1)
    assert "carries no digest" in verdict["reason"]


def test_a_missing_or_disagreeing_seal_copy_is_tampering():
    job = _sealed()
    assert _verify(job, report=dict(job["report"], ledger_seal=None))["status"] == "broken"
    other = dict(_seal(job), entries=3)
    assert "disagree" in _verify(job, report=dict(job["report"], ledger_seal=other))["reason"]


def test_rows_with_digests_and_no_seal_anywhere_are_tampering():
    job = _sealed()
    report = dict(_report_row(job["job_id"]))
    verdict = _verify(job, report=report, audit=_audit())
    assert (verdict["status"], verdict["first_broken_seq"]) == ("broken", 1)


def test_a_rotated_key_is_reported_as_such():
    job = _sealed()
    verdict = _verify(job, keys={OTHER.key_id: OTHER})
    assert verdict["status"] == "other_key"
    assert KEY.key_id in verdict["reason"]
    job["rows"][0]["output"] = "changed under a rotated key"
    assert _verify(job, keys={OTHER.key_id: OTHER})["status"] == "broken"


def test_an_unkeyed_seal_is_never_verified():
    job = _sealed(key=ledger_chain.UNKEYED)
    assert _verify(job)["status"] == "other_key"
    assert _verify(job, keys={})["status"] == "other_key"


def test_a_change_to_any_report_column_without_an_amendment_is_tampering():
    for name, value in (
        ("verdict", "Benign"),
        ("overall_confidence", 0.1),
        ("malware_category", "adware"),
        ("mitre_techniques", []),
        ("agent_reports", {"static": "benign"}),
        ("negotiation_log", {}),
        ("judge_stix_bundle", {"bundle": {}}),
        ("incomplete_reason", "stopped"),
    ):
        job = _sealed()
        verdict = _verify(job, report=dict(job["report"], **{name: value}))
        assert verdict["status"] == "broken", name
        assert "no amendment" in verdict["reason"], name


def test_every_report_column_is_digested_or_named_as_bookkeeping():
    columns = {c.name for c in AnalysisReport.__table__.columns}
    digested = set(ledger_chain.REPORT_DIGESTED)
    bookkeeping = set(ledger_chain.REPORT_BOOKKEEPING)
    assert not digested & bookkeeping
    assert digested | bookkeeping == columns


def _amended(job: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    report = job["report"]
    changed = dict(report["malware_report"], verdict="Benign")
    payload, summary, record = ledger_chain.amend(
        report, changed, None, seal_record=report["ledger_seal"], kind="enrichment", key=KEY, at=NOW
    )
    assert record is not None
    return dict(report, malware_report=payload, run_summary=summary), record


def test_a_report_changed_with_an_amendment_on_both_sides_verifies():
    job = _sealed()
    report, record = _amended(job)
    audit = _audit(
        {"report_id": report["id"], "seal": _core(job)},
        amendments=[{"report_id": report["id"], "amendment": record}],
    )
    verdict = _verify(job, report=report, audit=audit)
    assert verdict["status"] == "verified", verdict
    assert verdict["amendments"] == 1


def test_a_dropped_trailing_amendment_and_a_rolled_back_report_is_tampering():
    job = _sealed()
    report, record = _amended(job)
    audit = _audit(
        {"report_id": report["id"], "seal": _core(job)},
        amendments=[{"report_id": report["id"], "amendment": record}],
    )
    rolled_back = job["report"]
    verdict = _verify(job, report=rolled_back, audit=audit)
    assert verdict["status"] == "broken"
    assert "Amendment 1, recorded on the audit chain for this seal, is missing" in verdict["reason"]


def test_an_amendment_whose_audit_append_did_not_land_reads_unverifiable():
    job = _sealed()
    report, _record = _amended(job)
    verdict = _verify(job, report=report)
    assert verdict["status"] == "unverifiable"
    assert "amendment 1 did not land" in verdict["reason"]


def test_a_seal_row_that_landed_and_is_gone_reads_broken():
    job = _sealed()
    assert _seal(job)["audit_anchored"] is True
    verdict = _verify(job, audit=_audit())
    assert verdict["status"] == "broken"
    assert "the row was removed" in verdict["reason"]


def test_a_seal_whose_audit_append_did_not_land_reads_unverifiable():
    job = _sealed()
    report = _report_row(job["job_id"])
    rows = job["rows"]
    _seal_into(report, job["job_id"], rows, rows[-1]["chain"], landed=False)
    verdict = _verify(job, report=report, audit=_audit())
    assert verdict["status"] == "unverifiable"
    assert verdict["reason"] == ledger_verify.SEAL_NOT_ANCHORED
    assert "did not land" in verdict["reason"]


def test_a_seal_copied_onto_another_report_row_reads_broken():
    job = _sealed()
    other = _report_row(job["job_id"])
    seal = _seal(job)
    other["ledger_seal"] = seal
    other["malware_report"] = ledger_chain.with_seal(other["malware_report"], seal)
    other["run_summary"] = ledger_chain.with_seal(other["run_summary"], seal)
    audit = _audit({"report_id": other["id"], "seal": _core(job)})
    verdict = _verify(job, report=other, audit=audit)
    assert verdict["status"] == "broken"
    assert "another report row" in verdict["reason"]


def test_a_deleted_amend_row_with_its_payload_stripped_reads_broken():
    from app.services import audit_chain

    job = _sealed()
    report, record = _amended(job)
    head = None
    rows: list[dict[str, Any]] = []
    for seq, (action, details) in enumerate(
        (
            (audit_chain.LEDGER_SEAL, {"report_id": report["id"], "seal": _core(job)}),
            (audit_chain.REPORT_AMEND, {"report_id": report["id"], "amendment": record}),
            (audit_chain.LEDGER_SEAL, {"seal": {}}),
        ),
        start=1,
    ):
        owner = job["job_id"] if seq < 3 else uuid.uuid4()
        rows.append(_audit_row(seq, head, owner, action, details))
        head = rows[-1]["chain"]
    head_record = {
        "chain_seq": 3,
        "chain": head,
        "key_id": KEY.key_id,
        "rotated_at_seq": 1,
        "mac": audit_chain.head_mac(3, head, 1, KEY),
    }
    surviving = [rows[0]]
    neighbours = {2: rows[2]}  # the amend row at 2 is gone; nothing answers for it
    check = audit_chain.verify_job_rows(
        surviving,
        {},
        KEYS,
        head_record,
        KEY.key_id,
        successors={k: v for k, v in neighbours.items() if k != 2},
    )
    assert check.broken_at == 1
    assert "after this job's ledger.seal row is missing" in (check.reason or "")
    stripped = job["report"]
    verdict = _verify(job, report=stripped, audit=JobAudit(check=check))
    assert verdict["status"] == "broken"


def test_the_audit_seal_is_picked_by_this_report_s_seal_digest():
    job = _sealed()
    earlier = _sealed()
    audit = _audit(
        {"report_id": job["report"]["id"], "seal": _core(job)},
        {"report_id": earlier["report"]["id"], "seal": _core(earlier)},
    )
    assert _verify(job, audit=audit)["status"] == "verified"


def test_a_relabelled_key_id_with_recomputed_digests_does_not_escape():
    job = _sealed()
    seal = dict(_seal(job), key_id="0000000000000000")
    report = dict(job["report"], ledger_seal=seal)
    report["malware_report"] = ledger_chain.with_seal(report["malware_report"], seal)
    report["run_summary"] = ledger_chain.with_seal(report["run_summary"], seal)
    job["rows"][0]["output"] = "edited"
    job["rows"][0]["digest"] = ledger_chain.entry_digest(job["rows"][0])
    verdict = _verify(job, report=report)
    assert verdict["status"] == "broken"
    assert "differs" in verdict["reason"]


def test_a_report_deleted_by_its_owner_reads_deleted_and_one_gone_silently_is_broken():
    job = _sealed()
    seal = _core(job)
    audit = _audit(
        {"report_id": job["report"]["id"], "seal": seal},
        deletes=[
            {
                "report_id": job["report"]["id"],
                "seal_digest": _seal(job)["digest"],
                "core_digest": seal["digest"],
            }
        ],
    )
    deleted = _verify(job, report=None, audit=audit)
    assert deleted["status"] == "deleted", deleted
    gone = _verify(job, report=None, audit=_audit({"report_id": job["report"]["id"], "seal": seal}))
    assert gone["status"] == "broken"
    assert "no report.delete audit row" in gone["reason"]
    job["rows"][0]["output"] = "edited after the deletion"
    assert _verify(job, report=None, audit=audit)["status"] == "broken"


def test_a_broken_job_audit_row_is_tampering_without_a_global_position():
    job = _sealed()
    check = AuditChainCheck(
        rows=1, broken_at=812, reason="this job's ledger.seal audit row differs from its digest"
    )
    verdict = _verify(job, audit=JobAudit(check=check))
    assert verdict["status"] == "broken"
    assert "812" not in verdict["reason"]


def test_a_job_sealed_after_a_rotation_verifies_beside_an_unverifiable_older_segment():
    job = _sealed()
    audit = job["audit"]
    audit.check.unverifiable = []
    assert _verify(job)["status"] == "verified"


def test_a_head_under_an_unknown_key_reads_unverifiable_never_verified():
    job = _sealed()
    job["audit"].check.head_unverifiable = True
    verdict = _verify(job)
    assert verdict["status"] == "unverifiable"
    assert verdict["reason"] == ledger_verify.HEAD_UNVERIFIABLE


def test_a_job_whose_own_seal_row_is_unverifiable_reads_unverifiable():
    job = _sealed()
    check = AuditChainCheck(rows=1, head_seq=3, rotated_at_seq=3, unverifiable=[1])
    verdict = _verify(job, audit=JobAudit(check=check))
    assert verdict["status"] == "unverifiable"
    assert verdict["reason"] == ledger_verify.OWN_ROWS_UNVERIFIABLE
    gone = _verify(job, report=None, audit=JobAudit(check=check))
    assert gone["status"] == "unverifiable"


def test_an_old_job_predates_sealing_and_an_empty_one_stored_nothing():
    job = _sealed()
    old_rows = [{k: v for k, v in r.items() if k not in ("digest", "chain")} for r in job["rows"]]
    verdict = ledger_verify.verify_ledger(
        job["job_id"], old_rows, report=_report_row(job["job_id"]), keys=KEYS
    )
    assert (verdict["status"], verdict["reason"]) == ("not_sealed", ledger_verify.PREDATES)
    empty = ledger_verify.verify_ledger(uuid.uuid4(), [], keys=KEYS)
    assert (empty["status"], empty["reason"]) == ("not_sealed", ledger_verify.NOTHING_STORED)


def _write_run(job: dict[str, Any], into: Path) -> None:
    into.mkdir()
    report = job["report"]
    (into / "evidence.json").write_text(
        json.dumps({"total": len(job["rows"]), "items": job["rows"]}), encoding="utf-8"
    )
    byjob = {name: report.get(name) for name in (*ledger_chain.REPORT_DIGESTED, "id")}
    byjob["ledger_seal"] = report["ledger_seal"]
    (into / "report-byjob.json").write_text(json.dumps(byjob), encoding="utf-8")
    if report["malware_report"] is not None:
        (into / "report.json").write_text(json.dumps(report["malware_report"]), encoding="utf-8")
    if report["run_summary"] is not None:
        (into / "run-summary.json").write_text(json.dumps(report["run_summary"]), encoding="utf-8")


def test_the_command_verifies_a_stored_run_directory(tmp_path: Path, monkeypatch: Any, capsys):
    monkeypatch.setattr(ledger_chain, "known_keys", lambda: KEYS)
    job = _sealed()
    _write_run(job, tmp_path / "run")
    assert cli.main(["--run", str(tmp_path / "run")]) == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["status"] == "verified"
    assert any("audit log was not read" in note for note in printed["notes"])

    job["rows"][1]["output"] = "edited in the export"
    _write_run(job, tmp_path / "edited")
    assert cli.main(["--run", str(tmp_path / "edited")]) == 1
    assert json.loads(capsys.readouterr().out)["first_broken_seq"] == 2


def test_a_null_run_summary_reads_the_same_from_an_export_as_from_the_database(
    tmp_path: Path, monkeypatch: Any
):
    monkeypatch.setattr(ledger_chain, "known_keys", lambda: KEYS)
    job_id = uuid.uuid4()
    report = _report_row(job_id) | {"run_summary": None}
    _seal_into(report, job_id, [], ledger_chain.genesis(job_id, KEY))
    assert report["run_summary"] is None
    job = {"job_id": job_id, "rows": [], "report": report, "audit": None}
    database = _verify(job)
    _write_run(job, tmp_path / "run")
    exported = cli.verify_run(tmp_path / "run")
    assert database["status"] == exported["status"] == "verified", (database, exported)


def _benchmark() -> Path | None:
    main = Path("/home/user/Belgeler/kingston/Projects/Maljan/.superpowers/sdd/mandate-2026-09-17")
    for parent in (*Path(__file__).resolve().parents, main.parents[2]):
        candidate = parent / ".superpowers/sdd/mandate-2026-09-17/benchmark/deepseek"
        if candidate.is_dir():
            return candidate
    return None


@pytest.mark.parametrize("run", ["run7", "run5", "run4", "local8", "haiku4"])
def test_a_stored_run_from_before_sealing_reads_as_not_sealed(run: str, capsys):
    root = _benchmark()
    if root is None or not (root / run).is_dir():
        pytest.skip("the stored runs are not on this machine")
    assert cli.main(["--run", str(root / run)]) == 3
    printed = json.loads(capsys.readouterr().out)
    assert (printed["status"], printed["reason"]) == ("not_sealed", ledger_verify.PREDATES)


class _Service:
    def __init__(self, job: Any) -> None:
        self._job = job

    async def get_job(self, job_id: uuid.UUID, user: Any) -> Any:
        return self._job


class _User:
    id = uuid.uuid4()


@pytest.mark.asyncio
async def test_the_route_is_owner_only_and_serves_the_verdict(monkeypatch: Any):
    from app.api.v1.jobs import verify_job_evidence

    with pytest.raises(HTTPException) as refused:
        await verify_job_evidence(uuid.uuid4(), user=_User(), svc=_Service(None), db=object())
    assert refused.value.status_code == 404

    job = _sealed()

    async def _verify_job(db: Any, job_id: Any) -> dict[str, Any]:
        return _verify(job)

    monkeypatch.setattr(ledger_verify, "verify_job", _verify_job)
    served = await verify_job_evidence(
        job["job_id"], user=_User(), svc=_Service(object()), db=object()
    )
    assert served.status == "verified"
    assert served.seal == _seal(job)
    assert KEY.key.hex() not in json.dumps(served.model_dump())


class _AsyncConnection:
    """The calls ``verify_job`` makes, answered by a synchronous SQLite connection."""

    def __init__(self, conn: Any) -> None:
        self._conn = conn

    async def execute(self, statement: Any) -> Any:
        return self._conn.execute(statement)


def _audit_row(seq: int, previous: str | None, job_id: Any, action: str, details: Any) -> dict:
    from app.services import audit_chain

    row: dict[str, Any] = {
        "id": uuid.uuid4(),
        "user_id": None,
        "action": action,
        "resource_type": "job",
        "resource_id": str(job_id),
        "details": details,
        "ip_address": None,
        "created_at": NOW,
        "chain_seq": seq,
        "chain_key_id": KEY.key_id,
    }
    row["digest"] = audit_chain.audit_digest(row)
    start = previous if previous is not None else audit_chain.audit_genesis(KEY)
    row["chain"] = audit_chain.audit_link(start, row["digest"], KEY)
    return row


@pytest.mark.asyncio
async def test_the_job_is_read_from_the_database_with_only_its_own_audit_rows(monkeypatch: Any):
    import sqlalchemy as sa
    from sqlalchemy.dialects import postgresql
    from sqlalchemy.ext.compiler import compiles

    from app.models.audit import AuditChainHead, AuditLog
    from app.models.evidence import EvidenceEntry
    from app.services import audit_chain

    @compiles(postgresql.JSONB, "sqlite")
    def _json(element, compiler, **kw):  # noqa: ANN001, ANN202
        return "JSON"

    @compiles(postgresql.INET, "sqlite")
    def _inet(element, compiler, **kw):  # noqa: ANN001, ANN202
        return "TEXT"

    monkeypatch.setattr(ledger_chain, "platform_key_status", lambda: (KEY, None))
    job_id = uuid.uuid4()
    rows = [
        _evidence_row(
            LedgerEntry(id=f"ev_{s:04d}", tool="pe_info", seq=s, output="x").model_dump(
                mode="json"
            ),
            job_id=job_id,
            written_at=NOW,
        )
        for s in (1, 2, 3)
    ]
    head = ledger_chain.chain_rows(job_id, rows, KEY)
    report = _report_row(job_id)
    seal = _seal_into(report, job_id, rows, head)
    other_job = uuid.uuid4()
    first = _audit_row(1, None, other_job, audit_chain.LEDGER_SEAL, {"seal": {}})
    mine = _audit_row(
        2,
        first["chain"],
        job_id,
        audit_chain.LEDGER_SEAL,
        {"report_id": report["id"], "seal": seal},
    )
    last = _audit_row(3, mine["chain"], other_job, audit_chain.REPORT_AMEND, {})

    engine = sa.create_engine("sqlite://")
    with engine.begin() as conn:
        for model in (EvidenceEntry, AnalysisReport, AuditLog, AuditChainHead):
            model.__table__.create(conn)
        for row in rows:
            values = {c.name: getattr(row, c.name) for c in EvidenceEntry.__table__.columns}
            values |= {"id": uuid.uuid4(), "updated_at": NOW}
            conn.execute(EvidenceEntry.__table__.insert().values(**values))
        conn.execute(
            AnalysisReport.__table__.insert().values(
                **report | {"id": uuid.UUID(report["id"]), "job_id": job_id},
                created_at=NOW,
                updated_at=NOW,
            )
        )
        for audit_row in (first, mine, last):
            conn.execute(AuditLog.__table__.insert().values(**audit_row))
        conn.execute(
            AuditChainHead.__table__.insert().values(
                name=audit_chain.HEAD_NAME,
                chain_seq=3,
                chain=last["chain"],
                key_id=KEY.key_id,
                rotated_at_seq=1,
                mac=audit_chain.head_mac(3, last["chain"], 1, KEY),
            )
        )
        db = _AsyncConnection(conn)
        verdict = await ledger_verify.verify_job(db, job_id)
        assert verdict["status"] == "verified", verdict

        log = AuditLog.__table__
        conn.execute(log.update().where(log.c.chain_seq == 3).values(details={"x": 1}))
        verdict = await ledger_verify.verify_job(db, job_id)
        assert verdict["status"] == "verified", "a break in another job's row does not touch it"

        table = EvidenceEntry.__table__
        conn.execute(table.update().where(table.c.seq == 2).values(output="edited in place"))
        verdict = await ledger_verify.verify_job(db, job_id)
        assert (verdict["status"], verdict["first_broken_seq"]) == ("broken", 2)

        conn.execute(table.update().where(table.c.seq == 2).values(output="x"))
        conn.execute(log.update().where(log.c.chain_seq == 2).values(details={"seal": {}}))
        verdict = await ledger_verify.verify_job(db, job_id)
        assert verdict["status"] == "broken"
        assert "this job's ledger.seal audit row" in verdict["reason"]
        assert " 2 " not in verdict["reason"]

        conn.execute(log.delete().where(log.c.chain_seq == 2))
        verdict = await ledger_verify.verify_job(db, job_id)
        assert verdict["status"] == "broken"
        assert "the row was removed" in verdict["reason"]

"""A job's stored ledger is verified against its seal, and says what it found.

The chain is recomputed from the rows. A sealed job reads as tampered when a
row changed, a row was deleted or added, a digest is NULL, the count changed,
the chain was recomputed without the key, a copy of the seal is missing or
disagrees, or the report changed after the seal with no amendment; the first
broken ``seq`` is named where a row is to blame. A seal made under a key the
platform cannot derive is reported as such, not as tampering. A run stored
before sealing reads as not sealed, and so does a job that stored nothing.
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

from app.services import ledger_chain, ledger_verify
from app.services.audit_chain import AuditChainCheck
from app.worker.analysis_worker import _evidence_row
from maljan.schemas.evidence import LedgerEntry

KEY = ledger_chain.derive_key("verify-test-material")
OTHER = ledger_chain.derive_key("verify-test-rotated-material")
KEYS = {KEY.key_id: KEY}
NOW = datetime(2026, 10, 18, 9, 0, tzinfo=UTC)


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
    payload: dict[str, Any] = {"verdict": "Malicious", "network": {"domains": []}}
    summary: dict[str, Any] = {"evidence": {"entries": count}}
    stix = {"type": "bundle", "objects": []}
    seal = ledger_chain.seal(
        job_id,
        rows,
        head,
        report_sha256=ledger_chain.report_digest(payload, summary, stix),
        sealed_at=NOW,
        key=key,
    )
    return {
        "job_id": job_id,
        "rows": [
            ledger_chain.entry_fields(r) | {"digest": r.digest, "chain": r.chain} for r in rows
        ],
        "report_seal": seal,
        "malware_report": ledger_chain.with_seal(payload, seal),
        "run_summary": ledger_chain.with_seal(summary, seal),
        "stix_bundle": stix,
        "audit_seals": [seal],
        "audit_amendments": [],
    }


def _verify(job: dict[str, Any], keys: dict[str, Any] = KEYS, **changes: Any) -> dict[str, Any]:
    given = {**job, **changes}
    return ledger_verify.verify_ledger(
        given["job_id"],
        given["rows"],
        report_seal=given["report_seal"],
        malware_report=given["malware_report"],
        run_summary=given["run_summary"],
        stix_bundle=given["stix_bundle"],
        report_stored=True,
        audit_seals=given["audit_seals"],
        audit_amendments=given["audit_amendments"],
        audit_check=given.get("audit_check"),
        keys=keys,
    )


def test_an_untouched_sealed_ledger_verifies():
    job = _sealed()
    verdict = _verify(job)
    assert verdict["status"] == "verified", verdict
    assert verdict["head"] == job["report_seal"]["head"]
    assert verdict["first_broken_seq"] is None
    assert verdict["checks"]


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
    seal = dict(forged["report_seal"], job_id=str(job["job_id"]), key_id=KEY.key_id)
    for copy in ("report_seal",):
        job[copy] = seal
    job["malware_report"] = ledger_chain.with_seal(job["malware_report"], seal)
    job["run_summary"] = ledger_chain.with_seal(job["run_summary"], seal)
    job["audit_seals"] = [seal]
    verdict = _verify(job)
    assert verdict["status"] == "broken"
    assert "does not verify under its key" in verdict["reason"]


def test_a_deleted_row_is_tampering_at_the_next_seq():
    job = _sealed()
    del job["rows"][1]
    verdict = _verify(job)
    assert (verdict["status"], verdict["first_broken_seq"]) == ("broken", 3)


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
    assert _verify(job, report_seal=None)["status"] == "broken"
    other = dict(job["report_seal"], entries=3)
    assert "disagree" in _verify(job, report_seal=other)["reason"]
    assert _verify(job, audit_seals=[])["reason"].startswith("No ledger.seal row")


def test_rows_with_digests_and_no_seal_anywhere_are_tampering():
    job = _sealed()
    verdict = _verify(
        job,
        report_seal=None,
        malware_report={"verdict": "x"},
        run_summary={},
        audit_seals=[],
    )
    assert (verdict["status"], verdict["first_broken_seq"]) == ("broken", 1)


def test_a_rotated_key_is_reported_as_such():
    job = _sealed()
    verdict = _verify(job, keys={OTHER.key_id: OTHER})
    assert verdict["status"] == "other_key"
    assert KEY.key_id in verdict["reason"]
    job["rows"][0]["output"] = "changed under a rotated key"
    assert _verify(job, keys={OTHER.key_id: OTHER})["status"] == "broken"


def test_an_unkeyed_seal_on_a_keyed_platform_is_not_verified():
    job = _sealed(key=ledger_chain.UNKEYED)
    assert _verify(job)["status"] == "other_key"
    unkeyed = _verify(job, keys={"": ledger_chain.UNKEYED})
    assert unkeyed["status"] == "verified"
    assert any("without a key" in note for note in unkeyed["notes"])


def test_a_report_changed_without_an_amendment_is_tampering_and_with_one_verifies():
    job = _sealed()
    changed = dict(job["malware_report"], verdict="Benign")
    verdict = _verify(job, malware_report=changed)
    assert verdict["status"] == "broken"
    assert "no amendment" in verdict["reason"]

    payload, summary, record = ledger_chain.amend(
        job["malware_report"],
        job["run_summary"],
        dict(changed),
        None,
        job["stix_bundle"],
        seal_record=job["report_seal"],
        kind="enrichment",
        key=KEY,
        at=NOW,
    )
    assert record is not None
    amended = _verify(job, malware_report=payload, run_summary=summary, audit_amendments=[record])
    assert amended["status"] == "verified", amended
    assert amended["amendments"] == 1
    assert _verify(job, malware_report=payload, run_summary=summary)["status"] == "broken"


def test_a_broken_audit_chain_is_tampering():
    job = _sealed()
    check = AuditChainCheck(rows=3, broken_at=2, reason="chained audit row 2 is missing")
    verdict = _verify(job, audit_check=check)
    assert verdict["status"] == "broken"
    assert "chained row 2" in verdict["reason"]


def test_an_old_job_predates_sealing_and_an_empty_one_stored_nothing():
    job = _sealed()
    old_rows = [{k: v for k, v in r.items() if k not in ("digest", "chain")} for r in job["rows"]]
    verdict = ledger_verify.verify_ledger(
        job["job_id"],
        old_rows,
        malware_report={"verdict": "x"},
        run_summary={},
        report_stored=True,
        keys=KEYS,
    )
    assert (verdict["status"], verdict["reason"]) == ("not_sealed", ledger_verify.PREDATES)
    empty = ledger_verify.verify_ledger(uuid.uuid4(), [], keys=KEYS)
    assert (empty["status"], empty["reason"]) == ("not_sealed", ledger_verify.NOTHING_STORED)


def _write_run(job: dict[str, Any], into: Path) -> None:
    into.mkdir()
    (into / "evidence.json").write_text(
        json.dumps({"total": len(job["rows"]), "items": job["rows"]}), encoding="utf-8"
    )
    (into / "report.json").write_text(json.dumps(job["malware_report"]), encoding="utf-8")
    (into / "run-summary.json").write_text(json.dumps(job["run_summary"]), encoding="utf-8")
    (into / "stix-bundle.json").write_text(json.dumps(job["stix_bundle"]), encoding="utf-8")
    (into / "report-byjob.json").write_text(
        json.dumps({"job_id": str(job["job_id"]), "ledger_seal": job["report_seal"]}),
        encoding="utf-8",
    )


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


def _benchmark() -> Path | None:
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / ".superpowers/sdd/mandate-2026-09-17/benchmark/deepseek"
        if candidate.is_dir():
            return candidate
    main = Path("/home/user/Belgeler/kingston/Projects/Maljan/.superpowers/sdd/mandate-2026-09-17")
    candidate = main / "benchmark/deepseek"
    return candidate if candidate.is_dir() else None


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
    assert served.seal == job["report_seal"]
    assert KEY.key.hex() not in json.dumps(served.model_dump())


class _AsyncConnection:
    """The one call ``verify_job`` makes, answered by a synchronous SQLite connection."""

    def __init__(self, conn: Any) -> None:
        self._conn = conn

    async def execute(self, statement: Any) -> Any:
        return self._conn.execute(statement)


@pytest.mark.asyncio
async def test_the_job_is_read_from_the_database_and_verified(monkeypatch: Any):
    import sqlalchemy as sa
    from sqlalchemy.dialects import postgresql
    from sqlalchemy.ext.compiler import compiles

    from app.models.audit import AuditChainHead, AuditLog
    from app.models.evidence import EvidenceEntry
    from app.models.report import AnalysisReport
    from app.services import audit_chain

    @compiles(postgresql.JSONB, "sqlite")
    def _json(element, compiler, **kw):  # noqa: ANN001, ANN202
        return "JSON"

    @compiles(postgresql.INET, "sqlite")
    def _inet(element, compiler, **kw):  # noqa: ANN001, ANN202
        return "TEXT"

    monkeypatch.setattr(ledger_chain, "known_keys", lambda: KEYS)
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
    payload: dict[str, Any] = {"verdict": "Malicious"}
    summary: dict[str, Any] = {"evidence": {}}
    seal = ledger_chain.seal(
        job_id,
        rows,
        head,
        report_sha256=ledger_chain.report_digest(payload, summary, None),
        sealed_at=NOW,
        key=KEY,
    )
    audit: dict[str, Any] = {
        "id": uuid.uuid4(),
        "user_id": None,
        "action": audit_chain.LEDGER_SEAL,
        "resource_type": "job",
        "resource_id": str(job_id),
        "details": {"seal": seal},
        "ip_address": None,
        "created_at": NOW,
        "chain_seq": 1,
        "chain_key_id": KEY.key_id,
    }
    audit["digest"] = audit_chain.audit_digest(audit)
    audit["chain"] = audit_chain.audit_link(audit_chain.audit_genesis(KEY), audit["digest"], KEY)

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
                id=uuid.uuid4(),
                job_id=job_id,
                verdict="Malicious",
                malware_report=ledger_chain.with_seal(payload, seal),
                run_summary=ledger_chain.with_seal(summary, seal),
                stix_bundle=None,
                ledger_seal=seal,
                created_at=NOW,
                updated_at=NOW,
            )
        )
        conn.execute(AuditLog.__table__.insert().values(**audit))
        conn.execute(
            AuditChainHead.__table__.insert().values(
                name=audit_chain.HEAD_NAME,
                chain_seq=1,
                chain=audit["chain"],
                key_id=KEY.key_id,
                mac=audit_chain.head_mac(1, audit["chain"], KEY),
            )
        )
        db = _AsyncConnection(conn)
        verdict = await ledger_verify.verify_job(db, job_id)
        assert verdict["status"] == "verified", verdict

        table = EvidenceEntry.__table__
        conn.execute(table.update().where(table.c.seq == 2).values(output="edited in place"))
        verdict = await ledger_verify.verify_job(db, job_id)
        assert (verdict["status"], verdict["first_broken_seq"]) == ("broken", 2)

        conn.execute(table.delete().where(table.c.seq == 2))
        verdict = await ledger_verify.verify_job(db, job_id)
        assert (verdict["status"], verdict["first_broken_seq"]) == ("broken", 3)

        conn.execute(AuditLog.__table__.delete())
        verdict = await ledger_verify.verify_job(db, job_id)
        assert verdict["status"] == "broken"
        assert "audit chain" in verdict["reason"]

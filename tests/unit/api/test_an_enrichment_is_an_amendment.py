"""An enrichment that changes a sealed report is recorded as an amendment chained onto the seal.

``write_under_lock`` is the one place an enrichment writes a stored report.
Over a report whose ledger is sealed, a change to its documents appends an
amendment to the payload and the run summary (the report digest before and
after, chained onto the seal or the last amendment, keyed) and writes a
chained ``report.amend`` audit row in the same transaction. A change that
leaves the documents as they were records nothing, and a report stored before
sealing existed is written exactly as before. No ledger row is touched.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest

from app.models.report import AnalysisReport
from app.services import audit_chain, ledger_chain
from app.worker.enrich_worker import write_under_lock

KEY = ledger_chain.derive_key("amend-test-material")
NOW = datetime(2026, 10, 18, 9, 0, tzinfo=UTC)


class _Session:
    def __init__(self, report: AnalysisReport) -> None:
        self.report = report
        self.commits = 0
        self.added: list[Any] = []

    async def get(self, *args: Any, **kwargs: Any) -> AnalysisReport:
        return self.report

    async def flush(self) -> None:
        return None

    async def commit(self) -> None:
        self.commits += 1

    async def __aenter__(self) -> _Session:
        return self

    async def __aexit__(self, *exc: Any) -> bool:
        return False


def _sealed_report() -> AnalysisReport:
    payload = {"network": {"domains": [{"fqdn": "example.test"}]}, "verdict": "Malicious"}
    summary = {"evidence": {"entries": 1}}
    stix = {"type": "bundle", "objects": []}
    job_id = uuid.uuid4()
    seal = ledger_chain.seal(
        job_id,
        [],
        ledger_chain.genesis(job_id, KEY),
        report_sha256=ledger_chain.report_digest(payload, summary, stix),
        sealed_at=NOW,
        key=KEY,
    )
    report = AnalysisReport(job_id=job_id, stix_bundle=stix, ledger_seal=seal)
    report.malware_report = ledger_chain.with_seal(payload, seal)
    report.run_summary = ledger_chain.with_seal(summary, seal)
    return report


def _enriched(stored: dict[str, Any], column: Any) -> tuple[dict[str, Any], Any]:
    out = dict(stored)
    out["network"] = {"domains": [{"fqdn": "example.test", "reputation": {"malicious": 3}}]}
    return out, None


@pytest.fixture
def appended(monkeypatch: Any) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []

    async def _append(db: Any, **kwargs: Any) -> None:
        calls.append(kwargs)

    monkeypatch.setattr(audit_chain, "append", _append)
    monkeypatch.setattr(ledger_chain, "platform_key", lambda: KEY)
    return calls


@pytest.mark.asyncio
async def test_a_change_to_a_sealed_report_is_an_amendment_chained_onto_the_seal(appended):
    report = _sealed_report()
    seal = report.ledger_seal
    db = _Session(report)
    assert await write_under_lock(lambda: db, uuid.uuid4(), _enriched)

    [record] = report.malware_report[ledger_chain.AMENDMENTS_KEY]
    assert report.run_summary[ledger_chain.AMENDMENTS_KEY] == [record]
    assert report.malware_report[ledger_chain.SEAL_KEY] == seal, "the seal is never rewritten"
    assert record["number"] == 1
    assert record["kind"] == "enrichment"
    assert record["prev"] == seal["digest"]
    assert record["report_sha256_before"] == seal["report_sha256"]
    assert record["report_sha256_after"] == ledger_chain.report_digest(
        report.malware_report, report.run_summary, report.stix_bundle
    )
    assert record["key_id"] == KEY.key_id
    assert record["digest"] == ledger_chain.record_digest(record, KEY)
    [call] = appended
    assert call["action"] == audit_chain.REPORT_AMEND
    assert call["details"]["amendment"] == record
    assert call["resource_id"] == str(report.job_id)
    assert db.commits == 1


@pytest.mark.asyncio
async def test_a_second_change_chains_onto_the_first_amendment(appended):
    report = _sealed_report()
    db = _Session(report)
    await write_under_lock(lambda: db, uuid.uuid4(), _enriched, kind="enrichment_started")

    def _more(stored: dict[str, Any], column: Any) -> tuple[dict[str, Any], Any]:
        return {**stored, "attribution": {"similar_samples": ["x"]}}, dict(column)

    await write_under_lock(lambda: db, uuid.uuid4(), _more)
    first, second = report.malware_report[ledger_chain.AMENDMENTS_KEY]
    assert (first["kind"], second["kind"]) == ("enrichment_started", "enrichment")
    assert second["prev"] == first["digest"]
    assert second["report_sha256_before"] == first["report_sha256_after"]
    assert len(appended) == 2


@pytest.mark.asyncio
async def test_a_change_that_changes_nothing_records_nothing(appended):
    report = _sealed_report()
    before = dict(report.malware_report)
    await write_under_lock(lambda: _Session(report), uuid.uuid4(), lambda s, c: (dict(s), None))
    assert report.malware_report == before
    assert ledger_chain.AMENDMENTS_KEY not in report.run_summary
    assert appended == []


@pytest.mark.asyncio
async def test_a_report_stored_before_sealing_is_enriched_as_before(appended):
    report = AnalysisReport(job_id=uuid.uuid4(), stix_bundle=None)
    report.malware_report = {"network": {"domains": [{"fqdn": "example.test"}]}}
    report.run_summary = {"evidence": {}}
    await write_under_lock(lambda: _Session(report), uuid.uuid4(), _enriched)
    assert ledger_chain.AMENDMENTS_KEY not in report.malware_report
    assert report.malware_report["network"]["domains"][0]["reputation"] == {"malicious": 3}
    assert report.run_summary == {"evidence": {}}
    assert appended == []

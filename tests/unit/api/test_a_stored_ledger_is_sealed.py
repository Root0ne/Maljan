"""A stored ledger is sealed: its chain head lands in the report row, payload and run summary.

The seal records the chain head, what it covers, the id of the key the chain
was computed under, the digest of every column of the stored report row and its
own keyed digest. It is written in the transaction that stores the ledger. A
platform with no settings key seals nothing and the warning names why; the key
itself is never in the seal, its repr or the log. The downgrade takes the seals
out of the reports it wrote them into. A report with a seal prints one
line under Appendix A; one without prints nothing new.
"""

from __future__ import annotations

import importlib.util
import json
import logging
import uuid
from pathlib import Path
from typing import Any

import pytest
import sqlalchemy as sa
from alembic.operations import Operations
from alembic.runtime.migration import MigrationContext
from pydantic import SecretStr
from tests.integration._session_probe import SessionFactory, fake_job, fake_sample, rows_for

from app.models.evidence import EvidenceEntry
from app.services import ledger_chain
from app.worker.analysis_worker import _store_the_report
from maljan.core.config import Settings
from maljan.reporting.models import MalwareReport
from maljan.reporting.renderers.markdown import MarkdownRenderer
from maljan.schemas.evidence import LedgerEntry

KEY = ledger_chain.derive_key("seal-test-material")
_REV = (
    Path(__file__).resolve().parents[3]
    / "apps/api/alembic/versions/20261021000000_report_carries_its_ledger_seal.py"
)


def _entry(seq: int) -> dict[str, Any]:
    return LedgerEntry(
        id=f"ev_{seq:04d}", tool="pe_info", seq=seq, output="{}", started_at=1.7e9 + seq
    ).model_dump(mode="json")


async def _store(state: dict[str, Any], run_summary: dict[str, Any], stix: Any) -> tuple:
    job = fake_job()
    factory = SessionFactory(rows_for(job, fake_sample(job.sample_id)))
    async with factory() as db:
        report = await _store_the_report(
            db,
            job_uuid=job.id,
            job_id=str(job.id),
            pipeline_result=state,
            stix_bundle=stix,
            run_summary=run_summary,
            transcript=[],
            core_settings=Settings(_env_file=None),
        )
    rows = [o for s in factory.sessions for o in s.added if isinstance(o, EvidenceEntry)]
    return job, report, rows


@pytest.mark.asyncio
async def test_the_seal_is_written_into_the_row_the_payload_and_the_summary(monkeypatch: Any):
    monkeypatch.setattr(ledger_chain, "platform_key_status", lambda: (KEY, None))
    payload = {"verdict": "Malicious", "score": 1.0}
    job, report, rows = await _store(
        {"evidence_ledger": [_entry(1), _entry(2)], "malware_report": payload},
        {"evidence": {"entries": 2}},
        {"type": "bundle", "objects": []},
    )
    seal = report.ledger_seal
    assert report.malware_report[ledger_chain.SEAL_KEY] == seal
    assert report.run_summary[ledger_chain.SEAL_KEY] == seal
    assert ledger_chain.SEAL_KEY not in payload, "the run's own state is not changed"
    assert seal["job_id"] == str(job.id)
    assert (seal["entries"], seal["first_seq"], seal["last_seq"]) == (2, 1, 2)
    assert seal["head"] == rows[-1].chain
    assert seal["key_id"] == KEY.key_id
    assert seal["report_sha256"] == ledger_chain.report_digest(report)
    assert seal["digest"] == ledger_chain.record_digest(seal, KEY)
    assert seal["digest"] != ledger_chain.record_digest(seal, ledger_chain.derive_key("other"))


@pytest.mark.asyncio
async def test_the_seal_covers_every_column_of_the_report_row(monkeypatch: Any):
    monkeypatch.setattr(ledger_chain, "platform_key_status", lambda: (KEY, None))
    _, report, _ = await _store({"evidence_ledger": [_entry(1)], "malware_report": {}}, {}, None)
    sealed = report.ledger_seal["report_sha256"]
    report.verdict = "Benign"
    assert ledger_chain.report_digest(report) != sealed


@pytest.mark.asyncio
async def test_a_run_with_no_report_payload_is_sealed_in_the_summary_and_the_row(
    monkeypatch: Any,
):
    monkeypatch.setattr(ledger_chain, "platform_key_status", lambda: (KEY, None))
    _, report, rows = await _store({"evidence_ledger": [], "malware_report": None}, {}, None)
    assert rows == []
    assert report.malware_report is None
    assert report.ledger_seal["entries"] == 0
    assert report.ledger_seal["head"] == ledger_chain.genesis(report.job_id, KEY)
    assert report.run_summary[ledger_chain.SEAL_KEY] == report.ledger_seal


@pytest.mark.asyncio
async def test_without_a_settings_key_nothing_is_sealed_and_the_warning_names_why(
    monkeypatch: Any, caplog: Any
):
    monkeypatch.setattr(
        ledger_chain, "platform_key_status", lambda: (None, "SETTINGS_ENCRYPTION_KEY is not set")
    )
    with caplog.at_level(logging.WARNING):
        _, report, rows = await _store({"evidence_ledger": [_entry(1)]}, {}, None)
    assert report.ledger_seal is None
    assert ledger_chain.SEAL_KEY not in (report.run_summary or {})
    assert [r.digest for r in rows] == [None]
    assert any(
        "is not sealed: SETTINGS_ENCRYPTION_KEY is not set" in r.getMessage()
        for r in caplog.records
    )


def test_the_platform_key_is_derived_from_the_settings_key_and_never_shown(monkeypatch: Any):
    from app.config import settings

    material = "-".join(["derived", "from", "the", "settings", "key"])
    monkeypatch.setattr(settings, "settings_encryption_key", SecretStr(material))
    key = ledger_chain.platform_key()
    assert key == ledger_chain.derive_key(material)
    assert key is not None and len(key.key_id) == ledger_chain.KEY_ID_LENGTH
    assert key.key.hex() not in repr(key)
    assert material.encode() != key.key, "derived, never the secret itself"
    monkeypatch.setattr(settings, "settings_encryption_key", SecretStr(""))
    monkeypatch.delenv("SETTINGS_ENCRYPTION_KEY", raising=False)
    assert ledger_chain.platform_key_status() == (None, "SETTINGS_ENCRYPTION_KEY is not set")
    assert ledger_chain.known_keys() == {}


def test_an_unreadable_settings_module_is_named_and_nothing_else_is_swallowed(monkeypatch: Any):
    import builtins

    real_import = builtins.__import__

    def _refuse(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "app.config":
            raise ImportError("no app on the path")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _refuse)
    monkeypatch.delenv("SETTINGS_ENCRYPTION_KEY", raising=False)
    key, reason = ledger_chain.platform_key_status()
    assert key is None
    assert reason is not None and "could not be read (ImportError)" in reason

    def _break(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "app.config":
            raise RuntimeError("a defect, not a missing module")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _break)
    with pytest.raises(RuntimeError):
        ledger_chain.platform_key_status()


def _sealed_report() -> MalwareReport:
    report = MalwareReport.model_validate({"identity": {"hashes": {"sha256": "a" * 64}}})
    report.ledger_seal = {
        "head": "b" * 64,
        "entries": 3,
        "first_seq": 1,
        "last_seq": 3,
        "key_id": "0123456789abcdef",
        "digest": "c" * 64,
    }
    return report


def test_a_sealed_report_prints_its_seal_under_appendix_a():
    markdown = MarkdownRenderer().render(_sealed_report())
    assert f"chain head `{'b' * 64}` over 3 entries (seq 1 to 3), key `0123456789abcdef`" in (
        markdown
    )


def test_a_report_without_a_seal_prints_no_seal_and_dumps_none():
    report = MalwareReport.model_validate({"identity": {"hashes": {"sha256": "a" * 64}}})
    assert "Ledger seal" not in MarkdownRenderer().render(report)
    dump = report.model_dump(mode="json")
    assert ledger_chain.SEAL_KEY not in dump
    assert ledger_chain.AMENDMENTS_KEY not in dump


def _load():
    spec = importlib.util.spec_from_file_location("report_carries_its_ledger_seal", _REV)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_revision_follows_the_chain_one():
    mod = _load()
    assert (mod.revision, mod.down_revision) == ("20261021000000", "20261020000000")


def test_an_older_report_holds_no_seal_and_the_downgrade_takes_the_seals_out():
    engine = sa.create_engine("sqlite://")
    with engine.connect() as conn:
        conn.execute(
            sa.text(
                "CREATE TABLE analysis_reports "
                "(id TEXT PRIMARY KEY, malware_report JSON, run_summary JSON)"
            )
        )
        conn.execute(sa.text("INSERT INTO analysis_reports (id) VALUES ('old')"))
        mod = _load()
        with Operations.context(MigrationContext.configure(conn)):
            mod.upgrade()
            assert (
                conn.execute(sa.text("SELECT ledger_seal FROM analysis_reports")).scalar() is None
            )
            sealed = json.dumps({"verdict": "x", "ledger_seal": {"d": 1}, "ledger_amendments": []})
            summary = json.dumps({"evidence": {}, "ledger_seal": {"d": 1}})
            conn.execute(
                sa.text(
                    "INSERT INTO analysis_reports (id, malware_report, run_summary, ledger_seal) "
                    "VALUES ('new', :payload, :summary, '{}')"
                ),
                {"payload": sealed, "summary": summary},
            )
            mod.downgrade()
        columns = {c["name"] for c in sa.inspect(conn).get_columns("analysis_reports")}
        assert "ledger_seal" not in columns
        payload, summary = conn.execute(
            sa.text("SELECT malware_report, run_summary FROM analysis_reports WHERE id = 'new'")
        ).one()
        assert json.loads(payload) == {"verdict": "x"}
        assert json.loads(summary) == {"evidence": {}}


def test_the_job_id_is_bound_into_the_seal():
    one, other = uuid.uuid4(), uuid.uuid4()
    assert ledger_chain.genesis(one, KEY) != ledger_chain.genesis(other, KEY)

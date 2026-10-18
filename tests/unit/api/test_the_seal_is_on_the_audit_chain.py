"""The ledger's seal is written onto the audit chain, in the transaction that stores it.

A chained audit row takes the next ``chain_seq``, a digest of its columns and a
keyed chain value linking it to the chained row before it. Recomputing the
chain finds a changed row, a missing row and a row chained by someone without
the key; a row chained under another key is said to be so, not called changed.
A failed append is counted and logged and never raises into the store.
"""

from __future__ import annotations

import importlib.util
import uuid
from pathlib import Path
from typing import Any

import pytest
import sqlalchemy as sa
from alembic.operations import Operations
from alembic.runtime.migration import MigrationContext
from tests.integration._session_probe import SessionFactory, fake_job, fake_sample, rows_for

from app import observability
from app.models.audit import AuditLog
from app.services import audit_chain, ledger_chain
from app.worker.analysis_worker import _store_the_report
from maljan.core.config import Settings
from maljan.schemas.evidence import LedgerEntry

KEY = ledger_chain.derive_key("audit-test-material")
OTHER = ledger_chain.derive_key("audit-test-other-material")
_REV = (
    Path(__file__).resolve().parents[3]
    / "apps/api/alembic/versions/20261022000000_audit_log_carries_a_chain.py"
)


class _Nested:
    async def __aenter__(self) -> None:
        return None

    async def __aexit__(self, *exc: Any) -> bool:
        return False


class _Result:
    def __init__(self, row: Any) -> None:
        self._row = row

    def first(self) -> Any:
        return self._row


class _ChainSession:
    """Holds the chained audit rows it is handed and answers the last one."""

    def __init__(self, fail: bool = False) -> None:
        self.rows: list[AuditLog] = []
        self.fail = fail

    def begin_nested(self) -> _Nested:
        return _Nested()

    def get_bind(self) -> Any:
        raise RuntimeError("no bind in the unit environment")

    async def execute(self, statement: Any, *args: Any) -> _Result:
        if self.fail:
            raise RuntimeError("the database went away")
        if not self.rows:
            return _Result(None)
        last = max(self.rows, key=lambda r: r.chain_seq)
        return _Result((last.chain_seq, last.chain))

    def add(self, row: AuditLog) -> None:
        self.rows.append(row)

    async def flush(self) -> None:
        return None


async def _chain(count: int, key: ledger_chain.ChainKey = KEY) -> _ChainSession:
    db = _ChainSession()
    for index in range(count):
        await audit_chain.append(
            db,
            action=audit_chain.LEDGER_SEAL,
            resource_type="job",
            resource_id=str(uuid.uuid4()),
            details={"seal": {"head": f"{index:064d}"}},
            key=key,
        )
    return db


@pytest.mark.asyncio
async def test_chained_rows_follow_one_another_and_verify():
    db = await _chain(3)
    assert [r.chain_seq for r in db.rows] == [1, 2, 3]
    assert all(r.chain_key_id == KEY.key_id for r in db.rows)
    check = audit_chain.verify_audit_chain(db.rows, KEY)
    assert (check.rows, check.broken_at, check.other_key_rows) == (3, None, [])


@pytest.mark.asyncio
async def test_a_changed_row_is_found():
    db = await _chain(3)
    db.rows[1].details = {"seal": {"head": "f" * 64}}
    check = audit_chain.verify_audit_chain(db.rows, KEY)
    assert check.broken_at == 2
    assert "differs from its digest" in (check.reason or "")


@pytest.mark.asyncio
async def test_a_deleted_row_is_found():
    db = await _chain(3)
    del db.rows[1]
    check = audit_chain.verify_audit_chain(db.rows, KEY)
    assert check.broken_at == 2
    assert "missing" in (check.reason or "")


@pytest.mark.asyncio
async def test_a_row_rechained_without_the_key_is_found():
    db = await _chain(3)
    forged = db.rows[1]
    forged.details = {"seal": {"head": "e" * 64}}
    forged.digest = audit_chain.audit_digest(forged)
    forged.chain = audit_chain.audit_link(db.rows[0].chain, forged.digest, ledger_chain.UNKEYED)
    check = audit_chain.verify_audit_chain(db.rows, KEY)
    assert check.broken_at == 2
    assert "does not link" in (check.reason or "")


@pytest.mark.asyncio
async def test_rows_chained_under_another_key_are_said_to_be_so():
    db = await _chain(2, key=OTHER)
    check = audit_chain.verify_audit_chain(db.rows, KEY)
    assert check.broken_at is None
    assert check.other_key_rows == [1, 2]


@pytest.mark.asyncio
async def test_a_failed_append_is_counted_and_never_raises():
    before = observability.counters.audit_write_failures
    row = await audit_chain.append(
        _ChainSession(fail=True),
        action=audit_chain.LEDGER_SEAL,
        resource_type="job",
        resource_id="j",
        details={},
        key=KEY,
    )
    assert row is None
    assert observability.counters.audit_write_failures == before + 1


@pytest.mark.asyncio
async def test_the_store_puts_the_seal_on_the_chain_in_its_own_transaction(monkeypatch: Any):
    monkeypatch.setattr(ledger_chain, "platform_key", lambda: KEY)
    appended: list[dict[str, Any]] = []

    async def _append(db: Any, **kwargs: Any) -> None:
        appended.append({"db": db, **kwargs})

    monkeypatch.setattr(audit_chain, "append", _append)
    job = fake_job()
    factory = SessionFactory(rows_for(job, fake_sample(job.sample_id)))
    entry = LedgerEntry(id="ev_0001", tool="pe_info", seq=1, started_at=1.7e9)
    async with factory() as db:
        report = await _store_the_report(
            db,
            job_uuid=job.id,
            job_id=str(job.id),
            pipeline_result={"evidence_ledger": [entry.model_dump(mode="json")]},
            stix_bundle=None,
            run_summary={},
            transcript=[],
            core_settings=Settings(_env_file=None),
        )
    [call] = appended
    assert call["db"] is db
    assert call["action"] == audit_chain.LEDGER_SEAL
    assert call["resource_id"] == str(job.id)
    assert call["details"]["seal"] == report.ledger_seal
    assert call["key"] is KEY


def _load():
    spec = importlib.util.spec_from_file_location("audit_log_carries_a_chain", _REV)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_revision_follows_the_report_seal_one():
    mod = _load()
    assert (mod.revision, mod.down_revision) == ("20261022000000", "20261021000000")


def test_older_rows_hold_no_chain_the_seq_is_unique_and_the_downgrade_takes_it_back():
    engine = sa.create_engine("sqlite://")
    with engine.connect() as conn:
        conn.execute(sa.text("CREATE TABLE audit_log (id TEXT PRIMARY KEY, action TEXT)"))
        conn.execute(sa.text("INSERT INTO audit_log (id, action) VALUES ('a', 'auth.login')"))
        conn.execute(sa.text("INSERT INTO audit_log (id, action) VALUES ('b', 'auth.login')"))
        mod = _load()
        with Operations.context(MigrationContext.configure(conn)):
            mod.upgrade()
            rows = conn.execute(sa.text("SELECT chain_seq, digest, chain FROM audit_log")).all()
            assert {tuple(r) for r in rows} == {(None, None, None)}
            conn.execute(sa.text("UPDATE audit_log SET chain_seq = 1 WHERE id = 'a'"))
            with pytest.raises(sa.exc.IntegrityError):
                conn.execute(sa.text("UPDATE audit_log SET chain_seq = 1 WHERE id = 'b'"))
            mod.downgrade()
        columns = {c["name"] for c in sa.inspect(conn).get_columns("audit_log")}
        assert not {"chain_seq", "digest", "chain", "chain_key_id"} & columns

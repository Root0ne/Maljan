"""The ledger's seal is written onto the audit chain, in the transaction that stores it.

A chained audit row takes the next ``chain_seq``, a digest of its columns and a
keyed chain value linking it to the chained row before it. Recomputing the
chain finds a changed row, a missing row, a tail cut off the end (the keyed
head record points past it) and a row chained by someone without the key. A
row is checked under the key its id names, looked up among the keys the
platform can derive: a relabelled or unknown key id is a break, never a skip.
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
from app.models.audit import AuditChainHead, AuditLog
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
    """Holds the chained audit rows and the head it is handed and answers the last row."""

    def __init__(self, fail: bool = False) -> None:
        self.rows: list[AuditLog] = []
        self.head: AuditChainHead | None = None
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

    async def get(self, model: Any, name: str) -> Any:
        return self.head

    def add(self, row: Any) -> None:
        if isinstance(row, AuditChainHead):
            self.head = row
        else:
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


def _verify(db: _ChainSession) -> audit_chain.AuditChainCheck:
    return audit_chain.verify_audit_chain(db.rows, {KEY.key_id: KEY}, db.head)


@pytest.mark.asyncio
async def test_chained_rows_follow_one_another_and_verify_to_the_head():
    db = await _chain(3)
    assert [r.chain_seq for r in db.rows] == [1, 2, 3]
    assert all(r.chain_key_id == KEY.key_id for r in db.rows)
    assert db.head is not None and db.head.chain_seq == 3 and db.head.chain == db.rows[-1].chain
    check = _verify(db)
    assert (check.rows, check.broken_at, check.head_seq) == (3, None, 3)


@pytest.mark.asyncio
async def test_a_changed_row_is_found():
    db = await _chain(3)
    db.rows[1].details = {"seal": {"head": "f" * 64}}
    check = _verify(db)
    assert check.broken_at == 2
    assert "differs from its digest" in (check.reason or "")


@pytest.mark.asyncio
async def test_a_deleted_row_is_found():
    db = await _chain(3)
    del db.rows[1]
    check = _verify(db)
    assert check.broken_at == 2
    assert "missing" in (check.reason or "")


@pytest.mark.asyncio
async def test_a_tail_cut_off_the_end_is_found():
    db = await _chain(3)
    del db.rows[2]
    check = _verify(db)
    assert check.broken_at == 3
    assert "cut off the end" in (check.reason or "")


@pytest.mark.asyncio
async def test_a_tail_cut_with_a_head_moved_back_without_the_key_is_found():
    db = await _chain(3)
    del db.rows[2]
    assert db.head is not None
    db.head.chain_seq = 2
    db.head.chain = db.rows[1].chain
    db.head.mac = audit_chain.head_mac(2, db.rows[1].chain, ledger_chain.UNKEYED)
    check = _verify(db)
    assert check.broken_at == 3
    assert "head record does not verify" in (check.reason or "")


@pytest.mark.asyncio
async def test_rows_with_no_head_record_are_a_break():
    db = await _chain(2)
    db.head = None
    assert _verify(db).broken_at == 2


@pytest.mark.asyncio
async def test_a_row_rechained_without_the_key_is_found():
    db = await _chain(3)
    forged = db.rows[1]
    forged.details = {"seal": {"head": "e" * 64}}
    forged.digest = audit_chain.audit_digest(forged)
    forged.chain = audit_chain.audit_link(db.rows[0].chain, forged.digest, ledger_chain.UNKEYED)
    check = _verify(db)
    assert check.broken_at == 2
    assert "does not link" in (check.reason or "")


@pytest.mark.asyncio
async def test_a_relabelled_key_id_is_a_break_not_a_skip():
    db = await _chain(3)
    forged = db.rows[1]
    forged.details = {"seal": {"head": "d" * 64}}
    forged.chain_key_id = "0000000000000000"
    forged.digest = audit_chain.audit_digest(forged)
    check = _verify(db)
    assert check.broken_at == 2
    assert "cannot derive" in (check.reason or "")


@pytest.mark.asyncio
async def test_a_row_relabelled_as_unkeyed_is_a_break_on_a_keyed_platform():
    db = await _chain(2)
    forged = db.rows[0]
    forged.chain_key_id = None
    forged.digest = audit_chain.audit_digest(forged)
    forged.chain = audit_chain.audit_link(
        audit_chain.audit_genesis(ledger_chain.UNKEYED), forged.digest, ledger_chain.UNKEYED
    )
    assert _verify(db).broken_at == 1


@pytest.mark.asyncio
async def test_rows_chained_under_a_key_the_platform_cannot_derive_are_a_break():
    db = await _chain(2, key=OTHER)
    check = _verify(db)
    assert check.broken_at == 1
    assert OTHER.key_id in (check.reason or "")


@pytest.mark.asyncio
async def test_rows_chained_under_an_older_known_key_verify_under_it():
    db = await _chain(1, key=OTHER)
    for index in range(2):
        await audit_chain.append(
            db,
            action=audit_chain.REPORT_AMEND,
            resource_type="job",
            resource_id=str(index),
            details={},
            key=KEY,
        )
    keys = {KEY.key_id: KEY, OTHER.key_id: OTHER}
    check = audit_chain.verify_audit_chain(db.rows, keys, db.head)
    assert check.broken_at is None
    db.rows[0].details = {"changed": True}
    db.rows[0].digest = audit_chain.audit_digest(db.rows[0])
    assert audit_chain.verify_audit_chain(db.rows, keys, db.head).broken_at == 1


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


def test_the_head_table_is_created_and_dropped():
    path = _REV.with_name("20261023000000_audit_chain_head.py")
    spec = importlib.util.spec_from_file_location("audit_chain_head", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert (mod.revision, mod.down_revision) == ("20261023000000", "20261022000000")
    engine = sa.create_engine("sqlite://")
    with engine.connect() as conn:
        with Operations.context(MigrationContext.configure(conn)):
            mod.upgrade()
            columns = {c["name"] for c in sa.inspect(conn).get_columns("audit_chain_head")}
            assert columns == {"name", "chain_seq", "chain", "key_id", "mac"}
            mod.downgrade()
        assert "audit_chain_head" not in sa.inspect(conn).get_table_names()


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

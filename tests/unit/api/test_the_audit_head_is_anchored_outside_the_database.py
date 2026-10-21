"""The audit chain's head is kept outside the database, and the chain is checked against it.

A chained append anchors the committed head after its transaction commits,
never before. Verification compares the chain with the latest anchored head: a
chain rewritten under the key, or cut back with an earlier head record put
back, verifies against its database head and breaks against the anchor. An
anchor that is down never fails the append or the job: the write is logged and
counted, and verification states that the chain was checked against the
database head only. Without an anchor configured nothing changes but the note
that says so. What protects the anchor is read from its store and stated.
"""

from __future__ import annotations

import asyncio
import importlib.util
import io
import json
import uuid
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import sqlalchemy as sa
from alembic.operations import Operations
from alembic.runtime.migration import MigrationContext
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.pool import StaticPool
from tests.credential_shapes import password

from app import observability
from app.bootstrap import validate_bootstrap
from app.config import APISettings
from app.models.audit import AuditChainAnchor, AuditChainHead, AuditLog
from app.models.evidence import EvidenceEntry
from app.models.report import AnalysisReport
from app.services import audit_anchor, audit_chain, ledger_chain, ledger_verify
from app.services.audit_anchor import AnchoredHead, BucketLock

KEY = ledger_chain.derive_key("anchor-test-material")
KEYS = {KEY.key_id: KEY}
NOW = datetime(2026, 10, 23, 9, 0, tzinfo=UTC)
_REV = (
    Path(__file__).resolve().parents[3]
    / "apps/api/alembic/versions/20261028000000_audit_chain_anchor.py"
)


@compiles(postgresql.JSONB, "sqlite")
def _json(element, compiler, **kw):  # noqa: ANN001, ANN202
    return "JSON"


@compiles(postgresql.INET, "sqlite")
def _inet(element, compiler, **kw):  # noqa: ANN001, ANN202
    return "TEXT"


@pytest.fixture(autouse=True)
def _platform_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ledger_chain, "platform_key_status", lambda: (KEY, None))
    audit_anchor.reset()
    yield
    audit_anchor.reset()


# ---------------------------------------------------------------------------
# Doubles: an async face over synchronous SQLite, and anchors held in memory
# ---------------------------------------------------------------------------


class _Conn:
    """The calls the verification and the anchor make, on a synchronous connection."""

    def __init__(self, conn: Any, engine: Any = None) -> None:
        self._conn = conn
        self.dialect = conn.dialect
        if engine is not None:
            # What an ``AsyncConnection`` names its engine by: a read outside
            # this connection's snapshot goes through it.
            self.engine = engine

    async def execute(self, statement: Any, *args: Any) -> Any:
        return self._conn.execute(statement, *args)


class _Engine:
    """An async engine's ``connect`` and ``begin`` over a synchronous SQLite engine."""

    def __init__(self, engine: Any) -> None:
        self._engine = engine

    @asynccontextmanager
    async def connect(self) -> Any:
        with self._engine.connect() as conn:
            yield _Conn(conn)

    @asynccontextmanager
    async def begin(self) -> Any:
        with self._engine.begin() as conn:
            yield _Conn(conn)


def _sqlite() -> Any:
    return sa.create_engine(
        "sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False}
    )


class _Anchor(audit_anchor.ChainAnchor):
    """Heads kept in memory; ``down`` makes every call fail as an unreachable store."""

    kind = "memory"

    def __init__(self, *, down: bool = False) -> None:
        self.heads: dict[int, AnchoredHead] = {}
        self.down = down

    async def latest(self) -> AnchoredHead | None:
        if self.down:
            raise ConnectionError("the anchor is unreachable")
        return self.heads[max(self.heads)] if self.heads else None

    async def put(self, head: AnchoredHead) -> None:
        if self.down:
            raise ConnectionError("the anchor is unreachable")
        held = self.heads.get(head.chain_seq)
        if held is not None and held.chain != head.chain:
            raise audit_anchor.AnchorConflict("another head at this seq")
        self.heads[head.chain_seq] = head

    async def protection(self) -> str:
        return "held in memory for the test"


# ---------------------------------------------------------------------------
# A chain in SQLite
# ---------------------------------------------------------------------------


def _audit_row(seq: int, previous: str | None, job_id: Any, details: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "id": uuid.uuid4(),
        "user_id": None,
        "action": audit_chain.LEDGER_SEAL,
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


def _chain_rows(details: list[Any], jobs: list[Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for seq, (detail, job) in enumerate(zip(details, jobs, strict=True), start=1):
        rows.append(_audit_row(seq, rows[-1]["chain"] if rows else None, job, detail))
    return rows


def _head(rows: list[dict[str, Any]], upto: int | None = None) -> dict[str, Any]:
    last = rows[(upto or len(rows)) - 1]
    seq = int(last["chain_seq"])
    return {
        "name": audit_chain.HEAD_NAME,
        "chain_seq": seq,
        "chain": last["chain"],
        "key_id": KEY.key_id,
        "rotated_at_seq": 1,
        "mac": audit_chain.head_mac(seq, last["chain"], 1, KEY),
    }


def _write_chain(conn: Any, rows: list[dict[str, Any]], head: dict[str, Any]) -> None:
    log, heads = AuditLog.__table__, AuditChainHead.__table__
    conn.execute(log.delete())
    conn.execute(heads.delete())
    for row in rows:
        conn.execute(log.insert().values(**row))
    conn.execute(heads.insert().values(**head))


def _database(rows: list[dict[str, Any]]) -> Any:
    engine = _sqlite()
    with engine.begin() as conn:
        for model in (EvidenceEntry, AnalysisReport, AuditLog, AuditChainHead):
            model.__table__.create(conn)
        _write_chain(conn, rows, _head(rows))
    return engine


async def _anchored(engine: Any, anchor: audit_anchor.ChainAnchor) -> str:
    with engine.connect() as conn:
        return await audit_anchor.anchor_committed_head(_Conn(conn), anchor)


async def _verdict(engine: Any, anchor: Any) -> audit_anchor.AnchorVerdict:
    with engine.connect() as conn:
        head = conn.execute(sa.select(AuditChainHead.__table__)).mappings().first()
        return await audit_anchor.verification(_Conn(conn), head, anchor)


# ---------------------------------------------------------------------------
# Tamper detection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_chain_rewritten_under_the_key_breaks_against_the_anchor() -> None:
    jobs = [uuid.uuid4() for _ in range(3)]
    rows = _chain_rows([{"seal": {"n": n}} for n in range(3)], jobs)
    engine = _database(rows)
    anchor = _Anchor()
    assert await _anchored(engine, anchor) == audit_anchor.ANCHORED
    assert anchor.heads[3].chain == rows[-1]["chain"]
    assert (await _verdict(engine, anchor)).state == audit_anchor.MATCHES

    # A writer holding the settings key rewrites row 2 and re-chains the rest,
    # head included: the database alone cannot tell.
    rewritten = _chain_rows(
        [{"seal": {"n": 0}}, {"seal": {"n": "forged"}}, {"seal": {"n": 2}}], jobs
    )
    with engine.begin() as conn:
        _write_chain(conn, rewritten, _head(rewritten))
        stored = conn.execute(sa.select(AuditLog.__table__)).mappings().all()
        held = conn.execute(sa.select(AuditChainHead.__table__)).mappings().first()
    assert audit_chain.verify_audit_chain(stored, KEYS, held).broken_at is None

    verdict = await _verdict(engine, anchor)
    assert verdict.state == audit_anchor.BROKEN
    assert "the chain was rewritten" in (verdict.broken or "")
    assert " 3" not in (verdict.broken or ""), "a reason never names a seq"
    # And the rewritten head is never anchored over the true one.
    before = observability.counters.audit_anchor_failures
    assert await _anchored(engine, anchor) == audit_anchor.REFUSED
    assert observability.counters.audit_anchor_failures == before + 1
    assert set(anchor.heads) == {3}


@pytest.mark.asyncio
async def test_a_tail_cut_and_an_earlier_head_put_back_breaks_against_the_anchor() -> None:
    jobs = [uuid.uuid4() for _ in range(3)]
    rows = _chain_rows([{"seal": {"n": n}} for n in range(3)], jobs)
    engine = _database(rows)
    anchor = _Anchor()
    await _anchored(engine, anchor)
    # The writer kept the head record at seq 2: cutting row 3 and putting it
    # back leaves a chain that verifies against the database head.
    with engine.begin() as conn:
        _write_chain(conn, rows[:2], _head(rows, upto=2))
        stored = conn.execute(sa.select(AuditLog.__table__)).mappings().all()
        held = conn.execute(sa.select(AuditChainHead.__table__)).mappings().first()
    assert audit_chain.verify_audit_chain(stored, KEYS, held).broken_at is None

    verdict = await _verdict(engine, anchor)
    assert verdict.state == audit_anchor.BROKEN
    assert "behind the head anchored outside the database" in (verdict.broken or "")
    assert await _anchored(engine, anchor) == audit_anchor.REFUSED


def test_an_anchored_head_forged_without_the_key_is_a_break() -> None:
    rows = _chain_rows([{"n": 0}], [uuid.uuid4()])
    head = _head(rows)
    forged = AnchoredHead.read(head | {"mac": "0" * 64})
    verdict = audit_anchor.compare("memory", forged, head, rows[0]["chain"], KEYS)
    assert verdict.state == audit_anchor.BROKEN
    assert "does not verify under its key" in (verdict.broken or "")


def test_a_missing_anchored_row_and_a_lagging_anchor_are_told_apart() -> None:
    rows = _chain_rows([{"n": n} for n in range(3)], [uuid.uuid4()] * 3)
    anchored = AnchoredHead.read(_head(rows, upto=2))
    missing = audit_anchor.compare("memory", anchored, _head(rows), None, KEYS)
    assert missing.state == audit_anchor.BROKEN
    assert "missing from the database" in (missing.broken or "")
    lags = audit_anchor.compare("memory", anchored, _head(rows), rows[1]["chain"], KEYS)
    assert (lags.state, lags.broken) == (audit_anchor.LAGS, None)
    assert any("past the last head anchored" in n for n in lags.notes)
    assert lags.checks == ["the audit chain holds the head anchored outside the database (memory)"]


@pytest.mark.asyncio
async def test_the_full_walk_breaks_on_a_rewritten_chain_and_names_both_seqs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scripts.ledger import verify as cli

    jobs = [uuid.uuid4() for _ in range(3)]
    rows = _chain_rows([{"n": n} for n in range(3)], jobs)
    engine = _database(rows)
    anchor = _Anchor()
    await _anchored(engine, anchor)
    monkeypatch.setattr(audit_anchor, "configured", lambda: anchor)
    with engine.connect() as conn:
        walked = await cli.walk_audit_chain(_Conn(conn))
    assert walked["status"] == "verified"
    assert walked["anchor"] == {
        "kind": "memory",
        "state": "matches",
        "protection": "held in memory for the test",
        "anchored_seq": 3,
        "head_seq": 3,
    }
    with engine.begin() as conn:
        _write_chain(conn, rows[:2], _head(rows, upto=2))
    with engine.connect() as conn:
        walked = await cli.walk_audit_chain(_Conn(conn))
    assert walked["status"] == "broken"
    assert walked["broken_at"] is None, "the database chain itself still holds"
    assert "does not match its anchor outside the database" in walked["reason"]
    assert (walked["anchor"]["anchored_seq"], walked["anchor"]["head_seq"]) == (3, 2)


# ---------------------------------------------------------------------------
# A job's verification
# ---------------------------------------------------------------------------


def _sealed_job(engine: Any) -> tuple[uuid.UUID, list[dict[str, Any]]]:
    """A job with one ledger row, its sealed report and its seal on a chain of three."""
    from app.worker.analysis_worker import _evidence_row
    from maljan.schemas.evidence import LedgerEntry

    job_id = uuid.uuid4()
    entry = _evidence_row(
        LedgerEntry(id="ev_0001", tool="pe_info", seq=1, output="x").model_dump(mode="json"),
        job_id=job_id,
        written_at=NOW,
    )
    chain_head = ledger_chain.chain_rows(job_id, [entry], KEY)
    report: dict[str, Any] = {
        "id": str(uuid.uuid4()),
        "job_id": str(job_id),
        "verdict": "Malicious",
        "overall_confidence": 0.8,
        "malware_category": "loader",
        "stix_bundle": None,
        "judge_stix_bundle": None,
        "mitre_techniques": [],
        "agent_reports": {},
        "negotiation_log": {},
        "run_summary": {},
        "malware_report": {"verdict": "Malicious"},
        "incomplete_reason": None,
        "ledger_seal": None,
    }
    core = ledger_chain.seal(
        job_id,
        [entry],
        chain_head,
        report_sha256=ledger_chain.report_digest(report),
        sealed_at=NOW,
        key=KEY,
        report_id=report["id"],
    )
    seal = ledger_chain.anchored(core, landed=True, key=KEY)
    report["ledger_seal"] = seal
    report["malware_report"] = ledger_chain.with_seal(report["malware_report"], seal)
    report["run_summary"] = ledger_chain.with_seal(report["run_summary"], seal)
    other = uuid.uuid4()
    rows = _chain_rows(
        [{"seal": {}}, {"report_id": report["id"], "seal": core}, {"seal": {"n": 3}}],
        [other, job_id, other],
    )
    with engine.begin() as conn:
        for model in (EvidenceEntry, AnalysisReport, AuditLog, AuditChainHead):
            model.__table__.create(conn)
        values = {c.name: getattr(entry, c.name) for c in EvidenceEntry.__table__.columns}
        conn.execute(
            EvidenceEntry.__table__.insert().values(
                **values | {"id": uuid.uuid4(), "updated_at": NOW}
            )
        )
        conn.execute(
            AnalysisReport.__table__.insert().values(
                **report | {"id": uuid.UUID(report["id"]), "job_id": job_id},
                created_at=NOW,
                updated_at=NOW,
            )
        )
        _write_chain(conn, rows, _head(rows))
    return job_id, rows


async def _verify_job(engine: Any, job_id: Any) -> dict[str, Any]:
    with engine.connect() as conn:
        return await ledger_verify.verify_job(_Conn(conn), job_id)


@pytest.mark.asyncio
async def test_without_an_anchor_a_stored_chain_verifies_as_before_and_says_so(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.config import settings

    monkeypatch.setattr(settings, "audit_anchor", "")
    monkeypatch.setattr(settings, "audit_anchor_database_url", "")
    engine = _sqlite()
    job_id, _ = _sealed_job(engine)
    verdict = await _verify_job(engine, job_id)
    assert verdict["status"] == "verified", verdict
    assert verdict["anchor"] == {"kind": "none", "state": "none"}
    assert audit_anchor.NOT_CONFIGURED in verdict["notes"]
    # The answer the API serves carries it too.
    from app.schemas.evidence import LedgerVerificationResponse

    served = LedgerVerificationResponse(**verdict).model_dump()
    assert served["anchor"]["kind"] == "none"


@pytest.mark.asyncio
async def test_a_job_verifies_against_its_anchor_and_breaks_when_the_chain_is_cut(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = _sqlite()
    job_id, rows = _sealed_job(engine)
    anchor = _Anchor()
    await _anchored(engine, anchor)
    monkeypatch.setattr(audit_anchor, "configured", lambda: anchor)
    verdict = await _verify_job(engine, job_id)
    assert verdict["status"] == "verified", verdict
    assert verdict["anchor"]["state"] == "matches"
    assert (
        "the audit chain holds the head anchored outside the database (memory)" in verdict["checks"]
    )
    assert verdict["anchor"] == {"kind": "memory", "state": "matches"}, (
        "a job's answer names no chain position and no protection"
    )
    assert not any("held in memory for the test" in n for n in verdict["notes"])
    with engine.connect() as conn:
        operator = await ledger_verify.verify_job(_Conn(conn), job_id, operator=True)
    assert operator["anchor"] == {
        "kind": "memory",
        "state": "matches",
        "protection": "held in memory for the test",
    }
    assert operator["notes"][0] == "Audit chain anchor (memory): held in memory for the test"

    with engine.begin() as conn:
        _write_chain(conn, rows[:2], _head(rows, upto=2))
    verdict = await _verify_job(engine, job_id)
    assert verdict["status"] == "broken"
    assert verdict["reason"].startswith(
        "The audit chain does not match its anchor outside the database:"
    )


@pytest.mark.asyncio
async def test_an_anchor_that_is_down_degrades_the_job_s_verification_with_a_stated_note(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = _sqlite()
    job_id, _ = _sealed_job(engine)
    anchor = _Anchor(down=True)
    monkeypatch.setattr(audit_anchor, "configured", lambda: anchor)
    verdict = await _verify_job(engine, job_id)
    assert verdict["status"] == "unverifiable", "an unreadable anchor is never verified"
    assert verdict["first_broken_seq"] is None
    assert verdict["anchor"]["state"] == "unreadable"
    [note] = [n for n in verdict["notes"] if "could not be read" in n]
    assert "checked against the database head only" in note
    assert "ConnectionError" not in note, "a job's answer names no exception class"
    assert verdict["reason"] == note
    with engine.connect() as conn:
        operator = await ledger_verify.verify_job(_Conn(conn), job_id, operator=True)
    assert "could not be read (ConnectionError)" in operator["reason"]


@pytest.mark.asyncio
async def test_a_job_whose_row_is_past_the_last_anchored_head_is_told_so(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = _sqlite()
    job_id, rows = _sealed_job(engine)
    anchor = _Anchor()
    anchor.heads[1] = AnchoredHead.read(_head(rows, upto=1))
    monkeypatch.setattr(audit_anchor, "configured", lambda: anchor)
    verdict = await _verify_job(engine, job_id)
    assert verdict["status"] == "verified", verdict
    assert verdict["anchor"]["state"] == "lags"
    assert any("This job's last chained audit row lies past" in n for n in verdict["notes"])


# ---------------------------------------------------------------------------
# Anchoring after the commit; an anchor down never fails the job
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_an_anchor_that_is_down_is_counted_and_never_raises() -> None:
    rows = _chain_rows([{"n": 0}], [uuid.uuid4()])
    engine = _database(rows)
    before = observability.counters.audit_anchor_failures
    assert await _anchored(engine, _Anchor(down=True)) == audit_anchor.FAILED
    assert observability.counters.audit_anchor_failures == before + 1


@pytest.mark.asyncio
async def test_a_hanging_anchor_is_given_up_on(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Hangs(_Anchor):
        async def latest(self) -> AnchoredHead | None:
            await asyncio.sleep(30)
            return None

    monkeypatch.setattr(audit_anchor, "ANCHOR_SECONDS", 0.05)
    rows = _chain_rows([{"n": 0}], [uuid.uuid4()])
    engine = _database(rows)
    assert await _anchored(engine, _Hangs()) == audit_anchor.FAILED
    with engine.connect() as conn:
        verdict = await audit_anchor.verification(_Conn(conn), _head(rows), _Hangs())
    assert verdict.state == audit_anchor.UNREADABLE


@pytest.mark.asyncio
async def test_the_head_is_anchored_once_the_transaction_commits_and_not_on_rollback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from sqlalchemy.orm import Session

    rows = _chain_rows([{"n": 0}, {"n": 1}], [uuid.uuid4()] * 2)
    engine = _database(rows)
    anchor = _Anchor()
    monkeypatch.setattr(audit_anchor, "configured", lambda: anchor)
    with Session(engine) as sync:
        db = SimpleNamespace(sync_session=sync, bind=_Engine(engine))
        # The append's transaction is open when it asks, as in the worker.
        sync.execute(sa.text("SELECT 1"))
        audit_anchor.anchor_after_commit(db, _head(rows))
        sync.rollback()
        await audit_anchor.drain()
        assert anchor.heads == {}, "a head rolled back is never anchored"
        sync.commit()
        await audit_anchor.drain()
        assert anchor.heads == {}, "a commit after the rollback has nothing of it to anchor"
        audit_anchor.anchor_after_commit(db, _head(rows, upto=1))
        audit_anchor.anchor_after_commit(db, _head(rows))
        audit_anchor.anchor_after_commit(db, _head(rows, upto=1))  # the highest is kept
        sync.commit()
        await audit_anchor.drain()
    assert set(anchor.heads) == {2}
    assert anchor.heads[2].mac == _head(rows)["mac"]


@pytest.mark.asyncio
async def test_a_chained_append_asks_for_the_anchor_after_its_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    asked: list[Any] = []
    monkeypatch.setattr(
        audit_anchor, "anchor_after_commit", lambda db, head: asked.append((db, head))
    )

    class _Nested:
        async def __aenter__(self) -> None:
            return None

        async def __aexit__(self, *exc: Any) -> bool:
            return False

    class _Session:
        head = None

        def begin_nested(self) -> _Nested:
            return _Nested()

        def get_bind(self) -> Any:
            raise RuntimeError("no bind")

        async def execute(self, statement: Any, *args: Any) -> Any:
            return SimpleNamespace(first=lambda: None)

        async def get(self, model: Any, name: str) -> Any:
            return None

        def add(self, row: Any) -> None:
            return None

        async def flush(self) -> None:
            return None

    db = _Session()
    row = await audit_chain.append(
        db,
        action=audit_chain.LEDGER_SEAL,
        resource_type="job",
        resource_id="j",
        details={},
        key=KEY,
    )
    assert row is not None
    [(session, head)] = asked
    assert session is db
    assert head == {
        "chain_seq": 1,
        "chain": row.chain,
        "key_id": KEY.key_id,
        "rotated_at_seq": 1,
        "mac": audit_chain.head_mac(1, row.chain, 1, KEY),
    }, "the head the append computed is the value anchored"


def test_without_an_anchor_the_append_puts_no_hook_on_the_session() -> None:
    from sqlalchemy.orm import Session

    engine = _sqlite()
    with Session(engine) as sync:
        db = SimpleNamespace(sync_session=sync, bind=_Engine(engine))
        audit_anchor.anchor_after_commit(db)
        assert audit_anchor._HOOKED not in sync.info


# ---------------------------------------------------------------------------
# The database anchor
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_database_anchor_keeps_heads_and_refuses_another_at_the_same_seq() -> None:
    anchor_db = _sqlite()
    with anchor_db.begin() as conn:
        AuditChainAnchor.__table__.create(conn)
    anchor = audit_anchor.DatabaseAnchor(engine=_Engine(anchor_db))
    assert await anchor.latest() is None
    rows = _chain_rows([{"n": 0}, {"n": 1}], [uuid.uuid4()] * 2)
    await anchor.put(AnchoredHead.read(_head(rows, upto=1)))
    await anchor.put(AnchoredHead.read(_head(rows)))
    await anchor.put(AnchoredHead.read(_head(rows)))  # the same head again is nothing
    latest = await anchor.latest()
    assert latest is not None and (latest.chain_seq, latest.chain) == (2, rows[1]["chain"])
    with pytest.raises(audit_anchor.AnchorConflict):
        await anchor.put(AnchoredHead.read(_head(rows) | {"chain": "f" * 64}))
    assert "not PostgreSQL" in await anchor.protection()


def test_the_protection_sentence_reads_the_roles_privileges() -> None:
    strong = audit_anchor.database_protection(
        {
            "role": "maljan_anchor",
            "owner": "postgres",
            "can_insert": True,
            "can_select": True,
            "append_only": True,
        },
        "maljan",
        {"superuser": False},
    )
    assert strong.startswith("The anchor role maljan_anchor may only INSERT and SELECT")
    assert "cannot move an anchored head" in strong
    same = audit_anchor.database_protection(
        {"role": "maljan", "owner": "maljan", "can_insert": True, "can_select": True},
        "maljan",
        None,
    )
    assert same.startswith("The anchor table is not protected")
    assert "application's own database role (maljan)" in same
    assert "no append-only trigger" in same
    owner = audit_anchor.database_protection(
        {
            "role": "maljan_anchor",
            "owner": "maljan",
            "can_insert": True,
            "can_select": True,
            "can_update": True,
            "append_only": True,
        },
        "maljan",
        {"superuser": False},
    )
    assert "may also UPDATE it" in owner
    assert "the application's role maljan owns the anchor table" in owner


# ---------------------------------------------------------------------------
# The object-store anchor
# ---------------------------------------------------------------------------


class _S3Error(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class _Store:
    """A MinIO double: objects in memory, versioned with delete markers under a lock."""

    def __init__(self, lock: Any = None, *, down: bool = False) -> None:
        self.lock = lock
        self.down = down
        # name -> [(version id, time, bytes or None for a delete marker)]
        self.versions: dict[str, list[tuple[str, datetime, bytes | None]]] = {}
        self.puts: list[dict[str, Any]] = []
        self.listings: list[dict[str, Any]] = []
        self._clock = 0

    def _up(self) -> None:
        if self.down:
            raise ConnectionError("the store is unreachable")

    def _stamp(self) -> tuple[str, datetime]:
        self._clock += 1
        return f"v{self._clock}", NOW + timedelta(seconds=self._clock)

    def bucket_exists(self, bucket: str) -> bool:
        self._up()
        return True

    def get_object_lock_config(self, bucket: str) -> Any:
        self._up()
        if self.lock is None:
            raise _S3Error("ObjectLockConfigurationNotFoundError")
        return self.lock

    def put_object(self, bucket: str, name: str, data: Any, **kwargs: Any) -> None:
        self._up()
        self.puts.append({"name": name, **kwargs})
        version, stamp = self._stamp()
        if self.lock is None:
            self.versions[name] = []
        self.versions.setdefault(name, []).append((version, stamp, data.read()))

    def remove_object(self, bucket: str, name: str) -> None:
        """Removed outright without a lock; a delete marker over it with one."""
        if self.lock is None:
            self.versions.pop(name, None)
            return
        version, stamp = self._stamp()
        self.versions[name].append((version, stamp, None))

    def list_objects(self, bucket: str, prefix: str = "", **kwargs: Any) -> list[Any]:
        self._up()
        self.listings.append(dict(kwargs, prefix=prefix))
        start_after = kwargs.get("start_after") or ""
        found = []
        for name, versions in sorted(self.versions.items()):
            if not name.startswith(prefix) or name <= start_after:
                continue
            if not kwargs.get("include_version"):
                if versions[-1][2] is not None:
                    found.append(SimpleNamespace(object_name=name, last_modified=versions[-1][1]))
                continue
            for index, (version_id, stamp, blob) in enumerate(versions):
                found.append(
                    SimpleNamespace(
                        object_name=name,
                        version_id=version_id,
                        last_modified=stamp,
                        is_latest=index == len(versions) - 1,
                        is_delete_marker=blob is None,
                    )
                )
        return found

    def get_object(self, bucket: str, name: str, version_id: str | None = None) -> Any:
        versions = self.versions[name]
        blob = next((b for v, _, b in versions if v == version_id), versions[-1][2])
        return SimpleNamespace(read=lambda: blob, close=lambda: None, release_conn=lambda: None)


_UNLOCKED = None
_HOLD = SimpleNamespace(mode=None, duration=None, duration_unit=None)
_COMPLIANCE = SimpleNamespace(mode="COMPLIANCE", duration=30, duration_unit="Days")


@pytest.mark.asyncio
async def test_a_bucket_without_object_lock_keeps_heads_and_says_plainly_it_does_not_lock() -> None:
    store = _Store()
    anchor = audit_anchor.ObjectStoreAnchor(store=store)
    rows = _chain_rows([{"n": 0}, {"n": 1}], [uuid.uuid4()] * 2)
    await anchor.put(AnchoredHead.read(_head(rows, upto=1)))
    await anchor.put(AnchoredHead.read(_head(rows)))
    assert [p["name"] for p in store.puts] == [
        "audit-chain/head/000000000001.json",
        "audit-chain/head/000000000002.json",
    ]
    assert all(p["legal_hold"] is False for p in store.puts)
    latest = await anchor.latest()
    assert latest is not None and latest.chain == rows[1]["chain"]
    protection = await anchor.protection()
    assert protection.startswith("The bucket has no object lock")
    assert "can overwrite or delete an anchored head" in protection
    with pytest.raises(audit_anchor.AnchorConflict):
        await anchor.put(AnchoredHead.read(_head(rows) | {"chain": "f" * 64}))


@pytest.mark.asyncio
async def test_a_locked_bucket_holds_each_head_and_reads_the_first_version_written() -> None:
    store = _Store(lock=_HOLD)
    anchor = audit_anchor.ObjectStoreAnchor(store=store)
    rows = _chain_rows([{"n": 0}], [uuid.uuid4()])
    await anchor.put(AnchoredHead.read(_head(rows)))
    assert store.puts[0]["legal_hold"] is True
    assert "legal hold" in await anchor.protection()
    # A later version put over the head's name is not taken for it.
    forged = json.dumps(_head(rows) | {"chain": "e" * 64}).encode()
    store.put_object("b", "audit-chain/head/000000000001.json", io.BytesIO(forged))
    latest = await audit_anchor.ObjectStoreAnchor(store=store).latest()
    assert latest is not None and latest.chain == rows[0]["chain"]


@pytest.mark.asyncio
async def test_a_head_hidden_behind_a_delete_marker_is_a_break() -> None:
    store = _Store(lock=_COMPLIANCE)
    rows = _chain_rows([{"n": 0}, {"n": 1}], [uuid.uuid4()] * 2)
    writer = audit_anchor.ObjectStoreAnchor(store=store)
    await writer.put(AnchoredHead.read(_head(rows, upto=1)))
    await writer.put(AnchoredHead.read(_head(rows)))
    # The newest head is hidden: a cold reader would otherwise take seq 1 for
    # the latest and accept a chain cut back to it.
    store.remove_object("b", "audit-chain/head/000000000002.json")
    with pytest.raises(audit_anchor.AnchorTampered, match="delete marker"):
        await audit_anchor.ObjectStoreAnchor(store=store).latest()
    engine = _database(rows[:1])
    verdict = await _verdict(engine, audit_anchor.ObjectStoreAnchor(store=store))
    assert verdict.state == audit_anchor.BROKEN
    assert "hidden behind a delete marker" in (verdict.broken or "")
    # And nothing is anchored over it.
    assert await _anchored(engine, audit_anchor.ObjectStoreAnchor(store=store)) == (
        audit_anchor.REFUSED
    )


@pytest.mark.asyncio
async def test_a_head_seen_once_and_gone_from_an_unlocked_bucket_is_a_break() -> None:
    store = _Store()
    rows = _chain_rows([{"n": 0}, {"n": 1}], [uuid.uuid4()] * 2)
    anchor = audit_anchor.ObjectStoreAnchor(store=store)
    await anchor.put(AnchoredHead.read(_head(rows, upto=1)))
    await anchor.put(AnchoredHead.read(_head(rows)))
    assert (await anchor.latest()).chain_seq == 2  # type: ignore[union-attr]
    store.remove_object("b", "audit-chain/head/000000000002.json")
    with pytest.raises(audit_anchor.AnchorTampered, match="gone"):
        await anchor.latest()


@pytest.mark.asyncio
async def test_a_warm_reader_lists_from_just_below_the_highest_head_it_saw() -> None:
    store = _Store(lock=_COMPLIANCE)
    rows = _chain_rows([{"n": n} for n in range(3)], [uuid.uuid4()] * 3)
    anchor = audit_anchor.ObjectStoreAnchor(store=store)
    for upto in (1, 2):
        await anchor.put(AnchoredHead.read(_head(rows, upto=upto)))
    cold = audit_anchor.ObjectStoreAnchor(store=store)
    assert (await cold.latest()).chain_seq == 2  # type: ignore[union-attr]
    assert "start_after" not in store.listings[-1], "a cold reader lists everything"
    await anchor.put(AnchoredHead.read(_head(rows)))
    assert (await cold.latest()).chain_seq == 3  # type: ignore[union-attr]
    assert store.listings[-1]["start_after"] == "audit-chain/head/000000000001.json"
    assert store.listings[-1]["include_version"] is True


def test_the_anchor_s_own_client_ends_within_its_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.services import object_store

    built: list[dict[str, Any]] = []
    monkeypatch.setattr(object_store, "bounded_client", lambda **kw: built.append(kw) or "c")
    assert audit_anchor.ObjectStoreAnchor()._client() == "c"
    assert built == [{"read_seconds": audit_anchor.ANCHOR_SECONDS, "retries": 0}]


def test_the_lock_sentence_says_what_each_mode_holds() -> None:
    compliance = audit_anchor.bucket_lock_sentence(BucketLock(True, "COMPLIANCE", 30, "Days"))
    assert "COMPLIANCE mode for 30 days" in compliance
    assert "versions cannot be removed" in compliance
    assert "a delete marker hides a head, and is detected" in compliance
    governance = audit_anchor.bucket_lock_sentence(BucketLock(True, "GOVERNANCE", 1, "Years"))
    assert "s3:BypassGovernanceRetention can still remove a version" in governance


@pytest.mark.asyncio
async def test_an_object_store_that_is_down_fails_the_anchor_write_only() -> None:
    rows = _chain_rows([{"n": 0}], [uuid.uuid4()])
    engine = _database(rows)
    anchor = audit_anchor.ObjectStoreAnchor(store=_Store(down=True))
    assert await _anchored(engine, anchor) == audit_anchor.FAILED
    verdict = await _verdict(engine, anchor)
    assert verdict.state == audit_anchor.UNREADABLE
    assert verdict.unverifiable is not None and verdict.broken is None


# ---------------------------------------------------------------------------
# Configuration: a declared bootstrap setting, credentials never printed
# ---------------------------------------------------------------------------


def _settings(**values: Any) -> APISettings:
    return APISettings(**values)


def test_the_anchor_is_chosen_by_the_bootstrap_setting(monkeypatch: pytest.MonkeyPatch) -> None:
    assert audit_anchor.configured_kind(_settings()) == "none"
    url = f"postgresql+asyncpg://maljan_anchor:{password()}@db:5432/maljan"
    assert audit_anchor.configured_kind(_settings(audit_anchor_database_url=url)) == "database"
    assert audit_anchor.configured_kind(_settings(audit_anchor="Object_Store")) == "object_store"
    assert (
        audit_anchor.configured_kind(_settings(audit_anchor="none", audit_anchor_database_url=url))
        == "none"
    )
    from app.config import settings

    monkeypatch.setattr(settings, "audit_anchor", "object_store")
    assert isinstance(audit_anchor.configured(), audit_anchor.ObjectStoreAnchor)
    monkeypatch.setattr(settings, "audit_anchor", "none")
    assert audit_anchor.configured() is None


def test_the_startup_check_refuses_a_bad_anchor_and_never_prints_its_url() -> None:
    secret = password(18)
    problems, _ = audit_anchor.bootstrap_findings(_settings(audit_anchor="ledger"))
    assert problems == ["AUDIT_ANCHOR must be one of none, database, object_store, or empty"]
    problems, _ = audit_anchor.bootstrap_findings(_settings(audit_anchor="database"))
    assert problems == ["AUDIT_ANCHOR is database but AUDIT_ANCHOR_DATABASE_URL is not set"]
    same = _settings(
        database_url=f"postgresql+asyncpg://maljan:{secret}@db:5432/maljan",
        audit_anchor_database_url=f"postgresql+asyncpg://maljan:{secret}@db:5432/maljan",
    )
    problems, warnings = audit_anchor.bootstrap_findings(same)
    assert problems == [] and len(warnings) == 1
    assert "application's own database role" in warnings[0]
    report = validate_bootstrap(same)
    assert all(secret not in line for line in report.problems + report.warnings)
    assert warnings[0] in report.warnings


# ---------------------------------------------------------------------------
# The revision
# ---------------------------------------------------------------------------


def _load() -> Any:
    spec = importlib.util.spec_from_file_location("audit_chain_anchor", _REV)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_anchor_table_is_created_and_its_downgrade_is_refused_while_it_holds_a_head() -> None:
    mod = _load()
    assert (mod.revision, mod.down_revision) == ("20261028000000", "20261027000000")
    engine = sa.create_engine("sqlite://")
    with engine.connect() as conn:
        with Operations.context(MigrationContext.configure(conn)):
            mod.upgrade()
            columns = {c["name"] for c in sa.inspect(conn).get_columns("audit_chain_anchor")}
            assert columns == {c.name for c in AuditChainAnchor.__table__.columns}
            conn.execute(
                sa.text(
                    "INSERT INTO audit_chain_anchor (chain_seq, chain, key_id, rotated_at_seq, "
                    "mac) VALUES (1, 'c', NULL, 1, 'm')"
                )
            )
            with pytest.raises(RuntimeError, match="holds anchored heads"):
                mod.downgrade()
            conn.execute(sa.text("DELETE FROM audit_chain_anchor"))
            mod.downgrade()
        assert "audit_chain_anchor" not in sa.inspect(conn).get_table_names()


def test_the_revision_makes_the_table_append_only_on_postgresql() -> None:
    text = _REV.read_text(encoding="utf-8")
    assert "BEFORE UPDATE OR DELETE" in text and "BEFORE TRUNCATE" in text
    assert "REVOKE UPDATE, DELETE, TRUNCATE ON audit_chain_anchor FROM PUBLIC" in text
    assert "SET LOCAL lock_timeout" in text


# ---------------------------------------------------------------------------
# A head read before a newer one was anchored is read again, not called cut
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_stale_head_read_before_a_newer_anchor_is_read_again_and_not_broken() -> None:
    rows = _chain_rows([{"n": n} for n in range(3)], [uuid.uuid4()] * 3)
    engine = _database(rows)
    anchor = _Anchor()
    anchor.heads[3] = AnchoredHead.read(_head(rows))
    stale = _head(rows, upto=2)
    with engine.connect() as conn:
        verdict = await audit_anchor.verification(_Conn(conn, _Engine(engine)), stale, anchor)
    assert (verdict.state, verdict.broken) == (audit_anchor.MATCHES, None)
    # Where no read outside the snapshot can be made, the first read stands.
    with engine.connect() as conn:
        unchecked = await audit_anchor.verification(_Conn(conn), stale, anchor)
    assert unchecked.broken == audit_anchor.BEHIND
    # A chain really cut back is still a break after the second read.
    with engine.begin() as conn:
        _write_chain(conn, rows[:2], _head(rows, upto=2))
    with engine.connect() as conn:
        cut = await audit_anchor.verification(_Conn(conn, _Engine(engine)), stale, anchor)
    assert cut.broken == audit_anchor.BEHIND


@pytest.mark.asyncio
async def test_a_job_reads_the_anchor_before_the_database(monkeypatch: pytest.MonkeyPatch) -> None:
    engine = _sqlite()
    job_id, _ = _sealed_job(engine)
    order: list[str] = []

    class _Watched(_Anchor):
        async def latest(self) -> AnchoredHead | None:
            order.append("anchor")
            return await super().latest()

    anchor = _Watched()
    await _anchored(engine, anchor)
    order.clear()
    monkeypatch.setattr(audit_anchor, "configured", lambda: anchor)
    real = audit_anchor._db_head
    with engine.connect() as conn:
        db = _Conn(conn)
        original = db.execute

        async def _execute(statement: Any, *args: Any) -> Any:
            order.append("database")
            return await original(statement, *args)

        db.execute = _execute  # type: ignore[method-assign]
        await ledger_verify.verify_job(db, job_id)
    assert order[0] == "anchor"
    assert real is audit_anchor._db_head


# ---------------------------------------------------------------------------
# Once configured, an anchor that cannot vouch is never "verified"
# ---------------------------------------------------------------------------


def test_an_empty_anchor_beside_a_head_and_an_unknown_key_are_unverifiable() -> None:
    rows = _chain_rows([{"n": 0}], [uuid.uuid4()])
    empty = audit_anchor.compare("memory", None, _head(rows), None, KEYS)
    assert (empty.state, empty.unverifiable) == (
        audit_anchor.EMPTY,
        audit_anchor.EMPTY_BESIDE_A_HEAD,
    )
    fresh_platform = audit_anchor.compare("memory", None, None, None, KEYS)
    assert fresh_platform.unverifiable is None, "an empty anchor over an empty chain is right"
    other = AnchoredHead.read(_head(rows) | {"key_id": "f" * 16})
    unknown = audit_anchor.compare("memory", other, _head(rows), "0" * 64, KEYS)
    assert (unknown.state, unknown.broken) == (audit_anchor.UNVERIFIABLE, None)
    assert unknown.unverifiable == audit_anchor.UNKNOWN_KEY
    assert audit_anchor.UNKNOWN_KEY in unknown.notes


@pytest.mark.asyncio
async def test_a_job_beside_an_empty_anchor_reads_unverifiable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = _sqlite()
    job_id, _ = _sealed_job(engine)
    anchor = _Anchor()
    monkeypatch.setattr(audit_anchor, "configured", lambda: anchor)
    verdict = await _verify_job(engine, job_id)
    assert verdict["status"] == "unverifiable"
    assert verdict["reason"] == audit_anchor.EMPTY_BESIDE_A_HEAD


@pytest.mark.asyncio
async def test_the_full_walk_reads_unverifiable_when_the_anchor_is_down(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scripts.ledger import verify as cli

    rows = _chain_rows([{"n": 0}], [uuid.uuid4()])
    engine = _database(rows)
    monkeypatch.setattr(audit_anchor, "configured", lambda: _Anchor(down=True))
    with engine.connect() as conn:
        walked = await cli.walk_audit_chain(_Conn(conn))
    assert walked["status"] == "unverifiable"
    assert "could not be read" in walked["reason"]


@pytest.mark.asyncio
async def test_an_empty_anchor_is_given_the_current_head_at_startup_and_a_full_one_is_not(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rows = _chain_rows([{"n": 0}, {"n": 1}], [uuid.uuid4()] * 2)
    engine = _database(rows)
    anchor = _Anchor()
    monkeypatch.setattr(audit_anchor, "configured", lambda: anchor)
    audit_anchor.start_anchoring(_Engine(engine))
    await audit_anchor.drain()
    assert set(anchor.heads) == {2}
    held = _Anchor()
    held.heads[1] = AnchoredHead.read(_head(rows, upto=1))
    monkeypatch.setattr(audit_anchor, "configured", lambda: held)
    audit_anchor.start_anchoring(_Engine(engine))
    await audit_anchor.drain()
    assert set(held.heads) == {1}, "startup only fills an empty anchor"


def test_the_api_and_the_workers_wait_for_anchor_writes_at_shutdown() -> None:
    import inspect

    from app import main
    from app.worker import analysis_worker, enrich_worker

    assert "audit_anchor.start_anchoring(async_engine)" in inspect.getsource(main.lifespan)
    assert "await audit_anchor.drain()" in inspect.getsource(main.lifespan)
    assert "audit_anchor.start_anchoring(engine)" in inspect.getsource(analysis_worker.startup)
    assert "await audit_anchor.drain(EXIT_GRACE)" in inspect.getsource(analysis_worker.shutdown)
    assert "await audit_anchor.drain()" in inspect.getsource(enrich_worker.enrich_shutdown)


# ---------------------------------------------------------------------------
# The hook anchors only what the committed database vouches for
# ---------------------------------------------------------------------------


async def _anchor_with(engine: Any, anchor: Any, expected: Any = None) -> str:
    with engine.connect() as conn:
        return await audit_anchor.anchor_committed_head(_Conn(conn), anchor, expected)


@pytest.mark.asyncio
async def test_a_head_whose_mac_fails_or_whose_key_is_unknown_is_never_anchored() -> None:
    rows = _chain_rows([{"n": 0}], [uuid.uuid4()])
    engine = _database(rows)
    anchor = _Anchor()
    with engine.begin() as conn:
        conn.execute(AuditChainHead.__table__.update().values(mac="0" * 64))
    before = observability.counters.audit_anchor_failures
    assert await _anchor_with(engine, anchor) == audit_anchor.REFUSED
    assert observability.counters.audit_anchor_failures == before + 1
    with engine.begin() as conn:
        conn.execute(AuditChainHead.__table__.update().values(key_id="f" * 16))
    assert await _anchor_with(engine, anchor) == audit_anchor.REFUSED
    assert anchor.heads == {}


@pytest.mark.asyncio
async def test_a_head_record_moved_back_over_intact_rows_is_refused() -> None:
    rows = _chain_rows([{"n": n} for n in range(3)], [uuid.uuid4()] * 3)
    engine = _database(rows)
    anchor = _Anchor()
    anchor.heads[3] = AnchoredHead.read(_head(rows))
    # The rows are all there; only the head record was put back to seq 2.
    with engine.begin() as conn:
        conn.execute(AuditChainHead.__table__.delete())
        conn.execute(AuditChainHead.__table__.insert().values(**_head(rows, upto=2)))
    before = observability.counters.audit_anchor_failures
    assert await _anchor_with(engine, anchor) == audit_anchor.REFUSED
    assert observability.counters.audit_anchor_failures == before + 1


@pytest.mark.asyncio
async def test_the_head_the_append_computed_is_anchored_once_the_database_agrees() -> None:
    rows = _chain_rows([{"n": n} for n in range(3)], [uuid.uuid4()] * 3)
    engine = _database(rows)
    anchor = _Anchor()
    # The database head moved on since: the computed head is still the value.
    assert await _anchor_with(engine, anchor, _head(rows, upto=2)) == audit_anchor.ANCHORED
    assert set(anchor.heads) == {2}
    assert await _anchor_with(engine, anchor, _head(rows, upto=2)) == audit_anchor.CURRENT
    # A computed head the database does not hold (rolled back, or another
    # chain at its seq) is refused.
    forged = _head(rows) | {"chain": "e" * 64}
    forged["mac"] = audit_chain.head_mac(3, forged["chain"], 1, KEY)
    assert await _anchor_with(engine, anchor, forged) == audit_anchor.REFUSED
    beyond = _head(rows) | {"chain_seq": 4}
    beyond["mac"] = audit_chain.head_mac(4, beyond["chain"], 1, KEY)
    assert await _anchor_with(engine, anchor, beyond) == audit_anchor.REFUSED
    assert set(anchor.heads) == {2}


@pytest.mark.asyncio
async def test_the_hook_reads_the_anchor_before_the_database() -> None:
    rows = _chain_rows([{"n": 0}], [uuid.uuid4()])
    engine = _database(rows)
    order: list[str] = []

    class _Watched(_Anchor):
        async def latest(self) -> AnchoredHead | None:
            order.append("anchor")
            return await super().latest()

    with engine.connect() as conn:
        db = _Conn(conn)
        original = db.execute

        async def _execute(statement: Any, *args: Any) -> Any:
            order.append("database")
            return await original(statement, *args)

        db.execute = _execute  # type: ignore[method-assign]
        assert await audit_anchor.anchor_committed_head(db, _Watched()) == audit_anchor.ANCHORED
    assert order[0] == "anchor"


@pytest.mark.asyncio
async def test_a_cancelled_anchor_write_is_counted_and_stays_cancelled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    started = asyncio.Event()

    class _Hangs(_Anchor):
        async def latest(self) -> AnchoredHead | None:
            started.set()
            await asyncio.sleep(30)
            return None

    rows = _chain_rows([{"n": 0}], [uuid.uuid4()])
    engine = _database(rows)
    monkeypatch.setattr(audit_anchor, "configured", lambda: _Hangs())
    before = observability.counters.audit_anchor_failures
    task = asyncio.create_task(audit_anchor._anchor_through(_Engine(engine)))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert observability.counters.audit_anchor_failures == before + 1


# ---------------------------------------------------------------------------
# The protection sentence: every branch that weakens it
# ---------------------------------------------------------------------------


def test_an_anchor_role_that_owns_the_table_and_an_app_role_that_inserts_are_weak() -> None:
    owns = audit_anchor.database_protection(
        {"role": "maljan_anchor", "owner": "maljan_anchor", "can_insert": True, "can_select": True},
        "maljan",
        {"superuser": False},
    )
    assert owns.startswith("The anchor table is not protected")
    assert "the anchor role maljan_anchor owns the anchor table" in owns
    inserts = audit_anchor.database_protection(
        {
            "role": "maljan_anchor",
            "owner": "postgres",
            "can_insert": True,
            "can_select": True,
            "append_only": True,
        },
        "maljan",
        {"superuser": False, "can_insert": True},
    )
    assert inserts.startswith("The anchor table is not protected")
    assert "the application's role maljan may INSERT it" in inserts


# ---------------------------------------------------------------------------
# On a real PostgreSQL: the trigger and the revoke
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_on_postgresql_the_anchor_table_refuses_every_change() -> None:
    asyncpg = pytest.importorskip("asyncpg")
    from sqlalchemy.engine import make_url
    from sqlalchemy.ext.asyncio import create_async_engine

    from app.config import get_settings

    url = make_url(get_settings().database_url)
    if not url.drivername.startswith("postgresql"):
        pytest.skip("the configured database is not PostgreSQL")
    dsn = url.set(drivername="postgresql", database="postgres").render_as_string(
        hide_password=False
    )
    try:
        admin = await asyncio.wait_for(asyncpg.connect(dsn), timeout=3)
    except Exception as exc:  # noqa: BLE001 — any failure to reach it is a skip
        pytest.skip(
            f"no PostgreSQL reachable at the configured DATABASE_URL ({type(exc).__name__})"
        )
    # A throwaway database of its own, never the platform's.
    name = f"maljan_anchor_test_{uuid.uuid4().hex[:12]}"
    try:
        await admin.execute(f'CREATE DATABASE "{name}"')
    except asyncpg.PostgresError as exc:
        await admin.close()
        pytest.skip(f"no right to create a throwaway database ({type(exc).__name__})")
    engine = create_async_engine(url.set(database=name))
    try:
        mod = _load()

        def _run(sync: Any, step: Any) -> None:
            with Operations.context(MigrationContext.configure(sync)):
                step()

        async with engine.begin() as conn:
            await conn.run_sync(_run, mod.upgrade)
        anchor = audit_anchor.DatabaseAnchor(engine=engine, app_role=url.username)
        rows = _chain_rows([{"n": 0}], [uuid.uuid4()])
        await anchor.put(AnchoredHead.read(_head(rows)))
        assert (await anchor.latest()).chain == rows[0]["chain"]  # type: ignore[union-attr]
        for statement in (
            "UPDATE audit_chain_anchor SET chain = 'x'",
            "DELETE FROM audit_chain_anchor",
            "TRUNCATE audit_chain_anchor",
        ):
            with pytest.raises(sa.exc.DBAPIError, match="append-only"):
                async with engine.begin() as conn:
                    await conn.execute(sa.text(statement))
        async with engine.connect() as conn:
            public = (
                await conn.execute(
                    sa.text(
                        "SELECT has_table_privilege('public', 'audit_chain_anchor', 'UPDATE'), "
                        "has_table_privilege('public', 'audit_chain_anchor', 'DELETE'), "
                        "has_table_privilege('public', 'audit_chain_anchor', 'TRUNCATE')"
                    )
                )
            ).one()
        assert tuple(public) == (False, False, False)
        protection = await anchor.protection()
        assert "an append-only trigger refuses UPDATE, DELETE and TRUNCATE" in protection
        assert protection.startswith("The anchor table is not protected"), (
            "the test connects as the application's own role, which owns the table"
        )
        with pytest.raises(RuntimeError, match="holds anchored heads"):
            async with engine.begin() as conn:
                await conn.run_sync(_run, mod.downgrade)
    finally:
        await engine.dispose()
        await admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        await admin.close()


@pytest.mark.asyncio
async def test_a_head_record_below_the_head_to_anchor_is_refused_even_on_an_empty_anchor() -> None:
    rows = _chain_rows([{"n": n} for n in range(3)], [uuid.uuid4()] * 3)
    engine = _database(rows)
    # Row 3 is intact, but the head record says 2: the head the append
    # computed at 3 is not what the committed database vouches for.
    with engine.begin() as conn:
        conn.execute(AuditChainHead.__table__.delete())
        conn.execute(AuditChainHead.__table__.insert().values(**_head(rows, upto=2)))
    anchor = _Anchor()
    assert await _anchor_with(engine, anchor, _head(rows)) == audit_anchor.REFUSED
    assert anchor.heads == {}


@pytest.mark.asyncio
async def test_an_unkeyed_head_is_not_anchored_and_nothing_is_said(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    from sqlalchemy.orm import Session

    anchor = _Anchor()
    monkeypatch.setattr(audit_anchor, "configured", lambda: anchor)
    engine = _sqlite()
    before = observability.counters.audit_anchor_failures
    with Session(engine) as sync:
        db = SimpleNamespace(sync_session=sync, bind=_Engine(engine))
        rows = _chain_rows([{"n": 0}], [uuid.uuid4()])
        audit_anchor.anchor_after_commit(db, _head(rows) | {"key_id": None})
        assert audit_anchor._HEAD not in sync.info
        assert audit_anchor._HOOKED not in sync.info
    assert observability.counters.audit_anchor_failures == before
    assert not [r for r in caplog.records if r.levelname == "ERROR"]


@pytest.mark.asyncio
async def test_a_rolled_back_savepoint_drops_the_head_waiting_to_be_anchored(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from sqlalchemy.orm import Session

    rows = _chain_rows([{"n": 0}], [uuid.uuid4()])
    engine = _database(rows)
    anchor = _Anchor()
    monkeypatch.setattr(audit_anchor, "configured", lambda: anchor)
    with Session(engine) as sync:
        db = SimpleNamespace(sync_session=sync, bind=_Engine(engine))
        sync.execute(sa.text("SELECT 1"))
        savepoint = sync.begin_nested()
        audit_anchor.anchor_after_commit(db, _head(rows))
        savepoint.rollback()
        assert audit_anchor._HEAD not in sync.info
        sync.commit()
        await audit_anchor.drain()
    assert anchor.heads == {}

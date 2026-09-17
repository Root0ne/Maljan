"""``job_events`` and the transcript's addressee: created, unique, reversible.

Chains onto ``20260924000000`` — the alembic head at the time the live feed
was given a table. Exercised against a throwaway in-memory SQLite database,
the same technique as ``test_evidence_entries_migration.py``: bind a plain
connection through ``MigrationContext`` and resolve the module's ``op`` calls
through ``Operations.context``.
"""

from __future__ import annotations

import importlib.util
import uuid
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.compiler import compiles


# SQLite has no JSONB and refuses to render one, so the throwaway database
# used here is told to read the column as plain JSON. The production DDL is
# unchanged — this only teaches the test's dialect how to spell the type.
@compiles(postgresql.JSONB, "sqlite")
def _jsonb_as_json(element, compiler, **kw):  # noqa: ANN001, ANN202
    return "JSON"


_API = Path(__file__).resolve().parents[3] / "apps" / "api"
_REV = _API / "alembic" / "versions" / "20260925000000_job_events_and_transcript_addressee.py"


def _load():
    spec = importlib.util.spec_from_file_location("job_events", _REV)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _tables(conn) -> None:
    conn.execute(sa.text("CREATE TABLE analysis_jobs (id TEXT PRIMARY KEY)"))
    conn.execute(sa.text("CREATE TABLE agent_messages (id TEXT PRIMARY KEY, seq INTEGER)"))
    conn.commit()


def _upgraded(conn):
    from alembic.operations import Operations
    from alembic.runtime.migration import MigrationContext

    module = _load()
    _tables(conn)
    with Operations.context(MigrationContext.configure(conn)):
        module.upgrade()
    return module


def _job(conn) -> str:
    job_id = str(uuid.uuid4())
    conn.execute(sa.text("INSERT INTO analysis_jobs (id) VALUES (:i)"), {"i": job_id})
    return job_id


def _event(conn, job_id: str, seq: int, event_type: str = "agent_message") -> None:
    conn.execute(
        sa.text(
            "INSERT INTO job_events (id, job_id, seq, type, payload, ts) "
            "VALUES (:id, :job, :seq, :type, '{}', '2026-09-25T00:00:00+00:00')"
        ),
        {"id": str(uuid.uuid4()), "job": job_id, "seq": seq, "type": event_type},
    )


def test_this_revision_chains_onto_the_real_alembic_head() -> None:
    versions = _API / "alembic" / "versions"
    module = _load()
    assert module.down_revision == "20260924000000"
    for path in versions.glob("*.py"):
        if path == _REV:
            continue
        if 'down_revision = "20260924000000"' in path.read_text(encoding="utf-8"):
            raise AssertionError(f"{path.name} also chains onto 20260924000000 — no longer head")


def test_the_revision_imports_no_application_code() -> None:
    text = _REV.read_text(encoding="utf-8")
    assert "maljan" not in text
    assert "from app" not in text


def test_upgrade_creates_the_expected_columns() -> None:
    engine = sa.create_engine("sqlite://")
    with engine.connect() as conn:
        _upgraded(conn)
        columns = {c["name"]: c for c in sa.inspect(conn).get_columns("job_events")}
        assert set(columns) == {
            "id",
            "created_at",
            "updated_at",
            "job_id",
            "seq",
            "type",
            "payload",
            "ts",
        }
        # A feed entry that carried no data and one published before the clock
        # was read are both real; everything that orders the feed is not.
        assert columns["payload"]["nullable"] is True
        assert columns["ts"]["nullable"] is True
        for name in ("id", "job_id", "seq", "type"):
            assert columns[name]["nullable"] is False, name


def test_one_job_cannot_hold_the_same_sequence_number_twice() -> None:
    engine = sa.create_engine("sqlite://")
    with engine.connect() as conn:
        _upgraded(conn)
        job_id = _job(conn)
        _event(conn, job_id, 1)
        with pytest.raises(sa.exc.IntegrityError):
            _event(conn, job_id, 1)


def test_two_jobs_may_each_start_at_one() -> None:
    engine = sa.create_engine("sqlite://")
    with engine.connect() as conn:
        _upgraded(conn)
        first, second = _job(conn), _job(conn)
        _event(conn, first, 1)
        _event(conn, second, 1)
        conn.commit()
        assert conn.execute(sa.text("SELECT COUNT(*) FROM job_events")).scalar_one() == 2


def test_a_feed_reads_back_in_sequence_order() -> None:
    engine = sa.create_engine("sqlite://")
    with engine.connect() as conn:
        _upgraded(conn)
        job_id = _job(conn)
        for seq, event_type in ((3, "completed"), (1, "roster"), (2, "agent_message")):
            _event(conn, job_id, seq, event_type)
        conn.commit()
        rows = conn.execute(
            sa.text("SELECT type FROM job_events WHERE job_id = :j ORDER BY seq"), {"j": job_id}
        ).all()
        assert [r.type for r in rows] == ["roster", "agent_message", "completed"]


def test_the_transcript_gains_an_addressee_that_old_rows_may_leave_empty() -> None:
    engine = sa.create_engine("sqlite://")
    with engine.connect() as conn:
        _upgraded(conn)
        columns = {c["name"]: c for c in sa.inspect(conn).get_columns("agent_messages")}
        assert "addressed_to" in columns
        assert columns["addressed_to"]["nullable"] is True
        conn.execute(
            sa.text("INSERT INTO agent_messages (id, seq) VALUES (:i, 0)"),
            {"i": str(uuid.uuid4())},
        )
        conn.commit()
        assert conn.execute(sa.text("SELECT addressed_to FROM agent_messages")).scalar_one() is None


def test_upgrade_downgrade_upgrade_is_a_clean_round_trip() -> None:
    from alembic.operations import Operations
    from alembic.runtime.migration import MigrationContext

    engine = sa.create_engine("sqlite://")
    with engine.connect() as conn:
        module = _upgraded(conn)
        ctx = MigrationContext.configure(conn)
        assert "job_events" in sa.inspect(conn).get_table_names()

        with Operations.context(ctx):
            module.downgrade()
        assert "job_events" not in sa.inspect(conn).get_table_names()
        assert "addressed_to" not in {
            c["name"] for c in sa.inspect(conn).get_columns("agent_messages")
        }

        with Operations.context(ctx):
            module.upgrade()
        assert "job_events" in sa.inspect(conn).get_table_names()

        with Operations.context(ctx):
            module.downgrade()
        assert "job_events" not in sa.inspect(conn).get_table_names()

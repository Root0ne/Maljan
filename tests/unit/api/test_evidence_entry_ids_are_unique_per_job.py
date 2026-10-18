"""A job's ledger holds each entry id and each sequence number once.

The revision runs on a throwaway SQLite database whose ``evidence_entries``
table is built by the revision that created it. On a clean table it adds both
constraints; on a seeded duplicate it stops, names the job, and changes
nothing; the downgrade takes the constraints away again.
"""

from __future__ import annotations

import importlib.util
import uuid
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic.operations import Operations
from alembic.runtime.migration import MigrationContext
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.compiler import compiles


@compiles(postgresql.JSONB, "sqlite")
def _jsonb_as_json(element, compiler, **kw):  # noqa: ANN001, ANN202
    return "JSON"


_VERSIONS = Path(__file__).resolve().parents[3] / "apps" / "api" / "alembic" / "versions"
_CREATE = _VERSIONS / "20260914000000_add_evidence_entries.py"
_REV = _VERSIONS / "20261018000000_evidence_entry_ids_are_unique_per_job.py"
_NAMES = {"uq_evidence_entries_job_entry_id", "uq_evidence_entries_job_seq"}


def _load(path: Path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(conn, path: Path, step: str) -> None:
    mod = _load(path)
    context = MigrationContext.configure(conn)
    with Operations.context(context):
        mod.op = Operations(context)
        getattr(mod, step)()


def _table(conn) -> None:
    conn.execute(sa.text("CREATE TABLE analysis_jobs (id TEXT PRIMARY KEY)"))
    _run(conn, _CREATE, "upgrade")


def _insert(conn, job: str, entry_id: str, seq: int) -> None:
    conn.execute(
        sa.text(
            "INSERT INTO evidence_entries "
            "(id, job_id, entry_id, stage, agent, tool, ok, duration_ms, seq, output, "
            " created_at, updated_at) "
            "VALUES (:id, :job, :entry, 'analysis', 'static', 'pe_info', 1, 0, :seq, '', "
            " CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
        ),
        {"id": str(uuid.uuid4()), "job": job, "entry": entry_id, "seq": seq},
    )


def _unique_names(conn) -> set[str]:
    return {c["name"] for c in sa.inspect(conn).get_unique_constraints("evidence_entries")}


def _index_names(conn) -> set[str]:
    return {i["name"] for i in sa.inspect(conn).get_indexes("evidence_entries")}


def test_the_revision_follows_the_every_field_one():
    mod = _load(_REV)
    assert mod.revision == "20261018000000"
    assert mod.down_revision == "20261017000000"


def test_a_clean_table_gains_both_constraints_and_refuses_a_second_row():
    engine = sa.create_engine("sqlite://")
    with engine.connect() as conn:
        _table(conn)
        one, other = str(uuid.uuid4()), str(uuid.uuid4())
        _insert(conn, one, "ev_0001", 1)
        _insert(conn, one, "ev_0002", 2)
        # Another job issues the same ids from its own counter.
        _insert(conn, other, "ev_0001", 1)

        assert "ix_evidence_entries_job_seq" in _index_names(conn)
        _run(conn, _REV, "upgrade")
        assert _NAMES <= _unique_names(conn)
        # The constraint on (job_id, seq) makes the plain index redundant.
        assert "ix_evidence_entries_job_seq" not in _index_names(conn)
        assert conn.execute(sa.text("SELECT COUNT(*) FROM evidence_entries")).scalar() == 3

        with pytest.raises(sa.exc.IntegrityError):
            _insert(conn, one, "ev_0001", 3)
        with pytest.raises(sa.exc.IntegrityError):
            _insert(conn, one, "ev_0003", 2)


def test_a_stored_duplicate_stops_the_upgrade_naming_the_job_and_changing_nothing():
    engine = sa.create_engine("sqlite://")
    with engine.connect() as conn:
        _table(conn)
        clean, twice_id, twice_seq = (str(uuid.uuid4()) for _ in range(3))
        _insert(conn, clean, "ev_0001", 1)
        _insert(conn, twice_id, "ev_0001", 1)
        _insert(conn, twice_id, "ev_0001", 2)
        _insert(conn, twice_seq, "ev_0001", 1)
        _insert(conn, twice_seq, "ev_0002", 1)

        with pytest.raises(RuntimeError) as raised:
            _run(conn, _REV, "upgrade")

        reason = str(raised.value)
        assert "nothing was changed" in reason
        assert f"one entry_id: {twice_id}" in reason
        assert f"one seq: {twice_seq}" in reason
        assert clean not in reason
        assert not _NAMES & _unique_names(conn)
        assert "ix_evidence_entries_job_seq" in _index_names(conn)
        assert conn.execute(sa.text("SELECT COUNT(*) FROM evidence_entries")).scalar() == 5


def test_the_downgrade_takes_both_constraints_away():
    engine = sa.create_engine("sqlite://")
    with engine.connect() as conn:
        _table(conn)
        job = str(uuid.uuid4())
        _insert(conn, job, "ev_0001", 1)
        _run(conn, _REV, "upgrade")
        _run(conn, _REV, "downgrade")

        assert not _NAMES & _unique_names(conn)
        assert "ix_evidence_entries_job_seq" in _index_names(conn)
        _insert(conn, job, "ev_0001", 1)
        assert conn.execute(sa.text("SELECT COUNT(*) FROM evidence_entries")).scalar() == 2


def _postgres_sql(step: str) -> str:
    """What the revision does on PostgreSQL, as the offline SQL script it writes."""
    import io

    buffer = io.StringIO()
    mod = _load(_REV)
    context = MigrationContext.configure(
        dialect_name="postgresql", opts={"as_sql": True, "output_buffer": buffer}
    )
    with Operations.context(context):
        mod.op = Operations(context)
        getattr(mod, step)()
    return buffer.getvalue()


def test_on_postgres_the_indexes_are_built_concurrently_and_then_attached():
    sql = _postgres_sql("upgrade")
    for name, column in (
        ("uq_evidence_entries_job_entry_id", "entry_id"),
        ("uq_evidence_entries_job_seq", "seq"),
    ):
        built = f"CREATE UNIQUE INDEX CONCURRENTLY {name} ON evidence_entries (job_id, {column})"
        attached = f"ALTER TABLE evidence_entries ADD CONSTRAINT {name} UNIQUE USING INDEX {name}"
        assert built in sql
        assert attached in sql
        assert sql.index(built) < sql.index(attached)
    assert "DROP INDEX CONCURRENTLY IF EXISTS ix_evidence_entries_job_seq" in sql
    # Built outside the migration's transaction: a concurrent build refuses one.
    assert sql.index("COMMIT") < sql.index("CREATE UNIQUE INDEX CONCURRENTLY")


def test_on_postgres_the_downgrade_puts_the_plain_index_back_before_dropping_the_constraints():
    sql = _postgres_sql("downgrade")
    restored = (
        "CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_evidence_entries_job_seq "
        "ON evidence_entries (job_id, seq)"
    )
    assert restored in sql
    for name in ("uq_evidence_entries_job_entry_id", "uq_evidence_entries_job_seq"):
        dropped = f"ALTER TABLE evidence_entries DROP CONSTRAINT IF EXISTS {name}"
        assert dropped in sql
        assert sql.index(restored) < sql.index(dropped)

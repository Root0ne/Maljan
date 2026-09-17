"""The evidence table gains the failure text and the remedy, and loses them on the way down."""

from __future__ import annotations

import importlib.util
from pathlib import Path

MIGRATION = (
    Path(__file__).resolve().parents[3]
    / "apps/api/alembic/versions/20260922000000_evidence_error_columns.py"
)


def _module():
    spec = importlib.util.spec_from_file_location("evidence_error_columns", MIGRATION)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _connect():
    import sqlalchemy as sa

    engine = sa.create_engine("sqlite://")
    conn = engine.connect()
    conn.execute(
        sa.text(
            "CREATE TABLE evidence_entries ("
            "id TEXT PRIMARY KEY, job_id TEXT, entry_id TEXT, stage TEXT, agent TEXT, "
            "server TEXT, tool TEXT, ok BOOLEAN, duration_ms INTEGER, seq INTEGER, "
            "args TEXT, output TEXT, structured TEXT)"
        )
    )
    return conn


def _columns(conn) -> set[str]:
    import sqlalchemy as sa

    rows = conn.execute(sa.text("PRAGMA table_info(evidence_entries)")).fetchall()
    return {row[1] for row in rows}


def _run(mod, conn, direction="upgrade"):
    from alembic.operations import Operations
    from alembic.runtime.migration import MigrationContext

    ctx = MigrationContext.configure(conn)
    with Operations.context(ctx):
        getattr(mod, direction)()


def test_upgrade_adds_the_two_nullable_columns_and_keeps_old_rows():
    import sqlalchemy as sa

    conn = _connect()
    conn.execute(
        sa.text(
            "INSERT INTO evidence_entries (id, entry_id, tool, ok, output) "
            "VALUES ('1', 'ev_0001', 'hashes', 1, '{}')"
        )
    )
    _run(_module(), conn)
    assert {"error", "remediation"} <= _columns(conn)
    row = conn.execute(
        sa.text("SELECT error, remediation FROM evidence_entries WHERE id = '1'")
    ).fetchone()
    assert row == (None, None)


def test_downgrade_drops_them_again():
    conn = _connect()
    mod = _module()
    _run(mod, conn)
    _run(mod, conn, "downgrade")
    assert not {"error", "remediation"} & _columns(conn)


def test_the_revision_chains_after_the_lead_rename():
    mod = _module()
    assert mod.revision == "20260922000000"
    assert mod.down_revision == "20260921000000"

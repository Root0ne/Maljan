"""The ``evidence_entries`` table: created, indexed, dropped, re-creatable.

Chains onto ``20260913000000`` — the alembic head at the time the ledger was
added. Exercised against a throwaway in-memory SQLite database, the same
technique as ``test_sandbox_report_migration.py``: bind a plain connection
through ``MigrationContext`` and resolve the module's ``op`` calls through
``Operations.context``.
"""

from __future__ import annotations

import importlib.util
import uuid
from pathlib import Path

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
_REV = _API / "alembic" / "versions" / "20260914000000_add_evidence_entries.py"


def _load():
    spec = importlib.util.spec_from_file_location("add_evidence_entries", _REV)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _connect(conn) -> None:
    conn.execute(sa.text("CREATE TABLE analysis_jobs (id TEXT PRIMARY KEY)"))
    conn.commit()


def test_this_revision_chains_onto_the_real_alembic_head():
    versions_dir = _API / "alembic" / "versions"
    mod = _load()
    assert mod.down_revision == "20260913000000"
    for path in versions_dir.glob("*.py"):
        if path == _REV:
            continue
        text = path.read_text(encoding="utf-8")
        if 'down_revision = "20260913000000"' in text:
            raise AssertionError(f"{path.name} also chains onto 20260913000000 — no longer head")


def test_upgrade_creates_the_expected_columns_and_index():
    from alembic.operations import Operations
    from alembic.runtime.migration import MigrationContext

    mod = _load()
    engine = sa.create_engine("sqlite://")
    with engine.connect() as conn:
        _connect(conn)
        with Operations.context(MigrationContext.configure(conn)):
            mod.upgrade()

        columns = {c["name"]: c for c in sa.inspect(conn).get_columns("evidence_entries")}
        assert set(columns) == {
            "id",
            "created_at",
            "updated_at",
            "job_id",
            "entry_id",
            "stage",
            "agent",
            "server",
            "tool",
            "ok",
            "duration_ms",
            "seq",
            "args",
            "output",
            "structured",
        }
        # Only what a call may genuinely not have is nullable: an in-process
        # tool has no server, and a tool that answered prose has no structure.
        assert columns["server"]["nullable"] is True
        assert columns["structured"]["nullable"] is True
        assert columns["args"]["nullable"] is True
        for name in set(columns) - {"server", "structured", "args"}:
            assert columns[name]["nullable"] is False, name

        index_names = {i["name"] for i in sa.inspect(conn).get_indexes("evidence_entries")}
        assert "ix_evidence_entries_job_seq" in index_names


def test_rows_round_trip_and_read_back_in_call_order():
    from alembic.operations import Operations
    from alembic.runtime.migration import MigrationContext

    mod = _load()
    engine = sa.create_engine("sqlite://")
    with engine.connect() as conn:
        _connect(conn)
        with Operations.context(MigrationContext.configure(conn)):
            mod.upgrade()

        job_id = str(uuid.uuid4())
        conn.execute(sa.text("INSERT INTO analysis_jobs (id) VALUES (:i)"), {"i": job_id})
        for seq, (entry_id, agent, tool) in enumerate(
            [("ev_0002", "dynamic", "sandbox_network"), ("ev_0001", "static", "pe_info")], start=1
        ):
            conn.execute(
                sa.text(
                    "INSERT INTO evidence_entries "
                    "(id, job_id, entry_id, stage, agent, server, tool, ok, "
                    " duration_ms, seq, args, output, structured) "
                    "VALUES (:id, :job, :entry, 'analysis', :agent, NULL, :tool, 1, "
                    " 5, :seq, '{}', 'out', NULL)"
                ),
                {
                    "id": str(uuid.uuid4()),
                    "job": job_id,
                    "entry": entry_id,
                    "agent": agent,
                    "tool": tool,
                    # Reversed on purpose: the endpoint orders by ``seq``, not
                    # by insertion order.
                    "seq": 2 if seq == 1 else 1,
                },
            )
        conn.commit()

        rows = conn.execute(
            sa.text("SELECT entry_id FROM evidence_entries WHERE job_id = :j ORDER BY seq"),
            {"j": job_id},
        ).all()
        assert [r.entry_id for r in rows] == ["ev_0001", "ev_0002"]


def test_upgrade_downgrade_upgrade_is_a_clean_round_trip():
    from alembic.operations import Operations
    from alembic.runtime.migration import MigrationContext

    mod = _load()
    engine = sa.create_engine("sqlite://")
    with engine.connect() as conn:
        _connect(conn)
        ctx = MigrationContext.configure(conn)

        with Operations.context(ctx):
            mod.upgrade()
        assert "evidence_entries" in sa.inspect(conn).get_table_names()

        with Operations.context(ctx):
            mod.downgrade()
        assert "evidence_entries" not in sa.inspect(conn).get_table_names()

        with Operations.context(ctx):
            mod.upgrade()
        assert {i["name"] for i in sa.inspect(conn).get_indexes("evidence_entries")} == {
            "ix_evidence_entries_job_seq"
        }

        with Operations.context(ctx):
            mod.downgrade()
        assert "evidence_entries" not in sa.inspect(conn).get_table_names()

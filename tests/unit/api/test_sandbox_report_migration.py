"""The ``sandbox_reports`` table: created, dropped and cleanly re-created.

Chains onto ``20260903000000`` (Task 4's provider-setting-key rename) — the
real alembic head at the time this table was added; nothing in the tree
declares that revision as its own ``down_revision``. Exercised against a
throwaway in-memory SQLite database, never the developer database: the same
technique as ``test_settings_key_migration.py`` — bind a plain connection
through ``MigrationContext`` and resolve the module's ``op`` calls through
``Operations.context``.
"""

from __future__ import annotations

import importlib.util
import sys
import uuid
from pathlib import Path

import sqlalchemy as sa

_API = Path(__file__).resolve().parents[3] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

_REV = _API / "alembic" / "versions" / "20260904000000_add_sandbox_reports.py"


def _load():
    spec = importlib.util.spec_from_file_location("add_sandbox_reports", _REV)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_this_revision_chains_onto_the_real_alembic_head():
    """Nothing else in the tree points at 20260903000000 as its down_revision."""
    versions_dir = _API / "alembic" / "versions"
    mod = _load()
    assert mod.down_revision == "20260903000000"
    for path in versions_dir.glob("*.py"):
        if path == _REV:
            continue
        text = path.read_text(encoding="utf-8")
        if 'down_revision = "20260903000000"' in text:
            raise AssertionError(f"{path.name} also chains onto 20260903000000 — no longer head")


def test_upgrade_creates_the_expected_columns():
    from alembic.operations import Operations
    from alembic.runtime.migration import MigrationContext

    mod = _load()
    engine = sa.create_engine("sqlite://")
    with engine.connect() as conn:
        conn.execute(sa.text("CREATE TABLE users (id TEXT PRIMARY KEY)"))
        conn.execute(sa.text("CREATE TABLE samples (id TEXT PRIMARY KEY)"))
        conn.commit()

        ctx = MigrationContext.configure(conn)
        with Operations.context(ctx):
            mod.upgrade()

        columns = {c["name"]: c for c in sa.inspect(conn).get_columns("sandbox_reports")}
        assert set(columns) == {
            "id",
            "created_at",
            "updated_at",
            "sample_id",
            "storage_path",
            "format",
            "task_id",
            "size_bytes",
            "sha256_of_blob",
            "sample_sha256_match",
            "uploaded_by",
        }
        # Every column is required except the one that a Cuckoo/CAPE report
        # (rather than Triage) may simply not carry.
        assert columns["task_id"]["nullable"] is True
        for name in set(columns) - {"task_id"}:
            assert columns[name]["nullable"] is False, name

        index_names = {i["name"] for i in sa.inspect(conn).get_indexes("sandbox_reports")}
        assert "ix_sandbox_reports_sample_id" in index_names


def test_a_row_round_trips_including_the_match_flag():
    from alembic.operations import Operations
    from alembic.runtime.migration import MigrationContext

    mod = _load()
    engine = sa.create_engine("sqlite://")
    with engine.connect() as conn:
        conn.execute(sa.text("CREATE TABLE users (id TEXT PRIMARY KEY)"))
        conn.execute(sa.text("CREATE TABLE samples (id TEXT PRIMARY KEY)"))
        conn.commit()
        with Operations.context(MigrationContext.configure(conn)):
            mod.upgrade()

        sample_id, user_id, report_id = (str(uuid.uuid4()) for _ in range(3))
        conn.execute(sa.text("INSERT INTO samples (id) VALUES (:i)"), {"i": sample_id})
        conn.execute(sa.text("INSERT INTO users (id) VALUES (:i)"), {"i": user_id})
        conn.execute(
            sa.text(
                "INSERT INTO sandbox_reports "
                "(id, sample_id, storage_path, format, task_id, size_bytes, "
                " sha256_of_blob, sample_sha256_match, uploaded_by) "
                "VALUES (:id, :sample_id, :path, :fmt, :task, :size, :sha, :match, :user)"
            ),
            {
                "id": report_id,
                "sample_id": sample_id,
                "path": "sandbox-reports/aa/" + "a" * 64 + "/x.json",
                "fmt": "cape2",
                "task": "42",
                "size": 10,
                "sha": "a" * 64,
                "match": False,
                "user": user_id,
            },
        )
        conn.commit()

        row = conn.execute(
            sa.text(
                "SELECT format, sample_sha256_match, task_id FROM sandbox_reports WHERE id = :id"
            ),
            {"id": report_id},
        ).one()
        assert row.format == "cape2"
        assert bool(row.sample_sha256_match) is False
        assert row.task_id == "42"


def test_upgrade_downgrade_upgrade_is_a_clean_round_trip():
    """Reversible: downgrade removes exactly what upgrade added, and it can
    be re-applied afterwards with no left-over state from the first pass."""
    from alembic.operations import Operations
    from alembic.runtime.migration import MigrationContext

    mod = _load()
    engine = sa.create_engine("sqlite://")
    with engine.connect() as conn:
        conn.execute(sa.text("CREATE TABLE users (id TEXT PRIMARY KEY)"))
        conn.execute(sa.text("CREATE TABLE samples (id TEXT PRIMARY KEY)"))
        conn.commit()
        ctx = MigrationContext.configure(conn)

        with Operations.context(ctx):
            mod.upgrade()
        assert "sandbox_reports" in sa.inspect(conn).get_table_names()

        with Operations.context(ctx):
            mod.downgrade()
        assert "sandbox_reports" not in sa.inspect(conn).get_table_names()
        # The index goes with it — dropping the table alone would still leave
        # the index name registered on some backends if it were not dropped
        # explicitly first.
        assert "ix_sandbox_reports_sample_id" not in {
            i["name"] for i in sa.inspect(conn).get_indexes("samples")
        }

        with Operations.context(ctx):
            mod.upgrade()
        assert "sandbox_reports" in sa.inspect(conn).get_table_names()
        assert {i["name"] for i in sa.inspect(conn).get_indexes("sandbox_reports")} == {
            "ix_sandbox_reports_sample_id"
        }

        with Operations.context(ctx):
            mod.downgrade()
        assert "sandbox_reports" not in sa.inspect(conn).get_table_names()

"""``evidence_entries`` gains ``chars_dropped``, zero on every older row, and loses it again.

The revision runs on a bare table and never imports the application.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import sqlalchemy as sa
from alembic.operations import Operations
from alembic.runtime.migration import MigrationContext

_REV = (
    Path(__file__).resolve().parents[3]
    / "apps/api/alembic/versions/20261007000000_evidence_chars_dropped.py"
)


def _load():
    spec = importlib.util.spec_from_file_location("evidence_chars_dropped", _REV)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(conn, step) -> None:
    mod = _load()
    context = MigrationContext.configure(conn)
    with Operations.context(context):
        mod.op = Operations(context)
        step(mod)


def test_the_revision_follows_the_stage_mode_one():
    mod = _load()
    assert mod.revision == "20261007000000"
    assert mod.down_revision == "20261002000000"


def test_an_older_row_reads_zero_and_the_downgrade_takes_the_column_away():
    engine = sa.create_engine("sqlite://")
    with engine.connect() as conn:
        conn.execute(sa.text("CREATE TABLE evidence_entries (id INTEGER PRIMARY KEY, tool TEXT)"))
        conn.execute(sa.text("INSERT INTO evidence_entries (tool) VALUES ('decompile_function')"))

        _run(conn, lambda mod: mod.upgrade())
        assert conn.execute(sa.text("SELECT chars_dropped FROM evidence_entries")).scalar() == 0

        _run(conn, lambda mod: mod.downgrade())
        columns = [c["name"] for c in sa.inspect(conn).get_columns("evidence_entries")]
        assert "chars_dropped" not in columns

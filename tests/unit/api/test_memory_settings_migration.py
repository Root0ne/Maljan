"""The memory backend's stored settings move under its id, and back, row for row.

Run against a throwaway in-memory SQLite copy of the table, never a real
database. Each row keeps its value, its secret flag (the ciphertext untouched)
and its bookkeeping columns.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

import sqlalchemy as sa

MIGRATION = (
    Path(__file__).resolve().parents[3]
    / "apps/api/alembic/versions/20261010000000_memory_backend_settings_under_their_backend.py"
)
CIPHERTEXT = "gAAAAA" + "x" * 40


def _module() -> Any:
    spec = importlib.util.spec_from_file_location("memory_settings_move", MIGRATION)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _connect() -> Any:
    conn = sa.create_engine("sqlite://").connect()
    conn.execute(
        sa.text(
            "CREATE TABLE runtime_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL, "
            "is_secret BOOLEAN NOT NULL DEFAULT 0, updated_by TEXT, updated_at TEXT)"
        )
    )
    return conn


def _insert(conn: Any, key: str, value: Any, is_secret: bool = False) -> None:
    conn.execute(
        sa.text(
            "INSERT INTO runtime_settings VALUES (:k, :v, :s, 'admin-1', '2026-01-02T03:04:05')"
        ),
        {"k": key, "v": json.dumps(value), "s": is_secret},
    )


def _table(conn: Any) -> dict[str, tuple[Any, bool, str, str]]:
    rows = conn.execute(sa.text("SELECT * FROM runtime_settings")).fetchall()
    return {k: (json.loads(v), bool(s), by, at) for k, v, s, by, at in rows}


def _run(conn: Any, direction: str) -> None:
    from alembic.operations import Operations
    from alembic.runtime.migration import MigrationContext

    with Operations.context(MigrationContext.configure(conn)):
        getattr(_module(), direction)()


def _seed(conn: Any) -> None:
    _insert(conn, "core.memory.backend", "qdrant")
    _insert(conn, "core.memory.qdrant_url", "http://qdrant:6333")
    _insert(conn, "core.memory.qdrant_collection", "cases")
    _insert(conn, "core.memory.qdrant_function_hash_collection", "hashes")
    _insert(conn, "core.memory.qdrant_api_key", CIPHERTEXT, is_secret=True)


def test_the_revision_follows_the_head_it_was_written_on() -> None:
    mod = _module()
    assert (mod.revision, mod.down_revision) == ("20261010000000", "20261009000000")


def test_every_moved_key_is_one_the_catalogue_holds() -> None:
    from maljan.core.settings_annotations import RENAMED_SETTINGS
    from maljan.core.settings_catalog import core_catalog

    keys = {e.key for e in core_catalog()}
    memory = {o: n for o, n in RENAMED_SETTINGS.items() if o.startswith("core.memory.")}
    assert _module().MOVES == memory
    assert set(RENAMED_SETTINGS.values()) <= keys
    assert not set(RENAMED_SETTINGS) & keys


def test_upgrade_renames_each_row_keeping_everything_it_holds() -> None:
    conn = _connect()
    _seed(conn)
    _run(conn, "upgrade")
    table = _table(conn)
    assert set(table) == {
        "core.memory.backend",
        "core.memory.qdrant.url",
        "core.memory.qdrant.collection",
        "core.memory.qdrant.function_hash_collection",
        "core.memory.qdrant.api_key",
    }
    assert table["core.memory.qdrant.url"] == (
        "http://qdrant:6333",
        False,
        "admin-1",
        "2026-01-02T03:04:05",
    )
    assert table["core.memory.qdrant.api_key"][:2] == (CIPHERTEXT, True)


def test_the_upgraded_rows_read_back_as_the_same_configuration() -> None:
    from maljan.core.settings_overrides import build_settings

    conn = _connect()
    _seed(conn)
    before = build_settings(
        {k.removeprefix("core."): v[0] for k, v in _table(conn).items() if "api_key" not in k}
    )
    _run(conn, "upgrade")
    after = build_settings(
        {k.removeprefix("core."): v[0] for k, v in _table(conn).items() if "api_key" not in k}
    )
    assert after.memory.model_dump() == before.memory.model_dump()


def test_downgrade_puts_every_row_back() -> None:
    conn = _connect()
    _seed(conn)
    original = _table(conn)
    _run(conn, "upgrade")
    _run(conn, "downgrade")
    assert _table(conn) == original


def test_running_twice_changes_nothing_more() -> None:
    conn = _connect()
    _seed(conn)
    _run(conn, "upgrade")
    once = _table(conn)
    _run(conn, "upgrade")
    assert _table(conn) == once


def test_a_new_key_already_held_keeps_its_row_and_the_old_one_goes() -> None:
    conn = _connect()
    _insert(conn, "core.memory.qdrant_url", "http://old:6333")
    _insert(conn, "core.memory.qdrant.url", "http://new:6333")
    _run(conn, "upgrade")
    table = _table(conn)
    assert table["core.memory.qdrant.url"][0] == "http://new:6333"
    assert "core.memory.qdrant_url" not in table


def test_a_database_with_nothing_stored_is_left_alone() -> None:
    conn = _connect()
    _insert(conn, "core.memory.top_k", 5)
    _run(conn, "upgrade")
    assert set(_table(conn)) == {"core.memory.top_k"}

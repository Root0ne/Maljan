"""radare2's stored ``mirror_dir`` is read as its ``work_dir``, by the model and by the store.

The migration is run against a throwaway in-memory SQLite copy of the table,
never a real database. The settings model, the import path and the migration
read an old value the same way.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

import sqlalchemy as sa

MIGRATION = (
    Path(__file__).resolve().parents[3]
    / "apps/api/alembic/versions/20261026000000_r2_mirror_dir_is_its_work_dir.py"
)
OLD = "core.static.r2.mirror_dir"
NEW = "core.static.r2.work_dir"


def _module() -> Any:
    spec = importlib.util.spec_from_file_location("r2_work_dir_move", MIGRATION)
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
        sa.text("INSERT INTO runtime_settings VALUES (:k, :v, :s, 'admin-1', '2026-01-02')"),
        {"k": key, "v": json.dumps(value), "s": is_secret},
    )


def _table(conn: Any) -> dict[str, tuple[Any, bool, str]]:
    rows = conn.execute(sa.text("SELECT key, value, is_secret, updated_by FROM runtime_settings"))
    return {k: (json.loads(v), bool(s), by) for k, v, s, by in rows.fetchall()}


def _run(conn: Any, direction: str) -> None:
    from alembic.operations import Operations
    from alembic.runtime.migration import MigrationContext

    with Operations.context(MigrationContext.configure(conn)):
        getattr(_module(), direction)()


def test_the_revision_follows_the_head_it_was_written_on() -> None:
    mod = _module()
    assert (mod.revision, mod.down_revision) == ("20261026000000", "20261025000000")
    assert (mod.OLD_KEY, mod.NEW_KEY) == (OLD, NEW)


def test_the_moved_key_is_the_one_the_settings_rename_names_and_the_new_one_is_held() -> None:
    from maljan.core.settings_annotations import RENAMED_SETTING_VALUES, RENAMED_SETTINGS
    from maljan.core.settings_catalog import core_catalog

    keys = {e.key for e in core_catalog()}
    assert RENAMED_SETTINGS[OLD] == NEW
    assert NEW in keys and OLD not in keys
    assert OLD in RENAMED_SETTING_VALUES


def test_upgrade_renames_the_row_to_its_last_segment_keeping_the_rest() -> None:
    conn = _connect()
    _insert(conn, OLD, "data/samples/r2-elsewhere")
    _insert(conn, "core.static.provider", "r2")
    _run(conn, "upgrade")
    assert _table(conn) == {
        NEW: ("r2-elsewhere", False, "admin-1"),
        "core.static.provider": ("r2", False, "admin-1"),
    }


def test_the_migration_and_the_model_read_a_value_the_same_way() -> None:
    from maljan.core.config import StaticR2Config

    mod = _module()
    for value in ("data/samples/r2-x", "r2-x", "./a/b/r2-x/", "data\\samples\\r2-x"):
        assert mod._last_segment(value) == StaticR2Config(mirror_dir=value).work_dir


def test_a_newer_work_dir_row_keeps_and_the_old_row_goes() -> None:
    conn = _connect()
    _insert(conn, OLD, "data/samples/old")
    _insert(conn, NEW, "new")
    _run(conn, "upgrade")
    assert _table(conn) == {NEW: ("new", False, "admin-1")}


def test_a_value_that_names_no_directory_is_left_for_the_model_to_refuse() -> None:
    conn = _connect()
    _insert(conn, OLD, "data/samples/..")
    _run(conn, "upgrade")
    assert list(_table(conn)) == [OLD]


def test_running_it_again_finds_nothing_to_move() -> None:
    conn = _connect()
    _insert(conn, OLD, "data/samples/r2-elsewhere")
    _run(conn, "upgrade")
    before = _table(conn)
    _run(conn, "upgrade")
    assert _table(conn) == before


def test_downgrade_writes_the_old_key_back_and_leaves_the_work_dir_row() -> None:
    conn = _connect()
    _insert(conn, NEW, "r2-elsewhere")
    _run(conn, "downgrade")
    table = _table(conn)
    assert table[OLD][0] == "data/samples/r2-elsewhere"
    assert table[NEW][0] == "r2-elsewhere"


def test_an_import_of_an_old_export_reads_the_old_key_as_the_new_one() -> None:
    from app.api.v1.settings import _current_keys

    assert _current_keys({OLD: "data/samples/r2-elsewhere"}) == {NEW: "r2-elsewhere"}
    assert _current_keys({OLD: "data/samples/old", NEW: "new"}) == {NEW: "new"}
    memory = _current_keys({"core.memory.qdrant_url": "http://q:6333"})
    assert memory == {"core.memory.qdrant.url": "http://q:6333"}

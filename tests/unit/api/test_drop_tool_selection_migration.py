"""Stored tool-selection overrides are removed when the modes go away."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

MIGRATION = (
    Path(__file__).resolve().parents[3]
    / "apps/api/alembic/versions/20260913000000_drop_tool_selection_settings.py"
)


def _module():
    spec = importlib.util.spec_from_file_location("drop_tool_selection", MIGRATION)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _connect():
    """A throwaway in-memory SQLite database, never the developer database."""
    import sqlalchemy as sa

    engine = sa.create_engine("sqlite://")
    conn = engine.connect()
    conn.execute(
        sa.text(
            "CREATE TABLE runtime_settings ("
            "key TEXT PRIMARY KEY, value TEXT, is_secret BOOLEAN NOT NULL DEFAULT 0)"
        )
    )
    return conn


def _insert(conn, key, value):
    import sqlalchemy as sa

    conn.execute(
        sa.text("INSERT INTO runtime_settings (key, value, is_secret) VALUES (:k, :v, 0)"),
        {"k": key, "v": json.dumps(value)},
    )


def _rows(conn):
    import sqlalchemy as sa

    result = conn.execute(sa.text("SELECT key, value FROM runtime_settings")).fetchall()
    return {k: json.loads(v) for k, v in result}


def _upgrade(mod, conn):
    from alembic.operations import Operations
    from alembic.runtime.migration import MigrationContext

    ctx = MigrationContext.configure(conn)
    with Operations.context(ctx):
        mod.upgrade()


def test_the_flat_rows_name_both_static_leaves():
    mod = _module()
    assert set(mod.FLAT_KEYS) == {
        "core.static.ghidra.tool_selection",
        "core.static.ghidra.use_all_tools",
        "core.static.r2.tool_selection",
        "core.static.r2.use_all_tools",
    }


def test_the_upgrade_strips_the_leaves_and_is_idempotent():
    mod = _module()
    conn = _connect()
    _insert(conn, "core.static.ghidra.tool_selection", "curated")
    _insert(conn, "core.static.ghidra.use_all_tools", True)
    _insert(conn, "core.static.r2.tool_selection", "all")
    _insert(conn, "core.static.r2.binary_path", "/opt/r2mcp")
    _insert(
        conn,
        "core.mcp.servers",
        {
            "network": {"enabled": True, "tool_selection": "dynamic", "use_all_tools": False},
            "custom": {"enabled": True, "command": "my-mcp", "tool_selection": "curated"},
        },
    )
    conn.commit()

    _upgrade(mod, conn)
    first = _rows(conn)
    _upgrade(mod, conn)
    second = _rows(conn)

    assert first == second
    assert first["core.static.r2.binary_path"] == "/opt/r2mcp"
    assert not any(key in first for key in mod.FLAT_KEYS)
    assert first["core.mcp.servers"] == {
        "network": {"enabled": True},
        "custom": {"enabled": True, "command": "my-mcp"},
    }


def test_an_empty_store_is_left_alone():
    mod = _module()
    conn = _connect()
    _upgrade(mod, conn)
    assert _rows(conn) == {}

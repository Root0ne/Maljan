"""Stored builtin sidecar paths under core.mcp.servers follow services/."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

MIGRATION = (
    Path(__file__).resolve().parents[3]
    / "apps/api/alembic/versions/20260906000000_move_builtin_sidecar_paths.py"
)


def _module():
    spec = importlib.util.spec_from_file_location("move_sidecar_paths", MIGRATION)
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


def _insert(conn, key, value, *, secret=False):
    import sqlalchemy as sa

    conn.execute(
        sa.text("INSERT INTO runtime_settings (key, value, is_secret) VALUES (:k, :v, :s)"),
        {"k": key, "v": json.dumps(value), "s": secret},
    )


def _servers(conn):
    import sqlalchemy as sa

    row = conn.execute(
        sa.text("SELECT value FROM runtime_settings WHERE key = :k"), {"k": "core.mcp.servers"}
    ).fetchone()
    return json.loads(row[0]) if row is not None else None


def _old_servers_map():
    return {
        "network": {
            "enabled": True,
            "transport": "stdio",
            "command": "/usr/bin/python3",
            "args": ["network-mcp/server.py"],
            "cwd": "network-mcp",
            "agents": ["network"],
            "label": "Network MCP",
        },
        "threatintel": {
            "enabled": True,
            "transport": "stdio",
            "command": "/usr/bin/python3",
            "args": ["threatintel-mcp/server.py"],
            "cwd": "threatintel-mcp",
            "env_allow": ["VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY"],
            "agents": ["judge"],
            "label": "Threat intel MCP",
        },
        "custom": {
            "enabled": False,
            "transport": "stdio",
            "command": "",
            "args": [],
            "cwd": "",
            "agents": [],
            "label": "",
        },
        "generic-http": {
            "enabled": True,
            "transport": "http",
            "url": "https://example.internal/mcp",
            "agents": ["static"],
            "label": "Generic HTTP",
        },
    }


def test_the_upgrade_rewrites_only_the_two_stale_paths_and_leaves_the_rest_alone():
    from alembic.operations import Operations
    from alembic.runtime.migration import MigrationContext

    mod = _module()
    conn = _connect()
    _insert(conn, "core.mcp.servers", _old_servers_map())
    conn.commit()

    ctx = MigrationContext.configure(conn)
    with Operations.context(ctx):
        mod.upgrade()

    servers = _servers(conn)
    assert servers["network"]["cwd"] == "services/network-mcp"
    assert servers["network"]["args"] == ["services/network-mcp/server.py"]
    assert servers["threatintel"]["cwd"] == "services/threatintel-mcp"
    assert servers["threatintel"]["args"] == ["services/threatintel-mcp/server.py"]
    # Unrelated fields on the rewritten entries are untouched.
    assert servers["network"]["command"] == "/usr/bin/python3"
    assert servers["network"]["agents"] == ["network"]
    assert servers["threatintel"]["env_allow"] == ["VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY"]
    # Entries with no stale path are byte-for-byte unchanged.
    assert servers["custom"] == _old_servers_map()["custom"]
    assert servers["generic-http"] == _old_servers_map()["generic-http"]


def test_an_override_already_on_the_new_paths_is_left_byte_for_byte_and_not_rewritten():
    from alembic.operations import Operations
    from alembic.runtime.migration import MigrationContext

    mod = _module()
    conn = _connect()
    new_map = _old_servers_map()
    new_map["network"]["cwd"] = "services/network-mcp"
    new_map["network"]["args"] = ["services/network-mcp/server.py"]
    new_map["threatintel"]["cwd"] = "services/threatintel-mcp"
    new_map["threatintel"]["args"] = ["services/threatintel-mcp/server.py"]
    _insert(conn, "core.mcp.servers", new_map)
    conn.commit()

    ctx = MigrationContext.configure(conn)
    with Operations.context(ctx):
        mod.upgrade()

    assert _servers(conn) == new_map


def test_no_override_row_means_no_error_and_no_write():
    from alembic.operations import Operations
    from alembic.runtime.migration import MigrationContext

    mod = _module()
    conn = _connect()
    conn.commit()

    ctx = MigrationContext.configure(conn)
    with Operations.context(ctx):
        mod.upgrade()

    assert _servers(conn) is None


def test_the_downgrade_reverses_the_upgrade():
    from alembic.operations import Operations
    from alembic.runtime.migration import MigrationContext

    mod = _module()
    conn = _connect()
    old_map = _old_servers_map()
    _insert(conn, "core.mcp.servers", old_map)
    conn.commit()

    ctx = MigrationContext.configure(conn)
    with Operations.context(ctx):
        mod.upgrade()
    with Operations.context(ctx):
        mod.downgrade()

    assert _servers(conn) == old_map

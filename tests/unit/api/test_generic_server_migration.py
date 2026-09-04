"""Stored UI overrides for static.generic become the custom server's."""

from __future__ import annotations

import importlib.util
import json
import logging
from pathlib import Path

MIGRATION = (
    Path(__file__).resolve().parents[3]
    / "apps/api/alembic/versions/20260905000000_move_generic_mcp_server_overrides.py"
)


def _module():
    spec = importlib.util.spec_from_file_location("move_generic", MIGRATION)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_every_moved_leaf_is_named_and_points_into_the_custom_server():
    renames = _module().KEY_RENAMES
    assert renames["core.static.generic.command"] == "core.mcp.servers.custom.command"
    assert renames["core.static.generic.auth_token"] == "core.mcp.servers.custom.auth_token"
    assert renames["core.static.generic.tool_selection"] == (
        "core.mcp.servers.custom.tool_selection"
    )
    assert len(renames) == 9, "the nine MCPServerConfig leaves sub-project A stored"


def test_the_reference_row_is_written_alongside_the_move():
    mod = _module()
    assert mod.REFERENCE_KEY == "core.static.generic.server"
    assert mod.REFERENCE_VALUE == "custom"


def _connect():
    """A throwaway in-memory SQLite database, never the developer database.

    Same technique ``test_settings_key_migration.py`` uses for the
    ``20260903000000`` revision: bind a plain connection through
    ``MigrationContext`` and resolve the module's ``op`` calls through
    ``Operations.context``.
    """
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


def _rows(conn):
    import sqlalchemy as sa

    result = conn.execute(sa.text("SELECT key, value FROM runtime_settings")).fetchall()
    return {k: json.loads(v) for k, v in result}


def test_the_upgrade_folds_the_nine_rows_into_one_json_document_and_is_idempotent(caplog):
    """Exercises the plain (non-secret) leaves branch of ``upgrade()``.

    Every leaf here is an ordinary value (no ``is_secret`` row among them), so
    this covers the fold-and-delete path end to end: nine dotted rows become
    one ``core.mcp.servers`` document plus the reference row, a second pass
    changes nothing, and ``downgrade`` reverses it.
    """
    from alembic.operations import Operations
    from alembic.runtime.migration import MigrationContext

    mod = _module()
    conn = _connect()
    _insert(conn, "core.static.generic.enabled", True)
    _insert(conn, "core.static.generic.transport", "stdio")
    _insert(conn, "core.static.generic.command", "my-mcp")
    _insert(conn, "core.static.generic.args", ["--stdio"])
    _insert(conn, "core.static.generic.env", {"A": "b"})
    _insert(conn, "core.static.generic.tool_selection", "dynamic")
    _insert(conn, "core.static.generic.use_all_tools", False)
    conn.commit()

    ctx = MigrationContext.configure(conn)
    with Operations.context(ctx):
        mod.upgrade()
    first_pass = _rows(conn)
    with Operations.context(ctx):
        mod.upgrade()  # second pass: must change nothing
    second_pass = _rows(conn)

    assert first_pass == second_pass
    server = first_pass["core.mcp.servers"]["custom"]
    assert server["command"] == "my-mcp"
    assert server["args"] == ["--stdio"]
    assert server["env"] == {"A": "b"}
    assert server["agents"] == ["static"]
    assert first_pass["core.static.generic.server"] == "custom"
    for leaf in mod.KEY_RENAMES:
        assert leaf not in first_pass

    with Operations.context(ctx):
        mod.downgrade()
    reverted = _rows(conn)
    assert reverted["core.static.generic.command"] == "my-mcp"
    assert "core.mcp.servers" not in reverted or "custom" not in reverted.get(
        "core.mcp.servers", {}
    )
    assert "core.static.generic.server" not in reverted


def test_a_secret_auth_token_row_is_dropped_not_folded_in_clear(caplog):
    """Exercises the ``is_secret`` branch of ``upgrade()``.

    The stored ``auth_token`` is Fernet-encrypted and marked ``is_secret`` --
    exactly the operator data sub-project A produced when the field was
    saved through the UI. It must never land inside the plain
    ``core.mcp.servers`` document, and the drop is logged by key only.
    """
    from alembic.operations import Operations
    from alembic.runtime.migration import MigrationContext

    mod = _module()
    conn = _connect()
    _insert(conn, "core.static.generic.command", "my-mcp")
    _insert(conn, "core.static.generic.auth_token", "enc:v1:SECRET", secret=True)
    conn.commit()

    ctx = MigrationContext.configure(conn)
    with caplog.at_level(logging.WARNING):
        with Operations.context(ctx):
            mod.upgrade()

    rows = _rows(conn)
    server = rows["core.mcp.servers"]["custom"]
    assert server["command"] == "my-mcp"
    assert "auth_token" not in server
    assert "core.static.generic.auth_token" not in rows
    assert "core.static.generic.auth_token" in caplog.text
    assert "SECRET" not in caplog.text


def test_an_unrelated_server_already_in_the_map_is_left_byte_for_byte_alone():
    """The registry leaf is one JSON document shared by every server.

    Folding ``custom`` in must not touch a sibling key already sitting in
    that same document -- an operator-configured ``netmon`` entry here,
    standing in for any server the catalog already knows about.
    """
    from alembic.operations import Operations
    from alembic.runtime.migration import MigrationContext

    mod = _module()
    conn = _connect()
    netmon = {"enabled": True, "agents": ["network"], "command": "netmon-mcp"}
    _insert(conn, "core.mcp.servers", {"netmon": netmon})
    _insert(conn, "core.static.generic.enabled", True)
    _insert(conn, "core.static.generic.transport", "stdio")
    _insert(conn, "core.static.generic.command", "my-mcp")
    _insert(conn, "core.static.generic.args", ["--stdio"])
    _insert(conn, "core.static.generic.env", {"A": "b"})
    _insert(conn, "core.static.generic.url", "")
    _insert(conn, "core.static.generic.tool_selection", "dynamic")
    _insert(conn, "core.static.generic.use_all_tools", False)
    conn.commit()

    ctx = MigrationContext.configure(conn)
    with Operations.context(ctx):
        mod.upgrade()

    servers = _rows(conn)["core.mcp.servers"]
    assert servers["netmon"] == netmon, "the unrelated entry must be unchanged, byte for byte"
    custom = servers["custom"]
    assert custom["command"] == "my-mcp"
    assert custom["args"] == ["--stdio"]
    assert custom["env"] == {"A": "b"}
    assert custom["transport"] == "stdio"
    assert custom["tool_selection"] == "dynamic"
    assert custom["agents"] == ["static"]
    assert _rows(conn)["core.static.generic.server"] == "custom"


def test_an_existing_custom_entry_is_merged_not_replaced():
    """A ``custom`` server already carries operator state (``label``, probed
    ``tools``) the legacy block never had a slot for; the migration must not
    clobber it. On the nine folded fields themselves, the legacy row is the
    operator's most recent UI state (set through the old static.generic form,
    after whatever produced the existing ``custom`` entry), so it wins over
    what the ``custom`` entry already held for the same field.
    """
    from alembic.operations import Operations
    from alembic.runtime.migration import MigrationContext

    mod = _module()
    conn = _connect()
    existing_custom = {
        "label": "Mine",
        "tools": ["a"],
        "command": "old-mcp",
        "enabled": False,
    }
    _insert(conn, "core.mcp.servers", {"custom": existing_custom})
    _insert(conn, "core.static.generic.enabled", True)
    _insert(conn, "core.static.generic.command", "new-mcp")
    conn.commit()

    ctx = MigrationContext.configure(conn)
    with Operations.context(ctx):
        mod.upgrade()

    custom = _rows(conn)["core.mcp.servers"]["custom"]
    # Not touched by the fold: kept from the pre-existing entry.
    assert custom["label"] == "Mine"
    assert custom["tools"] == ["a"]
    # Folded fields: the legacy row wins over the pre-existing entry's value.
    assert custom["command"] == "new-mcp"
    assert custom["enabled"] is True

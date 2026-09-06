"""Move a stored static.generic block into the tool-server registry.

Sub-project B turns ``static.generic`` from a server's configuration into the
*name* of a server in ``mcp.servers``. An operator who configured a custom MCP
server through the UI on sub-project A has nine ``core.static.generic.*`` rows;
without this they would stop matching a catalog entry and be ignored in
silence. Each moves to ``core.mcp.servers.custom.*`` and one new row points
``core.static.generic.server`` at it.

The registry leaf is stored as one JSON document, so the moved rows are folded
into a single ``core.mcp.servers`` row rather than left as dotted keys: the
catalog has exactly one entry for the whole map, and a key it does not know is
a key the settings service refuses.

The legacy ``auth_token`` row is Fernet-encrypted and marked ``is_secret``
(``20260902000000_runtime_settings``); the folded ``core.mcp.servers`` document
is not a secret entry, so writing the encrypted payload into it would leave a
ciphertext this row can never decrypt (the registry has no encryption key of
its own — only ``is_secret`` rows do) and the settings API refuses plain
writes to a secret's stored shape either way. Task 14 landed on this same
branch and gives the custom server its own per-server encrypted token row at
``core.mcp.servers.custom.auth_token`` (``server_token_key("custom")``) — the
same Fernet box and the same ``is_secret`` flag. The legacy row is therefore
renamed in place to that key rather than dropped: its ``value`` and
``is_secret`` travel across untouched, so an operator's existing bearer token
keeps working after the upgrade with no re-entry step.

Idempotent by construction: a run that finds no legacy row writes nothing.

Revision ID: 20260905000000
Revises: 20260904000000
"""

from __future__ import annotations

import json
import logging

import sqlalchemy as sa
from alembic import op

# ``20260904000000`` is already taken by ``add_sandbox_reports`` on this branch
# (sub-project A shipped it), so this one is dated a day later and chains after
# it rather than forking a second head off ``20260903000000``.
revision = "20260905000000"
down_revision = "20260904000000"
branch_labels = None
depends_on = None

logger = logging.getLogger(__name__)

SERVER_KEY = "custom"
MAP_KEY = "core.mcp.servers"
REFERENCE_KEY = "core.static.generic.server"
REFERENCE_VALUE = SERVER_KEY
TOKEN_LEAF = "auth_token"
LEGACY_TOKEN_KEY = f"core.static.generic.{TOKEN_LEAF}"
NEW_TOKEN_KEY = f"core.mcp.servers.{SERVER_KEY}.{TOKEN_LEAF}"

# The eight leaves that fold into the ``core.mcp.servers`` JSON document.
# ``auth_token`` is handled separately: it keeps its own encrypted row (see
# module docstring) and is renamed, not folded.
_LEAVES = (
    "enabled",
    "transport",
    "command",
    "args",
    "env",
    "url",
    "tool_selection",
    "use_all_tools",
)

KEY_RENAMES: dict[str, str] = {
    f"core.static.generic.{leaf}": f"core.mcp.servers.{SERVER_KEY}.{leaf}" for leaf in _LEAVES
}

# Postgres INSERT ... ON CONFLICT for a JSONB column needs the value cast so a
# text-typed bind parameter is not mistaken for the json/jsonb overload
# ambiguity; the throwaway SQLite this revision is exercised against in tests
# stores ``value`` as plain TEXT and has no JSONB type, so the cast is a
# literal per-dialect statement rather than something built by interpolating
# a value into the SQL text.
_UPSERT_JSON_PG = sa.text(
    "INSERT INTO runtime_settings (key, value, is_secret) "
    "VALUES (:k, CAST(:v AS JSONB), false) "
    "ON CONFLICT (key) DO UPDATE SET value = CAST(:v AS JSONB)"
)
_UPSERT_JSON_OTHER = sa.text(
    "INSERT INTO runtime_settings (key, value, is_secret) "
    "VALUES (:k, :v, false) "
    "ON CONFLICT (key) DO UPDATE SET value = :v"
)
_INSERT_IF_ABSENT_PG = sa.text(
    "INSERT INTO runtime_settings (key, value, is_secret) "
    "VALUES (:k, CAST(:v AS JSONB), false) "
    "ON CONFLICT (key) DO NOTHING"
)
_INSERT_IF_ABSENT_OTHER = sa.text(
    "INSERT INTO runtime_settings (key, value, is_secret) "
    "VALUES (:k, :v, false) "
    "ON CONFLICT (key) DO NOTHING"
)
_RENAME_KEY = sa.text("UPDATE runtime_settings SET key = :new_key WHERE key = :old_key")


def _load_map(conn: sa.engine.Connection) -> dict:
    row = conn.execute(
        sa.text("SELECT value FROM runtime_settings WHERE key = :k"), {"k": MAP_KEY}
    ).fetchone()
    if row is None:
        return {}
    value = row[0]
    return json.loads(value) if isinstance(value, str) else dict(value)


def _store_map(conn: sa.engine.Connection, servers: dict) -> None:
    statement = _UPSERT_JSON_PG if conn.dialect.name == "postgresql" else _UPSERT_JSON_OTHER
    conn.execute(statement, {"k": MAP_KEY, "v": json.dumps(servers)})


def upgrade() -> None:
    conn = op.get_bind()
    rows = []
    for key in KEY_RENAMES:
        row = conn.execute(
            sa.text("SELECT key, value, is_secret FROM runtime_settings WHERE key = :k"),
            {"k": key},
        ).fetchone()
        if row is not None:
            rows.append(row)
    token_row = conn.execute(
        sa.text("SELECT key, value, is_secret FROM runtime_settings WHERE key = :k"),
        {"k": LEGACY_TOKEN_KEY},
    ).fetchone()
    if not rows and token_row is None:
        return
    if rows:
        servers = _load_map(conn)
        entry = dict(servers.get(SERVER_KEY) or {})
        for key, value, _is_secret in rows:
            leaf = key.rsplit(".", 1)[1]
            entry[leaf] = json.loads(value) if isinstance(value, str) else value
        entry.setdefault("agents", ["static"])
        servers[SERVER_KEY] = entry
        _store_map(conn, servers)
        insert_if_absent = (
            _INSERT_IF_ABSENT_PG if conn.dialect.name == "postgresql" else _INSERT_IF_ABSENT_OTHER
        )
        conn.execute(insert_if_absent, {"k": REFERENCE_KEY, "v": json.dumps(REFERENCE_VALUE)})
    if token_row is not None:
        # The encrypted value and its ``is_secret`` flag travel across
        # untouched — only the key changes — so the operator's bearer token
        # keeps decrypting under ``core.mcp.servers.custom.auth_token``
        # exactly as it did under its legacy name.
        conn.execute(_RENAME_KEY, {"old_key": LEGACY_TOKEN_KEY, "new_key": NEW_TOKEN_KEY})
        logger.info("runtime_settings: renamed key %r to %r", LEGACY_TOKEN_KEY, NEW_TOKEN_KEY)
    for key in KEY_RENAMES:
        conn.execute(sa.text("DELETE FROM runtime_settings WHERE key = :k"), {"k": key})
    logger.info("runtime_settings: moved %d static.generic override(s) into %s", len(rows), MAP_KEY)


def downgrade() -> None:
    conn = op.get_bind()
    servers = _load_map(conn)
    entry = servers.pop(SERVER_KEY, None)
    if entry is not None:
        upsert = _UPSERT_JSON_PG if conn.dialect.name == "postgresql" else _UPSERT_JSON_OTHER
        for leaf in _LEAVES:
            if leaf not in entry:
                continue
            conn.execute(upsert, {"k": f"core.static.generic.{leaf}", "v": json.dumps(entry[leaf])})
        _store_map(conn, servers)
        conn.execute(sa.text("DELETE FROM runtime_settings WHERE key = :k"), {"k": REFERENCE_KEY})
    token_row = conn.execute(
        sa.text("SELECT key FROM runtime_settings WHERE key = :k"), {"k": NEW_TOKEN_KEY}
    ).fetchone()
    if token_row is not None:
        conn.execute(_RENAME_KEY, {"old_key": NEW_TOKEN_KEY, "new_key": LEGACY_TOKEN_KEY})

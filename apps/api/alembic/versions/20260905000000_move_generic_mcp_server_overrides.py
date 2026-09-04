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
writes to a secret's stored shape either way. The token is therefore dropped
rather than carried across; a one-line warning names the key and Task 14 gives
the custom server its own per-server encrypted token row. Until then the
operator re-enters it.

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

# The nine leaves an MCPServerConfig block stores.
_LEAVES = (
    "enabled",
    "transport",
    "command",
    "args",
    "env",
    "url",
    "auth_token",
    "tool_selection",
    "use_all_tools",
)

KEY_RENAMES: dict[str, str] = {
    f"core.static.generic.{leaf}": f"core.mcp.servers.{SERVER_KEY}.{leaf}" for leaf in _LEAVES
}


def _jsonb(conn: sa.engine.Connection, placeholder: str) -> str:
    """Wrap a bind parameter for a JSONB column, only where the dialect has one.

    Postgres needs the explicit cast so a text-typed bind parameter is not
    mistaken for the ``json``/``jsonb`` overload ambiguity on ``INSERT``. The
    throwaway SQLite this revision is exercised against in tests stores
    ``value`` as plain ``TEXT`` and has no ``JSONB`` type at all — casting to
    it there does not fail loudly, it silently coerces the text to ``0``
    (SQLite's affinity rule for a non-numeric cast target it does not
    recognise), so the cast is applied only on a real Postgres connection.
    """
    if conn.dialect.name == "postgresql":
        return f"CAST({placeholder} AS JSONB)"
    return placeholder


def _load_map(conn: sa.engine.Connection) -> dict:
    row = conn.execute(
        sa.text("SELECT value FROM runtime_settings WHERE key = :k"), {"k": MAP_KEY}
    ).fetchone()
    if row is None:
        return {}
    value = row[0]
    return json.loads(value) if isinstance(value, str) else dict(value)


def _store_map(conn: sa.engine.Connection, servers: dict) -> None:
    value_expr = _jsonb(conn, ":v")
    conn.execute(
        sa.text(
            f"INSERT INTO runtime_settings (key, value, is_secret) "
            f"VALUES (:k, {value_expr}, false) "
            f"ON CONFLICT (key) DO UPDATE SET value = {value_expr}"
        ),
        {"k": MAP_KEY, "v": json.dumps(servers)},
    )


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
    if not rows:
        return
    servers = _load_map(conn)
    entry = dict(servers.get(SERVER_KEY) or {})
    for key, value, is_secret in rows:
        leaf = key.rsplit(".", 1)[1]
        if leaf == "auth_token" and is_secret:
            # An encrypted token cannot be folded into the registry's single,
            # non-secret JSON row in clear: leave it out and let the operator
            # re-enter it (Task 14 gives the custom server its own encrypted
            # token row). Never log the value, only the key.
            logger.warning(
                "runtime_settings: dropping secret %s; the custom server has no "
                "encrypted token storage yet, re-enter it after upgrading",
                key,
            )
            continue
        entry[leaf] = json.loads(value) if isinstance(value, str) else value
    entry.setdefault("agents", ["static"])
    servers[SERVER_KEY] = entry
    _store_map(conn, servers)
    ref_expr = _jsonb(conn, ":v")
    conn.execute(
        sa.text(
            f"INSERT INTO runtime_settings (key, value, is_secret) "
            f"VALUES (:k, {ref_expr}, false) "
            f"ON CONFLICT (key) DO NOTHING"
        ),
        {"k": REFERENCE_KEY, "v": json.dumps(REFERENCE_VALUE)},
    )
    for key in KEY_RENAMES:
        conn.execute(sa.text("DELETE FROM runtime_settings WHERE key = :k"), {"k": key})
    logger.info("runtime_settings: moved %d static.generic override(s) into %s", len(rows), MAP_KEY)


def downgrade() -> None:
    conn = op.get_bind()
    servers = _load_map(conn)
    entry = servers.pop(SERVER_KEY, None)
    if entry is None:
        return
    leaf_expr = _jsonb(conn, ":v")
    for leaf in _LEAVES:
        if leaf not in entry:
            continue
        conn.execute(
            sa.text(
                f"INSERT INTO runtime_settings (key, value, is_secret) "
                f"VALUES (:k, {leaf_expr}, false) "
                f"ON CONFLICT (key) DO UPDATE SET value = {leaf_expr}"
            ),
            {"k": f"core.static.generic.{leaf}", "v": json.dumps(entry[leaf])},
        )
    _store_map(conn, servers)
    conn.execute(sa.text("DELETE FROM runtime_settings WHERE key = :k"), {"k": REFERENCE_KEY})

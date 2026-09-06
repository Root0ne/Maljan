"""Move the persisted builtin sidecar paths to services/network-mcp and services/threatintel-mcp.

The sidecar MCP servers moved from ``network-mcp/`` and ``threatintel-mcp/``
to ``services/network-mcp/`` and ``services/threatintel-mcp/`` on this branch.
``_builtin_servers()`` in ``src/maljan/core/config.py`` already seeds the new
paths, but ``MCPConfig._reseed_builtins`` only fills in a builtin key that is
*absent* (``servers.setdefault(key, default)``) -- a key already present,
whatever its content, is kept wholesale. An operator who ever saved the
``core.mcp.servers`` override through the UI has a ``network`` and/or
``threatintel`` entry pinned to the old ``cwd``/``args`` values, and that
entry now wins over the corrected default forever: the worker fails to attach
either sidecar with a "cwd does not exist" error.

This rewrites only the two known stale path values, in place, inside the
single ``core.mcp.servers`` JSON document. Every other field of every entry
(including an unrelated custom or http-transport server) is left untouched.

Idempotent by construction: a row already on the new paths, or no row at all,
is not rewritten.

Revision ID: 20260906000000
Revises: 20260905000000
"""

from __future__ import annotations

import json
import logging

import sqlalchemy as sa
from alembic import op

revision = "20260906000000"
down_revision = "20260905000000"
branch_labels = None
depends_on = None

logger = logging.getLogger(__name__)

MAP_KEY = "core.mcp.servers"

# cwd -> new cwd
CWD_RENAMES: dict[str, str] = {
    "network-mcp": "services/network-mcp",
    "threatintel-mcp": "services/threatintel-mcp",
}

# args element -> new args element
ARG_RENAMES: dict[str, str] = {
    "network-mcp/server.py": "services/network-mcp/server.py",
    "threatintel-mcp/server.py": "services/threatintel-mcp/server.py",
}

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


def _load_map(conn: sa.engine.Connection) -> dict | None:
    row = conn.execute(
        sa.text("SELECT value FROM runtime_settings WHERE key = :k"), {"k": MAP_KEY}
    ).fetchone()
    if row is None:
        return None
    value = row[0]
    return json.loads(value) if isinstance(value, str) else dict(value)


def _store_map(conn: sa.engine.Connection, servers: dict) -> None:
    statement = _UPSERT_JSON_PG if conn.dialect.name == "postgresql" else _UPSERT_JSON_OTHER
    conn.execute(statement, {"k": MAP_KEY, "v": json.dumps(servers)})


def _rewrite(entry: dict, renames: dict[str, str], arg_renames: dict[str, str]) -> dict | None:
    """Return a rewritten copy of ``entry``, or ``None`` if nothing changed."""
    changed = False
    new_entry = dict(entry)

    cwd = new_entry.get("cwd")
    if isinstance(cwd, str) and cwd in renames:
        new_entry["cwd"] = renames[cwd]
        changed = True

    args = new_entry.get("args")
    if isinstance(args, list):
        new_args = [arg_renames.get(a, a) if isinstance(a, str) else a for a in args]
        if new_args != args:
            new_entry["args"] = new_args
            changed = True

    return new_entry if changed else None


def _apply(renames: dict[str, str], arg_renames: dict[str, str]) -> None:
    conn = op.get_bind()
    servers = _load_map(conn)
    if servers is None:
        return
    any_changed = False
    for key, entry in list(servers.items()):
        if not isinstance(entry, dict):
            continue
        rewritten = _rewrite(entry, renames, arg_renames)
        if rewritten is not None:
            servers[key] = rewritten
            any_changed = True
    if not any_changed:
        return
    _store_map(conn, servers)
    logger.info("runtime_settings: moved builtin sidecar paths under %s to services/", MAP_KEY)


def upgrade() -> None:
    _apply(CWD_RENAMES, ARG_RENAMES)


def downgrade() -> None:
    reverse_cwd = {new: old for old, new in CWD_RENAMES.items()}
    reverse_args = {new: old for old, new in ARG_RENAMES.items()}
    _apply(reverse_cwd, reverse_args)

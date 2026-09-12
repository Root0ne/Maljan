"""Drop the retired tool-selection settings from stored MCP server entries.

``tool_selection`` and ``use_all_tools`` chose how many of a server's tools
the model saw: a curated allow-list, a per-sample relevance cut, or all of
them. The modes are gone — every tool a server offers reaches the model, minus
whatever the operator unticks in the server's own ``tools`` list — so this
revision removes the two leaves from every entry of the ``core.mcp.servers``
document and deletes the flat rows the ``static.ghidra``, ``static.r2`` and
``sandbox.cape2.mcp`` leaves stored. A stored override that names a setting the catalog no longer
knows would otherwise be refused by the settings service.

Downgrade restores nothing: the old values selected a narrowing that no
longer exists, and the previous model defaults apply again on their own.

Revision ID: 20260913000000
Revises: 20260912000000
"""

from __future__ import annotations

import json

import sqlalchemy as sa
from alembic import op

revision = "20260913000000"
down_revision = "20260912000000"
branch_labels = None
depends_on = None

MAP_KEY = "core.mcp.servers"
LEAVES = ("tool_selection", "use_all_tools")
_PREFIXES = ("static.ghidra", "static.r2", "sandbox.cape2.mcp")
FLAT_KEYS = tuple(f"core.{prefix}.{name}" for prefix in _PREFIXES for name in LEAVES)

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
    loaded = json.loads(value) if isinstance(value, str) else value
    return dict(loaded) if isinstance(loaded, dict) else None


def _store_map(conn: sa.engine.Connection, servers: dict) -> None:
    statement = _UPSERT_JSON_PG if conn.dialect.name == "postgresql" else _UPSERT_JSON_OTHER
    conn.execute(statement, {"k": MAP_KEY, "v": json.dumps(servers)})


def upgrade() -> None:
    conn = op.get_bind()
    conn.execute(
        sa.text("DELETE FROM runtime_settings WHERE key IN :keys").bindparams(
            sa.bindparam("keys", expanding=True)
        ),
        {"keys": list(FLAT_KEYS)},
    )
    servers = _load_map(conn)
    if servers is None:
        return
    changed = False
    for entry in servers.values():
        if not isinstance(entry, dict):
            continue
        for leaf in LEAVES:
            if leaf in entry:
                del entry[leaf]
                changed = True
    if changed:
        _store_map(conn, servers)


def downgrade() -> None:
    return None

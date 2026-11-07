"""A server's stored environment names take the product's new prefix (T-576).

The product was renamed, and every environment variable it reads moved from the
previous prefix to ``MALSPARK_``. A server map stored before that may still
name the old ones: ``20260915000000`` moved an operator's rule directories into
``core.mcp.servers.analysis.env`` as the old ``..._SIGMA_RULES_DIR`` and
``..._YARA_RULES_DIR``, and an operator's own ``env`` and ``env_allow`` entries
may name any of them. The sidecars read only the new names, so a stored value
under an old one was silently not passed on.

Each block of the clear ``core.mcp.servers`` row has every ``env`` key and
every ``env_allow`` entry with the old prefix renamed to the new one. A key
whose new name the block already sets keeps the new one, and the old one is
dropped; an ``env_allow`` entry that is already listed under its new name is
not listed twice. ``is_secret`` rows are never read: a server's encrypted
``env`` row is renamed as it is read (``app.services.server_map``), never here.
Values are never logged, only key names and block names. Running it again
writes nothing.

The previous prefix is restated here rather than imported from
``malspark.core.previous_name``, as every revision restates what it acts on.

The downgrade renames the new prefix back to the old one in the same places.

Revision ID: 20261107000000
Revises: 20261103000000
"""

from __future__ import annotations

import json
import logging
from typing import Any

import sqlalchemy as sa
from alembic import op

revision = "20261107000000"
down_revision = "20261103000000"
branch_labels = None
depends_on = None

logger = logging.getLogger(__name__)

MAP_KEY = "core.mcp.servers"
PREVIOUS_PREFIX = "MALJAN_"
CURRENT_PREFIX = "MALSPARK_"
# How long the row write waits for a lock before the migration fails instead.
LOCK_TIMEOUT = "5s"

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


def _plain_value(conn: sa.engine.Connection, key: str) -> Any:
    """The stored value for ``key``, or ``None``. A secret row is left alone."""
    row = conn.execute(
        sa.text("SELECT value, is_secret FROM runtime_settings WHERE key = :k"), {"k": key}
    ).fetchone()
    if row is None or row[1]:
        return None
    value = row[0]
    return json.loads(value) if isinstance(value, str) else value


def _store(conn: sa.engine.Connection, key: str, value: Any) -> None:
    statement = _UPSERT_JSON_PG if conn.dialect.name == "postgresql" else _UPSERT_JSON_OTHER
    conn.execute(statement, {"k": key, "v": json.dumps(value)})


def _renamed(name: str, old: str, new: str) -> str:
    return new + name[len(old) :] if name.startswith(old) else name


def renamed_block(entry: dict, old: str, new: str) -> tuple[dict, list[str]]:
    """``entry`` with its ``env`` keys and ``env_allow`` entries renamed, and the names moved."""
    moved: list[str] = []
    out = dict(entry)
    env = entry.get("env")
    if isinstance(env, dict) and any(str(k).startswith(old) for k in env):
        held: dict[str, Any] = {}
        for key, value in env.items():
            if not str(key).startswith(old):
                held[key] = value
        for key, value in env.items():
            if str(key).startswith(old):
                moved.append(str(key))
                held.setdefault(_renamed(str(key), old, new), value)
        out["env"] = held
    allow = entry.get("env_allow")
    if isinstance(allow, list) and any(isinstance(n, str) and n.startswith(old) for n in allow):
        listed: list[Any] = []
        for name in allow:
            if isinstance(name, str) and name.startswith(old):
                moved.append(name)
                name = _renamed(name, old, new)
            if name not in listed:
                listed.append(name)
        out["env_allow"] = listed
    return out, moved


def _rename(old: str, new: str) -> None:
    conn = op.get_bind()
    servers = _plain_value(conn, MAP_KEY)
    if not isinstance(servers, dict):
        return
    changed = False
    out: dict[str, Any] = {}
    for name, entry in servers.items():
        if not isinstance(entry, dict):
            out[name] = entry
            continue
        out[name], moved = renamed_block(entry, old, new)
        if moved:
            changed = True
            logger.info(
                "runtime_settings: %s.%s: %s renamed to the %s prefix",
                MAP_KEY,
                name,
                ", ".join(sorted(set(moved))),
                new,
            )
    if not changed:
        return
    if conn.dialect.name == "postgresql":
        op.execute(f"SET LOCAL lock_timeout = '{LOCK_TIMEOUT}'")
    _store(conn, MAP_KEY, out)


def upgrade() -> None:
    _rename(PREVIOUS_PREFIX, CURRENT_PREFIX)


def downgrade() -> None:
    _rename(CURRENT_PREFIX, PREVIOUS_PREFIX)

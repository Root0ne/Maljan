"""Drop the settings that configured the judgement layers, and move the rule dir.

Every key removed here tuned a component that decided something on an agent's
behalf: the ATT&CK autocorrect pass that rewrote a claim's technique id, the
offensive-tool marker layer that named a family, the category classifier that
filled in the STIX schema-pruning hint. Those components are gone — an agent
asks the knowledge tools itself, and what it gets wrong comes back to it as
feedback — so a stored override naming one of them would be refused by the
settings service on the next read.

``analysis.sigma_rules_dir`` is not dropped but moved. It named a directory the
pipeline's own Sigma stage read; Sigma matching is now a tool the ``analysis``
sidecar serves, so an operator's directory belongs in that server's environment
as ``MALJAN_SIGMA_RULES_DIR``. It folds into the ``core.mcp.servers`` JSON
document rather than staying a dotted key, for the reason
``20260905000000`` gives: the catalog has one entry for the whole map and a key
it does not know is a key the settings service refuses. ``is_secret`` rows are
never touched — a rules directory is not a credential and none of these keys
was ever stored as one.

Downgrade restores the moved directory to its old flat key and nothing else:
the dropped values configured behaviour that no longer exists.

Revision ID: 20260915000000
Revises: 20260914000000
"""

from __future__ import annotations

import json
import logging

import sqlalchemy as sa
from alembic import op

revision = "20260915000000"
down_revision = "20260914000000"
branch_labels = None
depends_on = None

logger = logging.getLogger(__name__)

MAP_KEY = "core.mcp.servers"
SERVER_KEY = "analysis"
SIGMA_ENV_NAME = "MALJAN_SIGMA_RULES_DIR"
YARA_ENV_NAME = "MALJAN_YARA_RULES_DIR"
LEGACY_SIGMA_KEY = "core.analysis.sigma_rules_dir"
LEGACY_YARA_KEY = "core.analysis.yara_rules_dir"

# The rule-directory keys, and the sidecar environment name each becomes.
MOVED_KEYS: dict[str, str] = {
    LEGACY_SIGMA_KEY: SIGMA_ENV_NAME,
    LEGACY_YARA_KEY: YARA_ENV_NAME,
}

# Flat rows whose settings no longer exist.
DROPPED_KEYS: tuple[str, ...] = (
    "core.preprocessing.use_attck_autocorrect",
    "core.preprocessing.attck_autocorrect_min_alignment",
    "core.preprocessing.attck_autocorrect_min_alignment_semantic",
    "core.preprocessing.attck_autocorrect_swap_valid",
    "core.preprocessing.use_tool_artifacts",
    "core.preprocessing.tool_artifacts_path",
    "core.preprocessing.category_inference_backend",
)

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


def _load_map(conn: sa.engine.Connection) -> dict:
    row = conn.execute(
        sa.text("SELECT value FROM runtime_settings WHERE key = :k"), {"k": MAP_KEY}
    ).fetchone()
    if row is None:
        return {}
    value = row[0]
    loaded = json.loads(value) if isinstance(value, str) else value
    return dict(loaded) if isinstance(loaded, dict) else {}


def _store_map(conn: sa.engine.Connection, servers: dict) -> None:
    statement = _UPSERT_JSON_PG if conn.dialect.name == "postgresql" else _UPSERT_JSON_OTHER
    conn.execute(statement, {"k": MAP_KEY, "v": json.dumps(servers)})


def _plain_row(conn: sa.engine.Connection, key: str) -> str | None:
    """The stored value for ``key``, or ``None``. Secret rows are left alone."""
    row = conn.execute(
        sa.text("SELECT value, is_secret FROM runtime_settings WHERE key = :k"), {"k": key}
    ).fetchone()
    if row is None or row[1]:
        return None
    value = row[0]
    decoded = json.loads(value) if isinstance(value, str) else value
    return str(decoded) if isinstance(decoded, str) and decoded.strip() else None


def upgrade() -> None:
    conn = op.get_bind()

    moved: dict[str, str] = {}
    for key, env_name in MOVED_KEYS.items():
        directory = _plain_row(conn, key)
        if directory:
            moved[env_name] = directory

    if moved:
        servers = _load_map(conn)
        entry = dict(servers.get(SERVER_KEY) or {})
        env = dict(entry.get("env") or {})
        env.update(moved)
        entry["env"] = env
        servers[SERVER_KEY] = entry
        _store_map(conn, servers)
        logger.info(
            "runtime_settings: moved %s into %s.%s.env",
            ", ".join(sorted(moved)),
            MAP_KEY,
            SERVER_KEY,
        )

    conn.execute(
        sa.text("DELETE FROM runtime_settings WHERE key IN :keys").bindparams(
            sa.bindparam("keys", expanding=True)
        ),
        {"keys": [*DROPPED_KEYS, *MOVED_KEYS]},
    )


def downgrade() -> None:
    conn = op.get_bind()
    servers = _load_map(conn)
    entry = servers.get(SERVER_KEY)
    if not isinstance(entry, dict):
        return
    env = dict(entry.get("env") or {})
    upsert = _UPSERT_JSON_PG if conn.dialect.name == "postgresql" else _UPSERT_JSON_OTHER
    changed = False
    for key, env_name in MOVED_KEYS.items():
        directory = env.pop(env_name, None)
        if directory:
            conn.execute(upsert, {"k": key, "v": json.dumps(directory)})
            changed = True
    if changed:
        entry["env"] = env
        servers[SERVER_KEY] = entry
        _store_map(conn, servers)

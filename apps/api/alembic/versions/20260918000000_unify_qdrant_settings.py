"""Move the API's own Qdrant settings onto the ones the analysis path reads.

There were two sets of keys for one server. ``core.memory.qdrant_url`` /
``qdrant_collection`` / ``qdrant_api_key`` are what a run's long-term memory
uses; ``api.qdrant_url`` / ``qdrant_collection`` / ``qdrant_api_key`` were what
the health probe and the enrichment worker read. An operator filled in one of
the two, and every enrich run answered 401 because the worker was reading the
other.

The ``api.*`` keys are gone from the catalog, so this revision carries their
values across before deleting the rows: each one is written to its
``core.memory`` counterpart only when that counterpart holds nothing, so a
deployment that configured the analysis path keeps what it configured. The key
row is carried across as it is stored — encrypted, with its ``is_secret`` flag
— because this revision has no key to decrypt it with and does not need one.

Downgrade puts the ``api.*`` rows back from the ``core.memory`` values, which
is what the old readers would have read.

Revision ID: 20260918000000
Revises: 20260917000000
"""

from __future__ import annotations

import json
from typing import Any

import sqlalchemy as sa
from alembic import op

revision = "20260918000000"
down_revision = "20260917000000"
branch_labels = None
depends_on = None

# ``api`` key -> the ``core.memory`` key that now holds it.
MOVES: dict[str, str] = {
    "api.qdrant_url": "core.memory.qdrant_url",
    "api.qdrant_collection": "core.memory.qdrant_collection",
    "api.qdrant_api_key": "core.memory.qdrant_api_key",
}

_UPSERT_PG = sa.text(
    "INSERT INTO runtime_settings (key, value, is_secret) "
    "VALUES (:k, CAST(:v AS JSONB), :s) "
    "ON CONFLICT (key) DO UPDATE SET value = CAST(:v AS JSONB), is_secret = :s"
)
_UPSERT_OTHER = sa.text(
    "INSERT INTO runtime_settings (key, value, is_secret) "
    "VALUES (:k, :v, :s) "
    "ON CONFLICT (key) DO UPDATE SET value = :v, is_secret = :s"
)


def _row(conn: sa.engine.Connection, key: str) -> Any:
    """The stored ``(value, is_secret)`` for one key, or ``None``."""
    return conn.execute(
        sa.text("SELECT value, is_secret FROM runtime_settings WHERE key = :k"), {"k": key}
    ).fetchone()


def _is_empty(raw: object) -> bool:
    """Whether a stored value says nothing, whichever way the driver read it.

    JSONB comes back parsed and a TEXT column comes back as the JSON document,
    so both are asked the same question here: an absent row, a null, an empty
    string and a string holding ``"null"`` all mean the operator set nothing.
    """
    if raw is None:
        return True
    value = raw
    if isinstance(raw, str):
        try:
            value = json.loads(raw)
        except ValueError:
            value = raw
    return value is None or (isinstance(value, str) and not value.strip())


def _write(conn: sa.engine.Connection, key: str, value: object, is_secret: bool) -> None:
    statement = _UPSERT_PG if conn.dialect.name == "postgresql" else _UPSERT_OTHER
    payload = value if isinstance(value, str) else json.dumps(value)
    conn.execute(statement, {"k": key, "v": payload, "s": is_secret})


def _delete(conn: sa.engine.Connection, keys: list[str]) -> None:
    conn.execute(
        sa.text("DELETE FROM runtime_settings WHERE key IN :keys").bindparams(
            sa.bindparam("keys", expanding=True)
        ),
        {"keys": keys},
    )


def upgrade() -> None:
    conn = op.get_bind()
    for old_key, new_key in MOVES.items():
        source = _row(conn, old_key)
        if source is None or _is_empty(source[0]):
            continue
        target = _row(conn, new_key)
        if target is not None and not _is_empty(target[0]):
            # The analysis path was configured; it wins, and the duplicate
            # simply goes. Overwriting it would move a working deployment onto
            # whatever the other half happened to hold.
            continue
        _write(conn, new_key, source[0], bool(source[1]))
    _delete(conn, list(MOVES))


def downgrade() -> None:
    conn = op.get_bind()
    for old_key, new_key in MOVES.items():
        source = _row(conn, new_key)
        if source is None or _is_empty(source[0]):
            continue
        _write(conn, old_key, source[0], bool(source[1]))

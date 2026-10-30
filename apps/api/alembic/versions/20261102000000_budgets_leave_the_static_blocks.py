"""A server's call budget and a drafted rule's check budget leave the static blocks.

A tool server whose block declares no ``call_timeout_seconds`` (every
built-in) got, per call, the longer of ``core.static.capa.timeout_seconds``
and ``core.static.yara.timeout_seconds``: two blocks named for one provider's
tools set the budget of every other server. That budget is now a setting of
its own, read alike for every such server
(``core.mcp.breaker.default_call_timeout_seconds``). This revision writes the
deployment's floor into it, the longer of the two stored values with each
one's shipped default standing in where it is not stored, so no server's
budget changes. Where the floor is the new setting's default, nothing is
written.

``core.static.yara.timeout_seconds`` bounded one other thing: the check of the
drafted YARA rule against its sample, under every provider. That budget is now
``core.reporting.detection_rule_check_seconds``, and the stored row is moved
there as it is. A row whose new key is already held keeps the newer row, and
the old one goes.

A secret row, or a value that is not a number, is read as not stored: the
settings model refuses it at that key, as it did before. Running it again
writes nothing more: the floor is read only where the new key is not held.

The downgrade moves the check budget back and deletes the call budget row,
which the earlier release does not know; that release derives the same floor
from the two static values again.

Revision ID: 20261102000000
Revises: 20261101000000
"""

from __future__ import annotations

import json
from typing import Any

import sqlalchemy as sa
from alembic import op

revision = "20261102000000"
down_revision = "20261101000000"
branch_labels = None
depends_on = None

# How long the row writes wait for a lock before the migration fails instead,
# so a busy table is retried by the operator rather than queueing requests.
LOCK_TIMEOUT = "5s"

CALL_BUDGET_KEY = "core.mcp.breaker.default_call_timeout_seconds"
# The two values the floor was the longer of, each with its shipped default:
# restated rather than imported, as every revision restates what it acts on.
FLOOR_SOURCES: dict[str, float] = {
    "core.static.capa.timeout_seconds": 300.0,
    "core.static.yara.timeout_seconds": 60.0,
}
CALL_BUDGET_DEFAULT = 300.0
OLD_CHECK_KEY = "core.static.yara.timeout_seconds"
NEW_CHECK_KEY = "core.reporting.detection_rule_check_seconds"

_INSERT_PG = sa.text(
    "INSERT INTO runtime_settings (key, value, is_secret) VALUES (:k, CAST(:v AS JSONB), false)"
)
_INSERT_OTHER = sa.text(
    "INSERT INTO runtime_settings (key, value, is_secret) VALUES (:k, :v, false)"
)


def _row(conn: sa.engine.Connection, key: str) -> Any:
    return conn.execute(
        sa.text("SELECT value, is_secret FROM runtime_settings WHERE key = :k"), {"k": key}
    ).fetchone()


def _number(row: Any) -> float | None:
    """A stored row's value as a number; ``None`` for no row, a secret one or no number."""
    if row is None or row[1]:
        return None
    value = json.loads(row[0]) if isinstance(row[0], str) else row[0]
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value)


def floor(stored: dict[str, float | None]) -> float:
    """The floor every server got: the longer of the two values, a default for one not stored."""
    return max(
        default if stored.get(key) is None else float(stored[key])  # type: ignore[arg-type]
        for key, default in FLOOR_SOURCES.items()
    )


def _lock_timeout(conn: sa.engine.Connection) -> None:
    if conn.dialect.name == "postgresql":
        op.execute(f"SET LOCAL lock_timeout = '{LOCK_TIMEOUT}'")


def _write_call_budget(conn: sa.engine.Connection) -> None:
    if _row(conn, CALL_BUDGET_KEY) is not None:
        return
    value = floor({key: _number(_row(conn, key)) for key in FLOOR_SOURCES})
    if value == CALL_BUDGET_DEFAULT:
        return
    statement = _INSERT_PG if conn.dialect.name == "postgresql" else _INSERT_OTHER
    stored: float | int = int(value) if value.is_integer() else value
    conn.execute(statement, {"k": CALL_BUDGET_KEY, "v": json.dumps(stored)})


def _move(conn: sa.engine.Connection, old: str, new: str) -> None:
    """Rename the ``old`` row to ``new``; a held ``new`` row keeps and ``old`` goes."""
    source = _row(conn, old)
    if source is None or source[1]:
        return
    if _row(conn, new) is not None:
        conn.execute(sa.text("DELETE FROM runtime_settings WHERE key = :k"), {"k": old})
        return
    conn.execute(
        sa.text("UPDATE runtime_settings SET key = :new WHERE key = :old"),
        {"new": new, "old": old},
    )


def upgrade() -> None:
    conn = op.get_bind()
    _lock_timeout(conn)
    # The floor reads the YARA value, so it is written before that row moves.
    _write_call_budget(conn)
    _move(conn, OLD_CHECK_KEY, NEW_CHECK_KEY)


def downgrade() -> None:
    conn = op.get_bind()
    _lock_timeout(conn)
    _move(conn, NEW_CHECK_KEY, OLD_CHECK_KEY)
    conn.execute(sa.text("DELETE FROM runtime_settings WHERE key = :k"), {"k": CALL_BUDGET_KEY})

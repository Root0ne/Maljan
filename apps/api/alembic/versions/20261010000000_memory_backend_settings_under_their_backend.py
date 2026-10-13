"""Move each memory backend's stored settings under ``memory.<backend>``.

The Qdrant backend's settings were flat leaves of the memory block
(``core.memory.qdrant_url`` and its siblings); every backend's settings now
live under its own id (``core.memory.qdrant.url``), as each static and sandbox
provider's already do, so a backend registered later adds keys under its id
instead of flat fields on the shared block.

Each row is renamed in place: its value, its ``is_secret`` flag and every
other column stay as stored. A secret row stays encrypted exactly as it was —
the stored ciphertext does not depend on the key it is filed under, and this
revision has no key to decrypt it with and needs none. A row whose new key is
already held (written by a newer process before the upgrade ran) keeps the
newer row, and the old one goes.

Downgrade renames the rows back the same way.

Revision ID: 20261010000000
Revises: 20261009000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "20261010000000"
down_revision = "20261009000000"
branch_labels = None
depends_on = None

# Old key -> the key that now holds it.
MOVES: dict[str, str] = {
    "core.memory.qdrant_url": "core.memory.qdrant.url",
    "core.memory.qdrant_collection": "core.memory.qdrant.collection",
    "core.memory.qdrant_function_hash_collection": "core.memory.qdrant.function_hash_collection",
    "core.memory.qdrant_api_key": "core.memory.qdrant.api_key",
}


def _held(conn: sa.engine.Connection, key: str) -> bool:
    return (
        conn.execute(
            sa.text("SELECT 1 FROM runtime_settings WHERE key = :k"), {"k": key}
        ).fetchone()
        is not None
    )


def _rename(conn: sa.engine.Connection, moves: dict[str, str]) -> None:
    for source, target in moves.items():
        if not _held(conn, source):
            continue
        if _held(conn, target):
            conn.execute(sa.text("DELETE FROM runtime_settings WHERE key = :k"), {"k": source})
            continue
        conn.execute(
            sa.text("UPDATE runtime_settings SET key = :new WHERE key = :old"),
            {"new": target, "old": source},
        )


def upgrade() -> None:
    _rename(op.get_bind(), MOVES)


def downgrade() -> None:
    _rename(op.get_bind(), {new: old for old, new in MOVES.items()})

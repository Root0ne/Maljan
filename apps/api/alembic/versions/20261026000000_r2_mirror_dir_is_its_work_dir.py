"""radare2's stored ``mirror_dir`` becomes its ``work_dir``.

radare2's block kept a ``mirror_dir`` (a path whose last segment named the
directory the sample is copied into) beside the ``work_dir`` every server block
declares for the same thing, and the two could disagree. ``work_dir`` is now the
only one. A stored ``core.static.r2.mirror_dir`` is moved to
``core.static.r2.work_dir`` with its last segment as the value, which is all the
old setting ever used. The settings model reads an old row the same way until
this revision has run, so nothing depends on the order.

A row whose new key is already held keeps the newer row, and the old one goes.
A secret row, or a value that is not text or has no last segment, is left as it
is: the settings model refuses it at that key, as it did before, and the console
can open past it and repair it.

The downgrade writes ``core.static.r2.mirror_dir`` back as ``data/samples/<name>``
where that key is not held, and leaves the ``work_dir`` row, which the earlier
release also reads.

Revision ID: 20261026000000
Revises: 20261025000000
"""

from __future__ import annotations

import json
from pathlib import PurePosixPath
from typing import Any

import sqlalchemy as sa
from alembic import op

revision = "20261026000000"
down_revision = "20261025000000"
branch_labels = None
depends_on = None

# How long the row writes wait for a lock before the migration fails instead,
# so a busy table is retried by the operator rather than queueing requests.
LOCK_TIMEOUT = "5s"

OLD_KEY = "core.static.r2.mirror_dir"
NEW_KEY = "core.static.r2.work_dir"
# The earlier release's own default, where a downgrade has to write a path.
MIRROR_PARENT = "data/samples"

_WRITE_PG = sa.text(
    "UPDATE runtime_settings SET key = :new, value = CAST(:v AS JSONB) WHERE key = :old"
)
_WRITE_OTHER = sa.text("UPDATE runtime_settings SET key = :new, value = :v WHERE key = :old")


def _row(conn: sa.engine.Connection, key: str) -> Any:
    return conn.execute(
        sa.text("SELECT value, is_secret FROM runtime_settings WHERE key = :k"), {"k": key}
    ).fetchone()


def _plain(row: Any) -> Any:
    value = row[0]
    return json.loads(value) if isinstance(value, str) else value


def _last_segment(value: Any) -> str:
    """The last path segment of a stored mirror directory; empty when it names none."""
    if not isinstance(value, str):
        return ""
    name = PurePosixPath(value.replace("\\", "/")).name
    return "" if name == ".." else name


def _move(conn: sa.engine.Connection, old: str, new: str, read_as: Any) -> None:
    """Rename the ``old`` row to ``new``, its value read as ``read_as``; see the module text."""
    source = _row(conn, old)
    if source is None or source[1]:
        return
    if _row(conn, new) is not None:
        conn.execute(sa.text("DELETE FROM runtime_settings WHERE key = :k"), {"k": old})
        return
    value = read_as(_plain(source))
    if not isinstance(value, str) or not value:
        return
    statement = _WRITE_PG if conn.dialect.name == "postgresql" else _WRITE_OTHER
    conn.execute(statement, {"new": new, "old": old, "v": json.dumps(value)})


def _lock_timeout(conn: sa.engine.Connection) -> None:
    if conn.dialect.name == "postgresql":
        op.execute(f"SET LOCAL lock_timeout = '{LOCK_TIMEOUT}'")


def upgrade() -> None:
    conn = op.get_bind()
    _lock_timeout(conn)
    _move(conn, OLD_KEY, NEW_KEY, _last_segment)


def downgrade() -> None:
    conn = op.get_bind()
    _lock_timeout(conn)
    source = _row(conn, NEW_KEY)
    if source is None or source[1] or _row(conn, OLD_KEY) is not None:
        return
    name = _plain(source)
    if not isinstance(name, str) or not name:
        return
    value = f"{MIRROR_PARENT}/{name}"
    insert = (
        "INSERT INTO runtime_settings (key, value, is_secret) VALUES (:k, CAST(:v AS JSONB), false)"
        if conn.dialect.name == "postgresql"
        else "INSERT INTO runtime_settings (key, value, is_secret) VALUES (:k, :v, false)"
    )
    conn.execute(sa.text(insert), {"k": OLD_KEY, "v": json.dumps(value)})

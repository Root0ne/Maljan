"""Read each retired environment variable once into the setting that replaced it.

``GHIDRA_CONTAINER_SAMPLES_PATH`` named the path at which one container saw the
samples directory, and the worker built every server's sample path from it.
Each server now declares its own ``sample_mount``, and Ghidra's is the
``core.static.ghidra.sample_mount`` setting, so the variable is read no more.

A deployment that set it to something other than the shipped mount has its
value written to that setting here, once, when the store holds nothing for the
key: a value an operator saved in the console is kept. A value that is not an
absolute path, or that holds a ``..`` segment, is not a mount and is left
unwritten, as is one equal to the shipped mount, which the setting already
has. The revision reads the environment of the process that runs it, which is
the one ``make migrate`` sources from ``bootstrap.env``.

Downgrade deletes nothing: a row written here is an ordinary setting, which the
older code ignores.

Revision ID: 20261011000000
Revises: 20261010000000
"""

from __future__ import annotations

import json
import os
import posixpath

import sqlalchemy as sa
from alembic import op

revision = "20261011000000"
down_revision = "20261010000000"
branch_labels = None
depends_on = None

# Variable -> the settings key that now holds it, and that key's shipped value
# (``maljan.core.settings_annotations.RETIRED_ENVIRONMENT``, copied: a revision
# imports no application code).
READS: dict[str, tuple[str, str]] = {
    "GHIDRA_CONTAINER_SAMPLES_PATH": ("core.static.ghidra.sample_mount", "/data/samples"),
}

_INSERT_PG = sa.text(
    "INSERT INTO runtime_settings (key, value, is_secret) VALUES (:k, CAST(:v AS JSONB), false)"
)
_INSERT_OTHER = sa.text(
    "INSERT INTO runtime_settings (key, value, is_secret) VALUES (:k, :v, false)"
)


def _mount(raw: str) -> str | None:
    """``raw`` as a mount path written plainly, or ``None`` when it is not one."""
    value = raw.strip()
    if not value.startswith("/") or any(part == ".." for part in value.split("/")):
        return None
    return posixpath.normpath(value)


def _held(conn: sa.engine.Connection, key: str) -> bool:
    return (
        conn.execute(
            sa.text("SELECT 1 FROM runtime_settings WHERE key = :k"), {"k": key}
        ).fetchone()
        is not None
    )


def read_environment(conn: sa.engine.Connection, environ: dict[str, str]) -> list[str]:
    """Write each set variable's value to its key; return the keys written."""
    written: list[str] = []
    statement = _INSERT_PG if conn.dialect.name == "postgresql" else _INSERT_OTHER
    for variable, (key, shipped) in READS.items():
        value = _mount(environ.get(variable, ""))
        if value is None or value == shipped or _held(conn, key):
            continue
        conn.execute(statement, {"k": key, "v": json.dumps(value)})
        written.append(key)
    return written


def upgrade() -> None:
    read_environment(op.get_bind(), dict(os.environ))


def downgrade() -> None:
    return None

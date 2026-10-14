"""Read the retired ATT&CK cache-age variable once into the setting that replaced it.

``MALJAN_ATTCK_MAX_AGE_DAYS`` said how many days the cached ATT&CK bundles
were kept before the loader downloaded them again. The interval is the
``core.validation.attck_refresh_days`` setting now, edited in the console, and
the variable is read no more.

A deployment that set it to a whole number of days, 0 or more, other than the
shipped 7 has its value written to that setting here, once, when the store
holds nothing for the key: a value an operator saved in the console is kept.
Anything else is left unwritten. The revision reads the environment of the
process that runs it, which is the one ``make migrate`` sources from
``bootstrap.env``.

Downgrade deletes nothing: a row written here is an ordinary setting, which the
older code ignores.

Revision ID: 20261014000000
Revises: 20261012000000
"""

from __future__ import annotations

import json
import os

import sqlalchemy as sa
from alembic import op

revision = "20261014000000"
down_revision = "20261012000000"
branch_labels = None
depends_on = None

# Variable -> the settings key that now holds it, and that key's shipped value
# (``maljan.core.settings_annotations.RETIRED_ENVIRONMENT``, copied: a revision
# imports no application code).
READS: dict[str, tuple[str, int]] = {
    "MALJAN_ATTCK_MAX_AGE_DAYS": ("core.validation.attck_refresh_days", 7),
}

_INSERT_PG = sa.text(
    "INSERT INTO runtime_settings (key, value, is_secret) VALUES (:k, CAST(:v AS JSONB), false)"
)
_INSERT_OTHER = sa.text(
    "INSERT INTO runtime_settings (key, value, is_secret) VALUES (:k, :v, false)"
)


def _days(raw: str) -> int | None:
    """``raw`` as a whole number of days, 0 or more, or ``None`` when it is not one."""
    value = raw.strip()
    if not value.isdigit():
        return None
    return int(value)


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
        value = _days(environ.get(variable, ""))
        if value is None or value == shipped or _held(conn, key):
            continue
        conn.execute(statement, {"k": key, "v": json.dumps(value)})
        written.append(key)
    return written


def upgrade() -> None:
    read_environment(op.get_bind(), dict(os.environ))


def downgrade() -> None:
    return None

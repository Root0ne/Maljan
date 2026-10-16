"""Allow, once, the memory plugin a deployment has in use.

An installed provider plugin is loaded now only while the plugin allow-list
(``core.plugins.allowed``) names it; before, every installed memory backend
package was loaded on its own. A deployment whose stored ``memory.backend``
names an installed memory plugin would lose its memory on upgrade, so this
revision adds that one plugin to the allow-list, as ``memory:<name>``, once.

A plugin is known by its entry point's name, which is the backend id it
registers; the installed entry points are read from package metadata in the
process that runs the revision (the image ``make migrate`` and the migrate
service run), and nothing of the package is imported. A stored backend that
is a shipped one adds nothing. One that no installed memory entry point
carries by name adds nothing either, and the revision says so in its output
and its log, naming the installed memory entry points: a package written to
the older advice (an entry point named otherwise than the id it registers, or
with capitals) no longer loads, and what to do is said with it. Nothing else
is ever added.

Downgrade deletes nothing: the allow-list is an ordinary setting, which older
code ignores.

Revision ID: 20261016000000
Revises: 20261014000000
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable
from importlib.metadata import entry_points
from typing import Any

import sqlalchemy as sa
from alembic import op

revision = "20261016000000"
down_revision = "20261014000000"
branch_labels = None
depends_on = None

# Copied, as a revision imports no application code: the memory plugins'
# entry-point group (``maljan.core.plugins.PLUGIN_GROUPS``), the shipped
# backends (``maljan.memory.store_factory.BUILT_IN_BACKENDS``) and the two keys.
MEMORY_GROUP = "maljan.memory_backends"
SHIPPED_BACKENDS = frozenset({"memory", "qdrant"})
BACKEND_KEY = "core.memory.backend"
ALLOW_LIST_KEY = "core.plugins.allowed"

logger = logging.getLogger("alembic.runtime.migration")

_INSERT_PG = sa.text(
    "INSERT INTO runtime_settings (key, value, is_secret) VALUES (:k, CAST(:v AS JSONB), false)"
)
_INSERT_OTHER = sa.text(
    "INSERT INTO runtime_settings (key, value, is_secret) VALUES (:k, :v, false)"
)
_UPDATE_PG = sa.text("UPDATE runtime_settings SET value = CAST(:v AS JSONB) WHERE key = :k")
_UPDATE_OTHER = sa.text("UPDATE runtime_settings SET value = :v WHERE key = :k")


def _stored(conn: sa.engine.Connection, key: str) -> tuple[bool, Any]:
    """Whether ``key`` has a row, and its value read as JSON."""
    row = conn.execute(
        sa.text("SELECT value FROM runtime_settings WHERE key = :k"), {"k": key}
    ).fetchone()
    if row is None:
        return False, None
    value = row[0]
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            pass
    return True, value


def installed_memory_plugins() -> list[str]:
    """The names of the installed memory plugins' entry points, from package metadata."""
    return [str(point.name) for point in entry_points(group=MEMORY_GROUP)]


def unloadable_statement(backend: str, installed: list[str]) -> str:
    """What the revision says of a backend in use that no memory entry point carries by name."""
    found = ", ".join(installed) if installed else "none"
    return (
        f"The memory backend in use, {backend!r}, is not shipped, and no installed memory "
        f"plugin's entry point is named {backend!r} (installed memory entry points: {found}). "
        "A memory plugin is now loaded only under its entry point's name, which must be the "
        "backend id it registers in lowercase, and only once the plugin allow-list "
        f"({ALLOW_LIST_KEY}) names it, so this backend will not load and long-term memory "
        f"is off until it does. Install a release of the plugin whose entry point is named "
        f"{backend!r} (in the {MEMORY_GROUP} group), then allow memory:{backend} under "
        "Settings, Configuration, Platform, Provider plugins; or select a shipped backend."
    )


def allow_the_memory_plugin_in_use(
    conn: sa.engine.Connection, installed: Iterable[str]
) -> str | None:
    """Add the stored backend's plugin to the allow-list when it is installed; its entry, or None.

    A backend that is not shipped and that no installed memory entry point
    carries by name is said in the revision's output and log, with why it will
    not load and what to do.
    """
    held, backend = _stored(conn, BACKEND_KEY)
    if not held or not isinstance(backend, str):
        return None
    name = backend.strip().lower()
    if not name or name in SHIPPED_BACKENDS:
        return None
    names = list(installed)
    if name not in set(names):
        said = unloadable_statement(name, names)
        logger.warning(said)
        print(said)
        return None
    entry = f"memory:{name}"
    has_list, allowed = _stored(conn, ALLOW_LIST_KEY)
    if has_list and isinstance(allowed, list):
        if entry in allowed:
            return None
        statement = _UPDATE_PG if conn.dialect.name == "postgresql" else _UPDATE_OTHER
        conn.execute(statement, {"k": ALLOW_LIST_KEY, "v": json.dumps([*allowed, entry])})
    elif has_list:
        # A stored value that is not a list is the operator's to repair; the
        # settings page names it. Nothing is written over it.
        return None
    else:
        statement = _INSERT_PG if conn.dialect.name == "postgresql" else _INSERT_OTHER
        conn.execute(statement, {"k": ALLOW_LIST_KEY, "v": json.dumps([entry])})
    logger.warning(
        "The memory backend in use, %r, is an installed plugin: %s is added to the plugin "
        "allow-list (%s) once, so it keeps loading.",
        name,
        entry,
        ALLOW_LIST_KEY,
    )
    return entry


def upgrade() -> None:
    allow_the_memory_plugin_in_use(op.get_bind(), installed_memory_plugins())


def downgrade() -> None:
    return None

"""Whether the database has every migration this release ships, said once at startup.

A release reads what its own migrations wrote. A store a revision has not yet
rewritten is read as the release that wrote it read it (a block's tool
declarations stored whole stay whole), so nothing is refused; but what the
operator expects from this release (a shipped correction reaching a tool they
never changed) waits for the migration. The API therefore says, in one fixed
line, when the database is not at this release's head revision.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from app.logging_config import get_logger

logger = get_logger("api.migrations")

ALEMBIC_INI = Path(__file__).resolve().parents[2] / "alembic.ini"
BEHIND_HEAD = (
    "The database is not at this release's latest migration: stored settings are read as "
    "the release that wrote them read them until it is. Run the migrations (make migrate) "
    "before starting this release."
)


def head_revisions() -> set[str]:
    """The head revisions of the migrations this release ships."""
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    config = Config(str(ALEMBIC_INI))
    config.set_main_option("script_location", str(ALEMBIC_INI.parent / "alembic"))
    return set(ScriptDirectory.from_config(config).get_heads())


def current_revisions(connection: Any) -> set[str]:
    """The revisions a (synchronous) database connection is stamped with."""
    from alembic.runtime.migration import MigrationContext

    return set(MigrationContext.configure(connection).get_current_heads())


def warn_when_behind_head(connection: Any) -> bool:
    """Log :data:`BEHIND_HEAD` once when the database is not at head; whether it was.

    Never refuses to start: a store a revision has not rewritten is read as
    it was written.
    """
    if current_revisions(connection) == head_revisions():
        return False
    logger.warning(BEHIND_HEAD)
    return True

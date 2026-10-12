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
    "The database is behind this release's latest migration: stored settings are read as "
    "the release that wrote them read them until it is. Run the migrations (make migrate) "
    "before starting this release."
)
AHEAD_OF_HEAD = (
    "The database is ahead of this release's latest migration: a later release migrated it, "
    "and this release may not read what that release stored. Start the release that "
    "migrated it, or downgrade the database to this release's head first."
)
CHECK_FAILED = "Checking the database's migration revision failed (%s); the start goes on."


def head_revisions() -> set[str]:
    """The head revisions of the migrations this release ships."""
    return set(_scripts().get_heads())


def _scripts() -> Any:
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    config = Config(str(ALEMBIC_INI))
    config.set_main_option("script_location", str(ALEMBIC_INI.parent / "alembic"))
    return ScriptDirectory.from_config(config)


def current_revisions(connection: Any) -> set[str]:
    """The revisions a (synchronous) database connection is stamped with."""
    from alembic.runtime.migration import MigrationContext

    return set(MigrationContext.configure(connection).get_current_heads())


def revision_state(connection: Any) -> str:
    """``"head"``, ``"behind"`` (also never migrated) or ``"ahead"`` (a revision unknown here)."""
    scripts = _scripts()
    current = current_revisions(connection)
    if current == set(scripts.get_heads()):
        return "head"
    known = {script.revision for script in scripts.walk_revisions()}
    return "ahead" if current - known else "behind"


def warn_when_behind_head(connection: Any) -> bool:
    """Log one fixed line once when the database is not at head; whether it was.

    :data:`BEHIND_HEAD` when it lacks a migration of this release,
    :data:`AHEAD_OF_HEAD` when it holds one this release does not ship.
    Never refuses to start: a store a revision has not rewritten is read as
    it was written.
    """
    state = revision_state(connection)
    if state == "head":
        return False
    logger.warning(AHEAD_OF_HEAD if state == "ahead" else BEHIND_HEAD)
    return True


def check_revision_at_start(connection: Any) -> None:
    """:func:`warn_when_behind_head`; a failure is one fixed line naming the error's type."""
    try:
        warn_when_behind_head(connection)
    except Exception as exc:
        # Best effort: the check only says something; it never stops a start,
        # and nothing a driver says reaches the log.
        logger.warning(CHECK_FAILED, type(exc).__name__)

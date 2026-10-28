"""What each tool server last declared of its own tools, kept in the database.

The process half is ``maljan.core.served_declarations``: what a server
declares when it is listed is held there, and read by every reader of the
declarations in force. This module keeps it past the process, in
``served_tool_declarations`` (``app.models.served_declaration``):

* :func:`load` reads every kept row into this process, before anything reads a
  declaration: the worker at the start of each job, the API before it serves
  what depends on one.
* :func:`save` writes back what this process listed or forgot since, one row
  per source, replaced whole: a listing under another launch identity
  replaces the row, a forgotten source loses it.
* :func:`prepare_job` is the worker's start of a job: what is kept is read,
  and what the job's settings point elsewhere is forgotten
  (``served_declarations.forget_moved``). :func:`list_before_run` follows
  once the job is known to run for real (no mock run reaches a server of its
  own accord): each trusted server nothing is kept for is listed
  (``providers.served_listing.list_unlisted``), and the result is saved.

The database is the store because every process that reads declarations
already reads it (the worker and the API, in containers of their own whose
data directory is read-only), and because it outlives each of them. Nothing
here is an operator's setting, so it is a table of its own, written only by
the platform. A failure to read or write it costs a job nothing: a server
nothing is kept for is read as undeclared until it attaches, and its attach
keeps what it declares for this process.
"""

from __future__ import annotations

import time
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.logging_config import get_logger
from app.models.served_declaration import ServedDeclaration

logger = get_logger(__name__)


async def load(db: AsyncSession) -> int:
    """Read every kept declaration into this process; the number of rows read, -1 on failure."""
    from maljan.core.served_declarations import install_persisted

    try:
        rows = (await db.execute(select(ServedDeclaration))).scalars().all()
    except SQLAlchemyError as exc:
        await db.rollback()
        # Said once per process: a store not migrated yet says so at every read.
        if not _SAID_UNREAD[0]:
            _SAID_UNREAD[0] = True
            logger.warning(
                "The servers' kept declarations were not read (%s); each server is read as "
                "undeclared until it attaches.",
                type(exc).__name__,
            )
        return -1
    held = [(row.source, row.launch, row.tool_facts, row.shipped) for row in rows]
    # The read is over: the session holds no transaction past it.
    await db.rollback()
    install_persisted(held)
    return len(held)


_SAID_UNREAD: list[bool] = [False]


async def save(db: AsyncSession) -> int:
    """Write back what this process listed or forgot since; the rows written, -1 on failure."""
    from maljan.core.served_declarations import mark_saved, unsaved

    rows = unsaved()
    if not rows:
        return 0
    try:
        for source, launch, tool_facts, shipped in rows:
            held = await db.get(ServedDeclaration, source)
            if tool_facts is None:
                if held is not None:
                    await db.delete(held)
            elif held is None:
                db.add(
                    ServedDeclaration(
                        source=source, launch=launch, shipped=shipped, tool_facts=tool_facts
                    )
                )
            else:
                held.launch = launch
                held.shipped = shipped
                held.tool_facts = tool_facts
        await db.commit()
    except SQLAlchemyError as exc:
        await db.rollback()
        logger.warning(
            "The servers' declarations were not kept (%s); this process still reads them.",
            type(exc).__name__,
        )
        return -1
    mark_saved(rows)
    return len(rows)


# How often a request of the API reads the kept declarations again: the worker
# writes them at the end of a job, and a reading a few seconds old decides
# nothing a later request cannot correct.
REFRESH_SECONDS = 5.0
_READ_AT: list[float] = [float("-inf")]


async def refresh(session_maker: Any) -> None:
    """The kept declarations read into the API, at most every few seconds.

    A request dependency (``deps.reads_served_declarations``), on the
    routers whose answers read a declaration before any server attaches
    (the settings, the jobs, the system status). Read in a session of its
    own from ``session_maker`` (the application's), never the request's,
    so it holds nothing of the request's transaction. Never fails a request.
    """
    now = time.monotonic()
    if now - _READ_AT[0] < REFRESH_SECONDS:
        return
    _READ_AT[0] = now
    try:
        async with session_maker() as db:
            await load(db)
            # The API installs no settings of its own: its built-in servers
            # are read through the blocks the stored settings hold, as the
            # worker reads them (``declared_reading.read_through_settings``).
            await read_through_stored(db)
    except Exception as exc:  # noqa: BLE001 — a kept declaration never fails a request
        logger.warning("The servers' kept declarations were not read (%s).", type(exc).__name__)


async def read_through_stored(db: AsyncSession) -> None:
    """Have this process read its built-in servers through the stored settings' blocks."""
    from maljan.core.declared_reading import read_through_settings

    from app.services.settings_service import effective_core_settings

    read_through_settings(await effective_core_settings(db))


def launches(settings: Any) -> dict[str, str]:
    """Each source's block launch identity under ``settings``: its servers and providers."""
    from maljan.core.tool_declarations import ToolDeclarations

    return {
        str(declared.source): declared.launch
        for declared in ToolDeclarations.from_settings(settings, served=False).sources()
    }


async def prepare_job(db_session: Any, settings: Any) -> None:
    """Have this job read what every server declared, kept, and nothing a moved block's.

    ``db_session`` opens a session (the worker's ``async_sessionmaker``).
    Reaches no server. Never raises: a store that cannot be read or written
    leaves each server read as undeclared until it attaches.
    """
    from maljan.core.served_declarations import forget_moved

    try:
        async with db_session() as db:
            await load(db)
        moved = forget_moved(launches(settings))
        if moved:
            logger.info("Forgot what %s declared under another launch.", ", ".join(moved))
        await keep(db_session)
    except Exception as exc:  # noqa: BLE001 — a kept declaration never costs a job
        logger.warning("The servers' declarations were not prepared (%s).", type(exc).__name__)


async def list_before_run(db_session: Any, settings: Any) -> None:
    """List each trusted server nothing is kept for, and keep what it declares; never raises.

    Only for a job that runs for real: a mock run reaches no server of its
    own accord (``providers.served_listing``).
    """
    from maljan.providers.served_listing import list_unlisted

    try:
        listed = await list_unlisted(settings)
        if listed:
            logger.info("Listed %s before the run: their declarations are kept.", ", ".join(listed))
        await keep(db_session)
    except Exception as exc:  # noqa: BLE001 — a kept declaration never costs a job
        logger.warning("The servers were not listed before the run (%s).", type(exc).__name__)


async def keep(db_session: Any) -> None:
    """Save what this process listed or forgot since; never raises."""
    from maljan.core.served_declarations import unsaved

    if not unsaved():
        return
    try:
        async with db_session() as db:
            await save(db)
    except Exception as exc:  # noqa: BLE001 — a kept declaration never costs a job
        logger.warning("The servers' declarations were not kept (%s).", type(exc).__name__)


def probed_as_saved(server: str, stored: dict[str, Any], values: dict[str, Any]) -> bool:
    """Whether a connection test of ``server`` reaches the saved block's server, as saved.

    True only where the request stages nothing for it, or where the entry it
    tests (the staged fields over the stored ones, as the test merges them)
    is the saved block in force, every field compared, its environment and
    token included. An entry no saved settings hold is never the saved one.
    """
    from maljan.core.settings_overrides import build_settings, split_key

    from app.services.settings_probes import _merge_server_entry

    core = {split_key(key)[1]: value for key, value in stored.items() if key.startswith("core.")}
    saved = build_settings(core).mcp.servers.get(server)
    if saved is None:
        return False
    staged_map = values.get("core.mcp.servers")
    staged = staged_map.get(server) if isinstance(staged_map, dict) else None
    if not staged:
        return True
    stored_map = stored.get("core.mcp.servers")
    stored_entry = stored_map.get(server) if isinstance(stored_map, dict) else None
    merged = _merge_server_entry(dict(stored_entry or {}), dict(staged))
    servers = dict(stored_map) if isinstance(stored_map, dict) else {}
    servers[server] = merged
    probed = build_settings({**core, "mcp.servers": servers}).mcp.servers.get(server)
    return probed is not None and probed.model_dump() == saved.model_dump()


async def keep_probe_listing(
    db: AsyncSession,
    server: str,
    stored: dict[str, Any],
    values: dict[str, Any],
    before: Any,
) -> bool:
    """Keep what a connection test listed only where it tested the saved block, as saved.

    ``before`` is what this process held for the source before the test
    (``served_declarations.snapshot_served``). A test of an entry not saved,
    or of staged values that differ from the saved block in any field (its
    launch, its environment, its trust), listed a server no run reaches as
    the test reached it: whatever it listed, or failed to list, is put back as
    it was, never saved over the saved block's row. Whether it was kept;
    never raises.
    """
    from maljan.core.served_declarations import restore_served

    source = f"mcp:{server}"
    try:
        as_saved = probed_as_saved(server, stored, values)
    except Exception:  # noqa: BLE001 — settings that do not build hold no saved block
        as_saved = False
    if not as_saved:
        restore_served(source, before)
        return False
    try:
        await save(db)
    except Exception:  # noqa: BLE001 — a kept declaration never costs a connection test
        return False
    return True

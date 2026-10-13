"""One serialisation for every write of the declared report formats.

``core.sandbox.report_formats`` and ``core.sandbox.upload.allowed_formats`` are stored as
whole lists: a write reads them, changes them and saves them back. The accept
route (``api.v1.sandbox_reports``) and the settings routes (a PATCH, an
import, a reset) all write them, so each such write holds the same lock from
before it reads the lists until its save commits, and none drops another's
change.

The lock is two locks: an ``asyncio.Lock`` serialises the writes of one
process, and on PostgreSQL a transaction-scoped advisory lock
(``pg_advisory_xact_lock``) serialises them across processes, released when
the save commits or rolls back. Only PostgreSQL gives the cross-process lock;
on any other database only the writes of one process are serialised.
"""

from __future__ import annotations

import asyncio
import hashlib
import weakref
from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager
from typing import Any

# The settings keys (as the settings catalog names them) whose writes are
# serialised: the declared formats and the formats an upload may be.
REPORT_FORMATS_KEY = "core.sandbox.report_formats"
ALLOWED_FORMATS_KEY = "core.sandbox.upload.allowed_formats"
REPORT_FORMAT_KEYS: tuple[str, ...] = (REPORT_FORMATS_KEY, ALLOWED_FORMATS_KEY)

# One lock per event loop (a process serves on one; a test may run several).
_LOCKS: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Lock] = (
    weakref.WeakKeyDictionary()
)
_LOCK_KEY = int.from_bytes(hashlib.sha256(b"sandbox.report_formats").digest()[:4], "big")


def held_lock() -> asyncio.Lock:
    """The in-process lock of the running event loop."""
    loop = asyncio.get_running_loop()
    lock = _LOCKS.get(loop)
    if lock is None:
        lock = _LOCKS[loop] = asyncio.Lock()
    return lock


def touches_report_formats(keys: Iterable[Any]) -> bool:
    """Whether a write of ``keys`` writes the declared report formats (or a part of them)."""
    return any(
        isinstance(key, str)
        and any(key == name or key.startswith(f"{name}.") for name in REPORT_FORMAT_KEYS)
        for key in keys
    )


async def _database_lock(db: Any) -> None:
    """Take PostgreSQL's transaction lock on the report formats; nothing on another database."""
    from sqlalchemy import text

    bind = getattr(db, "bind", None)
    dialect = getattr(getattr(bind, "dialect", None), "name", "")
    if dialect == "postgresql":
        await db.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": _LOCK_KEY})


@asynccontextmanager
async def report_formats_serialised(db: Any, *, needed: bool = True) -> AsyncIterator[None]:
    """Hold the report formats' lock for the body, where ``needed``; a no-op otherwise."""
    if not needed:
        yield
        return
    async with held_lock():
        await _database_lock(db)
        yield

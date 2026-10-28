"""List each server a run will read as its own before anything decides by its tools.

A server that declares its tools itself (``core.served_declarations``) is read
by what it declared when it was last listed, kept past the process. Until it
has been listed once nothing is kept: the readers that decide before any
server attaches (the pack's servers and steps, the reputation order, the
routed formats) would read it as an undeclared server, and a fresh install's
first run would be weaker than every later one.

:func:`list_unlisted` closes that gap the generic way: every enabled server
whose block trusts what its server declares (``trusts_served_declaration``),
or whose ``roles`` say the platform reads its undeclared tools as a reputation
service's (``core.derived_declarations``), and for which nothing is kept under
its block's launch identity is attached
long enough to list its tools (the handshake a connection test makes,
``server_probe.handshake``: no tool is called), and what it declares is kept
as any attach keeps it. A server that cannot be reached within the budget is
left unlisted and is read as undeclared, never refused; the run's own attach
lists it again. Such a server, and one whose listing declared nothing, is not
reached again here for a while (:data:`RETRY_SECONDS`), per launch identity,
so a server that is down costs no job its budget twice nor every job forever.
At most :data:`AT_ONCE` servers are listed at a time. Any other server is
not reached here: its declaration is only ever its cautious claims, and what
is read of its tools only whether they send the sample, which its own attach
reads.
"""

from __future__ import annotations

import asyncio
import threading
import time
from typing import Any

from maljan.core.logger import logger

# How long the listing of all of them may take. They are listed side by side,
# once per launch identity, so this is paid by a fresh install's first run and
# after a block is pointed elsewhere, never by a run whose servers are kept.
LISTING_BUDGET_SECONDS = 30.0
# How long a server that could not be listed, or whose listing declared
# nothing, is left unreached here, per (source, launch identity).
RETRY_SECONDS = 600.0
# How many servers are listed at once: each stdio listing starts a process.
AT_ONCE = 4

_LOCK = threading.Lock()
# (source, launch identity) -> when it may be reached here again (monotonic).
_NOT_BEFORE: dict[tuple[str, str], float] = {}


def _resting(source: str, launch: str) -> bool:
    with _LOCK:
        until = _NOT_BEFORE.get((source, launch))
        if until is None:
            return False
        if time.monotonic() >= until:
            _NOT_BEFORE.pop((source, launch), None)
            return False
        return True


def _rest(source: str, launch: str) -> None:
    with _LOCK:
        _NOT_BEFORE[(source, launch)] = time.monotonic() + RETRY_SECONDS


def _read_before_run(source: str, block: Any) -> bool:
    """Whether a block's listing is read by a reader that decides before any server attaches.

    Its block trusts what its server declares, or its ``roles`` hold
    ``reputation``: what is read of a reputation service's undeclared tools
    decides the pack's lookup and the capability binding.
    """
    from maljan.core.reputation import REPUTATION_ROLE
    from maljan.core.tool_declarations import trusts_served

    roles = getattr(block, "roles", None) or ()
    return trusts_served(source, block) or REPUTATION_ROLE in roles


def unlisted(settings: Any) -> list[tuple[str, Any]]:
    """Each enabled server, ``(key, block)``, read before the run (:func:`_read_before_run`),
    of which nothing is kept.

    Not one that could not be listed, or declared nothing, a while ago
    (:data:`RETRY_SECONDS`).
    """
    from maljan.core.served_declarations import kept
    from maljan.core.tool_declarations import launch_identity

    out: list[tuple[str, Any]] = []
    for key, block in settings.mcp.servers.items():
        source = f"mcp:{key}"
        if not getattr(block, "enabled", False) or not _read_before_run(source, block):
            continue
        launch = launch_identity(block)
        if kept(source, launch) or _resting(source, launch):
            continue
        out.append((str(key), block))
    return out


async def list_unlisted(settings: Any, *, budget: float = LISTING_BUDGET_SECONDS) -> list[str]:
    """List every server :func:`unlisted` names, side by side; the keys that declared themselves.

    Each listing keeps what its server declares (``ServerHandle``'s attach
    does, ``core.served_declarations.register_served``). A failure or an
    overrun costs only that server's listing, said once in the log. All of
    them together take ``budget`` at most: one deadline is taken at the start,
    each listing is given what is left of it, and one that would start past it
    is not started (nor rested: it was not tried).
    """
    from maljan.core.served_declarations import kept
    from maljan.core.tool_declarations import launch_identity
    from maljan.providers import server_probe

    wanted = unlisted(settings)
    if not wanted:
        return []
    at_once = asyncio.Semaphore(AT_ONCE)
    deadline = time.monotonic() + budget
    tried: set[str] = set()

    async def _one(key: str, block: Any) -> None:
        async with at_once:
            left = deadline - time.monotonic()
            if left <= 0:
                return
            tried.add(key)
            try:
                await server_probe.handshake(block, key, budget=left)
            except Exception as exc:  # noqa: BLE001 — an unlisted server is read as undeclared
                logger.info(
                    "Server %r was not listed before the run (%s); its tools are read as "
                    "undeclared until it attaches.",
                    key,
                    type(exc).__name__,
                )

    await asyncio.gather(*(_one(key, block) for key, block in wanted))
    listed: list[str] = []
    for key, block in wanted:
        source, launch = f"mcp:{key}", launch_identity(block)
        if kept(source, launch):
            listed.append(key)
        elif key in tried:
            _rest(source, launch)
    return listed

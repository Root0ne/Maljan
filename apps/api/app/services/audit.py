"""The one place an audit row is written.

Audit 2026-07-26 (K1) established the rule: an audit row goes on a session of
its own, never the request-scoped one. ``database.get_db`` commits only when
the endpoint returns successfully, so a row added to the request's session is
rolled back with the ``HTTPException`` that ended it -- which silently
discarded exactly the security-relevant events (a failed login, a refused
delete). A separate session decouples the record from the request
transaction's fate.

Best effort by design: an audit failure must never turn a handled 4xx into a
500, so every error is logged at ERROR and counted for operator visibility.

Dev audit 2026-09-06 (A2) gave this its own module. ``auth`` and ``settings``
each had a private copy of the same twelve lines, and the sample, job and
sandbox-report endpoints -- the actions that put malware and its analysis into
the system -- had no copy at all and wrote nothing.
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import Request

from app import observability
from app.database import async_session_factory
from app.logging_config import get_logger
from app.models.audit import AuditLog

logger = get_logger("api.audit")


def client_ip(request: Request | None) -> str | None:
    """The peer address, or None when there is no client to name."""
    return getattr(getattr(request, "client", None), "host", "") or None


async def record(
    action: str,
    *,
    resource_type: str,
    resource_id: str | None = None,
    user_id: uuid.UUID | None = None,
    details: dict[str, Any] | None = None,
    request: Request | None = None,
    ip: str | None = None,
) -> None:
    """Persist one audit row on an independent transaction. Never raises.

    ``ip`` wins over ``request`` so a caller that already resolved the address
    (the settings service, which is handed one rather than a request) does not
    have to carry the request object just to reach it.
    """
    try:
        async with async_session_factory() as session:
            session.add(
                AuditLog(
                    user_id=user_id,
                    action=action,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    details=details or None,
                    ip_address=ip or client_ip(request),
                )
            )
            await session.commit()
    except Exception as exc:  # noqa: BLE001 - audit is best effort, but never silent
        observability.counters.audit_write_failures += 1
        logger.error("Audit write failed (action=%s): %s", action, type(exc).__name__)

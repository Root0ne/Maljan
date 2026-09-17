"""Reading one job's live conversation back, from wherever it still is.

Two stores hold the same events for different lengths of time. The Redis
stream ``analysis:{job_id}:events`` holds the last thousand for a day and is
what a client reconnecting mid-run reads; ``job_events`` holds all of them for
``core.events.retention_days`` and is what is left afterwards. One reader over
both, used by the events endpoint and by the WebSocket's resume, so a replay
is the same recording whichever store answered it.

The order is Redis first. It is in memory, it is the hot path — a client that
navigated away and came back ten seconds later wants the last few events — and
the table is one query behind it when the stream cannot answer: when it has
expired, and when the cursor the client resumes from is older than the oldest
event the capped stream still holds.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

import redis.asyncio as aioredis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.logging_config import get_logger
from app.logsafe import log_safe

logger = get_logger("api.job_events")

# The most events one read returns. The same ceiling the endpoint's own
# ``limit`` is bounded by, applied here too so a resume with no limit cannot
# ask for a hundred thousand rows.
MAX_EVENTS = 1000


def stream_key(job_id: Any) -> str:
    return f"analysis:{job_id}:events"


def _seq_of(event: dict[str, Any]) -> int:
    """The ``seq`` an event carries, or 0 for one published before there were any."""
    data = event.get("data")
    if not isinstance(data, dict):
        return 0
    try:
        return int(data.get("seq") or 0)
    except (TypeError, ValueError):
        return 0


async def _from_stream(
    redis_conn: aioredis.Redis, job_id: Any, since: int | None, limit: int
) -> list[dict[str, Any]]:
    """What the Redis stream still holds, newer than ``since``."""
    try:
        entries = await redis_conn.xrange(stream_key(job_id), min="-", max="+", count=MAX_EVENTS)
    except Exception as exc:  # noqa: BLE001 — an unreadable stream is an empty one
        logger.warning(f"Event stream read failed for job={log_safe(job_id)}: {log_safe(exc)}")
        return []

    events: list[dict[str, Any]] = []
    for stream_id, fields in entries:
        raw = fields.get("payload") if isinstance(fields, dict) else None
        if not raw:
            continue
        try:
            payload = json.loads(raw)
        except (ValueError, TypeError):
            continue
        if not isinstance(payload, dict):
            continue
        if since is not None and _seq_of(payload) <= since:
            continue
        payload["stream_id"] = stream_id
        events.append(payload)
    return events[:limit]


async def _from_table(
    db: AsyncSession, job_id: Any, since: int | None, limit: int
) -> list[dict[str, Any]]:
    """What the table holds, newer than ``since``, in sequence order."""
    from app.models.job_event import JobEvent

    try:
        job_uuid = job_id if isinstance(job_id, uuid.UUID) else uuid.UUID(str(job_id))
    except (TypeError, ValueError):
        return []

    query = select(JobEvent).where(JobEvent.job_id == job_uuid)
    if since is not None:
        query = query.where(JobEvent.seq > since)
    try:
        rows = (await db.execute(query.order_by(JobEvent.seq).limit(limit))).scalars().all()
    except Exception as exc:  # noqa: BLE001 — a replay never 500s
        logger.warning(f"Event table read failed for job={log_safe(job_id)}: {log_safe(exc)}")
        return []

    return [
        {
            "type": row.type,
            "data": row.payload or {},
            "ts": row.ts.isoformat() if row.ts else None,
        }
        for row in rows
    ]


async def read_events(
    db: AsyncSession,
    redis_conn: aioredis.Redis,
    job_id: Any,
    *,
    since: int | None = None,
    limit: int = 500,
) -> list[dict[str, Any]]:
    """This job's events after ``since``, in sequence order, from either store.

    The table is consulted when the stream answered nothing at all — it has
    expired, or the run predates it — and when what the stream answered starts
    later than the cursor asked for, which is the capped-stream case: a client
    resuming from event 40 of a run that has published 2,000 would otherwise
    be handed events 1,001 onwards with a silent hole in front of them.

    Merged on ``seq``, which is unique per job in both stores, so an event held
    by both is returned once. An event published before sequencing existed
    carries ``seq`` 0; those are kept in the order the stream held them and
    never deduplicated against each other.
    """
    limit = max(1, min(int(limit), MAX_EVENTS))
    from_stream = await _from_stream(redis_conn, job_id, since, limit)
    lowest = min((_seq_of(e) for e in from_stream), default=0)
    complete = bool(from_stream) and (since is None or lowest <= since + 1)
    if complete:
        return sorted(from_stream, key=_seq_of)

    merged: dict[int, dict[str, Any]] = {}
    unsequenced: list[dict[str, Any]] = []
    for event in [*await _from_table(db, job_id, since, limit), *from_stream]:
        seq = _seq_of(event)
        if seq <= 0:
            unsequenced.append(event)
            continue
        merged[seq] = event
    ordered = [merged[seq] for seq in sorted(merged)]
    return (unsequenced + ordered)[:limit]

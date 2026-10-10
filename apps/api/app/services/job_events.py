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

One kind of event is in the table alone: ``model_usage``, one per model call,
which the publisher keeps off the stream and the socket. The events endpoint
asks for it (``usage=True``) and a page the stream answered gets it from the
table; the socket's resume does not ask and gets it from neither store.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

import redis.asyncio as aioredis
from maljan.pipeline.events import MODEL_USAGE
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
    db: AsyncSession,
    job_id: Any,
    since: int | None,
    limit: int | None,
    *,
    usage: bool | None = True,
) -> list[dict[str, Any]]:
    """What the table holds, newer than ``since``, in sequence order.

    ``usage`` is which events about model usage come back: ``True`` every
    event, ``False`` every event but ``model_usage``, ``None`` only
    ``model_usage``. ``limit`` ``None`` is every row.
    """
    from app.models.job_event import JobEvent

    try:
        job_uuid = job_id if isinstance(job_id, uuid.UUID) else uuid.UUID(str(job_id))
    except (TypeError, ValueError):
        return []

    query = select(JobEvent).where(JobEvent.job_id == job_uuid)
    if usage is None:
        query = query.where(JobEvent.type == MODEL_USAGE)
    elif not usage:
        query = query.where(JobEvent.type != MODEL_USAGE)
    if since is not None:
        query = query.where(JobEvent.seq > since)
    query = query.order_by(JobEvent.seq)
    if limit is not None:
        query = query.limit(limit)
    try:
        rows = (await db.execute(query)).scalars().all()
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


async def _with_usage(
    db: AsyncSession,
    job_id: Any,
    since: int | None,
    limit: int,
    page: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """The stream's ``page`` with the table's ``model_usage`` events in its range, on ``seq``.

    A page that came back full may end before the stream does, so a usage
    event past its last ``seq`` is left for the next page: taking it would
    move the client's cursor past the stream events between the two. An event
    both stores hold is returned once.
    """
    found = await _from_table(db, job_id, since, limit, usage=None)
    if not found:
        return page
    if len(page) >= limit:
        last = max((_seq_of(e) for e in page), default=0)
        found = [e for e in found if _seq_of(e) <= last]
    unsequenced = [e for e in page if _seq_of(e) <= 0]
    merged: dict[int, dict[str, Any]] = {_seq_of(e): e for e in found}
    merged.update({_seq_of(e): e for e in page if _seq_of(e) > 0})
    return (unsequenced + [merged[seq] for seq in sorted(merged)])[:limit]


async def read_usage(db: AsyncSession, job_id: Any) -> list[dict[str, Any]]:
    """Every ``model_usage`` record of this job, in sequence order, from the table.

    The table is the only store that holds them. No ceiling: a job's usage
    total is the sum over all of its calls.
    """
    return [
        dict(event["data"])
        for event in await _from_table(db, job_id, None, None, usage=None)
        if isinstance(event.get("data"), dict)
    ]


async def read_events(
    db: AsyncSession,
    redis_conn: aioredis.Redis,
    job_id: Any,
    *,
    since: int | None = None,
    limit: int = 500,
    usage: bool = False,
) -> list[dict[str, Any]]:
    """This job's events after ``since``, in sequence order, from either store.

    ``usage`` adds the job's ``model_usage`` events. The publisher writes them
    to the table alone — the live socket and the capped stream are left to
    the events a reader follows — so a page the stream answers is given the
    table's usage events in its range, merged on ``seq``. The events endpoint
    asks for them; the socket's resume does not, and gets none from either
    store.

    No cursor means "from the beginning", which is the same question as
    ``since=0``: the publisher's first event of a run is ``seq`` 1, so a read
    is complete only when what came back starts there. Anything else — an
    expired stream, a run that predates sequencing, or a stream trimmed past
    its own start, which a long run reaches routinely now that a tool call is
    two events — goes through the table, and the stream is used only for what
    the table does not yet hold.

    That last case is why the test is on the lowest ``seq`` rather than on the
    stream being empty. A run that published 2,400 events keeps 1,401–2,400 in
    a ``maxlen=1000`` stream; a console mounting fresh would otherwise be
    handed a conversation that begins in the middle of the debate, with
    nothing saying so, while the table holds all 2,400 one query away.

    Merged on ``seq``, which is unique per job in both stores, so an event held
    by both is returned once. An event published before sequencing existed
    carries ``seq`` 0; those are kept in the order the stream held them and
    never deduplicated against each other.
    """
    limit = max(1, min(int(limit), MAX_EVENTS))
    from_stream = await _from_stream(redis_conn, job_id, since, limit)
    # ``None`` and ``0`` ask the same question of the stream; they differ only
    # in ``_from_stream``, which leaves an unsequenced legacy event in when no
    # cursor was given and filters it out when one was.
    floor = 0 if since is None else since
    lowest = min((_seq_of(e) for e in from_stream), default=0)
    if from_stream and lowest <= floor + 1:
        page = sorted(from_stream, key=_seq_of)
        if not usage:
            return page
        return await _with_usage(db, job_id, since, limit, page)

    merged: dict[int, dict[str, Any]] = {}
    unsequenced: list[dict[str, Any]] = []
    table = await _from_table(db, job_id, since, limit, usage=usage)
    for event in [*table, *from_stream]:
        seq = _seq_of(event)
        if seq <= 0:
            unsequenced.append(event)
            continue
        merged[seq] = event
    ordered = [merged[seq] for seq in sorted(merged)]
    return (unsequenced + ordered)[:limit]

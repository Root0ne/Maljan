"""WebSocket hub for real-time analysis event streaming.

Architecture:
    1. Client connects to ``/ws/analysis/{job_id}``
    2. Server subscribes to Redis PubSub channel ``analysis:{job_id}``
    3. Every event published by the ARQ worker is forwarded to the client
    4. Client receives JSON messages with event type, data, and timestamp

This provides real-time visibility into:
    - Job status transitions (pending -> running -> completed)
    - Agent progress (which agent is currently analyzing)
    - Confidence updates (per-round convergence)
    - Final verdict delivery
"""

import asyncio
import json
import uuid
from typing import Any

import redis.asyncio as aioredis
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy import select

from app.auth.jwt import decode_token
from app.config import settings
from app.database import async_session_factory
from app.logging_config import get_logger
from app.logsafe import log_safe
from app.models.job import AnalysisJob
from app.models.user import User

logger = get_logger("ws")

router = APIRouter(tags=["WebSocket"])

# How often a streaming socket reads its own account again. Every HTTP route
# reaches ``is_active`` on every request; a socket is one request that lasts
# as long as the run, so it asks on a clock instead. A minute is short against
# the half-hour an access token lives and long against the cost of one
# indexed read per socket.
ACTIVE_RECHECK_SECONDS = 60.0


async def _account_is_open(db: Any, user_id: str) -> bool:
    """Whether this account still exists and is still active.

    The same question ``deps.require_active_user`` asks on every mutating
    HTTP request, asked here because the handshake never did: a user an admin
    deactivated kept the live feed of their own jobs — and everything the
    events on it carry — until their access token expired.
    """
    try:
        user_uuid = uuid.UUID(str(user_id))
    except (ValueError, AttributeError, TypeError):
        return False
    row = (await db.execute(select(User).where(User.id == user_uuid))).scalar_one_or_none()
    return bool(row is not None and getattr(row, "is_active", False))


async def _reject(websocket: WebSocket, code: int, reason: str) -> None:
    """Accept the handshake, then immediately close it with ``code``/``reason``.

    A close sent before ``accept()`` is downgraded by uvicorn to an HTTP 403
    handshake rejection: the close code never becomes a WebSocket close
    frame, so the browser sees 1006 ("abnormal closure") instead of whatever
    code the caller asked for, and a client-side check keyed on that code
    (e.g. "don't auto-reconnect on a rejected credential") never fires.
    Every rejection path in this route must go through this helper — never
    call ``websocket.close(...)`` directly before an ``accept()`` — so the
    accept-then-close pattern cannot drift back to a bare pre-accept close.
    No subprotocol is echoed: nothing about the request was validated, and
    nothing else is sent between the accept and the close.
    """
    await websocket.accept()
    await websocket.close(code=code, reason=reason)


class ConnectionManager:
    """Manages active WebSocket connections and Redis PubSub subscriptions.

    All mutation of ``_active`` / ``_tasks`` happens under ``_lock`` so the
    connect / disconnect paths cannot race when multiple clients arrive
    simultaneously.
    """

    def __init__(self) -> None:
        self._active: dict[str, list[WebSocket]] = {}
        self._tasks: dict[str, asyncio.Task] = {}
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket, job_id: str) -> None:
        """Accept a WebSocket connection and start a PubSub listener if needed."""
        # Per the WebSocket spec, the server may only echo a subprotocol when
        # the client advertised it; otherwise browsers reject the handshake
        # with "Response must not include 'Sec-WebSocket-Protocol' header if
        # not present in request". Inspect the request headers and accept
        # ``maljan.v1`` only when the client actually asked for it.
        requested = websocket.scope.get("subprotocols") or []
        if "maljan.v1" in requested:
            await websocket.accept(subprotocol="maljan.v1")
        else:
            await websocket.accept()
        logger.info("WebSocket connected: job=%s", log_safe(job_id))
        async with self._lock:
            self._active.setdefault(job_id, []).append(websocket)
            if job_id not in self._tasks or self._tasks[job_id].done():
                self._tasks[job_id] = asyncio.create_task(self._redis_listener(job_id))

    async def disconnect(self, websocket: WebSocket, job_id: str) -> None:
        """Remove a WebSocket connection from tracking."""
        logger.info("WebSocket disconnected: job=%s", log_safe(job_id))
        async with self._lock:
            if job_id not in self._active:
                return
            self._active[job_id] = [ws for ws in self._active[job_id] if ws is not websocket]
            if not self._active[job_id]:
                del self._active[job_id]
                task = self._tasks.pop(job_id, None)
                if task and not task.done():
                    task.cancel()
                    logger.debug("Redis PubSub listener cancelled: job=%s", log_safe(job_id))

    async def broadcast(self, job_id: str, message: str) -> None:
        """Send a message to all connected clients watching a job."""
        dead_connections: list[WebSocket] = []
        for ws in list(self._active.get(job_id, [])):
            try:
                await ws.send_text(message)
            except Exception:
                dead_connections.append(ws)

        for ws in dead_connections:
            await self.disconnect(ws, job_id)

    async def _redis_listener(self, job_id: str) -> None:
        """Subscribe to Redis PubSub and forward events to WebSocket clients."""
        redis_conn = aioredis.from_url(settings.redis_url)
        pubsub = redis_conn.pubsub()

        try:
            await pubsub.subscribe(f"analysis:{job_id}")

            while job_id in self._active:
                message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                if message and message["type"] == "message":
                    data = message["data"]
                    if isinstance(data, bytes):
                        data = data.decode("utf-8")
                    await self.broadcast(job_id, data)

                await asyncio.sleep(0.1)
        except asyncio.CancelledError:
            pass
        finally:
            await pubsub.unsubscribe(f"analysis:{job_id}")
            await pubsub.aclose()
            await redis_conn.aclose()


# Global connection manager instance
manager = ConnectionManager()


# How much of a resume is read at once, and how many of those a single resume
# may take. The page size is the reader's own ceiling; the page count bounds a
# socket that would otherwise sit replaying a pathological run while the
# client waits for its first live event.
#
# Ten pages is ten thousand events. A long run publishes a few thousand — two
# per tool call plus a delta per model turn — so this is well above any run
# this has seen while being small enough that a client reconnecting in a loop
# cannot use the handshake as an amplifier: nothing rate-limits reconnects,
# and forty pages of a thousand was forty database reads and forty thousand
# frames per attempt. A resume that reaches the bound stops and says so; the
# client has every event's ``seq`` and can page ``GET /jobs/{id}/events`` for
# the rest.
_REPLAY_PAGE = 1000
_REPLAY_PAGES = 10


async def _replay(websocket: WebSocket, job_id: str, since: int) -> None:
    """Send everything this job published after ``since``, then return.

    Sent after the socket has joined the fan-out rather than before, so an
    event published while the replay is being read is broadcast rather than
    dropped between the two. That can put a live event in front of a replayed
    one; both carry ``seq`` and the client orders and dedupes on it, which is
    what the cursor is for.

    Paged rather than capped. A single read is bounded — by the reader's
    ceiling and, before that, by the Redis stream's own length — so a resume
    that asked for a long run used to get a prefix of what it asked for with
    nothing saying so, and no way for the client to know it should page the
    REST endpoint instead. Each page advances the cursor to the last ``seq``
    it carried, so the next one continues from there.

    Never raises. A replay that cannot be read leaves the client where it
    already was — attached, and one refresh away from the endpoint that reads
    the same two stores.
    """
    sent = 0
    cursor = since
    try:
        from app.services.job_events import read_events

        redis_conn = aioredis.from_url(settings.redis_url, decode_responses=True)
        try:
            for _page in range(_REPLAY_PAGES):
                # A session per page, closed before the page is sent. The
                # send is where the time goes — a thousand frames to a client
                # that reads them as fast as it feels like — and a database
                # transaction held open across it is a backend idle in
                # transaction for as long as that client takes.
                async with async_session_factory() as db:
                    events = await read_events(
                        db, redis_conn, job_id, since=cursor, limit=_REPLAY_PAGE
                    )
                if not events:
                    break
                for event in events:
                    await websocket.send_text(json.dumps(event))
                sent += len(events)
                highest = max(
                    (int((e.get("data") or {}).get("seq") or 0) for e in events), default=0
                )
                if highest <= cursor or len(events) < _REPLAY_PAGE:
                    # Either the page was short — there is nothing more —
                    # or it carried no number this could advance past,
                    # which is a run from before there were numbers and
                    # has no second page to ask for.
                    break
                cursor = highest
                # One page at a time, and the loop gets a turn between
                # them: a resume is a burst of sends on a socket that is
                # also carrying live events for this job and others.
                await asyncio.sleep(0)
            else:
                logger.info(
                    "WebSocket resume reached its page bound at seq=%s: job=%s",
                    log_safe(cursor),
                    log_safe(job_id),
                )
        finally:
            try:
                await redis_conn.aclose()
            except Exception:  # noqa: BLE001
                pass
        logger.info(
            "WebSocket replayed %d event(s) after seq=%s: job=%s",
            sent,
            log_safe(since),
            log_safe(job_id),
        )
    except Exception as exc:  # noqa: BLE001 — a replay never closes a socket
        logger.warning("WebSocket replay failed (job=%s): %s", log_safe(job_id), log_safe(exc))


@router.websocket("/ws/analysis/{job_id}")
async def ws_analysis(websocket: WebSocket, job_id: str, since: int | None = None) -> None:
    """WebSocket endpoint for real-time analysis event streaming.

    Clients connect here to receive live updates about an analysis job.
    Events are forwarded from the ARQ worker via Redis PubSub.

    Resume:
        ``?since=<seq>`` is the last sequence number the client already holds.
        The server replays everything after it — from the Redis stream, or
        from ``job_events`` when the stream has expired or no longer reaches
        back that far — and then forwards live events as usual. Omitting it
        attaches without a replay, which is what a client opening a fresh run
        wants. The cursor changes nothing about the handshake: it is read
        after the credential and the ownership check, and a socket that would
        have been refused is still refused.

    Authentication:
        Pass the JWT access token as a WebSocket subprotocol, never as a
        query parameter (proxy access logs and browser Referer headers can
        leak query strings): open the socket with subprotocols
        ``["maljan.v1", "maljan.v1.<jwt-access-token>"]``. The server
        accepts and echoes back only ``maljan.v1``. Every rejection (missing
        or malformed credential, invalid job ID, unowned job, ...) is
        accepted first (with no subprotocol echoed, since nothing was
        validated) and then immediately closed with its close code via the
        ``_reject`` helper — closing before accept would be turned into an
        HTTP 403 handshake rejection by the ASGI server, which discards the
        close code and leaves the client seeing 1006 instead.

    Event types:
        - ``status_change``: Job status transition
        - ``agent_progress``: Agent started/completed work
        - ``confidence_update``: Per-round confidence snapshot
        - ``completed``: Analysis finished with verdict
        - ``error``: Analysis failed
        - ``cancelled``: Job was cancelled
    """
    # ── Auth gate ────────────────────────────────────────────────────
    #
    # Tokens MUST be sent via the WebSocket subprotocol so they do not appear
    # in proxy access logs or browser Referer headers. The expected protocol
    # is ``maljan.v1.<jwt-access-token>``.
    payload: dict[str, object] = {}
    user_id: str
    if settings.auth_disabled:
        user_id = settings.auth_disabled_user_id
    else:
        token: str | None = None
        requested_protocols = websocket.headers.get("sec-websocket-protocol", "")
        for raw in requested_protocols.split(","):
            candidate = raw.strip()
            if candidate.startswith("maljan.v1."):
                token = candidate[len("maljan.v1.") :]
                break

        if not token:
            logger.warning(  # nosemgrep
                "WebSocket rejected: missing credential (job=%s)", log_safe(job_id)
            )
            await _reject(
                websocket,
                4401,
                "Unauthorized: token must be sent as the maljan.v1.<jwt> subprotocol",
            )
            return

        decoded = decode_token(token)
        if decoded is None:
            logger.warning(  # nosemgrep
                "WebSocket rejected: invalid token (job=%s)", log_safe(job_id)
            )
            await _reject(websocket, 1008, "Unauthorized: invalid token")
            return
        payload = decoded

        if payload.get("type") != "access":
            logger.warning(  # nosemgrep
                "WebSocket rejected: wrong token type (job=%s)", log_safe(job_id)
            )
            await _reject(websocket, 1008, "Unauthorized: access token required")
            return

        sub = payload.get("sub")
        if not sub or not isinstance(sub, str):
            logger.warning(  # nosemgrep
                "WebSocket rejected: token missing subject (job=%s)", log_safe(job_id)
            )
            await _reject(websocket, 1008, "Unauthorized: token missing subject")
            return
        user_id = sub

    # ── Job ownership check ──────────────────────────────────────────
    try:
        job_uuid = uuid.UUID(job_id)
    except ValueError:
        logger.warning("WebSocket rejected: invalid job_id format (%s)", log_safe(job_id))
        await _reject(websocket, 1008, "Bad request: invalid job ID")
        return

    # One spelling from here on. ``uuid.UUID`` accepts the uppercase,
    # brace-wrapped and unhyphenated forms of the same id, and the publisher
    # publishes to the canonical one — so a socket opened under any other
    # spelling was given a bucket, a listener task and a Redis connection of
    # its own, and then received nothing on any of them.
    job_id = str(job_uuid)

    # Both questions are asked and answered inside the session; the handshake
    # they decide happens outside it. A rejection is an accept and a close on
    # a socket whose peer may be slow, and this connection is about to run for
    # the length of an analysis — neither is something to hold a transaction
    # across.
    async with async_session_factory() as db:
        # The account first, and before the job: a caller whose account is
        # closed learns nothing about whether the job exists.
        account_open = await _account_is_open(db, user_id)
        owner: str | None = None
        job_exists = False
        if account_open:
            result = await db.execute(select(AnalysisJob).where(AnalysisJob.id == job_uuid))
            job = result.scalar_one_or_none()
            job_exists = job is not None
            if job is not None:
                owner = str(job.created_by)

    if not account_open:
        logger.warning(
            "WebSocket rejected: account is not active (user=%s job=%s)",
            log_safe(user_id),
            log_safe(job_id),
        )
        await _reject(websocket, 1008, "Unauthorized: account is deactivated")
        return

    if not job_exists:
        logger.warning("WebSocket rejected: job not found (%s)", log_safe(job_id))
        await _reject(websocket, 1008, "Not found: job does not exist")
        return

    if owner != user_id:
        logger.warning(
            "WebSocket rejected: user %s does not own job %s",
            log_safe(user_id),
            log_safe(job_id),
        )
        await _reject(websocket, 1008, "Forbidden: not your job")
        return

    # ── Connection accepted ──────────────────────────────────────────
    logger.info("WebSocket authenticated: user=%s job=%s", log_safe(user_id), log_safe(job_id))
    await manager.connect(websocket, job_id)
    if since is not None and since >= 0:
        await _replay(websocket, job_id, int(since))

    # The handshake checked
    # ``exp``, but a long-lived connection could outlive its token. Read
    # the original ``exp`` claim once and revalidate against the wall
    # clock on every heartbeat tick (~30 s). When expired, close the
    # connection with policy code 1008 so the client must re-auth before
    # reconnecting.
    import time as _time

    _token_exp_ts: float | None = None
    _raw_exp = payload.get("exp")
    if isinstance(_raw_exp, int | float):
        _token_exp_ts = float(_raw_exp)

    # The account is re-read on a clock of its own rather than on the heartbeat
    # boundary, because the heartbeat only fires when the client is silent: a
    # page that pings every few seconds never reaches the timeout branch, and
    # a check that lived there would never run for exactly the client that is
    # watching a run.
    _checked_at = _time.monotonic()

    async def _still_allowed() -> bool:
        nonlocal _checked_at
        if _time.monotonic() - _checked_at < ACTIVE_RECHECK_SECONDS:
            return True
        _checked_at = _time.monotonic()
        try:
            async with async_session_factory() as db:
                return await _account_is_open(db, user_id)
        except Exception as exc:  # noqa: BLE001 — a database blip is not a verdict
            logger.warning(
                "WebSocket account re-check failed (job=%s): %s",
                log_safe(job_id),
                type(exc).__name__,
            )
            return True

    async def _close_unauthorized(reason: str) -> None:
        try:
            await websocket.close(code=1008, reason=reason)
        except Exception:  # noqa: BLE001 — the socket may already be gone
            pass

    try:
        # Keep connection alive — also allows client-to-server messages
        while True:
            try:
                # Wait for client messages (ping/pong or close)
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)

                # Asked before the message is served, not after: a socket the
                # account no longer entitles anyone to is not one to answer
                # once more first.
                if not await _still_allowed():
                    logger.warning(
                        "WebSocket closed: account deactivated mid-stream (user=%s job=%s).",
                        log_safe(user_id),
                        log_safe(job_id),
                    )
                    await _close_unauthorized("Unauthorized: account is deactivated")
                    break

                # Handle client ping
                if data == "ping":
                    await websocket.send_text(json.dumps({"type": "pong", "data": {}}))
            except TimeoutError:
                if not await _still_allowed():
                    logger.warning(
                        "WebSocket closed: account deactivated mid-stream (user=%s job=%s).",
                        log_safe(user_id),
                        log_safe(job_id),
                    )
                    await _close_unauthorized("Unauthorized: account is deactivated")
                    break
                # Re-check token expiry on every heartbeat boundary.
                if _token_exp_ts is not None and _time.time() >= _token_exp_ts:
                    logger.warning(  # nosemgrep: python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure — user_id/job_id are opaque identifiers, not the token  # noqa: E501
                        "WebSocket closed: token expired mid-stream (user=%s job=%s).",
                        log_safe(user_id),
                        log_safe(job_id),
                    )
                    await _close_unauthorized("Unauthorized: token expired")
                    break
                # Send heartbeat to keep connection alive
                try:
                    await websocket.send_text(json.dumps({"type": "heartbeat", "data": {}}))
                except Exception:
                    break
    except WebSocketDisconnect:
        pass
    finally:
        await manager.disconnect(websocket, job_id)

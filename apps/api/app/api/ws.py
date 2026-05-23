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

import redis.asyncio as aioredis
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy import select

from app.auth.jwt import decode_token
from app.config import settings
from app.database import async_session_factory
from app.logging_config import get_logger
from app.models.job import AnalysisJob

logger = get_logger("ws")

router = APIRouter(tags=["WebSocket"])


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
        logger.info("WebSocket connected: job=%s", job_id)
        async with self._lock:
            self._active.setdefault(job_id, []).append(websocket)
            if job_id not in self._tasks or self._tasks[job_id].done():
                self._tasks[job_id] = asyncio.create_task(self._redis_listener(job_id))

    async def disconnect(self, websocket: WebSocket, job_id: str) -> None:
        """Remove a WebSocket connection from tracking."""
        logger.info("WebSocket disconnected: job=%s", job_id)
        async with self._lock:
            if job_id not in self._active:
                return
            self._active[job_id] = [ws for ws in self._active[job_id] if ws is not websocket]
            if not self._active[job_id]:
                del self._active[job_id]
                task = self._tasks.pop(job_id, None)
                if task and not task.done():
                    task.cancel()
                    logger.debug("Redis PubSub listener cancelled: job=%s", job_id)

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


@router.websocket("/ws/analysis/{job_id}")
async def ws_analysis(websocket: WebSocket, job_id: str) -> None:
    """WebSocket endpoint for real-time analysis event streaming.

    Clients connect here to receive live updates about an analysis job.
    Events are forwarded from the ARQ worker via Redis PubSub.

    Authentication:
        Pass the JWT access token as a query parameter:
        ``wss://api/ws/analysis/{job_id}?token=<jwt>``

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
    # is ``maljan.v1.<jwt-access-token>``. Legacy clients passing ``?token=``
    # still work but are logged as deprecated and will be removed.
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

        if token is None:
            legacy = websocket.query_params.get("token")
            if legacy:
                logger.warning(
                    "WebSocket using deprecated query-string auth (job=%s)", job_id
                )  # nosemgrep # noqa: E501
                token = legacy

        if not token:
            logger.warning("WebSocket rejected: missing credential (job=%s)", job_id)  # nosemgrep
            await websocket.close(code=1008, reason="Unauthorized: missing token")
            return

        decoded = decode_token(token)
        if decoded is None:
            logger.warning("WebSocket rejected: invalid token (job=%s)", job_id)  # nosemgrep
            await websocket.close(code=1008, reason="Unauthorized: invalid token")
            return
        payload = decoded

        if payload.get("type") != "access":
            logger.warning("WebSocket rejected: wrong token type (job=%s)", job_id)  # nosemgrep
            await websocket.close(code=1008, reason="Unauthorized: access token required")
            return

        sub = payload.get("sub")
        if not sub or not isinstance(sub, str):
            logger.warning(  # nosemgrep
                "WebSocket rejected: token missing subject (job=%s)", job_id
            )
            await websocket.close(code=1008, reason="Unauthorized: token missing subject")
            return
        user_id = sub

    # ── Job ownership check ──────────────────────────────────────────
    try:
        job_uuid = uuid.UUID(job_id)
    except ValueError:
        logger.warning("WebSocket rejected: invalid job_id format (%s)", job_id)
        await websocket.close(code=1008, reason="Bad request: invalid job ID")
        return

    async with async_session_factory() as db:
        result = await db.execute(select(AnalysisJob).where(AnalysisJob.id == job_uuid))
        job = result.scalar_one_or_none()

        if job is None:
            logger.warning("WebSocket rejected: job not found (%s)", job_id)
            await websocket.close(code=1008, reason="Not found: job does not exist")
            return

        if str(job.created_by) != user_id:
            logger.warning(
                "WebSocket rejected: user %s does not own job %s",
                user_id,
                job_id,
            )
            await websocket.close(code=1008, reason="Forbidden: not your job")
            return

    # ── Connection accepted ──────────────────────────────────────────
    logger.info("WebSocket authenticated: user=%s job=%s", user_id, job_id)
    await manager.connect(websocket, job_id)

    # SEC-WS-AUTH-CONTINUOUS-01 (audit 2026-05-19): the handshake checked
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

    try:
        # Keep connection alive — also allows client-to-server messages
        while True:
            try:
                # Wait for client messages (ping/pong or close)
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)

                # Handle client ping
                if data == "ping":
                    await websocket.send_text(json.dumps({"type": "pong", "data": {}}))
            except TimeoutError:
                # Re-check token expiry on every heartbeat boundary.
                if _token_exp_ts is not None and _time.time() >= _token_exp_ts:
                    logger.warning(
                        "WebSocket closed: token expired mid-stream (user=%s job=%s).",
                        user_id,
                        job_id,
                    )
                    try:
                        await websocket.close(code=1008, reason="Unauthorized: token expired")
                    except Exception:
                        pass
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

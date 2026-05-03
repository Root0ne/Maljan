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

import redis.asyncio as aioredis
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.config import settings
from app.logging_config import get_logger

logger = get_logger("ws")

router = APIRouter(tags=["WebSocket"])


class ConnectionManager:
    """Manages active WebSocket connections and Redis PubSub subscriptions."""

    def __init__(self) -> None:
        self._active: dict[str, list[WebSocket]] = {}  # job_id -> [websockets]
        self._tasks: dict[str, asyncio.Task] = {}  # job_id -> subscriber task

    async def connect(self, websocket: WebSocket, job_id: str) -> None:
        """Accept a WebSocket connection and start a PubSub listener if needed."""
        await websocket.accept()
        logger.info(f"WebSocket connected: job={job_id}")

        if job_id not in self._active:
            self._active[job_id] = []
        self._active[job_id].append(websocket)

        # Start a Redis PubSub listener for this job if not already running
        if job_id not in self._tasks or self._tasks[job_id].done():
            self._tasks[job_id] = asyncio.create_task(self._redis_listener(job_id))

    def disconnect(self, websocket: WebSocket, job_id: str) -> None:
        """Remove a WebSocket connection from tracking."""
        logger.info(f"WebSocket disconnected: job={job_id}")
        if job_id in self._active:
            self._active[job_id] = [ws for ws in self._active[job_id] if ws is not websocket]
            # If no more connections for this job, cancel the listener
            if not self._active[job_id]:
                del self._active[job_id]
                task = self._tasks.pop(job_id, None)
                if task and not task.done():
                    task.cancel()
                    logger.debug(f"Redis PubSub listener cancelled: job={job_id}")

    async def broadcast(self, job_id: str, message: str) -> None:
        """Send a message to all connected clients watching a job."""
        dead_connections = []
        for ws in self._active.get(job_id, []):
            try:
                await ws.send_text(message)
            except Exception:
                dead_connections.append(ws)

        # Clean up dead connections
        for ws in dead_connections:
            self.disconnect(ws, job_id)

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

    Event types:
        - ``status_change``: Job status transition
        - ``agent_progress``: Agent started/completed work
        - ``confidence_update``: Per-round confidence snapshot
        - ``completed``: Analysis finished with verdict
        - ``error``: Analysis failed
        - ``cancelled``: Job was cancelled
    """
    await manager.connect(websocket, job_id)

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
                # Send heartbeat to keep connection alive
                try:
                    await websocket.send_text(json.dumps({"type": "heartbeat", "data": {}}))
                except Exception:
                    break
    except WebSocketDisconnect:
        pass
    finally:
        manager.disconnect(websocket, job_id)

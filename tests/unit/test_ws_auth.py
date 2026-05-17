"""Unit tests for WebSocket authentication gate.

These tests verify that the /ws/analysis/{job_id} endpoint correctly:
  - Rejects connections without a token
  - Rejects connections with invalid tokens
  - Rejects connections with refresh tokens (access token required)
  - Rejects users trying to watch another user's job
  - Accepts the job owner with a valid access token
"""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from app.api.ws import ws_analysis  # noqa: I001
from fastapi import WebSocket, WebSocketDisconnect


@pytest.fixture
def mock_ws() -> MagicMock:
    """Return a mocked WebSocket object."""
    ws = MagicMock(spec=WebSocket)
    ws.query_params = {}
    ws.close = AsyncMock()
    ws.accept = AsyncMock()
    ws.receive_text = AsyncMock(side_effect=WebSocketDisconnect())
    ws.send_text = AsyncMock()
    return ws


@pytest.fixture
def valid_token_payload() -> dict:
    return {"sub": str(uuid.uuid4()), "type": "access"}


# ---------------------------------------------------------------------------
# Missing / invalid token
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ws_rejects_missing_token(mock_ws: MagicMock) -> None:
    mock_ws.query_params = {}

    await ws_analysis(mock_ws, str(uuid.uuid4()))

    mock_ws.close.assert_awaited_once_with(code=1008, reason="Unauthorized: missing token")
    mock_ws.accept.assert_not_awaited()


@pytest.mark.asyncio
async def test_ws_rejects_invalid_token(mock_ws: MagicMock) -> None:
    mock_ws.query_params = {"token": "bad-token"}

    with patch("app.api.ws.decode_token", return_value=None):
        await ws_analysis(mock_ws, str(uuid.uuid4()))

    mock_ws.close.assert_awaited_once_with(code=1008, reason="Unauthorized: invalid token")


@pytest.mark.asyncio
async def test_ws_rejects_refresh_token(mock_ws: MagicMock) -> None:
    mock_ws.query_params = {"token": "refresh-token"}

    with patch("app.api.ws.decode_token", return_value={"sub": "user-1", "type": "refresh"}):
        await ws_analysis(mock_ws, str(uuid.uuid4()))

    mock_ws.close.assert_awaited_once_with(code=1008, reason="Unauthorized: access token required")


@pytest.mark.asyncio
async def test_ws_rejects_token_without_subject(mock_ws: MagicMock) -> None:
    mock_ws.query_params = {"token": "no-sub-token"}

    with patch("app.api.ws.decode_token", return_value={"type": "access"}):
        await ws_analysis(mock_ws, str(uuid.uuid4()))

    mock_ws.close.assert_awaited_once_with(code=1008, reason="Unauthorized: token missing subject")


# ---------------------------------------------------------------------------
# Job ownership
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ws_rejects_invalid_job_id(mock_ws: MagicMock) -> None:
    mock_ws.query_params = {"token": "tok"}

    with patch("app.api.ws.decode_token", return_value={"sub": "user-1", "type": "access"}):
        await ws_analysis(mock_ws, "not-a-uuid")

    mock_ws.close.assert_awaited_once_with(code=1008, reason="Bad request: invalid job ID")


@pytest.mark.asyncio
async def test_ws_rejects_nonexistent_job(mock_ws: MagicMock) -> None:
    job_id = str(uuid.uuid4())
    mock_ws.query_params = {"token": "tok"}

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None

    mock_session = AsyncMock()
    mock_session.execute = AsyncMock(return_value=mock_result)

    with (
        patch("app.api.ws.decode_token", return_value={"sub": "user-1", "type": "access"}),
        patch("app.api.ws.async_session_factory") as mock_factory,
    ):
        mock_factory.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        mock_factory.return_value.__aexit__ = AsyncMock(return_value=False)
        await ws_analysis(mock_ws, job_id)

    mock_ws.close.assert_awaited_once_with(code=1008, reason="Not found: job does not exist")


@pytest.mark.asyncio
async def test_ws_rejects_wrong_owner(mock_ws: MagicMock, valid_token_payload: dict) -> None:
    job_id = str(uuid.uuid4())
    mock_ws.query_params = {"token": "tok"}

    job = MagicMock()
    job.created_by = uuid.uuid4()  # different user

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = job

    mock_session = AsyncMock()
    mock_session.execute = AsyncMock(return_value=mock_result)

    with (
        patch("app.api.ws.decode_token", return_value=valid_token_payload),
        patch("app.api.ws.async_session_factory") as mock_factory,
    ):
        mock_factory.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        mock_factory.return_value.__aexit__ = AsyncMock(return_value=False)
        await ws_analysis(mock_ws, job_id)

    mock_ws.close.assert_awaited_once_with(code=1008, reason="Forbidden: not your job")


@pytest.mark.asyncio
async def test_ws_accepts_valid_owner(mock_ws: MagicMock, valid_token_payload: dict) -> None:
    user_id = uuid.UUID(valid_token_payload["sub"])
    job_id = str(uuid.uuid4())
    mock_ws.query_params = {"token": "tok"}

    job = MagicMock()
    job.created_by = user_id

    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = job

    mock_session = AsyncMock()
    mock_session.execute = AsyncMock(return_value=mock_result)

    with (
        patch("app.api.ws.decode_token", return_value=valid_token_payload),
        patch("app.api.ws.async_session_factory") as mock_factory,
        patch("app.api.ws.manager") as mock_manager,
    ):
        mock_factory.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        mock_factory.return_value.__aexit__ = AsyncMock(return_value=False)
        mock_manager.connect = AsyncMock()
        # The endpoint's finally-block awaits manager.disconnect; without the
        # AsyncMock here the await raises TypeError on a plain MagicMock.
        mock_manager.disconnect = AsyncMock()
        await ws_analysis(mock_ws, job_id)

    mock_ws.close.assert_not_awaited()
    mock_manager.connect.assert_awaited_once_with(mock_ws, job_id)

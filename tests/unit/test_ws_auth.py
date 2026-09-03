"""Unit tests for WebSocket authentication gate.

These tests verify that the /ws/analysis/{job_id} endpoint correctly:
  - Rejects connections with refresh tokens (access token required)
  - Rejects connections with a token that has no subject
  - Rejects connections with a malformed job ID
  - Rejects connections for a job that does not exist
  - Rejects users trying to watch another user's job
  - Accepts the job owner with a valid access token

The token travels only in the ``sec-websocket-protocol`` header, as
``maljan.v1.<jwt>`` (see ``app.api.ws``): the endpoint no longer reads a
``?token=`` query parameter at all. Every rejection is accepted first (no
subprotocol echoed) and then closed immediately via the ``_reject`` helper
so a real close frame reaches the client — closing before accept is
downgraded by the ASGI server to an HTTP 403 that discards the close code.
These tests assert that accept-then-close order directly, the same way
``tests/api/test_ws_auth.py`` does at the ASGI/TestClient level.

The "missing credential" (4401) and "invalid token" (1008) scenarios are
covered at that more realistic layer by ``tests/api/test_ws_auth.py``
(``test_missing_credential_accepts_before_closing_with_4401`` and the
``invalid-token`` case of ``test_rejection_branches_accept_before_closing_with_1008``)
and were removed from here as exact duplicates.
"""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest
from app.api.ws import ws_analysis  # noqa: I001
from fastapi import WebSocket, WebSocketDisconnect


def _subprotocol_headers(token: str) -> dict[str, str]:
    """Build the header the endpoint reads the ``maljan.v1.<jwt>`` token from."""
    return {"sec-websocket-protocol": f"maljan.v1, maljan.v1.{token}"}


@pytest.fixture
def mock_ws() -> MagicMock:
    """Return a mocked WebSocket object with no subprotocol offered by default."""
    ws = MagicMock(spec=WebSocket)
    ws.headers = {}
    ws.close = AsyncMock()
    ws.accept = AsyncMock()
    ws.receive_text = AsyncMock(side_effect=WebSocketDisconnect())
    ws.send_text = AsyncMock()
    return ws


@pytest.fixture
def valid_token_payload() -> dict:
    return {"sub": str(uuid.uuid4()), "type": "access"}


# ---------------------------------------------------------------------------
# Token validity (missing credential / invalid token duplicated at the
# tests/api/test_ws_auth.py layer and removed from here)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ws_rejects_refresh_token(mock_ws: MagicMock) -> None:
    mock_ws.headers = _subprotocol_headers("refresh-token")

    with patch("app.api.ws.decode_token", return_value={"sub": "user-1", "type": "refresh"}):
        await ws_analysis(mock_ws, str(uuid.uuid4()))

    assert mock_ws.method_calls == [
        call.accept(),
        call.close(code=1008, reason="Unauthorized: access token required"),
    ]


@pytest.mark.asyncio
async def test_ws_rejects_token_without_subject(mock_ws: MagicMock) -> None:
    mock_ws.headers = _subprotocol_headers("no-sub-token")

    with patch("app.api.ws.decode_token", return_value={"type": "access"}):
        await ws_analysis(mock_ws, str(uuid.uuid4()))

    assert mock_ws.method_calls == [
        call.accept(),
        call.close(code=1008, reason="Unauthorized: token missing subject"),
    ]


# ---------------------------------------------------------------------------
# Job ownership
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ws_rejects_invalid_job_id(mock_ws: MagicMock) -> None:
    mock_ws.headers = _subprotocol_headers("tok")

    with patch("app.api.ws.decode_token", return_value={"sub": "user-1", "type": "access"}):
        await ws_analysis(mock_ws, "not-a-uuid")

    assert mock_ws.method_calls == [
        call.accept(),
        call.close(code=1008, reason="Bad request: invalid job ID"),
    ]


@pytest.mark.asyncio
async def test_ws_rejects_nonexistent_job(mock_ws: MagicMock) -> None:
    job_id = str(uuid.uuid4())
    mock_ws.headers = _subprotocol_headers("tok")

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

    assert mock_ws.method_calls == [
        call.accept(),
        call.close(code=1008, reason="Not found: job does not exist"),
    ]


@pytest.mark.asyncio
async def test_ws_rejects_wrong_owner(mock_ws: MagicMock, valid_token_payload: dict) -> None:
    job_id = str(uuid.uuid4())
    mock_ws.headers = _subprotocol_headers("tok")

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

    assert mock_ws.method_calls == [
        call.accept(),
        call.close(code=1008, reason="Forbidden: not your job"),
    ]


@pytest.mark.asyncio
async def test_ws_accepts_valid_owner(mock_ws: MagicMock, valid_token_payload: dict) -> None:
    user_id = uuid.UUID(valid_token_payload["sub"])
    job_id = str(uuid.uuid4())
    mock_ws.headers = _subprotocol_headers("tok")

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

    # Success routes accept/subprotocol-echo through manager.connect (mocked
    # away here and exercised for real at the tests/api/test_ws_auth.py
    # layer, which checks ws.accepted_subprotocol == "maljan.v1"); the
    # endpoint itself never calls accept/close directly on this path.
    mock_ws.close.assert_not_awaited()
    mock_ws.accept.assert_not_awaited()
    mock_manager.connect.assert_awaited_once_with(mock_ws, job_id)

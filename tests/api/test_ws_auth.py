"""The WebSocket access token travels only as the ``maljan.v1.<jwt>`` subprotocol.

A token in the ``?token=`` query string is refused before accept (close code
4401); a token carried in the subprotocol list is accepted and the server
echoes back the bare ``maljan.v1`` subprotocol.
"""

import sys
import uuid
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

_API = Path(__file__).resolve().parents[2] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

from app.api import ws as ws_module  # noqa: E402


class _FakeJob:
    """Stand-in for ``AnalysisJob`` with just the field the ownership check reads."""

    def __init__(self, created_by: str) -> None:
        self.created_by = created_by


class _FakeResult:
    def __init__(self, job: _FakeJob | None) -> None:
        self._job = job

    def scalar_one_or_none(self) -> _FakeJob | None:
        return self._job


class _FakeSession:
    """Async context manager standing in for the real DB session.

    Lets the accepted-path test reach ``manager.connect`` (and thus the
    subprotocol accept under test) without a real database.
    """

    def __init__(self, job: _FakeJob | None) -> None:
        self._job = job

    async def __aenter__(self) -> "_FakeSession":
        return self

    async def __aexit__(self, *exc_info: object) -> bool:
        return False

    async def execute(self, *_args: object, **_kwargs: object) -> _FakeResult:
        return _FakeResult(self._job)


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setattr(ws_module.settings, "auth_disabled", False)
    monkeypatch.setattr(
        ws_module,
        "decode_token",
        lambda t: {"sub": "u1", "type": "access"} if t == "good" else None,
    )
    app = FastAPI()
    app.include_router(ws_module.router)
    return TestClient(app)


def test_query_string_token_is_refused(client: TestClient) -> None:
    job_id = str(uuid.uuid4())
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect(f"/ws/analysis/{job_id}?token=good"):
            pass
    assert exc.value.code == 4401


def test_subprotocol_token_is_accepted(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    job_id = str(uuid.uuid4())

    # The job-ownership check below the auth gate needs a session that
    # resolves to a job owned by the decoded token's ``sub`` ("u1").
    monkeypatch.setattr(
        ws_module,
        "async_session_factory",
        lambda: _FakeSession(_FakeJob(created_by="u1")),
    )

    # Stop the connection from spawning a real Redis PubSub listener; the
    # handshake/accept path under test happens before any event forwarding.
    async def _no_listener(self: object, job_id: str) -> None:
        return None

    monkeypatch.setattr(ws_module.ConnectionManager, "_redis_listener", _no_listener)

    with client.websocket_connect(
        f"/ws/analysis/{job_id}", subprotocols=["maljan.v1", "maljan.v1.good"]
    ) as ws:
        assert ws.accepted_subprotocol == "maljan.v1"

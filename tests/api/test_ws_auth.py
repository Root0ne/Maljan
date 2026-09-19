"""The WebSocket access token travels only as the ``maljan.v1.<jwt>`` subprotocol.

A token in the ``?token=`` query string (or no token at all) is rejected:
the server accepts the handshake and then immediately closes with 4401 — a
token carried in the subprotocol list is accepted and the server echoes
back the bare ``maljan.v1`` subprotocol.

Why accept-then-close and not just close: closing a WebSocket *before*
``accept()`` is turned into an HTTP 403 handshake rejection by the ASGI
server (uvicorn). The close code never makes it into a WebSocket close
frame, so a browser sees close code 1006 ("abnormal closure") instead of
4401, and a client-side check keyed on 4401 (e.g. "don't auto-reconnect on
a rejected credential") never fires. ``TestClient.websocket_connect()``
models this faithfully: with a pre-accept close, entering the ``with``
block itself raises ``WebSocketDisconnect``; with accept-then-close, the
``with`` block is entered successfully (the accept happened) and the close
frame with code 4401 only appears on the *next* receive — which is why the
assertions below call ``ws.receive_text()`` inside the block rather than
relying on ``pytest.raises`` around the ``with`` statement itself.
"""

import json
import uuid

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.websockets import WebSocket, WebSocketDisconnect

from app.api import ws as ws_module  # noqa: E402

# The subject of an access token is a user id, so the stand-in is one too:
# the route reads the row it names, and a session that is asked for a row has
# to be asked with a value the column can hold.
USER_ID = "11111111-1111-4111-8111-111111111111"


class _FakeJob:
    """Stand-in for ``AnalysisJob`` with just the field the ownership check reads."""

    def __init__(self, created_by: str) -> None:
        self.created_by = created_by


class _FakeUser:
    """Stand-in for ``User`` with just the field the account check reads."""

    def __init__(self, is_active: bool = True) -> None:
        self.is_active = is_active


# The default account: open, because that is what every test about something
# else needs. ``None`` in its place is an account that is not there at all.
_ACTIVE_ACCOUNT = _FakeUser()


class _FakeResult:
    def __init__(self, row: object | None) -> None:
        self._row = row

    def scalar_one_or_none(self) -> object | None:
        return self._row


class _FakeSession:
    """Async context manager standing in for the real DB session.

    Answers by what was asked for: the route reads the ``User`` row and then
    the job row, and a session that answered both with the same object would
    let a missing account pass as a present one.
    """

    def __init__(self, job: _FakeJob | None, user: _FakeUser | None = _ACTIVE_ACCOUNT) -> None:
        self._job = job
        self._user = user
        self.asked: list[str] = []

    async def __aenter__(self) -> "_FakeSession":
        return self

    async def __aexit__(self, *exc_info: object) -> bool:
        return False

    async def execute(self, statement: object, *_a: object, **_k: object) -> _FakeResult:
        text = str(statement)
        self.asked.append("users" if "users" in text else "jobs")
        return _FakeResult(self._user if "users" in text else self._job)


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setattr(ws_module.settings, "auth_disabled", False)
    monkeypatch.setattr(
        ws_module,
        "decode_token",
        lambda t: {"sub": USER_ID, "type": "access"} if t == "good" else None,
    )
    app = FastAPI()
    app.include_router(ws_module.router)
    return TestClient(app)


def test_query_string_token_is_refused(client: TestClient) -> None:
    job_id = str(uuid.uuid4())
    # The handshake itself succeeds (accept-then-close, see module
    # docstring): the disconnect only surfaces once something tries to
    # receive after the close frame arrives.
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect(f"/ws/analysis/{job_id}?token=good") as ws:
            ws.receive_text()
    assert exc.value.code == 4401


def test_missing_credential_accepts_before_closing_with_4401(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The missing-credential branch must accept the handshake before closing.

    A close sent before ``accept()`` is downgraded by uvicorn to an HTTP 403
    handshake rejection, which discards the close code entirely. This test
    guards the ordering directly by recording calls to
    ``WebSocket.accept``/``WebSocket.close`` on the class the route uses,
    rather than only inferring it from the client-visible close code.
    """
    calls: list[tuple[str, object]] = []
    original_accept = WebSocket.accept
    original_close = WebSocket.close

    async def recording_accept(self: WebSocket, *args: object, **kwargs: object) -> None:
        calls.append(("accept", kwargs.get("subprotocol")))
        await original_accept(self, *args, **kwargs)

    async def recording_close(self: WebSocket, *args: object, **kwargs: object) -> None:
        code = kwargs.get("code", args[0] if args else None)
        calls.append(("close", code))
        await original_close(self, *args, **kwargs)

    monkeypatch.setattr(WebSocket, "accept", recording_accept)
    monkeypatch.setattr(WebSocket, "close", recording_close)

    job_id = str(uuid.uuid4())
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(f"/ws/analysis/{job_id}") as ws:
            ws.receive_text()

    assert calls == [("accept", None), ("close", 4401)]


@pytest.mark.parametrize(
    "protocols, job_lookup, expected_reason",
    [
        pytest.param(
            ["maljan.v1", "maljan.v1.bad"],
            None,
            "invalid token",
            id="invalid-token",
        ),
        pytest.param(
            ["maljan.v1", "maljan.v1.good"],
            "not_found",
            "does not exist",
            id="job-not-found",
        ),
    ],
)
def test_rejection_branches_accept_before_closing_with_1008(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    protocols: list[str],
    job_lookup: str | None,
    expected_reason: str,
) -> None:
    """1008 branches must accept before closing too, same as the 4401 one.

    These go through the shared ``_reject`` helper (Fix round 2), so the
    close code reaches the client as a real close frame rather than being
    downgraded to 1006 by a pre-accept HTTP 403. Covers the "invalid token"
    branch (fails before any DB lookup) and the "job not found" branch
    (needs a session that resolves to no job), per the review's minimum.
    """
    if job_lookup == "not_found":
        monkeypatch.setattr(ws_module, "async_session_factory", lambda: _FakeSession(None))

    job_id = str(uuid.uuid4())
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect(f"/ws/analysis/{job_id}", subprotocols=protocols) as ws:
            ws.receive_text()

    assert exc.value.code == 1008
    assert expected_reason in (exc.value.reason or "")


def test_subprotocol_token_is_accepted(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    job_id = str(uuid.uuid4())

    # The job-ownership check below the auth gate needs a session that
    # resolves to a job owned by the decoded token's ``sub`` ("u1").
    monkeypatch.setattr(
        ws_module,
        "async_session_factory",
        lambda: _FakeSession(_FakeJob(created_by=USER_ID)),
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


def test_a_resume_cursor_does_not_bypass_the_credential(client: TestClient) -> None:
    """``?since=`` is read after the auth gate, never instead of it.

    A cursor is the one thing a client may add to this handshake, so it is the
    one thing worth pinning: an unauthenticated socket asking to resume is
    refused exactly as an unauthenticated socket asking for nothing is, and
    nothing is replayed to it.
    """
    job_id = str(uuid.uuid4())
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect(f"/ws/analysis/{job_id}?since=0") as ws:
            ws.receive_text()
    assert exc.value.code == 4401


def test_a_resume_cursor_does_not_bypass_the_ownership_check(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    replayed: list[int] = []

    async def _recording_replay(websocket: object, job_id: str, since: int) -> None:
        replayed.append(since)

    monkeypatch.setattr(ws_module, "_replay", _recording_replay)
    monkeypatch.setattr(
        ws_module, "async_session_factory", lambda: _FakeSession(_FakeJob(created_by="somebody"))
    )

    job_id = str(uuid.uuid4())
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect(
            f"/ws/analysis/{job_id}?since=5", subprotocols=["maljan.v1", "maljan.v1.good"]
        ) as ws:
            ws.receive_text()

    assert exc.value.code == 1008
    assert "not your job" in (exc.value.reason or "")
    assert replayed == []


def test_an_owner_that_resumes_is_replayed_from_its_cursor(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    replayed: list[int] = []

    async def _recording_replay(websocket: object, job_id: str, since: int) -> None:
        replayed.append(since)

    async def _no_listener(self: object, job_id: str) -> None:
        return None

    monkeypatch.setattr(ws_module, "_replay", _recording_replay)
    monkeypatch.setattr(ws_module.ConnectionManager, "_redis_listener", _no_listener)
    monkeypatch.setattr(
        ws_module, "async_session_factory", lambda: _FakeSession(_FakeJob(created_by=USER_ID))
    )

    job_id = str(uuid.uuid4())
    with client.websocket_connect(
        f"/ws/analysis/{job_id}?since=42", subprotocols=["maljan.v1", "maljan.v1.good"]
    ) as ws:
        assert ws.accepted_subprotocol == "maljan.v1"
    assert replayed == [42]


def test_a_socket_with_no_cursor_is_not_replayed_to(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    replayed: list[int] = []

    async def _recording_replay(websocket: object, job_id: str, since: int) -> None:
        replayed.append(since)

    async def _no_listener(self: object, job_id: str) -> None:
        return None

    monkeypatch.setattr(ws_module, "_replay", _recording_replay)
    monkeypatch.setattr(ws_module.ConnectionManager, "_redis_listener", _no_listener)
    monkeypatch.setattr(
        ws_module, "async_session_factory", lambda: _FakeSession(_FakeJob(created_by=USER_ID))
    )

    job_id = str(uuid.uuid4())
    with client.websocket_connect(
        f"/ws/analysis/{job_id}", subprotocols=["maljan.v1", "maljan.v1.good"]
    ):
        pass
    assert replayed == []


class TestADeactivatedAccountIsRefused:
    """Every HTTP route reaches ``is_active``; this one never did.

    The handshake decoded the token, checked its type and subject, and went
    straight to the ownership query — so an account an admin had just
    deactivated kept the full live feed of its own jobs, everything on it
    included, until the access token expired half an hour later.
    """

    def test_a_deactivated_account_cannot_open_the_socket(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            ws_module,
            "async_session_factory",
            lambda: _FakeSession(_FakeJob(created_by=USER_ID), _FakeUser(is_active=False)),
        )

        job_id = str(uuid.uuid4())
        with pytest.raises(WebSocketDisconnect) as exc:
            with client.websocket_connect(
                f"/ws/analysis/{job_id}", subprotocols=["maljan.v1", "maljan.v1.good"]
            ) as ws:
                ws.receive_text()

        assert exc.value.code == 1008
        assert "deactivated" in (exc.value.reason or "")

    def test_an_account_that_no_longer_exists_cannot_open_the_socket(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            ws_module,
            "async_session_factory",
            lambda: _FakeSession(_FakeJob(created_by=USER_ID), None),
        )

        job_id = str(uuid.uuid4())
        with pytest.raises(WebSocketDisconnect) as exc:
            with client.websocket_connect(
                f"/ws/analysis/{job_id}", subprotocols=["maljan.v1", "maljan.v1.good"]
            ) as ws:
                ws.receive_text()

        assert exc.value.code == 1008

    def test_the_account_is_read_before_the_job(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Authentication before authorisation: a refused account learns
        nothing about whether the job exists."""
        session = _FakeSession(_FakeJob(created_by=USER_ID), _FakeUser(is_active=False))
        monkeypatch.setattr(ws_module, "async_session_factory", lambda: session)

        job_id = str(uuid.uuid4())
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(
                f"/ws/analysis/{job_id}", subprotocols=["maljan.v1", "maljan.v1.good"]
            ) as ws:
                ws.receive_text()

        assert session.asked == ["users"]

    def test_a_deactivation_mid_stream_closes_the_socket(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The account is re-read while the socket streams, so a deactivation
        does not wait for the token to expire."""
        user = _FakeUser(is_active=True)
        monkeypatch.setattr(
            ws_module,
            "async_session_factory",
            lambda: _FakeSession(_FakeJob(created_by=USER_ID), user),
        )

        async def _no_listener(self: object, job_id: str) -> None:
            return None

        monkeypatch.setattr(ws_module.ConnectionManager, "_redis_listener", _no_listener)
        # Every tick is due, so the first message after the deactivation is
        # the one that reads the row again.
        monkeypatch.setattr(ws_module, "ACTIVE_RECHECK_SECONDS", 0.0)

        job_id = str(uuid.uuid4())
        with pytest.raises(WebSocketDisconnect) as exc:
            with client.websocket_connect(
                f"/ws/analysis/{job_id}", subprotocols=["maljan.v1", "maljan.v1.good"]
            ) as ws:
                ws.send_text("ping")
                assert json.loads(ws.receive_text())["type"] == "pong"
                user.is_active = False
                ws.send_text("ping")
                ws.receive_text()

        assert exc.value.code == 1008
        assert "deactivated" in (exc.value.reason or "")

    def test_an_active_account_keeps_its_socket(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            ws_module,
            "async_session_factory",
            lambda: _FakeSession(_FakeJob(created_by=USER_ID), _FakeUser(is_active=True)),
        )

        async def _no_listener(self: object, job_id: str) -> None:
            return None

        monkeypatch.setattr(ws_module.ConnectionManager, "_redis_listener", _no_listener)
        monkeypatch.setattr(ws_module, "ACTIVE_RECHECK_SECONDS", 0.0)

        job_id = str(uuid.uuid4())
        with client.websocket_connect(
            f"/ws/analysis/{job_id}", subprotocols=["maljan.v1", "maljan.v1.good"]
        ) as ws:
            ws.send_text("ping")
            assert json.loads(ws.receive_text())["type"] == "pong"
            ws.send_text("ping")
            assert json.loads(ws.receive_text())["type"] == "pong"


class TestTheJobIdIsCanonical:
    """One job, one bucket. ``uuid.UUID`` accepts several spellings of the same
    id and the publisher uses the canonical one, so a socket opened under any
    other spelling got its own listener, its own Redis connection and no
    events at all."""

    def test_an_uppercase_id_is_normalised_before_anything_uses_it(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        connected: list[str] = []
        disconnected: list[str] = []
        replayed: list[str] = []

        async def _recording_connect(self: object, websocket: object, job_id: str) -> None:
            connected.append(job_id)
            await websocket.accept()  # type: ignore[attr-defined]

        async def _recording_disconnect(self: object, websocket: object, job_id: str) -> None:
            disconnected.append(job_id)

        async def _recording_replay(websocket: object, job_id: str, since: int) -> None:
            replayed.append(job_id)

        monkeypatch.setattr(ws_module.ConnectionManager, "connect", _recording_connect)
        monkeypatch.setattr(ws_module.ConnectionManager, "disconnect", _recording_disconnect)
        monkeypatch.setattr(ws_module, "_replay", _recording_replay)
        monkeypatch.setattr(
            ws_module,
            "async_session_factory",
            lambda: _FakeSession(_FakeJob(created_by=USER_ID)),
        )

        canonical = str(uuid.uuid4())
        with client.websocket_connect(
            f"/ws/analysis/{canonical.upper()}?since=3",
            subprotocols=["maljan.v1", "maljan.v1.good"],
        ):
            pass

        assert connected == [canonical]
        assert replayed == [canonical]
        assert disconnected == [canonical]

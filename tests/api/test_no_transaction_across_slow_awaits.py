"""No request path holds a database transaction across a slow await.

A request-scoped session is in a transaction from its first statement — on an
authenticated route, the dependency that resolved the caller — and stays in it
until the handler returns. The routes here then wait on somebody else: a probe
may spend five minutes at a model endpoint, the purge scrolls a whole Qdrant
collection, and a WebSocket resume sends a thousand frames to a client that
reads them whenever it likes. A transaction left open across any of those is a
backend ``idle in transaction`` for the length of it, holding its locks
against every migration and every reader — the same defect the worker was
carrying, on the request side.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1.settings import router as settings_router
from app.database import get_db
from app.deps import require_admin
from app.services.settings_probes import ProbeResult


class FakeSession:
    """The bits of ``AsyncSession`` a route touches, with a transaction flag."""

    def __init__(self) -> None:
        self.in_transaction = False
        self.commits = 0

    async def execute(self, *args: Any, **kwargs: Any) -> MagicMock:
        self.in_transaction = True
        result = MagicMock()
        result.scalars.return_value.all.return_value = []
        result.scalar_one_or_none.return_value = None
        result.all.return_value = []
        return result

    async def commit(self) -> None:
        self.in_transaction = False
        self.commits += 1

    async def rollback(self) -> None:
        self.in_transaction = False

    async def close(self) -> None:
        self.in_transaction = False

    def add(self, obj: Any) -> None:
        self.in_transaction = True

    async def __aenter__(self) -> FakeSession:
        return self

    async def __aexit__(self, *exc: Any) -> bool:
        await self.close()
        return False


@pytest.fixture
def session() -> FakeSession:
    return FakeSession()


@pytest.fixture
def client(session: FakeSession) -> TestClient:
    app = FastAPI()
    # The router carries its own ``/settings`` prefix.
    app.include_router(settings_router, prefix="/api/v1")
    app.dependency_overrides[require_admin] = lambda: MagicMock(
        id="00000000-0000-0000-0000-000000000001"
    )

    def _db() -> FakeSession:
        # The dependency that resolved the caller has already read from this
        # session on every authenticated route, so the handler starts inside a
        # transaction. Said here rather than left implicit, because that is
        # the state the routes below have to end.
        session.in_transaction = True
        return session

    app.dependency_overrides[get_db] = _db
    return TestClient(app)


def _stored_is_empty():
    return patch("app.api.v1.settings.SettingsService.load_overrides", AsyncMock(return_value={}))


@pytest.mark.parametrize(
    ("path", "params", "target"),
    [
        ("/api/v1/settings/test/llm", None, "app.api.v1.settings.run_probe"),
        (
            "/api/v1/settings/test/mcp",
            {"server": "analysis"},
            "app.api.v1.settings.run_mcp_probe",
        ),
        (
            "/api/v1/settings/test/agent",
            {"name": "static"},
            "app.api.v1.settings.run_agent_probe",
        ),
    ],
)
def test_a_probe_runs_with_no_transaction_open(
    client: TestClient, session: FakeSession, path: str, params: Any, target: str
) -> None:
    open_during_the_probe: list[bool] = []

    async def _probe(*args: Any, **kwargs: Any) -> ProbeResult:
        open_during_the_probe.append(session.in_transaction)
        return ProbeResult(True, 1, "ok", None, [], {})

    with (
        _stored_is_empty(),
        patch(target, _probe),
        # The audit row goes on a session of its own, which here would be a
        # real one: this test is about the request's transaction.
        patch("app.api.v1.settings.audit_record", AsyncMock()),
        patch("app.api.v1.settings._write_down_what_was_reached", AsyncMock()),
    ):
        response = client.post(path, params=params, json={"values": {}})

    assert response.status_code == 200, response.text
    assert open_during_the_probe == [False]
    assert session.commits >= 1


def test_the_virustotal_registration_runs_with_no_transaction_open(
    client: TestClient, session: FakeSession
) -> None:
    """The call goes to VirusTotal; the request's transaction does not wait on it."""
    open_during_the_call: list[bool] = []

    from app.services.virustotal_register import RegistrationError

    async def _register() -> dict[str, str]:
        open_during_the_call.append(session.in_transaction)
        raise RegistrationError("VirusTotal refused the registration")

    with patch("app.api.v1.settings.register_agent", _register):
        response = client.post("/api/v1/settings/virustotal/register")

    assert response.status_code == 502
    assert open_during_the_call == [False]


def test_the_memory_purge_runs_with_no_transaction_open(session: FakeSession) -> None:
    """The purge scrolls a whole Qdrant collection; Postgres waits for none of it."""
    from app.api.v1.system import router as system_router

    app = FastAPI()
    app.include_router(system_router, prefix="/api/v1")
    app.dependency_overrides[require_admin] = lambda: MagicMock(id="admin")
    app.dependency_overrides[get_db] = lambda: session
    client = TestClient(app)

    open_during_the_purge: list[bool] = []

    class _Store:
        _cases: list[Any] = []

        def purge_low_quality(self, **kwargs: Any) -> int:
            open_during_the_purge.append(session.in_transaction)
            return 3

    async def _build(db: Any) -> Any:
        # Reading the settings is what puts the request in a transaction.
        await db.execute("select the configured collection")
        return _Store()

    with patch("app.api.v1.system._build_memory_store", _build):
        response = client.post("/api/v1/system/ltm/purge", json={"dry_run": False})

    assert response.status_code == 200, response.text
    assert response.json()["removed"] == 3
    assert open_during_the_purge == [False]
    assert session.commits >= 1


@pytest.mark.asyncio
async def test_the_websocket_resume_closes_its_session_before_sending() -> None:
    """The send is where a resume spends its time, and it is a client's pace."""
    from app.api import ws as ws_module

    open_sessions: list[Any] = []
    sessions: list[FakeSession] = []
    open_while_sending: list[int] = []

    class _Session(FakeSession):
        # ``async with`` resolves the protocol on the type, so the bookkeeping
        # lives on a subclass rather than on the instance.
        async def __aenter__(self) -> Any:
            open_sessions.append(self)
            return self

        async def __aexit__(self, *exc: Any) -> bool:
            open_sessions.remove(self)
            return False

    def _factory() -> FakeSession:
        made = _Session()
        sessions.append(made)
        return made

    page = [{"type": "agent_message", "data": {"seq": n}} for n in range(3)]

    async def _read_events(db: Any, redis: Any, job_id: str, *, since: int, limit: int) -> list:
        # The read happens inside a session, as it must.
        assert open_sessions
        return page if since == 0 else []

    socket = MagicMock()

    async def _send_text(payload: str) -> None:
        open_while_sending.append(len(open_sessions))
        json.loads(payload)

    socket.send_text = _send_text

    with (
        patch.object(ws_module, "async_session_factory", _factory),
        patch("app.services.job_events.read_events", _read_events),
        patch.object(ws_module.aioredis, "from_url", MagicMock(return_value=AsyncMock())),
    ):
        await ws_module._replay(socket, "0b6c6e0e-0000-4000-8000-000000000000", 0)

    assert open_while_sending == [0, 0, 0]
    assert open_sessions == []
    assert len(sessions) >= 1


@pytest.mark.asyncio
async def test_the_websocket_handshake_checks_are_answered_inside_the_session() -> None:
    """The reject itself is a send on a socket, and happens outside it."""
    from app.api import ws as ws_module

    open_sessions: list[Any] = []

    class _Session(FakeSession):
        async def __aenter__(self) -> Any:
            open_sessions.append(self)
            return self

        async def __aexit__(self, *exc: Any) -> bool:
            open_sessions.remove(self)
            return False

    open_while_rejecting: list[int] = []

    async def _reject(websocket: Any, code: int, reason: str) -> None:
        open_while_rejecting.append(len(open_sessions))

    socket = MagicMock()
    socket.scope = {"subprotocols": []}
    socket.headers = {}

    with (
        patch.object(ws_module, "async_session_factory", _Session),
        patch.object(ws_module, "_reject", _reject),
        patch.object(ws_module.settings, "auth_disabled", True),
        patch.object(ws_module.settings, "auth_disabled_user_id", "not-a-uuid"),
    ):
        await ws_module.ws_analysis(socket, "0b6c6e0e-0000-4000-8000-000000000000")

    # The account check refuses the unparseable id, and the refusal is sent
    # after the session has closed.
    assert open_while_rejecting == [0]
    assert open_sessions == []

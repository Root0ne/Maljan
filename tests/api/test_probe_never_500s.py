"""A probe reports a failure; it never takes the request down with it.

B1 (dev audit 2026-09-06): a staged stdio entry whose command is not an MCP
server made ``POST /settings/test/mcp`` answer 500. The stdio handshake runs
inside an anyio task group, and a child that dies during the handshake
cancels that group -- the cancel scope reached the *request* task, so the
handler returned no response at all and the logging middleware raised
``RuntimeError: No response returned``. The browser saw a bare connection
failure with no CORS headers rather than a legible message.

Every case here goes through the real probe code (no ``ServerHandle`` stub)
against the FastAPI test client, and every one of them must be a 200 carrying
``ok=false`` -- followed by a second request that still succeeds, because a
cancel scope that escaped once would poison the loop for everything after it.
"""

from __future__ import annotations

import asyncio
import shutil
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from app.api.v1.settings import router  # noqa: E402
from app.database import get_db  # noqa: E402
from app.deps import require_admin  # noqa: E402
from app.middleware.logging_middleware import RequestLoggingMiddleware  # noqa: E402
from fastapi import FastAPI
from fastapi.testclient import TestClient

_TRUE = shutil.which("true") or "/bin/true"
_ECHO = shutil.which("echo") or "/bin/echo"


@pytest.fixture
def client() -> TestClient:
    app = FastAPI()
    # The middleware is what turned the escaped cancellation into a 500: it is
    # a ``BaseHTTPMiddleware``, whose ``call_next`` raises "No response
    # returned." when the task it is waiting on is cancelled instead of
    # answering. Without it in the stack the bug is invisible from a test
    # client, so it is part of the reproduction rather than scenery.
    app.add_middleware(RequestLoggingMiddleware)
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[require_admin] = lambda: MagicMock(
        id="00000000-0000-0000-0000-000000000001"
    )
    app.dependency_overrides[get_db] = lambda: MagicMock()
    return TestClient(app)


def _probe(client: TestClient, entry: dict) -> dict:
    with patch("app.api.v1.settings.SettingsService.load_overrides", AsyncMock(return_value={})):
        response = client.post(
            "/api/v1/settings/test/mcp",
            params={"server": "uiaudit_srv"},
            json={"values": {"core.mcp.servers": {"uiaudit_srv": entry}}},
        )
    assert response.status_code == 200, response.text
    return response.json()


@pytest.mark.parametrize(
    ("label", "entry"),
    [
        (
            "a command that exits at once without speaking MCP",
            {"enabled": True, "transport": "stdio", "command": _TRUE},
        ),
        (
            "a command that does not exist",
            {
                "enabled": True,
                "transport": "stdio",
                "command": "maljan-no-such-binary-uiaudit",
            },
        ),
        (
            "a command that prints garbage and exits",
            {
                "enabled": True,
                "transport": "stdio",
                "command": _ECHO,
                "args": ["not json at all"],
            },
        ),
    ],
)
def test_a_command_that_is_not_an_mcp_server_is_reported_not_raised(client, label, entry):
    body = _probe(client, entry)
    assert body["ok"] is False, f"{label} was reported as a success"
    assert body["detail"].strip(), f"{label} produced an empty message"


def test_the_api_still_answers_after_a_failed_probe(client):
    _probe(client, {"enabled": True, "transport": "stdio", "command": _TRUE})
    with patch("app.api.v1.settings.SettingsService.load_overrides", AsyncMock(return_value={})):
        again = client.post(
            "/api/v1/settings/test/mcp",
            params={"server": "nothing_staged_here"},
            json={"values": {}},
        )
    assert again.status_code == 200, again.text
    assert again.json()["ok"] is False
    assert "unknown server" in again.json()["detail"]


def test_an_agent_bound_to_a_dead_server_is_reported_not_raised(client):
    """The agent probe opens the same handles and must fail the same way."""
    values = {
        "core.mcp.servers": {
            "uiaudit_srv": {
                "enabled": True,
                "transport": "stdio",
                "command": _TRUE,
                "agents": ["uiaudit_gen"],
            }
        },
        "core.agents.definitions": {
            "uiaudit_gen": {
                "role": "generic",
                "label": "UI audit",
                "prompt": "probe me",
                "enabled": True,
            }
        },
    }
    with patch("app.api.v1.settings.SettingsService.load_overrides", AsyncMock(return_value={})):
        response = client.post(
            "/api/v1/settings/test/agent",
            params={"name": "uiaudit_gen"},
            json={"values": values},
        )
    assert response.status_code == 200, response.text


class _DyingHandle:
    """A handle whose ``aopen`` fails the way a dying stdio child fails.

    ``ServerHandle.aopen`` re-raises whatever ended the handshake, unchanged,
    and an anyio task group whose child process dies mid-handshake ends it
    with a cancellation -- either bare or wrapped in the group's own
    ``BaseExceptionGroup``. Neither is an ``Exception``, so neither was caught
    on the way out, and the request task inherited the cancellation.
    """

    raised: BaseException = RuntimeError("not configured")

    def __init__(self, name, config):
        self.name = name
        self.config = config

    async def aopen(self, job_id, **kw):
        raise type(self).raised

    async def aclose(self):
        return None

    def all_tool_names(self):
        return []


@pytest.mark.parametrize(
    ("label", "raised"),
    [
        ("a bare cancellation", asyncio.CancelledError()),
        (
            "a task group's exception group carrying one",
            BaseExceptionGroup("unhandled errors in a TaskGroup", [asyncio.CancelledError()]),
        ),
    ],
)
def test_a_cancelled_handshake_is_reported_not_inherited(client, monkeypatch, label, raised):
    monkeypatch.setattr("app.services.settings_probes.ServerHandle", _DyingHandle)
    _DyingHandle.raised = raised
    body = _probe(client, {"enabled": True, "transport": "stdio", "command": _TRUE})
    assert body["ok"] is False, f"{label} was reported as a success"
    assert body["detail"].strip(), f"{label} produced an empty message"

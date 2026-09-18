"""Registering the VirusTotal agent from the product.

The endpoint does three things and each is tested here: it asks VirusTotal for
a token, it stores that token the way every other tool-server credential is
stored -- its own encrypted row, never the JSON map -- and it turns the server
on. The fourth thing it must never do is echo the token back, which is what the
masked answer is for.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1.settings import router
from app.database import get_db
from app.deps import require_admin
from app.services.server_map import TOKEN_MASK, server_token_key
from app.services.settings_service import SettingsService
from app.services.virustotal_register import (
    RegistrationError,
    register_agent,
    server_map_with_token,
)
from maljan.core import settings_secrets as box
from maljan.core import virustotal

TOKEN = "vtai_" + "b" * 43
FACTS = {
    "agent_token": TOKEN,
    "agent_id": "agt_00000000-0000-0000-0000-000000000000",
    "public_handle": "Agent#00000000",
    "mcp_endpoint": virustotal.MCP_ENDPOINT,
}


@pytest.fixture
def client() -> TestClient:
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[require_admin] = lambda: MagicMock(
        id="00000000-0000-0000-0000-000000000001"
    )
    # The route ends the request's read transaction before it calls
    # VirusTotal, so the stand-in session has to answer ``commit``.
    app.dependency_overrides[get_db] = lambda: MagicMock(commit=AsyncMock())
    return TestClient(app)


class _Rows(list):
    """A stand-in session: records what was written, replays what is stored."""

    def __init__(self, rows=()):
        super().__init__(rows)
        self.added: list = []

    def add(self, row):
        self.added.append(row)

    async def delete(self, row):
        return None

    async def commit(self):
        return None


class TestTheRegisterCall:
    @pytest.mark.asyncio
    async def test_it_posts_the_agent_family_and_returns_the_token(self) -> None:
        seen: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["url"] = str(request.url)
            seen["body"] = request.read().decode()
            return httpx.Response(200, json=dict(FACTS, setup_url="https://x"))

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            facts = await register_agent(client=http)

        assert seen["url"] == virustotal.REGISTER_URL
        assert virustotal.AGENT_FAMILY in seen["body"]
        assert virustotal.VT_MCP_VERSION in seen["body"]
        assert facts["agent_token"] == TOKEN
        assert facts["public_handle"] == FACTS["public_handle"]

    @pytest.mark.asyncio
    async def test_an_answer_without_a_token_is_a_registration_error(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"agent_id": "agt_1"})

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            with pytest.raises(RegistrationError):
                await register_agent(client=http)

    @pytest.mark.asyncio
    async def test_a_rejected_registration_carries_virustotals_own_sentence(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(429, text="Too many requests, retry later")

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            with pytest.raises(RegistrationError) as exc:
                await register_agent(client=http)

        assert "429" in str(exc.value) and "retry later" in str(exc.value)


class TestTheEndpoint:
    def test_it_enables_the_server_and_answers_with_the_mask(self, client) -> None:
        saved: dict = {}

        async def _save(self, changes, *, user_id, ip):
            saved.update(changes)
            return SimpleNamespace(applied=list(changes), applies="restart")

        with (
            patch("app.api.v1.settings.register_agent", AsyncMock(return_value=dict(FACTS))),
            patch("app.api.v1.settings.SettingsService.load_overrides", AsyncMock(return_value={})),
            patch.object(SettingsService, "save", _save),
            patch("app.api.v1.settings.audit_record", AsyncMock()),
        ):
            response = client.post("/api/v1/settings/virustotal/register")

        assert response.status_code == 200
        body = response.json()
        assert body["enabled"] is True
        assert body["auth_token"] == TOKEN_MASK
        assert body["public_handle"] == FACTS["public_handle"]
        assert body["url"] == virustotal.MCP_ENDPOINT
        assert TOKEN not in response.text

        entry = saved["core.mcp.servers"][virustotal.SERVER_KEY]
        assert entry["enabled"] is True
        assert entry["auth_token"] == TOKEN

    def test_a_failed_registration_stores_nothing(self, client) -> None:
        save = AsyncMock()
        with (
            patch(
                "app.api.v1.settings.register_agent",
                AsyncMock(side_effect=RegistrationError("ConnectError: no route")),
            ),
            patch.object(SettingsService, "save", save),
        ):
            response = client.post("/api/v1/settings/virustotal/register")

        assert response.status_code == 502
        assert "no route" in response.json()["errors"]["virustotal"]
        save.assert_not_awaited()


class TestWhereTheTokenLands:
    def test_the_operators_other_servers_and_edits_survive_a_registration(self) -> None:
        stored = {
            "r2custom": {"enabled": True, "command": "r2mcp"},
            virustotal.SERVER_KEY: {
                "enabled": False,
                "transport": "streamable-http",
                "url": virustotal.MCP_ENDPOINT,
                "tools": ["get_file_report"],
                "agents": ["judge"],
            },
        }

        servers = server_map_with_token(stored, TOKEN)

        assert servers["r2custom"] == {"enabled": True, "command": "r2mcp"}
        assert servers[virustotal.SERVER_KEY]["tools"] == ["get_file_report"]
        assert servers[virustotal.SERVER_KEY]["agents"] == ["judge"]
        assert servers[virustotal.SERVER_KEY]["enabled"] is True

    @pytest.mark.asyncio
    async def test_saving_that_map_puts_the_token_in_its_own_encrypted_row(
        self, monkeypatch
    ) -> None:
        """The endpoint stores nothing itself; it hands the map to ``save``.

        So the claim worth pinning is what ``save`` then does with it: the
        JSON row carries no credential and the token is a separate encrypted
        ``is_secret`` row, exactly as a token typed into the console is.
        """
        from cryptography.fernet import Fernet

        monkeypatch.setenv(box.ENV_VAR, Fernet.generate_key().decode())
        session = _Rows()
        service = SettingsService(MagicMock())
        service._rows = AsyncMock(return_value=[])  # type: ignore[method-assign]
        service.db = session
        service.load_overrides = AsyncMock(return_value={})  # type: ignore[method-assign]

        await service.save(
            {"core.mcp.servers": server_map_with_token({}, TOKEN)}, user_id=None, ip=None
        )

        map_row = next(r for r in session.added if r.key == "core.mcp.servers")
        token_row = next(
            r for r in session.added if r.key == server_token_key(virustotal.SERVER_KEY)
        )
        assert TOKEN not in str(map_row.value)
        assert map_row.value[virustotal.SERVER_KEY]["enabled"] is True
        assert token_row.is_secret is True
        assert box.decrypt(str(token_row.value)) == TOKEN

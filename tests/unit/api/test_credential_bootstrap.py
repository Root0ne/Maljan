"""Obtaining a tool server's credential by the request its declaration names.

The route does three things and each is tested here: it performs the declared
request, it stores the token the way every other tool-server credential is
stored -- its own encrypted row, never the JSON map -- and it turns the server
on. It never echoes the token, never logs it, takes no URL from its caller,
refuses a non-https declaration, and is admin-only. VirusTotal's agent-token
registration is the shipped declaration; an invented server declared only as
data gets the same route.
"""

from __future__ import annotations

import json
import logging
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.api.v1.settings import router
from app.database import get_db
from app.deps import require_admin
from app.services import credential_bootstrap
from app.services.server_map import TOKEN_MASK, server_token_key
from app.services.settings_service import SettingsService
from maljan.core import settings_secrets as box
from maljan.core import virustotal
from maljan.core.config import MCPServerConfig
from maljan.core.tool_declarations import CredentialBootstrap

# Built at run time: never a literal that looks like a credential.
VT_TOKEN = "vtai_" + "b" * 43
INVENTED_TOKEN = "".join(["inv", "_", "c" * 24])
INVENTED_HOST = ".".join(["issuer", "example", "org"])
VT_ANSWER = {
    "agent_token": VT_TOKEN,
    "agent_id": "agt_00000000-0000-0000-0000-000000000000",
    "public_handle": "Agent#00000000",
    "mcp_endpoint": virustotal.MCP_ENDPOINT,
}


def _invented_server(**bootstrap: Any) -> dict[str, Any]:
    """A tool server no code names, whose credential is issued by one request."""
    return {
        "enabled": False,
        "transport": "streamable-http",
        "url": f"https://{INVENTED_HOST}/mcp",
        "label": "Invented intel",
        "tools": [],
        "credential_bootstrap": {
            "url": f"https://{INVENTED_HOST}/register",
            "body": {"client": "{family}", "scope": "read"},
            "token_json_path": "/grant/token",
            "token_prefix": "inv_",
            "family": "maljan-test",
            "facts": {"client_id": "/grant/client"},
            "note": "Issued per deployment.",
            **bootstrap,
        },
    }


class _Wire:
    def __init__(self, answer: Any, status: int = 200) -> None:
        self.answer, self.status = answer, status
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if isinstance(self.answer, str):
            return httpx.Response(self.status, text=self.answer)
        return httpx.Response(self.status, json=self.answer)

    def factory(self) -> Any:
        return lambda: httpx.AsyncClient(transport=httpx.MockTransport(self))


def _client(*, admin: bool = True) -> TestClient:
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    if admin:
        app.dependency_overrides[require_admin] = lambda: MagicMock(
            id="00000000-0000-0000-0000-000000000001"
        )
    else:

        def _refused() -> None:
            raise HTTPException(status_code=403, detail="admin role required")

        app.dependency_overrides[require_admin] = _refused
    # The route ends the request's read transaction before it calls out, so
    # the stand-in session has to answer ``commit``.
    app.dependency_overrides[get_db] = lambda: MagicMock(commit=AsyncMock())
    return TestClient(app)


def _post(stored: dict[str, Any], wire: _Wire, key: str, saved: dict[str, Any]) -> httpx.Response:
    async def _save(self: Any, changes: dict[str, Any], *, user_id: Any, ip: Any) -> Any:
        saved.update(changes)
        return SimpleNamespace(applied=list(changes), applies="restart")

    with (
        patch.object(SettingsService, "load_overrides", AsyncMock(return_value=stored)),
        patch.object(SettingsService, "save", _save),
        patch.object(credential_bootstrap, "new_client", wire.factory()),
        patch("app.api.v1.settings.audit_record", AsyncMock()) as audit,
    ):
        response = _client().post(f"/api/v1/settings/servers/{key}/credential", json={"url": "x"})
    _post.audit = audit  # type: ignore[attr-defined]
    return response


class TestTheShippedDeclaration:
    def test_virustotal_s_registration_is_the_built_in_s_declaration(self) -> None:
        from maljan.core.config import _builtin_servers

        declared = _builtin_servers()[virustotal.SERVER_KEY].credential_bootstrap
        assert declared is not None
        assert declared.url == virustotal.REGISTER_URL
        assert declared.request_body() == {
            "agent_family": virustotal.AGENT_FAMILY,
            "agent_version": virustotal.VT_MCP_VERSION,
        }
        assert declared.token_prefix == "vtai_"

    def test_it_makes_the_same_request_stores_the_same_row_and_answers_as_before(self) -> None:
        wire = _Wire(dict(VT_ANSWER, setup_url="https://x"))
        saved: dict[str, Any] = {}
        response = _post({}, wire, virustotal.SERVER_KEY, saved)

        assert response.status_code == 200, response.text
        (request,) = wire.requests
        assert request.method == "POST"
        assert str(request.url) == virustotal.REGISTER_URL
        assert json.loads(request.read()) == {
            "agent_family": virustotal.AGENT_FAMILY,
            "agent_version": virustotal.VT_MCP_VERSION,
        }
        body = response.json()
        assert body["server"] == virustotal.SERVER_KEY
        assert body["enabled"] is True
        assert body["auth_token"] == TOKEN_MASK
        assert body["url"] == virustotal.MCP_ENDPOINT
        assert body["transport"] == "streamable-http"
        assert body["facts"] == {
            "public_handle": VT_ANSWER["public_handle"],
            "agent_id": VT_ANSWER["agent_id"],
        }
        assert VT_TOKEN not in response.text

        entry = saved["core.mcp.servers"][virustotal.SERVER_KEY]
        assert entry["enabled"] is True
        assert entry["auth_token"] == VT_TOKEN
        audit_details = _post.audit.call_args.kwargs["details"]  # type: ignore[attr-defined]
        assert VT_TOKEN not in json.dumps(audit_details)

    def test_a_refusal_carries_the_service_s_sentence_and_stores_nothing(self) -> None:
        saved: dict[str, Any] = {}
        response = _post({}, _Wire("Too many requests, retry later", 429), "virustotal", saved)
        assert response.status_code == 502
        said = response.json()["errors"]["virustotal"]
        assert "429" in said and "retry later" in said
        assert saved == {}

    def test_an_answer_without_a_token_is_refused(self) -> None:
        saved: dict[str, Any] = {}
        response = _post({}, _Wire({"agent_id": "agt_1"}), "virustotal", saved)
        assert response.status_code == 502
        assert "carried no credential" in response.json()["errors"]["virustotal"]
        assert saved == {}

    def test_a_token_without_the_declared_prefix_is_refused(self) -> None:
        saved: dict[str, Any] = {}
        answer = dict(VT_ANSWER, agent_token="other_" + "d" * 20)
        response = _post({}, _Wire(answer), "virustotal", saved)
        assert response.status_code == 502
        assert saved == {}


class TestAnInventedServer:
    def test_a_server_declared_only_as_data_gets_the_route(self) -> None:
        stored = {"core.mcp.servers": {"invented": _invented_server()}}
        wire = _Wire({"grant": {"token": INVENTED_TOKEN, "client": "cl-7"}})
        saved: dict[str, Any] = {}
        response = _post(stored, wire, "invented", saved)

        assert response.status_code == 200, response.text
        (request,) = wire.requests
        assert str(request.url) == f"https://{INVENTED_HOST}/register"
        assert json.loads(request.read()) == {"client": "maljan-test", "scope": "read"}
        body = response.json()
        assert body["facts"] == {"client_id": "cl-7"}
        assert body["url"] == f"https://{INVENTED_HOST}/mcp"
        assert INVENTED_TOKEN not in response.text
        entry = saved["core.mcp.servers"]["invented"]
        assert entry["enabled"] is True and entry["auth_token"] == INVENTED_TOKEN
        # The other built-ins are left for the save to re-seed; nothing else moved.
        assert set(saved["core.mcp.servers"]) == {"invented"}

    def test_a_server_without_a_declaration_has_no_route(self) -> None:
        stored = {"core.mcp.servers": {"plain": {"enabled": True, "command": "x"}}}
        response = _post(stored, _Wire({}), "plain", {})
        assert response.status_code == 404
        assert _post(stored, _Wire({}), "nowhere", {}).status_code == 404

    def test_the_schema_offers_its_step(self) -> None:
        from app.api.v1.settings import served_schema
        from app.services.credential_bootstrap import bootstrap_facts

        configs = {
            "invented": MCPServerConfig.model_validate(_invented_server()),
            "plain": MCPServerConfig(),
        }
        assert bootstrap_facts(configs) == {
            "invented": {
                "label": "Invented intel",
                "family": "maljan-test",
                "note": "Issued per deployment.",
            }
        }
        schema = served_schema([], profiles=[], agents=[], server_configs=configs)
        assert list(schema.credential_servers) == ["invented"]


class TestSecurity:
    def test_the_route_requires_admin(self) -> None:
        response = _client(admin=False).post("/api/v1/settings/servers/virustotal/credential")
        assert response.status_code == 403

    def test_the_url_comes_from_the_declaration_never_the_request(self) -> None:
        wire = _Wire(dict(VT_ANSWER))
        _post({}, wire, "virustotal", {})
        # The request carried a "url" field; the call went where the declaration says.
        assert str(wire.requests[0].url) == virustotal.REGISTER_URL

    @pytest.mark.parametrize(
        "url",
        [
            f"http://{INVENTED_HOST}/register",
            "ftp://x/y",
            "https://" + ":".join(["user", "pw"]) + chr(64) + INVENTED_HOST + "/r",
        ],
    )
    def test_a_declaration_that_is_not_plain_https_is_refused(self, url: str) -> None:
        with pytest.raises(ValidationError):
            MCPServerConfig.model_validate(_invented_server(url=url))

    def test_the_token_never_reaches_a_log_line(self, caplog: pytest.LogCaptureFixture) -> None:
        caplog.set_level(logging.DEBUG)
        _post({}, _Wire(dict(VT_ANSWER)), "virustotal", {})
        refused = _post({}, _Wire(dict(VT_ANSWER), 500), "virustotal", {})
        assert VT_TOKEN not in caplog.text
        # A refusing answer that still carries a credential has it masked.
        assert VT_TOKEN not in refused.text and TOKEN_MASK in refused.text

    @pytest.mark.asyncio
    async def test_redirects_are_not_followed(self) -> None:
        async with credential_bootstrap.new_client() as http:
            assert http.follow_redirects is False


class TestWhereTheTokenLands:
    def test_the_operators_other_servers_and_edits_survive(self) -> None:
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
        servers = credential_bootstrap.server_map_with_token(
            stored, virustotal.SERVER_KEY, VT_TOKEN
        )
        assert servers["r2custom"] == {"enabled": True, "command": "r2mcp"}
        assert servers[virustotal.SERVER_KEY]["tools"] == ["get_file_report"]
        assert servers[virustotal.SERVER_KEY]["agents"] == ["judge"]
        assert servers[virustotal.SERVER_KEY]["enabled"] is True

    @pytest.mark.asyncio
    async def test_saving_that_map_puts_the_token_in_its_own_encrypted_row(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cryptography.fernet import Fernet

        class _Rows(list):
            def __init__(self) -> None:
                super().__init__()
                self.added: list = []

            def add(self, row: Any) -> None:
                self.added.append(row)

            async def delete(self, row: Any) -> None:
                return None

            async def commit(self) -> None:
                return None

        monkeypatch.setenv(box.ENV_VAR, Fernet.generate_key().decode())
        session = _Rows()
        service = SettingsService(MagicMock())
        service._rows = AsyncMock(return_value=[])  # type: ignore[method-assign]
        service.db = session  # type: ignore[assignment]
        service.load_overrides = AsyncMock(return_value={})  # type: ignore[method-assign]

        servers = credential_bootstrap.server_map_with_token({}, virustotal.SERVER_KEY, VT_TOKEN)
        await service.save({"core.mcp.servers": servers}, user_id=None, ip=None)

        map_row = next(r for r in session.added if r.key == "core.mcp.servers")
        token_row = next(
            r for r in session.added if r.key == server_token_key(virustotal.SERVER_KEY)
        )
        assert VT_TOKEN not in str(map_row.value)
        assert map_row.value[virustotal.SERVER_KEY]["enabled"] is True
        # The shipped declaration is not frozen into the stored row.
        assert "credential_bootstrap" not in map_row.value[virustotal.SERVER_KEY]
        assert token_row.is_secret is True
        assert box.decrypt(str(token_row.value)) == VT_TOKEN


def test_a_declaration_reads_its_family_into_the_body() -> None:
    declared = CredentialBootstrap(
        url="https://a.example/r",
        body={"who": "{family}", "nested": ["{family}", 1]},
        token_json_path="/t",
        family="fam",
    )
    assert declared.request_body() == {"who": "fam", "nested": ["fam", 1]}

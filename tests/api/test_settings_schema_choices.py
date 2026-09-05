"""The API fills in every choice list; the web computes none."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

_API = Path(__file__).resolve().parents[2] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

from app.api.v1.settings import router  # noqa: E402
from app.database import get_db  # noqa: E402
from app.deps import require_admin  # noqa: E402


@pytest.fixture
def client() -> TestClient:
    """The same harness ``tests/api/test_settings_routes.py`` uses."""
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[require_admin] = lambda: MagicMock(
        id="00000000-0000-0000-0000-000000000001"
    )
    app.dependency_overrides[get_db] = lambda: MagicMock()
    return TestClient(app)


def test_the_schema_carries_registry_ids_and_the_current_server_keys(client):
    from maljan.providers.registry import sandbox_provider_ids, static_provider_ids

    with patch("app.api.v1.settings.SettingsService.load_overrides", AsyncMock(return_value={})):
        response = client.get("/api/v1/settings/schema")
    entries = {e["key"]: e for g in response.json()["groups"] for e in g["entries"]}
    # Both provider selectors are registry-backed (spec 6): the settings
    # ``Literal`` is what pydantic validates against, but the choice *list* an
    # operator picks from is resolved here, against the same registry a job
    # actually dispatches through, so a provider module registered after the
    # ``Literal`` was last edited still shows up.
    assert entries["core.static.provider"]["choices_from"] == "static_providers"
    assert entries["core.static.provider"]["choices"] == static_provider_ids()
    assert entries["core.sandbox.provider"]["choices_from"] == "sandbox_providers"
    assert entries["core.sandbox.provider"]["choices"] == sandbox_provider_ids()
    assert "rest" in entries["core.sandbox.provider"]["choices"]
    generic = entries["core.static.generic.server"]
    assert generic["choices_from"] == "mcp_servers"
    assert generic["choices"] == ["", "network", "threatintel"]
    assert entries["core.mcp.servers"]["editor"] == "server_map"


def test_a_patch_to_the_server_map_is_validated_and_reported_per_key(client):
    with patch("app.api.v1.settings.SettingsService.load_overrides", AsyncMock(return_value={})):
        response = client.patch(
            "/api/v1/settings",
            json={"changes": {"core.mcp.servers": {"Bad Key": {"command": "x"}}}},
        )
    assert response.status_code == 422
    assert "core.mcp.servers.Bad Key" in response.json()["errors"]


def test_the_mcp_probe_route_addresses_one_server(client, monkeypatch):
    from app.services.settings_probes import ProbeResult

    async def fake(server, values, stored):
        assert server == "network"
        assert values == {"core.mcp.servers": {"network": {"command": "python"}}}
        return ProbeResult(True, 12, "3 tools: a, b, c", None, ["a", "b", "c"])

    monkeypatch.setattr("app.api.v1.settings.run_mcp_probe", fake)
    with patch("app.api.v1.settings.SettingsService.load_overrides", AsyncMock(return_value={})):
        response = client.post(
            "/api/v1/settings/test/mcp?server=network",
            json={"values": {"core.mcp.servers": {"network": {"command": "python"}}}},
        )
    assert response.status_code == 200
    assert response.json()["tools"] == ["a", "b", "c"]


def test_the_mcp_probe_route_needs_a_server(client):
    response = client.post("/api/v1/settings/test/mcp", json={"values": {}})
    assert response.status_code == 422


def test_the_mcp_probe_route_refuses_a_non_admin():
    """Same guard as every other admin route -- built with no ``require_admin``
    override at all, the way ``test_non_admin_is_rejected`` checks ``/schema``."""
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[get_db] = lambda: MagicMock()
    response = TestClient(app).post("/api/v1/settings/test/mcp?server=network", json={"values": {}})
    assert response.status_code in (401, 403)


def test_the_mcp_probe_route_never_echoes_a_staged_token(client, monkeypatch):
    """A staged ``auth_token`` reaches the probe, and nothing else reaches back."""
    from app.services.settings_probes import ProbeResult

    token = "-".join(["s3cr3t", "runtime", "built", "token"])

    async def fake(server, values, stored):
        assert values["core.mcp.servers"]["network"]["auth_token"] == token
        return ProbeResult(False, 5, "no MCP handshake within 5 s", None, None)

    monkeypatch.setattr("app.api.v1.settings.run_mcp_probe", fake)
    with patch("app.api.v1.settings.SettingsService.load_overrides", AsyncMock(return_value={})):
        response = client.post(
            "/api/v1/settings/test/mcp?server=network",
            json={
                "values": {
                    "core.mcp.servers": {
                        "network": {"transport": "http", "url": "https://h", "auth_token": token}
                    }
                }
            },
        )
    assert response.status_code == 200
    assert token not in response.text

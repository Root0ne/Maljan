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
    with patch("app.api.v1.settings.SettingsService.load_overrides", AsyncMock(return_value={})):
        response = client.get("/api/v1/settings/schema")
    entries = {e["key"]: e for g in response.json()["groups"] for e in g["entries"]}
    # No ``choices_from`` on the two provider selectors: their choices come
    # from the settings ``Literal`` and keep its declaration order, which is
    # what the submit dialog renders. The registry sources exist for a leaf
    # that needs them; the parity test is what keeps the two lists equal.
    assert entries["core.static.provider"]["choices"] == [
        "ghidra",
        "r2",
        "capa_yara",
        "generic_mcp",
        "none",
    ]
    assert entries["core.static.provider"]["choices_from"] is None
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

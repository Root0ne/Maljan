"""The console's per-agent effort field reads its levels from the API.

Free and read-only: the levels are the settings' own list and, for an
Anthropic model the window probe described, what the Models API said it takes.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1.settings import router
from app.database import get_db
from app.deps import require_admin
from maljan.core.config import ANTHROPIC_EFFORT_LEVELS
from maljan.llm import model_capabilities


@pytest.fixture
def client() -> TestClient:
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[require_admin] = lambda: MagicMock(
        id="00000000-0000-0000-0000-000000000001"
    )
    app.dependency_overrides[get_db] = lambda: AsyncMock()
    return TestClient(app)


@pytest.fixture(autouse=True)
def _nothing_described() -> Any:
    model_capabilities.forget_capabilities()
    yield
    model_capabilities.forget_capabilities()


def _with_overrides(overrides: dict[str, Any]) -> Any:
    return patch(
        "app.api.v1.settings.SettingsService.load_overrides",
        AsyncMock(return_value=overrides),
    )


def test_anthropic_offers_its_levels_and_the_global_value(client: TestClient) -> None:
    with _with_overrides({"core.llm.anthropic.effort": "max"}):
        r = client.get(
            "/api/v1/settings/effort-options",
            params={"provider": "anthropic", "model": "claude-haiku-5-5"},
        )
    assert r.status_code == 200
    body = r.json()
    assert body["takes_effort"] is True
    assert body["levels"] == list(ANTHROPIC_EFFORT_LEVELS)
    assert body["levels_source"] == "settings"
    assert body["global_key"] == "core.llm.anthropic.effort"
    assert body["global_value"] == "max"


def test_an_openai_compatible_value_is_typed(client: TestClient) -> None:
    with _with_overrides({}):
        body = client.get(
            "/api/v1/settings/effort-options", params={"provider": "openai", "model": "m"}
        ).json()
    assert body["takes_effort"] is True
    assert body["levels"] is None
    assert body["global_value"] is None


def test_ollama_takes_none(client: TestClient) -> None:
    with _with_overrides({}):
        body = client.get(
            "/api/v1/settings/effort-options", params={"provider": "ollama", "model": "m"}
        ).json()
    assert body["takes_effort"] is False
    assert body["levels"] == []


def test_a_provider_must_be_named(client: TestClient) -> None:
    with _with_overrides({}):
        r = client.get("/api/v1/settings/effort-options")
    assert r.status_code == 422

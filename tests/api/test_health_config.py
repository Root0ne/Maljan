"""``/health`` reports configuration readiness: bootstrap, encryption, legacy import.

The full app is built with ``create_app()`` and hit with a plain (non
context-managed) ``TestClient`` -- lifespan startup never runs that way (no
real DB/Redis needed), which is exactly what is wanted here: bootstrap and
encryption are reported as static facts, only the legacy-import marker read
touches the database, and that one call is mocked.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.main import create_app


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app())


class _FakeSession:
    def __init__(self, marker):
        self._marker = marker

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def execute(self, *a, **k):
        result = MagicMock()
        result.scalar_one_or_none = MagicMock(return_value=self._marker)
        return result


def _factory(marker):
    return lambda: _FakeSession(marker)


def test_config_block_reports_done_when_the_marker_shows_imports(client):
    marker = SimpleNamespace(value={"imported": 2, "at": "2026-09-11T00:00:00+00:00"})
    with patch("app.database.async_session_factory", _factory(marker)):
        r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["config"] == {"bootstrap": "ok", "encryption": "ok", "legacy_import": "done"}


def test_config_block_reports_not_needed_when_the_marker_shows_zero(client):
    marker = SimpleNamespace(value={"imported": 0, "at": "2026-09-11T00:00:00+00:00"})
    with patch("app.database.async_session_factory", _factory(marker)):
        r = client.get("/health")
    assert r.json()["config"]["legacy_import"] == "not-needed"


def test_config_block_reports_not_needed_when_there_is_no_marker_yet(client):
    with patch("app.database.async_session_factory", _factory(None)):
        r = client.get("/health")
    assert r.json()["config"]["legacy_import"] == "not-needed"


def test_config_block_reports_unknown_on_a_db_failure_and_status_is_unaffected(client):
    def _factory_raises():
        raise RuntimeError("db is down")

    with patch("app.database.async_session_factory", _factory_raises):
        r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["config"]["legacy_import"] == "unknown"
    assert r.json()["status"] == "healthy"


def test_deep_health_also_carries_the_config_block(client):
    with (
        patch("app.database.async_session_factory", _factory(None)),
        patch("app.main._probe_components", AsyncMock(return_value={})),
    ):
        r = client.get("/health", params={"deep": "true"})
    assert r.json()["config"] == {
        "bootstrap": "ok",
        "encryption": "ok",
        "legacy_import": "not-needed",
    }

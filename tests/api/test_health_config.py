"""``/health`` reports configuration readiness: bootstrap and encryption.

The full app is built with ``create_app()`` and hit with a plain (non
context-managed) ``TestClient`` -- lifespan startup never runs that way (no
real DB/Redis needed), which is exactly what is wanted here: the endpoint
does no I/O of its own and both facts it reports are constants the process
already satisfied before it could serve a request at all.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from app.main import create_app


@pytest.fixture
def app():
    return create_app()


@pytest.fixture
def client(app) -> TestClient:
    return TestClient(app)


def test_config_block_reports_bootstrap_and_encryption(app, client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["config"] == {"bootstrap": "ok", "encryption": "ok"}
    assert r.json()["status"] == "healthy"


def test_deep_health_also_carries_the_config_block(app, client):
    with patch("app.main._probe_components", AsyncMock(return_value={})):
        r = client.get("/health", params={"deep": "true"})
    assert r.json()["config"] == {"bootstrap": "ok", "encryption": "ok"}

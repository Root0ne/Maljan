"""``/health`` reports configuration readiness: bootstrap, encryption, legacy import.

The full app is built with ``create_app()`` and hit with a plain (non
context-managed) ``TestClient`` -- lifespan startup never runs that way (no
real DB/Redis needed), which is exactly what is wanted here: the endpoint
does no I/O of its own. ``legacy_import`` is read straight from
``app.state.legacy_import_status`` -- the value the lifespan's import step
caches once at startup -- so each test sets that attribute directly instead
of standing in for a database read the handler no longer performs.
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


def test_config_block_reports_done_when_the_cached_status_says_so(app, client):
    app.state.legacy_import_status = "done"
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["config"] == {"bootstrap": "ok", "encryption": "ok", "legacy_import": "done"}


def test_config_block_reports_not_needed_when_the_cached_status_says_so(app, client):
    app.state.legacy_import_status = "not-needed"
    r = client.get("/health")
    assert r.json()["config"]["legacy_import"] == "not-needed"


def test_config_block_reports_unknown_when_lifespan_never_ran(app, client):
    """No ``TestClient`` context manager means no lifespan, so ``app.state``
    never got the attribute -- exactly the state a fresh process would be in
    before its first startup step finished, and the same state a startup
    that raised would leave it in.
    """
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["config"]["legacy_import"] == "unknown"
    assert r.json()["status"] == "healthy"


def test_deep_health_also_carries_the_cached_config_block(app, client):
    app.state.legacy_import_status = "not-needed"
    with patch("app.main._probe_components", AsyncMock(return_value={})):
        r = client.get("/health", params={"deep": "true"})
    assert r.json()["config"] == {
        "bootstrap": "ok",
        "encryption": "ok",
        "legacy_import": "not-needed",
    }

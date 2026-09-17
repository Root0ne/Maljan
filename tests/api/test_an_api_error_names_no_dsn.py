"""An exception's text reaches an HTTP response only with its credentials gone.

Three outer fences answered with ``f"{type(exc).__name__}: {exc}"``. The
exceptions that reach them come from arq, Redis and Qdrant, whose messages
carry the connection string they were configured with — and a DSN carries its
password. The probe's own transport paths have used ``redact_url`` from the
beginning; these three had never been given it.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.database import get_db
from app.deps import get_current_user, require_admin

# A DSN of the shape every one of these drivers prints in its own errors.
PASSWORD = "sup3rs3cret"
DSN = f"redis://default:{PASSWORD}@redis.internal:6379/0"


def test_a_probe_that_fails_before_it_runs_names_no_password() -> None:
    from app.api.v1 import settings as settings_module

    app = FastAPI()
    app.include_router(settings_module.router, prefix="/api/v1")
    app.dependency_overrides[get_db] = lambda: MagicMock()
    app.dependency_overrides[require_admin] = lambda: MagicMock(id="u")
    client = TestClient(app)

    with (
        patch.object(settings_module.SettingsService, "load_overrides", AsyncMock(return_value={})),
        patch.object(
            settings_module,
            "run_probe",
            AsyncMock(side_effect=RuntimeError(f"cannot reach {DSN}")),
        ),
    ):
        response = client.post("/api/v1/settings/test/qdrant", json={"values": {}})

    assert response.status_code == 200, response.text
    detail = response.json()["detail"]
    assert PASSWORD not in detail
    assert "RuntimeError" in detail


def test_a_memory_store_that_will_not_build_names_no_password() -> None:
    from app.api.v1 import system as system_module

    app = FastAPI()
    app.include_router(system_module.router, prefix="/api/v1")
    app.dependency_overrides[get_db] = lambda: MagicMock()
    app.dependency_overrides[require_admin] = lambda: MagicMock(id="u")
    client = TestClient(app)

    with patch.object(
        system_module,
        "_build_memory_store",
        AsyncMock(side_effect=RuntimeError(f"no route to {DSN}")),
    ):
        response = client.post("/api/v1/system/ltm/purge", json={"dry_run": True})

    assert response.status_code == 503, response.text
    assert PASSWORD not in response.json()["detail"]


def test_an_enrichment_queue_that_is_down_names_no_password() -> None:
    from app.api.v1 import reports as reports_module
    from app.services.report_service import EnrichmentEnqueueError

    app = FastAPI()
    app.include_router(reports_module.router, prefix="/api/v1")
    app.dependency_overrides[get_db] = lambda: MagicMock()
    app.dependency_overrides[get_current_user] = lambda: MagicMock(id="u")
    service = MagicMock()
    service.get_report = AsyncMock(
        return_value=MagicMock(malware_report={"network": {"domains": ["evil.example"], "ips": []}})
    )
    service.enqueue_enrichment = AsyncMock(
        side_effect=EnrichmentEnqueueError(f"arq could not connect to {DSN}")
    )
    app.dependency_overrides[reports_module._get_service] = lambda: service
    client = TestClient(app)

    import uuid

    response = client.post(f"/api/v1/reports/{uuid.uuid4()}/enrich")

    assert response.status_code == 503, response.text
    assert PASSWORD not in response.json()["detail"]


@pytest.mark.parametrize(
    "text",
    [
        f"redis://default:{PASSWORD}@redis.internal:6379/0",
        f"postgresql://maljan:{PASSWORD}@db.internal:5432/maljan",
        f"ConnectionError: http://user:{PASSWORD}@qdrant.internal:6333 refused",
    ],
)
def test_the_masking_itself_covers_every_dsn_shape(text: str) -> None:
    from maljan.core.settings_overrides import redact_url

    assert PASSWORD not in redact_url(text)

from __future__ import annotations

import json
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
from app.services.settings_service import (  # noqa: E402
    SaveResult,
    SettingsValidationError,
    ValueInfo,
)


@pytest.fixture
def client() -> TestClient:
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[require_admin] = lambda: MagicMock(
        id="00000000-0000-0000-0000-000000000001"
    )
    app.dependency_overrides[get_db] = lambda: MagicMock()
    return TestClient(app)


def test_schema_lists_groups_in_order_and_entries(client):
    r = client.get("/api/v1/settings/schema")
    assert r.status_code == 200
    groups = r.json()["groups"]
    assert groups[0]["key"] == "llm"
    keys = {e["key"] for g in groups for e in g["entries"]}
    assert {"core.llm.provider", "api.enrichment_enabled", "api.debug"} <= keys
    ro = next(e for g in groups for e in g["entries"] if e["key"] == "api.debug")
    assert ro["editable"] is False


def test_values_never_contain_secret_values(client):
    fake = {
        "core.llm.openai.api_key": ValueInfo(None, True, "1234", "ui"),
        "core.llm.provider": ValueInfo("openai", None, None, "env"),
    }
    with patch("app.api.v1.settings.SettingsService.values", AsyncMock(return_value=fake)):
        r = client.get("/api/v1/settings")
    assert r.status_code == 200
    body = r.json()["values"]
    assert body["core.llm.openai.api_key"] == {
        "value": None,
        "is_set": True,
        "hint": "1234",
        "source": "ui",
        "updated_at": None,
        "updated_by": None,
    }
    assert body["core.llm.provider"]["value"] == "openai"


def test_patch_returns_applies_summary(client):
    with patch(
        "app.api.v1.settings.SettingsService.save",
        AsyncMock(return_value=SaveResult(["core.llm.provider"], {"next_job": 1})),
    ):
        r = client.patch("/api/v1/settings", json={"changes": {"core.llm.provider": "openai"}})
    assert r.status_code == 200
    assert r.json() == {"applied": ["core.llm.provider"], "applies": {"next_job": 1}}


def test_patch_validation_error_is_422_with_field_map(client):
    with patch(
        "app.api.v1.settings.SettingsService.save",
        AsyncMock(
            side_effect=SettingsValidationError(
                {"core.negotiation.max_iterations": "Input should be a valid integer"}
            )
        ),
    ):
        r = client.patch(
            "/api/v1/settings", json={"changes": {"core.negotiation.max_iterations": "x"}}
        )
    assert r.status_code == 422
    assert r.json()["errors"] == {
        "core.negotiation.max_iterations": "Input should be a valid integer"
    }


def test_reset_one_and_group(client):
    with patch(
        "app.api.v1.settings.SettingsService.reset", AsyncMock(return_value=["core.llm.provider"])
    ) as reset:
        r = client.delete("/api/v1/settings/core.llm.provider")
        assert r.status_code == 200 and r.json() == {"reset": ["core.llm.provider"]}
        r = client.delete("/api/v1/settings?group=llm")
        assert r.status_code == 200
        keys_passed = reset.call_args_list[1].args[0]
        assert (
            all(k.startswith("core.llm.") for k in keys_passed)
            and "core.llm.provider" in keys_passed
        )


def test_export_is_env_syntax_with_secrets_masked(client):
    fake = {
        "core.llm.openai.api_key": ValueInfo(None, True, "1234", "ui"),
        "core.llm.provider": ValueInfo("openai", None, None, "ui"),
        "core.chunking.overlap_tokens": ValueInfo(200, None, None, "default"),
    }
    with patch("app.api.v1.settings.SettingsService.values", AsyncMock(return_value=fake)):
        r = client.get("/api/v1/settings/export")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain")
    assert "LLM__OPENAI__API_KEY=***" in r.text
    assert "LLM__PROVIDER=openai" in r.text
    assert "CHUNKING__OVERLAP_TOKENS" not in r.text  # only overrides are exported


def test_reset_group_unknown_is_404(client):
    r = client.delete("/api/v1/settings?group=does-not-exist")
    assert r.status_code == 404


def test_probe_unknown_is_404(client):
    r = client.post("/api/v1/settings/test/bogus", json={"values": {}})
    assert r.status_code == 404


def test_non_admin_is_rejected():
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[get_db] = lambda: MagicMock()
    r = TestClient(app).get("/api/v1/settings/schema")
    assert r.status_code in (401, 403)


def test_the_preview_route_caps_the_pasted_sample(client):
    from app.services.mapping_preview import PREVIEW_MAX_BYTES

    r = client.post(
        "/api/v1/settings/sandbox-rest/preview",
        json={"sample": {"pad": "x" * (PREVIEW_MAX_BYTES + 1)}, "mapping": {}},
    )
    assert r.status_code == 413


def test_the_preview_route_caps_a_streamed_body_with_no_content_length(client):
    """A body sent without a declared length (chunked transfer, or a lying
    header) must still be capped — the streamed guard, not ``Content-Length``,
    is what catches it."""
    from app.services.mapping_preview import PREVIEW_MAX_BYTES

    body = json.dumps({"sample": {"pad": "x" * (PREVIEW_MAX_BYTES + 1)}, "mapping": {}}).encode()

    def chunks():
        for i in range(0, len(body), 65536):
            yield body[i : i + 65536]

    r = client.post(
        "/api/v1/settings/sandbox-rest/preview",
        content=chunks(),
        headers={"content-type": "application/json"},
    )
    assert r.status_code == 413


def test_the_preview_route_counts_rows_per_channel(client):
    r = client.post(
        "/api/v1/settings/sandbox-rest/preview",
        json={"sample": {"p": [{"pid": 1}, {"nope": 2}]}, "mapping": {"processes": "$.p[*]"}},
    )
    assert r.status_code == 200
    assert r.json()["channels"]["processes"] == {
        "matched": 2,
        "kept": 1,
        "dropped": 1,
        "truncated": False,
        "sample_rows": [{"pid": 1}],
        "error": None,
    }


def test_the_preview_route_is_admin_only():
    """Without the ``require_admin`` override the real dependency runs and refuses."""
    from app.api.v1.settings import router
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    r = TestClient(app).post(
        "/api/v1/settings/sandbox-rest/preview", json={"sample": {}, "mapping": {}}
    )
    assert r.status_code in (401, 403)

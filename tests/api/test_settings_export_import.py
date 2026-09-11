"""JSON export and import: the .env export is gone, replaced by a document
that round-trips through the same ``SettingsService`` path a UI edit uses."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1.settings import router
from app.database import get_db
from app.deps import require_active_user, require_admin
from app.models.user import UserRole
from app.services.settings_service import SaveResult, SettingsValidationError, ValueInfo

ADMIN_ID = "00000000-0000-0000-0000-000000000001"


def _app(role: UserRole | None = UserRole.ADMIN) -> FastAPI:
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    if role is UserRole.ADMIN:
        app.dependency_overrides[require_admin] = lambda: MagicMock(id=ADMIN_ID, role=role)
    else:
        app.dependency_overrides[require_active_user] = lambda: MagicMock(role=role)
    app.dependency_overrides[get_db] = lambda: MagicMock()
    return app


@pytest.fixture
def client() -> TestClient:
    return TestClient(_app())


# ---- export -----------------------------------------------------------


def test_export_omits_secrets_and_lists_their_names(client):
    fake = {
        "core.llm.openai.api_key": ValueInfo(None, True, "1234", "ui"),
        "core.llm.provider": ValueInfo("openai", None, None, "ui"),
        "core.chunking.overlap_tokens": ValueInfo(200, None, None, "default"),
    }
    with patch("app.api.v1.settings.SettingsService.values", AsyncMock(return_value=fake)):
        r = client.get("/api/v1/settings/export")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")
    assert r.headers["content-disposition"] == "attachment; filename=maljan-settings.json"
    body = r.json()
    assert body["format"] == "maljan-settings/1"
    assert body["values"] == {"core.llm.provider": "openai"}
    assert body["secrets_omitted"] == ["core.llm.openai.api_key"]
    assert "exported_at" in body
    assert "1234" not in r.text


def test_export_values_are_native_json_not_strings(client):
    fake = {
        "core.negotiation.max_iterations": ValueInfo(7, None, None, "ui"),
        "api.trusted_proxy_ips": ValueInfo(["10.0.0.0/8", "192.168.1.1"], None, None, "ui"),
    }
    with patch("app.api.v1.settings.SettingsService.values", AsyncMock(return_value=fake)):
        r = client.get("/api/v1/settings/export")
    body = r.json()
    assert body["values"]["core.negotiation.max_iterations"] == 7
    assert body["values"]["api.trusted_proxy_ips"] == ["10.0.0.0/8", "192.168.1.1"]


def test_export_of_the_server_map_strips_the_token_mask(client):
    """Regression (F8, carried over from the .env export): the ten-asterisk
    token mask ``values()`` shows the UI must never be re-exported as though
    it were a real credential -- re-importing it would store the mask as the
    server's actual token."""
    fake = {
        "core.mcp.servers": ValueInfo(
            {
                "custom": {
                    "enabled": True,
                    "command": "my-mcp",
                    "auth_token": "**********",
                    "auth_token_source": "ui",
                }
            },
            None,
            None,
            "ui",
        ),
    }
    with patch("app.api.v1.settings.SettingsService.values", AsyncMock(return_value=fake)):
        r = client.get("/api/v1/settings/export")
    body = r.json()
    server = body["values"]["core.mcp.servers"]["custom"]
    assert "auth_token" not in server
    assert "auth_token_source" not in server
    assert server["command"] == "my-mcp"


def test_export_is_admin_only():
    r = TestClient(_app(UserRole.ANALYST)).get("/api/v1/settings/export")
    assert r.status_code == 403


# ---- import -------------------------------------------------------------


def test_import_unsupported_format_is_422():
    r = TestClient(_app()).post("/api/v1/settings/import", json={"format": "not-it", "values": {}})
    assert r.status_code == 422
    assert r.json()["errors"] == {"format": "unsupported format"}


def test_import_rejects_unknown_and_read_only_keys_before_applying(client):
    with patch("app.api.v1.settings.SettingsService.save", AsyncMock()) as save:
        r = client.post(
            "/api/v1/settings/import",
            json={
                "format": "maljan-settings/1",
                "values": {
                    "core.no.such.key": "x",
                    "api.debug": True,
                    "core.llm.provider": "openai",
                },
            },
        )
    assert r.status_code == 422
    assert r.json()["errors"] == {
        "core.no.such.key": "unknown key",
        "api.debug": "read-only",
    }
    save.assert_not_called()


def test_import_round_trip_saves_through_settings_service_and_audits(client):
    with (
        patch(
            "app.api.v1.settings.SettingsService.save",
            AsyncMock(return_value=SaveResult(["core.llm.provider"], {"next_job": 1})),
        ) as save,
        patch("app.api.v1.settings.audit_record", AsyncMock()) as audit_record,
    ):
        r = client.post(
            "/api/v1/settings/import",
            json={"format": "maljan-settings/1", "values": {"core.llm.provider": "openai"}},
        )
    assert r.status_code == 200
    assert r.json() == {"applied": ["core.llm.provider"], "applies": {"next_job": 1}}
    save.assert_awaited_once()
    assert save.call_args.args[0] == {"core.llm.provider": "openai"}
    audit_record.assert_awaited_once()
    _, kwargs = audit_record.call_args
    assert audit_record.call_args.args[0] == "settings.import"
    assert kwargs["details"] == {"keys": ["core.llm.provider"], "count": 1}


def test_import_validation_error_from_save_is_422_field_map(client):
    with patch(
        "app.api.v1.settings.SettingsService.save",
        AsyncMock(side_effect=SettingsValidationError({"core.llm.provider": "bad value"})),
    ):
        r = client.post(
            "/api/v1/settings/import",
            json={"format": "maljan-settings/1", "values": {"core.llm.provider": "nope"}},
        )
    assert r.status_code == 422
    assert r.json()["errors"] == {"core.llm.provider": "bad value"}


def test_import_never_echoes_a_secret_value(client):
    with (
        patch(
            "app.api.v1.settings.SettingsService.save",
            AsyncMock(return_value=SaveResult(["core.llm.openai.api_key"], {})),
        ),
        patch("app.api.v1.settings.audit_record", AsyncMock()),
    ):
        r = client.post(
            "/api/v1/settings/import",
            json={
                "format": "maljan-settings/1",
                "values": {"core.llm.openai.api_key": "sk-super-secret"},
            },
        )
    assert r.status_code == 200
    assert "sk-super-secret" not in r.text


def test_import_is_admin_only():
    r = TestClient(_app(UserRole.ANALYST)).post(
        "/api/v1/settings/import", json={"format": "maljan-settings/1", "values": {}}
    )
    assert r.status_code == 403


def test_schema_response_no_longer_carries_secrets_available(client):
    with patch("app.api.v1.settings.SettingsService.load_overrides", AsyncMock(return_value={})):
        r = client.get("/api/v1/settings/schema")
    assert r.status_code == 200
    assert "secrets_available" not in r.json()

"""JSON export and import: the .env export is gone, replaced by a document
that round-trips through the same ``SettingsService`` path a UI edit uses."""

from __future__ import annotations

from datetime import UTC, datetime
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
    assert r.headers["content-disposition"] == "attachment; filename=malspark-settings.json"
    body = r.json()
    assert body["format"] == "malspark-settings/3"
    assert body["values"] == {"core.llm.provider": "openai"}
    assert body["secrets_omitted"] == ["core.llm.openai.api_key"]
    exported_at = datetime.fromisoformat(body["exported_at"])
    assert exported_at.tzinfo is not None
    assert exported_at.utcoffset() == UTC.utcoffset(None)
    assert "1234" not in r.text


def test_export_skips_a_stored_but_read_only_key(client):
    """A row for a key the catalog no longer lets an admin edit (``api.debug``
    is ``editable=False``) still reports ``source == "ui"`` -- exporting it
    anyway would hand back a document its own import rejects as read-only."""
    fake = {
        "api.debug": ValueInfo(True, None, None, "ui"),
        "core.llm.provider": ValueInfo("openai", None, None, "ui"),
    }
    with patch("app.api.v1.settings.SettingsService.values", AsyncMock(return_value=fake)):
        r = client.get("/api/v1/settings/export")
    body = r.json()
    assert body["values"] == {"core.llm.provider": "openai"}
    assert "api.debug" not in body["secrets_omitted"]


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
    assert "core.mcp.servers.custom.auth_token" in body["secrets_omitted"]


def test_export_of_the_frontier_arms_strips_every_arm_key(client):
    """W2/W3: each arm's ``api_key`` reaches ``values()`` as the mask, and the
    export must carry neither it nor the mask -- a re-import would otherwise
    configure ten asterisks as the arm's credential."""
    fake = {
        "core.llm.frontier.arms": ValueInfo(
            {
                "glm": {"base_url": "https://f", "model": "m", "api_key": "**********"},
                "free": {"base_url": "https://g", "model": "n", "api_key": None},
            },
            None,
            None,
            "ui",
        ),
    }
    with patch("app.api.v1.settings.SettingsService.values", AsyncMock(return_value=fake)):
        r = client.get("/api/v1/settings/export")
    body = r.json()
    arms = body["values"]["core.llm.frontier.arms"]
    assert "api_key" not in arms["glm"]
    assert arms["glm"]["model"] == "m"
    assert arms["free"]["api_key"] is None
    assert body["secrets_omitted"] == ["core.llm.frontier.arms.glm.api_key"]
    assert "**********" not in r.text


def test_export_strips_a_mask_nested_at_any_depth(client):
    """Defence in depth: the sanitiser is not a list of known secret leaves.

    A composite that grows a new credential field is covered the day it is
    added rather than the day someone remembers to extend the export.
    """
    fake = {
        "core.mcp.servers": ValueInfo(
            {"custom": {"nested": {"deeper": [{"secret": "**********"}]}}},
            None,
            None,
            "ui",
        ),
    }
    with patch("app.api.v1.settings.SettingsService.values", AsyncMock(return_value=fake)):
        r = client.get("/api/v1/settings/export")
    body = r.json()
    assert body["values"]["core.mcp.servers"]["custom"]["nested"]["deeper"][0] == {}
    assert body["secrets_omitted"] == ["core.mcp.servers.custom.nested.deeper.0.secret"]


def test_export_lists_one_path_per_arm_whose_key_is_stored(client):
    """Once the repair has written the leaves, ``values()`` masks all four arms
    and the export names each one it did not carry -- exactly once."""
    arms = {
        name: {"base_url": "https://f", "model": name, "api_key": "**********"}
        for name in ("dsk", "glm", "nim", "or")
    }
    fake = {"core.llm.frontier.arms": ValueInfo(arms, None, None, "ui")}
    with patch("app.api.v1.settings.SettingsService.values", AsyncMock(return_value=fake)):
        r = client.get("/api/v1/settings/export")
    body = r.json()
    assert body["secrets_omitted"] == [
        f"core.llm.frontier.arms.{name}.api_key" for name in ("dsk", "glm", "nim", "or")
    ]
    assert all("api_key" not in arm for arm in body["values"]["core.llm.frontier.arms"].values())


def test_export_masks_every_server_env_value(client):
    """A server's ``env`` map is where its own credential lives, so the
    export carries the variable names and the mask, never the values; each one
    is named under ``secrets_omitted`` so an operator can see what is missing."""
    fake = {
        "core.mcp.servers": ValueInfo(
            {
                "custom": {
                    "command": "my-mcp",
                    "env": {"API_TOKEN": "s3cr3t", "MODE": "fast"},
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
    env = body["values"]["core.mcp.servers"]["custom"]["env"]
    assert env == {"API_TOKEN": "**********", "MODE": "**********"}
    assert body["secrets_omitted"] == [
        "core.mcp.servers.custom.env.API_TOKEN",
        "core.mcp.servers.custom.env.MODE",
    ]
    assert "s3cr3t" not in r.text


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
                "format": "malspark-settings/1",
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


def test_import_names_a_retired_key_as_the_one_to_delete(client):
    """An export written before a setting was retired is refused, saying which key to delete."""
    with patch("app.api.v1.settings.SettingsService.save", AsyncMock()) as save:
        r = client.post(
            "/api/v1/settings/import",
            json={
                "format": "malspark-settings/1",
                "values": {
                    "core.preprocessing.summarizer_provider": "openai",
                    "core.preprocessing.summarizer_model": "gpt-x",
                    "core.reporting.narrative_max_tokens": 1500,
                    "core.llm.provider": "openai",
                },
            },
        )
    assert r.status_code == 422
    errors = r.json()["errors"]
    assert set(errors) == {
        "core.preprocessing.summarizer_provider",
        "core.preprocessing.summarizer_model",
        "core.reporting.narrative_max_tokens",
    }
    for key, message in errors.items():
        assert message.startswith("retired setting"), key
        assert "delete" in message, key
    assert "llm.agents.summarizer" in errors["core.preprocessing.summarizer_model"]
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
            json={"format": "malspark-settings/1", "values": {"core.llm.provider": "openai"}},
        )
    assert r.status_code == 200
    assert r.json() == {
        "applied": ["core.llm.provider"],
        "applies": {"next_job": 1},
        "warnings": {},
    }
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
            json={"format": "malspark-settings/1", "values": {"core.llm.provider": "nope"}},
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
                "format": "malspark-settings/1",
                "values": {"core.llm.openai.api_key": "sk-super-secret"},
            },
        )
    assert r.status_code == 200
    assert "sk-super-secret" not in r.text


def test_import_audits_nothing_when_no_key_was_applied(client):
    """A no-op import (an empty document, or one whose changes all resolve to
    nothing) must not add a settings.import row -- same reasoning as the
    legacy import only auditing real work (84c609e)."""
    with (
        patch(
            "app.api.v1.settings.SettingsService.save",
            AsyncMock(return_value=SaveResult([], {})),
        ) as save,
        patch("app.api.v1.settings.audit_record", AsyncMock()) as audit_record,
    ):
        r = client.post(
            "/api/v1/settings/import",
            json={"format": "malspark-settings/1", "values": {}},
        )
    assert r.status_code == 200
    assert r.json() == {"applied": [], "applies": {}, "warnings": {}}
    save.assert_awaited_once()
    audit_record.assert_not_called()


def test_export_then_import_round_trips_unchanged(client):
    """The document a real export produces posts straight back to import:
    the extra ``exported_at``/``secrets_omitted`` fields are ignored, and the
    values that made it through export are exactly what gets saved."""
    fake = {
        "core.llm.openai.api_key": ValueInfo(None, True, "1234", "ui"),
        "core.llm.provider": ValueInfo("openai", None, None, "ui"),
        "core.negotiation.max_iterations": ValueInfo(7, None, None, "ui"),
    }
    with patch("app.api.v1.settings.SettingsService.values", AsyncMock(return_value=fake)):
        exported = client.get("/api/v1/settings/export").json()
    assert "secrets_omitted" in exported
    assert exported["values"] == {
        "core.llm.provider": "openai",
        "core.negotiation.max_iterations": 7,
    }
    with (
        patch(
            "app.api.v1.settings.SettingsService.save",
            AsyncMock(
                return_value=SaveResult(
                    list(exported["values"]), {"next_job": len(exported["values"])}
                )
            ),
        ) as save,
        patch("app.api.v1.settings.audit_record", AsyncMock()),
    ):
        r = client.post("/api/v1/settings/import", json=exported)
    assert r.status_code == 200
    assert save.call_args.args[0] == exported["values"]


def test_import_is_admin_only():
    r = TestClient(_app(UserRole.ANALYST)).post(
        "/api/v1/settings/import", json={"format": "malspark-settings/1", "values": {}}
    )
    assert r.status_code == 403


def test_schema_response_no_longer_carries_secrets_available(client):
    with patch("app.api.v1.settings.SettingsService.load_overrides", AsyncMock(return_value={})):
        r = client.get("/api/v1/settings/schema")
    assert r.status_code == 200
    assert "secrets_available" not in r.json()


# ---- an export written before definitions carried a category -----------

_LEGACY_DEFINITIONS = {
    "my_sandbox": {"role": "generic", "prompt": "read the run", "tools": [{"kind": "sandbox"}]},
    "my_checker": {"role": "generic", "prompt": "check", "tools": []},
    "kept": {"role": "generic", "prompt": "mine", "tools": []},
    "chosen": {"role": "generic", "prompt": "c", "category": "intel"},
}


def _import_legacy(client, stored: dict) -> tuple:
    with (
        patch(
            "app.api.v1.settings.SettingsService.load_overrides",
            AsyncMock(return_value=stored),
        ),
        patch(
            "app.api.v1.settings.SettingsService.save",
            AsyncMock(return_value=SaveResult(["core.agents.definitions"], {"next_job": 1})),
        ) as save,
        patch("app.api.v1.settings.audit_record", AsyncMock()),
        patch("app.api.v1.settings._agent_warnings", AsyncMock(return_value={})),
    ):
        r = client.post(
            "/api/v1/settings/import",
            json={
                "format": "malspark-settings/1",
                "values": {"core.agents.definitions": _LEGACY_DEFINITIONS},
            },
        )
    return r, save


def test_an_export_without_categories_imports_with_the_fitted_ones_and_says_so(client):
    from app.services.agent_map import validate_agent_map

    stored = {"core.agents.definitions": {"kept": {"role": "generic", "prompt": "mine"}}}
    r, save = _import_legacy(client, stored)

    assert r.status_code == 200
    sent = save.call_args.args[0]["core.agents.definitions"]
    assert sent["my_sandbox"]["category"] == "dynamic"
    assert sent["my_checker"]["category"] == "other"
    # A stored definition reads the one it fits as before; a named one is kept.
    assert "category" not in sent["kept"]
    assert sent["chosen"]["category"] == "intel"
    warnings = r.json()["warnings"]
    assert warnings["core.agents.definitions.my_sandbox.category"] == (
        "set to dynamic from its role and tools; pick the one that fits in Settings"
    )
    assert "tell no category" in warnings["core.agents.definitions.my_checker.category"]
    assert "core.agents.definitions.kept.category" not in warnings
    assert "core.agents.definitions.chosen.category" not in warnings
    # What the import saves passes the edit's own strict check.
    validate_agent_map({"core.agents.definitions": sent}, stored)


def test_an_edit_without_a_category_is_still_refused():
    from app.services.agent_map import AgentMapError, validate_agent_map

    with pytest.raises(AgentMapError) as exc:
        validate_agent_map({"core.agents.definitions": _LEGACY_DEFINITIONS}, {})
    assert "core.agents.definitions.my_sandbox.category" in exc.value.errors

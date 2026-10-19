"""Settings writes take a signed-in session, and the sign-in policy the password too (AUD-75).

An admin API key, or one leaked, reached every settings write through
``require_admin``: it could turn the login lockout off, add a trusted proxy,
stretch the token lifetimes, import a whole configuration, obtain a server's
credential, or point a probe carrying a stored credential at an address of its
choosing. Each of these takes a bearer session now (``deps.require_admin_session``,
the same refusal F6 gave the password change and the key routes), and a change
to a sign-in policy setting asks for the current password again (the same
step-up and lock as a password change).
"""

from __future__ import annotations

import re
import uuid
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1 import settings as settings_module
from app.api.v1.settings import router
from app.auth import step_up
from app.auth.jwt import create_access_token, session_claims
from app.auth.password import hash_password
from app.database import get_db
from app.deps import SESSION_ONLY_DETAIL, require_admin
from app.services.settings_catalog_api import api_catalog
from app.services.settings_service import SaveResult, SettingsService
from tests.credential_shapes import password, prefixed_key

CURRENT_PASSWORD = password(variant=3)
WRONG_PASSWORD = password(variant=4)
ADMIN_KEY = prefixed_key("mk_")
POLICY_KEY = "api.login_max_attempts"

# Every settings route that writes, imports, obtains a credential, or sends a
# stored credential to a staged address, with a body it accepts.
WRITE_ROUTES: list[tuple[str, str, dict[str, Any] | None]] = [
    ("PATCH", "/api/v1/settings", {"changes": {"core.llm.provider": "openai"}}),
    ("DELETE", "/api/v1/settings?group=llm", None),
    ("DELETE", "/api/v1/settings/core.llm.provider", None),
    ("POST", "/api/v1/settings/import", {"format": "maljan-settings/1", "values": {}}),
    ("POST", "/api/v1/settings/servers/virustotal/credential", None),
    ("POST", "/api/v1/settings/test/mcp?server=x", {"values": {}}),
    ("POST", "/api/v1/settings/test/agent", {"values": {}}),
    ("POST", "/api/v1/settings/test/llm", {"values": {}}),
    # The reads that serve every stored value a save can set.
    ("GET", "/api/v1/settings", None),
    ("GET", "/api/v1/settings/export", None),
]


def _admin() -> Any:
    return SimpleNamespace(
        id=uuid.uuid4(),
        email="admin@example.com",
        role="admin",
        is_active=True,
        hashed_password=hash_password(CURRENT_PASSWORD),
        token_generation=0,
    )


def _db(*rows: Any) -> MagicMock:
    db = MagicMock(commit=AsyncMock())
    result = MagicMock()
    result.scalar_one_or_none.return_value = rows[0] if rows else None
    db.execute = AsyncMock(return_value=result)
    return db


def _client(db: Any, user: Any | None = None) -> TestClient:
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    if user is not None:
        app.dependency_overrides[require_admin] = lambda: user
    app.dependency_overrides[get_db] = lambda: db
    return TestClient(app)


@pytest.fixture
def step_up_offline(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    state = SimpleNamespace(failure=AsyncMock(), record=AsyncMock())
    monkeypatch.setattr(step_up, "is_login_locked", AsyncMock(return_value=False))
    monkeypatch.setattr(step_up, "record_login_failure", state.failure)
    monkeypatch.setattr(step_up.audit, "record", state.record)
    return state


@pytest.mark.parametrize(("method", "url", "body"), WRITE_ROUTES)
def test_an_admin_api_key_is_refused_on_every_settings_write(method, url, body):
    db = _db()
    client = _client(db, user=_admin())
    save = AsyncMock()
    with (
        patch.object(SettingsService, "save", save),
        patch.object(SettingsService, "reset", save),
        patch.object(SettingsService, "values", save),
    ):
        r = client.request(method, url, json=body, headers={"X-API-Key": ADMIN_KEY})
    assert r.status_code == 403
    assert r.json()["detail"] == SESSION_ONLY_DETAIL
    save.assert_not_awaited()
    # Refused before the key was looked up or anything was read.
    db.execute.assert_not_awaited()


def test_a_bearer_session_saves():
    admin = _admin()
    token = create_access_token({**session_claims(admin), "type": "access"})
    client = _client(_db(admin))
    with patch.object(
        SettingsService,
        "save",
        AsyncMock(return_value=SaveResult(["core.llm.provider"], {"next_job": 1})),
    ) as save:
        r = client.patch(
            "/api/v1/settings",
            json={"changes": {"core.llm.provider": "openai"}},
            headers={"Authorization": f"Bearer {token}"},
        )
    assert r.status_code == 200, r.text
    save.assert_awaited_once()


def test_a_session_resets_and_imports():
    client = _client(_db(), user=_admin())
    with (
        patch.object(SettingsService, "reset", AsyncMock(return_value=["core.llm.provider"])),
        patch.object(
            SettingsService,
            "save",
            AsyncMock(return_value=SaveResult(["core.llm.provider"], {"next_job": 1})),
        ),
        patch.object(settings_module, "audit_record", AsyncMock()),
    ):
        assert client.delete("/api/v1/settings/core.llm.provider").status_code == 200
        imported = client.post(
            "/api/v1/settings/import",
            json={"format": "maljan-settings/1", "values": {"core.llm.provider": "openai"}},
        )
    assert imported.status_code == 200, imported.text


def test_the_sign_in_policy_settings_are_marked_for_the_password():
    marked = {e.key for e in api_catalog() if e.needs_current_password}
    assert {
        "api.rate_limit_enabled",
        "api.rate_limit_requests",
        "api.rate_limit_window_seconds",
        "api.rate_limit_whitelist",
        "api.login_max_attempts",
        "api.login_lockout_seconds",
        "api.trusted_proxy_ips",
        "api.jwt_access_token_expire_minutes",
        "api.jwt_refresh_token_expire_days",
        "api.refresh_reuse_grace_seconds",
    } <= marked
    assert "api.enrichment_enabled" not in marked
    # Every editable setting the sign-in path reads (the login throttle, the
    # rate limiter, the client address, the token lifetimes) is marked.
    from pathlib import Path

    read = set()
    root = Path(__file__).resolve().parents[2] / "apps" / "api" / "app"
    for source in [*(root / "auth").glob("*.py"), *(root / "middleware").glob("*.py")]:
        read |= set(re.findall(r'runtime_config\.get(?:_cached)?\("([a-z_]+)"', source.read_text()))
    read |= set(
        re.findall(
            r'runtime_config\.get(?:_cached)?\("([a-z_]+)"',
            (root / "api" / "v1" / "auth.py").read_text(),
        )
    )
    assert {"login_max_attempts", "trusted_proxy_ips", "rate_limit_enabled"} <= read
    editable = {e.key.removeprefix("api.") for e in api_catalog() if e.editable}
    assert {f"api.{name}" for name in read & editable} <= marked


@pytest.mark.parametrize("route", ["patch", "import"])
def test_a_policy_change_without_the_current_password_is_refused(route, step_up_offline):
    client = _client(_db(), user=_admin())
    save = AsyncMock(return_value=SaveResult([POLICY_KEY], {"live": 1}))
    with patch.object(SettingsService, "save", save):
        if route == "patch":
            r = client.patch("/api/v1/settings", json={"changes": {POLICY_KEY: 100}})
        else:
            r = client.post(
                "/api/v1/settings/import",
                json={"format": "maljan-settings/1", "values": {POLICY_KEY: 100}},
            )
    assert r.status_code == 422
    assert POLICY_KEY in r.json()["errors"]["current_password"]
    save.assert_not_awaited()
    step_up_offline.failure.assert_not_awaited()


@pytest.mark.parametrize("route", ["patch", "import"])
def test_a_policy_change_with_a_wrong_password_is_refused_and_counted(route, step_up_offline):
    admin = _admin()
    client = _client(_db(), user=admin)
    save = AsyncMock(return_value=SaveResult([POLICY_KEY], {"live": 1}))
    with patch.object(SettingsService, "save", save):
        if route == "patch":
            r = client.patch(
                "/api/v1/settings",
                json={"changes": {POLICY_KEY: 100}, "current_password": WRONG_PASSWORD},
            )
        else:
            r = client.post(
                "/api/v1/settings/import",
                json={
                    "format": "maljan-settings/1",
                    "values": {POLICY_KEY: 100},
                    "current_password": WRONG_PASSWORD,
                },
            )
    assert r.status_code == 400
    assert r.json()["detail"] == step_up.WRONG_CURRENT_PASSWORD
    save.assert_not_awaited()
    step_up_offline.failure.assert_awaited_once_with(admin.email)
    assert step_up_offline.record.await_args.args[0] == "settings.sign_in_policy.rejected"


@pytest.mark.parametrize("route", ["patch", "import"])
def test_a_policy_change_with_the_current_password_saves(route, step_up_offline):
    client = _client(_db(), user=_admin())
    save = AsyncMock(return_value=SaveResult([POLICY_KEY], {"live": 1}))
    with (
        patch.object(SettingsService, "save", save),
        patch.object(settings_module, "audit_record", AsyncMock()),
    ):
        if route == "patch":
            r = client.patch(
                "/api/v1/settings",
                json={"changes": {POLICY_KEY: 100}, "current_password": CURRENT_PASSWORD},
            )
        else:
            r = client.post(
                "/api/v1/settings/import",
                json={
                    "format": "maljan-settings/1",
                    "values": {POLICY_KEY: 100},
                    "current_password": CURRENT_PASSWORD,
                },
            )
    assert r.status_code == 200, r.text
    save.assert_awaited_once()
    step_up_offline.failure.assert_not_awaited()


def test_a_change_outside_the_policy_needs_no_password(step_up_offline):
    client = _client(_db(), user=_admin())
    with patch.object(
        SettingsService,
        "save",
        AsyncMock(return_value=SaveResult(["api.enrichment_enabled"], {"live": 1})),
    ) as save:
        r = client.patch("/api/v1/settings", json={"changes": {"api.enrichment_enabled": False}})
    assert r.status_code == 200, r.text
    save.assert_awaited_once()


@pytest.mark.parametrize("route", ["key", "group"])
def test_a_reset_of_a_stored_policy_setting_asks_for_the_password(route, step_up_offline):
    admin = _admin()
    client = _client(_db(), user=admin)
    url = f"/api/v1/settings/{POLICY_KEY}" if route == "key" else "/api/v1/settings?group=api"
    reset = AsyncMock(return_value=[POLICY_KEY])
    with (
        patch.object(SettingsService, "load_overrides", AsyncMock(return_value={POLICY_KEY: 3})),
        patch.object(SettingsService, "reset", reset),
    ):
        missing = client.request("DELETE", url)
        wrong = client.request("DELETE", url, json={"current_password": WRONG_PASSWORD})
        right = client.request("DELETE", url, json={"current_password": CURRENT_PASSWORD})
    assert missing.status_code == 422
    assert POLICY_KEY in missing.json()["errors"]["current_password"]
    assert wrong.status_code == 400
    assert wrong.json()["detail"] == step_up.WRONG_CURRENT_PASSWORD
    assert right.status_code == 200, right.text
    reset.assert_awaited_once()
    step_up_offline.failure.assert_awaited_once_with(admin.email)


def test_a_reset_of_a_policy_setting_with_nothing_stored_asks_for_nothing(step_up_offline):
    client = _client(_db(), user=_admin())
    with (
        patch.object(SettingsService, "load_overrides", AsyncMock(return_value={})),
        patch.object(SettingsService, "reset", AsyncMock(return_value=[])),
    ):
        r = client.delete(f"/api/v1/settings/{POLICY_KEY}")
    assert r.status_code == 200, r.text
    step_up_offline.failure.assert_not_awaited()


def test_a_refusal_answers_with_the_current_422_name(step_up_offline):
    """The routes name 422 as ``HTTP_422_UNPROCESSABLE_CONTENT``; the old name warns."""
    import warnings

    client = _client(_db(), user=_admin())
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        r = client.patch("/api/v1/settings", json={"changes": {POLICY_KEY: 100}})
    assert r.status_code == 422

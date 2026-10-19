"""Unit tests for the PATCH /auth/me endpoint and UserUpdateRequest schema.

These tests exercise the update path with a mocked AsyncSession and assert:
    * full_name updates are written to the user object.
    * Passwords are hashed (not stored plaintext) via hash_password().
    * A new password needs the current one, verified, and a bearer session.
    * The 8-character minimum length is enforced by the Pydantic schema.
    * extra fields are forbidden.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException, Response
from pydantic import ValidationError

from app.api.v1 import auth as auth_module  # noqa: E402
from app.api.v1.auth import update_me  # noqa: E402
from app.auth import step_up  # noqa: E402
from app.auth.password import hash_password, verify_password  # noqa: E402
from app.deps import SESSION_ONLY_DETAIL  # noqa: E402
from app.runtime_config import API_DEFAULTS  # noqa: E402
from app.schemas.auth import UserUpdateRequest  # noqa: E402
from tests.credential_shapes import password

# Built rather than written down, the way every other credential-shaped value
# in this suite is: what the assertions need is the account's current
# password, a new one past the minimum, and a third that is neither.
CURRENT_PASSWORD = password(variant=2)
NEW_PASSWORD = password()
OTHER_PASSWORD = password(variant=1)


class _FakeRuntimeConfig:
    async def get(self, name: str) -> Any:
        return API_DEFAULTS[name]


@pytest.fixture(autouse=True)
def offline_auth(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    """No Redis, no settings table, no audit database: every side is recorded."""
    state = SimpleNamespace(
        audit=AsyncMock(),
        record=AsyncMock(),
        locked=AsyncMock(return_value=False),
        failure=AsyncMock(),
        clear=AsyncMock(),
        register=AsyncMock(),
        revoke_sessions=AsyncMock(),
        revoke_api_keys=AsyncMock(return_value=2),
    )
    monkeypatch.setattr(auth_module, "_audit", state.audit)
    monkeypatch.setattr(auth_module.audit, "record", state.record)
    monkeypatch.setattr(step_up, "is_login_locked", state.locked)
    monkeypatch.setattr(step_up, "record_login_failure", state.failure)
    monkeypatch.setattr(auth_module, "clear_login_throttle", state.clear)
    monkeypatch.setattr(auth_module, "refresh_token_register", state.register)
    monkeypatch.setattr(auth_module, "revoke_sessions", state.revoke_sessions)
    monkeypatch.setattr(auth_module, "revoke_api_keys", state.revoke_api_keys)
    monkeypatch.setattr(auth_module, "runtime_config", _FakeRuntimeConfig())
    return state


def _fake_request() -> Any:
    client = SimpleNamespace(host="127.0.0.1")
    return SimpleNamespace(client=client)


def _fake_user() -> Any:
    return SimpleNamespace(
        id=uuid.uuid4(),
        email="test@example.com",
        full_name="Old Name",
        role="analyst",
        is_active=True,
        created_at=datetime.now(UTC),
        hashed_password=hash_password(CURRENT_PASSWORD),
        token_generation=0,
    )


def _fake_db() -> AsyncMock:
    db = AsyncMock()
    db.add = MagicMock()
    db.flush = AsyncMock()
    db.refresh = AsyncMock()
    return db


async def _update(body: UserUpdateRequest, user: Any, db: Any, api_key: str | None = None):
    return await update_me(
        body=body,
        request=_fake_request(),
        response=Response(),
        user=user,
        api_key=api_key,
        maljan_refresh=None,
        db=db,
    )


# ── Schema validation ──────────────────────────────────────────────────


def test_schema_allows_empty_update() -> None:
    """An empty body is valid — no fields are required."""
    body = UserUpdateRequest()
    assert body.full_name is None
    assert body.password is None


def test_schema_accepts_valid_password_with_the_current_one() -> None:
    body = UserUpdateRequest(password=NEW_PASSWORD, current_password=CURRENT_PASSWORD)
    assert body.password == NEW_PASSWORD


def test_schema_refuses_a_new_password_without_the_current_one() -> None:
    with pytest.raises(ValidationError) as excinfo:
        UserUpdateRequest(password=NEW_PASSWORD)
    assert "current_password" in str(excinfo.value)
    with pytest.raises(ValidationError):
        UserUpdateRequest(password=NEW_PASSWORD, current_password="")


def test_schema_rejects_short_password() -> None:
    """The 8-char minimum is enforced at the schema layer."""
    with pytest.raises(ValidationError) as excinfo:
        UserUpdateRequest(password="short", current_password=CURRENT_PASSWORD)
    assert "at least 8" in str(excinfo.value).lower() or "min_length" in str(excinfo.value).lower()


def test_schema_forbids_extra_fields() -> None:
    """extra='forbid' prevents callers from sneaking in role/email/etc."""
    with pytest.raises(ValidationError):
        UserUpdateRequest.model_validate({"role": "admin"})


def test_schema_accepts_full_name_only() -> None:
    body = UserUpdateRequest(full_name="New Name")
    assert body.full_name == "New Name"
    assert body.password is None


# ── Endpoint behaviour ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_update_me_updates_full_name(offline_auth: SimpleNamespace) -> None:
    user = _fake_user()
    db = _fake_db()

    result = await _update(UserUpdateRequest(full_name="New Name"), user, db)

    assert result.full_name == "New Name"
    assert result.access_token is None
    assert user.full_name == "New Name"
    db.flush.assert_awaited_once()
    db.refresh.assert_awaited_once_with(user)
    # A name change revokes nothing.
    offline_auth.revoke_sessions.assert_not_awaited()
    offline_auth.revoke_api_keys.assert_not_awaited()


@pytest.mark.asyncio
async def test_update_me_hashes_password(offline_auth: SimpleNamespace) -> None:
    """Password is hashed via hash_password() — never stored plaintext."""
    user = _fake_user()
    original_hash = user.hashed_password
    db = _fake_db()
    body = UserUpdateRequest(password=NEW_PASSWORD, current_password=CURRENT_PASSWORD)

    result = await _update(body, user, db)

    assert user.hashed_password != NEW_PASSWORD
    assert user.hashed_password != original_hash
    assert verify_password(NEW_PASSWORD, user.hashed_password)
    db.flush.assert_awaited_once()
    # Every earlier session and API key of the account is revoked, and this
    # session is handed its replacement.
    offline_auth.revoke_sessions.assert_awaited_once_with(db, user.id)
    offline_auth.revoke_api_keys.assert_awaited_once_with(db, user.id)
    offline_auth.register.assert_awaited_once()
    assert result.access_token


@pytest.mark.asyncio
async def test_update_me_updates_both_fields(offline_auth: SimpleNamespace) -> None:
    user = _fake_user()
    db = _fake_db()
    body = UserUpdateRequest(
        full_name="Both Updated", password=OTHER_PASSWORD, current_password=CURRENT_PASSWORD
    )

    await _update(body, user, db)

    assert user.full_name == "Both Updated"
    assert verify_password(OTHER_PASSWORD, user.hashed_password)
    db.add.assert_called()
    offline_auth.audit.assert_awaited_once()
    assert offline_auth.audit.await_args.kwargs["detail"] == "full_name,credential"


@pytest.mark.asyncio
async def test_update_me_no_op_when_empty() -> None:
    """An empty body should not touch the DB or hash anything."""
    user = _fake_user()
    original_hash = user.hashed_password
    original_name = user.full_name
    db = _fake_db()

    await _update(UserUpdateRequest(), user, db)

    assert user.full_name == original_name
    assert user.hashed_password == original_hash
    db.flush.assert_not_awaited()
    db.refresh.assert_not_awaited()
    db.add.assert_not_called()


@pytest.mark.asyncio
async def test_a_wrong_current_password_is_refused_and_changes_nothing(
    offline_auth: SimpleNamespace,
) -> None:
    user = _fake_user()
    original_hash = user.hashed_password
    db = _fake_db()
    body = UserUpdateRequest(
        full_name="Not Applied", password=NEW_PASSWORD, current_password=OTHER_PASSWORD
    )

    with pytest.raises(HTTPException) as excinfo:
        await _update(body, user, db)

    assert excinfo.value.status_code == 400
    assert user.hashed_password == original_hash
    assert user.full_name == "Old Name"
    db.flush.assert_not_awaited()
    offline_auth.revoke_sessions.assert_not_awaited()
    # Counted against the per-account lock, and audited.
    offline_auth.failure.assert_awaited_once_with(user.email)
    assert offline_auth.record.await_args.args[0] == "auth.credential.change.rejected"


@pytest.mark.asyncio
async def test_a_locked_account_cannot_guess_the_current_password(
    offline_auth: SimpleNamespace,
) -> None:
    offline_auth.locked.return_value = True
    user = _fake_user()
    body = UserUpdateRequest(password=NEW_PASSWORD, current_password=CURRENT_PASSWORD)

    with pytest.raises(HTTPException) as excinfo:
        await _update(body, user, _fake_db())

    assert excinfo.value.status_code == 429
    assert verify_password(CURRENT_PASSWORD, user.hashed_password)
    assert offline_auth.record.await_args.args[0] == "auth.credential.change.locked"


@pytest.mark.asyncio
async def test_an_api_key_cannot_change_the_password(offline_auth: SimpleNamespace) -> None:
    user = _fake_user()
    body = UserUpdateRequest(password=NEW_PASSWORD, current_password=CURRENT_PASSWORD)

    with pytest.raises(HTTPException) as excinfo:
        await _update(body, user, _fake_db(), api_key="mk_leaked")

    assert excinfo.value.status_code == 403
    assert excinfo.value.detail == SESSION_ONLY_DETAIL
    assert verify_password(CURRENT_PASSWORD, user.hashed_password)
    offline_auth.revoke_sessions.assert_not_awaited()


@pytest.mark.asyncio
async def test_an_api_key_may_still_change_the_name(offline_auth: SimpleNamespace) -> None:
    user = _fake_user()

    result = await _update(UserUpdateRequest(full_name="Key Named"), user, _fake_db(), "mk_k")

    assert result.full_name == "Key Named"

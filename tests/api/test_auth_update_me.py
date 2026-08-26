"""Unit tests for the PATCH /auth/me endpoint and UserUpdateRequest schema.

These tests exercise the update path with a mocked AsyncSession and assert:
    * full_name updates are written to the user object.
    * Passwords are hashed (not stored plaintext) via hash_password().
    * The 8-character minimum length is enforced by the Pydantic schema.
    * extra fields are forbidden.
"""

from __future__ import annotations

import sys
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from pydantic import ValidationError

# apps/api code lives outside the canonical maljan package path; make it
# importable so the test runner doesn't need a PYTHONPATH hack.
_API_PATH = Path(__file__).resolve().parents[2] / "apps" / "api"
if str(_API_PATH) not in sys.path:
    sys.path.insert(0, str(_API_PATH))


from app.api.v1.auth import update_me  # noqa: E402
from app.auth.password import verify_password  # noqa: E402
from app.schemas.auth import UserUpdateRequest  # noqa: E402


def _fake_request() -> Any:
    client = SimpleNamespace(host="127.0.0.1")
    return SimpleNamespace(client=client)


def _fake_user() -> Any:
    user = MagicMock()
    user.id = uuid.uuid4()
    user.email = "test@example.com"
    user.full_name = "Old Name"
    user.hashed_password = "argon2-original-hash"
    return user


def _fake_db() -> AsyncMock:
    db = AsyncMock()
    db.add = MagicMock()
    db.flush = AsyncMock()
    db.refresh = AsyncMock()
    return db


# ── Schema validation ──────────────────────────────────────────────────


def test_schema_allows_empty_update() -> None:
    """An empty body is valid — no fields are required."""
    body = UserUpdateRequest()
    assert body.full_name is None
    assert body.password is None


def test_schema_accepts_valid_password() -> None:
    body = UserUpdateRequest(password="longenough")
    assert body.password == "longenough"


def test_schema_rejects_short_password() -> None:
    """The 8-char minimum is enforced at the schema layer."""
    with pytest.raises(ValidationError) as excinfo:
        UserUpdateRequest(password="short")
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
async def test_update_me_updates_full_name() -> None:
    user = _fake_user()
    db = _fake_db()
    body = UserUpdateRequest(full_name="New Name")

    result = await update_me(body=body, request=_fake_request(), user=user, db=db)

    assert result is user
    assert user.full_name == "New Name"
    db.flush.assert_awaited_once()
    db.refresh.assert_awaited_once_with(user)


@pytest.mark.asyncio
async def test_update_me_hashes_password() -> None:
    """Password is hashed via hash_password() — never stored plaintext."""
    user = _fake_user()
    db = _fake_db()
    body = UserUpdateRequest(password="newsecret123")

    await update_me(body=body, request=_fake_request(), user=user, db=db)

    assert user.hashed_password != "newsecret123"
    assert user.hashed_password != "argon2-original-hash"
    # Hash should be verifiable.
    assert verify_password("newsecret123", user.hashed_password)
    db.flush.assert_awaited_once()


@pytest.mark.asyncio
async def test_update_me_updates_both_fields() -> None:
    user = _fake_user()
    db = _fake_db()
    body = UserUpdateRequest(full_name="Both Updated", password="anothersecret")

    await update_me(body=body, request=_fake_request(), user=user, db=db)

    assert user.full_name == "Both Updated"
    assert verify_password("anothersecret", user.hashed_password)
    # One audit log entry should be staged.
    db.add.assert_called()


@pytest.mark.asyncio
async def test_update_me_no_op_when_empty() -> None:
    """An empty body should not touch the DB or hash anything."""
    user = _fake_user()
    original_hash = user.hashed_password
    original_name = user.full_name
    db = _fake_db()
    body = UserUpdateRequest()

    await update_me(body=body, request=_fake_request(), user=user, db=db)

    assert user.full_name == original_name
    assert user.hashed_password == original_hash
    db.flush.assert_not_awaited()
    db.refresh.assert_not_awaited()
    db.add.assert_not_called()

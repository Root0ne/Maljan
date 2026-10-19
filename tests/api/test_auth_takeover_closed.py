"""A leaked credential no longer becomes a permanent account takeover.

* A request authenticated by an API key cannot change the password, mint a key
  or revoke one (``deps.get_session_user`` / ``refuse_api_key_credential``).
* A password change moves the account's token generation on and deactivates
  its API keys, so the access and refresh tokens minted before it, and the
  keys, are refused afterwards.
* A replayed refresh token revokes the whole family (every session of the
  account) and audits it; a token already revoked does not revoke again.
* API key creation and revocation write audit rows.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI, HTTPException, Response
from fastapi.security import HTTPAuthorizationCredentials
from fastapi.testclient import TestClient
from sqlalchemy.dialects import postgresql

from app.api import ws as ws_module  # noqa: E402
from app.api.v1 import audit as audit_router_module  # noqa: E402
from app.api.v1 import auth as auth_module  # noqa: E402
from app.api.v1.auth import REFRESH_COOKIE, update_me  # noqa: E402
from app.auth import revocation, step_up, throttle  # noqa: E402
from app.auth.jwt import (  # noqa: E402
    TOKEN_GENERATION_CLAIM,
    client_fingerprint,
    create_access_token,
    create_refresh_token,
    decode_token,
    session_claims,
    token_generation,
)
from app.auth.password import hash_password  # noqa: E402
from app.auth.throttle import GraceLookup  # noqa: E402
from app.database import get_db  # noqa: E402
from app.deps import SESSION_ONLY_DETAIL, _user_from_api_key, get_current_user  # noqa: E402
from app.runtime_config import API_DEFAULTS  # noqa: E402
from app.schemas.audit import APIKeyCreateRequest  # noqa: E402
from app.schemas.auth import UserUpdateRequest  # noqa: E402
from tests.credential_shapes import password, prefixed_key

CURRENT_PASSWORD = password(variant=2)
NEW_PASSWORD = password()
LEAKED_KEY = prefixed_key("mk_")
ACCESS_LIFETIME = timedelta(minutes=API_DEFAULTS["jwt_access_token_expire_minutes"])


class _FakeRuntimeConfig:
    async def get(self, name: str) -> Any:
        return API_DEFAULTS[name]


def _user(generation: int = 0) -> Any:
    return SimpleNamespace(
        id=uuid.uuid4(),
        email="victim@example.com",
        full_name="Victim",
        role="analyst",
        is_active=True,
        created_at=datetime.now(UTC),
        hashed_password=hash_password(CURRENT_PASSWORD),
        token_generation=generation,
    )


def _key(user: Any) -> Any:
    """An active, unexpiring key created under the owner's current generation."""
    return SimpleNamespace(
        user_id=user.id,
        is_active=True,
        expires_at=None,
        last_used_at=None,
        token_generation=user.token_generation,
    )


def _result(row: Any) -> MagicMock:
    result = MagicMock()
    result.scalar_one_or_none.return_value = row
    return result


def _db_returning(*rows: Any) -> MagicMock:
    """A session whose ``execute`` answers each row in turn, then the last again."""
    db = MagicMock()
    answers = [_result(row) for row in rows]

    async def _execute(*_args: Any, **_kwargs: Any) -> MagicMock:
        return answers.pop(0) if len(answers) > 1 else answers[0]

    db.execute = AsyncMock(side_effect=_execute)
    db.add = MagicMock()
    db.flush = AsyncMock()
    db.refresh = AsyncMock()
    db.commit = AsyncMock()
    return db


def _bearer(token: str) -> HTTPAuthorizationCredentials:
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


@pytest.fixture
def offline(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    """Redis, the settings table and the audit database replaced by recorders.

    The revocation functions act on the in-memory account the way their SQL
    acts on the row, so what is refused afterwards is decided by the real
    token checks.
    """
    state = SimpleNamespace(
        audit=AsyncMock(),
        record=AsyncMock(),
        consume=AsyncMock(return_value=True),
        grace=AsyncMock(return_value=GraceLookup(readable=True, fingerprint=None)),
        fingerprints=[],
        failure=AsyncMock(),
        accounts={},
        keys=[],
    )

    async def _rotate(user_id: str, jti: str, fingerprint: str) -> bool:
        # The route's atomic consume-and-open-grace, answered by ``consume``.
        state.fingerprints.append(fingerprint)
        return bool(await state.consume(user_id, jti))

    async def _client_ip(request: Any) -> str:
        return request.client.host

    state.rotate = AsyncMock(side_effect=_rotate)

    async def _revoke_sessions(_db: Any, user_id: uuid.UUID) -> None:
        state.accounts[user_id].token_generation += 1

    async def _revoke_api_keys(_db: Any, user_id: uuid.UUID) -> int:
        live = [k for k in state.keys if k.user_id == user_id and k.is_active]
        for key in live:
            key.is_active = False
        return len(live)

    state.revoke_sessions = AsyncMock(side_effect=_revoke_sessions)
    state.revoke_api_keys = AsyncMock(side_effect=_revoke_api_keys)
    monkeypatch.setattr(auth_module, "_audit", state.audit)
    monkeypatch.setattr(auth_module.audit, "record", state.record)
    monkeypatch.setattr(audit_router_module.audit, "record", state.record)
    monkeypatch.setattr(step_up, "is_login_locked", AsyncMock(return_value=False))
    monkeypatch.setattr(step_up, "record_login_failure", state.failure)
    monkeypatch.setattr(auth_module, "clear_login_throttle", AsyncMock())
    monkeypatch.setattr(auth_module, "refresh_token_register", AsyncMock())
    monkeypatch.setattr(auth_module, "refresh_token_consume", state.consume)
    monkeypatch.setattr(auth_module, "refresh_token_rotate", state.rotate)
    monkeypatch.setattr(auth_module, "refresh_token_grace", state.grace)
    monkeypatch.setattr(auth_module, "request_client_ip", _client_ip)
    monkeypatch.setattr(auth_module, "throttle_state", lambda: {"available": True})
    monkeypatch.setattr(auth_module, "revoke_sessions", state.revoke_sessions)
    monkeypatch.setattr(auth_module, "revoke_api_keys", state.revoke_api_keys)
    monkeypatch.setattr(auth_module, "runtime_config", _FakeRuntimeConfig())
    return state


def _auth_client(db: Any) -> TestClient:
    app = FastAPI()
    app.include_router(auth_module.router, prefix="/api/v1")
    app.include_router(audit_router_module.router, prefix="/api/v1")
    app.dependency_overrides[get_db] = lambda: db
    return TestClient(app, base_url="https://testserver")


# ── A leaked API key ──────────────────────────────────────────────────


def test_a_leaked_api_key_cannot_mint_or_revoke_a_key(offline: SimpleNamespace) -> None:
    db = _db_returning(None)
    client = _auth_client(db)
    headers = {"X-API-Key": LEAKED_KEY}

    minted = client.post("/api/v1/audit/api-keys", json={"name": "backdoor"}, headers=headers)
    revoked = client.delete(f"/api/v1/audit/api-keys/{uuid.uuid4()}", headers=headers)

    assert minted.status_code == 403 and minted.json()["detail"] == SESSION_ONLY_DETAIL
    assert revoked.status_code == 403 and revoked.json()["detail"] == SESSION_ONLY_DETAIL
    # Refused before the key was even looked up, and nothing was written.
    db.execute.assert_not_awaited()
    db.add.assert_not_called()
    offline.record.assert_not_awaited()


def test_a_leaked_api_key_cannot_change_the_password(offline: SimpleNamespace) -> None:
    user = _user()
    client = _auth_client(_db_returning(user))
    # The key resolves to its owner, as it does for every other route.
    client.app.dependency_overrides[get_current_user] = lambda: user  # type: ignore[attr-defined]

    r = client.patch(
        "/api/v1/auth/me",
        json={"password": NEW_PASSWORD, "current_password": CURRENT_PASSWORD},
        headers={"X-API-Key": LEAKED_KEY},
    )

    assert r.status_code == 403 and r.json()["detail"] == SESSION_ONLY_DETAIL
    offline.revoke_sessions.assert_not_awaited()


def test_a_password_change_without_the_current_password_is_refused(
    offline: SimpleNamespace,
) -> None:
    user = _user()
    client = _auth_client(_db_returning(user))
    client.app.dependency_overrides[get_current_user] = lambda: user  # type: ignore[attr-defined]

    r = client.patch("/api/v1/auth/me", json={"password": NEW_PASSWORD})

    assert r.status_code == 422
    assert "current_password" in r.text
    offline.revoke_sessions.assert_not_awaited()


# ── A password change revokes what came before it ─────────────────────


@pytest.mark.asyncio
async def test_a_password_change_revokes_old_tokens_and_api_keys(
    offline: SimpleNamespace,
) -> None:
    user = _user()
    offline.accounts[user.id] = user
    key = _key(user)
    offline.keys.append(key)
    old_access = create_access_token(session_claims(user), expires_delta=ACCESS_LIFETIME)
    old_refresh, old_jti = create_refresh_token(session_claims(user))

    # Before: the session and the key are honoured.
    assert await get_current_user(_bearer(old_access), None, _db_returning(user)) is user
    assert await _user_from_api_key(LEAKED_KEY, _db_returning(key, user)) is user

    body = UserUpdateRequest(password=NEW_PASSWORD, current_password=CURRENT_PASSWORD)
    response = Response()
    request = SimpleNamespace(client=SimpleNamespace(host="127.0.0.1"))
    updated = await update_me(
        body=body, request=request, response=response, user=user, api_key=None,
        db=_db_returning(user), maljan_refresh=old_refresh,
    )  # fmt: skip

    assert user.token_generation == 1
    # The caller's own refresh token is consumed, not left to its expiry.
    offline.consume.assert_awaited_once_with(str(user.id), old_jti)
    offline.consume.reset_mock()
    # The old access token is refused…
    with pytest.raises(HTTPException) as excinfo:
        await get_current_user(_bearer(old_access), None, _db_returning(user))
    assert excinfo.value.status_code == 401
    assert excinfo.value.detail == "Token has been revoked"
    # …the API key is refused…
    with pytest.raises(HTTPException) as excinfo:
        await _user_from_api_key(LEAKED_KEY, _db_returning(key, user))
    assert excinfo.value.status_code == 401
    # …and the old refresh token is refused as revoked, without revoking again.
    client = _auth_client(_db_returning(user))
    client.cookies.set(REFRESH_COOKIE, old_refresh)
    refused = client.post("/api/v1/auth/refresh")
    assert refused.status_code == 401
    assert refused.json()["detail"] == "Refresh token has been revoked"
    assert user.token_generation == 1

    # This session's replacement is honoured, and carries the new generation.
    assert updated.access_token
    payload = decode_token(updated.access_token)
    assert payload is not None and token_generation(payload) == 1
    assert await get_current_user(_bearer(updated.access_token), None, _db_returning(user)) is user
    assert REFRESH_COOKIE in response.headers["set-cookie"]

    offline.record.assert_awaited_once()
    assert offline.record.await_args.args == ("auth.sessions.revoked",)
    assert offline.record.await_args.kwargs["details"] == {
        "reason": "credential_change",
        "api_keys_revoked": 1,
    }


@pytest.mark.asyncio
async def test_a_token_minted_before_the_claim_existed_reads_as_generation_zero() -> None:
    """An upgrade signs no one out; the first revocation retires such a token."""
    user = _user()
    legacy = create_access_token({"sub": str(user.id)}, expires_delta=ACCESS_LIFETIME)
    assert await get_current_user(_bearer(legacy), None, _db_returning(user)) is user
    user.token_generation = 1
    with pytest.raises(HTTPException):
        await get_current_user(_bearer(legacy), None, _db_returning(user))


def test_a_non_integer_generation_claim_never_matches() -> None:
    assert token_generation({TOKEN_GENERATION_CLAIM: "0"}) is None
    assert token_generation({TOKEN_GENERATION_CLAIM: True}) is None
    assert token_generation({}) == 0


@pytest.mark.asyncio
async def test_the_live_feed_refuses_a_revoked_token() -> None:
    user = _user(generation=1)
    stale = {"sub": str(user.id), TOKEN_GENERATION_CLAIM: 0}
    current = {"sub": str(user.id), TOKEN_GENERATION_CLAIM: 1}
    assert not await ws_module._account_is_open(_db_returning(user), str(user.id), stale)
    assert await ws_module._account_is_open(_db_returning(user), str(user.id), current)
    # auth_disabled: no token, no generation to check.
    assert await ws_module._account_is_open(_db_returning(user), str(user.id), None)


# ── Refresh-token reuse revokes the family ────────────────────────────


def test_refresh_reuse_revokes_every_session_and_is_audited(offline: SimpleNamespace) -> None:
    user = _user()
    offline.accounts[user.id] = user
    replayed, _ = create_refresh_token(session_claims(user))
    sibling, _ = create_refresh_token(session_claims(user))
    sibling_access = create_access_token(session_claims(user), expires_delta=ACCESS_LIFETIME)
    db = _db_returning(user)
    client = _auth_client(db)

    offline.consume.return_value = False  # already rotated: a replay
    client.cookies.set(REFRESH_COOKIE, replayed)
    r = client.post("/api/v1/auth/refresh")

    assert r.status_code == 401
    assert r.json()["detail"] == "Refresh token has already been used"
    offline.revoke_sessions.assert_awaited_once_with(db, user.id)
    db.commit.assert_awaited_once()
    assert user.token_generation == 1
    assert offline.audit.await_args.args[2] == "auth.refresh.reuse_detected"
    offline.record.assert_awaited_once()
    assert offline.record.await_args.args == ("auth.sessions.revoked",)
    assert offline.record.await_args.kwargs["details"] == {"reason": "refresh_reuse"}

    # The rest of the family is gone with it: a sibling refresh token still
    # registered in the store and a sibling access token are both refused.
    offline.consume.return_value = True
    client.cookies.set(REFRESH_COOKIE, sibling)
    assert client.post("/api/v1/auth/refresh").status_code == 401
    assert offline.revoke_sessions.await_count == 1
    with pytest.raises(HTTPException) as excinfo:
        asyncio.run(get_current_user(_bearer(sibling_access), None, _db_returning(user)))
    assert excinfo.value.detail == "Token has been revoked"


def test_refresh_reuse_also_retires_the_accounts_api_keys(offline: SimpleNamespace) -> None:
    user = _user()
    offline.accounts[user.id] = user
    key = _key(user)
    replayed, _ = create_refresh_token(session_claims(user))
    assert asyncio.run(_user_from_api_key(LEAKED_KEY, _db_returning(key, user))) is user

    offline.consume.return_value = False
    client = _auth_client(_db_returning(user))
    client.cookies.set(REFRESH_COOKIE, replayed)
    assert client.post("/api/v1/auth/refresh").status_code == 401

    # Bound to the generation the replay moved past: refused, though no row
    # of api_keys was touched.
    assert key.is_active is True
    with pytest.raises(HTTPException) as excinfo:
        asyncio.run(_user_from_api_key(LEAKED_KEY, _db_returning(key, user)))
    assert excinfo.value.status_code == 401


# TestClient's peer address and user agent are both "testclient".
TESTCLIENT_FINGERPRINT = client_fingerprint("testclient", "testclient")


def _replay_in_grace(offline: SimpleNamespace, stored: str) -> tuple[Any, Any, Any]:
    user = _user()
    offline.accounts[user.id] = user
    rotated, rotated_jti = create_refresh_token(session_claims(user))
    client = _auth_client(_db_returning(user))
    offline.consume.return_value = False
    offline.grace.return_value = GraceLookup(readable=True, fingerprint=stored)
    client.cookies.set(REFRESH_COOKIE, rotated)
    return user, rotated_jti, client.post("/api/v1/auth/refresh")


def test_the_same_client_inside_the_grace_window_revokes_nothing(
    offline: SimpleNamespace,
) -> None:
    """A retried request or a second tab: refused, cookie kept, nothing revoked."""
    user, rotated_jti, r = _replay_in_grace(offline, TESTCLIENT_FINGERPRINT)

    assert r.status_code == 401
    assert "set-cookie" not in r.headers  # the successor cookie stays in place
    assert "access_token" not in r.text  # no fresh pair
    offline.grace.assert_awaited_once_with(str(user.id), rotated_jti)
    offline.revoke_sessions.assert_not_awaited()
    assert user.token_generation == 0
    offline.record.assert_awaited_once()
    assert offline.record.await_args.args == ("auth.refresh.reuse_in_grace",)
    # The operator's row says whether the client matched, and nothing else.
    assert offline.record.await_args.kwargs["details"] == {"fingerprint_match": True}


def test_another_client_inside_the_grace_window_is_a_replay(offline: SimpleNamespace) -> None:
    thief = client_fingerprint("203.0.113.9", "curl/8")
    user, _, r = _replay_in_grace(offline, thief)

    assert r.status_code == 401
    assert r.json()["detail"] == "Refresh token has already been used"
    assert "Max-Age=0" in r.headers["set-cookie"]  # the cookie is cleared
    offline.revoke_sessions.assert_awaited_once()
    assert user.token_generation == 1
    rows = [(c.args[0], c.kwargs["details"]) for c in offline.record.await_args_list]
    assert rows == [
        ("auth.refresh.reuse_in_grace", {"fingerprint_match": False}),
        ("auth.sessions.revoked", {"reason": "refresh_reuse_other_client"}),
    ]


def test_an_unreadable_grace_record_revokes_nothing(offline: SimpleNamespace) -> None:
    user = _user()
    offline.accounts[user.id] = user
    token, _ = create_refresh_token(session_claims(user))
    client = _auth_client(_db_returning(user))
    offline.consume.return_value = False
    offline.grace.return_value = GraceLookup(readable=False, fingerprint=None)
    client.cookies.set(REFRESH_COOKIE, token)

    r = client.post("/api/v1/auth/refresh")

    assert r.status_code == 401
    assert r.json()["detail"] == "Session could not be refreshed; sign in again."
    offline.revoke_sessions.assert_not_awaited()
    assert offline.audit.await_args.args[2] == "auth.refresh.store_unavailable"


def test_a_successful_refresh_rotates_with_the_clients_fingerprint(
    offline: SimpleNamespace,
) -> None:
    user = _user()
    token, jti = create_refresh_token(session_claims(user))
    client = _auth_client(_db_returning(user))
    client.cookies.set(REFRESH_COOKIE, token)

    assert client.post("/api/v1/auth/refresh").status_code == 200
    offline.rotate.assert_awaited_once_with(str(user.id), jti, TESTCLIENT_FINGERPRINT)
    offline.grace.assert_not_awaited()


def test_the_fingerprint_is_keyed_coarse_and_holds_no_address() -> None:
    a = client_fingerprint("2001:db8:1:2:aaaa::1", "ua")
    assert a == client_fingerprint("2001:db8:1:2:bbbb::9", "ua")  # same /64
    assert a != client_fingerprint("2001:db8:1:3::1", "ua")
    assert a != client_fingerprint("2001:db8:1:2::1", "other-ua")
    assert client_fingerprint("198.51.100.7", "ua") != client_fingerprint("198.51.100.8", "ua")
    assert "198.51.100.7" not in client_fingerprint("198.51.100.7", "ua")


class _RecordingRedis:
    def __init__(self) -> None:
        self.calls: list[tuple[Any, ...]] = []

    async def eval(self, *args: Any) -> int:
        self.calls.append(args)
        return 1


def _window(monkeypatch: pytest.MonkeyPatch, seconds: int) -> dict[str, int]:
    window = {"refresh_reuse_grace_seconds": seconds}

    class _Config:
        async def get(self, name: str) -> Any:
            return window[name]

    monkeypatch.setattr(throttle, "runtime_config", _Config())
    return window


@pytest.mark.asyncio
async def test_consume_and_grace_are_one_redis_round_trip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    redis = _RecordingRedis()
    _window(monkeypatch, API_DEFAULTS["refresh_reuse_grace_seconds"])
    monkeypatch.setattr(throttle, "_redis", AsyncMock(return_value=redis))

    assert await throttle.refresh_token_rotate("u1", "j1", "fp") is True
    assert redis.calls == [
        (
            throttle.ROTATE_SCRIPT,
            2,
            "auth:refresh:u1:j1",
            "auth:refresh:grace:u1:j1",
            "fp",
            str(API_DEFAULTS["refresh_reuse_grace_seconds"]),
        )
    ]


@pytest.mark.asyncio
async def test_the_rotate_script_leaves_no_gap_between_consume_and_grace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The real Lua, run by fakeredis: a racing second use always finds one or the other."""
    # fakeredis runs the Lua through lupa (the dev group pins fakeredis[lua]);
    # a missing lupa fails here rather than skipping the atomicity proof.
    import fakeredis
    import lupa  # noqa: F401

    redis = fakeredis.FakeAsyncRedis(decode_responses=True)
    window = _window(monkeypatch, API_DEFAULTS["refresh_reuse_grace_seconds"])
    monkeypatch.setattr(throttle, "_redis", AsyncMock(return_value=redis))
    await redis.set("auth:refresh:u1:j1", "1")

    first, second = await asyncio.gather(
        throttle.refresh_token_rotate("u1", "j1", "fp-a"),
        throttle.refresh_token_rotate("u1", "j1", "fp-b"),
    )

    # Exactly one consumed it, and the grace record holds that one's client.
    assert sorted([first, second]) == [False, True]
    winner = "fp-a" if first else "fp-b"
    assert await throttle.refresh_token_grace("u1", "j1") == GraceLookup(True, winner)
    assert await redis.exists("auth:refresh:u1:j1") == 0
    ttl = await redis.ttl("auth:refresh:grace:u1:j1")
    assert 0 < ttl <= API_DEFAULTS["refresh_reuse_grace_seconds"]
    # A jti never active opens no window; a window of 0 writes no record.
    assert await throttle.refresh_token_rotate("u1", "never", "fp") is False
    assert await throttle.refresh_token_grace("u1", "never") == GraceLookup(True, None)
    window["refresh_reuse_grace_seconds"] = 0
    await redis.set("auth:refresh:u1:j2", "1")
    assert await throttle.refresh_token_rotate("u1", "j2", "fp") is True
    assert await throttle.refresh_token_grace("u1", "j2") == GraceLookup(True, None)


def test_the_grace_window_must_be_shorter_than_the_access_token() -> None:
    from app.services.settings_catalog_api import refresh_grace_problem

    assert refresh_grace_problem({}) is None  # the documented defaults fit
    minutes = API_DEFAULTS["jwt_access_token_expire_minutes"]
    assert refresh_grace_problem({"refresh_reuse_grace_seconds": minutes * 60}) is not None
    assert (
        refresh_grace_problem(
            {"refresh_reuse_grace_seconds": 120, "jwt_access_token_expire_minutes": 2}
        )
        is not None
    )
    assert refresh_grace_problem({"refresh_reuse_grace_seconds": 0}) is None


def test_a_save_that_stretches_the_grace_window_is_refused() -> None:
    from app.services.settings_service import SettingsService, SettingsValidationError

    service = SettingsService.__new__(SettingsService)
    with pytest.raises(SettingsValidationError) as excinfo:
        service.validate(
            {}, {"refresh_reuse_grace_seconds": 60, "jwt_access_token_expire_minutes": 1}
        )
    assert "api.refresh_reuse_grace_seconds" in excinfo.value.errors


def test_a_revoked_refresh_token_replayed_does_not_revoke_again(offline: SimpleNamespace) -> None:
    user = _user(generation=0)
    offline.accounts[user.id] = user
    stale, _ = create_refresh_token(session_claims(user))
    user.token_generation = 3
    client = _auth_client(_db_returning(user))
    offline.consume.return_value = False

    client.cookies.set(REFRESH_COOKIE, stale)
    r = client.post("/api/v1/auth/refresh")

    assert r.status_code == 401 and r.json()["detail"] == "Refresh token has been revoked"
    offline.revoke_sessions.assert_not_awaited()
    assert user.token_generation == 3
    assert offline.audit.await_args.args[2] == "auth.refresh.revoked"


# ── API key create and revoke are audited ─────────────────────────────


@pytest.mark.asyncio
async def test_api_key_create_and_revoke_write_audit_rows(offline: SimpleNamespace) -> None:
    user = _user()
    request = SimpleNamespace(client=SimpleNamespace(host="127.0.0.1"))
    db = _db_returning(None)
    minted_ids: list[uuid.UUID] = []

    async def _refresh(obj: Any) -> None:
        obj.id = obj.id or uuid.uuid4()
        minted_ids.append(obj.id)

    db.refresh = AsyncMock(side_effect=_refresh)
    order: list[str] = []
    db.commit = AsyncMock(side_effect=lambda: order.append("commit"))
    offline.record.side_effect = lambda action, **_: order.append(action)
    created = await audit_router_module.create_api_key(
        req=APIKeyCreateRequest(name="ci", expires_in_days=7, current_password=CURRENT_PASSWORD),
        request=request,
        user=user,
        db=db,
    )
    assert created.raw_key  # type: ignore[attr-defined]
    # Bound to the owner's generation, and committed before it is audited or
    # handed back.
    assert created.token_generation == user.token_generation
    assert order == ["commit", "api_key.create"]
    action, kwargs = offline.record.await_args.args[0], offline.record.await_args.kwargs
    assert action == "api_key.create"
    assert kwargs["resource_type"] == "api_key"
    assert kwargs["resource_id"] == str(minted_ids[0])
    assert kwargs["user_id"] == user.id
    assert kwargs["details"]["name"] == "ci"
    assert kwargs["details"]["prefix"] == created.key_prefix
    assert kwargs["details"]["expires_at"]
    assert "raw_key" not in kwargs["details"] and "key_hash" not in kwargs["details"]

    key = SimpleNamespace(id=minted_ids[0], is_active=True, key_prefix=created.key_prefix)
    order.clear()
    revoke_db = _db_returning(key)
    revoke_db.commit = AsyncMock(side_effect=lambda: order.append("commit"))
    await audit_router_module.revoke_api_key(
        key_id=key.id, request=request, user=user, db=revoke_db
    )
    assert key.is_active is False
    assert order == ["commit", "api_key.revoke"]
    assert offline.record.await_args.args[0] == "api_key.revoke"
    assert offline.record.await_args.kwargs["resource_id"] == str(key.id)
    assert offline.record.await_args.kwargs["details"] == {"prefix": created.key_prefix}


@pytest.mark.asyncio
async def test_a_stolen_access_token_cannot_mint_a_key_without_the_password(
    offline: SimpleNamespace,
) -> None:
    user = _user()
    request = SimpleNamespace(client=SimpleNamespace(host="127.0.0.1"))
    db = _db_returning(None)

    with pytest.raises(HTTPException) as excinfo:
        await audit_router_module.create_api_key(
            req=APIKeyCreateRequest(name="backdoor", current_password=NEW_PASSWORD),
            request=request,
            user=user,
            db=db,
        )

    assert excinfo.value.status_code == 400
    db.add.assert_not_called()
    db.commit.assert_not_awaited()
    # Counted against the login lock, and audited.
    offline.failure.assert_awaited_once_with(user.email)
    assert offline.record.await_args.args[0] == "api_key.create.rejected"


def test_key_creation_without_the_current_password_is_refused(offline: SimpleNamespace) -> None:
    user = _user()
    client = _auth_client(_db_returning(None))
    client.app.dependency_overrides[audit_router_module.get_session_user] = lambda: user  # type: ignore[attr-defined]

    r = client.post("/api/v1/audit/api-keys", json={"name": "backdoor"})

    assert r.status_code == 422 and "current_password" in r.text


@pytest.mark.asyncio
async def test_a_key_from_an_earlier_generation_is_refused() -> None:
    user = _user(generation=2)
    current = _key(user)
    older = SimpleNamespace(**{**vars(current), "token_generation": 1})

    assert await _user_from_api_key(LEAKED_KEY, _db_returning(current, user)) is user
    with pytest.raises(HTTPException) as excinfo:
        await _user_from_api_key(LEAKED_KEY, _db_returning(older, user))
    assert excinfo.value.status_code == 401
    assert excinfo.value.detail == "Invalid or expired API key"


@pytest.mark.asyncio
async def test_the_password_change_commits_before_the_answer_is_built(
    offline: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    user = _user()
    offline.accounts[user.id] = user
    order: list[str] = []
    db = _db_returning(user)
    db.commit = AsyncMock(side_effect=lambda: order.append("commit"))
    offline.record.side_effect = lambda action, **_: order.append(action)
    real_refresh, real_access = auth_module.create_refresh_token, auth_module.create_access_token

    def _refresh(data: dict) -> tuple[str, str]:
        order.append("mint refresh")
        return real_refresh(data)

    def _access(data: dict) -> str:
        order.append("mint access")
        return real_access(data)

    monkeypatch.setattr(auth_module, "create_refresh_token", _refresh)
    monkeypatch.setattr(auth_module, "create_access_token", _access)

    await update_me(
        body=UserUpdateRequest(password=NEW_PASSWORD, current_password=CURRENT_PASSWORD),
        request=SimpleNamespace(client=SimpleNamespace(host="127.0.0.1")),
        response=Response(),
        user=user,
        api_key=None,
        db=db,
        maljan_refresh=None,
    )

    assert order[0] == "commit"
    assert order[1:] == ["mint refresh", "mint access", "auth.sessions.revoked"]


# ── The revocation statements ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_revocation_statements_touch_only_the_account() -> None:
    statements: list[Any] = []
    deactivated = [uuid.uuid4(), uuid.uuid4()]

    async def _execute(stmt: Any) -> MagicMock:
        statements.append(stmt)
        result = MagicMock()
        result.scalars.return_value.all.return_value = deactivated
        return result

    db = MagicMock()
    db.execute = AsyncMock(side_effect=_execute)
    user_id = uuid.uuid4()

    await revocation.revoke_sessions(db, user_id)
    count = await revocation.revoke_api_keys(db, user_id)

    assert count == len(deactivated)
    sessions_sql, keys_sql = (str(s.compile(dialect=postgresql.dialect())) for s in statements)
    assert "UPDATE users SET token_generation=(users.token_generation +" in sessions_sql
    assert "WHERE users.id =" in sessions_sql
    assert "UPDATE api_keys SET is_active=" in keys_sql
    assert "api_keys.user_id =" in keys_sql and "api_keys.is_active IS true" in keys_sql
    assert "RETURNING api_keys.id" in keys_sql


def _console_ms(name: str) -> int:
    import re
    from pathlib import Path

    source = (
        Path(__file__).resolve().parents[2] / "apps" / "web" / "src" / "lib" / "refreshLock.ts"
    ).read_text(encoding="utf-8")
    found = re.search(rf"export const {name} = ([\d_]+);", source)
    assert found is not None, name
    return int(found.group(1).replace("_", ""))


def test_the_consoles_lease_and_prompt_retry_land_inside_the_default_grace_window() -> None:
    """A refresh aborted at the lease's end, retried at once, lands inside the window.

    The values live in two languages; this is where their coupling is checked
    (``LEASE_MS`` and ``TRANSPORT_RETRY_ACQUIRE_MS`` in refreshLock.ts against
    the API's mirrors in ``settings_catalog_api``).
    """
    from app.services import settings_catalog_api as catalog

    lease_ms = _console_ms("LEASE_MS")
    retry_ms = _console_ms("TRANSPORT_RETRY_ACQUIRE_MS")
    poll_ms = _console_ms("LEASE_POLL_MS")
    assert lease_ms == catalog.CONSOLE_REFRESH_LEASE_SECONDS * 1000
    assert retry_ms == catalog.CONSOLE_REFRESH_RETRY_SECONDS * 1000
    assert poll_ms == round(catalog.CONSOLE_REFRESH_POLL_SECONDS * 1000)
    # Worst case: rotation just after the lease starts, abort at the lease's
    # end (lease - poll), the retry's lease acquired within its budget and
    # confirmed after one poll, then the network.
    worst_ms = (
        (lease_ms - poll_ms)
        + retry_ms
        + poll_ms
        + catalog.CONSOLE_REFRESH_LATENCY_MARGIN_SECONDS * 1000
    )
    min_ms = catalog.MIN_REFRESH_REUSE_GRACE_SECONDS * 1000
    assert worst_ms <= min_ms <= API_DEFAULTS["refresh_reuse_grace_seconds"] * 1000
    assert catalog.MIN_REFRESH_REUSE_GRACE_SECONDS == 10
    assert catalog.refresh_grace_problem({}) is None


def test_a_grace_window_shorter_than_the_consoles_retry_is_refused() -> None:
    from app.services.settings_catalog_api import (
        MIN_REFRESH_REUSE_GRACE_SECONDS,
        refresh_grace_problem,
    )

    assert refresh_grace_problem({"refresh_reuse_grace_seconds": 0}) is None  # off
    assert refresh_grace_problem({"refresh_reuse_grace_seconds": 1}) is not None
    below = MIN_REFRESH_REUSE_GRACE_SECONDS - 1
    assert "at least" in (refresh_grace_problem({"refresh_reuse_grace_seconds": below}) or "")
    assert (
        refresh_grace_problem({"refresh_reuse_grace_seconds": MIN_REFRESH_REUSE_GRACE_SECONDS})
        is None
    )

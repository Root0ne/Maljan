"""A session a release before the product's rename opened is still read (T-579).

Its tokens carry the issuer and audience that release minted under, its
refresh cookie has the previous name, and a grace record it wrote holds a
fingerprint under its label. Each is read while the deployment keeps the
shipped defaults; nothing else about the token is relaxed.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import jwt as pyjwt
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1 import auth as auth_module
from app.api.v1.auth import PREVIOUS_REFRESH_COOKIE, REFRESH_COOKIE, router
from app.auth import jwt as auth_jwt
from app.config import APISettings, settings
from app.database import get_db
from malspark.core.previous_name import PREVIOUS_NAME


def _token(issuer: str, audience: str, secret: str | None = None) -> str:
    return pyjwt.encode(
        {
            "sub": "someone",
            "type": "access",
            "exp": datetime.now(UTC) + timedelta(hours=1),
            "iss": issuer,
            "aud": audience,
        },
        secret if secret is not None else auth_jwt._secret(),
        algorithm=settings.jwt_algorithm,
    )


def test_the_previous_labels_are_built_from_the_previous_name() -> None:
    assert auth_jwt.PREVIOUS_ISSUER == f"{PREVIOUS_NAME}-api"
    assert auth_jwt.PREVIOUS_AUDIENCE == f"{PREVIOUS_NAME}-clients"
    assert PREVIOUS_REFRESH_COOKIE == f"{PREVIOUS_NAME}_refresh"


def test_a_token_minted_under_the_previous_labels_is_read(monkeypatch: pytest.MonkeyPatch) -> None:
    for field in ("jwt_issuer", "jwt_audience"):
        monkeypatch.setattr(settings, field, APISettings.model_fields[field].default)
    old = _token(auth_jwt.PREVIOUS_ISSUER, auth_jwt.PREVIOUS_AUDIENCE)
    new = _token(settings.jwt_issuer, settings.jwt_audience)
    assert auth_jwt.decode_token(old)["sub"] == "someone"
    assert auth_jwt.decode_token(new)["sub"] == "someone"


def test_a_token_under_the_previous_labels_still_needs_the_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for field in ("jwt_issuer", "jwt_audience"):
        monkeypatch.setattr(settings, field, APISettings.model_fields[field].default)
    forged = _token(auth_jwt.PREVIOUS_ISSUER, auth_jwt.PREVIOUS_AUDIENCE, secret="x" * 48)
    assert auth_jwt.decode_token(forged) is None


def test_an_operator_s_own_issuer_is_the_only_one_read(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "jwt_issuer", "our-issuer")
    monkeypatch.setattr(settings, "jwt_audience", "our-clients")
    assert auth_jwt.decode_token(_token(auth_jwt.PREVIOUS_ISSUER, "our-clients")) is None
    assert auth_jwt.decode_token(_token("our-issuer", auth_jwt.PREVIOUS_AUDIENCE)) is None
    assert auth_jwt.decode_token(_token("our-issuer", "our-clients"))["sub"] == "someone"


def test_a_grace_record_under_the_previous_label_matches_its_client() -> None:
    current = auth_jwt.client_fingerprint("198.51.100.1", "ua")
    previous = auth_jwt.previous_client_fingerprint("198.51.100.1", "ua")
    assert current != previous
    assert previous != auth_jwt.previous_client_fingerprint("198.51.100.2", "ua")


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    user = MagicMock()
    user.id = uuid.uuid4()
    user.is_active = True
    user.token_generation = 0
    db = MagicMock()
    res = MagicMock()
    res.scalar_one_or_none.return_value = user
    db.execute = AsyncMock(return_value=res)
    app.dependency_overrides[get_db] = lambda: db
    monkeypatch.setattr(auth_module, "refresh_token_register", AsyncMock())
    monkeypatch.setattr(auth_module, "refresh_token_consume", AsyncMock(return_value=True))
    monkeypatch.setattr(auth_module, "refresh_token_rotate", AsyncMock(return_value=True))
    monkeypatch.setattr(auth_module, "request_client_ip", AsyncMock(return_value="198.51.100.1"))
    monkeypatch.setattr(auth_module, "_audit", AsyncMock())
    monkeypatch.setattr(auth_module, "create_refresh_token", lambda d: ("new-refresh", "jti-2"))
    monkeypatch.setattr(auth_module, "create_access_token", lambda d: "access-jwt")
    monkeypatch.setattr(
        auth_module,
        "decode_token",
        lambda t: (
            {"type": "refresh", "sub": str(user.id), "jti": "jti-1"} if t == "old-refresh" else None
        ),
    )
    return TestClient(app, base_url="https://testserver")


def test_the_previous_refresh_cookie_opens_a_session_under_the_current_one(
    client: TestClient,
) -> None:
    client.cookies.set(PREVIOUS_REFRESH_COOKIE, "old-refresh", path="/api/v1/auth")
    r = client.post("/api/v1/auth/refresh")
    assert r.status_code == 200 and r.json()["access_token"] == "access-jwt"
    assert r.headers["set-cookie"].startswith(f"{REFRESH_COOKIE}=new-refresh")
    auth_module.refresh_token_rotate.assert_awaited()


def test_logout_consumes_the_previous_cookie_and_clears_both(client: TestClient) -> None:
    client.cookies.set(PREVIOUS_REFRESH_COOKIE, "old-refresh", path="/api/v1/auth")
    r = client.post("/api/v1/auth/logout")
    assert r.status_code == 204
    cleared = r.headers.get_list("set-cookie")
    assert any(c.startswith(f"{REFRESH_COOKIE}=") for c in cleared)
    assert any(c.startswith(f"{PREVIOUS_REFRESH_COOKIE}=") for c in cleared)
    auth_module.refresh_token_consume.assert_awaited_with(
        auth_module.refresh_token_consume.await_args.args[0], "jti-1"
    )

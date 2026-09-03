import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

_API = Path(__file__).resolve().parents[3] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

from app.api.v1 import auth as auth_module  # noqa: E402
from app.api.v1.auth import REFRESH_COOKIE, router  # noqa: E402
from app.database import get_db  # noqa: E402


def _user():
    u = MagicMock()
    u.id = __import__("uuid").uuid4()
    u.is_active = True
    u.hashed_password = "h"
    return u


@pytest.fixture
def client(monkeypatch):
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    db = MagicMock()
    user = _user()
    res = MagicMock()
    res.scalar_one_or_none.return_value = user
    db.execute = AsyncMock(return_value=res)
    app.dependency_overrides[get_db] = lambda: db
    monkeypatch.setattr(auth_module, "verify_password", lambda p, h: True)
    monkeypatch.setattr(auth_module, "is_login_locked", AsyncMock(return_value=False))
    monkeypatch.setattr(auth_module, "clear_login_throttle", AsyncMock())
    monkeypatch.setattr(auth_module, "refresh_token_register", AsyncMock())
    monkeypatch.setattr(auth_module, "refresh_token_consume", AsyncMock(return_value=True))
    monkeypatch.setattr(auth_module, "_audit", AsyncMock())
    monkeypatch.setattr(auth_module, "create_refresh_token", lambda d: ("refresh-jwt", "jti-1"))
    monkeypatch.setattr(auth_module, "create_access_token", lambda d: "access-jwt")

    def _decode(token: str) -> dict | None:
        if token != "refresh-jwt":
            return None
        return {"type": "refresh", "sub": str(user.id), "jti": "jti-1"}

    monkeypatch.setattr(auth_module, "decode_token", _decode)
    return TestClient(app)


def test_login_sets_httponly_cookie_and_keeps_refresh_out_of_the_body(client):
    r = client.post("/api/v1/auth/login", json={"email": "a@b.c", "password": "x"})
    assert r.status_code == 200
    assert set(r.json()) == {"access_token", "token_type"}
    cookie = r.headers["set-cookie"]
    assert cookie.startswith(f"{REFRESH_COOKIE}=refresh-jwt")
    assert "HttpOnly" in cookie and "SameSite=lax" in cookie and "Path=/api/v1/auth" in cookie


def test_refresh_reads_the_cookie_and_rotates_it(client):
    client.post("/api/v1/auth/login", json={"email": "a@b.c", "password": "x"})
    r = client.post("/api/v1/auth/refresh")
    assert r.status_code == 200 and r.json()["access_token"] == "access-jwt"
    assert REFRESH_COOKIE in r.headers["set-cookie"]


def test_refresh_without_cookie_is_401(client):
    assert client.post("/api/v1/auth/refresh").status_code == 401


def test_logout_consumes_and_clears(client):
    client.post("/api/v1/auth/login", json={"email": "a@b.c", "password": "x"})
    r = client.post("/api/v1/auth/logout")
    assert r.status_code == 204
    assert "Max-Age=0" in r.headers["set-cookie"] or "expires=" in r.headers["set-cookie"].lower()
    auth_module.refresh_token_consume.assert_awaited()

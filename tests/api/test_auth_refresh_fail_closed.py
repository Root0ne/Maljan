import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

from fastapi import FastAPI
from fastapi.testclient import TestClient

_API = Path(__file__).resolve().parents[3] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

from app.api.v1 import auth as auth_module  # noqa: E402
from app.api.v1.auth import REFRESH_COOKIE, router  # noqa: E402
from app.database import get_db  # noqa: E402


def test_refresh_answers_401_when_the_session_store_is_unavailable(monkeypatch):
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[get_db] = lambda: MagicMock()
    monkeypatch.setattr(
        auth_module, "decode_token", lambda t: {"type": "refresh", "sub": "u1", "jti": "j1"}
    )
    monkeypatch.setattr(auth_module, "refresh_token_consume", AsyncMock(return_value=False))
    audit = AsyncMock()
    monkeypatch.setattr(auth_module, "_audit", audit)
    monkeypatch.setattr(
        "app.auth.throttle.throttle_state", lambda: {"available": False, "last_error": "x"}
    )
    client = TestClient(app)
    client.cookies.set(REFRESH_COOKIE, "t")
    r = client.post("/api/v1/auth/refresh")
    assert r.status_code == 401
    # Generic detail: the reason (store outage vs. reuse) stays server-side,
    # in the audit row and the log line, not in the response body.
    assert r.json()["detail"] == "Session could not be refreshed; sign in again."
    audit.assert_awaited_once()
    _db, _user_id, action = audit.await_args.args
    assert action == "auth.refresh.store_unavailable"

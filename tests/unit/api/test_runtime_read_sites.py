"""The samples upload limit and the login throttle read their knobs through
``runtime_config``: a UI override must win over the static setting."""

import io
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException

_API = Path(__file__).resolve().parents[3] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

from app.api.v1 import samples  # noqa: E402
from app.auth import throttle  # noqa: E402


def _override(monkeypatch, module, values: dict[str, object]) -> None:
    async def _get(name: str) -> object:
        return values[name]

    monkeypatch.setattr(module.runtime_config, "get", _get)


@pytest.mark.asyncio
async def test_login_lockout_seconds_override_reaches_redis_expire(monkeypatch):
    pipe = MagicMock()
    pipe.execute = AsyncMock()
    r = MagicMock()
    r.pipeline.return_value = pipe

    async def _fake_redis():
        return r

    monkeypatch.setattr(throttle, "_redis", _fake_redis)
    _override(monkeypatch, throttle, {"login_lockout_seconds": 4321})
    await throttle.record_login_failure("Someone@Example.org")
    pipe.expire.assert_called_once_with("auth:login:fail:someone@example.org", 4321)


@pytest.mark.asyncio
async def test_login_max_attempts_override_decides_lockout(monkeypatch):
    r = MagicMock()
    r.get = AsyncMock(return_value="3")

    async def _fake_redis():
        return r

    monkeypatch.setattr(throttle, "_redis", _fake_redis)
    _override(monkeypatch, throttle, {"login_max_attempts": 3})
    assert await throttle.is_login_locked("a@b.c") is True
    _override(monkeypatch, throttle, {"login_max_attempts": 5})
    assert await throttle.is_login_locked("a@b.c") is False


def test_streaming_hashes_enforces_the_given_limit(tmp_path):
    upload = MagicMock()
    upload.file = io.BytesIO(b"x" * 100)
    with pytest.raises(HTTPException) as exc:
        samples._streaming_hashes(upload, tmp_path / "f", max_bytes=99)
    assert exc.value.status_code == 413
    upload.file = io.BytesIO(b"x" * 100)
    sha256, _sha1, _md5, size = samples._streaming_hashes(upload, tmp_path / "g", max_bytes=100)
    assert size == 100 and len(sha256) == 64

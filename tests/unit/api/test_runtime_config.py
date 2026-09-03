import sys
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_API = Path(__file__).resolve().parents[3] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

from app.runtime_config import RuntimeConfig  # noqa: E402


def factory_returning(overrides: dict):
    calls = {"n": 0}

    @asynccontextmanager
    async def _session():
        calls["n"] += 1
        db = MagicMock()
        yield db

    async def _load(_db):
        return dict(overrides)

    return _session, _load, calls


@pytest.mark.asyncio
async def test_override_wins_and_is_cached_within_ttl(monkeypatch):
    now = [100.0]
    session, load, calls = factory_returning({"api.enrichment_enabled": False})
    monkeypatch.setattr(
        "app.runtime_config.SettingsService.load_overrides", lambda self: load(self.db)
    )
    rc = RuntimeConfig(session, ttl_seconds=5, clock=lambda: now[0])
    assert await rc.get("enrichment_enabled") is False
    assert await rc.get("enrichment_enabled") is False
    assert calls["n"] == 1
    now[0] += 6
    await rc.get("enrichment_enabled")
    assert calls["n"] == 2


@pytest.mark.asyncio
async def test_falls_back_to_static_settings(monkeypatch):
    session, load, _ = factory_returning({})
    monkeypatch.setattr(
        "app.runtime_config.SettingsService.load_overrides", lambda self: load(self.db)
    )
    rc = RuntimeConfig(session, ttl_seconds=5)
    assert isinstance(await rc.get("upload_max_bytes"), int)
    assert isinstance(await rc.get_secret("virustotal_api_key"), str)


@pytest.mark.asyncio
async def test_db_failure_falls_back_and_does_not_raise(monkeypatch):
    @asynccontextmanager
    async def boom():
        raise RuntimeError("db down")
        yield

    rc = RuntimeConfig(boom, ttl_seconds=5)
    assert isinstance(await rc.get("rate_limit_requests"), int)

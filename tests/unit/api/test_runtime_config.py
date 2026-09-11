from contextlib import asynccontextmanager
from unittest.mock import MagicMock

import pytest

from app.runtime_config import RuntimeConfig
from app.services.settings_catalog_api import API_DEFAULTS


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


@pytest.mark.asyncio
async def test_every_api_default_is_reachable_with_no_override(monkeypatch):
    """Task 2: every removed-from-APISettings knob still resolves through
    ``get``/``get_secret``, falling back to ``API_DEFAULTS`` with no store
    override and no environment involved at all."""
    session, load, _ = factory_returning({})
    monkeypatch.setattr(
        "app.runtime_config.SettingsService.load_overrides", lambda self: load(self.db)
    )
    rc = RuntimeConfig(session, ttl_seconds=5)
    for name, default in API_DEFAULTS.items():
        value = await rc.get(name)
        assert value == default


@pytest.mark.asyncio
async def test_get_raises_for_a_name_absent_from_defaults(monkeypatch):
    session, load, _ = factory_returning({})
    monkeypatch.setattr(
        "app.runtime_config.SettingsService.load_overrides", lambda self: load(self.db)
    )
    rc = RuntimeConfig(session, ttl_seconds=5)
    with pytest.raises(KeyError):
        await rc.get("not_a_real_setting")


@pytest.mark.asyncio
async def test_get_cached_returns_the_default_before_get_is_ever_called():
    session, _, _ = factory_returning({})
    rc = RuntimeConfig(session, ttl_seconds=5)
    assert rc.get_cached("jwt_access_token_expire_minutes") == 30


@pytest.mark.asyncio
async def test_get_cached_reflects_the_last_get_and_invalidate_clears_it(monkeypatch):
    session, load, _ = factory_returning({"api.jwt_access_token_expire_minutes": 99})
    monkeypatch.setattr(
        "app.runtime_config.SettingsService.load_overrides", lambda self: load(self.db)
    )
    rc = RuntimeConfig(session, ttl_seconds=5)
    assert rc.get_cached("jwt_access_token_expire_minutes") == 30
    assert await rc.get("jwt_access_token_expire_minutes") == 99
    assert rc.get_cached("jwt_access_token_expire_minutes") == 99
    rc.invalidate()
    assert rc.get_cached("jwt_access_token_expire_minutes") == 30

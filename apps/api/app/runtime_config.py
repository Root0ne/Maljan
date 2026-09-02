"""Live reads of the API's runtime-safe knobs.

``api.*`` overrides saved from the UI are read through here with a short TTL,
so a change is effective on every API process within seconds without a
restart. Anything not overridden falls back to the static APISettings, and so
does everything when the database cannot be reached: a settings read must
never take a request down.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from typing import Any

from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import async_session_factory
from app.services.settings_service import SettingsService

logger = logging.getLogger(__name__)

SessionFactory = Callable[[], AbstractAsyncContextManager[AsyncSession]]


class RuntimeConfig:
    def __init__(
        self,
        session_factory: SessionFactory,
        ttl_seconds: float = 5.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._factory = session_factory
        self._ttl = ttl_seconds
        self._clock = clock
        self._cache: dict[str, Any] = {}
        self._loaded_at: float | None = None

    async def _overrides(self) -> dict[str, Any]:
        now = self._clock()
        if self._loaded_at is not None and now - self._loaded_at < self._ttl:
            return self._cache
        try:
            async with self._factory() as db:
                self._cache = await SettingsService(db).load_overrides()
        except Exception as exc:  # noqa: BLE001 - fall back to static settings
            logger.warning("runtime settings unavailable, using static configuration: %s", exc)
        self._loaded_at = now
        return self._cache

    async def get(self, name: str) -> Any:
        overrides = await self._overrides()
        if f"api.{name}" in overrides:
            return overrides[f"api.{name}"]
        value = getattr(settings, name)
        return value.get_secret_value() if isinstance(value, SecretStr) else value

    async def get_secret(self, name: str) -> str:
        value = await self.get(name)
        return str(value) if value else ""

    def invalidate(self) -> None:
        self._loaded_at = None


runtime_config = RuntimeConfig(async_session_factory)

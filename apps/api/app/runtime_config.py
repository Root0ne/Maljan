"""Live reads of the API's runtime-safe knobs.

``api.*`` overrides saved from the UI are read through here with a short TTL,
so a change is effective on every API process within seconds without a
restart. Anything not overridden falls back to ``API_DEFAULTS`` (Task 2:
these knobs no longer live on ``APISettings``/the environment at all), and so
does everything when the database cannot be reached: a settings read must
never take a request down.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_factory
from app.services.settings_catalog_api import API_DEFAULTS
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
        # The last value ``get()`` resolved for each name, for the synchronous
        # ``get_cached`` accessor used by call sites (``app.auth.jwt``) that
        # cannot await a DB round trip on every token issued.
        self._resolved: dict[str, Any] = {}

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
            value = overrides[f"api.{name}"]
        else:
            value = API_DEFAULTS[name]
        self._resolved[name] = value
        return value

    def get_cached(self, name: str) -> Any:
        """Synchronous read of the last value ``get()`` resolved for ``name``.

        Falls back to ``API_DEFAULTS[name]`` when ``get()`` has never been
        called for this name in this process yet. Used by call sites that are
        sync (``app.auth.jwt``'s token builders) or cannot afford to await a
        settings read on every call; the async caller that issues tokens
        warms this by calling ``get()`` once beforehand.
        """
        if name in self._resolved:
            return self._resolved[name]
        return API_DEFAULTS[name]

    async def get_secret(self, name: str) -> str:
        value = await self.get(name)
        return str(value) if value else ""

    def invalidate(self) -> None:
        self._loaded_at = None
        self._resolved = {}


runtime_config = RuntimeConfig(async_session_factory)

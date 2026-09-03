"""Redis-backed authentication throttling helpers.

All helpers degrade gracefully if Redis is unreachable: they emit a debug
log and behave as if the throttle/store were empty. This means the API
remains functional during a Redis outage, at the cost of temporarily
disabling brute-force protection and refresh-token rotation.
"""

from __future__ import annotations

from typing import Any

import redis.asyncio as aioredis

from app.config import settings
from app.logging_config import get_logger
from app.runtime_config import runtime_config

logger = get_logger("auth.throttle")

_REFRESH_KEY = "auth:refresh:{user_id}:{jti}"
_LOGIN_FAIL_KEY = "auth:login:fail:{email}"

_pool: Any = None


async def _redis() -> Any | None:
    """Return a process-wide Redis pool, or ``None`` if Redis is unavailable."""
    global _pool
    if _pool is None:
        try:
            _pool = aioredis.from_url(settings.redis_url, decode_responses=True)
            await _pool.ping()
        except Exception as exc:
            logger.warning("Redis unreachable for auth throttle (%s); throttle disabled.", exc)
            _pool = False  # sentinel: don't keep retrying
    return _pool if _pool not in (None, False) else None


async def refresh_token_register(user_id: str, jti: str) -> None:
    """Mark a refresh token's jti as active."""
    r = await _redis()
    if r is None:
        return
    key = _REFRESH_KEY.format(user_id=user_id, jti=jti)
    ttl = settings.jwt_refresh_token_expire_days * 86400
    try:
        await r.set(key, "1", ex=ttl)
    except Exception as exc:
        logger.debug("refresh_token_register failed: %s", exc)


async def refresh_token_consume(user_id: str | None, jti: str) -> bool:
    """Atomically consume a refresh token's jti.

    Returns ``True`` if the jti was active and has now been invalidated.
    Returns ``False`` if the token has already been used or never existed —
    the caller should treat this as a reuse attempt.
    """
    if not user_id or not jti:
        return False
    r = await _redis()
    if r is None:
        # Throttle disabled — accept the token so the API remains usable.
        return True
    key = _REFRESH_KEY.format(user_id=user_id, jti=jti)
    try:
        return bool(await r.delete(key))
    except Exception as exc:
        logger.debug("refresh_token_consume failed: %s", exc)
        return True


async def record_login_failure(email: str) -> None:
    """Increment the per-account failure counter and apply lockout when exceeded."""
    r = await _redis()
    if r is None:
        return
    key = _LOGIN_FAIL_KEY.format(email=email.lower())
    try:
        pipe = r.pipeline()
        pipe.incr(key)
        pipe.expire(key, await runtime_config.get("login_lockout_seconds"))
        await pipe.execute()
    except Exception as exc:
        logger.debug("record_login_failure failed: %s", exc)


async def clear_login_throttle(email: str) -> None:
    r = await _redis()
    if r is None:
        return
    try:
        await r.delete(_LOGIN_FAIL_KEY.format(email=email.lower()))
    except Exception as exc:
        logger.debug("clear_login_throttle failed: %s", exc)


async def is_login_locked(email: str) -> bool:
    r = await _redis()
    if r is None:
        return False
    try:
        value = await r.get(_LOGIN_FAIL_KEY.format(email=email.lower()))
        return value is not None and int(value) >= await runtime_config.get("login_max_attempts")
    except Exception as exc:
        logger.debug("is_login_locked failed: %s", exc)
        return False

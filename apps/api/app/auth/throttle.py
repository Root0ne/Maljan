"""Redis-backed authentication throttling helpers.

Availability is tracked, not assumed. When Redis is unreachable:

- refresh-token consumption FAILS CLOSED (``False``): reuse detection is
  blind, so no refresh token is honoured until the store is back; a user
  loses at most one access-token lifetime;
- the login lock FAILS OPEN (``False``): failing closed would lock every
  account for the length of the outage;
- failures are still not recorded (nowhere to record them).

Every helper marks the process-wide ``observability.throttle`` state, the
connection is retried after ``RETRY_AFTER_S`` rather than abandoned, and each
transition (down, restored) logs exactly one warning.
"""

from __future__ import annotations

import time
from typing import Any, NamedTuple

import redis.asyncio as aioredis

from app import observability
from app.config import settings
from app.logging_config import get_logger
from app.runtime_config import runtime_config

logger = get_logger("auth.throttle")

_REFRESH_KEY = "auth:refresh:{user_id}:{jti}"
# Written when a refresh token is consumed, for ``refresh_reuse_grace_seconds``,
# holding a keyed hash of the client that consumed it: a second presentation
# of that jti inside the window from the same client is a retry or a race
# between tabs, refused without revoking anything; from another client it is
# a replay.
_REFRESH_GRACE_KEY = "auth:refresh:grace:{user_id}:{jti}"
_LOGIN_FAIL_KEY = "auth:login:fail:{email}"

RETRY_AFTER_S = 30.0

_pool: Any = None
_last_failure_at: float | None = None


async def _mark_down(exc: BaseException) -> None:
    global _pool, _last_failure_at
    old_pool, _pool = _pool, None
    if old_pool is not None:
        try:
            await old_pool.aclose()
        except Exception:  # noqa: BLE001 - already down; closing is best-effort
            pass
    _last_failure_at = time.monotonic()
    state = observability.throttle
    if state.available:
        logger.warning(
            "Auth throttle store unreachable (%s); refresh fails closed, login lock is "
            "open until Redis is back.",
            type(exc).__name__,
        )
        state.available = False
        state.degraded_since = _last_failure_at
    state.last_error = type(exc).__name__


def _mark_up() -> None:
    state = observability.throttle
    if not state.available:
        logger.warning("Auth throttle store restored.")
    state.available = True
    state.degraded_since = None
    state.last_error = None


async def _redis() -> Any | None:
    """Return the shared Redis client, or ``None`` while the store is down.

    A failed connection is retried once ``RETRY_AFTER_S`` has passed; there is
    no permanent sentinel.
    """
    global _pool
    if _pool is not None:
        return _pool
    if _last_failure_at is not None and time.monotonic() - _last_failure_at < RETRY_AFTER_S:
        return None
    try:
        client = aioredis.from_url(settings.redis_url, decode_responses=True)
        await client.ping()
    except Exception as exc:  # noqa: BLE001 - any failure means "down"
        await _mark_down(exc)
        return None
    if _pool is not None:
        # Another coroutine already reconnected while we were pinging; keep
        # its client as the one shared pool instead of racing to overwrite it.
        await client.aclose()
        return _pool
    _pool = client
    _mark_up()
    return _pool


def throttle_state() -> dict[str, object]:
    return observability.throttle.as_dict()


async def refresh_token_register(user_id: str, jti: str) -> None:
    """Mark a refresh token's jti as active."""
    r = await _redis()
    if r is None:
        return
    key = _REFRESH_KEY.format(user_id=user_id, jti=jti)
    ttl = await runtime_config.get("jwt_refresh_token_expire_days") * 86400
    try:
        await r.set(key, "1", ex=ttl)
    except Exception as exc:  # noqa: BLE001
        logger.debug(  # nosemgrep: python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure — logs only the exception's class name, never the exception itself  # noqa: E501
            "refresh_token_register failed: %s", type(exc).__name__
        )
        await _mark_down(exc)


async def refresh_token_consume(user_id: str | None, jti: str) -> bool:
    """Atomically consume a refresh token's jti.

    ``True`` only when the store confirmed the jti was active and is now gone.
    ``False`` when it was already used, never existed, or the store is
    unavailable — the caller must refuse the refresh in every one of those.
    """
    if not user_id or not jti:
        return False
    r = await _redis()
    if r is None:
        return False
    key = _REFRESH_KEY.format(user_id=user_id, jti=jti)
    try:
        return bool(await r.delete(key))
    except Exception as exc:  # noqa: BLE001
        logger.debug(  # nosemgrep: python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure — logs only the exception's class name, never the exception itself  # noqa: E501
            "refresh_token_consume failed: %s", type(exc).__name__
        )
        await _mark_down(exc)
        return False


# Consume the active jti and open its grace window in one step. Two separate
# commands left a gap in which a second request found the jti neither active
# nor in grace and was read as a replay, revoking every session. KEYS[1] is
# the active key, KEYS[2] the grace key; ARGV[1] the client fingerprint,
# ARGV[2] the window in seconds (0 opens none). Returns 1 when the jti was
# active and is now consumed, else 0.
ROTATE_SCRIPT = (
    "local deleted = redis.call('DEL', KEYS[1]) "
    "if deleted == 1 and tonumber(ARGV[2]) > 0 then "
    "redis.call('SET', KEYS[2], ARGV[1], 'EX', tonumber(ARGV[2])) end "
    "return deleted"
)


class GraceLookup(NamedTuple):
    """A grace record read back: ``readable`` False when the store failed."""

    readable: bool
    fingerprint: str | None


async def refresh_token_rotate(user_id: str | None, jti: str, fingerprint: str) -> bool:
    """Atomically consume a refresh token's jti and open its reuse grace window.

    ``True`` only when the store confirmed the jti was active and is now gone,
    as ``refresh_token_consume``; the grace record, holding ``fingerprint``
    (a keyed hash, never the address itself) for ``refresh_reuse_grace_seconds``,
    is written by the same script, so no request can fall between the two.
    """
    if not user_id or not jti:
        return False
    grace = int(await runtime_config.get("refresh_reuse_grace_seconds"))
    r = await _redis()
    if r is None:
        return False
    try:
        deleted = await r.eval(
            ROTATE_SCRIPT,
            2,
            _REFRESH_KEY.format(user_id=user_id, jti=jti),
            _REFRESH_GRACE_KEY.format(user_id=user_id, jti=jti),
            fingerprint,
            str(max(grace, 0)),
        )
        return bool(int(deleted))
    except Exception as exc:  # noqa: BLE001
        logger.debug(  # nosemgrep: python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure — logs only the exception's class name, never the exception itself  # noqa: E501
            "refresh_token_rotate failed: %s", type(exc).__name__
        )
        await _mark_down(exc)
        return False


async def refresh_token_grace(user_id: str | None, jti: str) -> GraceLookup:
    """The fingerprint stored when this jti was rotated, if within the window."""
    if not user_id or not jti:
        return GraceLookup(readable=True, fingerprint=None)
    r = await _redis()
    if r is None:
        return GraceLookup(readable=False, fingerprint=None)
    try:
        value = await r.get(_REFRESH_GRACE_KEY.format(user_id=user_id, jti=jti))
    except Exception as exc:  # noqa: BLE001
        logger.debug(  # nosemgrep: python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure — logs only the exception's class name, never the exception itself  # noqa: E501
            "refresh_token_grace failed: %s", type(exc).__name__
        )
        await _mark_down(exc)
        return GraceLookup(readable=False, fingerprint=None)
    return GraceLookup(readable=True, fingerprint=str(value) if value is not None else None)


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
    except Exception as exc:  # noqa: BLE001
        logger.debug("record_login_failure failed: %s", type(exc).__name__)
        await _mark_down(exc)


async def clear_login_throttle(email: str) -> None:
    r = await _redis()
    if r is None:
        return
    try:
        await r.delete(_LOGIN_FAIL_KEY.format(email=email.lower()))
    except Exception as exc:  # noqa: BLE001
        logger.debug("clear_login_throttle failed: %s", type(exc).__name__)
        await _mark_down(exc)


async def is_login_locked(email: str) -> bool:
    r = await _redis()
    if r is None:
        return False
    try:
        value = await r.get(_LOGIN_FAIL_KEY.format(email=email.lower()))
        return value is not None and int(value) >= await runtime_config.get("login_max_attempts")
    except Exception as exc:  # noqa: BLE001
        logger.debug("is_login_locked failed: %s", type(exc).__name__)
        await _mark_down(exc)
        return False

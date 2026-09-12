"""JWT token creation and verification.

Tokens carry ``aud`` and ``iss`` claims so that decode validation rejects
tokens minted by an unrelated service even if the secret were shared. A
unique ``jti`` is included on every token to enable Redis-backed revocation
and refresh-token rotation/reuse detection.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import jwt
from pydantic import SecretStr

from app.config import settings

# ``app.runtime_config`` is imported lazily inside the two token builders
# below, not at module scope: it transitively imports ``app.database``,
# which calls ``create_async_engine`` at import time. Nothing connects, but
# a script that only wants to mint/verify a token should not pay that
# import-time cost just for importing this module.


def _secret() -> str:
    raw = settings.jwt_secret_key
    return raw.get_secret_value() if isinstance(raw, SecretStr) else str(raw)


def _previous_secret() -> str:
    """Return the previous secret if one is configured, else empty string.

    During a key rotation window
    the previous secret is kept as a fallback in ``decode_token`` so
    in-flight tokens stay valid until they naturally expire.
    """
    raw = getattr(settings, "jwt_previous_secret_key", None)
    if raw is None:
        return ""
    return raw.get_secret_value() if isinstance(raw, SecretStr) else str(raw)


def _base_claims(token_type: str, expires: datetime) -> dict[str, Any]:
    return {
        "type": token_type,
        "exp": expires,
        "iat": datetime.now(UTC),
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "jti": uuid.uuid4().hex,
    }


def _encode_headers() -> dict[str, str]:
    """JWT header fragment that carries the current ``kid``."""
    return {"kid": getattr(settings, "jwt_key_id", "v1")}


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """Create a JWT access token.

    The expiry minutes come from ``runtime_config.get_cached`` rather than a
    static setting. This function stays synchronous on purpose —
    its signature takes no awaitable — and reads the *last value the async
    login/refresh route resolved* rather than awaiting a settings read
    itself; the route calls ``await runtime_config.get(...)`` once before
    minting so that cached value is fresh for the tokens it is about to
    issue.
    """
    from app.runtime_config import runtime_config

    expire = datetime.now(UTC) + (
        expires_delta
        or timedelta(minutes=runtime_config.get_cached("jwt_access_token_expire_minutes"))
    )
    payload = {**data, **_base_claims("access", expire)}
    return cast(
        str,
        jwt.encode(
            payload,
            _secret(),
            algorithm=settings.jwt_algorithm,
            headers=_encode_headers(),
        ),
    )


def create_refresh_token(data: dict) -> tuple[str, str]:
    """Create a JWT refresh token. Returns ``(token, jti)``.

    Callers should persist the ``jti`` so they can later detect reuse and
    rotate the token at the next ``/auth/refresh`` request. See
    ``create_access_token`` for why the expiry is read via
    ``runtime_config.get_cached`` rather than awaited here.
    """
    from app.runtime_config import runtime_config

    expire = datetime.now(UTC) + timedelta(
        days=runtime_config.get_cached("jwt_refresh_token_expire_days")
    )
    claims = _base_claims("refresh", expire)
    payload = {**data, **claims}
    token = cast(
        str,
        jwt.encode(
            payload,
            _secret(),
            algorithm=settings.jwt_algorithm,
            headers=_encode_headers(),
        ),
    )
    return token, claims["jti"]


def decode_token(token: str) -> dict[str, Any] | None:
    """Decode and validate a JWT token. Returns payload or ``None`` if invalid.

    Try the active secret first, then fall back to
    the previous secret if configured. This is the dual-secret accept
    window that lets operators rotate ``JWT_SECRET_KEY`` without
    invalidating every issued token at once.
    """
    secrets_to_try = [_secret()]
    prev = _previous_secret()
    if prev:
        secrets_to_try.append(prev)

    for candidate in secrets_to_try:
        try:
            return cast(
                dict[str, Any],
                jwt.decode(
                    token,
                    candidate,
                    algorithms=[settings.jwt_algorithm],
                    audience=settings.jwt_audience,
                    issuer=settings.jwt_issuer,
                ),
            )
        except jwt.PyJWTError:
            continue
    return None

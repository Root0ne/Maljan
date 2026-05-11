"""JWT token creation and verification.

Tokens carry ``aud`` and ``iss`` claims so that decode validation rejects
tokens minted by an unrelated service even if the secret were shared. A
unique ``jti`` is included on every token to enable Redis-backed revocation
and refresh-token rotation/reuse detection.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from jose import JWTError, jwt
from pydantic import SecretStr

from app.config import settings


def _secret() -> str:
    raw = settings.jwt_secret_key
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


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """Create a JWT access token."""
    expire = datetime.now(UTC) + (
        expires_delta or timedelta(minutes=settings.jwt_access_token_expire_minutes)
    )
    payload = {**data, **_base_claims("access", expire)}
    return jwt.encode(payload, _secret(), algorithm=settings.jwt_algorithm)


def create_refresh_token(data: dict) -> tuple[str, str]:
    """Create a JWT refresh token. Returns ``(token, jti)``.

    Callers should persist the ``jti`` so they can later detect reuse and
    rotate the token at the next ``/auth/refresh`` request.
    """
    expire = datetime.now(UTC) + timedelta(days=settings.jwt_refresh_token_expire_days)
    claims = _base_claims("refresh", expire)
    payload = {**data, **claims}
    token = jwt.encode(payload, _secret(), algorithm=settings.jwt_algorithm)
    return token, claims["jti"]


def decode_token(token: str) -> dict | None:
    """Decode and validate a JWT token. Returns payload or ``None`` if invalid."""
    try:
        return jwt.decode(
            token,
            _secret(),
            algorithms=[settings.jwt_algorithm],
            audience=settings.jwt_audience,
            issuer=settings.jwt_issuer,
        )
    except JWTError:
        return None

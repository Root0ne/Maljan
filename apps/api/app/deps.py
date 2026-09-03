"""FastAPI dependencies — database sessions, current user extraction."""

import hashlib
import uuid
from datetime import UTC, datetime

from fastapi import Depends, HTTPException, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.jwt import decode_token
from app.config import settings
from app.database import get_db
from app.models.audit import APIKey
from app.models.user import User

# auto_error=False so the dependency still runs when ``auth_disabled`` is
# active and the client sends no Authorization header.
security_scheme = HTTPBearer(auto_error=False)

# Audit 2026-07-26 (K2): API keys used to be write-only — ``/audit/api-keys``
# minted them and the UI told the operator to copy the secret, but NOTHING ever
# read ``APIKey.key_hash`` back, so a key authenticated exactly zero requests.
# auto_error=False mirrors the bearer scheme so the two can coexist.
api_key_scheme = APIKeyHeader(name="X-API-Key", auto_error=False)


def hash_api_key(raw_key: str) -> str:
    """Return the stored representation of a raw API key.

    Must stay in lockstep with ``app.api.v1.audit._generate_api_key``; both call
    sites import this helper so the algorithm can only ever change in one place.
    """
    return hashlib.sha256(raw_key.encode()).hexdigest()


async def _user_from_api_key(raw_key: str, db: AsyncSession) -> User:
    """Resolve an ``X-API-Key`` header to its owning user.

    Rejects unknown, revoked and expired keys with the same generic 401 so the
    header can't be used as an oracle to distinguish them. Stamps
    ``last_used_at`` so operators can spot stale or leaked keys.
    """
    result = await db.execute(select(APIKey).where(APIKey.key_hash == hash_api_key(raw_key)))
    api_key = result.scalar_one_or_none()

    invalid = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired API key",
    )
    if api_key is None or not api_key.is_active:
        raise invalid
    if api_key.expires_at is not None and api_key.expires_at <= datetime.now(UTC):
        raise invalid

    user_result = await db.execute(select(User).where(User.id == api_key.user_id))
    user = user_result.scalar_one_or_none()
    if user is None:
        raise invalid
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated",
        )

    api_key.last_used_at = datetime.now(UTC)
    return user


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(security_scheme),
    api_key: str | None = Depends(api_key_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Resolve the caller from an ``X-API-Key`` header or a JWT bearer token.

    Raises:
        HTTPException 401: If the credential is missing, invalid or expired.
        HTTPException 403: If the user account is deactivated.
    """
    if settings.auth_disabled:
        dev_uuid = uuid.UUID(settings.auth_disabled_user_id)
        result = await db.execute(select(User).where(User.id == dev_uuid))
        dev_user = result.scalar_one_or_none()
        if dev_user is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=(
                    "auth_disabled is set but the dev user row is missing; "
                    "restart the API to seed it."
                ),
            )
        return dev_user

    # API key first: it is an explicit, unambiguous credential, so a caller that
    # sends one gets its verdict rather than silently falling through to the
    # bearer path and receiving a confusing "Not authenticated".
    if api_key:
        return await _user_from_api_key(api_key, db)

    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_token(credentials.credentials)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token_type = payload.get("type")
    if token_type != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type; access token required",
        )

    user_id = payload.get("sub")
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing subject claim",
        )

    result = await db.execute(select(User).where(User.id == uuid.UUID(user_id)))
    user = result.scalar_one_or_none()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated",
        )

    return user


async def optional_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(security_scheme),
    api_key: str | None = Depends(api_key_scheme),
    db: AsyncSession = Depends(get_db),
) -> User | None:
    """Resolve the caller like ``get_current_user``, but never raise.

    For routes that stay reachable without authentication but reveal extra
    detail to a signed-in caller instead of gating the whole route behind
    it (``/system/status``'s throttle state is the first user). Any failure
    that would make ``get_current_user`` raise — no credential, an invalid
    or expired token, a deactivated account — resolves to ``None`` here.
    """
    try:
        return await get_current_user(credentials=credentials, api_key=api_key, db=db)
    except HTTPException:
        return None


async def require_active_user(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Re-validate the user's ``is_active`` state at resource-access time.

    SEC-TOCTOU-AUTHZ-01 (audit 2026-05-19): ``get_current_user`` decodes
    the JWT and reads the user row, but a concurrent admin action can
    deactivate the user *between* that lookup and the actual resource
    operation. Endpoints that mutate or expose sensitive data should
    depend on this re-check helper instead of plain ``get_current_user``;
    the second SELECT is microseconds compared to a request's typical
    lifetime and closes the TOCTOU window.
    """
    refreshed = await db.execute(select(User).where(User.id == user.id))
    fresh = refreshed.scalar_one_or_none()
    if fresh is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User no longer exists",
        )
    if not fresh.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated",
        )
    return fresh


async def require_admin(user: User = Depends(require_active_user)) -> User:
    """Dependency that requires the current user to have admin role.

    SEC-TOCTOU-AUTHZ-01 (audit 2026-05-19): now depends on
    ``require_active_user`` so admin-gated endpoints get the same
    deactivation re-check as ordinary user-gated mutations.
    """
    if user.role != "admin":
        # Surface the user's actual role so the UI can show "you need admin"
        # rather than a generic 403; clients sniffing this string can hide
        # admin-only nav links instead of guessing.
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Admin role required (current role: {user.role})",
        )
    return user

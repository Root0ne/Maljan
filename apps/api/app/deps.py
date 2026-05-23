"""FastAPI dependencies — database sessions, current user extraction."""

import uuid

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.jwt import decode_token
from app.config import settings
from app.database import get_db
from app.models.user import User

# auto_error=False so the dependency still runs when ``auth_disabled`` is
# active and the client sends no Authorization header.
security_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(security_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Extract and validate the current user from the JWT bearer token.

    Raises:
        HTTPException 401: If the token is invalid, expired, or user not found.
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

"""Authentication endpoints — register, login, refresh, me.

Hardening applied:
    * AuditLog entries on register / login / refresh / failure.
    * Per-account brute-force throttle backed by Redis (graceful fallback to
      noop when Redis is unavailable).
    * Refresh-token rotation with reuse detection — each refresh issues a
      new ``jti`` and invalidates the previous one. Re-using a previously
      rotated token logs an audit event and forces re-authentication.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.jwt import create_access_token, create_refresh_token, decode_token
from app.auth.password import hash_password, verify_password
from app.auth.throttle import (
    clear_login_throttle,
    is_login_locked,
    record_login_failure,
    refresh_token_consume,
    refresh_token_register,
)
from app.config import settings
from app.database import get_db
from app.deps import get_current_user
from app.logging_config import get_logger
from app.models.audit import AuditLog
from app.models.user import User
from app.schemas.auth import (
    RefreshTokenRequest,
    TokenResponse,
    UserLoginRequest,
    UserRegisterRequest,
    UserResponse,
    UserUpdateRequest,
)

logger = get_logger("api.auth")

router = APIRouter(prefix="/auth", tags=["Authentication"])


def _client_ip(request: Request) -> str:
    return getattr(getattr(request, "client", None), "host", "") or ""


async def _audit(
    db: AsyncSession,
    user_id: uuid.UUID | None,
    action: str,
    *,
    request: Request,
    detail: str | None = None,
) -> None:
    try:
        db.add(
            AuditLog(
                user_id=user_id,
                action=action,
                resource_type="auth",
                resource_id=str(user_id) if user_id else None,
                details={"detail": detail} if detail else None,
                ip_address=_client_ip(request) or None,
            )
        )
    except Exception as exc:
        logger.debug("AuditLog insert failed: %s", exc)


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(
    body: UserRegisterRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> User:
    """Register a new user account."""
    logger.info("Registration attempt: email=%s", body.email)

    result = await db.execute(select(User).where(User.email == body.email))
    if result.scalar_one_or_none():
        logger.warning("Registration failed: email already exists - %s", body.email)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    user = User(
        email=body.email,
        hashed_password=hash_password(body.password),
        full_name=body.full_name,
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)

    await _audit(db, user.id, "auth.register", request=request)
    logger.info("User registered: id=%s", user.id, extra={"user_id": str(user.id)})
    return user


@router.post("/login", response_model=TokenResponse)
async def login(
    body: UserLoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Authenticate and receive JWT tokens."""
    logger.info("Login attempt: email=%s", body.email)

    if await is_login_locked(body.email):
        await _audit(db, None, "auth.login.locked", request=request)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Try again later.",
        )

    result = await db.execute(select(User).where(User.email == body.email))
    user = result.scalar_one_or_none()

    if not user or not verify_password(body.password, user.hashed_password):
        await record_login_failure(body.email)
        await _audit(db, user.id if user else None, "auth.login.failure", request=request)
        logger.warning(
            "Login failed: invalid credentials for %s", body.email, extra={"component": "auth"}
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if not user.is_active:
        await _audit(db, user.id, "auth.login.blocked_inactive", request=request)
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is deactivated")

    await clear_login_throttle(body.email)

    token_data = {"sub": str(user.id)}
    refresh, jti = create_refresh_token(token_data)
    await refresh_token_register(str(user.id), jti)

    await _audit(db, user.id, "auth.login.success", request=request)
    logger.info("Login successful: user=%s", user.id, extra={"user_id": str(user.id)})
    return {
        "access_token": create_access_token(token_data),
        "refresh_token": refresh,
        "token_type": "bearer",
    }


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    body: RefreshTokenRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Exchange a refresh token for a new access + refresh token pair.

    Implements rotation + reuse detection: if the same refresh token is used
    twice, all of that user's refresh tokens are invalidated and the request
    is rejected with 401.
    """
    payload = decode_token(body.refresh_token)
    if payload is None or payload.get("type") != "refresh":
        await _audit(db, None, "auth.refresh.invalid", request=request)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    user_id = payload.get("sub")
    jti = payload.get("jti", "")
    consumed = await refresh_token_consume(user_id, jti)
    if not consumed:
        await _audit(
            db,
            uuid.UUID(user_id) if user_id else None,
            "auth.refresh.reuse_detected",
            request=request,
        )
        logger.warning("Refresh token reuse detected for user=%s", user_id)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has already been used",
        )

    result = await db.execute(select(User).where(User.id == uuid.UUID(user_id)))
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or deactivated",
        )

    token_data = {"sub": str(user.id)}
    new_refresh, new_jti = create_refresh_token(token_data)
    await refresh_token_register(str(user.id), new_jti)

    await _audit(db, user.id, "auth.refresh.success", request=request)
    return {
        "access_token": create_access_token(token_data),
        "refresh_token": new_refresh,
        "token_type": "bearer",
    }


@router.get("/me", response_model=UserResponse)
async def get_me(user: User = Depends(get_current_user)) -> User:
    """Get the currently authenticated user's profile."""
    return user


@router.patch("/me", response_model=UserResponse)
async def update_me(
    body: UserUpdateRequest,
    request: Request,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Update the caller's own profile (full_name and/or password)."""
    changed: list[str] = []

    if body.full_name is not None:
        user.full_name = body.full_name
        changed.append("full_name")

    if body.password is not None:
        user.hashed_password = hash_password(body.password)
        changed.append("credential")

    if changed:
        db.add(user)
        await db.flush()
        await db.refresh(user)
        await _audit(
            db,
            user.id,
            "auth.profile.update",
            request=request,
            detail=",".join(changed),
        )
        logger.info(
            "Profile updated: user=%s fields=%s",
            user.id,
            ",".join(changed),
            extra={"user_id": str(user.id)},
        )

    return user


__all__ = ["router", "settings"]

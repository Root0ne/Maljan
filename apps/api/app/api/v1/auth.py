"""Authentication endpoints — register, login, refresh, me.

Hardening applied:
    * AuditLog entries on register / login / refresh / failure.
    * Per-account brute-force throttle backed by Redis. When Redis is down,
      refresh-token consumption fails closed (no refresh is honoured) while
      the login lock stays a no-op (failing closed there would lock every
      account for the outage) — see ``app.auth.throttle``.
    * Refresh-token rotation with reuse detection — each refresh issues a
      new ``jti`` and invalidates the previous one. Re-using a previously
      rotated token logs an audit event and forces re-authentication.
"""

from __future__ import annotations

import hashlib
import uuid

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import observability
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
from app.database import async_session_factory, get_db
from app.deps import get_current_user
from app.logging_config import get_logger
from app.models.audit import AuditLog
from app.models.user import User
from app.schemas.auth import (
    TokenResponse,
    UserLoginRequest,
    UserRegisterRequest,
    UserResponse,
    UserUpdateRequest,
)

logger = get_logger("api.auth")

router = APIRouter(prefix="/auth", tags=["Authentication"])

REFRESH_COOKIE = "maljan_refresh"
REFRESH_COOKIE_PATH = "/api/v1/auth"


def _set_refresh_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        REFRESH_COOKIE,
        token,
        httponly=True,
        samesite="lax",
        secure=bool(settings.cookie_secure),
        path=REFRESH_COOKIE_PATH,
        max_age=settings.jwt_refresh_token_expire_days * 86400,
    )


def _clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(REFRESH_COOKIE, path=REFRESH_COOKIE_PATH)


def _email_tag(email: str) -> str:
    """A short, stable stand-in for an e-mail address in log lines."""
    return hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()[:12]


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
    """Persist an auth audit row on an INDEPENDENT transaction.

    Audit 2026-07-26 (K1): this used to ``db.add()`` on the request-scoped
    session, which only commits when the endpoint returns successfully
    (``database.get_db``). Every audit row written on a failure path was
    therefore rolled back with the ``HTTPException`` — verified live: after a
    failed login the table contained only ``auth.login.success`` and
    ``auth.register`` rows. That silently discarded exactly the
    security-relevant events: ``login.failure`` (brute force),
    ``login.locked``, ``login.blocked_inactive``, ``refresh.invalid`` and
    ``refresh.reuse_detected`` (a token-theft indicator).

    Writing on a separate session decouples the audit record from the request
    transaction's fate, so it survives the rollback. Best-effort by design: an
    audit failure must never turn a handled 401 into a 500, so every error is
    logged at ERROR and counted for operator visibility. ``db`` is kept in the
    signature for call-site compatibility and is deliberately unused.
    """
    del db  # audit rows must not share the request transaction (see docstring)
    try:
        async with async_session_factory() as audit_session:
            audit_session.add(
                AuditLog(
                    user_id=user_id,
                    action=action,
                    resource_type="auth",
                    resource_id=str(user_id) if user_id else None,
                    details={"detail": detail} if detail else None,
                    ip_address=_client_ip(request) or None,
                )
            )
            await audit_session.commit()
    except Exception as exc:  # noqa: BLE001 - audit is best effort, but never silent
        observability.counters.audit_write_failures += 1
        logger.error("Audit write failed (action=%s): %s", action, type(exc).__name__)


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(
    body: UserRegisterRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> User:
    """Register a new user account."""
    logger.info("Registration attempt: email_hash=%s", _email_tag(body.email))

    result = await db.execute(select(User).where(User.email == body.email))
    if result.scalar_one_or_none():
        logger.warning(
            "Registration failed: email already exists - email_hash=%s",
            _email_tag(body.email),
        )
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
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Authenticate and receive JWT tokens."""
    logger.info("Login attempt: email_hash=%s", _email_tag(body.email))

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
            "Login failed: invalid credentials for email_hash=%s",
            _email_tag(body.email),
            extra={"component": "auth"},
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
    _set_refresh_cookie(response, refresh)

    await _audit(db, user.id, "auth.login.success", request=request)
    logger.info("Login successful: user=%s", user.id, extra={"user_id": str(user.id)})
    return {
        "access_token": create_access_token(token_data),
        "token_type": "bearer",
    }


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
    maljan_refresh: str | None = Cookie(default=None),
) -> dict | Response:
    """Exchange the refresh cookie for a new access token and rotate it.

    Implements rotation + reuse detection: if the same refresh token is used
    twice, all of that user's refresh tokens are invalidated and the request
    is rejected with 401.
    """
    if not maljan_refresh:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="No refresh session")

    payload = decode_token(maljan_refresh)
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
        from app.auth.throttle import throttle_state

        if not throttle_state()["available"]:
            await _audit(db, None, "auth.refresh.store_unavailable", request=request)
            logger.warning("Refresh rejected: session store unavailable.")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session could not be refreshed; sign in again.",
            )
        await _audit(
            db,
            uuid.UUID(user_id) if user_id else None,
            "auth.refresh.reuse_detected",
            request=request,
        )
        logger.warning("Refresh token reuse detected for user=%s", user_id)
        reuse_response = JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"detail": "Refresh token has already been used"},
        )
        _clear_refresh_cookie(reuse_response)
        return reuse_response

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
    _set_refresh_cookie(response, new_refresh)

    await _audit(db, user.id, "auth.refresh.success", request=request)
    return {
        "access_token": create_access_token(token_data),
        "token_type": "bearer",
    }


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    request: Request,
    db: AsyncSession = Depends(get_db),
    maljan_refresh: str | None = Cookie(default=None),
) -> Response:
    """Consume the refresh cookie's session, if any, and always clear it.

    A missing or already-consumed cookie is not an error: logout is
    idempotent so a client can call it defensively without checking state.
    """
    if maljan_refresh:
        payload = decode_token(maljan_refresh) or {}
        if payload.get("type") == "refresh":
            await refresh_token_consume(payload.get("sub"), payload.get("jti", ""))
            await _audit(
                db,
                uuid.UUID(payload["sub"]) if payload.get("sub") else None,
                "auth.logout",
                request=request,
            )
    out = Response(status_code=status.HTTP_204_NO_CONTENT)
    _clear_refresh_cookie(out)
    return out


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

"""Authentication endpoints — register, login, refresh, me.

Hardening applied:
    * AuditLog entries on register / login / refresh / failure.
    * Per-account brute-force throttle backed by Redis. When Redis is down,
      refresh-token consumption fails closed (no refresh is honoured) while
      the login lock stays a no-op (failing closed there would lock every
      account for the outage) — see ``app.auth.throttle``.
    * Refresh-token rotation with reuse detection — each refresh issues a
      new ``jti`` and invalidates the previous one. Re-using a previously
      rotated token revokes every session of the account (its token
      generation moves on), logs an audit event and forces re-authentication.
    * A password change needs the current password and a bearer session (an
      API key is refused), and revokes every earlier session and API key of
      the account.
"""

from __future__ import annotations

import hashlib
import hmac
import uuid

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.jwt import (
    client_fingerprint,
    create_access_token,
    create_refresh_token,
    decode_token,
    is_current_generation,
    session_claims,
)
from app.auth.password import hash_password, verify_password
from app.auth.revocation import revoke_api_keys, revoke_sessions
from app.auth.step_up import check_current_password
from app.auth.throttle import (
    clear_login_throttle,
    is_login_locked,
    record_login_failure,
    refresh_token_consume,
    refresh_token_grace,
    refresh_token_register,
    refresh_token_rotate,
    throttle_state,
)
from app.config import settings
from app.database import get_db
from app.deps import api_key_scheme, get_current_user, refuse_api_key_credential
from app.logging_config import get_logger
from app.middleware.rate_limit_middleware import request_client_ip
from app.models.user import User
from app.runtime_config import runtime_config
from app.schemas.auth import (
    TokenResponse,
    UserLoginRequest,
    UserRegisterRequest,
    UserResponse,
    UserUpdateRequest,
    UserUpdateResponse,
)
from app.services import audit

logger = get_logger("api.auth")

router = APIRouter(prefix="/auth", tags=["Authentication"])

REFRESH_COOKIE = "maljan_refresh"
REFRESH_COOKIE_PATH = "/api/v1/auth"


def _set_refresh_cookie(response: Response, token: str, refresh_days: int) -> None:
    # ``refresh_days`` is passed in explicitly rather than read from
    # ``runtime_config`` here, so this function has no hidden dependency on
    # a caller having awaited a settings read first — the caller (``login``
    # / ``refresh_token`` below) already has the value, from the same
    # ``await runtime_config.get(...)`` it used to warm ``create_refresh_token``'s
    # cache.
    response.set_cookie(
        REFRESH_COOKIE,
        token,
        httponly=True,
        samesite="lax",
        secure=bool(settings.cookie_secure),
        path=REFRESH_COOKIE_PATH,
        max_age=refresh_days * 86400,
    )


def _clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(
        REFRESH_COOKIE,
        path=REFRESH_COOKIE_PATH,
        httponly=True,
        samesite="lax",
        secure=bool(settings.cookie_secure),
    )


def _email_tag(email: str) -> str:
    """A short, stable stand-in for an e-mail address in log lines."""
    return hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()[:12]


def _client_ip(request: Request) -> str:
    return getattr(getattr(request, "client", None), "host", "") or ""


def _subject_uuid(subject: object) -> uuid.UUID | None:
    """A token's ``sub`` as a user id, or ``None`` when it is not one."""
    try:
        return uuid.UUID(str(subject)) if subject else None
    except ValueError:
        return None


def _refresh_refused(detail: str) -> JSONResponse:
    """A 401 for a refresh that must not be honoured, clearing the cookie."""
    refused = JSONResponse(status_code=status.HTTP_401_UNAUTHORIZED, content={"detail": detail})
    _clear_refresh_cookie(refused)
    return refused


async def _audit(
    db: AsyncSession,
    user_id: uuid.UUID | None,
    action: str,
    *,
    request: Request,
    detail: str | None = None,
) -> None:
    """Persist an auth audit row on an INDEPENDENT transaction.

    This used to ``db.add()`` on the request-scoped
    session, which only commits when the endpoint returns successfully
    (``database.get_db``). Every audit row written on a failure path was
    therefore rolled back with the ``HTTPException`` — verified live: after a
    failed login the table contained only ``auth.login.success`` and
    ``auth.register`` rows. That silently discarded exactly the
    security-relevant events: ``login.failure`` (brute force),
    ``login.locked``, ``login.blocked_inactive``, ``refresh.invalid`` and
    ``refresh.reuse_detected`` (a token-theft indicator).

    The independent-session write itself lives in ``services.audit.record``,
    which the sample, job and sandbox-report endpoints share. What stays here
    is this endpoint's own shape of a row. ``db`` is kept in the signature for
    call-site compatibility and is deliberately unused.
    """
    del db  # audit rows must not share the request transaction (see docstring)
    await audit.record(
        action,
        resource_type="auth",
        resource_id=str(user_id) if user_id else None,
        user_id=user_id,
        details={"detail": detail} if detail else None,
        request=request,
    )


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
        logger.warning(  # nosemgrep: python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure — email_hash is a one-way hash, not the credential  # noqa: E501
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

    # create_access_token / create_refresh_token stay synchronous (see their
    # docstrings in app.auth.jwt) and read expiries via get_cached() instead
    # of awaiting; this route does the one settings read that keeps that
    # cache warm before minting.
    await runtime_config.get("jwt_access_token_expire_minutes")
    refresh_days = await runtime_config.get("jwt_refresh_token_expire_days")

    token_data = session_claims(user)
    refresh, jti = create_refresh_token(token_data)
    await refresh_token_register(str(user.id), jti)
    _set_refresh_cookie(response, refresh, refresh_days)

    await _audit(db, user.id, "auth.login.success", request=request)
    logger.info("Login successful: user=%s", user.id, extra={"user_id": str(user.id)})
    return {
        "access_token": create_access_token(token_data),
        "token_type": "bearer",
    }


async def _store_unavailable(db: AsyncSession, request: Request) -> JSONResponse:
    """A 401 for a refresh the session store could not decide; nothing revoked."""
    await _audit(db, None, "auth.refresh.store_unavailable", request=request)
    logger.warning("Refresh rejected: session store unavailable.")
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={"detail": "Session could not be refreshed; sign in again."},
    )


async def _revoke_for_reuse(
    db: AsyncSession,
    request: Request,
    user: User | None,
    user_uuid: uuid.UUID | None,
    reason: str,
) -> JSONResponse:
    """Revoke every session and key of the account for a replayed refresh token."""
    await _audit(db, user_uuid, "auth.refresh.reuse_detected", request=request, detail=reason)
    logger.warning(  # nosemgrep: python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure — user_id is an opaque UUID, not the refresh token  # noqa: E501
        "Refresh token reuse detected for user=%s (%s); revoking every session of the account.",
        user_uuid,
        reason,
    )
    if user is not None:
        # A replayed token means two holders of one family: retire every
        # access and refresh token and every API key of the account (keys are
        # bound to the generation), and commit before the refusal leaves so
        # the revocation cannot be lost with it.
        await revoke_sessions(db, user.id)
        await db.commit()
        await audit.record(
            "auth.sessions.revoked",
            resource_type="auth",
            resource_id=str(user.id),
            user_id=user.id,
            details={"reason": reason},
            request=request,
        )
    return _refresh_refused("Refresh token has already been used")


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
    maljan_refresh: str | None = Cookie(default=None),
) -> dict | Response:
    """Exchange the refresh cookie for a new access token and rotate it.

    Implements rotation + reuse detection: if the same refresh token is used
    twice, the account's token generation moves on, which revokes every
    access and refresh token of that user, the revocation is audited, and the
    request is rejected with 401. The jti is consumed and its grace record
    (a keyed hash of the client) written in one atomic step; a second use
    inside ``refresh_reuse_grace_seconds`` from the same client is refused
    without revoking anything or touching the cookie, from another client it
    revokes as above; both are audited as ``auth.refresh.reuse_in_grace`` with
    ``fingerprint_match``. A token minted under an earlier generation is
    refused as revoked without moving the generation again.
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
    fingerprint = client_fingerprint(
        await request_client_ip(request), request.headers.get("user-agent", "")
    )
    # Consume and open the grace window in one atomic step (see
    # ``throttle.ROTATE_SCRIPT``).
    consumed = await refresh_token_rotate(user_id, jti, fingerprint)
    if not consumed and not throttle_state()["available"]:
        return await _store_unavailable(db, request)

    user_uuid = _subject_uuid(user_id)
    user: User | None = None
    if user_uuid is not None:
        result = await db.execute(select(User).where(User.id == user_uuid))
        user = result.scalar_one_or_none()

    if user is not None and not is_current_generation(payload, user):
        # Minted before the account's last password change or replay: already
        # revoked. Not a fresh replay, so the current sessions are left alone.
        await _audit(db, user.id, "auth.refresh.revoked", request=request)
        return _refresh_refused("Refresh token has been revoked")

    if not consumed:
        grace = await refresh_token_grace(user_id, jti)
        if not grace.readable:
            # The grace record could not be read: not a verdict on the token.
            return await _store_unavailable(db, request)
        reason = "refresh_reuse"
        if grace.fingerprint is not None:
            # Used again within ``refresh_reuse_grace_seconds`` of its rotation.
            match = hmac.compare_digest(grace.fingerprint, fingerprint)
            await audit.record(
                "auth.refresh.reuse_in_grace",
                resource_type="auth",
                resource_id=str(user_uuid) if user_uuid else None,
                user_id=user_uuid,
                details={"fingerprint_match": match},
                request=request,
            )
            if match:
                # The client that rotated it: a retry or a second tab. Refused,
                # nothing revoked, cookie left alone so the browser keeps the
                # successor the first use set. No fresh pair: another client
                # behind the same address and user agent would get a session.
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={"detail": "Refresh token was just rotated; use the current session."},
                )
            reason = "refresh_reuse_other_client"
        return await _revoke_for_reuse(db, request, user, user_uuid, reason)

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or deactivated",
        )

    await runtime_config.get("jwt_access_token_expire_minutes")
    refresh_days = await runtime_config.get("jwt_refresh_token_expire_days")

    token_data = session_claims(user)
    new_refresh, new_jti = create_refresh_token(token_data)
    await refresh_token_register(str(user.id), new_jti)
    _set_refresh_cookie(response, new_refresh, refresh_days)

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


async def _consume_callers_refresh(user: User, maljan_refresh: str | None) -> None:
    """Consume the caller's own refresh token, if it is this account's.

    The generation bump already refuses it; consuming it as well removes it
    from the store now rather than at its expiry, and opens no grace window.
    """
    if not maljan_refresh:
        return
    payload = decode_token(maljan_refresh) or {}
    if payload.get("type") == "refresh" and payload.get("sub") == str(user.id):
        await refresh_token_consume(str(user.id), payload.get("jti", ""))


@router.patch("/me", response_model=UserUpdateResponse)
async def update_me(
    body: UserUpdateRequest,
    request: Request,
    response: Response,
    user: User = Depends(get_current_user),
    api_key: str | None = Depends(api_key_scheme),
    db: AsyncSession = Depends(get_db),
    maljan_refresh: str | None = Cookie(default=None),
) -> UserUpdateResponse:
    """Update the caller's own profile (full_name and/or password).

    A password change takes a bearer session (an API key is refused) and the
    current password. It revokes every earlier access and refresh token and
    every API key of the account, commits that before anything else happens,
    and hands this session a replacement: the new access token in
    ``access_token``, the new refresh token as the cookie.
    """
    changed: list[str] = []
    credential_changed = body.password is not None

    # Every refusal comes before any change, so a refused password change
    # leaves the name untouched too.
    if credential_changed:
        refuse_api_key_credential(api_key)
        await check_current_password(
            user, body.current_password, request=request, action="auth.credential.change"
        )

    if body.full_name is not None:
        user.full_name = body.full_name
        changed.append("full_name")

    if body.password is not None:
        user.hashed_password = hash_password(body.password)
        changed.append("credential")

    access_token: str | None = None
    if changed:
        db.add(user)
        await db.flush()
        revoked_keys = 0
        if credential_changed:
            await revoke_sessions(db, user.id)
            revoked_keys = await revoke_api_keys(db, user.id)
        await db.refresh(user)
        # Committed before any token is minted, cookie set or audit row
        # written: ``get_db`` would commit only after the response is sent, so
        # a failed commit there would leave the caller holding tokens of a
        # generation the database never reached, and the old ones still valid.
        await db.commit()
        if credential_changed:
            await _consume_callers_refresh(user, maljan_refresh)
            await clear_login_throttle(user.email)
            await runtime_config.get("jwt_access_token_expire_minutes")
            refresh_days = await runtime_config.get("jwt_refresh_token_expire_days")
            token_data = session_claims(user)
            new_refresh, new_jti = create_refresh_token(token_data)
            await refresh_token_register(str(user.id), new_jti)
            _set_refresh_cookie(response, new_refresh, refresh_days)
            access_token = create_access_token(token_data)
            await audit.record(
                "auth.sessions.revoked",
                resource_type="auth",
                resource_id=str(user.id),
                user_id=user.id,
                details={"reason": "credential_change", "api_keys_revoked": revoked_keys},
                request=request,
            )
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

    profile = UserUpdateResponse.model_validate(user)
    return profile.model_copy(update={"access_token": access_token})


__all__ = ["router", "settings"]

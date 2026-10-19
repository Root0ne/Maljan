"""Step-up: the current password, asked again before a credential-minting action.

An access token alone, stolen or left open, must not change the password or
mint an API key: both outlive the token. ``check_current_password`` asks for
the password again, and a wrong answer counts against the same per-account
lock as a failed login, so the step-up cannot be used to guess the password.
"""

from __future__ import annotations

from fastapi import HTTPException, Request, status

from app.auth.password import verify_password
from app.auth.throttle import is_login_locked, record_login_failure
from app.models.user import User
from app.services import audit

WRONG_CURRENT_PASSWORD = "Current password is incorrect"


async def check_current_password(
    user: User, current_password: str | None, *, request: Request, action: str
) -> None:
    """Refuse unless ``current_password`` verifies for ``user``.

    ``action`` names the audited step (``auth.credential.change``,
    ``api_key.create``); a refusal is audited as ``<action>.locked`` or
    ``<action>.rejected``.
    """
    if await is_login_locked(user.email):
        await _audit(f"{action}.locked", user, request)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed password attempts. Try again later.",
        )
    if not current_password or not verify_password(current_password, user.hashed_password):
        await record_login_failure(user.email)
        await _audit(f"{action}.rejected", user, request)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=WRONG_CURRENT_PASSWORD)


async def _audit(action: str, user: User, request: Request) -> None:
    await audit.record(
        action,
        resource_type="auth",
        resource_id=str(user.id),
        user_id=user.id,
        request=request,
    )

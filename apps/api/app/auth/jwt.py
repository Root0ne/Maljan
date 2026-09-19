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


def read_moment(value: object) -> datetime | None:
    """An ISO-8601 moment as an aware ``datetime``, or ``None``.

    A naive value is read as UTC: an operator writing a date in a bootstrap
    file is writing the deployment's clock, and reading it as local time would
    move the wall by the container's timezone. A date with no time is that
    day's midnight.

    Unparseable text gives ``None`` rather than raising — the setting is plain
    text precisely so that nothing here can fail at import — and
    ``app.bootstrap`` is what tells the operator their moment did not read.
    """
    if isinstance(value, datetime):
        moment = value
    else:
        text = str(value or "").strip()
        if not text:
            return None
        try:
            moment = datetime.fromisoformat(text)
        except ValueError:
            return None
    return moment if moment.tzinfo is not None else moment.replace(tzinfo=UTC)


def grace_secret_not_after() -> datetime | None:
    """When the grace secret stops being accepted, as an aware moment."""
    return read_moment(getattr(settings, "jwt_previous_secret_not_after", None))


def grace_secret_configured() -> bool:
    """Whether a previous signing secret is set at all.

    The one place that looks at its value, and only to ask whether there is
    one: a bool is what leaves here, and a bool is what every sentence about a
    rotation is built from. Anything that read the secret for itself and then
    handed out a dict would make every field of that dict something a reader —
    or a scanner following the flow — has to trace back to the box before it
    can say nothing escaped.
    """
    raw = getattr(settings, "jwt_previous_secret_key", None)
    secret = raw.get_secret_value() if isinstance(raw, SecretStr) else str(raw or "")
    return bool(secret)


def grace_secret_is_live(now: datetime | None = None) -> bool:
    """Whether a grace secret is configured and still accepted.

    A window with no end is open. Only a moment somebody wrote down is
    enforced: a deployment halfway through a rotation when this setting
    arrived has the previous secret set and nothing else, and refusing that
    secret would log out every session minted before the rotation — an upgrade
    that breaks a running deployment, quietly. ``bootstrap`` says so out loud
    at every start instead, and ``/system/status`` says the window is
    unbounded.

    Strictly before the moment, so a token is refused at it as well as after.
    """
    if not grace_secret_configured():
        return False
    # A moment that did not read is no moment. It is a bootstrap problem, so
    # the operator is told; it is not a reason to stop honouring a secret they
    # meant to keep honouring for a while longer.
    not_after = grace_secret_not_after()
    if not_after is None:
        return True
    return (now or datetime.now(UTC)) < not_after


def _previous_secret() -> str:
    """The previous secret while its window is open, else empty string.

    During a key rotation the previous secret is kept as a fallback in
    ``decode_token`` so tokens minted before the rotation stay valid until
    they expire. The window has a written end: past
    ``jwt_previous_secret_not_after`` the old secret signs nothing this API
    accepts, so an operator who forgets to clear it is not running a
    deployment where a retired key is honoured for good. A secret configured
    with no end has no window to be past, and is accepted as it was before
    the setting existed.
    """
    if not grace_secret_is_live():
        return ""
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

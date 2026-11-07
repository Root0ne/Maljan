"""The first admin account, created or promoted from the command line.

No endpoint grants or changes a role; a registration gets ``analyst``. The
first admin therefore comes from someone with access to the database, and
``malspark create-admin`` is that access with the API's own models, password
hashing and database settings rather than a hand-written ``UPDATE``.

The password is read only when an account is created, held as a
:class:`~pydantic.SecretStr` until it is hashed, and never logged or echoed:
a traceback that prints a frame's locals shows the mask, not the text. The
command's own engine never echoes SQL and keeps statement parameters out of
its errors, so ``SQL_ECHO`` does not put the new hash in a log either.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal

from annotated_types import MaxLen, MinLen
from pydantic import EmailStr, SecretStr, TypeAdapter, ValidationError
from sqlalchemy import func, select
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.auth.password import hash_password
from app.database import end_read_transaction
from app.models.user import User, UserRole
from app.schemas.auth import UserRegisterRequest
from app.services import audit

GRANT_ACTION = "auth.role.grant"

_EMAIL = TypeAdapter(EmailStr)


class AdminAccountRefused(Exception):
    """A refusal the command prints as it is, with nothing of the database's own text."""


@dataclass(frozen=True)
class AdminGrant:
    """What the command did to the account."""

    outcome: Literal["created", "promoted", "already_admin"]
    user_id: uuid.UUID
    email: str
    is_active: bool


def _password_bounds() -> tuple[int, int]:
    """The registration's own length rule for a password, read from its schema."""
    metadata = UserRegisterRequest.model_fields["password"].metadata
    low = next(m.min_length for m in metadata if isinstance(m, MinLen))
    high = next(m.max_length for m in metadata if isinstance(m, MaxLen))
    return low, high


def checked_email(email: str) -> str:
    """``email`` as a registration stores it, or a refusal naming why it is not one."""
    try:
        return str(_EMAIL.validate_python(email))
    except ValidationError as exc:
        reason = exc.errors()[0].get("msg", "not an e-mail address")
        raise AdminAccountRefused(f"{email!r} is not a valid e-mail address: {reason}") from None


def checked_password(password: SecretStr) -> SecretStr:
    """``password`` when a registration would accept it; the refusal never quotes it."""
    low, high = _password_bounds()
    if not low <= len(password.get_secret_value()) <= high:
        raise AdminAccountRefused(f"The password must be {low} to {high} characters long.")
    return password


def checked_full_name(full_name: str) -> str:
    """``full_name`` when a registration would accept it."""
    field = UserRegisterRequest.model_fields["full_name"]
    high = next(m.max_length for m in field.metadata if isinstance(m, MaxLen))
    name = full_name.strip()
    if not 1 <= len(name) <= high:
        raise AdminAccountRefused(f"The full name must be 1 to {high} characters long.")
    return name


async def grant_admin(
    session: AsyncSession,
    *,
    email: str,
    full_name: str,
    password: Callable[[], SecretStr],
) -> AdminGrant:
    """Make the account behind ``email`` an admin, creating it when there is none.

    ``password`` is asked only for an account that does not exist yet; an
    existing account keeps its password. Promoting an admin changes nothing.
    The caller commits.
    """
    address = checked_email(email)
    user = await _account(session, address)
    if user is not None:
        address = user.email
        if user.role == UserRole.ADMIN:
            return AdminGrant("already_admin", user.id, address, user.is_active)
        user.role = UserRole.ADMIN
        await session.flush()
        return AdminGrant("promoted", user.id, address, user.is_active)

    name = checked_full_name(full_name)
    # Nobody waits on a person typing a password with a transaction open.
    await end_read_transaction(session)
    secret = checked_password(password())
    user = User(
        email=address,
        hashed_password=hash_password(secret.get_secret_value()),
        full_name=name,
        role=UserRole.ADMIN,
        is_active=True,
    )
    session.add(user)
    try:
        await session.flush()
    except IntegrityError:
        raise AdminAccountRefused(
            f"{address} was registered while the password was asked for; "
            "run the command again to promote it."
        ) from None
    return AdminGrant("created", user.id, address, True)


async def _account(session: AsyncSession, address: str) -> User | None:
    """The account ``address`` names: its exact row, else the one row equal ignoring case.

    Sign-in compares the address exactly, so an exact row wins; an operator who
    typed the stored address in another case means that account, not a second
    one beside it. Two rows equal ignoring case are not chosen between.
    """
    exact = (await session.execute(select(User).where(User.email == address))).scalar_one_or_none()
    if exact is not None:
        return exact
    rows = (
        (await session.execute(select(User).where(func.lower(User.email) == address.lower())))
        .scalars()
        .all()
    )
    if len(rows) > 1:
        raise AdminAccountRefused(
            f"{len(rows)} accounts match {address} ignoring case; give the address exactly as "
            "it is stored."
        )
    return rows[0] if rows else None


def database_state(connection: Any) -> str:
    """The migration state of a synchronous connection (``head``, ``behind``, ``ahead``)."""
    from app.services.migration_state import revision_state

    return revision_state(connection)


def _where(engine: AsyncEngine) -> str:
    """The database's host, port and name: what an operator needs, without the password."""
    url = make_url(str(engine.url))
    host = url.host or "localhost"
    port = f":{url.port}" if url.port else ""
    return f"{host}{port}/{url.database or ''}"


async def check_database(engine: AsyncEngine) -> None:
    """Refuse unless the database answers and carries every migration of this release."""
    try:
        async with engine.connect() as connection:
            state = await connection.run_sync(database_state)
    except Exception as exc:  # noqa: BLE001 — a driver's text may carry the DSN
        raise AdminAccountRefused(
            f"The database at {_where(engine)} could not be reached ({type(exc).__name__}). "
            "Check that it is running and that DATABASE_URL names it."
        ) from None
    if state == "behind":
        raise AdminAccountRefused(
            f"The database at {_where(engine)} lacks this release's migrations. "
            "Apply them first (make migrate, or the compose stack's migrate service)."
        )
    if state == "ahead":
        raise AdminAccountRefused(
            f"The database at {_where(engine)} was migrated by a later release; "
            "run that release's command instead."
        )


async def create_admin(
    *,
    email: str,
    full_name: str,
    password: Callable[[], SecretStr],
    engine: AsyncEngine | None = None,
) -> AdminGrant:
    """Check the database, then create or promote the admin and record it in the audit log.

    Without ``engine`` the command opens its own on the API's ``DATABASE_URL``,
    with SQL echo off and statement parameters hidden, and closes it.
    """
    own = engine is None
    if engine is None:
        from app.config import settings

        engine = create_async_engine(settings.database_url, echo=False, hide_parameters=True)
    try:
        await check_database(engine)
        sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with sessions() as session:
            grant = await grant_admin(session, email=email, full_name=full_name, password=password)
            await session.commit()
    finally:
        if own:
            await engine.dispose()
    if grant.outcome != "already_admin":
        # The actor column is empty, as for every event no signed-in account
        # caused; the account the grant is about is the resource.
        await audit.record(
            GRANT_ACTION,
            resource_type="auth",
            resource_id=str(grant.user_id),
            details={"role": UserRole.ADMIN.value, "by": "command line", "outcome": grant.outcome},
        )
    return grant

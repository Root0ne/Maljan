"""``malspark create-admin`` makes the first admin without a hand-written ``UPDATE``.

No endpoint grants ``admin``, so the first one used to be promoted in the
database by SQL. The command creates the account or promotes an existing one
through the API's own model and password hashing, asks for a new account's
password only (never from an argument, never echoed), changes nothing for an
admin, and refuses with a plain sentence when the database cannot be reached
or lacks a migration.

The ORM runs on an in-memory SQLite engine behind a thin async adapter (the
driver the API uses needs a server); the migration check reads a real
SQLite connection, and the unreachable database is a refused local port.
"""

from __future__ import annotations

import asyncio
import getpass
import sys
import uuid
from collections.abc import Callable
from typing import Any

import click
import pytest
import typer
from pydantic import SecretStr
from sqlalchemy import create_engine, text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool
from typer.testing import CliRunner

from app.auth.password import verify_password
from app.models.user import User, UserRole
from app.services import admin_account
from app.services.admin_account import (
    GRANT_ACTION,
    AdminAccountRefused,
    AdminGrant,
    check_database,
    create_admin,
    database_state,
    grant_admin,
)
from app.services.migration_state import head_revisions
from malspark import cli

PASSWORD = "correct horse battery"


class _AsyncSessionOverSync:
    """The ``AsyncSession`` methods the command awaits, over a sync session."""

    def __init__(self, session: Session) -> None:
        self._session = session

    async def __aenter__(self) -> _AsyncSessionOverSync:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        self._session.rollback()

    async def execute(self, statement: Any) -> Any:
        return self._session.execute(statement)

    def add(self, row: Any) -> None:
        self._session.add(row)

    async def flush(self) -> None:
        self._session.flush()

    async def commit(self) -> None:
        self._session.commit()


@pytest.fixture
def session() -> Session:
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    User.__table__.create(engine)
    with Session(engine, expire_on_commit=False) as sync_session:
        yield sync_session


def _user(session: Session, role: UserRole, *, active: bool = True) -> User:
    user = User(
        email="first@example.com",
        hashed_password="kept-hash",
        full_name="First",
        role=role,
        is_active=active,
    )
    session.add(user)
    session.commit()
    return user


def _grant(session: Session, password: Callable[[], SecretStr], email: str = "first@example.com"):
    return asyncio.run(
        grant_admin(
            _AsyncSessionOverSync(session),  # type: ignore[arg-type]
            email=email,
            full_name="Administrator",
            password=password,
        )
    )


def _never() -> SecretStr:
    raise AssertionError("the password was asked for an account that exists")


def test_a_new_account_is_created_as_admin_with_the_password_hashed(session: Session) -> None:
    grant = _grant(session, lambda: SecretStr(PASSWORD))
    session.commit()

    assert grant.outcome == "created" and grant.is_active
    user = session.query(User).one()
    assert user.role == UserRole.ADMIN and user.is_active
    assert user.hashed_password != PASSWORD and verify_password(PASSWORD, user.hashed_password)
    # The role column holds the enum's name, as the migrations write it.
    assert session.execute(text("SELECT role FROM users")).scalar_one() == "ADMIN"


def test_an_existing_account_is_promoted_and_keeps_its_password(session: Session) -> None:
    _user(session, UserRole.ANALYST)
    grant = _grant(session, _never)
    session.commit()

    assert grant.outcome == "promoted"
    user = session.query(User).one()
    assert user.role == UserRole.ADMIN and user.hashed_password == "kept-hash"


def test_promoting_an_admin_changes_nothing(session: Session) -> None:
    user = _user(session, UserRole.ADMIN)
    before = user.updated_at
    grant = _grant(session, _never)

    assert grant.outcome == "already_admin"
    assert not session.dirty and not session.new
    assert session.query(User).one().updated_at == before


def test_a_deactivated_account_is_promoted_and_said_to_be_deactivated(session: Session) -> None:
    _user(session, UserRole.ANALYST, active=False)
    grant = _grant(session, _never)
    assert grant.outcome == "promoted" and grant.is_active is False


def test_a_password_the_registration_refuses_is_refused_without_quoting_it(
    session: Session,
) -> None:
    with pytest.raises(AdminAccountRefused) as refused:
        _grant(session, lambda: SecretStr("short"))
    assert "8 to 128 characters" in str(refused.value)
    assert "short" not in str(refused.value)
    assert session.query(User).count() == 0


def test_an_address_that_is_not_one_is_refused(session: Session) -> None:
    with pytest.raises(AdminAccountRefused, match="not a valid e-mail address"):
        _grant(session, _never, email="not-an-address")


def test_the_stored_account_is_promoted_whatever_case_the_address_is_typed_in(
    session: Session,
) -> None:
    user = _user(session, UserRole.ANALYST)
    user.email = "First@example.com"
    session.commit()

    grant = _grant(session, _never, email="  FIRST@EXAMPLE.COM ")
    session.commit()

    assert grant.outcome == "promoted" and grant.email == "First@example.com"
    assert session.query(User).count() == 1
    assert session.query(User).one().role == UserRole.ADMIN


def test_two_accounts_equal_ignoring_case_are_not_chosen_between(session: Session) -> None:
    for address in ("First@example.com", "FIRST@example.com"):
        session.add(User(email=address, hashed_password="h", full_name="F"))
    session.commit()

    with pytest.raises(AdminAccountRefused, match="give the address exactly"):
        _grant(session, _never, email="first@example.com")
    assert _grant(session, _never, email="FIRST@example.com").outcome == "promoted"


def test_an_address_registered_while_the_password_is_asked_for_is_refused(
    session: Session,
) -> None:
    def registered_meanwhile() -> SecretStr:
        with Session(session.get_bind()) as other:
            other.add(User(email="first@example.com", hashed_password="h", full_name="F"))
            other.commit()
        return SecretStr(PASSWORD)

    with pytest.raises(AdminAccountRefused, match="run the command again to promote it"):
        _grant(session, registered_meanwhile)
    session.rollback()
    assert session.query(User).one().role == UserRole.ANALYST


def test_the_command_s_engine_echoes_no_sql_and_hides_parameters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opened: list[dict[str, Any]] = []
    disposed: list[bool] = []

    class _Engine:
        async def dispose(self) -> None:
            disposed.append(True)

    def engine(url: str, **kwargs: Any) -> _Engine:
        opened.append(kwargs)
        return _Engine()

    async def refuse(_engine: Any) -> None:
        raise AdminAccountRefused("stop here")

    monkeypatch.setattr(admin_account, "create_async_engine", engine)
    monkeypatch.setattr(admin_account, "check_database", refuse)
    with pytest.raises(AdminAccountRefused):
        asyncio.run(create_admin(email="a@example.com", full_name="A", password=_never))
    assert opened == [{"echo": False, "hide_parameters": True}]
    assert disposed == [True]


def test_a_database_without_this_release_s_migrations_is_named_behind() -> None:
    engine = create_engine("sqlite://")
    with engine.connect() as connection:
        assert database_state(connection) == "behind"
        connection.execute(text("CREATE TABLE alembic_version (version_num VARCHAR(32))"))
        for head in head_revisions():
            connection.execute(text("INSERT INTO alembic_version VALUES (:v)"), {"v": head})
        assert database_state(connection) == "head"
        connection.execute(text("DELETE FROM alembic_version"))
        connection.execute(text("INSERT INTO alembic_version VALUES ('ffffffffffff')"))
        assert database_state(connection) == "ahead"


def test_an_unreachable_database_is_refused_without_its_password() -> None:
    engine = create_async_engine("postgresql+asyncpg://malspark:s3cret-pw@127.0.0.1:1/malspark")

    async def check() -> None:
        try:
            await check_database(engine)
        finally:
            await engine.dispose()

    with pytest.raises(AdminAccountRefused) as refused:
        asyncio.run(check())
    message = str(refused.value)
    assert "could not be reached" in message and "127.0.0.1:1/malspark" in message
    assert "s3cret-pw" not in message


@pytest.mark.parametrize(
    ("state", "says"), [("behind", "make migrate"), ("ahead", "later release")]
)
def test_a_database_not_at_head_is_refused(
    monkeypatch: pytest.MonkeyPatch, state: str, says: str
) -> None:
    class _Connection:
        async def run_sync(self, _fn: Any) -> str:
            return state

    class _Connect:
        async def __aenter__(self) -> _Connection:
            return _Connection()

        async def __aexit__(self, *_exc: object) -> None:
            return None

    class _Engine:
        url = "postgresql+asyncpg://u:pw@db:5432/malspark"

        def connect(self) -> _Connect:
            return _Connect()

    with pytest.raises(AdminAccountRefused, match=says):
        asyncio.run(check_database(_Engine()))  # type: ignore[arg-type]


def test_a_grant_is_committed_and_recorded_in_the_audit_log(
    monkeypatch: pytest.MonkeyPatch, session: Session
) -> None:
    _user(session, UserRole.ANALYST)
    recorded: list[tuple[str, dict]] = []

    async def no_check(_engine: Any) -> None:
        return None

    async def record(action: str, **kwargs: Any) -> None:
        recorded.append((action, kwargs))

    monkeypatch.setattr(admin_account, "check_database", no_check)
    monkeypatch.setattr(
        admin_account,
        "async_sessionmaker",
        lambda *_a, **_k: lambda: _AsyncSessionOverSync(session),
    )
    monkeypatch.setattr(admin_account.audit, "record", record)

    def grant() -> AdminGrant:
        return asyncio.run(
            create_admin(
                email="first@example.com",
                full_name="x",
                password=_never,
                engine=object(),  # type: ignore[arg-type]
            )
        )

    assert grant().outcome == "promoted"
    session.expire_all()
    assert session.query(User).one().role == UserRole.ADMIN
    [(action, kwargs)] = recorded
    assert action == GRANT_ACTION and kwargs["details"]["outcome"] == "promoted"
    # No signed-in account did it: the actor is empty, the account is the resource.
    assert kwargs.get("user_id") is None
    assert kwargs["resource_id"] == str(session.query(User).one().id)
    # A no-op leaves the audit log alone.
    assert grant().outcome == "already_admin" and len(recorded) == 1


# ---------------------------------------------------------------------------
# The command
# ---------------------------------------------------------------------------


class _Command:
    """``create_admin`` in place of the database: it asks for the password, as a creation does."""

    def __init__(self) -> None:
        self.passwords: list[str] = []
        self.before_password: Callable[[], None] = lambda: None

    async def __call__(
        self, *, email: str, full_name: str, password: Callable[[], SecretStr]
    ) -> AdminGrant:
        if email == "boom@example.com":
            raise RuntimeError("DETAIL: postgresql://malspark:s3cret-pw@db/malspark")
        if email == "admin@example.com":
            return AdminGrant("already_admin", uuid.uuid4(), email, True)
        self.before_password()
        self.passwords.append(password().get_secret_value())
        return AdminGrant("created", uuid.uuid4(), email, True)


@pytest.fixture
def command(monkeypatch: pytest.MonkeyPatch) -> _Command:
    fake = _Command()
    monkeypatch.setattr(admin_account, "create_admin", fake)
    return fake


def _as_terminal(monkeypatch: pytest.MonkeyPatch) -> Callable[[], None]:
    """Standard input answering as a terminal, set inside the invocation (the runner swaps it)."""
    return lambda: monkeypatch.setattr(sys.stdin, "isatty", lambda: True)


def test_the_command_reads_the_password_from_standard_input(command: _Command) -> None:
    result = CliRunner().invoke(
        cli.app, ["create-admin", "new@example.com", "--password-stdin"], input=PASSWORD + "\n"
    )
    assert result.exit_code == 0, result.output
    assert command.passwords == [PASSWORD]
    assert "Created the admin account new@example.com." in result.output
    assert PASSWORD not in result.output


def test_the_command_takes_no_password_argument(command: _Command) -> None:
    result = CliRunner().invoke(cli.app, ["create-admin", "new@example.com", PASSWORD])
    assert result.exit_code != 0 and command.passwords == []
    result = CliRunner().invoke(cli.app, ["create-admin", "new@example.com", "--password", "x"])
    assert result.exit_code != 0 and command.passwords == []


def test_an_address_after_a_double_dash_is_an_argument(command: _Command) -> None:
    result = CliRunner().invoke(
        cli.app, ["create-admin", "--password-stdin", "--", "-new@example.com"], input=PASSWORD
    )
    assert result.exit_code == 0, result.output
    assert "Created the admin account -new@example.com." in result.output


def test_without_a_terminal_the_command_asks_for_password_stdin(command: _Command) -> None:
    result = CliRunner().invoke(cli.app, ["create-admin", "new@example.com"], input=PASSWORD)
    assert result.exit_code == 1
    assert "--password-stdin" in result.output and command.passwords == []


def test_on_a_terminal_the_password_is_asked_hidden_and_twice(
    monkeypatch: pytest.MonkeyPatch, command: _Command
) -> None:
    asked: list[dict[str, Any]] = []

    def prompt(text: str, **kwargs: Any) -> str:
        asked.append(kwargs)
        return PASSWORD

    monkeypatch.setattr(typer, "prompt", prompt)
    command.before_password = _as_terminal(monkeypatch)
    result = CliRunner().invoke(cli.app, ["create-admin", "new@example.com"])
    assert result.exit_code == 0, result.output
    assert asked == [{"hide_input": True, "confirmation_prompt": True}]
    assert command.passwords == [PASSWORD]


def test_password_stdin_typed_on_a_terminal_is_not_echoed(
    monkeypatch: pytest.MonkeyPatch, command: _Command
) -> None:
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": PASSWORD)
    command.before_password = _as_terminal(monkeypatch)
    result = CliRunner().invoke(cli.app, ["create-admin", "new@example.com", "--password-stdin"])
    assert result.exit_code == 0, result.output
    assert command.passwords == [PASSWORD] and PASSWORD not in result.output


def test_an_aborted_prompt_says_aborted(monkeypatch: pytest.MonkeyPatch, command: _Command) -> None:
    def prompt(*_a: Any, **_k: Any) -> str:
        raise click.exceptions.Abort()

    monkeypatch.setattr(typer, "prompt", prompt)
    command.before_password = _as_terminal(monkeypatch)
    result = CliRunner().invoke(cli.app, ["create-admin", "new@example.com"])
    assert result.exit_code == 1
    assert "Aborted." in result.output and "failed" not in result.output


def test_promoting_an_admin_is_a_no_op_the_command_says(command: _Command) -> None:
    result = CliRunner().invoke(cli.app, ["create-admin", "admin@example.com"])
    assert result.exit_code == 0
    assert "already an admin; nothing changed" in result.output


def test_an_unexpected_failure_names_its_type_only(command: _Command) -> None:
    result = CliRunner().invoke(cli.app, ["create-admin", "boom@example.com"])
    assert result.exit_code == 1
    assert "create-admin failed (RuntimeError)" in result.output
    assert "s3cret-pw" not in result.output

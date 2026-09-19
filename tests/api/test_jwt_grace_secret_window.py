"""A retired signing secret stops being accepted on a day somebody wrote down.

Rotation is two settings and a wait, and the wait is where it is forgotten: the
grace secret used to be accepted for the life of the deployment, so an old key
an operator meant to retire stayed a key that could mint sessions. The window
now has an end, the end is refused at startup if it is missing, and both the
status endpoint and the startup log say when it is.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock

import jwt as pyjwt
import pytest
from pydantic import SecretStr

from app.auth import jwt as auth_jwt
from app.config import settings
from app.main import log_jwt_rotation
from tests.credential_shapes import lowercase_base64_blob

NEW_SECRET = "new-" + lowercase_base64_blob()
OLD_SECRET = "old-" + lowercase_base64_blob()


def _state_of(rotating, not_after):
    """The status block for a deployment whose window ends at ``not_after``."""
    from app.api.v1.system import _grace_secret_state

    rotating(not_after)
    return _grace_secret_state()


def _token_signed_with(secret: str) -> str:
    return pyjwt.encode(
        {
            "sub": "someone",
            "type": "access",
            "exp": datetime.now(UTC) + timedelta(hours=1),
            "iss": settings.jwt_issuer,
            "aud": settings.jwt_audience,
        },
        secret,
        algorithm=settings.jwt_algorithm,
    )


@pytest.fixture
def rotating(monkeypatch: pytest.MonkeyPatch):
    """A deployment mid-rotation, with the window's end left to each test."""

    def _set(not_after: datetime | None) -> str:
        monkeypatch.setattr(settings, "jwt_secret_key", SecretStr(NEW_SECRET))
        monkeypatch.setattr(settings, "jwt_previous_secret_key", SecretStr(OLD_SECRET))
        monkeypatch.setattr(settings, "jwt_previous_key_id", "v0")
        monkeypatch.setattr(settings, "jwt_previous_secret_not_after", not_after)
        return _token_signed_with(OLD_SECRET)

    return _set


class TestTheWindow:
    def test_a_token_on_the_old_secret_is_accepted_inside_it(self, rotating) -> None:
        token = rotating(datetime.now(UTC) + timedelta(days=1))

        assert auth_jwt.decode_token(token) is not None

    def test_the_same_token_is_refused_once_the_moment_has_passed(self, rotating) -> None:
        token = rotating(datetime.now(UTC) - timedelta(seconds=1))

        assert auth_jwt.decode_token(token) is None

    def test_a_naive_moment_is_read_as_the_deployment_s_clock(self, rotating) -> None:
        """A date in a bootstrap file is UTC, not the container's timezone."""
        token = rotating(datetime.now(UTC).replace(tzinfo=None) + timedelta(days=1))

        assert auth_jwt.grace_secret_not_after().tzinfo is UTC
        assert auth_jwt.decode_token(token) is not None

    def test_the_current_secret_is_unaffected_by_a_lapsed_window(self, rotating) -> None:
        rotating(datetime.now(UTC) - timedelta(days=1))

        assert auth_jwt.decode_token(_token_signed_with(NEW_SECRET)) is not None

    def test_no_previous_secret_is_no_window_at_all(self, monkeypatch) -> None:
        monkeypatch.setattr(settings, "jwt_previous_secret_key", SecretStr(""))
        monkeypatch.setattr(settings, "jwt_previous_secret_not_after", None)

        assert auth_jwt.grace_secret_is_live() is False

    def test_a_token_is_refused_at_the_moment_as_well_as_after_it(self, rotating) -> None:
        """The boundary is strict: the window is open before the moment only."""
        moment = datetime.now(UTC) + timedelta(days=1)
        token = rotating(moment)

        assert auth_jwt.grace_secret_is_live(now=moment) is False
        assert auth_jwt.grace_secret_is_live(now=moment - timedelta(seconds=1)) is True
        assert auth_jwt.decode_token(token) is not None


class TestAnUpgradeChangesNothingForADeploymentMidRotation:
    """A grace secret with no end keeps the behaviour it had before the setting.

    An operator halfway through a rotation has the previous secret set and has
    never heard of the new timestamp. Refusing to start would stop a running
    deployment on an upgrade; refusing the old secret while starting would be
    worse and quieter, because every session minted before the rotation would
    be logged out. Only a moment somebody wrote down is enforced.
    """

    def test_the_old_secret_is_still_accepted(self, rotating) -> None:
        token = rotating(None)

        assert auth_jwt.grace_secret_is_live() is True
        assert auth_jwt.decode_token(token) is not None

    def test_the_current_secret_is_accepted_beside_it(self, rotating) -> None:
        rotating(None)

        assert auth_jwt.decode_token(_token_signed_with(NEW_SECRET)) is not None

    def test_no_end_is_not_a_lapsed_end(self, rotating) -> None:
        """The two cases differ, and the status has to be able to say which."""
        rotating(None)
        unbounded = auth_jwt.grace_secret_is_live()
        rotating(datetime.now(UTC) - timedelta(days=1))

        assert unbounded is True
        assert auth_jwt.grace_secret_is_live() is False


class TestStartupWillNotLetItBeForgotten:
    @staticmethod
    def _report(monkeypatch, not_after):
        from app.bootstrap import validate_bootstrap
        from app.config import get_settings

        s = get_settings()
        monkeypatch.setattr(s, "jwt_previous_secret_key", SecretStr(OLD_SECRET))
        monkeypatch.setattr(s, "jwt_previous_secret_not_after", not_after)
        return validate_bootstrap(s)

    def test_a_grace_secret_with_no_end_is_a_warning_and_never_a_refusal(self, monkeypatch) -> None:
        """A running deployment keeps running; the reminder is loud instead."""
        report = self._report(monkeypatch, None)

        assert not [problem for problem in report.problems if "JWT_PREVIOUS" in problem]
        assert any("JWT_PREVIOUS_SECRET_NOT_AFTER" in warning for warning in report.warnings)
        assert any("no end" in warning for warning in report.warnings)

    def test_a_grace_secret_inside_its_window_is_neither_a_problem_nor_a_warning(
        self, monkeypatch
    ) -> None:
        report = self._report(monkeypatch, datetime.now(UTC) + timedelta(days=1))

        assert not [p for p in report.problems if "JWT_PREVIOUS" in p]
        assert not [w for w in report.warnings if "JWT_PREVIOUS" in w]

    def test_a_leftover_moment_with_no_secret_left_to_bound_is_not_a_refusal(
        self, monkeypatch
    ) -> None:
        """Step three of the runbook is clearing the secret; the moment may lag."""
        from app.bootstrap import validate_bootstrap
        from app.config import get_settings

        s = get_settings()
        monkeypatch.setattr(s, "jwt_previous_secret_key", SecretStr(""))
        monkeypatch.setattr(s, "jwt_previous_secret_not_after", "tomorrow")

        report = validate_bootstrap(s)

        assert not [problem for problem in report.problems if "JWT_PREVIOUS" in problem]

    def test_a_lapsed_one_is_a_warning_to_finish_the_rotation(self, monkeypatch) -> None:
        report = self._report(monkeypatch, datetime.now(UTC) - timedelta(days=1))

        assert not [p for p in report.problems if "JWT_PREVIOUS" in p]
        assert any("no longer accepted" in warning for warning in report.warnings)


class TestAMomentThatDoesNotRead:
    """A typo reaches the operator as the bootstrap report, never as a traceback.

    The setting is plain text and is parsed where it is read, because
    ``APISettings`` construction is not allowed to raise: a pydantic error
    there comes from whichever import built the singleton first and names one
    field, which is the opposite of the one report that names every problem.
    """

    def test_an_unparseable_moment_is_a_bootstrap_problem(self, monkeypatch) -> None:
        from app.bootstrap import validate_bootstrap
        from app.config import get_settings

        s = get_settings()
        monkeypatch.setattr(s, "jwt_previous_secret_key", SecretStr(OLD_SECRET))
        monkeypatch.setattr(s, "jwt_previous_secret_not_after", "2026-13-99")

        report = validate_bootstrap(s)

        assert any("JWT_PREVIOUS_SECRET_NOT_AFTER" in problem for problem in report.problems)

    def test_building_the_settings_with_one_does_not_raise(self, monkeypatch) -> None:
        from app.config import APISettings

        monkeypatch.setenv("JWT_PREVIOUS_SECRET_NOT_AFTER", "not-a-date")

        assert APISettings().jwt_previous_secret_not_after == "not-a-date"

    def test_the_shapes_an_operator_writes_all_read(self, monkeypatch) -> None:
        for written, expected in (
            ("2026-09-30", datetime(2026, 9, 30, tzinfo=UTC)),
            ("2026-09-30T12:00:00", datetime(2026, 9, 30, 12, tzinfo=UTC)),
            ("2026-09-30T12:00:00+00:00", datetime(2026, 9, 30, 12, tzinfo=UTC)),
        ):
            monkeypatch.setattr(settings, "jwt_previous_secret_not_after", written)
            assert auth_jwt.grace_secret_not_after() == expected, written

    def test_an_unreadable_moment_does_not_retire_a_secret_by_itself(self, monkeypatch) -> None:
        """The operator is told; their sessions are not ended for a typo."""
        monkeypatch.setattr(settings, "jwt_secret_key", SecretStr(NEW_SECRET))
        monkeypatch.setattr(settings, "jwt_previous_secret_key", SecretStr(OLD_SECRET))
        monkeypatch.setattr(settings, "jwt_previous_secret_not_after", "not-a-date")

        assert auth_jwt.decode_token(_token_signed_with(OLD_SECRET)) is not None


class TestTheLineAtEveryStart:
    """What the startup line says, and what it is built from.

    Nothing in it comes from a function that reads the previous secret\'s
    value. The key id is not in it at all: an operator who wants it reads it
    from ``/system/status``, which answers an authenticated admin rather than
    writing to a log file. What is left is the moment, which is a setting of
    its own, and two words chosen by a bool.
    """

    @staticmethod
    def _said(caplog) -> list[Any]:
        import logging

        caplog.clear()
        with caplog.at_level(logging.INFO):
            log_jwt_rotation()
        return list(caplog.records)

    def test_a_rotation_with_no_end_is_a_warning_that_says_what_to_set(
        self, rotating, caplog
    ) -> None:
        rotating(None)

        records = self._said(caplog)

        assert len(records) == 1
        assert records[0].levelname == "WARNING"
        assert "JWT_PREVIOUS_SECRET_NOT_AFTER" in records[0].getMessage()
        assert "no end" in records[0].getMessage()

    def test_a_rotation_with_an_end_says_when_it_lapses(self, rotating, caplog) -> None:
        lapses = datetime.now(UTC) + timedelta(days=1)
        rotating(lapses)

        records = self._said(caplog)

        assert len(records) == 1
        assert records[0].levelname == "INFO"
        said = records[0].getMessage()
        assert lapses.isoformat() in said
        assert "accepted" in said and "lapses" in said

    def test_a_lapsed_window_says_so_in_the_past(self, rotating, caplog) -> None:
        lapsed = datetime.now(UTC) - timedelta(days=1)
        rotating(lapsed)

        said = self._said(caplog)[0].getMessage()

        assert "no longer accepted" in said
        assert "lapsed" in said

    def test_the_key_id_is_not_written_to_a_log(self, rotating, caplog) -> None:
        """It is on the status for an admin to read, not in a file on disk."""
        rotating(datetime.now(UTC) + timedelta(days=1))

        said = self._said(caplog)[0].getMessage()

        assert "v0" not in said
        assert "kid" not in said

    def test_nothing_is_said_when_no_rotation_is_in_progress(self, monkeypatch, caplog) -> None:
        monkeypatch.setattr(settings, "jwt_previous_secret_key", SecretStr(""))

        assert self._said(caplog) == []

    def test_the_secret_never_reaches_a_log_line(self, rotating, caplog) -> None:
        rotating(datetime.now(UTC) + timedelta(days=1))

        said = " ".join(record.getMessage() for record in self._said(caplog))

        assert OLD_SECRET not in said
        assert NEW_SECRET not in said


class TestOnlyOnePlaceLooksAtTheSecret:
    """Everything that asks whether a rotation is on asks the same question.

    Three sentences used to be built from a dict a function returned after
    reading the secret out of its box, which is a flow a reader — human or
    scanner — has to follow to the end before it can say nothing leaked. The
    bool is the flow now.
    """

    def test_the_bool_says_whether_one_is_configured(self, rotating, monkeypatch) -> None:
        rotating(None)
        assert auth_jwt.grace_secret_configured() is True

        monkeypatch.setattr(settings, "jwt_previous_secret_key", SecretStr(""))
        assert auth_jwt.grace_secret_configured() is False

    def test_nothing_else_opens_the_box_to_ask_a_yes_or_no(self) -> None:
        import ast
        import inspect

        from app import main
        from app.api.v1 import system
        from app.auth import jwt as jwt_module

        for module in (jwt_module, system, main):
            tree = ast.parse(inspect.getsource(module))
            for node in ast.walk(tree):
                if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                    continue
                body = ast.dump(node)
                # Only the functions that are about this secret; the modules
                # hold others that open boxes of their own.
                if "jwt_previous_secret_key" not in body:
                    continue
                opens = any(
                    isinstance(call.func, ast.Attribute) and call.func.attr == "get_secret_value"
                    for call in ast.walk(node)
                    if isinstance(call, ast.Call)
                )
                if opens:
                    assert node.name in {"grace_secret_configured", "_previous_secret"}, (
                        f"{module.__name__}.{node.name} reads the secret's value"
                    )


class TestWhatAnOperatorIsShown:
    def test_the_status_names_the_key_and_when_it_lapses(self, rotating) -> None:
        from app.api.v1.system import _grace_secret_state

        lapses = datetime.now(UTC) + timedelta(days=1)
        rotating(lapses)

        state = _grace_secret_state()

        assert state == {
            "key_id": "v0",
            "not_after": lapses.isoformat(),
            "accepted": True,
            "bounded": True,
        }

    def test_a_lapsed_rotation_still_shows_until_the_secret_is_cleared(self, rotating) -> None:
        from app.api.v1.system import _grace_secret_state

        rotating(datetime.now(UTC) - timedelta(days=1))

        state = _grace_secret_state()
        assert state["accepted"] is False
        assert state["bounded"] is True

    def test_an_unbounded_rotation_is_told_apart_from_a_bounded_live_one(self, rotating) -> None:
        """Both are accepted; only one of them ends, and a reader has to know."""
        rotating(None)

        assert _state_of(rotating, None) == {
            "key_id": "v0",
            "not_after": None,
            "accepted": True,
            "bounded": False,
        }
        assert _state_of(rotating, datetime.now(UTC) + timedelta(days=1))["bounded"] is True

    def test_nothing_is_shown_when_no_rotation_is_in_progress(self, monkeypatch) -> None:
        from app.api.v1.system import _grace_secret_state

        monkeypatch.setattr(settings, "jwt_previous_secret_key", SecretStr(""))

        assert _grace_secret_state() is None

    def test_only_an_admin_is_told_about_the_rotation(self, rotating) -> None:
        """Rotation state is operational detail, like the throttle beside it."""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from app.api.v1.system import router
        from app.deps import optional_current_user

        rotating(datetime.now(UTC) + timedelta(days=1))
        app = FastAPI()
        app.include_router(router, prefix="/api/v1")

        def _caller(role: str | None):
            if role is None:
                return None
            user = MagicMock()
            user.role = role
            return user

        for role, shown in ((None, False), ("analyst", False), ("admin", True)):
            app.dependency_overrides[optional_current_user] = lambda role=role: _caller(role)
            with TestClient(app) as client:
                body = client.get("/api/v1/system/status").json()
            assert ("jwt_grace_secret" in body) is shown, role

    def test_the_secret_itself_never_reaches_the_status(self, rotating) -> None:
        from app.api.v1.system import _grace_secret_state

        rotating(datetime.now(UTC) + timedelta(days=1))

        assert OLD_SECRET not in str(_grace_secret_state())

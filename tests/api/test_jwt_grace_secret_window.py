"""A retired signing secret stops being accepted on a day somebody wrote down.

Rotation is two settings and a wait, and the wait is where it is forgotten: the
grace secret used to be accepted for the life of the deployment, so an old key
an operator meant to retire stayed a key that could mint sessions. The window
now has an end, the end is refused at startup if it is missing, and both the
status endpoint and the startup log say when it is.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jwt as pyjwt
import pytest
from pydantic import SecretStr

from app.auth import jwt as auth_jwt
from app.config import settings
from tests.credential_shapes import lowercase_base64_blob

NEW_SECRET = "new-" + lowercase_base64_blob()
OLD_SECRET = "old-" + lowercase_base64_blob()


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


class TestStartupWillNotLetItBeForgotten:
    @staticmethod
    def _report(monkeypatch, not_after):
        from app.bootstrap import validate_bootstrap
        from app.config import get_settings

        s = get_settings()
        monkeypatch.setattr(s, "jwt_previous_secret_key", SecretStr(OLD_SECRET))
        monkeypatch.setattr(s, "jwt_previous_secret_not_after", not_after)
        return validate_bootstrap(s)

    def test_a_grace_secret_with_no_end_refuses_the_start(self, monkeypatch) -> None:
        report = self._report(monkeypatch, None)

        assert any("JWT_PREVIOUS_SECRET_NOT_AFTER" in problem for problem in report.problems)

    def test_a_grace_secret_inside_its_window_is_neither_a_problem_nor_a_warning(
        self, monkeypatch
    ) -> None:
        report = self._report(monkeypatch, datetime.now(UTC) + timedelta(days=1))

        assert not [p for p in report.problems if "JWT_PREVIOUS" in p]
        assert not [w for w in report.warnings if "JWT_PREVIOUS" in w]

    def test_a_lapsed_one_is_a_warning_to_finish_the_rotation(self, monkeypatch) -> None:
        report = self._report(monkeypatch, datetime.now(UTC) - timedelta(days=1))

        assert not [p for p in report.problems if "JWT_PREVIOUS" in p]
        assert any("no longer accepted" in warning for warning in report.warnings)


class TestWhatAnOperatorIsShown:
    def test_the_status_names_the_key_and_when_it_lapses(self, rotating) -> None:
        from app.api.v1.system import _grace_secret_state

        lapses = datetime.now(UTC) + timedelta(days=1)
        rotating(lapses)

        state = _grace_secret_state()

        assert state == {"key_id": "v0", "not_after": lapses.isoformat(), "accepted": True}

    def test_a_lapsed_rotation_still_shows_until_the_secret_is_cleared(self, rotating) -> None:
        from app.api.v1.system import _grace_secret_state

        rotating(datetime.now(UTC) - timedelta(days=1))

        assert _grace_secret_state()["accepted"] is False

    def test_nothing_is_shown_when_no_rotation_is_in_progress(self, monkeypatch) -> None:
        from app.api.v1.system import _grace_secret_state

        monkeypatch.setattr(settings, "jwt_previous_secret_key", SecretStr(""))

        assert _grace_secret_state() is None

    def test_the_secret_itself_never_reaches_the_status(self, rotating) -> None:
        from app.api.v1.system import _grace_secret_state

        rotating(datetime.now(UTC) + timedelta(days=1))

        assert OLD_SECRET not in str(_grace_secret_state())

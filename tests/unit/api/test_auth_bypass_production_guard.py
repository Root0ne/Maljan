"""``AUTH_DISABLED`` must not be able to reach a non-debug deployment.

``get_current_user`` returns the seeded dev admin for *every* request when
``auth_disabled`` is set — before any token is inspected (``app/deps.py``).
``model_post_init`` forces the flag off under pytest so the suite's 401/403
assertions stay honest, but that is a test guard, not a production one: an
environment carried from a dev box to a real deployment would serve an
unauthenticated admin API, and nothing anywhere would say so.

The refusal itself is a *bootstrap* problem rather than a construction error
(fix wave C1): ``APISettings`` no longer raises, so a misconfigured process
dies with one ``bootstrap: ...`` line naming every problem at once instead of
a pydantic traceback naming whichever field pydantic reached first. These
tests therefore read ``validate_bootstrap``. They still patch ``_is_test_env``
where the flag has to survive construction: without that, ``auth_disabled`` is
cleared before the check can see it.
"""

from __future__ import annotations

from unittest.mock import patch

from app.bootstrap import validate_bootstrap
from app.config import APISettings

_AUTH_DISABLED_PROBLEM = "AUTH_DISABLED is set with DEBUG=False"


def _settings(**overrides: object) -> APISettings:
    # Every field with a strength check is supplied here rather than left to the
    # environment. jwt_secret_key was not, so on a machine carrying a .env the
    # settings validated and these tests ran, and on a clean checkout they failed
    # on the JWT validator before reaching the bypass they exist to test. A test
    # that needs an untracked file is a test that passes for the wrong reason.
    base: dict[str, object] = {
        "debug": False,
        "auth_disabled": False,
        "minio_secret_key": "a-real-secret-not-a-placeholder",
        "jwt_secret_key": "0" * 64,
    }
    base.update(overrides)
    return APISettings(**base)  # type: ignore[arg-type]


def _problems(s: APISettings) -> list[str]:
    return validate_bootstrap(s).problems


class TestTheBypassCannotShipToProduction:
    def test_auth_disabled_with_debug_off_is_refused(self) -> None:
        with patch("app.config._is_test_env", return_value=False):
            s = _settings(auth_disabled=True)
        assert any(p.startswith(_AUTH_DISABLED_PROBLEM) for p in _problems(s))

    def test_the_error_names_the_flag_to_unset(self) -> None:
        """An operator reading only the message must know what to do."""
        with patch("app.config._is_test_env", return_value=False):
            s = _settings(auth_disabled=True)
        message = next(p for p in _problems(s) if p.startswith("AUTH_DISABLED"))
        assert "AUTH_DISABLED" in message
        assert "DEBUG=False" in message

    def test_construction_itself_never_raises(self) -> None:
        """W1: the refusal is one ``bootstrap:`` line, not an import traceback."""
        with patch("app.config._is_test_env", return_value=False):
            s = _settings(auth_disabled=True, minio_secret_key="minioadmin")
        assert s.auth_disabled is True


class TestLocalDevelopmentIsUntouched:
    def test_auth_disabled_with_debug_on_is_allowed(self) -> None:
        """The whole point of the flag — this is how the dev box runs today."""
        with patch("app.config._is_test_env", return_value=False):
            s = _settings(debug=True, auth_disabled=True)
        assert s.auth_disabled is True
        assert not any(p.startswith("AUTH_DISABLED") for p in _problems(s))

    def test_a_production_config_without_the_bypass_still_builds(self) -> None:
        with patch("app.config._is_test_env", return_value=False):
            s = _settings(auth_disabled=False)
        assert s.auth_disabled is False
        assert not any(p.startswith("AUTH_DISABLED") for p in _problems(s))


class TestTheTestSuiteGuardStillHolds:
    def test_pytest_clears_the_flag_rather_than_raising(self) -> None:
        """Under pytest the flag is forced off so 401/403 assertions stay real."""
        s = _settings(auth_disabled=True)
        assert s.auth_disabled is False

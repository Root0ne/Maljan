"""``AUTH_DISABLED`` must not be able to reach a non-debug deployment.

``get_current_user`` returns the seeded dev admin for *every* request when
``auth_disabled`` is set — before any token is inspected (``app/deps.py``).
``model_post_init`` forced the flag off under pytest so the suite's 401/403
assertions stayed honest, but that is a test guard, not a production one: the
MinIO placeholder check right below it raises when ``DEBUG=False``, and the
auth bypass — the more dangerous of the two — had no equivalent. A ``.env``
carried from a dev box to a real deployment would serve an unauthenticated
admin API, and nothing anywhere would say so.

The pytest guard is exactly why these tests patch ``_is_test_env``: without
that, ``auth_disabled`` is cleared before the production check can be reached.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from app.config import APISettings


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


class TestTheBypassCannotShipToProduction:
    def test_auth_disabled_with_debug_off_is_refused(self) -> None:
        with patch("app.config._is_test_env", return_value=False):
            with pytest.raises(ValueError, match="AUTH_DISABLED"):
                _settings(auth_disabled=True)

    def test_the_error_names_the_flag_to_unset(self) -> None:
        """An operator reading only the message must know what to do."""
        with patch("app.config._is_test_env", return_value=False):
            with pytest.raises(ValueError) as exc:
                _settings(auth_disabled=True)
        assert "AUTH_DISABLED" in str(exc.value)
        assert "DEBUG=False" in str(exc.value)


class TestLocalDevelopmentIsUntouched:
    def test_auth_disabled_with_debug_on_is_allowed(self) -> None:
        """The whole point of the flag — this is how the dev box runs today."""
        with patch("app.config._is_test_env", return_value=False):
            s = _settings(debug=True, auth_disabled=True)
        assert s.auth_disabled is True

    def test_a_production_config_without_the_bypass_still_builds(self) -> None:
        with patch("app.config._is_test_env", return_value=False):
            s = _settings(auth_disabled=False)
        assert s.auth_disabled is False


class TestTheTestSuiteGuardStillHolds:
    def test_pytest_clears_the_flag_rather_than_raising(self) -> None:
        """Under pytest the flag is forced off so 401/403 assertions stay real."""
        s = _settings(auth_disabled=True)
        assert s.auth_disabled is False

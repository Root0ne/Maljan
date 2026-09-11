from __future__ import annotations

from cryptography.fernet import Fernet

from app.bootstrap import BootstrapProblem, require_bootstrap, validate_bootstrap
from app.config import APISettings


def _valid_kwargs(**overrides: object) -> dict[object, object]:
    base: dict[object, object] = {
        "database_url": "postgresql+asyncpg://u:p@127.0.0.1:5433/maljan",
        "redis_url": "redis://127.0.0.1:6379/0",
        "minio_endpoint": "127.0.0.1:9000",
        "minio_access_key": "real-access-key",
        "minio_secret_key": "real-secret-key-not-a-placeholder",
        "jwt_secret_key": "0" * 32,
        "settings_encryption_key": Fernet.generate_key().decode(),
        "debug": False,
        "auth_disabled": False,
        "cookie_secure": True,
    }
    base.update(overrides)
    return base


def test_missing_required_lists_every_variable() -> None:
    s = APISettings(
        **_valid_kwargs(
            database_url="",
            redis_url="",
            minio_endpoint="",
            minio_access_key="",
            minio_secret_key="",
            settings_encryption_key="",
        ),
        _env_file=None,
    )
    report = validate_bootstrap(s)
    assert "DATABASE_URL is not set" in report.problems
    assert "REDIS_URL is not set" in report.problems
    assert "MINIO_ENDPOINT is not set" in report.problems
    assert "MINIO_ACCESS_KEY is not set" in report.problems
    assert "MINIO_SECRET_KEY is not set" in report.problems
    assert "SETTINGS_ENCRYPTION_KEY is not set" in report.problems

    try:
        require_bootstrap(s)
    except BootstrapProblem as exc:
        assert str(exc).startswith("bootstrap: ")
        assert "DATABASE_URL is not set" in str(exc)
    else:
        raise AssertionError("require_bootstrap should have raised")


def test_invalid_fernet_key_is_a_problem() -> None:
    s = APISettings(**_valid_kwargs(settings_encryption_key="not-a-fernet-key"), _env_file=None)
    report = validate_bootstrap(s)
    assert "SETTINGS_ENCRYPTION_KEY is not a valid Fernet key" in report.problems


def test_placeholder_jwt_secret_allowed_only_in_debug() -> None:
    non_debug = APISettings(**_valid_kwargs(debug=False, jwt_secret_key="0" * 64), _env_file=None)
    non_debug_report = validate_bootstrap(non_debug)
    assert not any("JWT_SECRET_KEY" in p for p in non_debug_report.problems)

    weak_non_debug = APISettings(
        **_valid_kwargs(debug=False, jwt_secret_key="short"), _env_file=None
    )
    weak_report = validate_bootstrap(weak_non_debug)
    assert any("JWT_SECRET_KEY" in p for p in weak_report.problems)

    debug_s = APISettings(**_valid_kwargs(debug=True, jwt_secret_key="short"), _env_file=None)
    debug_report = validate_bootstrap(debug_s)
    assert not any("JWT_SECRET_KEY" in p for p in debug_report.problems)


def test_clean_bootstrap_has_no_problems() -> None:
    s = APISettings(**_valid_kwargs(), _env_file=None)
    report = validate_bootstrap(s)
    assert report.problems == []
    require_bootstrap(s)  # must not raise


def test_cookie_secure_off_in_production_is_a_warning() -> None:
    s = APISettings(
        **_valid_kwargs(debug=False, auth_disabled=False, cookie_secure=False), _env_file=None
    )
    report = validate_bootstrap(s)
    assert report.problems == []
    assert any("COOKIE_SECURE" in w for w in report.warnings)

    # Not a warning when debug or the auth bypass is on.
    s_debug = APISettings(**_valid_kwargs(debug=True, cookie_secure=False), _env_file=None)
    assert validate_bootstrap(s_debug).warnings == []

    # ``auth_disabled=True`` with ``debug=False`` is refused by APISettings
    # itself (the auth-bypass production guard), so the "warning suppressed
    # by auth_disabled" branch is exercised against a minimal stand-in that
    # carries only the attributes validate_bootstrap reads.
    class _Stub:
        database_url = "postgresql+asyncpg://u:p@127.0.0.1:5433/maljan"
        redis_url = "redis://127.0.0.1:6379/0"
        minio_endpoint = "127.0.0.1:9000"
        minio_access_key = "real-access-key"
        minio_secret_key = "real-secret-key-not-a-placeholder"
        jwt_secret_key = "0" * 32
        settings_encryption_key = Fernet.generate_key().decode()
        debug = False
        auth_disabled = True
        cookie_secure = False

    assert validate_bootstrap(_Stub()).warnings == []

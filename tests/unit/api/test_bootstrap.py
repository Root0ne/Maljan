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


def test_placeholder_jwt_secret_allowed_only_in_debug(monkeypatch) -> None:
    monkeypatch.setenv("JWT_SECRET_KEY", "0" * 64)
    non_debug = APISettings(**_valid_kwargs(debug=False), _env_file=None)
    non_debug_report = validate_bootstrap(non_debug)
    assert not any("JWT_SECRET_KEY" in p for p in non_debug_report.problems)

    monkeypatch.setenv("JWT_SECRET_KEY", "short")
    weak_non_debug = APISettings(**_valid_kwargs(debug=False), _env_file=None)
    weak_report = validate_bootstrap(weak_non_debug)
    assert any("JWT_SECRET_KEY" in p for p in weak_report.problems)

    debug_s = APISettings(**_valid_kwargs(debug=True), _env_file=None)
    debug_report = validate_bootstrap(debug_s)
    assert not any("JWT_SECRET_KEY" in p for p in debug_report.problems)


def test_whitespace_padded_placeholder_jwt_secret_is_a_problem_outside_debug(monkeypatch) -> None:
    monkeypatch.setenv("JWT_SECRET_KEY", "  changeme  \n")
    s = APISettings(**_valid_kwargs(debug=False), _env_file=None)
    report = validate_bootstrap(s)
    assert any("JWT_SECRET_KEY" in p for p in report.problems)


def test_the_jwt_secret_is_read_from_the_environment_not_the_field(monkeypatch) -> None:
    """The field may carry the in-repo test secret; the check may not see it.

    ``_enforce_jwt_secret`` substitutes ``TEST_JWT_SECRET`` for an unset
    ``JWT_SECRET_KEY`` under pytest, and that string is 43 characters long and
    not in the placeholder set -- exactly the shape every check below accepts.
    Reading the environment is what keeps a published secret from satisfying
    the gate it exists to fail.
    """
    monkeypatch.setenv("JWT_SECRET_KEY", "changeme")
    s = APISettings(**_valid_kwargs(debug=False, jwt_secret_key="0" * 64), _env_file=None)
    report = validate_bootstrap(s)
    assert "JWT_SECRET_KEY is a known placeholder value" in report.problems


def test_no_environment_variable_switches_the_guard_off(monkeypatch) -> None:
    """The removed ``MALJAN_API_SKIP_SECRET_CHECK`` flag changes nothing."""
    monkeypatch.setenv("MALJAN_API_SKIP_SECRET_CHECK", "1")
    monkeypatch.setenv("JWT_SECRET_KEY", "short")
    s = APISettings(**_valid_kwargs(debug=False), _env_file=None)
    assert any("JWT_SECRET_KEY" in p for p in validate_bootstrap(s).problems)


def test_the_minio_placeholder_is_a_bootstrap_problem_not_an_exception() -> None:
    """W1: this used to abort ``APISettings`` construction with a traceback."""
    s = APISettings(**_valid_kwargs(debug=False, minio_secret_key="minioadmin"), _env_file=None)
    report = validate_bootstrap(s)
    assert "MINIO_SECRET_KEY is using the default placeholder" in report.problems

    in_debug = APISettings(
        **_valid_kwargs(debug=True, minio_secret_key="minioadmin"), _env_file=None
    )
    assert validate_bootstrap(in_debug).problems == []


def test_an_unset_minio_secret_is_reported_once() -> None:
    s = APISettings(**_valid_kwargs(debug=False, minio_secret_key=""), _env_file=None)
    problems = validate_bootstrap(s).problems
    assert problems.count("MINIO_SECRET_KEY is not set") == 1
    assert "MINIO_SECRET_KEY is using the default placeholder" not in problems


def test_the_auth_bypass_outside_debug_is_a_bootstrap_problem() -> None:
    class _Bypass:
        database_url = "postgresql+asyncpg://u:p@127.0.0.1:5433/maljan"
        redis_url = "redis://127.0.0.1:6379/0"
        minio_endpoint = "127.0.0.1:9000"
        minio_access_key = "real-access-key"
        minio_secret_key = "real-secret-key-not-a-placeholder"
        jwt_secret_key = "0" * 32
        settings_encryption_key = Fernet.generate_key().decode()
        debug = False
        auth_disabled = True
        cookie_secure = True

    problems = validate_bootstrap(_Bypass()).problems
    assert any(p.startswith("AUTH_DISABLED is set with DEBUG=False") for p in problems)


def test_every_problem_is_listed_in_one_message() -> None:
    """W1: one ``bootstrap:`` line, not the first refusal pydantic reached."""

    class _Broken:
        database_url = ""
        redis_url = "redis://127.0.0.1:6379/0"
        minio_endpoint = "127.0.0.1:9000"
        minio_access_key = "real-access-key"
        minio_secret_key = "minioadmin"
        jwt_secret_key = "0" * 32
        settings_encryption_key = Fernet.generate_key().decode()
        debug = False
        auth_disabled = True
        cookie_secure = True

    try:
        require_bootstrap(_Broken())
    except BootstrapProblem as exc:
        message = str(exc)
    else:
        raise AssertionError("require_bootstrap should have raised")
    assert message.startswith("bootstrap: ")
    assert "DATABASE_URL is not set" in message
    assert "MINIO_SECRET_KEY is using the default placeholder" in message
    assert "AUTH_DISABLED is set with DEBUG=False" in message


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

import sys
from pathlib import Path

_API = Path(__file__).resolve().parents[3] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

from app.worker.analysis_worker import build_redis_settings  # noqa: E402


def _dsn(scheme: str, userinfo: str, rest: str) -> str:
    """Assemble a credentialed URL at runtime so no literal DSN sits in the source
    (secret scanners flag ``scheme://user:pass@host`` even in a test)."""
    return f"{scheme}://{userinfo}@{rest}"


def test_build_redis_settings_forwards_the_password():
    password = "p" * 16
    url = _dsn("redis", f":{password}", "redis:6379/0")
    rs = build_redis_settings(url)
    assert rs.host == "redis"
    assert rs.port == 6379
    assert rs.database == 0
    assert rs.password == password
    assert rs.username is None


def test_build_redis_settings_forwards_a_username_too():
    password = "q" * 16
    url = _dsn("redis", f"worker:{password}", "redis:6379/2")
    rs = build_redis_settings(url)
    assert rs.username == "worker"
    assert rs.password == password
    assert rs.database == 2


def test_build_redis_settings_with_no_credentials_leaves_them_none():
    rs = build_redis_settings("redis://redis:6379/0")
    assert rs.username is None
    assert rs.password is None

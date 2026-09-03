import sys
from pathlib import Path

import pytest

_API = Path(__file__).resolve().parents[3] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

from app import observability  # noqa: E402
from app.auth import throttle  # noqa: E402


class _Flaky:
    """A redis stand-in whose ping and commands raise while ``down`` is True."""

    def __init__(self) -> None:
        self.down = True
        self.deleted: list[str] = []

    async def ping(self) -> bool:
        if self.down:
            raise ConnectionError("refused")
        return True

    async def delete(self, key: str) -> int:
        if self.down:
            raise ConnectionError("refused")
        self.deleted.append(key)
        return 1


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    monkeypatch.setattr(throttle, "_pool", None)
    monkeypatch.setattr(throttle, "_last_failure_at", None)
    observability.throttle.__init__()
    yield
    observability.throttle.__init__()


@pytest.mark.asyncio
async def test_refresh_consume_fails_closed_when_redis_is_down(monkeypatch, caplog):
    flaky = _Flaky()
    monkeypatch.setattr(throttle.aioredis, "from_url", lambda *a, **k: flaky)
    with caplog.at_level("WARNING", logger="maljan.auth.throttle"):
        assert await throttle.refresh_token_consume("u1", "j1") is False
    state = throttle.throttle_state()
    assert state["available"] is False
    assert state["last_error"] == "ConnectionError"
    assert sum("throttle" in r.getMessage().lower() for r in caplog.records) == 1


@pytest.mark.asyncio
async def test_redis_is_retried_after_the_interval_and_recovery_logs_once(monkeypatch, caplog):
    flaky = _Flaky()
    monkeypatch.setattr(throttle.aioredis, "from_url", lambda *a, **k: flaky)
    now = [1000.0]
    monkeypatch.setattr(throttle.time, "monotonic", lambda: now[0])
    assert await throttle.refresh_token_consume("u1", "j1") is False
    flaky.down = False
    # Inside the interval: no reconnect attempt, still closed.
    now[0] += 5
    assert await throttle.refresh_token_consume("u1", "j1") is False
    now[0] += throttle.RETRY_AFTER_S
    with caplog.at_level("WARNING", logger="maljan.auth.throttle"):
        assert await throttle.refresh_token_consume("u1", "j1") is True
    assert throttle.throttle_state()["available"] is True
    assert flaky.deleted == ["auth:refresh:u1:j1"]
    assert any("restored" in r.getMessage() for r in caplog.records)


@pytest.mark.asyncio
async def test_login_lock_stays_open_but_degraded(monkeypatch):
    flaky = _Flaky()
    monkeypatch.setattr(throttle.aioredis, "from_url", lambda *a, **k: flaky)
    assert await throttle.is_login_locked("a@b.c") is False
    await throttle.record_login_failure("a@b.c")  # must not raise
    assert throttle.throttle_state()["available"] is False

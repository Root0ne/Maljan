# Security Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Apply the behaviour-changing findings of the 2026-09-02 audit (H1, H3, M1, M2, M5, M6, L4, L5, L6, L7, L9, L12, L13, L14, L15, MCP env filtering, parallelism tests, semgrep) so the API fails closed where it must, leaves no sample copies behind, publishes nothing by default, and reports its own degraded states.

**Architecture:** Seventeen independent tasks on one branch, one commit each. Runtime state that operators must see (throttle degradation, audit write failures) lives in one small module, `apps/api/app/observability.py`, read by `/health?deep=true` and `/system/status`. Subprocess environments come from one helper, `src/maljan/agents/subprocess_env.py`. Evaluation harnesses share one `Tally`. Everything else is a local change to the file the audit named.

**Tech Stack:** Python 3.13, FastAPI, pydantic-settings, redis.asyncio, SQLAlchemy async, arq; Next.js 16 / React 19 / TypeScript; Playwright; Docker Compose; GitHub Actions; semgrep.

**Spec:** `docs/specs/2026-09-03-security-hardening-design.md` (the audit itself is `other/audit/2026-09-02-audit.md`, git-ignored, sections 1 and 4).

## Global Constraints

- Branch `feat/security-hardening`, one commit per task, imperative messages in the repository's voice, no AI attribution anywhere.
- Every task: TDD (failing test first), `uv run ruff check <files>`, `uv run ruff format --check <files>`, `uv run mypy src/ apps/api/` clean; frontend tasks: `cd apps/web && npx tsc --noEmit && npm run lint` (10 pre-existing warnings, none new).
- Run only the test modules named in the task (`uv run pytest <paths> -q`), never the whole suite mid-task; the full suite, `make facts` (must be byte-identical) and the touched Playwright specs run once at the end.
- Never print or read the real `.env`; never log or return a secret value; tests use obviously fake credentials built at runtime (see `_dsn()` in `tests/unit/api/test_settings_probes.py`), never a literal `scheme://user:pass@host`.
- A new setting is a new catalog leaf: add the `ANNOTATIONS` entry in `src/maljan/core/settings_annotations.py` (core) or the `API_EDITABLE`/`API_READONLY` entry in `apps/api/app/services/settings_catalog_api.py` (api), or `tests/unit/core/test_settings_catalog.py` fails.
- Local development without Compose keeps working with an unchanged `.env`; every new environment variable has a default that preserves today's behaviour outside Compose.
- The paper's numbers do not move: no evaluation is re-run, `tests/evaluation/*.json` artefacts are not edited, `make facts` output is byte-identical.
- No question sentences in headings, comments or docs.

---

### Task 1: Throttle state and fail-closed refresh (H1)

**Files:**
- Create: `apps/api/app/observability.py`
- Modify: `apps/api/app/auth/throttle.py` (whole module), `apps/api/app/api/v1/auth.py:177-232` (refresh route), `apps/api/app/api/v1/system.py:32-65`, `apps/api/app/main.py:321-355` (health)
- Test: `tests/unit/api/test_throttle_state.py`, `tests/api/test_auth_refresh_fail_closed.py`

**Interfaces:**
- Produces:
  ```python
  # apps/api/app/observability.py
  @dataclass
  class ThrottleState:
      available: bool = True
      degraded_since: float | None = None   # time.monotonic() when it went down
      last_error: str | None = None         # exception type name only
      def as_dict(self) -> dict[str, object]: ...
  @dataclass
  class Counters:
      audit_write_failures: int = 0
  throttle = ThrottleState()
  counters = Counters()
  ```
  ```python
  # apps/api/app/auth/throttle.py
  RETRY_AFTER_S = 30.0
  async def _redis() -> Any | None            # retries after RETRY_AFTER_S, no permanent sentinel
  async def refresh_token_consume(user_id, jti) -> bool   # False when Redis unavailable or failing
  def throttle_state() -> dict[str, object]   # observability.throttle.as_dict()
  ```
  Health: `body["throttle_degraded"]: bool` in `/health?deep=true`. Status: `SystemStatusResponse.throttle: dict` and `audit_write_failures: int` (the counter is filled in Task 2; declare the field here with default 0).

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/api/test_throttle_state.py
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
```

```python
# tests/api/test_auth_refresh_fail_closed.py
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

_API = Path(__file__).resolve().parents[3] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

from app.api.v1 import auth as auth_module  # noqa: E402
from app.api.v1.auth import router  # noqa: E402
from app.database import get_db  # noqa: E402


def test_refresh_answers_401_when_the_session_store_is_unavailable(monkeypatch):
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[get_db] = lambda: MagicMock()
    monkeypatch.setattr(
        auth_module, "decode_token", lambda t: {"type": "refresh", "sub": "u1", "jti": "j1"}
    )
    monkeypatch.setattr(auth_module, "refresh_token_consume", AsyncMock(return_value=False))
    monkeypatch.setattr(auth_module, "_audit", AsyncMock())
    monkeypatch.setattr(
        "app.auth.throttle.throttle_state", lambda: {"available": False, "last_error": "x"}
    )
    r = TestClient(app).post("/api/v1/auth/refresh", json={"refresh_token": "t"})
    assert r.status_code == 401
    assert "sign in again" in r.json()["detail"]
```

(Task 10 changes the refresh request to a cookie; this test is rewritten there. Until then the body form is what the route accepts.)

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/unit/api/test_throttle_state.py tests/api/test_auth_refresh_fail_closed.py -q`
Expected: FAIL — `app.observability` does not exist; `throttle_state` undefined.

- [ ] **Step 3: Create the observability module**

```python
# apps/api/app/observability.py
"""Process-local state operators must be able to see.

Two things live here because two routes read them: the auth throttle's
availability (Task H1) and the count of audit rows that could not be written
(M6). Both are per process; a multi-process deployment reports each worker's
own view, which is what a health probe wants.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ThrottleState:
    available: bool = True
    degraded_since: float | None = None
    last_error: str | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "available": self.available,
            "degraded_since": self.degraded_since,
            "last_error": self.last_error,
        }


@dataclass
class Counters:
    audit_write_failures: int = 0


throttle = ThrottleState()
counters = Counters()
```

- [ ] **Step 4: Rewrite the throttle module**

Replace the module docstring, `_redis()` and `refresh_token_consume()`; keep the key formats and the other helpers' bodies, adding the degraded bookkeeping through one helper:

```python
"""Redis-backed authentication throttling helpers.

Availability is tracked, not assumed. When Redis is unreachable:

- refresh-token consumption FAILS CLOSED (``False``): reuse detection is
  blind, so no refresh token is honoured until the store is back; a user
  loses at most one access-token lifetime;
- the login lock FAILS OPEN (``False``): failing closed would lock every
  account for the length of the outage;
- failures are still not recorded (nowhere to record them).

Every helper marks the process-wide ``observability.throttle`` state, the
connection is retried after ``RETRY_AFTER_S`` rather than abandoned, and each
transition (down, restored) logs exactly one warning.
"""

from __future__ import annotations

import time
from typing import Any

import redis.asyncio as aioredis

from app import observability
from app.config import settings
from app.logging_config import get_logger
from app.runtime_config import runtime_config

logger = get_logger("auth.throttle")

_REFRESH_KEY = "auth:refresh:{user_id}:{jti}"
_LOGIN_FAIL_KEY = "auth:login:fail:{email}"

RETRY_AFTER_S = 30.0

_pool: Any = None
_last_failure_at: float | None = None


def _mark_down(exc: BaseException) -> None:
    global _pool, _last_failure_at
    _pool = None
    _last_failure_at = time.monotonic()
    state = observability.throttle
    if state.available:
        logger.warning(
            "Auth throttle store unreachable (%s); refresh fails closed, login lock is "
            "open until Redis is back.",
            type(exc).__name__,
        )
        state.available = False
        state.degraded_since = _last_failure_at
    state.last_error = type(exc).__name__


def _mark_up() -> None:
    state = observability.throttle
    if not state.available:
        logger.warning("Auth throttle store restored.")
    state.available = True
    state.degraded_since = None
    state.last_error = None


async def _redis() -> Any | None:
    """Return the shared Redis client, or ``None`` while the store is down.

    A failed connection is retried once ``RETRY_AFTER_S`` has passed; there is
    no permanent sentinel.
    """
    global _pool
    if _pool is not None:
        return _pool
    if _last_failure_at is not None and time.monotonic() - _last_failure_at < RETRY_AFTER_S:
        return None
    try:
        client = aioredis.from_url(settings.redis_url, decode_responses=True)
        await client.ping()
    except Exception as exc:  # noqa: BLE001 - any failure means "down"
        _mark_down(exc)
        return None
    _pool = client
    _mark_up()
    return _pool


def throttle_state() -> dict[str, object]:
    return observability.throttle.as_dict()
```

Then in every helper, the `except Exception as exc:` branch calls `_mark_down(exc)` in addition to its debug log, and `refresh_token_consume` becomes:

```python
async def refresh_token_consume(user_id: str | None, jti: str) -> bool:
    """Atomically consume a refresh token's jti.

    ``True`` only when the store confirmed the jti was active and is now gone.
    ``False`` when it was already used, never existed, or the store is
    unavailable — the caller must refuse the refresh in every one of those.
    """
    if not user_id or not jti:
        return False
    r = await _redis()
    if r is None:
        return False
    key = _REFRESH_KEY.format(user_id=user_id, jti=jti)
    try:
        return bool(await r.delete(key))
    except Exception as exc:  # noqa: BLE001
        logger.debug("refresh_token_consume failed: %s", exc)
        _mark_down(exc)
        return False
```

- [ ] **Step 5: Distinguish "store down" from "reuse" in the refresh route**

In `apps/api/app/api/v1/auth.py` the `if not consumed:` branch becomes:

```python
    consumed = await refresh_token_consume(user_id, jti)
    if not consumed:
        from app.auth.throttle import throttle_state

        if not throttle_state()["available"]:
            await _audit(db, None, "auth.refresh.store_unavailable", request=request)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session store unavailable; sign in again.",
            )
        await _audit(db, uuid.UUID(user_id) if user_id else None,
                     "auth.refresh.reuse_detected", request=request)
        logger.warning("Refresh token reuse detected for user=%s", user_id)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Refresh token has already been used")
```

- [ ] **Step 6: Expose the state**

`apps/api/app/api/v1/system.py`: add to `SystemStatusResponse`
```python
    throttle: dict[str, object] = Field(
        default_factory=dict,
        description="Auth throttle store availability; degraded means refresh fails closed.",
    )
    audit_write_failures: int = Field(
        default=0, description="Audit rows this process could not write since start."
    )
```
and in `system_status()` pass `throttle=throttle_state()` and `audit_write_failures=observability.counters.audit_write_failures` (import `from app import observability` and `from app.auth.throttle import throttle_state`).

`apps/api/app/main.py` health, after `components`:
```python
        from app import observability

        body["throttle_degraded"] = not observability.throttle.available
        body["audit_write_failures"] = observability.counters.audit_write_failures
```

- [ ] **Step 7: Run the tests, lint, types**

Run: `uv run pytest tests/unit/api/test_throttle_state.py tests/api/test_auth_refresh_fail_closed.py tests/unit/api/test_system_status.py tests/unit/api/test_runtime_read_sites.py -q && uv run ruff check apps/api/ tests/ && uv run mypy src/ apps/api/`
Expected: all pass. `test_runtime_read_sites.py` patches `throttle._redis`; it must still pass unchanged.

- [ ] **Step 8: Commit**

```bash
git add apps/api/app/observability.py apps/api/app/auth/throttle.py apps/api/app/api/v1/auth.py apps/api/app/api/v1/system.py apps/api/app/main.py tests/unit/api/test_throttle_state.py tests/api/test_auth_refresh_fail_closed.py
git commit -m "fix(auth): refresh fails closed while the throttle store is down, and the store is retried and reported"
```

---

### Task 2: Audit write failures are errors and are counted (M6)

**Files:**
- Modify: `apps/api/app/api/v1/auth.py:53-95` (`_audit`), `apps/api/app/services/settings_service.py` (`_audit` at the bottom)
- Test: `tests/unit/api/test_audit_failures.py`, extend `tests/unit/api/test_settings_service.py::test_save_does_not_raise_when_audit_session_fails`

**Interfaces:**
- Consumes: `observability.counters.audit_write_failures` (Task 1).
- Produces: both `_audit` helpers log `logger.error("Audit write failed (action=%s): %s", action, type(exc).__name__)` and increment the counter; no other behaviour change.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/api/test_audit_failures.py
import logging
import sys
from pathlib import Path

import pytest

_API = Path(__file__).resolve().parents[3] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

from app import observability  # noqa: E402
from app.api.v1 import auth as auth_module  # noqa: E402


class _BrokenFactory:
    def __call__(self):
        return self

    async def __aenter__(self):
        raise RuntimeError("db down")

    async def __aexit__(self, *exc):
        return False


@pytest.mark.asyncio
async def test_auth_audit_failure_is_an_error_and_is_counted(monkeypatch, caplog):
    monkeypatch.setattr(auth_module, "async_session_factory", _BrokenFactory())
    before = observability.counters.audit_write_failures
    with caplog.at_level(logging.ERROR, logger="maljan.auth"):
        await auth_module._audit(None, None, "auth.login.success", request=None)
    assert observability.counters.audit_write_failures == before + 1
    errors = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert errors and "auth.login.success" in errors[0].getMessage()
    assert "RuntimeError" in errors[0].getMessage()
```

Check the logger name `auth.py` uses (`get_logger("auth")` → `maljan.auth`; adjust the `caplog` logger argument to what `get_logger` produces, read `apps/api/app/logging_config.py`). In `test_settings_service.py`, extend the existing audit-failure test with `assert observability.counters.audit_write_failures == before + 1`.

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/unit/api/test_audit_failures.py tests/unit/api/test_settings_service.py -q`
Expected: FAIL on the counter assertion (still `debug`, no counter).

- [ ] **Step 3: Implement**

In both helpers replace the `except` branch:

```python
    except Exception as exc:  # noqa: BLE001 - audit is best effort, but never silent
        observability.counters.audit_write_failures += 1
        logger.error("Audit write failed (action=%s): %s", action, type(exc).__name__)
```

(`from app import observability` in both modules.)

- [ ] **Step 4: Run, lint, types**

Run: `uv run pytest tests/unit/api/test_audit_failures.py tests/unit/api/test_settings_service.py -q && uv run ruff check apps/api/ tests/unit/api && uv run mypy apps/api/`
Expected: pass.

- [ ] **Step 5: Commit**

```bash
git add apps/api/app/api/v1/auth.py apps/api/app/services/settings_service.py tests/unit/api/test_audit_failures.py tests/unit/api/test_settings_service.py
git commit -m "fix(audit): a failed audit write is logged as an error and counted where operators can see it"
```

---

### Task 3: Trusted proxies are networks (M1)

**Files:**
- Modify: `apps/api/app/config.py:77` (validator), `apps/api/app/middleware/rate_limit_middleware.py:66-74`
- Test: `tests/unit/test_rate_limiting.py` (new tests appended), `tests/unit/api/test_api_settings_validation.py` (new)

**Interfaces:**
- Produces: `APISettings.trusted_proxy_ips: list[str]` validated (each entry parses with `ipaddress.ip_network(strict=False)`); middleware helper `_trusted_networks(entries: list[str]) -> tuple[IPv4Network | IPv6Network, ...]` cached with `functools.lru_cache` keyed on the tuple of entries.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/api/test_api_settings_validation.py
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

_API = Path(__file__).resolve().parents[3] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

from app.config import APISettings  # noqa: E402


def test_trusted_proxy_entries_must_be_addresses_or_networks(monkeypatch):
    monkeypatch.delenv("TRUSTED_PROXY_IPS", raising=False)
    ok = APISettings(trusted_proxy_ips=["10.0.0.0/8", "192.168.1.5", "fd00::/8"])
    assert ok.trusted_proxy_ips == ["10.0.0.0/8", "192.168.1.5", "fd00::/8"]
    for bad in (["proxy"], ["10.0.0.0/33"], ["10.0.0.256"]):
        with pytest.raises(ValidationError):
            APISettings(trusted_proxy_ips=bad)
```

Append to `tests/unit/test_rate_limiting.py` (reuse its `mock_app`/`fake_redis` fixtures and `_install_counter`; read the file first):

```python
async def _peer_ip(middleware, peer: str, xff: str | None, trusted: list[str], monkeypatch):
    from app.middleware import rate_limit_middleware as rlm

    async def _get(name):
        return trusted if name == "trusted_proxy_ips" else None

    monkeypatch.setattr(rlm.runtime_config, "get", _get)
    request = MagicMock()
    request.client.host = peer
    request.headers = {"x-forwarded-for": xff} if xff else {}
    return await middleware._extract_client_ip(request)


class TestTrustedProxyNetworks:
    async def test_cidr_matches_a_host_inside_it(self, mock_app, fake_redis, monkeypatch):
        mw = RateLimitMiddleware(mock_app, redis_url="redis://localhost:6379/0", whitelist=[])
        assert await _peer_ip(mw, "10.1.2.3", "203.0.113.9", ["10.0.0.0/8"], monkeypatch) == "203.0.113.9"

    async def test_bare_address_matches_itself_only(self, mock_app, fake_redis, monkeypatch):
        mw = RateLimitMiddleware(mock_app, redis_url="redis://localhost:6379/0", whitelist=[])
        assert await _peer_ip(mw, "192.168.1.5", "203.0.113.9", ["192.168.1.5"], monkeypatch) == "203.0.113.9"
        assert await _peer_ip(mw, "192.168.1.6", "203.0.113.9", ["192.168.1.5"], monkeypatch) == "192.168.1.6"

    async def test_untrusted_peer_ignores_xff(self, mock_app, fake_redis, monkeypatch):
        mw = RateLimitMiddleware(mock_app, redis_url="redis://localhost:6379/0", whitelist=[])
        assert await _peer_ip(mw, "198.51.100.7", "203.0.113.9", ["10.0.0.0/8"], monkeypatch) == "198.51.100.7"
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/unit/api/test_api_settings_validation.py tests/unit/test_rate_limiting.py -q`
Expected: the validation test fails (no validator), the CIDR test fails (string comparison).

- [ ] **Step 3: Implement**

`apps/api/app/config.py` (imports: `import ipaddress`, `from pydantic import field_validator`):

```python
    @field_validator("trusted_proxy_ips")
    @classmethod
    def _proxies_are_networks(cls, value: list[str]) -> list[str]:
        for entry in value:
            try:
                ipaddress.ip_network(entry, strict=False)
            except ValueError as exc:
                raise ValueError(
                    f"trusted_proxy_ips entry {entry!r} is not an IP address or CIDR network"
                ) from exc
        return value
```

`apps/api/app/middleware/rate_limit_middleware.py`:

```python
import ipaddress
from functools import lru_cache


@lru_cache(maxsize=8)
def _trusted_networks(entries: tuple[str, ...]) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    return tuple(ipaddress.ip_network(e, strict=False) for e in entries)


    @staticmethod
    async def _extract_client_ip(request: Request) -> str:
        """Return the client IP, honouring X-Forwarded-For from trusted proxies."""
        entries = tuple(await runtime_config.get("trusted_proxy_ips") or ())
        peer = getattr(request.client, "host", "") or "unknown"
        try:
            peer_addr = ipaddress.ip_address(peer)
        except ValueError:
            return peer
        if any(peer_addr in net for net in _trusted_networks(entries)):
            xff = request.headers.get("x-forwarded-for", "")
            if xff:
                return xff.split(",")[0].strip() or peer
        return peer
```

- [ ] **Step 4: Run, lint, types**

Run: `uv run pytest tests/unit/api/test_api_settings_validation.py tests/unit/test_rate_limiting.py tests/unit/api/test_settings_service.py -q && uv run ruff check apps/api/ tests/ && uv run mypy apps/api/`
Expected: pass (the settings service validates `APISettings`, so a bad entry from the UI is a 422 without further code).

- [ ] **Step 5: Commit**

```bash
git add apps/api/app/config.py apps/api/app/middleware/rate_limit_middleware.py tests/unit/api/test_api_settings_validation.py tests/unit/test_rate_limiting.py
git commit -m "fix(api): trusted proxies are CIDR networks, validated at startup and in the settings UI"
```

---

### Task 4: Production defaults — docs routes, email in logs, uv pin (L4, L12, L9)

**Files:**
- Modify: `apps/api/app/main.py:250-256` (app factory) and the rate-limit whitelist default in `apps/api/app/config.py` (grep `rate_limit_whitelist`), `apps/api/app/api/v1/auth.py:104,108,135,150` (log lines), `docker/Dockerfile.backend:19`
- Test: `tests/api/test_docs_routes.py` (new), `tests/api/test_auth_logs_hash_email.py` (new)

**Interfaces:**
- Produces: `app.api.v1.auth._email_tag(email: str) -> str` returning `sha256(email.strip().lower())[:12]`; `create_app()` passes `docs_url=None, redoc_url=None, openapi_url=None` unless `settings.debug`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/api/test_docs_routes.py
import sys
from pathlib import Path

_API = Path(__file__).resolve().parents[3] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))


def test_docs_routes_exist_only_in_debug(monkeypatch):
    from app import config as api_config
    from app.main import create_app

    for debug, expected in ((True, {"/docs", "/redoc", "/openapi.json"}), (False, set())):
        api_config._settings = None
        monkeypatch.setenv("DEBUG", "true" if debug else "false")
        app = create_app()
        paths = {getattr(r, "path", "") for r in app.routes}
        assert paths & {"/docs", "/redoc", "/openapi.json"} == expected
    api_config._settings = None
```

If `create_app()` needs environment beyond `DEBUG` (MinIO placeholders, JWT secret), set the same variables `tests/api/conftest.py` sets; read it first.

```python
# tests/api/test_auth_logs_hash_email.py
import sys
from pathlib import Path

_API = Path(__file__).resolve().parents[3] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

from app.api.v1.auth import _email_tag  # noqa: E402


def test_email_tag_is_a_stable_short_hash_without_the_address():
    tag = _email_tag("Someone@Example.org")
    assert tag == _email_tag("someone@example.org")
    assert len(tag) == 12 and "@" not in tag and "example" not in tag
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/api/test_docs_routes.py tests/api/test_auth_logs_hash_email.py -q`
Expected: FAIL (`_email_tag` missing; docs present in non-debug).

- [ ] **Step 3: Implement**

`auth.py`:
```python
import hashlib


def _email_tag(email: str) -> str:
    """A short, stable stand-in for an e-mail address in log lines."""
    return hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()[:12]
```
and the four log lines use `email_hash=%s", _email_tag(body.email)` instead of the address (registration attempt, registration failed, login attempt, login failed).

`main.py` app factory:
```python
    docs_enabled = settings.debug
    app = FastAPI(
        ...,
        docs_url="/docs" if docs_enabled else None,
        redoc_url="/redoc" if docs_enabled else None,
        openapi_url="/openapi.json" if docs_enabled else None,
    )
```
Remove `/docs`, `/redoc`, `/openapi.json` from the `rate_limit_whitelist` default only if they are there (grep); if the whitelist is env-driven leave it.

`docker/Dockerfile.backend:19`: `COPY --from=ghcr.io/astral-sh/uv:0.11.28 /uv /usr/local/bin/uv`.

- [ ] **Step 4: Run, lint, types**

Run: `uv run pytest tests/api -q && uv run ruff check apps/api/ tests/api && uv run mypy apps/api/`
Expected: pass; also `grep -n "email=%s" apps/api/app/api/v1/auth.py` prints nothing.

- [ ] **Step 5: Commit**

```bash
git add apps/api/app/main.py apps/api/app/config.py apps/api/app/api/v1/auth.py docker/Dockerfile.backend tests/api/test_docs_routes.py tests/api/test_auth_logs_hash_email.py
git commit -m "chore(api): API docs only in debug, hashed e-mail in auth logs, pinned uv in the image"
```

---

### Task 5: Sample copies are private, scoped and removed (H3)

**Files:**
- Create: `apps/api/app/worker/sample_files.py`
- Modify: `apps/api/app/config.py:292` (add `samples_dir`), `apps/api/app/services/settings_catalog_api.py` (`API_READONLY` entry), `apps/api/app/worker/analysis_worker.py:480-545` (write sites), `:991` (finally), `:1217` (startup), `apps/api/app/api/v1/samples.py:478-495` (delete)
- Test: `tests/unit/api/test_sample_files.py`, `tests/integration/test_worker_job_lifecycle.py` (new assertions)

**Interfaces:**
- Produces:
  ```python
  # apps/api/app/worker/sample_files.py
  WORK_SUBDIR = ".work"
  def temp_dir() -> Path                       # Path(settings.upload_temp_dir).resolve(), created 0o700
  def work_dir() -> Path                       # (Path(settings.samples_dir) / WORK_SUBDIR).resolve(), created 0o700
  def private_copy(src: Path, dest: Path) -> None   # writes dest with mode 0o600 (os.open O_WRONLY|O_CREAT|O_TRUNC, 0o600)
  def remove_quietly(path: Path | str | None, *, job_id: str | None = None) -> None
  def remove_for_sha(sha256: str) -> list[Path]     # unlinks temp_dir()/<sha>* and work_dir()/<sha>*, returns removed
  def sweep(max_age_s: float = 86_400.0, *, now: float | None = None) -> int   # both dirs, returns count removed
  ```
  `APISettings.samples_dir: str = "data/samples"`; container path for the mirror becomes
  `f"{settings.ghidra_container_samples_path.rstrip('/')}/{WORK_SUBDIR}/{sha}{ext}"`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/api/test_sample_files.py
import os
import stat
import sys
import time
from pathlib import Path

import pytest

_API = Path(__file__).resolve().parents[3] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

from app.worker import sample_files as sf  # noqa: E402


@pytest.fixture
def dirs(tmp_path, monkeypatch):
    monkeypatch.setattr(sf.settings, "upload_temp_dir", str(tmp_path / "tmp"))
    monkeypatch.setattr(sf.settings, "samples_dir", str(tmp_path / "samples"))
    return tmp_path


def test_directories_and_files_are_private(dirs):
    src = dirs / "src.bin"
    src.write_bytes(b"MZ" * 10)
    dest = sf.work_dir() / "abc.exe"
    sf.private_copy(src, dest)
    assert stat.S_IMODE(os.stat(sf.work_dir()).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(sf.temp_dir()).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(dest).st_mode) == 0o600
    assert dest.read_bytes() == b"MZ" * 10
    assert sf.work_dir().name == ".work" and sf.work_dir().parent == (dirs / "samples").resolve()


def test_remove_for_sha_touches_only_that_hash_and_only_the_scoped_dirs(dirs):
    (sf.work_dir() / "aaa.exe").write_bytes(b"x")
    (sf.temp_dir() / "aaa.exe").write_bytes(b"x")
    (sf.work_dir() / "bbb.exe").write_bytes(b"x")
    corpus = Path(sf.settings.samples_dir) / "aaa.exe"   # operator's own file, outside .work
    corpus.write_bytes(b"x")
    removed = sf.remove_for_sha("aaa")
    assert {p.name for p in removed} == {"aaa.exe"} and len(removed) == 2
    assert (sf.work_dir() / "bbb.exe").exists() and corpus.exists()


def test_sweep_removes_only_old_files_in_the_scoped_dirs(dirs):
    old = sf.work_dir() / "old.exe"
    old.write_bytes(b"x")
    os.utime(old, (time.time() - 90_000, time.time() - 90_000))
    fresh = sf.temp_dir() / "fresh.exe"
    fresh.write_bytes(b"x")
    corpus = Path(sf.settings.samples_dir) / "keep.exe"
    corpus.write_bytes(b"x")
    os.utime(corpus, (time.time() - 90_000, time.time() - 90_000))
    assert sf.sweep() == 1
    assert not old.exists() and fresh.exists() and corpus.exists()


def test_remove_quietly_never_raises(dirs):
    sf.remove_quietly(dirs / "missing.bin")
    sf.remove_quietly(None)
```

In `tests/integration/test_worker_job_lifecycle.py`, in `test_mock_pipeline_completes`, after the run assert the two paths are gone. The mock path never downloads from MinIO (the MinIO client is mocked), so instead add a focused test that patches `analysis_worker.sample_files.remove_quietly` with a recorder and asserts it was called with the temp path and the mirror path after a successful run and after `test_pipeline_failure_sets_failed_status`'s failure (read how those tests inject `minio_client`; if they never reach the download, monkeypatch `analysis_worker._download_sample` — see Step 3 — to return a real file in `tmp_path` and assert both files are deleted afterwards).

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/unit/api/test_sample_files.py -q`
Expected: FAIL — module missing.

- [ ] **Step 3: Implement the helper and wire the worker**

```python
# apps/api/app/worker/sample_files.py
"""Where the worker keeps its private copies of a sample, and how they go away.

Two directories, both created 0o700, files 0o600: the download target
(``upload_temp_dir``) and the Ghidra mirror (``<samples_dir>/.work``). The
``.work`` subdirectory is the boundary between the worker's scratch and the
operator's own corpus in ``samples_dir``: nothing here lists or deletes
outside it.
"""

from __future__ import annotations

import os
import shutil
import time
from pathlib import Path

from app.config import settings
from app.logging_config import get_logger

logger = get_logger("worker.sample_files")

WORK_SUBDIR = ".work"


def _private_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return path


def temp_dir() -> Path:
    return _private_dir(Path(settings.upload_temp_dir).resolve())


def work_dir() -> Path:
    return _private_dir((Path(settings.samples_dir) / WORK_SUBDIR).resolve())


def private_copy(src: Path, dest: Path) -> None:
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as out, src.open("rb") as inp:
        shutil.copyfileobj(inp, out)
    os.chmod(dest, 0o600)


def remove_quietly(path: Path | str | None, *, job_id: str | None = None) -> None:
    if not path:
        return
    p = Path(path)
    try:
        p.unlink(missing_ok=True)
        logger.debug("Removed %s", p, extra={"job_id": job_id})
    except OSError as exc:
        logger.warning(
            "Could not remove %s: %s", p, type(exc).__name__, extra={"job_id": job_id}
        )


def remove_for_sha(sha256: str) -> list[Path]:
    removed: list[Path] = []
    for base in (temp_dir(), work_dir()):
        for candidate in base.glob(f"{sha256}*"):
            if candidate.is_file():
                remove_quietly(candidate)
                removed.append(candidate)
    return removed


def sweep(max_age_s: float = 86_400.0, *, now: float | None = None) -> int:
    cutoff = (now if now is not None else time.time()) - max_age_s
    count = 0
    for base in (temp_dir(), work_dir()):
        for candidate in base.iterdir():
            if candidate.is_file() and candidate.stat().st_mtime < cutoff:
                remove_quietly(candidate)
                count += 1
    if count:
        logger.info("Swept %d stale sample copies from %s and %s", count, temp_dir(), work_dir())
    return count
```

`apps/api/app/config.py`, next to `upload_temp_dir`:
```python
    samples_dir: str = Field(
        default="data/samples",
        description="Host directory bind-mounted into the Ghidra container; the worker's "
        "per-job mirror lives in its .work subdirectory.",
    )
```
`settings_catalog_api.py` `API_READONLY`: `"samples_dir": {"title": "Samples directory", "description": "Host path mounted into the Ghidra MCP container; the worker mirrors each job's binary under its .work subdirectory and removes it when the job ends."}` (and the existing `upload_temp_dir` entry if it is not already listed; check).

Worker (`analysis_worker.py`): the download block uses `sample_files.temp_dir()` for `_worker_tmp`, and after `fget_object` calls `os.chmod(temp_path, 0o600)`; the mirror block becomes

```python
                    host_mirror = sample_files.work_dir() / f"{sample.sha256}{_orig_ext}"
                    sample_files.private_copy(Path(temp_path), host_mirror)
                    static_sample_path = (
                        f"{settings.ghidra_container_samples_path.rstrip('/')}/"
                        f"{sample_files.WORK_SUBDIR}/{sample.sha256}{_orig_ext}"
                    )
```
Initialise `temp_path: str | None = None` and `host_mirror: Path | None = None` before the `try` that downloads, and in the outer `finally:` at line 991 add, before the toolkit teardown:
```python
            sample_files.remove_quietly(temp_path, job_id=job_id)
            sample_files.remove_quietly(host_mirror, job_id=job_id)
```
(Confirm both names are in scope at that `finally`; if the download happens inside a nested function, hoist the two variables to the `run_analysis` scope.) In `startup()` add `sample_files.sweep()` after logging setup, wrapped in `try/except OSError` with a warning.

`samples.py` `delete_sample`, after the MinIO branch (inside the same `others == 0` condition):
```python
        from app.worker import sample_files

        for removed in sample_files.remove_for_sha(sha256):
            logger.info("Removed local copy %s", removed, extra={"sample_id": str(sample_id)})
```

- [ ] **Step 4: Run, lint, types**

Run: `uv run pytest tests/unit/api/test_sample_files.py tests/integration/test_worker_job_lifecycle.py tests/api -q && uv run ruff check apps/api/ tests/ && uv run mypy apps/api/`
Expected: pass; `uv run pytest tests/unit/core/test_settings_catalog.py -q` passes (new read-only entry annotated).

- [ ] **Step 5: Commit**

```bash
git add apps/api/app/worker/sample_files.py apps/api/app/config.py apps/api/app/services/settings_catalog_api.py apps/api/app/worker/analysis_worker.py apps/api/app/api/v1/samples.py tests/unit/api/test_sample_files.py tests/integration/test_worker_job_lifecycle.py
git commit -m "fix(worker): sample copies are private, live under .work, and are removed when the job or the sample goes"
```

---

### Task 6: Attribution and report failures are loud (L14, L15)

**Files:**
- Modify: `src/maljan/analysis/function_hash_attribution.py:120-125`, `src/maljan/pipeline/nodes.py:1900-1902` (inside `make_report_node`), `apps/api/app/worker/analysis_worker.py:740-760, 864`
- Test: `tests/unit/analysis/test_function_hash_attribution_switch.py` (new; put next to the existing attribution tests, grep `function_hash_attribution` under tests/), `tests/integration/test_worker_job_lifecycle.py` (new test)

**Interfaces:**
- Produces: `report_node` returns `{"report_error": f"{type(exc).__name__}: {exc}"}` on a deterministic-build failure; the worker marks the job `failed` with `error_message = report_error or "pipeline produced no report"` when `pipeline_result.get("malware_report")` is falsy.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/analysis/test_function_hash_attribution_switch.py
import logging
from unittest.mock import MagicMock

from maljan.analysis import function_hash_attribution as fha


def test_a_failed_program_switch_skips_attribution_with_a_warning(monkeypatch, caplog):
    http = MagicMock()
    loaded = MagicMock(text='{"program": "sample.exe"}')

    def post(url, **kw):
        if url.endswith("/load_program"):
            return loaded
        raise ConnectionError("switch refused")

    http.post.side_effect = post
    monkeypatch.setattr(fha, "program_name_from_load", lambda text: "sample.exe")
    with caplog.at_level(logging.WARNING):
        result = fha.fetch_function_hashes(http, "http://ghidra", "/data/samples/.work/s.exe")
    assert result == []
    assert any("ConnectionError" in r.getMessage() for r in caplog.records)
    assert not any(c.args[0].endswith("/get_bulk_function_hashes") for c in http.get.call_args_list)
```
(Read the real function name and signature around lines 90-140 of the module and adjust the call; the behaviour under test is: switch failure → `[]`, a warning naming the exception type, no hash fetch.)

Worker test (append to `tests/integration/test_worker_job_lifecycle.py`, same fixtures as `test_mock_pipeline_completes`): monkeypatch the pipeline runner the mock path uses so `pipeline_result` is `{"report_error": "ValueError: boom"}` with no `malware_report` (find where the mock result is produced — grep `MALJAN_MOCK_MODE` and `pipeline_result =` in the worker — and patch that call), run `run_analysis`, assert `result["status"] == "failed"`, `job.status == "failed"` and `"ValueError: boom" in job.error_message`.

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/unit/analysis/test_function_hash_attribution_switch.py tests/integration/test_worker_job_lifecycle.py -q`
Expected: FAIL (switch failure is swallowed; job completes with an empty report).

- [ ] **Step 3: Implement**

`function_hash_attribution.py`:
```python
            try:
                http.post(f"{base}{SWITCH_PATH}", params={SWITCH_PARAM: name}, json={})
                http.post(f"{base}/run_analysis", json={})
            except Exception as exc:  # noqa: BLE001 - the current program is now unknown
                logger.warning(
                    "function-hash fetch: could not switch Ghidra to %s (%s); skipping "
                    "attribution rather than hashing whichever binary is current.",
                    name,
                    type(exc).__name__,
                )
                return []
```

`nodes.py` report node:
```python
        except Exception as exc:  # noqa: BLE001
            logger.error("report_node: deterministic build failed (%s).", exc, exc_info=True)
            return {"report_error": f"{type(exc).__name__}: {exc}"}
```

Worker, before the `AnalysisReport(...)` is built (line ~740):
```python
            if not pipeline_result.get("malware_report"):
                raise RuntimeError(
                    pipeline_result.get("report_error") or "pipeline produced no report"
                )
```
(the existing failure path at line ~943 already sets `job.status = "failed"` and `error_message` from the raised exception; confirm the message reaches `job.error_message` and that `report_error` is also copied into `run_summary` when present).

- [ ] **Step 4: Run, lint, types**

Run: `uv run pytest tests/unit/analysis tests/unit/pipeline tests/integration/test_worker_job_lifecycle.py -q && uv run ruff check src/ apps/api/ tests/ && uv run mypy src/ apps/api/`
Expected: pass.

- [ ] **Step 5: Commit**

```bash
git add src/maljan/analysis/function_hash_attribution.py src/maljan/pipeline/nodes.py apps/api/app/worker/analysis_worker.py tests/unit/analysis/test_function_hash_attribution_switch.py tests/integration/test_worker_job_lifecycle.py
git commit -m "fix(pipeline): a failed Ghidra switch skips attribution loudly, and a report-less run fails the job"
```

---

### Task 7: Internal domain names stay off VirusTotal (L13)

**Files:**
- Modify: `src/maljan/enrichment/orchestrator.py:81-95` (add `_is_public_fqdn`), `:159-175` (`_enrich_domains`), the completion log at `:155`
- Test: `tests/unit/enrichment/test_public_fqdn.py` (new; place next to existing orchestrator tests, grep `orchestrator` under tests/unit)

**Interfaces:**
- Produces: `_is_public_fqdn(name: str) -> bool`; `_PRIVATE_SUFFIXES = (".local", ".localhost", ".internal", ".lan", ".home", ".corp", ".intranet", ".test", ".example", ".invalid", ".onion", ".arpa")`.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/enrichment/test_public_fqdn.py
import pytest

from maljan.enrichment.orchestrator import _is_public_fqdn


@pytest.mark.parametrize(
    "name",
    ["example.com", "cdn.updates.microsoft.com", "xn--80ak6aa92e.com", "a.b.c.d.e.io"],
)
def test_public_names(name):
    assert _is_public_fqdn(name) is True


@pytest.mark.parametrize(
    "name",
    [
        "printer.local", "db.internal", "nas.lan", "router.home", "fs.corp", "wiki.intranet",
        "host.test", "www.example", "x.invalid", "abc.onion", "1.0.0.10.in-addr.arpa",
        "localhost", "LOCALHOST.", "intranet", "10.0.0.5", "::1", "[fe80::1]", "", "a..b",
    ],
)
def test_private_or_malformed_names(name):
    assert _is_public_fqdn(name) is False
```

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/unit/enrichment/test_public_fqdn.py -q` — Expected: ImportError.

- [ ] **Step 3: Implement**

```python
_PRIVATE_SUFFIXES = (
    ".local", ".localhost", ".internal", ".lan", ".home", ".corp", ".intranet",
    ".test", ".example", ".invalid", ".onion", ".arpa",
)


def _is_public_fqdn(name: str) -> bool:
    """True for a name a public reputation service can say something about.

    IP literals, single-label names and the special-use suffixes are internal
    infrastructure: sending them to VirusTotal leaks the operator's naming and
    costs quota for an answer that is always "unknown".
    """
    host = name.strip().rstrip(".").lower().strip("[]")
    if not host or ".." in host or "." not in host:
        return False
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        pass
    return not any(host.endswith(suffix) or host == suffix[1:] for suffix in _PRIVATE_SUFFIXES)
```

In `_enrich_domains`, after the `fqdn` check: `if not _is_public_fqdn(fqdn): skipped += 1; continue`, and return/log the skipped count the way the completion log reports domains and ips (`logger.info("enrich: completed (domains=%d, ips=%d, private_domains_skipped=%d).", ...)` — thread the count back through the return value of `_enrich_domains` or a module-level counter passed in; keep it simple: `_enrich_domains` returns `int` skipped).

- [ ] **Step 4: Run, lint, types**

Run: `uv run pytest tests/unit/enrichment -q && uv run ruff check src/maljan/enrichment tests/unit/enrichment && uv run mypy src/`
Expected: pass.

- [ ] **Step 5: Commit**

```bash
git add src/maljan/enrichment/orchestrator.py tests/unit/enrichment/test_public_fqdn.py
git commit -m "fix(enrichment): internal and special-use domain names are not sent to VirusTotal"
```

---

### Task 8: MCP sidecars get a filtered environment

**Files:**
- Create: `src/maljan/agents/subprocess_env.py`
- Modify: `src/maljan/agents/static_analyst.py:395-398`, `src/maljan/agents/dynamic_analyst.py:88-90`, `src/maljan/agents/network_analyst.py:87-92`, `src/maljan/agents/judge_agent.py:146-151`
- Test: `tests/unit/agents/test_subprocess_env.py` (new)

**Interfaces:**
- Produces:
  ```python
  BASE_KEYS = ("PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "TZ", "JAVA_HOME",
               "PYTHONIOENCODING", "VIRTUAL_ENV", "SYSTEMROOT", "TEMP", "TMP")
  def child_env(extra: Mapping[str, str] | None = None, *, allow: Iterable[str] = (),
                source: Mapping[str, str] | None = None) -> dict[str, str]
  ```
  `source` defaults to `os.environ` (tests pass a dict). Judge agent: `allow=("VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY")`; the other three: no allow list.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/agents/test_subprocess_env.py
from maljan.agents.subprocess_env import BASE_KEYS, child_env

FAKE = {
    "PATH": "/usr/bin", "HOME": "/home/x", "LANG": "C.UTF-8", "JAVA_HOME": "/opt/jdk",
    "OPENAI_API_KEY": "sk-not-for-children", "LLM__FRONTIER__API_KEY": "fk",
    "DATABASE_URL": "postgresql://u:p@db/x", "VIRUSTOTAL_API_KEY": "vt", "ABUSEIPDB_API_KEY": "ab",
    "SETTINGS_ENCRYPTION_KEY": "fernet",
}


def test_base_env_carries_no_secret():
    env = child_env(source=FAKE)
    assert set(env) <= set(BASE_KEYS)
    assert "OPENAI_API_KEY" not in env and "DATABASE_URL" not in env
    assert env["PATH"] == "/usr/bin" and env["JAVA_HOME"] == "/opt/jdk"


def test_allow_list_and_extra_are_the_only_additions():
    env = child_env({"GHIDRA_INSTALL_DIR": "/opt/ghidra"}, allow=("VIRUSTOTAL_API_KEY",), source=FAKE)
    assert env["VIRUSTOTAL_API_KEY"] == "vt"
    assert "ABUSEIPDB_API_KEY" not in env
    assert env["GHIDRA_INSTALL_DIR"] == "/opt/ghidra"


def test_missing_base_keys_are_skipped_not_empty():
    assert "TZ" not in child_env(source={"PATH": "/bin"})
```

Add one test per agent asserting the `env=` handed to `StdioServerParameters` contains no key ending in `_API_KEY` except the allowed ones: patch `StdioServerParameters` in each agent module with a recorder (`MagicMock`), set `os.environ["OPENAI_API_KEY"]` via `monkeypatch.setenv`, call the agent's toolkit-initialisation method with a config whose `mcp.<x>.enabled=True` and `transport="stdio"` (read each module to find the method and the minimum config; for the judge, `VIRUSTOTAL_API_KEY` must be present). If an agent's init cannot run without a live MCP process, patch `MCPLangChainToolkit` with an `AsyncMock`.

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/unit/agents/test_subprocess_env.py -q` — Expected: ImportError.

- [ ] **Step 3: Implement**

```python
# src/maljan/agents/subprocess_env.py
"""The environment an MCP sidecar is started with.

A child process gets what it needs to run and nothing it has no business
reading: no LLM keys, no database URL, no encryption key. Each agent adds
its explicit ``mcp.<server>.env`` mapping and, where the sidecar genuinely
reads a credential (threatintel-mcp reads the two intel keys), names it.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Mapping

BASE_KEYS = (
    "PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "TZ", "JAVA_HOME",
    "PYTHONIOENCODING", "VIRTUAL_ENV", "SYSTEMROOT", "TEMP", "TMP",
)


def child_env(
    extra: Mapping[str, str] | None = None,
    *,
    allow: Iterable[str] = (),
    source: Mapping[str, str] | None = None,
) -> dict[str, str]:
    src = os.environ if source is None else source
    env = {k: src[k] for k in BASE_KEYS if k in src}
    for key in allow:
        if key in src:
            env[key] = src[key]
    if extra:
        env.update(extra)
    return env
```

Agents:
- static: `env = child_env(cfg.mcp.ghidra.env, allow=()); env.setdefault("PYTHONIOENCODING", "utf-8")` (drop the `os.environ.copy()` and the manual update).
- dynamic: `env = child_env(cfg.mcp.cape.env)`.
- network: `env=child_env()`.
- judge: `env=child_env(allow=("VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY"))`.
Remove the now-unused `import os` where applicable.

- [ ] **Step 4: Run, lint, types**

Run: `uv run pytest tests/unit/agents -q && uv run ruff check src/maljan/agents tests/unit/agents && uv run mypy src/`
Expected: pass.

- [ ] **Step 5: Commit**

```bash
git add src/maljan/agents/subprocess_env.py src/maljan/agents/static_analyst.py src/maljan/agents/dynamic_analyst.py src/maljan/agents/network_analyst.py src/maljan/agents/judge_agent.py tests/unit/agents/test_subprocess_env.py
git commit -m "fix(agents): MCP sidecars start with a filtered environment, never the process's API keys"
```

---

### Task 9: WebSocket token only in the subprotocol (L5)

**Files:**
- Modify: `apps/api/app/api/ws.py:120-175`, `apps/web/src/lib/useWebSocket.ts:62-73`
- Test: `tests/api/test_ws_auth.py` (new), `apps/web/e2e/*.spec.ts` that assert a `?token=` URL (grep `token=` under `apps/web/e2e`; update to the protocol form)

**Interfaces:**
- Produces: client `new WebSocket(url, ["maljan.v1", \`maljan.v1.${token}\`])`; server accepts only the `maljan.v1.<jwt>` subprotocol, closes `4401` otherwise; the accepted subprotocol echoed is `maljan.v1` (existing code at `ws.py:50-57`).

- [ ] **Step 1: Write the failing tests**

```python
# tests/api/test_ws_auth.py
import sys
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

_API = Path(__file__).resolve().parents[3] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

from app.api import ws as ws_module  # noqa: E402


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(ws_module.settings, "auth_disabled", False)
    monkeypatch.setattr(ws_module, "decode_token", lambda t: {"sub": "u1"} if t == "good" else None)
    app = FastAPI()
    app.include_router(ws_module.router)
    return TestClient(app)


def test_query_string_token_is_refused(client):
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/ws/analysis/job1?token=good"):
            pass
    assert exc.value.code == 4401


def test_subprotocol_token_is_accepted(client, monkeypatch):
    async def _no_stream(*a, **k):
        return None

    # Read ws.py for the function that starts forwarding Redis events after the
    # auth gate and patch it here so the handshake alone is under test.
    monkeypatch.setattr(ws_module, "_stream_events", _no_stream, raising=False)
    with client.websocket_connect("/ws/analysis/job1", subprotocols=["maljan.v1", "maljan.v1.good"]) as ws:
        assert ws.accepted_subprotocol == "maljan.v1"
```

(Read `ws.py` past line 175 to see what runs after the gate — a job lookup, a Redis subscribe — and patch those so the accepted path returns cleanly; the assertions that matter are the close code for the query form and the accept for the protocol form.)

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/api/test_ws_auth.py -q` — Expected: the query-string test fails (still accepted).

- [ ] **Step 3: Implement**

`ws.py`: delete the `legacy = websocket.query_params.get("token")` block; change the missing-credential close to `await websocket.close(code=4401, reason="Unauthorized: token must be sent as the maljan.v1.<jwt> subprotocol")`; rewrite the docstring's Authentication paragraph to the subprotocol form; update the comment (no "legacy clients still work").

`useWebSocket.ts`:
```ts
    const url = `${WS_BASE}/ws/analysis/${jobId}`;
    const ws = token
      ? new WebSocket(url, ["maljan.v1", `maljan.v1.${token}`])
      : new WebSocket(url);
```

- [ ] **Step 4: Run, lint, types**

Run: `uv run pytest tests/api/test_ws_auth.py -q && uv run ruff check apps/api/ tests/api && uv run mypy apps/api/ && cd apps/web && npx tsc --noEmit && npm run lint`
Expected: pass; grep `token=` in `apps/web/src` returns nothing for the WS URL.

- [ ] **Step 5: Commit**

```bash
git add apps/api/app/api/ws.py apps/web/src/lib/useWebSocket.ts tests/api/test_ws_auth.py apps/web/e2e
git commit -m "fix(ws): the access token travels only in the maljan.v1 subprotocol, never in the URL"
```

---

### Task 10: Refresh token as an HttpOnly cookie — API side (L6)

**Files:**
- Modify: `apps/api/app/schemas/auth.py:24-36`, `apps/api/app/api/v1/auth.py:128-232` (+ new `/logout`), `apps/api/app/config.py` (`cookie_secure`), `apps/api/app/main.py:273-276` (CORS)
- Test: `tests/api/test_auth_cookie.py` (new); rewrite `tests/api/test_auth_refresh_fail_closed.py` to the cookie form; update any test posting `refresh_token` in a body (grep `refresh_token` under tests/)

**Interfaces:**
- Produces:
  - `REFRESH_COOKIE = "maljan_refresh"`, `REFRESH_COOKIE_PATH = "/api/v1/auth"` (module constants in `auth.py`).
  - `TokenResponse(access_token: str, token_type: str = "bearer")` — no `refresh_token`.
  - `POST /api/v1/auth/refresh` with no body; reads the cookie; 401 `{"detail": "No refresh session"}` when absent.
  - `POST /api/v1/auth/logout` → 204, consumes the cookie's jti when present, always clears the cookie.
  - `APISettings.cookie_secure: bool` default `not debug` (implement as a `model_validator` default; the catalog gets a read-only `system` entry).
  - `_set_refresh_cookie(response, token)` / `_clear_refresh_cookie(response)` helpers using `response.set_cookie(key, value, httponly=True, samesite="lax", secure=settings.cookie_secure, path=REFRESH_COOKIE_PATH, max_age=settings.jwt_refresh_token_expire_days * 86400)`.
  - CORS: `allow_credentials=True`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/api/test_auth_cookie.py
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

_API = Path(__file__).resolve().parents[3] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

from app.api.v1 import auth as auth_module  # noqa: E402
from app.api.v1.auth import REFRESH_COOKIE, router  # noqa: E402
from app.database import get_db  # noqa: E402


def _user():
    u = MagicMock()
    u.id = __import__("uuid").uuid4()
    u.is_active = True
    u.hashed_password = "h"
    return u


@pytest.fixture
def client(monkeypatch):
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    db = MagicMock()
    user = _user()
    res = MagicMock()
    res.scalar_one_or_none.return_value = user
    db.execute = AsyncMock(return_value=res)
    app.dependency_overrides[get_db] = lambda: db
    monkeypatch.setattr(auth_module, "verify_password", lambda p, h: True)
    monkeypatch.setattr(auth_module, "is_login_locked", AsyncMock(return_value=False))
    monkeypatch.setattr(auth_module, "clear_login_throttle", AsyncMock())
    monkeypatch.setattr(auth_module, "refresh_token_register", AsyncMock())
    monkeypatch.setattr(auth_module, "refresh_token_consume", AsyncMock(return_value=True))
    monkeypatch.setattr(auth_module, "_audit", AsyncMock())
    monkeypatch.setattr(auth_module, "create_refresh_token", lambda d: ("refresh-jwt", "jti-1"))
    monkeypatch.setattr(auth_module, "create_access_token", lambda d: "access-jwt")
    monkeypatch.setattr(
        auth_module, "decode_token",
        lambda t: {"type": "refresh", "sub": str(user.id), "jti": "jti-1"} if t == "refresh-jwt" else None,
    )
    return TestClient(app)


def test_login_sets_httponly_cookie_and_keeps_refresh_out_of_the_body(client):
    r = client.post("/api/v1/auth/login", json={"email": "a@b.c", "password": "x"})
    assert r.status_code == 200
    assert set(r.json()) == {"access_token", "token_type"}
    cookie = r.headers["set-cookie"]
    assert cookie.startswith(f"{REFRESH_COOKIE}=refresh-jwt")
    assert "HttpOnly" in cookie and "SameSite=lax" in cookie and "Path=/api/v1/auth" in cookie


def test_refresh_reads_the_cookie_and_rotates_it(client):
    client.post("/api/v1/auth/login", json={"email": "a@b.c", "password": "x"})
    r = client.post("/api/v1/auth/refresh")
    assert r.status_code == 200 and r.json()["access_token"] == "access-jwt"
    assert REFRESH_COOKIE in r.headers["set-cookie"]


def test_refresh_without_cookie_is_401(client):
    assert client.post("/api/v1/auth/refresh").status_code == 401


def test_logout_consumes_and_clears(client):
    client.post("/api/v1/auth/login", json={"email": "a@b.c", "password": "x"})
    r = client.post("/api/v1/auth/logout")
    assert r.status_code == 204
    assert "Max-Age=0" in r.headers["set-cookie"] or "expires=" in r.headers["set-cookie"].lower()
    auth_module.refresh_token_consume.assert_awaited()
```

Rewrite `test_auth_refresh_fail_closed.py` to set `client.cookies.set(REFRESH_COOKIE, "t")` and post with no body.

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/api/test_auth_cookie.py tests/api/test_auth_refresh_fail_closed.py -q` — Expected: FAIL (`REFRESH_COOKIE` missing, body has `refresh_token`).

- [ ] **Step 3: Implement**

`schemas/auth.py`: remove `refresh_token` from `TokenResponse`; delete `RefreshTokenRequest`.

`config.py`:
```python
    cookie_secure: bool | None = Field(
        default=None,
        description="Secure flag on the refresh cookie; defaults to the inverse of debug.",
    )

    @model_validator(mode="after")
    def _cookie_secure_default(self) -> "APISettings":
        if self.cookie_secure is None:
            self.cookie_secure = not self.debug
        return self
```
(`API_READONLY["cookie_secure"]`: title "Refresh cookie Secure flag", description "Set on the HttpOnly refresh cookie; true outside debug so the cookie is sent over HTTPS only.")

`auth.py`:
```python
from fastapi import Cookie, Response

REFRESH_COOKIE = "maljan_refresh"
REFRESH_COOKIE_PATH = "/api/v1/auth"


def _set_refresh_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        REFRESH_COOKIE, token, httponly=True, samesite="lax",
        secure=bool(settings.cookie_secure), path=REFRESH_COOKIE_PATH,
        max_age=settings.jwt_refresh_token_expire_days * 86400,
    )


def _clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(REFRESH_COOKIE, path=REFRESH_COOKIE_PATH)
```
`login(..., response: Response)`: after registering the jti, `_set_refresh_cookie(response, refresh)` and return `{"access_token": ..., "token_type": "bearer"}`.
`refresh_token(request, response, db, maljan_refresh: str | None = Cookie(default=None))`: `if not maljan_refresh: raise HTTPException(401, "No refresh session")`; decode `maljan_refresh` instead of the body; on success `_set_refresh_cookie(response, new_refresh)`; on every 401 branch `_clear_refresh_cookie(response)` is not possible on a raised HTTPException — instead return `JSONResponse(status_code=401, content={"detail": ...})` after clearing, or leave the stale cookie (it is useless once consumed); choose the `JSONResponse` form for the reuse-detected branch so a replayed cookie is removed from the browser.
```python
@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
    maljan_refresh: str | None = Cookie(default=None),
) -> Response:
    if maljan_refresh:
        payload = decode_token(maljan_refresh) or {}
        if payload.get("type") == "refresh":
            await refresh_token_consume(payload.get("sub"), payload.get("jti", ""))
            await _audit(db, uuid.UUID(payload["sub"]) if payload.get("sub") else None,
                         "auth.logout", request=request)
    out = Response(status_code=status.HTTP_204_NO_CONTENT)
    _clear_refresh_cookie(out)
    return out
```
`main.py` CORS: add `allow_credentials=True` (origins remain the explicit list; assert in a test that `"*"` is not among them when credentials are on — add to `tests/api/test_docs_routes.py` or a new small test).

- [ ] **Step 4: Run, lint, types**

Run: `uv run pytest tests/api tests/unit/api -q && uv run ruff check apps/api/ tests/ && uv run mypy apps/api/`
Expected: pass; `grep -rn "refresh_token" apps/api/app/schemas apps/api/app/api/v1/auth.py` shows only the cookie helpers and the throttle imports.

- [ ] **Step 5: Commit**

```bash
git add apps/api/app/schemas/auth.py apps/api/app/api/v1/auth.py apps/api/app/config.py apps/api/app/services/settings_catalog_api.py apps/api/app/main.py tests/api
git commit -m "feat(auth): the refresh token is an HttpOnly cookie; login answers with the access token only; logout consumes and clears"
```

---

### Task 11: Refresh cookie — web client and e2e (L6)

**Files:**
- Modify: `apps/web/src/lib/api.ts:255-292, 380-395, 420-425` (+ `logout()`), `apps/web/src/lib/auth.tsx:100-200` and the `logout` implementation, `apps/web/e2e/fixtures.ts:40-45`, `apps/web/e2e/mocks.ts` (`/auth/login`, `/auth/refresh`, new `/auth/logout`), `apps/web/e2e/auth.spec.ts`
- Test: `apps/web/e2e/auth.spec.ts` (assertions below); run only `npx playwright test e2e/auth.spec.ts --project=chromium`

**Interfaces:**
- Consumes: Task 10's cookie contract.
- Produces: `api.login()` → `{access_token, token_type}` with `credentials: "include"`; `api.refresh()` takes no argument, `credentials: "include"`; `api.logout()` → 204, `credentials: "include"`; `localStorage` holds only `access_token`; refresh is scheduled from the access token's `exp` (60 s before, min 5 s); the cross-tab lock stays (`navigator.locks`, name unchanged) and the "another tab refreshed first" check compares the stored access token instead of the refresh token.

- [ ] **Step 1: Write the failing e2e assertions**

In `apps/web/e2e/auth.spec.ts` add (mock routes: `POST /api/v1/auth/login` → `{access_token: "mock_access_token", token_type: "bearer"}`; `POST /api/v1/auth/refresh` → same; `POST /api/v1/auth/logout` → 204):

```ts
test("login keeps only the access token in storage and sends credentials", async ({ page }) => {
  await page.goto("/login");
  const [req] = await Promise.all([
    page.waitForRequest((r) => r.url().endsWith("/api/v1/auth/login") && r.method() === "POST"),
    (async () => {
      await page.getByLabel(/email/i).fill("a@b.c");
      await page.getByLabel(/password/i).fill("pw");
      await page.getByRole("button", { name: /sign in/i }).click();
    })(),
  ]);
  expect(await req.headerValue("cookie")).not.toBeNull; // the browser decides; the request must be credentialed
  await page.waitForURL(/dashboard/);
  const stored = await page.evaluate(() => Object.keys(localStorage));
  expect(stored).toContain("access_token");
  expect(stored).not.toContain("refresh_token");
});

test("sign out calls logout and clears the access token", async ({ authenticatedPage: page }) => {
  await page.goto("/dashboard");
  const logout = page.waitForRequest((r) => r.url().endsWith("/api/v1/auth/logout"));
  await page.getByRole("button", { name: /sign out/i }).click();
  await logout;
  await page.waitForURL(/login/);
  expect(await page.evaluate(() => localStorage.getItem("access_token"))).toBeNull();
});
```
(Playwright cannot see `credentials: "include"` directly; assert the request was made and, in a unit-style check, read `api.ts` in review. If the app's fetch wrapper exposes options for testing, prefer asserting them.)

- [ ] **Step 2: Run to verify failure**

Run: `cd apps/web && npx playwright test e2e/auth.spec.ts --project=chromium` — Expected: the storage assertion fails (`refresh_token` present) and the logout request never happens.

- [ ] **Step 3: Implement**

`api.ts`:
```ts
  login(email: string, password: string) {
    return this.request<{ access_token: string; token_type: string }>(
      "/api/v1/auth/login",
      { method: "POST", body: JSON.stringify({ email, password }), credentials: "include" }
    );
  }
  refresh() {
    return this.request<{ access_token: string; token_type: string }>(
      "/api/v1/auth/refresh",
      { method: "POST", credentials: "include" }
    );
  }
  logout() {
    return this.request<Record<string, never>>("/api/v1/auth/logout", {
      method: "POST",
      credentials: "include",
    });
  }
```
Remove every `localStorage.removeItem("refresh_token")` (four sites) and every `setItem("refresh_token")`.

`auth.tsx`: `runRefresh(scheduledWith, ...)` compares `localStorage.getItem("access_token")` with `scheduledWith`; on success stores only the access token and re-arms from it; `scheduleRefresh(accessToken, ...)` decodes the access token's expiry; `startRefreshTimer(accessToken)`; every call site that passed the refresh token now passes the access token; `logout()` calls `api.logout().catch(() => undefined)` before clearing storage and redirecting.

`e2e/fixtures.ts` `seedSession`: only `access_token`. `e2e/mocks.ts`: login/refresh/logout routes with the new shapes; any spec reading `refresh_token` is updated.

- [ ] **Step 4: Run, lint, types**

Run: `cd apps/web && npx tsc --noEmit && npm run lint && npx playwright test e2e/auth.spec.ts e2e/settings-configuration.spec.ts --project=chromium`
Expected: pass; `grep -rn "refresh_token" apps/web/src apps/web/e2e` returns nothing.

- [ ] **Step 5: Commit**

```bash
git add apps/web/src/lib/api.ts apps/web/src/lib/auth.tsx apps/web/e2e
git commit -m "feat(web): sessions refresh through the HttpOnly cookie; only the access token is kept in the browser"
```

---

### Task 12: No inline scripts in the CSP; the report page carries a nonce (L7)

**Files:**
- Modify: `apps/api/app/middleware/security_headers_middleware.py:21-33, 58-80`, `src/maljan/reporting/renderers/html.py:161-183`, `apps/api/app/api/v1/reports.py:148-175` (+ the service method `get_malware_report_html` so the nonce reaches the renderer; grep it under `apps/api/app/services`)
- Test: `tests/api/test_csp_headers.py` (new), `tests/unit/reporting/test_html_nonce.py` (new)

**Interfaces:**
- Produces:
  - `_DEFAULT_CSP` without `'unsafe-inline'` in `script-src`; `_DOCS_CSP = "default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline' cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' cdn.jsdelivr.net; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"` applied when `request.url.path` starts with `/docs`, `/redoc` or equals `/openapi.json`.
  - `HTMLRenderer.render(report, *, embed_figures=True, nonce: str | None = None)`; with a nonce the `<style>` tag is `<style nonce="…">`.
  - Report route: `nonce = base64.b64encode(secrets.token_bytes(16)).decode()`; response header `Content-Security-Policy: default-src 'none'; img-src data:; style-src 'nonce-<nonce>'; style-src-attr 'unsafe-inline'; script-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'` (the middleware's `setdefault` leaves it alone).

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/reporting/test_html_nonce.py
from maljan.reporting.renderers.html import HTMLRenderer


def test_style_tag_carries_the_nonce(minimal_report):  # reuse the fixture the existing html tests use
    out = HTMLRenderer().render(minimal_report, embed_figures=False, nonce="abc123==")
    assert '<style nonce="abc123==">' in out
    assert "<script" not in out


def test_no_nonce_means_no_attribute(minimal_report):
    assert "<style>" in HTMLRenderer().render(minimal_report, embed_figures=False)
```
(Find the existing renderer test module under `tests/unit/reporting` and its report fixture; name it accordingly.)

```python
# tests/api/test_csp_headers.py
import sys
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

_API = Path(__file__).resolve().parents[3] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

from app.middleware.security_headers_middleware import SecurityHeadersMiddleware  # noqa: E402


def _app():
    app = FastAPI(docs_url="/docs", openapi_url="/openapi.json")
    app.add_middleware(SecurityHeadersMiddleware)

    @app.get("/plain")
    def plain():
        return {"ok": True}

    return TestClient(app)


def test_default_policy_has_no_inline_script():
    csp = _app().get("/plain").headers["content-security-policy"]
    script = [d for d in csp.split(";") if d.strip().startswith("script-src")][0]
    assert "'unsafe-inline'" not in script


def test_docs_get_the_swagger_policy():
    csp = _app().get("/docs").headers["content-security-policy"]
    assert "'unsafe-inline'" in csp and "cdn.jsdelivr.net" in csp
```
Add a route-level test in the existing reports test module (grep `html` under `tests/api`) asserting the HTML response header contains `style-src 'nonce-` and that the same nonce appears in the body.

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/unit/reporting/test_html_nonce.py tests/api/test_csp_headers.py -q` — Expected: FAIL.

- [ ] **Step 3: Implement**

Middleware: two policies; in `dispatch`, `policy = _DOCS_CSP if request.url.path.startswith(("/docs", "/redoc")) or request.url.path == "/openapi.json" else self._csp`.

Renderer: `render(..., nonce: str | None = None)`; `style_open = f'<style nonce="{escape(nonce)}">' if nonce else "<style>"`.

Report route: generate the nonce, pass it through the service to the renderer (`svc.get_malware_report_html(report_id, user, nonce=nonce)`), and set the header on the `Response`:
```python
    headers = _disposition(rendered.filename, attachment=download)
    headers["Content-Security-Policy"] = (
        "default-src 'none'; img-src data:; "
        f"style-src 'nonce-{nonce}'; style-src-attr 'unsafe-inline'; "
        "script-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
    )
```
(`style-src-attr 'unsafe-inline'` is for the one `style="string-set: …"` span the PDF pipeline needs; attribute styles cannot execute script.)

- [ ] **Step 4: Run, lint, types**

Run: `uv run pytest tests/unit/reporting tests/api -q && uv run ruff check src/maljan/reporting apps/api/ tests/ && uv run mypy src/ apps/api/`
Expected: pass.

- [ ] **Step 5: Commit**

```bash
git add apps/api/app/middleware/security_headers_middleware.py src/maljan/reporting/renderers/html.py apps/api/app/api/v1/reports.py apps/api/app/services tests/unit/reporting/test_html_nonce.py tests/api
git commit -m "fix(api): no inline scripts in the CSP; the report page styles itself through a per-response nonce"
```

---

### Task 13: Compose publishes nothing and bakes in no secret; Qdrant gets an API key (M2)

**Files:**
- Modify: `docker/docker-compose.yml` (every `ports:`; `GHIDRA_MCP_AUTH_TOKEN`; redis `command`; qdrant `environment`; api/worker `REDIS_URL`/`QDRANT_API_KEY`), `README.md` (compose section), `src/maljan/core/config.py:374-390` (`MemoryConfig.qdrant_api_key: SecretStr | None = None`), `src/maljan/core/settings_annotations.py` (`memory.qdrant_api_key`), `apps/api/app/config.py:143` (`qdrant_api_key: SecretStr | None`), `apps/api/app/services/settings_catalog_api.py` (`API_READONLY["qdrant_api_key"]`), `src/maljan/memory/qdrant_store.py:84-96`, `src/maljan/memory/function_hash_store.py:78-90`, every `QdrantStore(`/`FunctionHashStore(` construction (grep in `src/maljan/core/container.py`, `apps/api/app/api/v1/system.py`, `apps/api/app/worker/enrich_worker.py`), `apps/api/app/services/settings_probes.py:170-182`
- Create: `docker/.env.example`, `tests/unit/test_compose_config.py`
- Test: `tests/unit/memory/test_store_api_key.py` (new), `tests/unit/test_compose_config.py`, `tests/unit/api/test_settings_probes.py` (qdrant probe sends the header)

**Interfaces:**
- Produces: `QdrantStore(url, collection=..., api_key: str | None = None)`, `FunctionHashStore(url, collection=..., api_key: str | None = None)` → `QdrantClient(url=url, api_key=api_key)`; `MemoryConfig.qdrant_api_key: SecretStr | None`; `APISettings.qdrant_api_key: SecretStr | None`; the qdrant probe adds header `api-key` when `v.get("api_key")` is set (`_INPUTS["qdrant"]` gains `"core.memory.qdrant_api_key": "api_key"`); compose variables `BIND_ADDRESS` (default `127.0.0.1`), `GHIDRA_MCP_AUTH_TOKEN`, `REDIS_PASSWORD`, `QDRANT_API_KEY` (required).

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/memory/test_store_api_key.py
from unittest.mock import MagicMock

import pytest


@pytest.mark.parametrize("module,cls", [("qdrant_store", "QdrantStore"), ("function_hash_store", "FunctionHashStore")])
def test_api_key_is_forwarded_to_the_client(monkeypatch, module, cls):
    import importlib

    mod = importlib.import_module(f"maljan.memory.{module}")
    fake = MagicMock()
    monkeypatch.setattr("qdrant_client.QdrantClient", fake)
    getattr(mod, cls)(url="http://q:6333", api_key="k")
    assert fake.call_args.kwargs == {"url": "http://q:6333", "api_key": "k"}
    fake.reset_mock()
    getattr(mod, cls)(url="http://q:6333")
    assert fake.call_args.kwargs == {"url": "http://q:6333", "api_key": None}
```

```python
# tests/unit/test_compose_config.py
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker not installed")
def test_compose_binds_loopback_and_requires_the_secrets(tmp_path):
    env = {
        "GHIDRA_MCP_AUTH_TOKEN": "t" * 32, "REDIS_PASSWORD": "p" * 32, "QDRANT_API_KEY": "q" * 32,
        "PATH": "/usr/bin:/bin",
    }
    out = subprocess.run(
        ["docker", "compose", "-f", str(ROOT / "docker" / "docker-compose.yml"), "config"],
        env=env, capture_output=True, text=True, check=True,
    ).stdout
    assert "maljan_ghidra_secret_2026" not in out
    for published in re.findall(r"host_ip: (\S+)", out):
        assert published == "127.0.0.1"
    assert "0.0.0.0" not in out
    missing = subprocess.run(
        ["docker", "compose", "-f", str(ROOT / "docker" / "docker-compose.yml"), "config"],
        env={"PATH": "/usr/bin:/bin"}, capture_output=True, text=True,
    )
    assert missing.returncode != 0 and "GHIDRA_MCP_AUTH_TOKEN" in missing.stderr
```

Probe test (append to `tests/unit/api/test_settings_probes.py`): a `MockTransport` handler asserting `req.headers.get("api-key") == "k"` when `probe_qdrant({"url": ..., "collection": "c", "api_key": "k"})` is called, and header absent otherwise.

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/unit/memory/test_store_api_key.py tests/unit/test_compose_config.py tests/unit/api/test_settings_probes.py -q` — Expected: FAIL.

- [ ] **Step 3: Implement**

Stores: add `api_key: str | None = None` to both constructors and `QdrantClient(url=url, api_key=api_key)`. Core config: `qdrant_api_key: SecretStr | None = None` in `MemoryConfig` with annotation `{"title": "Qdrant API key", "description": "API key sent with every Qdrant request when the server enforces one (compose does); empty means no authentication, which is fine for a loopback-only server."}`. Container and API constructions pass `api_key=cfg.memory.qdrant_api_key.get_secret_value() if cfg.memory.qdrant_api_key else None` (core) or the API setting (API-side stores). Probe: `_get(url, headers={"api-key": key} if key else None)`.

Compose (each service):
```yaml
    ports:
      - "${BIND_ADDRESS:-127.0.0.1}:${POSTGRES_PORT:-5432}:5432"
```
(same pattern for redis 6379, qdrant 6333 and 6334, minio 9000/9001, ghidra 8089, api 8000, web 3000);
```yaml
  redis:
    command: ["redis-server", "--requirepass", "${REDIS_PASSWORD:?set REDIS_PASSWORD in docker/.env (see README)}", "--appendonly", "yes"]
  qdrant:
    environment:
      QDRANT__SERVICE__API_KEY: ${QDRANT_API_KEY:?set QDRANT_API_KEY in docker/.env (see README)}
  ghidra-mcp:
    environment:
      GHIDRA_MCP_AUTH_TOKEN: ${GHIDRA_MCP_AUTH_TOKEN:?set GHIDRA_MCP_AUTH_TOKEN in docker/.env (see README)}
  api / worker:
    environment:
      REDIS_URL: redis://:${REDIS_PASSWORD}@redis:6379/0
      QDRANT_API_KEY: ${QDRANT_API_KEY}
      MEMORY__QDRANT_API_KEY: ${QDRANT_API_KEY}
```
(keep the existing redis command flags; read the file). Healthchecks that call `redis-cli ping` need `-a "$$REDIS_PASSWORD"`.

`docker/.env.example`:
```
# Required by docker compose. Generate all three with:
#   python -c "import secrets; [print(f'{k}={secrets.token_urlsafe(32)}') for k in ('GHIDRA_MCP_AUTH_TOKEN','REDIS_PASSWORD','QDRANT_API_KEY')]"
GHIDRA_MCP_AUTH_TOKEN=
REDIS_PASSWORD=
QDRANT_API_KEY=
# Where published ports bind. 127.0.0.1 keeps every service off the network;
# set 0.0.0.0 only behind a firewall or reverse proxy you control.
BIND_ADDRESS=127.0.0.1
```
README compose section: the three variables, the generation one-liner, the loopback default and `BIND_ADDRESS`.

- [ ] **Step 4: Run, lint, types**

Run: `uv run pytest tests/unit/memory tests/unit/test_compose_config.py tests/unit/api/test_settings_probes.py tests/unit/core/test_settings_catalog.py -q && uv run ruff check src/ apps/api/ tests/ && uv run mypy src/ apps/api/`
Expected: pass (the compose test is skipped where docker is absent, runs in CI).

- [ ] **Step 5: Commit**

```bash
git add docker/docker-compose.yml docker/.env.example README.md src/maljan/core/config.py src/maljan/core/settings_annotations.py apps/api/app/config.py apps/api/app/services/settings_catalog_api.py src/maljan/memory/qdrant_store.py src/maljan/memory/function_hash_store.py src/maljan/core/container.py apps/api/app/api/v1/system.py apps/api/app/worker/enrich_worker.py apps/api/app/services/settings_probes.py tests/unit/memory/test_store_api_key.py tests/unit/test_compose_config.py tests/unit/api/test_settings_probes.py
git commit -m "fix(compose): loopback-only ports, required secrets instead of a baked-in token, Redis password and Qdrant API key end to end"
```

---

### Task 14: Evaluation harnesses count what they drop (M5)

**Files:**
- Create: `tests/evaluation/_tally.py`
- Modify: `tests/evaluation/eval_attck_case_rag.py:268-283, 338`, `tests/evaluation/eval_family_rag_retrieval.py:47-64, 137`, `tests/evaluation/eval_fallback_bundle_content.py:97-101, 212`, `tests/evaluation/eval_confidence_cap.py:142-160, 236-246, 286`, `tests/evaluation/eval_dynamic_vs_static.py:413-420, 428-434, 658-666, 697`, `tests/evaluation/paper_facts.py:55-59` (+ new check)
- Test: `tests/evaluation/test_tally.py`, `tests/evaluation/test_paper_facts_population.py`

**Interfaces:**
- Produces:
  ```python
  # tests/evaluation/_tally.py
  @dataclass
  class Tally:
      attempted: int = 0
      parsed: int = 0
      scored: int = 0
      dropped: Counter[str] = field(default_factory=Counter)
      def attempt(self) -> None
      def parse_ok(self) -> None
      def score_ok(self) -> None
      def drop(self, reason: str, *, detail: str | None = None) -> None   # counts and prints one stderr line
      def as_dict(self) -> dict[str, object]   # {"attempted", "parsed", "scored", "dropped": {reason: n}}
  ```
  Producers write `"population": tally.as_dict()` beside their existing counts. `paper_facts.check_population(name: str, blob: Any) -> None` raises `FactError` when `population` is present and `attempted != scored` and `sum(dropped.values()) != attempted - scored`; `load()` calls it.

- [ ] **Step 1: Write the failing tests**

```python
# tests/evaluation/test_tally.py
from tests.evaluation._tally import Tally  # adjust to the import style paper tests use (sys.path or package)


def test_tally_counts_and_serialises(capsys):
    t = Tally()
    for _ in range(3):
        t.attempt()
    t.parse_ok(); t.score_ok()
    t.parse_ok(); t.drop("no_profile_text")
    t.drop("unparseable", detail="NE header")
    assert t.as_dict() == {"attempted": 3, "parsed": 2, "scored": 1, "dropped": {"no_profile_text": 1, "unparseable": 1}}
    assert "unparseable" in capsys.readouterr().err
```

```python
# tests/evaluation/test_paper_facts_population.py
import pytest

from tests.evaluation import paper_facts as pf


def test_population_gate():
    pf.check_population("x.json", {"samples": 3})  # no population: untouched
    pf.check_population("x.json", {"population": {"attempted": 5, "parsed": 5, "scored": 5, "dropped": {}}})
    pf.check_population("x.json", {"population": {"attempted": 5, "parsed": 4, "scored": 3, "dropped": {"a": 2}}})
    with pytest.raises(pf.FactError):
        pf.check_population("x.json", {"population": {"attempted": 5, "parsed": 4, "scored": 3, "dropped": {}}})
```
(Look at how `tests/evaluation/test_*.py` import `paper_facts` today and follow that.)

- [ ] **Step 2: Run to verify failure**

Run: `uv run pytest tests/evaluation/test_tally.py tests/evaluation/test_paper_facts_population.py -q` — Expected: ImportError / AttributeError.

- [ ] **Step 3: Implement**

```python
# tests/evaluation/_tally.py
"""One counter every evaluation harness reports its population with.

A harness that skips a sample it cannot parse must say so: the artefact then
carries attempted / parsed / scored and the reasons, and ``paper_facts``
refuses an artefact whose denominator shrank without explanation.
"""

from __future__ import annotations

import sys
from collections import Counter
from dataclasses import dataclass, field


@dataclass
class Tally:
    attempted: int = 0
    parsed: int = 0
    scored: int = 0
    dropped: Counter[str] = field(default_factory=Counter)

    def attempt(self) -> None:
        self.attempted += 1

    def parse_ok(self) -> None:
        self.parsed += 1

    def score_ok(self) -> None:
        self.scored += 1

    def drop(self, reason: str, *, detail: str | None = None) -> None:
        self.dropped[reason] += 1
        print(f"  drop [{reason}]{': ' + detail if detail else ''}", file=sys.stderr)

    def as_dict(self) -> dict[str, object]:
        return {
            "attempted": self.attempted,
            "parsed": self.parsed,
            "scored": self.scored,
            "dropped": dict(sorted(self.dropped.items())),
        }
```

Producers, at each site named above: create `tally = Tally()` before the loop, `tally.attempt()` per member, `tally.drop("unparseable", detail=type(exc).__name__)` in the except, `tally.drop("no_static")` on `static is None`, `tally.drop("no_profile_text")` on empty text, `tally.parse_ok()` / `tally.score_ok()` where a row is appended; for the checkpoint readers in `eval_fallback_bundle_content.py` and `eval_dynamic_vs_static.py` use `tally.drop("torn_line")`. Write `"population": tally.as_dict()` into the result dict next to `"samples"` (for `eval_confidence_cap.py` inside `"summary"`).

`paper_facts.py`:
```python
def check_population(name: str, blob: Any) -> None:
    pop = blob.get("population") if isinstance(blob, dict) else None
    if pop is None and isinstance(blob, dict):
        pop = (blob.get("summary") or {}).get("population") if isinstance(blob.get("summary"), dict) else None
    if not pop:
        return
    attempted, scored = int(pop["attempted"]), int(pop["scored"])
    explained = sum(int(v) for v in (pop.get("dropped") or {}).values())
    if attempted != scored and explained != attempted - scored:
        raise FactError(
            f"{name}: {attempted} attempted, {scored} scored, {explained} drops explained"
        )


def load(name: str) -> Any:
    path = _EVAL_DIR / name
    if not path.exists():
        raise FactError(f"missing artifact: {name}")
    blob = json.loads(path.read_text())
    check_population(name, blob)
    return blob
```

- [ ] **Step 4: Run, lint, and the byte-identity gate**

Run: `uv run pytest tests/evaluation -q && uv run ruff check tests/evaluation && make facts && git status --short tests/evaluation/`
Expected: tests pass; `make facts` exits 0 and `git status` shows no modified artefact (no evaluation is re-run; only the scripts changed).

- [ ] **Step 5: Commit**

```bash
git add tests/evaluation/_tally.py tests/evaluation/eval_attck_case_rag.py tests/evaluation/eval_family_rag_retrieval.py tests/evaluation/eval_fallback_bundle_content.py tests/evaluation/eval_confidence_cap.py tests/evaluation/eval_dynamic_vs_static.py tests/evaluation/paper_facts.py tests/evaluation/test_tally.py tests/evaluation/test_paper_facts_population.py
git commit -m "eval: every harness reports attempted, parsed and scored, and the paper gate refuses an unexplained shrink"
```

---

### Task 15: Analyst-parallelism tests run again

**Files:**
- Modify: `tests/unit/pipeline/test_analyst_parallelism.py` (whole file)

**Interfaces:**
- Produces: helper `_edges(graph) -> set[tuple[str, str]]` using `graph.get_graph().edges` (each edge has `.source` and `.target`); no `pytest.skip` remains; fixtures `fake_container` (`llm.parallel_analysts = True`) and `sequential_container` (`False`).

- [ ] **Step 1: Make the tests fail honestly**

Replace every
```python
    builder = getattr(graph, "builder", None) or graph
    edges = getattr(builder, "edges", None)
    if edges is None:
        pytest.skip("LangGraph internal layout changed; revisit this test.")
```
with `edge_set = _edges(graph)` and delete the tuple-unpacking loops; add
```python
def _edges(graph: Any) -> set[tuple[str, str]]:
    drawable = graph.get_graph()
    return {(e.source, e.target) for e in drawable.edges}
```
and `container.config.llm.parallel_analysts = True` in `fake_container`. `START` from `langgraph.graph` is the string `"__start__"`; the drawable graph names it the same — assert against `START`.

- [ ] **Step 2: Run**

Run: `uv run pytest tests/unit/pipeline/test_analyst_parallelism.py -v`
Expected: 5 tests, all PASS, none skipped. If a topology assertion fails, the pipeline builder, not the test, is wrong — stop and report rather than loosening the assertion.

- [ ] **Step 3: Lint and commit**

Run: `uv run ruff check tests/unit/pipeline && uv run ruff format --check tests/unit/pipeline`

```bash
git add tests/unit/pipeline/test_analyst_parallelism.py
git commit -m "test(pipeline): the parallelism tests read the public graph and no longer skip"
```

---

### Task 16: Semgrep in CI

**Files:**
- Create: `.semgrepignore`
- Modify: `.github/workflows/ci.yml` (new job after `quality`), `Makefile` (new `semgrep` target next to `lint`)

**Interfaces:**
- Produces: job `semgrep` (name "Semgrep") running `semgrep scan --config p/python --config p/security-audit --error --metrics=off src/ apps/api/ network-mcp/ threatintel-mcp/ scripts/`; `make semgrep` runs the same command locally via `uv run --with semgrep==1.176.0 semgrep …`.

- [ ] **Step 1: Run semgrep locally first**

Run: `uv run --with semgrep==1.176.0 semgrep scan --config p/python --config p/security-audit --error --metrics=off src/ apps/api/ network-mcp/ threatintel-mcp/ scripts/ 2>&1 | tail -40`
Expected: a list of findings, or none. For each finding: fix it if it is real; if it is a documented false positive, add `# nosemgrep: <rule-id>` on that line with a trailing reason (the file already uses this form in twelve places). Do not add a global ignore for a rule.

- [ ] **Step 2: Add the ignore file, the job and the target**

`.semgrepignore`:
```
other/
tests/
apps/web/
data/
.venv/
node_modules/
```
`ci.yml`, after the `quality` job:
```yaml
  semgrep:
    name: Semgrep
    runs-on: ubuntu-latest
    needs: quality
    steps:
      - name: Checkout
        uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.13"
      - name: Install semgrep
        run: pip install semgrep==1.176.0
      - name: Scan
        run: semgrep scan --config p/python --config p/security-audit --error --metrics=off src/ apps/api/ network-mcp/ threatintel-mcp/ scripts/
```
Makefile: `semgrep:` target with the `uv run --with` form and a one-line comment that CI runs the same rulesets.

- [ ] **Step 3: Verify**

Run: `make semgrep` → exit 0; `uv run python -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))"` → no error.

- [ ] **Step 4: Commit**

```bash
git add .semgrepignore .github/workflows/ci.yml Makefile
git commit -m "ci: semgrep over the Python code with the python and security-audit rulesets"
```

(After the first green run on the PR, add "Semgrep" to the required checks of `main` — the operator does this in GitHub; note it in the PR body.)

---

### Task 17: Documentation and templates

**Files:**
- Modify: `README.md` (security section: cookie sessions, WebSocket subprotocol, docs only in debug, throttle degradation and where to see it, sample copies), `.env.example` and `apps/api/.env.example` (`SAMPLES_DIR`, `COOKIE_SECURE`, `QDRANT_API_KEY` / `MEMORY__QDRANT_API_KEY`, `TRUSTED_PROXY_IPS` CIDR example already there), `docs/specs/2026-09-03-security-hardening-design.md` (status line)

- [ ] **Step 1: Write**

Each new variable is commented out with a one-line explanation and its default; the README paragraphs state only what the code does (verify each claim against the task that landed it: cookie name and path, 4401 close code, `throttle_degraded` field names, `.work` directory, loopback binding).

- [ ] **Step 2: Verify and commit**

Run: `uv run pytest tests/unit/scripts -q` (env-example parsers, if any) and `grep -n "refresh_token" README.md .env.example apps/api/.env.example` → nothing.

```bash
git add README.md .env.example apps/api/.env.example docs/specs/2026-09-03-security-hardening-design.md
git commit -m "docs: sessions, sockets, sample copies and compose secrets after the hardening"
```

---

## Verification before merge

1. `make lint format-check typecheck`
2. `uv run pytest tests/ -q` (all green; the pinned paper count is unaffected)
3. `make facts && git status --short tests/evaluation/` (byte-identical)
4. `cd apps/web && npx tsc --noEmit && npm run lint && npm run build`
5. `cd apps/web && npx playwright test e2e/auth.spec.ts e2e/settings-configuration.spec.ts --project=chromium --project=firefox` (stop any `next dev` first)
6. `make semgrep`
7. Live run (recipe in memory `local-observation-run-recipe`, CPU cap first): login sets the `maljan_refresh` cookie and `localStorage` has no refresh token; `/refresh` works; logout clears; a job's WebSocket connects (browser devtools shows the subprotocol); `/reports/{id}/html` carries `style-src 'nonce-…'`; `/system/status` shows `throttle.available: true`; stopping the Redis container flips it to `false`, `/refresh` answers 401, restarting Redis restores within 30 s; `data/uploads/.tmp` and `data/samples/.work` are empty after the job.

## Self-review notes

- Spec coverage: §1→T1, §2→T5, §3→T3, §4→T13, §5→T14, §6→T2, §7→T9, §8→T10+T11, §9→T12, §10→T4 (+T13 for the uv pin's file), §11→T6+T7, §12→T8, §13→T15, §14→T16, docs→T17. Out-of-scope items untouched.
- Type consistency: `observability.throttle` / `observability.counters` (T1, T2, T6 status), `child_env` (T8), `Tally.as_dict()` → `"population"` (T14), `REFRESH_COOKIE` (T10, T11), `WORK_SUBDIR` (T5), `qdrant_api_key` on both settings models and both stores (T13).
- Order: T1 before T2 (counter lives in T1's module); T10 before T11; everything else independent. Suggested execution order is the numbering.

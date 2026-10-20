"""Auth-policy ceilings, session-only settings writes, and the explicit memory adoption."""

from __future__ import annotations

import logging
import uuid
from contextlib import asynccontextmanager
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from app.deps import SESSION_ONLY_DETAIL, require_admin, require_admin_session
from app.runtime_config import RuntimeConfig
from app.services.settings_catalog_api import API_DEFAULTS, api_catalog, validate_editable_api_value
from tests.credential_shapes import prefixed_key

# ── F6-L1: every settings write is session-only ─────────────────────────

# Routes on the settings router that change no stored setting: read-only
# helpers, and the ATT&CK cache (attck/update is state-changing but writes no
# setting, and holds no auth, secret or provider value).
_NOT_SETTINGS_WRITES = {
    ("POST", "/settings/validate-condition"),
    ("POST", "/settings/lint-teams"),
    ("POST", "/settings/sandbox-rest/preview"),
    ("POST", "/settings/attck/check"),
    ("POST", "/settings/attck/update"),
}


def _calls(route: APIRoute) -> set[Any]:
    return {d.call for d in route.dependant.dependencies}


def test_every_settings_write_route_takes_a_session_not_an_api_key() -> None:
    from app.api.v1.settings import router

    open_writes = []
    for route in router.routes:
        assert isinstance(route, APIRoute)
        for method in route.methods - {"GET", "HEAD", "OPTIONS"}:
            if require_admin_session in _calls(route):
                continue
            if (method, route.path) not in _NOT_SETTINGS_WRITES:
                open_writes.append((method, route.path))
    assert open_writes == []


def test_the_report_format_accept_route_that_saves_settings_is_session_only() -> None:
    from app.api.v1.sandbox_reports import formats_router

    routes = [
        r for r in formats_router.routes if isinstance(r, APIRoute) and r.path.endswith("/accept")
    ]
    assert routes
    for route in routes:
        assert require_admin_session in _calls(route)


def test_the_memory_adoption_route_is_session_only() -> None:
    from app.api.v1.system import router

    routes = [r for r in router.routes if isinstance(r, APIRoute) and r.path.endswith("/ltm/adopt")]
    assert len(routes) == 1
    assert require_admin_session in _calls(routes[0])


# ── F10-L1: ceilings ────────────────────────────────────────────────────

_BOUNDS = {
    "jwt_access_token_expire_minutes": (1, 1440),
    "jwt_refresh_token_expire_days": (1, 90),
    "login_max_attempts": (1, 100),
    "login_lockout_seconds": (60, 86400),
}


def test_defaults_are_unchanged_and_inside_the_ceilings() -> None:
    assert API_DEFAULTS["jwt_access_token_expire_minutes"] == 30
    assert API_DEFAULTS["jwt_refresh_token_expire_days"] == 7
    assert API_DEFAULTS["login_max_attempts"] == 10
    assert API_DEFAULTS["login_lockout_seconds"] == 300
    for name, (low, high) in _BOUNDS.items():
        assert low <= API_DEFAULTS[name] <= high


@pytest.mark.parametrize("name", sorted(_BOUNDS))
def test_a_save_outside_the_ceilings_is_refused(name: str) -> None:
    entry = next(e for e in api_catalog() if e.path == name)
    low, high = _BOUNDS[name]
    assert (entry.minimum, entry.maximum) == (low, high)
    assert validate_editable_api_value(entry, low) is None
    assert validate_editable_api_value(entry, high) is None
    assert validate_editable_api_value(entry, high + 1)
    assert validate_editable_api_value(entry, low - 1)
    assert "At most" in entry.description or "From" in entry.description


@pytest.mark.parametrize(
    ("name", "stored", "used"),
    [
        ("jwt_access_token_expire_minutes", 525600 * 5, 1440),
        ("jwt_refresh_token_expire_days", 36500, 90),
        ("login_max_attempts", 10**9, 100),
        ("login_lockout_seconds", 0, 60),
        ("login_lockout_seconds", 10**9, 86400),
        ("login_max_attempts", 10, 10),
    ],
)
@pytest.mark.asyncio
async def test_a_stored_value_outside_the_ceiling_loads_clamped_with_a_warning(
    name: str, stored: int, used: int, caplog: pytest.LogCaptureFixture
) -> None:
    @asynccontextmanager
    async def factory():
        yield MagicMock()

    cfg = RuntimeConfig(factory)
    with (
        patch(
            "app.runtime_config.SettingsService.load_overrides",
            AsyncMock(return_value={f"api.{name}": stored}),
        ),
        caplog.at_level(logging.WARNING, logger="app.runtime_config"),
    ):
        got = await cfg.get(name)
    assert got == used
    assert cfg.get_cached(name) == used
    assert any(name in r.getMessage() for r in caplog.records) is (stored != used)


# ── Pre-owner memory adoption ───────────────────────────────────────────

ADMIN_KEY = prefixed_key("mk_")


class _Store:
    def __init__(self) -> None:
        self.owner: str | None = None
        self.ownerless = {
            "cases": 3,
            "function_hashes": 5,
            "dropped_cases": 1,
            "dropped_function_hashes": 2,
            "skipped_cases": 0,
            "skipped_function_hashes": 0,
        }
        self.closed = False

    def adopt_unowned(self, owner: str) -> dict[str, int]:
        counts = dict(self.ownerless)
        self.ownerless = dict.fromkeys(counts, 0)
        self.owner = owner
        return counts

    def close(self) -> None:
        self.closed = True


def _client(known: Any) -> tuple[TestClient, Any]:
    from app.api.v1.system import router
    from app.database import get_db

    admin = SimpleNamespace(id=uuid.uuid4(), role="admin")
    db = MagicMock()
    db.get = AsyncMock(return_value=known)
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[require_admin] = lambda: admin
    app.dependency_overrides[get_db] = lambda: db
    return TestClient(app), admin


def test_adoption_refuses_an_api_key() -> None:
    client, _ = _client(SimpleNamespace(id=uuid.uuid4()))
    r = client.post(
        "/api/v1/system/ltm/adopt",
        json={"user_id": str(uuid.uuid4())},
        headers={"X-API-Key": ADMIN_KEY},
    )
    assert r.status_code == 403
    assert r.json()["detail"] == SESSION_ONLY_DETAIL


def test_adoption_files_the_ownerless_memory_audits_and_is_idempotent() -> None:
    target = SimpleNamespace(id=uuid.uuid4())
    client, admin = _client(target)
    store = _Store()
    record = AsyncMock()
    with (
        patch("app.api.v1.system._build_memory_store", AsyncMock(return_value=store)),
        patch("app.api.v1.system.audit.record", record),
        patch("app.api.v1.system.end_read_transaction", AsyncMock()),
    ):
        first = client.post("/api/v1/system/ltm/adopt", json={"user_id": str(target.id)})
        second = client.post("/api/v1/system/ltm/adopt", json={"user_id": str(target.id)})
    assert first.status_code == 200, first.text
    assert (first.json()["cases"], first.json()["function_hashes"]) == (3, 5)
    assert store.owner == str(target.id)
    assert (second.json()["cases"], second.json()["function_hashes"]) == (0, 0)
    assert store.closed
    row = record.await_args_list[0]
    assert row.args[0] == "ltm.adopt"
    assert row.kwargs["user_id"] == admin.id
    assert row.kwargs["details"]["actor"] == str(admin.id)
    assert row.kwargs["details"]["owner"] == str(target.id)
    assert row.kwargs["details"]["count"] == 8
    assert row.kwargs["details"]["dropped_cases"] == 1
    assert row.kwargs["details"]["dropped_function_hashes"] == 2


def test_adoption_refuses_an_unknown_user_and_touches_nothing() -> None:
    client, _ = _client(None)
    build = AsyncMock()
    record = AsyncMock()
    with (
        patch("app.api.v1.system._build_memory_store", build),
        patch("app.api.v1.system.audit.record", record),
    ):
        r = client.post("/api/v1/system/ltm/adopt", json={"user_id": str(uuid.uuid4())})
    assert r.status_code == 404
    build.assert_not_awaited()
    record.assert_not_awaited()


def test_a_backend_without_owners_is_refused() -> None:
    client, _ = _client(SimpleNamespace(id=uuid.uuid4()))
    bare = SimpleNamespace(close=MagicMock())
    record = AsyncMock()
    with (
        patch("app.api.v1.system._build_memory_store", AsyncMock(return_value=bare)),
        patch("app.api.v1.system.audit.record", record),
        patch("app.api.v1.system.end_read_transaction", AsyncMock()),
    ):
        r = client.post("/api/v1/system/ltm/adopt", json={"user_id": str(uuid.uuid4())})
    assert r.status_code == 409
    record.assert_not_awaited()
    bare.close.assert_called_once()


def test_nothing_adopts_automatically() -> None:
    """The default stays: the repair that runs at start never labels an owner."""
    from maljan.memory import memory_repair

    source = open(memory_repair.__file__).read()
    start_up = source.split("def repair_once")[1].split("def repair_memory")[0]
    assert "adopt" not in start_up


# ── a stored out-of-range row does not block an unrelated save ──────────


def _service() -> Any:
    from app.services.settings_service import SettingsService

    return SettingsService(MagicMock())


def test_an_over_range_stored_row_does_not_block_other_keys_but_a_new_one_is_refused() -> None:
    from app.services.settings_service import SettingsValidationError

    stored = {"login_lockout_seconds": 30, "jwt_refresh_token_expire_days": 365}
    service = _service()
    # The stored rows are re-sent unchanged beside an unrelated key.
    service.validate({}, {**stored, "login_max_attempts": 5}, stored)
    # A changed or new out-of-range value is refused.
    with pytest.raises(SettingsValidationError) as exc:
        service.validate({}, {**stored, "login_lockout_seconds": 10}, stored)
    assert "api.login_lockout_seconds" in exc.value.errors
    with pytest.raises(SettingsValidationError) as exc:
        service.validate({}, {"jwt_refresh_token_expire_days": 400}, {})
    assert "api.jwt_refresh_token_expire_days" in exc.value.errors


def test_the_grace_window_is_checked_against_the_clamped_token() -> None:
    from app.services.settings_catalog_api import refresh_grace_problem

    # 5000 min is read as 1440 min (86400 s): a 100000 s window outlives it.
    assert refresh_grace_problem(
        {"jwt_access_token_expire_minutes": 5000, "refresh_reuse_grace_seconds": 100000}
    )
    assert not refresh_grace_problem(
        {"jwt_access_token_expire_minutes": 5000, "refresh_reuse_grace_seconds": 600}
    )


@pytest.mark.asyncio
async def test_the_grace_window_at_runtime_never_outlives_the_clamped_token() -> None:
    @asynccontextmanager
    async def factory():
        yield MagicMock()

    cfg = RuntimeConfig(factory)
    overrides = {
        "api.jwt_access_token_expire_minutes": 5000,
        "api.refresh_reuse_grace_seconds": 100000,
    }
    with patch(
        "app.runtime_config.SettingsService.load_overrides", AsyncMock(return_value=overrides)
    ):
        minutes = await cfg.get("jwt_access_token_expire_minutes")
        grace = await cfg.get("refresh_reuse_grace_seconds")
    assert minutes == 1440
    assert grace < minutes * 60


def test_a_failed_adoption_is_audited_with_the_partial_counts_and_re_raised() -> None:
    from maljan.memory.memory_repair import AdoptionFailed

    class _Failing(_Store):
        def adopt_unowned(self, owner: str) -> dict[str, int]:
            try:
                raise ConnectionError("qdrant went away")
            except ConnectionError as exc:
                raise AdoptionFailed({"cases": 4, "function_hashes": 1}) from exc

    target = SimpleNamespace(id=uuid.uuid4())
    client, admin = _client(target)
    store = _Failing()
    record = AsyncMock()
    with (
        patch("app.api.v1.system._build_memory_store", AsyncMock(return_value=store)),
        patch("app.api.v1.system.audit.record", record),
        patch("app.api.v1.system.end_read_transaction", AsyncMock()),
        pytest.raises(ConnectionError),
    ):
        client.post("/api/v1/system/ltm/adopt", json={"user_id": str(target.id)})
    record.assert_awaited_once()
    details = record.await_args.kwargs["details"]
    assert details["outcome"] == "failed"
    assert details["cases"] == 4
    assert details["function_hashes"] == 1
    assert details["error"] == "ConnectionError"
    assert details["actor"] == str(admin.id)
    assert details["owner"] == str(target.id)
    assert store.closed


def test_the_adoption_docstring_says_to_run_it_with_no_jobs_running() -> None:
    from app.api.v1.system import ltm_adopt

    assert "no jobs are running" in " ".join((ltm_adopt.__doc__ or "").split())

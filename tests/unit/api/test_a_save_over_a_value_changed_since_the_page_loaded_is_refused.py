"""A save over a value changed since the page loaded it is refused, naming the key.

A whole value (the declared report formats, the server map, any key) is
saved as a whole, so a page loaded before another writer changed it (an
accepted report format, a credential bootstrap, another admin) would drop
that change unseen. A PATCH carries, per changed key, the ``updated_at`` the
page was served it with; a key whose stored row is not that one any more is
refused with 409 and nothing is saved. A key the PATCH names no version for
is not checked. Through the real router, over a fake database.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.models import RuntimeSetting
from app.services import settings_service as svc

FORMATS = "core.sandbox.report_formats"
SERVERS = "core.mcp.servers"
PLAIN = "core.llm.expert_max_tokens"
LOADED = datetime(2026, 1, 2, 3, 4, 5, 678901, tzinfo=UTC)
LATER = LOADED + timedelta(microseconds=1)


@pytest.fixture(autouse=True)
def _no_audit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(svc, "_audit", AsyncMock())


def _row(key: str, value: Any, at: datetime) -> RuntimeSetting:
    row = RuntimeSetting(key=key, value=value, is_secret=False)
    row.updated_at = at
    return row


def _patch(rows: list[Any], body: dict[str, Any]) -> tuple[int, dict[str, Any], MagicMock]:
    from app.api.v1.settings import router
    from app.database import get_db
    from app.deps import require_admin

    db = MagicMock()
    db.execute = AsyncMock(
        return_value=SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: list(rows)))
    )
    db.add = MagicMock()
    db.delete = AsyncMock()
    db.commit = AsyncMock()
    db.flush = AsyncMock()
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[require_admin] = lambda: MagicMock(id=uuid.UUID(int=1))
    app.dependency_overrides[get_db] = lambda: db
    with (
        patch("app.api.v1.settings.audit_record", AsyncMock()),
        patch("app.api.v1.settings._agent_warnings", AsyncMock(return_value={})),
        patch("app.api.v1.settings._mapping_warnings", AsyncMock(return_value={})),
    ):
        answer = TestClient(app, raise_server_exceptions=False).patch("/api/v1/settings", json=body)
    return answer.status_code, answer.json(), db


def _iso(at: datetime | None) -> str | None:
    return None if at is None else at.isoformat()


STALE = [
    pytest.param(LATER, LOADED, "saved again", id="saved-again"),
    pytest.param(LOADED, None, "saved", id="saved-where-none-was"),
    pytest.param(None, LOADED, "reset", id="reset"),
]


@pytest.mark.parametrize(("stored_at", "loaded_at", "what"), STALE)
@pytest.mark.parametrize(
    ("key", "stored", "sent"),
    [
        pytest.param(FORMATS, [{"name": "accepted"}], [], id="report-formats"),
        pytest.param(SERVERS, {}, {}, id="server-map"),
        pytest.param(PLAIN, 4096, 2048, id="a-plain-key"),
    ],
)
def test_a_save_over_a_changed_value_is_a_409_naming_it_and_saves_nothing(
    key: str,
    stored: Any,
    sent: Any,
    stored_at: datetime | None,
    loaded_at: datetime | None,
    what: str,
) -> None:
    rows = [] if stored_at is None else [_row(key, stored, stored_at)]
    status, body, db = _patch(rows, {"changes": {key: sent}, "versions": {key: _iso(loaded_at)}})
    assert status == 409, body
    assert list(body["errors"]) == [key]
    assert body["errors"][key].startswith(f"{what} since this page loaded it")
    db.add.assert_not_called()
    db.delete.assert_not_awaited()
    db.commit.assert_not_awaited()


@pytest.mark.parametrize(
    ("rows", "loaded_at"),
    [
        pytest.param([_row(PLAIN, 4096, LOADED)], LOADED, id="the-row-it-loaded"),
        pytest.param([], None, id="no-row-then-or-now"),
    ],
)
def test_a_save_over_the_value_the_page_loaded_saves(rows: list[Any], loaded_at: Any) -> None:
    status, body, db = _patch(
        rows, {"changes": {PLAIN: 2048}, "versions": {PLAIN: _iso(loaded_at)}}
    )
    assert status == 200, body
    assert body["applied"] == [PLAIN]
    db.commit.assert_awaited()


def test_a_key_with_no_version_is_not_checked() -> None:
    rows = [_row(PLAIN, 4096, LATER)]
    status, body, _db = _patch(rows, {"changes": {PLAIN: 2048}})
    assert status == 200, body
    # A version for a key the save does not change is not this save's concern.
    status, body, _db = _patch(
        rows, {"changes": {PLAIN: 2048}, "versions": {FORMATS: _iso(LOADED), PLAIN: _iso(LATER)}}
    )
    assert status == 200, body


def test_the_check_is_linear_in_the_stored_rows() -> None:
    import asyncio

    rows = [_row(f"core.x{i}", i, LOADED) for i in range(20_000)]
    db = MagicMock()
    db.execute = AsyncMock(
        return_value=SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: rows))
    )
    versions = {f"core.x{i}": LOADED if i % 2 else LATER for i in range(20_000)}
    stale = asyncio.run(svc.SettingsService(db).changed_since(versions))
    assert len(stale) == 10_000

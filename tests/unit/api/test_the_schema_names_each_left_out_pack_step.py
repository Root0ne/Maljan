"""The settings schema names each stored pack step the settings leave out, and why.

A stored step can stop running without any save: a reset of the server it
calls takes no validation. Whatever left it out, ``GET /settings/schema``
lists it under ``pack_steps_left_out`` with the reason, so the console never
shows a stored step as in force when the shipped one runs, also where other
stored settings do not build. Through the real router, over a fake database.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.models import RuntimeSetting
from app.services import settings_service as svc
from maljan.core import settings_overrides

SERVER = {
    "command": "invented-rules",
    "enabled": True,
    "tool_facts": {"match": {"kind": "capability_rules", "rows": "/hits/*"}},
}
STEP = {"id": "extra", "server": "rules", "tool": "match"}


@pytest.fixture(autouse=True)
def _quiet(monkeypatch: pytest.MonkeyPatch) -> None:
    settings_overrides._WARNED_STEPS.clear()
    monkeypatch.setattr(svc, "_audit", AsyncMock())


def _db(rows: list[Any]) -> MagicMock:
    db = MagicMock()
    db.execute = AsyncMock(
        side_effect=lambda *_a, **_k: SimpleNamespace(
            scalars=lambda: SimpleNamespace(all=lambda: list(rows))
        )
    )
    db.delete = AsyncMock(side_effect=rows.remove)
    db.commit = AsyncMock()
    db.flush = AsyncMock()
    return db


def _client(db: MagicMock) -> TestClient:
    from app.api.v1.settings import router
    from app.database import get_db
    from app.deps import require_admin

    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[require_admin] = lambda: MagicMock(id=uuid.UUID(int=1))
    app.dependency_overrides[get_db] = lambda: db
    return TestClient(app, raise_server_exceptions=False)


def _left_out(client: TestClient) -> dict[str, str]:
    answer = client.get("/api/v1/settings/schema")
    assert answer.status_code == 200, answer.text
    return answer.json()["pack_steps_left_out"]


def test_a_reset_of_the_server_a_stored_step_calls_lists_the_step() -> None:
    rows = [
        RuntimeSetting(key="core.mcp.servers", value={"rules": SERVER}, is_secret=False),
        RuntimeSetting(key="core.triage.steps", value=[STEP], is_secret=False),
    ]
    with patch("app.api.v1.settings.audit_record", AsyncMock()):
        client = _client(_db(rows))
        assert _left_out(client) == {}
        reset = client.delete("/api/v1/settings/core.mcp.servers")
        assert reset.status_code == 200, reset.text
        assert reset.json()["reset"] == ["core.mcp.servers"]
        said = _left_out(client)
    assert list(said) == ["extra"]
    assert "references unknown mcp server 'rules'" in said["extra"]


def test_stored_settings_that_do_not_build_still_serve_the_schema() -> None:
    rows = [
        RuntimeSetting(key="core.triage.budget_seconds", value=0, is_secret=False),
        RuntimeSetting(
            key="core.triage.steps",
            value=[{"id": "lost", "server": "nowhere", "tool": "t"}],
            is_secret=False,
        ),
    ]
    with patch("app.api.v1.settings.audit_record", AsyncMock()):
        said = _left_out(_client(_db(rows)))
    assert said == {"lost": "triage step 'lost' references unknown mcp server 'nowhere'"}


def test_a_stored_step_on_a_server_whose_stored_entry_is_refused_is_listed_saying_so() -> None:
    servers = {"rules": SERVER, "refused": {"command": "x", "enabled": "maybe"}}
    rows = [
        RuntimeSetting(key="core.mcp.servers", value=servers, is_secret=False),
        RuntimeSetting(
            key="core.triage.steps",
            value=[STEP, {"id": "on_refused", "server": "refused", "tool": "t"}],
            is_secret=False,
        ),
    ]
    with patch("app.api.v1.settings.audit_record", AsyncMock()):
        said = _left_out(_client(_db(rows)))
    assert list(said) == ["on_refused"]
    assert "stored entry of its server 'refused' is refused" in said["on_refused"]


def test_a_stored_value_alone_that_does_not_build_serves_an_empty_listing() -> None:
    rows = [RuntimeSetting(key="core.triage.budget_seconds", value=0, is_secret=False)]
    with patch("app.api.v1.settings.audit_record", AsyncMock()):
        assert _left_out(_client(_db(rows))) == {}

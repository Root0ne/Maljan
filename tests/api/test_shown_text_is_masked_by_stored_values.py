"""Every place that reads settings in force registers their secret values for shown text (T-482).

Masking by value (``maljan.core.settings_masking.masked_values``) masks what
the process holds: the store as it is read (``SettingsService.load_overrides``,
encrypted rows included, again after a save or a reset and before the
console's read), the console's cached core settings on each rebuild, an app,
a worker and a job. A value a reader may not see is then masked wherever the
console, an error text or a log line carries it, whatever its shape.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.models import RuntimeSetting
from app.services import settings_service as svc
from app.services.server_map import TOKEN_MASK
from maljan.core import settings_masking as sm
from maljan.core.config import MCPServerConfig
from maljan.core.settings_overrides import build_settings
from tests.credential_shapes import lowercase_body

SERVERS = "core.mcp.servers"


def _value(variant: int = 0) -> str:
    return "Wd" + lowercase_body(14 + variant)


class _Result:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def scalars(self) -> SimpleNamespace:
        return SimpleNamespace(all=lambda: list(self._rows))


def _db(*row_sets: list[RuntimeSetting]) -> MagicMock:
    """A session whose reads answer each of ``row_sets`` in turn, the last one after."""
    answers = list(row_sets)

    async def execute(*_args: Any, **_kwargs: Any) -> _Result:
        return _Result(answers.pop(0) if len(answers) > 1 else answers[0])

    db = MagicMock()
    db.execute = execute
    db.add = MagicMock()
    db.delete = AsyncMock()
    db.commit = AsyncMock()
    db.flush = AsyncMock()
    return db


def _server(env_value: str) -> dict[str, Any]:
    return {
        "enabled": False,
        "transport": "stdio",
        "command": "tool",
        "args": ["--name", env_value],
        "env": {"MODE": env_value},
        "tools": [],
    }


@pytest.fixture(autouse=True)
def _quiet(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(svc, "_audit", AsyncMock())
    monkeypatch.setattr(svc.box, "decrypt", lambda stored: stored)
    logging.disable(logging.WARNING)
    yield
    logging.disable(logging.NOTSET)


@pytest.mark.asyncio
async def test_reading_the_store_registers_its_secrets_and_every_encrypted_row():
    env_value, row_value = _value(1), _value(2)
    rows = [
        RuntimeSetting(key=SERVERS, value={"custom": _server(env_value)}, is_secret=False),
        RuntimeSetting(key="core.some.unnamed_field", value=row_value, is_secret=True),
    ]

    await svc.SettingsService(_db(rows)).load_overrides()

    assert {env_value, row_value} <= sm.held_values()
    assert sm.masked_text(f"failed with {row_value}") == "failed with ***"


@pytest.mark.asyncio
async def test_a_reset_reads_the_store_again_so_a_removed_secret_is_no_longer_held():
    kept, removed = _value(1), _value(2)
    before = [
        RuntimeSetting(key="core.a.api_key", value=kept, is_secret=True),
        RuntimeSetting(key="core.b.api_key", value=removed, is_secret=True),
    ]
    after = [before[0]]
    service = svc.SettingsService(_db(before, before, after))
    await service.load_overrides()
    assert removed in sm.held_values()

    await service.reset(["core.b.api_key"], user_id=None, ip=None)

    assert kept in sm.held_values()
    assert removed not in sm.held_values()


@pytest.mark.asyncio
async def test_a_failed_read_after_a_write_never_fails_the_write():
    service = svc.SettingsService(_db([]))
    with patch.object(svc.SettingsService, "load_overrides", AsyncMock(side_effect=OSError)):
        await service._remember_stored_values()


def test_the_console_read_masks_a_stored_secret_wherever_it_stands():
    env_value = _value(3)
    rows = [RuntimeSetting(key=SERVERS, value={"custom": _server(env_value)}, is_secret=False)]
    from app.api.v1.settings import router
    from app.database import get_db
    from app.deps import require_admin

    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[require_admin] = lambda: MagicMock(id=uuid.UUID(int=1))
    db = _db(rows)
    app.dependency_overrides[get_db] = lambda: db
    with patch("app.api.v1.settings._agent_warnings", AsyncMock(return_value={})):
        answer = TestClient(app, raise_server_exceptions=False).get("/api/v1/settings")

    assert answer.status_code == 200, answer.text[:300]
    assert env_value not in answer.text
    server = answer.json()["values"][SERVERS]["value"]["custom"]
    assert server["args"] == ["--name", TOKEN_MASK]


@pytest.mark.asyncio
async def test_each_rebuild_of_the_cached_core_settings_registers_its_values(monkeypatch):
    first, second = _value(4), _value(5)
    stored = {"mcp.servers": {"any": {"command": "tool", "env": {"A": first}}}}

    async def overrides(_db: Any) -> dict[str, Any]:
        return stored

    monkeypatch.setattr(svc, "load_core_overrides", overrides)
    cache = svc._CoreSettingsCache()
    await cache.get(MagicMock())
    assert first in sm.held_values()

    stored = {"mcp.servers": {"any": {"command": "tool", "env": {"A": second}}}}
    cache.invalidate()
    await cache.get(MagicMock())

    assert second in sm.held_values()
    assert first not in sm.held_values()


def test_a_worker_and_a_job_register_their_values():
    from app.worker.analysis_worker import remember_configured_secrets, remember_process_secrets

    process, job = _value(6), _value(7)
    settings = build_settings({})
    settings.mcp.servers["any"] = MCPServerConfig(command="tool", env={"A": process})
    remember_process_secrets(settings)
    settings.mcp.servers["any"] = MCPServerConfig(command="tool", env={"A": job})
    remember_configured_secrets(settings)

    assert {process, job} <= sm.held_values()


def test_an_app_registers_the_values_of_its_settings():
    from maljan.app import _remember_the_secrets_of

    value = _value(8)
    settings = build_settings({})
    settings.mcp.servers["any"] = MCPServerConfig(command="tool", env={"A": value})

    _remember_the_secrets_of(settings)

    assert value in sm.held_values()

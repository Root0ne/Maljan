"""AUD-20 S-8 through the save: a new unknown agent key is refused, a stored one is not."""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

import app.services.settings_service as svc

ENTRY = {"provider": "openai", "model": "m"}
KEY = "core.llm.agents"


def _db(rows: dict[str, Any]) -> Any:
    held = [
        SimpleNamespace(key=k, value=v, is_secret=False, updated_at=None, updated_by=None)
        for k, v in rows.items()
    ]
    db = MagicMock()
    db.execute = AsyncMock(
        return_value=SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: list(held)))
    )
    db.add = MagicMock()
    db.delete = AsyncMock()
    db.commit = AsyncMock()
    return db


@pytest.mark.asyncio
async def test_the_save_refuses_an_unknown_agent_key_and_passes_a_stored_orphan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(svc, "_audit", AsyncMock())
    stored = {KEY: {"ghost": ENTRY}}

    db = _db(stored)
    with pytest.raises(svc.SettingsValidationError) as refused:
        await svc.SettingsService(db).save(
            {KEY: {"ghost": ENTRY, "other": ENTRY}}, user_id=uuid.uuid4(), ip=None
        )
    assert "other" in refused.value.errors[KEY]
    assert "ghost" not in refused.value.errors[KEY]
    db.commit.assert_not_awaited()

    # The stored orphan sent back unchanged passes.
    await svc.SettingsService(_db(stored)).save(
        {KEY: {"ghost": ENTRY}}, user_id=uuid.uuid4(), ip=None
    )

"""A save is refused when a pack step it changes cannot run; stored steps are read leniently.

The settings the store builds leave out a stored step that cannot run
(``core.settings_overrides.build_settings``); a save is checked strictly, so a
new step that cannot run is refused before anything is written, and a stale
stored step blocks no unrelated save.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.settings_service import SettingsService, SettingsValidationError

pytestmark = pytest.mark.asyncio

GONE = {"id": "lost", "server": "nowhere", "tool": "t"}


def _service(current: dict[str, Any]) -> SettingsService:
    service = SettingsService(MagicMock())
    service.load_overrides = AsyncMock(return_value=current)  # type: ignore[method-assign]
    return service


async def test_a_new_step_that_cannot_run_is_refused_before_anything_is_written() -> None:
    service = _service({})
    with patch.object(SettingsService, "_rows", AsyncMock(side_effect=AssertionError)):
        with pytest.raises(SettingsValidationError) as caught:
            await service.save({"core.triage.steps": [GONE]}, user_id=None, ip=None)
    said = caught.value.errors["core.triage.steps"]
    assert "triage step 'lost' references unknown mcp server 'nowhere'" in said


async def test_a_stale_stored_step_blocks_no_unrelated_save() -> None:
    service = _service({"core.triage.steps": [GONE]})
    reached = AssertionError("validation passed")
    with patch.object(SettingsService, "_rows", AsyncMock(side_effect=reached)):
        with pytest.raises(AssertionError) as caught:
            await service.save({"core.triage.budget_seconds": 90}, user_id=None, ip=None)
    assert caught.value is reached

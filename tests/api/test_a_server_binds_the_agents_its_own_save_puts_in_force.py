"""A server's agent binding is checked against the definitions in force after the same save.

The console applies the definition map and the server map in one request, so an
agent added in it may be bound to a server in it, and an agent the request
removes may not.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.settings_service import (
    SettingsService,
    SettingsValidationError,
    definitions_after_save,
)

pytestmark = pytest.mark.asyncio

DEFINITIONS = "core.agents.definitions"
SERVERS = "core.mcp.servers"
CHECKER = {
    "role": "generic",
    "label": "Dropped-file checker",
    "prompt": "Check the files the sample drops.",
    "tools": [],
    "enabled": True,
}


def _server(*agents: str) -> dict[str, Any]:
    return {
        "extra": {
            "enabled": True,
            "transport": "stdio",
            "command": "extra-mcp",
            "agents": list(agents),
        }
    }


def _service(current: dict[str, Any]) -> SettingsService:
    service = SettingsService(MagicMock())
    service.load_overrides = AsyncMock(return_value=current)  # type: ignore[method-assign]
    return service


async def test_an_agent_added_in_the_save_may_be_bound_in_the_same_save() -> None:
    service = _service({})
    reached = AssertionError("validation passed")
    changes = {DEFINITIONS: {"checker": CHECKER}, SERVERS: _server("checker")}
    with patch.object(SettingsService, "_rows", AsyncMock(side_effect=reached)):
        with pytest.raises(AssertionError) as caught:
            await service.save(changes, user_id=None, ip=None)
    assert caught.value is reached


async def test_an_agent_removed_in_the_save_may_not_stay_bound() -> None:
    service = _service({DEFINITIONS: {"checker": CHECKER}, SERVERS: _server("checker")})
    changes = {DEFINITIONS: {}, SERVERS: _server("checker")}
    with patch.object(SettingsService, "_rows", AsyncMock(side_effect=AssertionError)):
        with pytest.raises(SettingsValidationError) as caught:
            await service.save(changes, user_id=None, ip=None)
    said = caught.value.errors[f"{SERVERS}.extra.agents"]
    assert "'checker' is not a known agent" in said


async def test_the_definitions_in_force_are_the_request_s_map_less_its_null_entries() -> None:
    current = {DEFINITIONS: {"old": CHECKER}, "core.llm.provider": "openai"}
    after = definitions_after_save(current, {DEFINITIONS: {"new": CHECKER, "gone": None}})
    assert after == {DEFINITIONS: {"new": CHECKER}, "core.llm.provider": "openai"}
    assert definitions_after_save(current, {DEFINITIONS: None}) == {"core.llm.provider": "openai"}
    assert definitions_after_save(current, {"core.llm.provider": "x"}) is current

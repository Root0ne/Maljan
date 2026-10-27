"""A save of ``core.providers`` is checked as a save of the server map is.

* A block keyed by a built-in provider's id is refused: that provider keeps
  its own block or declaration.
* A tool declaration the save adds or changes is held to the strict rules;
  one sent back exactly as stored is not, so a stored block never blocks an
  unrelated save.
* A save that does not touch the map, or clears it, is not checked here.
"""

from __future__ import annotations

from typing import Any

import pytest

from app.services.settings_service import PROVIDER_BLOCKS_KEY, provider_block_refusals

PROVIDER = "invented_third_party_g14"
FACTS_STRICTLY_REFUSED = {"list_strings": {"kind": "strings", "no_such_field": 1}}


def _map(facts: dict[str, Any], key: str = PROVIDER) -> dict[str, Any]:
    return {PROVIDER_BLOCKS_KEY: {key: {"enabled": True, "tool_facts": facts}}}


def test_a_built_in_providers_id_is_refused() -> None:
    for built_in in ("generic_mcp", "mock"):
        refused = provider_block_refusals(_map({}, key=built_in), {})
        assert "built-in provider" in refused[f"{PROVIDER_BLOCKS_KEY}.{built_in}"]


def test_an_entry_a_provider_never_reads_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    from maljan.core import tool_declarations

    # A provider whose class registered a block of its own, not ``providers.<id>``.
    monkeypatch.setitem(
        tool_declarations._REGISTERED_PROVIDER_BLOCKS, f"provider:{PROVIDER}", "static.r2"
    )
    refused = provider_block_refusals(_map({}), {})
    assert "never be read" in refused[f"{PROVIDER_BLOCKS_KEY}.{PROVIDER}"]
    monkeypatch.setitem(
        tool_declarations._REGISTERED_PROVIDER_BLOCKS,
        f"provider:{PROVIDER}",
        f"providers.{PROVIDER}",
    )
    assert provider_block_refusals(_map({}), {}) == {}


def test_a_changed_declaration_is_held_to_the_strict_rules() -> None:
    refused = provider_block_refusals(_map(FACTS_STRICTLY_REFUSED), {})
    assert refused
    assert all(key.startswith(f"{PROVIDER_BLOCKS_KEY}.{PROVIDER}.tool_facts.") for key in refused)


def test_a_declaration_sent_back_as_stored_is_not() -> None:
    stored = _map(FACTS_STRICTLY_REFUSED)
    assert provider_block_refusals(_map(FACTS_STRICTLY_REFUSED), stored) == {}


def test_a_good_block_or_no_map_is_not_refused() -> None:
    assert provider_block_refusals(_map({"list_strings": {"kind": "strings"}}), {}) == {}
    assert provider_block_refusals({}, {}) == {}
    assert provider_block_refusals({PROVIDER_BLOCKS_KEY: None}, {}) == {}


class _Rows(list):
    """A stand-in session: records adds, replays rows."""

    def __init__(self) -> None:
        super().__init__()
        self.added: list[Any] = []

    def add(self, row: Any) -> None:
        self.added.append(row)

    async def delete(self, row: Any) -> None:
        return None

    async def commit(self) -> None:
        return None


def _service() -> tuple[Any, _Rows]:
    from unittest.mock import AsyncMock, MagicMock

    from app.services.settings_service import SettingsService

    session = _Rows()
    service = SettingsService(MagicMock())
    service._rows = AsyncMock(return_value=[])  # type: ignore[method-assign]
    service.db = session
    service.load_overrides = AsyncMock(return_value={})  # type: ignore[method-assign]
    return service, session


@pytest.mark.asyncio
async def test_a_block_is_saved_as_one_row_and_a_bad_one_is_refused_by_key() -> None:
    from app.services.settings_service import SettingsValidationError

    block = {
        "enabled": True,
        "transport": "streamable-http",
        "url": "http://invented:9000/mcp",
        "tool_facts": {"list_strings": {"kind": "strings"}},
    }
    service, session = _service()
    await service.save({PROVIDER_BLOCKS_KEY: {PROVIDER: block}}, user_id=None, ip=None)
    row = next(r for r in session.added if r.key == PROVIDER_BLOCKS_KEY)
    assert row.value[PROVIDER]["url"] == block["url"]

    for bad, words in (
        ({**block, "auth_token": "t0ken"}, "holds no credential"),
        ({**block, "tool_facts": FACTS_STRICTLY_REFUSED}, ""),
    ):
        service, session = _service()
        with pytest.raises(SettingsValidationError) as refused:
            await service.save({PROVIDER_BLOCKS_KEY: {PROVIDER: bad}}, user_id=None, ip=None)
        assert any(key.startswith(PROVIDER_BLOCKS_KEY) for key in refused.value.errors)
        assert words in " ".join(refused.value.errors.values())
        assert not session.added

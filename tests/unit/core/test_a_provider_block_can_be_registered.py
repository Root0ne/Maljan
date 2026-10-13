"""The provider blocks are the shipped ones plus any a provider registers.

* The shipped blocks are unchanged and come first.
* A provider class naming a ``declaration_block`` joins them when it registers:
  its declaration is read there as a built-in's is, the run snapshot walks it,
  and taking the provider out takes the block out.
* A shipped source keeps its shipped block, and a path that is not dotted
  words is refused.
* A path where the settings model holds no server block is refused at
  registration, and so is a path that is, holds or sits inside another
  source's block: two sources never read one block.
* A settings object that still lacks a registered block declares nothing, and
  that is logged once per source and path in the process, not on each read.
"""

from __future__ import annotations

import pytest

from maljan.core import declared_reading, tool_declarations
from maljan.core.config import Settings
from maljan.core.tool_declarations import (
    forget_provider_block,
    provider_block_at,
    provider_blocks,
    provider_declarations,
    register_provider_block,
    shipped_provider_blocks,
)

SOURCE = "provider:invented_block_g12"


@pytest.fixture
def unowned_r2_block(monkeypatch: pytest.MonkeyPatch) -> str:
    """A settings server block no shipped source owns: ``static.r2`` with its owner left out.

    The settings have no place of a third-party provider's own yet, so the
    registration path is proven on a real block with its shipped owner taken
    out of the shipped list.
    """
    shipped = {k: v for k, v in shipped_provider_blocks().items() if v != "static.r2"}
    monkeypatch.setattr(tool_declarations, "shipped_provider_blocks", lambda: dict(shipped))
    return "static.r2"


def test_the_shipped_blocks_are_unchanged_and_first() -> None:
    assert shipped_provider_blocks() == {
        "provider:ghidra": "static.ghidra",
        "provider:r2": "static.r2",
        "provider:cape2": "sandbox.cape2.mcp",
    }
    assert list(provider_blocks())[:3] == list(shipped_provider_blocks())


def test_a_registered_block_is_read_walked_and_forgotten(unowned_r2_block: str) -> None:
    from maljan.core.settings_overrides import declaration_blocks

    settings = Settings(_env_file=None)
    register_provider_block(SOURCE, unowned_r2_block)
    try:
        assert provider_blocks()[SOURCE] == "static.r2"
        assert provider_declarations(settings)[SOURCE] is settings.static.r2
        assert declaration_blocks(settings)[SOURCE] == "static.r2"
    finally:
        forget_provider_block(SOURCE)
        declared_reading.forget()
    assert SOURCE not in provider_blocks()


def test_a_provider_class_naming_its_block_joins_on_registration(unowned_r2_block: str) -> None:
    from maljan.providers.registry import forget_static_provider, register_static_provider

    @register_static_provider("invented_block_g12")
    class _Invented:
        declaration_block = "static.r2"

    try:
        assert provider_blocks()[SOURCE] == "static.r2"
    finally:
        forget_static_provider("invented_block_g12")
        declared_reading.forget()
    assert SOURCE not in provider_blocks()


def test_a_shipped_source_keeps_its_block_and_a_bad_path_is_refused() -> None:
    with pytest.raises(ValueError, match="shipped block"):
        register_provider_block("provider:ghidra", "static.r2")
    register_provider_block("provider:ghidra", "static.ghidra")
    assert provider_blocks()["provider:ghidra"] == "static.ghidra"
    for bad in ("", "Static.Block", "static..x", "static/x"):
        with pytest.raises(ValueError, match="settings path"):
            register_provider_block(SOURCE, bad)
    with pytest.raises(ValueError, match="provider source"):
        register_provider_block("mcp:x", "static.r2")


def test_a_path_the_settings_do_not_hold_is_refused_at_registration() -> None:
    for unheld in ("static.no_such_block", "static.capa", "mcp.servers.analysis", "triage"):
        with pytest.raises(ValueError, match="no server block in the settings"):
            register_provider_block(SOURCE, unheld)
    assert SOURCE not in provider_blocks()


def test_a_built_in_providers_block_is_refused_to_another_source() -> None:
    for aliasing in ("static.r2", "static.ghidra", "sandbox.cape2.mcp", "sandbox.cape2", "static"):
        with pytest.raises(ValueError, match="overlaps it"):
            register_provider_block(SOURCE, aliasing)
    assert SOURCE not in provider_blocks()


def test_a_provider_class_with_a_refused_block_is_not_registered() -> None:
    from maljan.providers.registry import _STATIC_REGISTRY, register_static_provider

    with pytest.raises(ValueError, match="overlaps it"):

        @register_static_provider("invented_block_g12")
        class _Aliasing:
            declaration_block = "static.r2"

    assert "invented_block_g12" not in _STATIC_REGISTRY
    assert SOURCE not in provider_blocks()


def test_a_registered_block_another_source_holds_is_refused(unowned_r2_block: str) -> None:
    register_provider_block(SOURCE, unowned_r2_block)
    try:
        with pytest.raises(ValueError, match="overlaps it"):
            register_provider_block("provider:another_g12", unowned_r2_block)
    finally:
        forget_provider_block(SOURCE)
        declared_reading.forget()


def test_a_missing_block_is_logged_once_not_on_every_read(monkeypatch: pytest.MonkeyPatch) -> None:
    from maljan.core.logger import logger

    said: list[str] = []
    monkeypatch.setattr(logger, "warning", lambda msg, *args: said.append(msg % args))
    monkeypatch.setattr(tool_declarations, "_MISSING_BLOCKS_NOTED", set())
    settings = Settings(_env_file=None)
    for _ in range(3):
        assert provider_block_at(settings, SOURCE, "static.no_such_block") is None
    assert len(said) == 1 and "static.no_such_block" in said[0]

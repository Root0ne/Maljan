"""The provider blocks are the shipped ones plus any a provider registers.

* The shipped blocks are unchanged and come first.
* A provider class naming a ``declaration_block`` joins them when it registers:
  its declaration is read there as a built-in's is, the run snapshot walks it,
  and taking the provider out takes the block out.
* A shipped source keeps its shipped block, a path that is not dotted words is
  refused, and a registered block the settings do not hold declares nothing,
  with a warning.
"""

from __future__ import annotations

import pytest

from maljan.core import declared_reading
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


def test_the_shipped_blocks_are_unchanged_and_first() -> None:
    assert shipped_provider_blocks() == {
        "provider:ghidra": "static.ghidra",
        "provider:r2": "static.r2",
        "provider:cape2": "sandbox.cape2.mcp",
    }
    assert list(provider_blocks())[:3] == list(shipped_provider_blocks())


def test_a_registered_block_is_read_walked_and_forgotten() -> None:
    from maljan.core.settings_overrides import declaration_blocks

    settings = Settings(_env_file=None)
    register_provider_block(SOURCE, "static.r2")
    try:
        assert provider_blocks()[SOURCE] == "static.r2"
        assert provider_declarations(settings)[SOURCE] is settings.static.r2
        assert declaration_blocks(settings)[SOURCE] == "static.r2"
    finally:
        forget_provider_block(SOURCE)
        declared_reading.forget()
    assert SOURCE not in provider_blocks()


def test_a_provider_class_naming_its_block_joins_on_registration() -> None:
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


def test_a_block_the_settings_do_not_hold_declares_nothing() -> None:
    settings = Settings(_env_file=None)
    assert provider_block_at(settings, SOURCE, "static.no_such_block") is None
    register_provider_block(SOURCE, "static.no_such_block")
    try:
        assert SOURCE not in provider_declarations(settings)
        # The settings still build: the provider-block check skips it.
        Settings(_env_file=None)
    finally:
        forget_provider_block(SOURCE)
        declared_reading.forget()

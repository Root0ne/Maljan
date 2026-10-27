"""A third-party provider's server block has a place in the settings: ``providers.<id>``.

* Empty by default, and settings written before it existed read as before.
* A block there declares the provider's tools under ``provider:<id>``, with no
  code naming the provider; it comes before the class's declaration hook, and
  the run snapshot walks it like any other block.
* A provider class may name ``providers.<id>`` as its ``declaration_block``;
  another provider's entry there, the map itself and a tool server's block
  are refused. A provider whose class registered another block keeps it, and
  its entry here is not read, said once.
* Each block validates as a tool server's does, and more: a shipped or other
  built-in provider's id, a token, an ``env`` value, a URL with a user name or
  password and a credential bootstrap are refused, and so is a tool declared
  under the provider's renamed spelling.
"""

from __future__ import annotations

from typing import Any

import pytest

from maljan.core import declared_reading
from maljan.core.config import Settings
from maljan.core.settings_overrides import build_settings, declaration_blocks, trim_declarations
from maljan.core.tool_declarations import (
    ToolDeclarations,
    forget_provider_block,
    forget_provider_declaration,
    provider_block,
    provider_blocks,
    provider_declarations,
    register_provider_block,
    register_provider_declaration,
)

PROVIDER = "invented_third_party_g14"
SOURCE = f"provider:{PROVIDER}"
BLOCK: dict[str, Any] = {
    "enabled": True,
    "transport": "streamable-http",
    "url": "http://invented:9000/mcp",
    "env_allow": ["INVENTED_TOKEN"],
    "tool_facts": {"list_strings": {"kind": "strings", "rows": "/strings/*"}},
}


def _settings(**blocks: Any) -> Settings:
    return build_settings({"providers": blocks})


@pytest.fixture(autouse=True)
def _fresh() -> Any:
    declared_reading.forget()
    yield
    declared_reading.forget()


def test_the_place_is_empty_by_default_and_old_settings_read_as_before() -> None:
    assert Settings(_env_file=None).providers == {}
    assert build_settings({}).providers == {}
    before = build_settings({"mcp.breaker.cooldown_seconds": 30.0})
    assert before.providers == {} and before.mcp.breaker.cooldown_seconds == 30.0


def test_a_block_declares_the_providers_tools_with_no_code() -> None:
    settings = _settings(**{PROVIDER: BLOCK})
    block = provider_block(settings, PROVIDER)
    assert block is settings.providers[PROVIDER]
    assert provider_declarations(settings)[SOURCE] is block
    facts = ToolDeclarations.from_settings(settings).declaration_for((SOURCE, "list_strings"))
    assert facts is not None and facts.kind == "strings"
    assert provider_block(settings, "another") is None


def test_the_block_comes_before_the_classs_hook() -> None:
    hooked = {"enabled": True, "tool_facts": {"list_strings": {"kind": "decompile"}}}
    register_provider_declaration(SOURCE, lambda _settings: hooked)
    try:
        with_block = _settings(**{PROVIDER: BLOCK})
        held = provider_declarations(with_block)[SOURCE]
        assert held.tool_facts["list_strings"].kind == "strings"
        without = build_settings({})
        assert provider_declarations(without)[SOURCE].tool_facts["list_strings"].kind == (
            "decompile"
        )
    finally:
        forget_provider_declaration(SOURCE)


def test_the_run_snapshot_walks_the_block() -> None:
    settings = _settings(**{PROVIDER: BLOCK})
    assert declaration_blocks(settings)[SOURCE] == f"providers.{PROVIDER}"
    snap = {
        f"providers.{PROVIDER}.tool_facts": {"x": 1},
        f"providers.{PROVIDER}.roles": [],
    }
    # Set in the stored map: kept; any field it did not set is named by a digest.
    out = trim_declarations(snap, settings, {"providers": {PROVIDER: {"tool_facts": {}}}})
    assert f"providers.{PROVIDER}.tool_facts" in out
    assert f"providers.{PROVIDER}.roles" not in out
    assert f"declaration_digest.{SOURCE}" in out


def test_a_class_may_name_its_own_entry_as_its_block() -> None:
    from maljan.providers.registry import forget_static_provider, register_static_provider

    @register_static_provider(PROVIDER)
    class _Invented:
        declaration_block = f"providers.{PROVIDER}"

    try:
        assert provider_blocks()[SOURCE] == f"providers.{PROVIDER}"
        settings = _settings(**{PROVIDER: BLOCK})
        assert provider_declarations(settings)[SOURCE] is settings.providers[PROVIDER]
    finally:
        forget_static_provider(PROVIDER)
    assert SOURCE not in provider_blocks()


@pytest.mark.parametrize(
    ("path", "words"),
    [
        ("providers.another", "its block there"),
        ("providers", "its block there"),
        (f"providers.{PROVIDER}.sample_open", "its block there"),
        ("mcp.servers.analysis", "tool server's block"),
        ("mcp.servers", "tool server's block"),
    ],
)
def test_another_entry_the_map_and_a_tool_servers_block_are_refused(path: str, words: str) -> None:
    with pytest.raises(ValueError, match=words):
        register_provider_block(SOURCE, path)
    assert SOURCE not in provider_blocks()


def test_a_registered_entry_the_settings_do_not_hold_declares_nothing() -> None:
    register_provider_block(SOURCE, f"providers.{PROVIDER}")
    try:
        assert SOURCE not in provider_declarations(build_settings({}))
    finally:
        forget_provider_block(SOURCE)


def test_an_entry_of_a_provider_whose_class_names_another_block_is_not_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from maljan.core import tool_declarations
    from maljan.core.logger import logger

    # ``static.r2`` with its shipped owner left out: a block no shipped source owns.
    shipped = {k: v for k, v in tool_declarations.shipped_provider_blocks().items()}
    shipped.pop("provider:r2")
    monkeypatch.setattr(tool_declarations, "shipped_provider_blocks", lambda: dict(shipped))
    monkeypatch.setattr(tool_declarations, "_UNREAD_ENTRIES_NOTED", set())
    said: list[str] = []
    monkeypatch.setattr(logger, "warning", lambda msg, *args: said.append(msg % args))
    register_provider_block(SOURCE, "static.r2")
    try:
        assert tool_declarations.elsewhere_declared(PROVIDER) == "static.r2"
        settings = _settings(**{PROVIDER: BLOCK})
        for _ in range(2):
            assert provider_declarations(settings)[SOURCE] is settings.static.r2
        assert len(said) == 1 and f"providers.{PROVIDER}" in said[0] and "static.r2" in said[0]
    finally:
        forget_provider_block(SOURCE)
    assert tool_declarations.elsewhere_declared(PROVIDER) == ""


@pytest.mark.parametrize(
    ("key", "block", "words"),
    [
        ("Bad Key", BLOCK, "provider id is"),
        ("ghidra", BLOCK, "shipped block"),
        ("generic_mcp", BLOCK, "built-in provider"),
        ("mock", BLOCK, "built-in provider"),
        (PROVIDER, {**BLOCK, "auth_token": "t0ken"}, "holds no credential"),
        (PROVIDER, {**BLOCK, "url": "http://user:pw@invented:9000/mcp"}, "holds no credential"),
        (PROVIDER, {**BLOCK, "url": "http://user@invented:9000/mcp"}, "holds no credential"),
        (PROVIDER, {**BLOCK, "env": {"INVENTED": "value"}}, "holds no credential"),
        (
            PROVIDER,
            {**BLOCK, "credential_bootstrap": {"url": "https://example.invalid/token"}},
            "credential_bootstrap",
        ),
        (
            PROVIDER,
            {**BLOCK, "tool_facts": {f"{PROVIDER}__list_strings": {"kind": "strings"}}},
            "renamed tool",
        ),
        (PROVIDER, {**BLOCK, "roles": ["Not A Word"]}, "role"),
    ],
)
def test_a_block_is_validated_as_a_tool_servers_and_holds_no_credential(
    key: str, block: dict[str, Any], words: str
) -> None:
    with pytest.raises(ValueError, match=words):
        _settings(**{key: block})

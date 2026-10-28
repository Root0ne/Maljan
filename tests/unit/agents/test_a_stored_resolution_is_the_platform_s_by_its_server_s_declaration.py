"""A stored API hash resolution is the platform's own by what its server declares (T-418 PR7).

An entry written before entries recorded their source is read by the legacy
reading, and whether its resolution was the platform's own was read against a
list of two server names (the pack's and the analysis server's). It is now
read from the declaration of the source the entry's server names: the pack's
for an entry the pack recorded, else the tool server of that key, and only a
source that declares ``platform_owned`` owns it. A server nobody shipped that
an operator declares as the platform's own reads as the analysis server does.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from maljan.agents.evidence_recorder import _platforms_own_resolution
from maljan.core.config import Settings
from maljan.core.declared_reading import kind_of


def _legacy(server: str) -> Any:
    return SimpleNamespace(tool="resolve_api_hashes", server=server, source=None, facts=None)


def _install(monkeypatch: pytest.MonkeyPatch, settings: Settings) -> None:
    monkeypatch.setattr("maljan.core.config.get_settings", lambda: settings)


def test_the_legacy_entry_is_a_resolution() -> None:
    assert kind_of(_legacy("analysis")) == "api_hash_resolution"


@pytest.mark.parametrize("server", ["pipeline", "analysis"])
def test_the_pack_s_and_the_analysis_server_s_stay_the_platform_s(
    monkeypatch: pytest.MonkeyPatch, server: str
) -> None:
    _install(monkeypatch, Settings())
    assert _platforms_own_resolution(_legacy(server)) is True


@pytest.mark.parametrize("server", ["knowledge", "ghidra", "", "nobody"])
def test_another_server_s_is_not(monkeypatch: pytest.MonkeyPatch, server: str) -> None:
    _install(monkeypatch, Settings())
    assert _platforms_own_resolution(_legacy(server)) is False


def test_a_never_seen_server_declared_as_the_platform_s_reads_as_the_analysis_server(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings.model_validate(
        {"mcp": {"servers": {"acme": {"command": "x", "enabled": True, "platform_owned": True}}}}
    )
    _install(monkeypatch, settings)
    assert _platforms_own_resolution(_legacy("acme")) is True


def test_an_analysis_server_an_operator_says_is_not_the_platform_s_is_not(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings.model_validate(
        {"mcp": {"servers": {"analysis": {"platform_owned": False}}}}
    )
    _install(monkeypatch, settings)
    assert _platforms_own_resolution(_legacy("analysis")) is False

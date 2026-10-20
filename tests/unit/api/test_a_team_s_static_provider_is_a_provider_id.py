"""A team's ``static_provider`` is a provider id, judged as an agent definition's is.

The team's choice outranks every other source at run time, so an id no
provider has is refused on save at the team's own key, a stored one is read
past so the console still opens, and a plugin only a team selects is a
selection: dropping it from the allow-list is refused and it is loaded.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from pydantic import ValidationError
from tests.unit._plugin_doubles import (
    AcmeStatic,
    FakePoint,
    installed_plugins,
    withdraw_every_plugin,
)

from maljan.core import plugins
from maljan.core.settings_overrides import build_settings, stored_settings

PROFILES = "core.agents.profiles"


@pytest.fixture
def installed(monkeypatch: pytest.MonkeyPatch) -> Iterator[dict[str, list[FakePoint]]]:
    yield installed_plugins(monkeypatch)
    withdraw_every_plugin()


def _team(provider: str) -> dict[str, Any]:
    return {
        "t1": {
            "label": "T1",
            "analysts": ["static", "dynamic", "network"],
            "static_provider": provider,
        }
    }


class TestTheSettingsModel:
    def test_an_unknown_id_is_refused_at_the_team_s_own_key(self) -> None:
        with pytest.raises(ValidationError) as refused:
            build_settings({"agents.profiles": _team("no_such_provider")})
        (error,) = refused.value.errors()
        assert error["loc"] == ("agents", "profiles", "t1", "static_provider")
        assert "unknown static provider 'no_such_provider'" in error["msg"]

    def test_a_shipped_id_and_none_are_accepted(self) -> None:
        for provider in ("ghidra", "none"):
            built = build_settings({"agents.profiles": _team(provider)})
            assert built.agents.profiles["t1"].static_provider == provider

    def test_a_stored_unknown_id_does_not_stop_the_console_from_opening(self) -> None:
        built, refused = stored_settings({"agents.profiles": _team("no_such_provider")})
        assert "t1" not in built.agents.profiles
        assert "unknown static provider" in refused["agents.profiles"]

    def test_an_installed_plugin_counts_only_once_the_list_names_it(
        self, installed: dict[str, list[FakePoint]]
    ) -> None:
        installed["static"].append(FakePoint("acme_static", AcmeStatic))
        with pytest.raises(ValidationError, match="plugin allow-list"):
            build_settings({"agents.profiles": _team("acme_static")})
        built = build_settings(
            {"agents.profiles": _team("acme_static"), "plugins.allowed": ["static:acme_static"]}
        )
        assert built.agents.profiles["t1"].static_provider == "acme_static"


class TestTheSelections:
    def test_a_team_s_choice_is_a_selection(self) -> None:
        core = {"agents.profiles": _team("myplug")}
        assert ("core.agents.profiles.t1.static_provider", "static", "myplug") in (
            plugins.selections(core)
        )

    def test_dropping_a_plugin_only_a_team_selects_is_named(
        self, installed: dict[str, list[FakePoint]]
    ) -> None:
        installed["static"].append(FakePoint("acme", AcmeStatic))
        errors = plugins.dropped_selections(["static:acme"], [], {"agents.profiles": _team("acme")})
        assert set(errors) == {"core.agents.profiles.t1.static_provider", "core.plugins.allowed"}


class TestTheConsoleSave:
    def test_an_unknown_id_is_refused_at_the_team_s_own_key(self) -> None:
        from app.services.agent_map import AgentMapError, validate_agent_map

        with pytest.raises(AgentMapError) as refused:
            validate_agent_map({PROFILES: _team("no_such_provider")}, {})
        said = refused.value.errors[f"{PROFILES}.t1.static_provider"]
        assert "unknown static provider 'no_such_provider'" in said

    def test_an_installed_plugin_is_saved_by_the_list_the_save_leaves(
        self, installed: dict[str, list[FakePoint]]
    ) -> None:
        from app.services.agent_map import AgentMapError, validate_agent_map

        installed["static"].append(FakePoint("acme_static", AcmeStatic))
        changes = {PROFILES: _team("acme_static")}
        with pytest.raises(AgentMapError) as refused:
            validate_agent_map(changes, {})
        assert "plugin allow-list" in refused.value.errors[f"{PROFILES}.t1.static_provider"]
        stored = {"core.plugins.allowed": ["static:acme_static"]}
        assert PROFILES in validate_agent_map(changes, stored)
        assert PROFILES in validate_agent_map({**changes, **stored}, {})


class TestWhatATeamSelectsIsSelectedForRuns:
    def test_the_agent_probe_loads_a_plugin_a_team_selects(
        self, installed: dict[str, list[FakePoint]]
    ) -> None:
        from app.services import plugins as api_plugins

        installed["static"].append(FakePoint("acme_static", AcmeStatic))
        core = {"agents.profiles": _team("acme_static")}
        allowed = ["static:acme_static"]
        assert api_plugins.selected_plugins(core, allowed, ("static",), "static") == [
            "static:acme_static"
        ]

    def test_the_mirrored_work_dirs_count_a_team_s_static_provider(self) -> None:
        from maljan.core.tool_declarations import selected_static_providers

        built = build_settings({"static.provider": "none", "agents.profiles": _team("r2")})
        assert {"none", "r2"} <= selected_static_providers(built)

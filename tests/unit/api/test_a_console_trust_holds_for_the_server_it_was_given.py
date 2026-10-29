"""A trust in a server's own declaration given from the console holds for that server alone.

A built-in block ships trusting what its server declares, and that trust
holds only while the block still starts the server it shipped with. The
console shows the trust in force, so a block pointed elsewhere shows none;
an operator's tick there is recorded with the launch it was given for
(``trust_granted_for``), and pointing the block at yet another server
withdraws it. The shipped value posted back is never read as a tick, and a
release that changes nothing of the launch keeps the grant.
"""

from __future__ import annotations

from typing import Any

import pytest

from app.services.server_map import shown_trust_of, validate_server_map
from maljan.core.config import Settings
from maljan.core.settings_overrides import build_settings
from maljan.core.tool_declarations import ToolDeclarations


def _trusted(out: dict[str, Any], key: str) -> bool:
    settings = build_settings({"mcp": {"servers": out}})
    held = ToolDeclarations.from_settings(settings).source(f"mcp:{key}")
    assert held is not None
    return held.trusts_served


def _shipped(key: str = "analysis") -> dict[str, Any]:
    entry = Settings(_env_file=None).mcp.servers[key].model_dump(mode="json")
    entry.pop("auth_token", None)
    return entry


def _shown(key: str, stored: dict[str, Any]) -> dict[str, Any]:
    """A stored entry as the console is served it and sends it back unchanged."""
    entry = {k: v for k, v in stored.items() if k != "trust_granted_for"}
    return {**entry, **shown_trust_of(key, stored)}


def test_the_shipped_trust_posted_back_by_a_repointed_built_in_is_no_grant() -> None:
    entry = {**_shipped(), "command": "/usr/bin/third-party-mcp", "args": []}
    assert entry["trusts_served_declaration"] is True
    out = validate_server_map({"analysis": entry})
    assert "trust_granted_for" not in out["analysis"]
    assert _trusted(out, "analysis") is False


def test_a_repointed_built_in_is_shown_without_the_trust_it_no_longer_has() -> None:
    shipped = _shipped()
    shown = shown_trust_of("analysis", shipped)
    assert shown["trusts_served_declaration"] is True
    assert shown["trust_granted_for"]
    moved = {**shipped, "command": "/usr/bin/third-party-mcp", "args": []}
    stored = validate_server_map({"analysis": moved})["analysis"]
    # The row stores no flag, and is shown with none (the box reads off), so
    # saving it unchanged stores none and the block keeps following what ships.
    assert "trusts_served_declaration" not in stored
    assert shown_trust_of("analysis", stored) == {}
    again = validate_server_map({"analysis": _shown("analysis", stored)})
    assert "trusts_served_declaration" not in again["analysis"]
    assert _trusted(again, "analysis") is False


def test_an_operator_s_tick_on_a_repointed_built_in_trusts_the_server_it_points_at() -> None:
    entry = {
        **_shipped(),
        "command": "/usr/bin/third-party-mcp",
        "args": [],
        "trusts_served_declaration": True,
        "trust_granted_for": "",
    }
    out = validate_server_map({"analysis": entry})
    assert out["analysis"]["trust_granted_for"]
    assert _trusted(out, "analysis") is True
    assert shown_trust_of("analysis", out["analysis"])["trusts_served_declaration"] is True


def test_a_granted_trust_is_kept_by_an_unchanged_save_and_withdrawn_by_a_repoint() -> None:
    ticked = {
        **_shipped(),
        "command": "/usr/bin/third-party-mcp",
        "args": [],
        "trusts_served_declaration": True,
        "trust_granted_for": "",
    }
    stored = validate_server_map({"analysis": ticked})["analysis"]
    again = validate_server_map({"analysis": _shown("analysis", stored)})
    assert again["analysis"]["trust_granted_for"] == stored["trust_granted_for"]
    assert _trusted(again, "analysis") is True

    moved = {**_shown("analysis", stored), "command": "/usr/bin/yet-another-mcp"}
    assert moved["trusts_served_declaration"] is True
    out = validate_server_map({"analysis": moved})
    assert "trust_granted_for" not in out["analysis"]
    assert _trusted(out, "analysis") is False
    # Pointed back at the server it ships with, its shipped trust holds again.
    back = {k: v for k, v in out["analysis"].items() if k not in ("command", "args")}
    back.update(command=_shipped()["command"], args=_shipped()["args"])
    assert _trusted(validate_server_map({"analysis": back}), "analysis") is True


def test_a_trusted_server_an_operator_added_loses_its_trust_when_pointed_elsewhere() -> None:
    entry = {
        "enabled": True,
        "command": "/usr/bin/mine-mcp",
        "agents": [],
        "trusts_served_declaration": True,
        "trust_granted_for": "",
    }
    stored = validate_server_map({"mine": entry})["mine"]
    assert _trusted({"mine": stored}, "mine") is True
    moved = {**_shown("mine", stored), "command": "/usr/bin/other-mcp"}
    out = validate_server_map({"mine": moved})
    assert out["mine"]["trusts_served_declaration"] is False
    assert _trusted(out, "mine") is False


def test_a_shipped_trust_is_shown_and_kept_at_the_shipped_server() -> None:
    shipped = _shipped()
    out = validate_server_map({"analysis": _shown("analysis", shipped)})
    assert "trusts_served_declaration" not in out["analysis"]
    assert "trust_granted_for" not in out["analysis"]
    assert _trusted(out, "analysis") is True


def test_an_untick_turns_the_trust_off() -> None:
    entry = {**_shown("analysis", _shipped()), "trusts_served_declaration": False}
    entry["trust_granted_for"] = None
    out = validate_server_map({"analysis": entry})
    assert out["analysis"]["trusts_served_declaration"] is False
    assert _trusted(out, "analysis") is False


def test_a_grant_outlives_a_release_that_changes_nothing_of_the_launch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import maljan.core.tool_declarations as td

    entry = {
        **_shipped(),
        "command": "/usr/bin/third-party-mcp",
        "args": [],
        "trusts_served_declaration": True,
        "trust_granted_for": "",
    }
    out = validate_server_map({"analysis": entry})
    monkeypatch.setattr(td, "KEPT_DECLARATIONS_RELEASE", "a-later-release+99")
    assert _trusted(out, "analysis") is True


def test_a_stored_grant_for_another_launch_trusts_nothing() -> None:
    row = {
        "enabled": True,
        "command": "/usr/bin/mine-mcp",
        "agents": [],
        "trusts_served_declaration": True,
        "trust_granted_for": "0123456789abcdef",
    }
    assert _trusted({"mine": row}, "mine") is False
    assert shown_trust_of("mine", row) == {"trusts_served_declaration": False}


def test_the_settings_answer_shows_each_block_s_trust_in_force() -> None:
    from app.services.settings_service import SettingsService

    moved = {**_shipped(), "command": "/usr/bin/third-party-mcp", "args": []}
    stored = validate_server_map({"analysis": moved})
    service = object.__new__(SettingsService)
    shown = service._masked_server_map(stored, Settings(_env_file=None).mcp.servers, {})
    assert shown["analysis"].get("trusts_served_declaration", False) is False
    assert "trust_granted_for" not in shown["analysis"]
    # A re-seeded built-in at the server it ships with: its stored row holds
    # no flag, and it is shown trusting, with the launch the trust holds for.
    assert "trusts_served_declaration" not in stored["yarax"]
    assert shown["yarax"]["trusts_served_declaration"] is True
    assert shown["yarax"]["trust_granted_for"]

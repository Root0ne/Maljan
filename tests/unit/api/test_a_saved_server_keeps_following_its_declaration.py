"""A saved tool-server map stores only the declaration an operator wrote.

The map is stored whole on every save. A built-in row that carried each shipped
declaration field would freeze it at the day of the save; so a field equal to
the shipped value is left out of the stored row and comes back on load, and a
value of the operator's own, an empty one included, is stored and kept.
"""

from __future__ import annotations

import pytest

from app.services.server_map import ServerMapError, validate_server_map
from maljan.core.config import Settings


def _entry(**over: object) -> dict:
    base: dict = {"enabled": True, "transport": "stdio", "command": "python", "agents": []}
    base.update(over)
    return base


def test_a_built_in_saved_with_its_shipped_declaration_stores_none_of_it() -> None:
    shipped = Settings().mcp.servers["analysis"].model_dump(mode="json")
    out = validate_server_map({"analysis": {**shipped, "enabled": False}})
    stored = out["analysis"]
    assert stored["enabled"] is False
    for name in ("tool_facts", "roles", "required_env_allow", "reads_staged_sample"):
        assert name not in stored, name
    loaded = Settings.model_validate({"mcp": {"servers": out}}).mcp.servers["analysis"]
    assert loaded.tool_facts["capa"].kind == "rule_match"


def test_a_built_in_saved_without_the_fields_keeps_following_them() -> None:
    out = validate_server_map({"threatintel": _entry(agents=["judge"])})
    assert "roles" not in out["threatintel"]
    loaded = Settings.model_validate({"mcp": {"servers": out}}).mcp.servers["threatintel"]
    assert loaded.roles == ["reputation"]


def test_an_operators_own_value_on_a_built_in_is_stored_even_empty() -> None:
    out = validate_server_map({"threatintel": _entry(agents=["judge"], roles=[])})
    assert out["threatintel"]["roles"] == []
    loaded = Settings.model_validate({"mcp": {"servers": out}}).mcp.servers["threatintel"]
    assert loaded.roles == []


def test_a_reseeded_built_in_stores_no_declaration() -> None:
    out = validate_server_map({"mine": _entry()})
    assert "tool_facts" not in out["virustotal"]
    assert out["virustotal"]["tools"]  # its launch settings are still seeded


def test_an_operators_server_stores_its_declaration_whole() -> None:
    facts = {"scan": {"kind": "rule_match", "rows": "/hits/*", "values": {"rule": "/name"}}}
    out = validate_server_map(
        {"mine": _entry(roles=["rule_scanner"], tool_facts=facts, sample_mount="/in")}
    )
    assert out["mine"]["roles"] == ["rule_scanner"]
    assert out["mine"]["tool_facts"]["scan"]["rows"] == "/hits/*"
    assert out["mine"]["sample_mount"] == "/in"


def test_a_malformed_declaration_is_refused_with_the_field_named() -> None:
    with pytest.raises(ServerMapError) as exc:
        validate_server_map({"mine": _entry(tool_facts={"scan": {"kind": "Rule Match"}})})
    assert any(key.startswith("mine.tool_facts") for key in exc.value.errors)
    with pytest.raises(ServerMapError) as exc:
        validate_server_map({"mine": _entry(error_patterns=[{"match": "(open"}])})
    assert any("not a valid regular expression" in m for m in exc.value.errors.values())

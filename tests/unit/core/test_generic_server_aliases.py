"""A .env written for sub-project A's static.generic block still works."""

from __future__ import annotations

from maljan.core.config import GENERIC_SERVER_KEY, Settings, apply_settings_aliases


def test_a_legacy_command_lands_on_the_custom_server_and_binds_it_to_static():
    out = apply_settings_aliases({"static": {"generic": {"command": "my-mcp", "enabled": True}}})
    server = out["mcp"]["servers"][GENERIC_SERVER_KEY]
    assert server["command"] == "my-mcp" and server["enabled"] is True
    assert server["agents"] == ["static"]
    assert out["static"]["generic"]["server"] == GENERIC_SERVER_KEY
    assert "command" not in out["static"]["generic"]


def test_the_json_leaves_survive_the_move():
    out = apply_settings_aliases(
        {"static": {"generic": {"args": '["--stdio"]', "env": '{"A": "b"}'}}}
    )
    server = out["mcp"]["servers"][GENERIC_SERVER_KEY]
    assert server["args"] == ["--stdio"] and server["env"] == {"A": "b"}


def test_a_settings_built_from_the_legacy_shape_attaches_the_custom_server():
    cfg = Settings(_env_file=None, static={"generic": {"command": "my-mcp", "enabled": True}})
    assert cfg.static.generic.server == GENERIC_SERVER_KEY
    assert cfg.mcp.servers[GENERIC_SERVER_KEY].command == "my-mcp"
    assert cfg.mcp.servers[GENERIC_SERVER_KEY].agents == ["static"]
    assert set(cfg.mcp.servers) >= {"network", "threatintel", GENERIC_SERVER_KEY}


def test_nothing_is_invented_when_no_legacy_key_is_present():
    cfg = Settings(_env_file=None)
    assert cfg.static.generic.server == ""
    assert set(cfg.mcp.servers) == {"network", "threatintel"}


def test_a_hand_written_custom_server_does_not_bind_static_generic(monkeypatch):
    """Regression (F3): the completion used to fire on any ``custom`` entry.

    An operator who names a UI- or env-added server ``custom`` -- with no
    ``static.generic.*`` alias in play at all -- must not have
    ``static.generic.server`` defaulted to it, or picking
    ``static.provider=generic_mcp`` with no explicit server would silently
    drive this unrelated entry.
    """
    monkeypatch.setenv("MCP__SERVERS__CUSTOM__COMMAND", "hand-written-mcp")
    monkeypatch.setenv("MCP__SERVERS__CUSTOM__ENABLED", "true")
    cfg = Settings(_env_file=None)
    assert cfg.mcp.servers[GENERIC_SERVER_KEY].command == "hand-written-mcp"
    assert cfg.static.generic.server == ""


def test_the_aliased_path_still_binds_it():
    out = apply_settings_aliases({"static": {"generic": {"command": "aliased-mcp"}}})
    assert out["static"]["generic"]["server"] == GENERIC_SERVER_KEY

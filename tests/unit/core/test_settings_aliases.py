"""Legacy environment variables must keep producing the same effective values.

The first test is a probe, not a feature test: it pins the shape the
``mode="before"`` validator sees when pydantic-settings has assembled the
env/dotenv sources. If it ever fails, the fallback is the
``settings_customise_sources`` pre-pass documented in the plan — same alias
table, applied one source at a time.
"""

from __future__ import annotations

import pytest

from maljan.core.config import SETTINGS_ALIASES, Settings, apply_settings_aliases


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in (
        "MCP__GHIDRA__URL",
        "MCP__GHIDRA__ENABLED",
        "MCP__GHIDRA__TRANSPORT",
        "MCP__GHIDRA__AUTH_TOKEN",
        "MCP__GHIDRA__TOOL_SELECTION",
        "MCP__CAPE__ENABLED",
        "MCP__CAPE__URL",
        "SANDBOX__BACKEND",
        "SANDBOX__PROVIDER",
        "SANDBOX__CAPE2_BASE_URL",
        "SANDBOX__CAPE2_API_TOKEN",
        "SANDBOX__CAPE2_TIMEOUT_SECONDS",
        "SANDBOX__CAPE2_POLL_INTERVAL_SECONDS",
        "SANDBOX__CAPE2__BASE_URL",
        "STATIC__PROVIDER",
        "STATIC__GHIDRA__URL",
    ):
        monkeypatch.delenv(var, raising=False)


def test_the_validator_sees_the_env_derived_nested_dict(monkeypatch):
    """PROBE: env vars reach ``mode='before'`` as a nested dict, not as strings."""
    seen: list[dict] = []
    monkeypatch.setenv("MCP__GHIDRA__URL", "http://ghidra.example:8089")
    monkeypatch.setenv("SANDBOX__BACKEND", "cape2")

    original = Settings._alias_legacy_keys.__func__  # type: ignore[attr-defined]

    def spy(cls, data):
        if isinstance(data, dict):
            seen.append(dict(data))
        return original(cls, data)

    monkeypatch.setattr(Settings, "_alias_legacy_keys", classmethod(spy))
    Settings(_env_file=None)

    assert seen, "the before-validator never ran"
    payload = seen[0]
    assert isinstance(payload.get("mcp"), dict), payload.get("mcp")
    assert payload["mcp"]["ghidra"]["url"] == "http://ghidra.example:8089"
    assert payload["sandbox"]["backend"] == "cape2"


def test_legacy_ghidra_env_lands_on_static_ghidra(monkeypatch):
    monkeypatch.setenv("MCP__GHIDRA__ENABLED", "true")
    monkeypatch.setenv("MCP__GHIDRA__TRANSPORT", "http")
    monkeypatch.setenv("MCP__GHIDRA__URL", "http://ghidra.example:8089")
    monkeypatch.setenv("MCP__GHIDRA__TOOL_SELECTION", "curated")
    s = Settings(_env_file=None)
    assert s.static.ghidra.enabled is True
    assert s.static.ghidra.transport == "http"
    assert s.static.ghidra.url == "http://ghidra.example:8089"
    assert s.static.ghidra.tool_selection == "curated"


def test_legacy_sandbox_env_lands_on_the_nested_cape2_block(monkeypatch):
    monkeypatch.setenv("SANDBOX__BACKEND", "cape2")
    monkeypatch.setenv("SANDBOX__CAPE2_BASE_URL", "http://cape.example:8000")
    monkeypatch.setenv("SANDBOX__CAPE2_API_TOKEN", "not-a-real-token")
    monkeypatch.setenv("SANDBOX__CAPE2_TIMEOUT_SECONDS", "1200")
    monkeypatch.setenv("SANDBOX__CAPE2_POLL_INTERVAL_SECONDS", "15")
    s = Settings(_env_file=None)
    assert s.sandbox.provider == "cape2"
    assert s.sandbox.cape2.base_url == "http://cape.example:8000"
    assert s.sandbox.cape2.api_token.get_secret_value() == "not-a-real-token"
    assert s.sandbox.cape2.timeout_seconds == 1200
    assert s.sandbox.cape2.poll_interval_seconds == 15


def test_legacy_cape_mcp_env_lands_under_sandbox_cape2_mcp(monkeypatch):
    monkeypatch.setenv("MCP__CAPE__ENABLED", "true")
    monkeypatch.setenv("MCP__CAPE__URL", "http://cape-mcp.example:9004/mcp/")
    s = Settings(_env_file=None)
    assert s.sandbox.cape2.mcp.enabled is True
    assert s.sandbox.cape2.mcp.url == "http://cape-mcp.example:9004/mcp/"


def test_the_new_key_wins_over_the_legacy_one(monkeypatch):
    monkeypatch.setenv("SANDBOX__BACKEND", "cape2")
    monkeypatch.setenv("SANDBOX__PROVIDER", "mock")
    monkeypatch.setenv("MCP__GHIDRA__URL", "http://legacy:8089")
    monkeypatch.setenv("STATIC__GHIDRA__URL", "http://new:8089")
    s = Settings(_env_file=None)
    assert s.sandbox.provider == "mock"
    assert s.static.ghidra.url == "http://new:8089"


def test_aliasing_is_a_pure_function_over_a_plain_dict():
    out = apply_settings_aliases({"sandbox": {"backend": "cape2", "cape2_base_url": "http://x:1"}})
    assert out["sandbox"]["provider"] == "cape2"
    assert out["sandbox"]["cape2"]["base_url"] == "http://x:1"
    assert "backend" not in out["sandbox"]
    assert "cape2_base_url" not in out["sandbox"]


def test_every_alias_names_a_real_new_path():
    flat = {
        "static.ghidra",
        "sandbox.cape2.mcp",
        "sandbox.provider",
        "sandbox.cape2.base_url",
        "sandbox.cape2.api_token",
        "sandbox.cape2.timeout_seconds",
        "sandbox.cape2.poll_interval_seconds",
        "mcp.servers.custom.enabled",
        "mcp.servers.custom.transport",
        "mcp.servers.custom.command",
        "mcp.servers.custom.args",
        "mcp.servers.custom.env",
        "mcp.servers.custom.url",
        "mcp.servers.custom.auth_token",
        "mcp.servers.custom.tool_selection",
        "mcp.servers.custom.use_all_tools",
    }
    assert {new for _old, new in SETTINGS_ALIASES} == flat


def test_defaults_are_todays_defaults():
    s = Settings(_env_file=None)
    assert s.static.provider == "ghidra"
    assert s.sandbox.provider == "mock"
    assert s.sandbox.cape2.base_url == "http://localhost:8000"
    assert s.sandbox.cape2.timeout_seconds == 300
    assert s.sandbox.cape2.poll_interval_seconds == 10
    assert s.sandbox.upload.max_report_bytes == 67_108_864
    assert s.sandbox.triage.base_url == "https://tria.ge/api/v0"


def test_one_deprecation_warning_per_process(monkeypatch, caplog):
    import maljan.core.config as config_module

    monkeypatch.setattr(config_module, "_ALIAS_WARNED", False, raising=False)
    monkeypatch.setenv("SANDBOX__BACKEND", "cape2")
    with caplog.at_level("WARNING"):
        Settings(_env_file=None)
        Settings(_env_file=None)
    hits = [r for r in caplog.records if "legacy setting name" in r.getMessage()]
    assert len(hits) == 1

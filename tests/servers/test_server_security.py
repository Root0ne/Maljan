# tests/servers/test_server_security.py
"""What a tool server may see, and what may never leave the process.

The set of guarantees the trust-boundary paragraph in the README makes. Each
one is small; together they are the reason connecting a third party's MCP
server to a malware pipeline is a considered act rather than a reckless one.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import SecretStr

from maljan.agents.subprocess_env import child_env
from maljan.core.config import MCPServerConfig, Settings
from maljan.providers.errors import ProviderConfigurationError
from maljan.providers.servers import ServerHandle


def test_a_server_token_never_appears_in_a_run_summary():
    from app.worker.analysis_worker import settings_snapshot

    cfg = Settings(_env_file=None)
    cfg.mcp.servers["custom"] = MCPServerConfig(
        enabled=True, transport="http", url="https://h", auth_token="s3cr3t"
    )
    # A runtime-built value, the same shape a stored override arrives in — a
    # plain string assigned to a ``SecretStr`` field, not the literal wrapped
    # at construction time.
    cfg.sandbox.rest.auth.token = SecretStr("r3st")
    snap = json.dumps(settings_snapshot(cfg))
    assert "s3cr3t" not in snap and "r3st" not in snap


def test_a_server_token_never_appears_in_a_repr_or_a_log_line(caplog):
    server = MCPServerConfig(enabled=True, transport="http", url="https://h", auth_token="s3cr3t")
    handle = ServerHandle("custom", server)
    assert "s3cr3t" not in repr(server)
    assert "s3cr3t" not in repr(handle.config)
    with caplog.at_level("DEBUG"):
        handle.close()
    assert "s3cr3t" not in caplog.text


def test_a_child_sees_the_base_keys_plus_only_the_names_it_was_allowed():
    source = {
        "PATH": "/usr/bin",
        "HOME": "/home/x",
        "VIRUSTOTAL_API_KEY": "vt",
        "SETTINGS_ENCRYPTION_KEY": "no",
        "DATABASE_URL": "no",
        "OPENAI_API_KEY": "no",
    }
    env = child_env({"MY": "1"}, allow=("VIRUSTOTAL_API_KEY",), source=source)
    assert env["VIRUSTOTAL_API_KEY"] == "vt" and env["MY"] == "1"
    assert "SETTINGS_ENCRYPTION_KEY" not in env
    assert "DATABASE_URL" not in env
    assert "OPENAI_API_KEY" not in env


def test_a_server_is_launched_with_an_argv_list_and_never_through_a_shell(monkeypatch):
    seen: dict[str, object] = {}

    class _Params:
        def __init__(self, command, args, env, cwd=None):
            seen.update({"command": command, "args": args, "env": env, "cwd": cwd})

    monkeypatch.setattr("mcp.StdioServerParameters", _Params)
    monkeypatch.setattr("maljan.providers.servers._run_async", lambda coro, label: None)

    class _Toolkit:
        def __init__(self, *a, **k):
            pass

        async def initialize(self):
            return None

        def get_tools(self):
            return []

    monkeypatch.setattr("maljan.agents.mcp_client.MCPLangChainToolkit", _Toolkit)
    # No "/" in the payload: ``resolve_mcp_args`` roots anything path-shaped at
    # the project directory, which is a separate, deliberate behavior this
    # test is not about — the point here is that the argument reaches the
    # child as one list element, not parsed by a shell.
    handle = ServerHandle(
        "x", MCPServerConfig(enabled=True, command="mcp", args=["--flag", "a b; rm -rf now"])
    )
    handle.open("job-1")
    assert isinstance(seen["args"], list)
    assert seen["args"][-1] == "a b; rm -rf now", "an argument is data, never shell syntax"
    assert "shell" not in seen


def test_an_absolute_cwd_must_exist(tmp_path):
    handle = ServerHandle("x", MCPServerConfig(enabled=True, command="mcp", cwd=str(tmp_path)))
    # An existing absolute directory is allowed; a missing one is not.
    missing = ServerHandle(
        "y", MCPServerConfig(enabled=True, command="mcp", cwd=str(tmp_path / "nope"))
    )
    assert handle._resolve_cwd() == str(Path(tmp_path).resolve())
    with pytest.raises(ProviderConfigurationError):
        missing._resolve_cwd()


def test_a_server_token_never_lands_in_the_map_row_it_arrived_in():
    """The map is one non-secret JSONB row; the token goes to its own encrypted one."""
    from app.services.server_map import split_server_secrets

    cleaned, tokens = split_server_secrets(
        {"x": {"enabled": True, "transport": "http", "url": "https://h", "auth_token": "s3cr3t"}}
    )
    assert "s3cr3t" not in str(cleaned)
    assert "auth_token" not in cleaned["x"]
    assert tokens == {"x": "s3cr3t"}

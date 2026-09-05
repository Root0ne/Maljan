# tests/servers/test_server_security.py
"""What a tool server may see, and what may never leave the process.

The set of guarantees the trust-boundary paragraph in the README makes. Each
one is small; together they are the reason connecting a third party's MCP
server to a malware pipeline is a considered act rather than a reckless one.
"""

from __future__ import annotations

import asyncio
import json
import uuid
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
    snap = settings_snapshot(cfg)
    dumped = json.dumps(snap)
    assert "s3cr3t" not in dumped and "r3st" not in dumped
    # Not merely absent — masked in the specific shape each field's type
    # produces: a nested server token by ``SecretStr``'s own serializer (ten
    # asterisks), a catalog leaf by ``public_snapshot``'s own convention.
    assert snap["mcp.servers.custom.auth_token"] == "**********"
    assert snap["sandbox.rest.auth.token"] == "***"


def test_a_server_token_never_appears_in_a_repr(monkeypatch, caplog):
    """Repr, a registry degrade, and a failed open all name the server, never its token."""
    from maljan.providers.servers import UNAVAILABLE_REASON, ServerRegistry

    token = f"s3cr3t-{uuid.uuid4().hex}"
    server = MCPServerConfig(
        enabled=True, transport="http", url="https://h", auth_token=token, agents=["network"]
    )
    handle = ServerHandle("custom", server)
    assert token not in repr(server)
    assert token not in repr(handle.config)

    class _BoomToolkit:
        """A toolkit whose handshake always fails, never touching the token."""

        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

        async def initialize(self) -> None:
            raise RuntimeError("boom")

        def get_tools(self) -> list[object]:
            return []

    monkeypatch.setattr("maljan.agents.mcp_client.MCPLangChainToolkit", _BoomToolkit)
    # ``_run_async`` normally hands off to the shared agent loop; run it
    # inline here so the real ``ServerHandle.open`` failure log — and the
    # registry's own degrade log around it — both fire on this thread, where
    # caplog can see them.
    monkeypatch.setattr(
        "maljan.providers.servers._run_async", lambda coro, label: asyncio.run(coro)
    )

    cfg = Settings(_env_file=None)
    # Only the server under test: the default map also carries the built-in
    # "network" server bound to this same role, which would degrade too once
    # every handshake is stubbed to fail, muddying the assertion below.
    cfg.mcp.servers = {"custom": server}
    registry = ServerRegistry(cfg)

    with caplog.at_level("DEBUG", logger="maljan"):
        tools, reasons = registry.tools_for("network", "job-1")

    assert tools == []
    assert reasons == [UNAVAILABLE_REASON.format(name="custom")]
    for record in caplog.records:
        assert token not in record.getMessage()
        assert token not in str(record.args)
    assert token not in caplog.text


@pytest.mark.asyncio
async def test_a_server_token_never_appears_in_a_probe_timeout(monkeypatch, caplog):
    """The probe's own timeout path — a server that never answers the handshake."""
    from app.services.settings_probes import probe_mcp

    token = f"s3cr3t-{uuid.uuid4().hex}"

    class _HangingToolkit:
        """A toolkit whose handshake never returns inside the probe budget."""

        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

        async def initialize(self) -> None:
            await asyncio.sleep(30)

        def get_tools(self) -> list[object]:
            return []

    monkeypatch.setattr("maljan.agents.mcp_client.MCPLangChainToolkit", _HangingToolkit)
    monkeypatch.setattr("app.services.settings_probes.PROBE_BUDGET_SECONDS", 0.05)

    with caplog.at_level("DEBUG", logger="maljan"):
        result = await probe_mcp(
            {
                "name": "x",
                "entry": {
                    "enabled": True,
                    "transport": "http",
                    "url": "https://h",
                    "auth_token": token,
                },
            }
        )

    assert result.ok is False
    assert "no MCP handshake" in result.detail
    assert token not in result.detail
    for record in caplog.records:
        assert token not in record.getMessage()
        assert token not in str(record.args)
    assert token not in caplog.text


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

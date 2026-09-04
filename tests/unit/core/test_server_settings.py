"""The registry of tool servers, and the REST sandbox's shape."""

from __future__ import annotations

import re
import sys
from typing import get_args

import pytest
from pydantic import SecretStr

from maljan.core.config import (
    BUILTIN_SERVER_KEYS,
    RESERVED_SERVER_KEYS,
    SERVER_KEY_PATTERN,
    MCPServerConfig,
    SandboxConfig,
    Settings,
)


def test_the_two_sidecars_are_seeded_with_todays_launch_parameters():
    cfg = Settings(_env_file=None)
    network = cfg.mcp.servers["network"]
    assert network.enabled is True
    assert network.command == sys.executable
    assert network.args == ["network-mcp/server.py"]
    assert network.cwd == "network-mcp"
    assert network.env_allow == []
    assert network.agents == ["network"]
    assert network.tools is None, "None means every tool, which is today's behaviour"

    intel = cfg.mcp.servers["threatintel"]
    assert intel.enabled is True
    assert intel.command == sys.executable
    assert intel.args == ["threatintel-mcp/server.py"]
    assert intel.cwd == "threatintel-mcp"
    assert intel.env_allow == ["VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY"]
    assert intel.agents == ["judge"]
    assert intel.tools is None


def test_builtin_keys_are_reserved_and_the_key_pattern_is_a_slug():
    assert set(BUILTIN_SERVER_KEYS) <= set(RESERVED_SERVER_KEYS)
    assert set(RESERVED_SERVER_KEYS) == {"network", "threatintel", "ghidra", "cape"}
    pattern = re.compile(SERVER_KEY_PATTERN)
    assert pattern.match("r2custom") and pattern.match("a")
    assert not pattern.match("R2") and not pattern.match("1a") and not pattern.match("a" * 33)


def test_an_auth_token_is_a_secret_everywhere_it_appears():
    cfg = Settings(_env_file=None)
    assert isinstance(MCPServerConfig().auth_token, SecretStr)
    assert isinstance(cfg.static.ghidra.auth_token, SecretStr)
    assert isinstance(cfg.sandbox.cape2.mcp.auth_token, SecretStr)
    server = MCPServerConfig(auth_token="hunter2")
    assert "hunter2" not in repr(server)
    assert server.model_dump(mode="json")["auth_token"] == "**********"


def test_static_generic_is_a_reference_to_a_server_key():
    cfg = Settings(_env_file=None)
    assert cfg.static.generic.server == ""
    assert not hasattr(cfg.static.generic, "command")


def test_the_sandbox_gains_rest_with_a_full_default_tree():
    assert "rest" in get_args(SandboxConfig.model_fields["provider"].annotation)
    rest = Settings(_env_file=None).sandbox.rest
    assert rest.base_url == ""
    assert rest.auth.header == "Authorization" and rest.auth.scheme == "Bearer"
    assert rest.submit.method == "POST" and rest.submit.task_id_path == "$.id"
    assert rest.status.done_values == ["reported", "completed", "finished"]
    assert rest.report.format == "generic" and rest.report.pcap_path == ""
    assert rest.mapping.target_sha256 == "$.target.sha256"
    assert rest.mapping.processes == "" and rest.mapping.field_names == {}
    assert rest.timeout_seconds == 900 and rest.poll_interval_seconds == 15
    assert rest.verify_tls is True


def test_a_server_entry_carries_an_allow_list_and_an_agent_binding():
    server = MCPServerConfig(tools=["open_file"], agents=["static"], label="xyz")
    assert server.tools == ["open_file"] and server.agents == ["static"]
    with pytest.raises(ValueError):
        MCPServerConfig(agents=["auditor"])

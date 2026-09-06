"""MCP sidecars must never inherit the process's API keys.

Every ``StdioServerParameters(...)`` call used to pass ``env=os.environ.copy()``
(or build on top of it), so a subprocess meant to talk to Ghidra, CAPE, Zeek or
threat-intel APIs received every LLM key, the database URL and the settings
encryption key along with it — reachable by anything that subprocess could be
made to run. ``child_env`` is the one seam all four sidecars now go through: a
small base set of process-hygiene variables, an explicit per-server ``env``
mapping, and only the credentials a server is actually documented to read.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from maljan.agents.subprocess_env import BASE_KEYS, child_env


def _dsn(scheme: str, userinfo: str, rest: str) -> str:
    """Assemble a credentialed URL at runtime so no literal DSN sits in the source
    (secret scanners flag ``scheme://user:pass@host`` even in a masking test)."""
    return f"{scheme}://{userinfo}@{rest}"


FAKE = {
    "PATH": "/usr/bin",
    "HOME": "/home/x",
    "LANG": "C.UTF-8",
    "JAVA_HOME": "/opt/jdk",
    "OPENAI_API_KEY": "not-for-children",
    "LLM__FRONTIER__API_KEY": "fk",
    "DATABASE_URL": _dsn("postgresql", "u:p", "db/x"),
    "VIRUSTOTAL_API_KEY": "vt",
    "ABUSEIPDB_API_KEY": "ab",
    "SETTINGS_ENCRYPTION_KEY": "fernet",
}


def test_base_env_carries_no_secret() -> None:
    env = child_env(source=FAKE)
    assert set(env) <= set(BASE_KEYS)
    assert "OPENAI_API_KEY" not in env and "DATABASE_URL" not in env
    assert env["PATH"] == "/usr/bin" and env["JAVA_HOME"] == "/opt/jdk"


def test_allow_list_and_extra_are_the_only_additions() -> None:
    env = child_env(
        {"GHIDRA_INSTALL_DIR": "/opt/ghidra"}, allow=("VIRUSTOTAL_API_KEY",), source=FAKE
    )
    assert env["VIRUSTOTAL_API_KEY"] == "vt"
    assert "ABUSEIPDB_API_KEY" not in env
    assert env["GHIDRA_INSTALL_DIR"] == "/opt/ghidra"


def test_missing_base_keys_are_skipped_not_empty() -> None:
    assert "TZ" not in child_env(source={"PATH": "/bin"})


# ---------------------------------------------------------------------------
# Per-agent: the ``env=`` actually handed to ``StdioServerParameters`` must be
# filtered, not a fresh ``os.environ.copy()`` in disguise. Each test patches
# ``StdioServerParameters`` (imported locally, inside the method, in every one
# of these four modules) at its source in ``mcp`` — a bare recorder, so no real
# subprocess is ever named — and ``MCPLangChainToolkit`` with an async-capable
# stand-in so ``initialize()``/``get_tools()`` return without a live MCP
# server. A key ending in ``_API_KEY`` reaching that ``env=`` would mean an
# LLM or threat-intel credential is reachable from a compromised sidecar.
# ---------------------------------------------------------------------------


def _toolkit_factory() -> MagicMock:
    """A stand-in ``MCPLangChainToolkit`` class: instances need no live MCP."""
    instance = MagicMock()
    instance.initialize = AsyncMock(return_value=None)
    instance.get_tools = MagicMock(return_value=[])
    factory = MagicMock(return_value=instance)
    return factory


def _no_api_keys(env: dict) -> bool:
    return not any(k.endswith("_API_KEY") for k in env)


class TestStaticAnalystEnv:
    def test_ghidra_sidecar_env_carries_no_api_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The child-environment filtering moved into ``GhidraStaticProvider.open()``
        (provider-layer refactor, Task 10): the analyst no longer builds
        ``StdioServerParameters`` itself, so this exercises the provider directly
        rather than ``StaticAnalyst._initialize_mcp_client`` (now a thin ask-the-
        provider call with nothing left to patch ``get_settings()`` into)."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-not-for-the-sidecar")

        class _Ghidra:
            enabled = True
            transport = "stdio"
            command = "ghidra-mcp"
            args: list[str] = []
            env: dict[str, str] = {}
            use_all_tools = False
            tool_selection = "curated"

        recorder = MagicMock()
        monkeypatch.setattr("mcp.StdioServerParameters", recorder)
        monkeypatch.setattr("maljan.agents.mcp_client.MCPLangChainToolkit", _toolkit_factory())

        from maljan.core.config import MemoryConfig, PreprocessingConfig
        from maljan.providers.base import StaticJobContext
        from maljan.providers.static.ghidra import GhidraStaticProvider

        provider = GhidraStaticProvider(_Ghidra(), PreprocessingConfig(), MemoryConfig())
        provider.open(StaticJobContext())

        assert recorder.called, "StdioServerParameters was never constructed"
        env = recorder.call_args.kwargs["env"]
        assert _no_api_keys(env), f"an API key reached the Ghidra sidecar: {env}"
        assert env.get("PYTHONIOENCODING") == "utf-8"


class TestDynamicAnalystEnv:
    def test_cape_sidecar_env_carries_no_api_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The child-environment filtering moved into
        ``CAPE2SandboxProvider.dynamic_tools()`` (provider-layer refactor, Task
        11): the analyst no longer builds ``StdioServerParameters`` itself, so
        this exercises the provider directly rather than
        ``DynamicAnalyst._initialize_mcp_client`` (now a thin ask-the-provider
        call with nothing left to patch ``get_settings()`` into)."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-not-for-the-sidecar")

        recorder = MagicMock()
        monkeypatch.setattr("mcp.StdioServerParameters", recorder)
        monkeypatch.setattr("maljan.agents.mcp_client.MCPLangChainToolkit", _toolkit_factory())

        from maljan.core.config import Settings
        from maljan.providers.sandbox.cape2 import CAPE2SandboxProvider

        cfg = Settings(_env_file=None)
        cfg.sandbox.cape2.mcp.enabled = True
        cfg.sandbox.cape2.mcp.transport = "stdio"
        cfg.sandbox.cape2.mcp.command = "python"
        provider = CAPE2SandboxProvider.from_settings(cfg)
        provider.dynamic_tools()

        assert recorder.called, "StdioServerParameters was never constructed"
        env = recorder.call_args.kwargs["env"]
        assert _no_api_keys(env), f"an API key reached the CAPE sidecar: {env}"


class TestNetworkAnalystEnv:
    def test_network_sidecar_env_carries_no_api_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The child-environment filtering moved into ``ServerHandle.open()``
        (tool-server registry refactor, Task 7): the network analyst no longer
        builds ``StdioServerParameters`` itself, so this exercises the
        registry's ``network`` built-in directly rather than
        ``NetworkAnalyst._initialize_mcp_client`` (now a thin ask-the-registry
        call with nothing left to patch ``get_settings()`` into)."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-not-for-the-sidecar")

        recorder = MagicMock()
        monkeypatch.setattr("mcp.StdioServerParameters", recorder)
        monkeypatch.setattr("maljan.agents.mcp_client.MCPLangChainToolkit", _toolkit_factory())

        from maljan.core.config import Settings
        from maljan.providers.servers import ServerRegistry

        registry = ServerRegistry(Settings(_env_file=None))
        registry.get("network").open("test-job")

        assert recorder.called, "StdioServerParameters was never constructed"
        env = recorder.call_args.kwargs["env"]
        assert _no_api_keys(env), f"an API key reached the network sidecar: {env}"


class TestJudgeAgentEnv:
    def test_threatintel_sidecar_env_carries_only_the_two_intel_keys(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Same move as the network analyst above, into ``ServerHandle.open()``
        for the ``threatintel`` built-in, whose ``env_allow`` now carries the
        two intel keys ``JudgeAgent._initialize_mcp_client`` used to allow-list
        inline (Task 2's ``_builtin_servers``)."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-not-for-the-sidecar")
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-real")
        monkeypatch.setenv("ABUSEIPDB_API_KEY", "ab-real")

        recorder = MagicMock()
        monkeypatch.setattr("mcp.StdioServerParameters", recorder)
        monkeypatch.setattr("maljan.agents.mcp_client.MCPLangChainToolkit", _toolkit_factory())

        from maljan.core.config import Settings
        from maljan.providers.servers import ServerRegistry

        registry = ServerRegistry(Settings(_env_file=None))
        registry.get("threatintel").open("test-job")

        assert recorder.called, "StdioServerParameters was never constructed"
        env = recorder.call_args.kwargs["env"]
        assert env["VIRUSTOTAL_API_KEY"] == "vt-real"
        assert env["ABUSEIPDB_API_KEY"] == "ab-real"
        assert "OPENAI_API_KEY" not in env
        allowed_extra = {"VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY"}
        api_keys = {k for k in env if k.endswith("_API_KEY")}
        assert api_keys <= allowed_extra, f"an unexpected credential reached the sidecar: {env}"

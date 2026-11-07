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

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from malspark.agents.subprocess_env import BASE_KEYS, child_env, stdio_launch
from malspark.core.platform_secrets import PLATFORM_SECRET_NAMES
from tests.credential_shapes import lowercase_body, password


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


def test_no_base_key_is_one_of_the_platforms_own_variables() -> None:
    assert not {key.upper() for key in BASE_KEYS} & PLATFORM_SECRET_NAMES


def test_a_platform_variable_asked_for_by_name_is_dropped_and_said(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Whatever the block says: by ``allow``, by ``extra``, in another case."""
    values = {name: f"{name.lower()}-{password(16)}" for name in PLATFORM_SECRET_NAMES}
    source = {"PATH": "/usr/bin", **values}
    asked = sorted(PLATFORM_SECRET_NAMES)

    with caplog.at_level("WARNING", logger="malspark"):
        env = child_env(
            {name.lower(): values[name] for name in asked},
            allow=(*asked, *(name.lower() for name in asked)),
            source=source,
            server="mine",
        )

    assert env == {"PATH": "/usr/bin"}
    said = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
    for name in asked:
        assert any(f" {name}:" in line and "mine" in line for line in said), name
    for value in values.values():
        assert value not in caplog.text


def test_an_ordinary_name_still_passes_and_is_not_said(caplog: pytest.LogCaptureFixture) -> None:
    """A provider key an operator allows, a base key and a plain variable reach the child."""
    provider_key = lowercase_body(24)
    with caplog.at_level("WARNING", logger="malspark"):
        env = child_env(
            {"JAVA_HOME": "/opt/jdk", "MY_SETTING": "1"},
            allow=("OPENAI_API_KEY",),
            source={"PATH": "/usr/bin", "OPENAI_API_KEY": provider_key},
            server="mine",
        )
    assert env == {
        "PATH": "/usr/bin",
        "OPENAI_API_KEY": provider_key,
        "JAVA_HOME": "/opt/jdk",
        "MY_SETTING": "1",
    }
    assert not [r for r in caplog.records if r.levelname == "WARNING"]


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

        recorder = MagicMock()
        monkeypatch.setattr("mcp.StdioServerParameters", recorder)
        monkeypatch.setattr("malspark.agents.mcp_client.MCPLangChainToolkit", _toolkit_factory())

        from malspark.core.config import MemoryConfig, PreprocessingConfig
        from malspark.providers.base import StaticJobContext
        from malspark.providers.static.ghidra import GhidraStaticProvider

        provider = GhidraStaticProvider(_Ghidra(), PreprocessingConfig(), MemoryConfig())
        provider.open(StaticJobContext())

        assert recorder.called, "StdioServerParameters was never constructed"
        env = recorder.call_args.kwargs["env"]
        assert _no_api_keys(env), f"an API key reached the Ghidra sidecar: {env}"
        assert env.get("PYTHONIOENCODING") == "utf-8"

    def test_the_stdio_branch_drops_a_platform_variable_its_block_sets(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A block built in code skips settings validation; the spawn still drops the name."""
        dsn = _dsn("postgresql", "u:" + password(), "db/x")

        class _Ghidra:
            enabled = True
            transport = "stdio"
            command = "ghidra-mcp"
            args: list[str] = []
            env: dict[str, str] = {"DATABASE_URL": dsn, "GHIDRA_INSTALL_DIR": "/opt/ghidra"}

        recorder = MagicMock()
        monkeypatch.setattr("mcp.StdioServerParameters", recorder)
        monkeypatch.setattr("malspark.agents.mcp_client.MCPLangChainToolkit", _toolkit_factory())

        from malspark.core.config import MemoryConfig, PreprocessingConfig
        from malspark.providers.base import StaticJobContext
        from malspark.providers.static.ghidra import GhidraStaticProvider

        provider = GhidraStaticProvider(_Ghidra(), PreprocessingConfig(), MemoryConfig())
        with caplog.at_level("WARNING", logger="malspark"):
            provider.open(StaticJobContext())

        env = recorder.call_args.kwargs["env"]
        assert "DATABASE_URL" not in env
        assert env["GHIDRA_INSTALL_DIR"] == "/opt/ghidra"
        assert f"Tool server {GhidraStaticProvider.id} is started without DATABASE_URL" in (
            caplog.text
        )
        assert dsn not in caplog.text


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
        monkeypatch.setattr("malspark.agents.mcp_client.MCPLangChainToolkit", _toolkit_factory())

        from malspark.core.config import Settings
        from malspark.providers.sandbox.cape2 import CAPE2SandboxProvider

        cfg = Settings(_env_file=None)
        cfg.sandbox.cape2.mcp.enabled = True
        cfg.sandbox.cape2.mcp.transport = "stdio"
        cfg.sandbox.cape2.mcp.command = "python"
        provider = CAPE2SandboxProvider.from_settings(cfg)
        provider.dynamic_tools()

        assert recorder.called, "StdioServerParameters was never constructed"
        env = recorder.call_args.kwargs["env"]
        assert _no_api_keys(env), f"an API key reached the CAPE sidecar: {env}"

    def test_the_cape_sidecar_drops_a_platform_variable_its_block_sets(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Assigned after validation, as code may: the spawn still drops the name."""
        recorder = MagicMock()
        monkeypatch.setattr("mcp.StdioServerParameters", recorder)
        monkeypatch.setattr("malspark.agents.mcp_client.MCPLangChainToolkit", _toolkit_factory())

        from malspark.core.config import Settings
        from malspark.providers.sandbox.cape2 import CAPE2SandboxProvider

        signing_key = lowercase_body(40)
        cfg = Settings(_env_file=None)
        cfg.sandbox.cape2.mcp.enabled = True
        cfg.sandbox.cape2.mcp.transport = "stdio"
        cfg.sandbox.cape2.mcp.command = "python"
        cfg.sandbox.cape2.mcp.env = {"JWT_SECRET_KEY": signing_key, "CAPE_TIMEOUT": "60"}
        provider = CAPE2SandboxProvider.from_settings(cfg)
        with caplog.at_level("WARNING", logger="malspark"):
            provider.dynamic_tools()

        env = recorder.call_args.kwargs["env"]
        assert "JWT_SECRET_KEY" not in env
        assert env["CAPE_TIMEOUT"] == "60"
        assert f"Tool server {CAPE2SandboxProvider.id} is started without JWT_SECRET_KEY" in (
            caplog.text
        )
        assert signing_key not in caplog.text


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
        monkeypatch.setattr("malspark.agents.mcp_client.MCPLangChainToolkit", _toolkit_factory())

        from malspark.core.config import Settings
        from malspark.providers.servers import ServerRegistry

        registry = ServerRegistry(Settings(_env_file=None))
        registry.get("network").open("test-job")

        assert recorder.called, "StdioServerParameters was never constructed"
        env = recorder.call_args.kwargs["env"]
        assert _no_api_keys(env), f"an API key reached the network sidecar: {env}"

    def test_a_block_built_in_code_never_hands_a_platform_variable_over(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """``model_construct`` skips the validator that refuses the names; the spawn does not."""
        settings_key = lowercase_body(44)
        monkeypatch.setenv("SETTINGS_ENCRYPTION_KEY", settings_key)

        recorder = MagicMock()
        monkeypatch.setattr("mcp.StdioServerParameters", recorder)
        monkeypatch.setattr("malspark.agents.mcp_client.MCPLangChainToolkit", _toolkit_factory())

        from malspark.core.config import MCPServerConfig
        from malspark.providers.servers import ServerHandle

        config = MCPServerConfig.model_construct(
            enabled=True,
            transport="stdio",
            command="theirs-mcp",
            args=[],
            env={"REDIS_URL": "redis://cache:6379/0"},
            env_allow=["SETTINGS_ENCRYPTION_KEY", "PATH"],
            tools=None,
            agents=[],
            label="",
            cwd="",
            url="",
        )
        with caplog.at_level("WARNING", logger="malspark"):
            ServerHandle("theirs", config).open("test-job")

        env = recorder.call_args.kwargs["env"]
        assert "SETTINGS_ENCRYPTION_KEY" not in env and "REDIS_URL" not in env
        assert "PATH" in env
        for name in ("SETTINGS_ENCRYPTION_KEY", "REDIS_URL"):
            assert f"Tool server theirs is started without {name}" in caplog.text
        assert settings_key not in caplog.text


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
        monkeypatch.setattr("malspark.agents.mcp_client.MCPLangChainToolkit", _toolkit_factory())

        from malspark.core.config import Settings
        from malspark.providers.servers import ServerRegistry

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


class TestRootedCommand:
    """A stdio block's command is rooted as its arguments are (``stdio_launch``).

    A relative path into the project runs the project's file whatever directory
    the parent was started in; a bare program name and an absolute path reach
    the child as written. The launch hands the child that one command.
    """

    @pytest.fixture()
    def project(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
        root = tmp_path / "project"
        (root / "scripts").mkdir(parents=True)
        (root / "scripts" / "run.sh").write_text("#!/bin/sh\n")
        (tmp_path / "evil").write_text("#!/bin/sh\n")
        (tmp_path / "elsewhere" / "scripts").mkdir(parents=True)
        monkeypatch.setattr("malspark.core.paths.get_project_root", lambda *a, **k: root)
        monkeypatch.chdir(tmp_path / "elsewhere")
        return root

    @pytest.mark.parametrize(
        "written", ["scripts/run.sh", "./scripts/run.sh", "././scripts/run.sh"]
    )
    def test_a_relative_command_into_the_project_is_rooted_there(
        self, project: Path, written: str
    ) -> None:
        from malspark.core.config import MCPServerConfig

        launch = stdio_launch(MCPServerConfig(enabled=True, command=written))
        assert launch.command == str(project / "scripts" / "run.sh")

    @pytest.mark.parametrize(
        "written",
        [
            "npx",
            "uvx",
            "/usr/bin/env",
            "missing/run.sh",
            "./missing/run.sh",
            "~/bin/x",
            "../evil",
            "./../evil",
            "scripts/../../evil",
            "scripts\\run.sh",
        ],
    )
    def test_a_bare_name_an_absolute_path_or_no_project_path_is_left_as_written(
        self, project: Path, written: str
    ) -> None:
        import os

        from malspark.core import tool_declarations as td
        from malspark.core.config import MCPServerConfig

        config = MCPServerConfig(enabled=True, command=written)
        assert stdio_launch(config).command == written
        # The grant reads it as the child runs it: from the parent's directory.
        resolved = td._resolved_launch(config)
        if resolved is not None and "/" in written and not written.startswith(("/", "~")):
            assert resolved["command"] == os.path.realpath(Path.cwd() / written)

    def test_a_relative_command_beside_a_working_directory_is_run_from_it(
        self, project: Path
    ) -> None:
        from malspark.core.config import MCPServerConfig

        config = MCPServerConfig(enabled=True, command="./run.sh", cwd="scripts")
        launch = stdio_launch(config)
        assert launch.cwd == str((project / "scripts").resolve())
        assert launch.command == "./run.sh"

    def test_the_launch_starts_the_rooted_command(
        self, project: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from malspark.core.config import MCPServerConfig
        from malspark.providers.servers import ServerHandle

        recorder = MagicMock()
        monkeypatch.setattr("mcp.StdioServerParameters", recorder)
        monkeypatch.setattr("malspark.agents.mcp_client.MCPLangChainToolkit", _toolkit_factory())
        config = MCPServerConfig(enabled=True, command="scripts/run.sh")
        handle = ServerHandle("zq-relative", config)
        handle._build_toolkit(None, 0, None)
        rooted = str(project / "scripts" / "run.sh")
        assert recorder.call_args.kwargs["command"] == rooted
        assert handle._launch_argv[0] == rooted

    def test_a_backslash_separates_only_where_the_platform_s_separator_is_one(
        self, project: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from malspark.core.paths import resolve_mcp_command

        assert resolve_mcp_command("scripts\\run.sh") == "scripts\\run.sh"
        monkeypatch.setattr("malspark.core.paths.os.sep", "\\")
        assert resolve_mcp_command("scripts\\run.sh") == str(project / "scripts" / "run.sh")
        assert resolve_mcp_command("..\\evil") == "..\\evil"

    def test_ghidra_starts_the_command_its_grant_reads(
        self, project: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import os

        from malspark.core import tool_declarations as td
        from malspark.core.config import MCPServerConfig, MemoryConfig, PreprocessingConfig
        from malspark.providers.base import StaticJobContext
        from malspark.providers.static.ghidra import GhidraStaticProvider

        recorder = MagicMock()
        monkeypatch.setattr("mcp.StdioServerParameters", recorder)
        monkeypatch.setattr("malspark.agents.mcp_client.MCPLangChainToolkit", _toolkit_factory())
        (project / "srv").mkdir()
        monkeypatch.setenv("ZQ_TOOL_HOME", "/opt/zq")
        monkeypatch.setenv("ZQ_NOT_ASKED", "kept-back")
        config = MCPServerConfig(
            enabled=True,
            transport="stdio",
            command="scripts/run.sh",
            args=["scripts/run.sh"],
            env_allow=["ZQ_TOOL_HOME"],
        )
        GhidraStaticProvider(config, PreprocessingConfig(), MemoryConfig()).open(StaticJobContext())
        started = recorder.call_args.kwargs
        rooted = str(project / "scripts" / "run.sh")
        assert started["command"] == rooted
        assert started["args"] == [rooted]
        assert started["cwd"] is None
        # The names the block lets through reach the child, as its grant holds.
        assert started["env"]["ZQ_TOOL_HOME"] == "/opt/zq"
        assert "ZQ_NOT_ASKED" not in started["env"]
        resolved = td._resolved_launch(config)
        assert resolved is not None
        assert resolved["command"] == os.path.realpath(started["command"])
        # A working directory reaches the child, and the grant reads the
        # command from it as the child runs it.
        recorder.reset_mock()
        beside = config.model_copy(update={"command": "../scripts/run.sh", "cwd": "srv"})
        GhidraStaticProvider(beside, PreprocessingConfig(), MemoryConfig()).open(StaticJobContext())
        started = recorder.call_args.kwargs
        assert started["cwd"] == str((project / "srv").resolve())
        resolved = td._resolved_launch(beside)
        assert resolved is not None
        assert resolved["command"] == os.path.realpath(Path(started["cwd"]) / started["command"])
        # A working directory the launch refuses is said, as for any server.
        from malspark.providers.errors import ProviderConfigurationError

        missing = config.model_copy(update={"cwd": "no-such-dir"})
        with pytest.raises(ProviderConfigurationError, match="no-such-dir"):
            GhidraStaticProvider(missing, PreprocessingConfig(), MemoryConfig()).open(
                StaticJobContext()
            )

    def test_every_shipped_stdio_server_starts_its_command_as_written(self) -> None:
        from malspark.core.config import Settings

        servers = Settings(_env_file=None).mcp.servers
        stdio = {n: c for n, c in servers.items() if c.transport == "stdio" and c.command}
        assert stdio
        for name, config in stdio.items():
            assert stdio_launch(config).command == config.command, name


class TestRootedArguments:
    """A stdio block's arguments are rooted by the rule its command is (``stdio_launch``).

    A relative path into the project is rooted there; one that leaves the
    project (``../x``) reaches the child as written and is said in a warning,
    and the trust grant reads the argument the launch hands the child.
    """

    @pytest.fixture()
    def project(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
        root = tmp_path / "project"
        (root / "scripts").mkdir(parents=True)
        (root / "scripts" / "server.py").write_text("")
        (tmp_path / "evil.py").write_text("")
        for where in ("one", "two"):
            (tmp_path / where / "run").mkdir(parents=True)
            (tmp_path / where / "near.py").write_text("")
        monkeypatch.setattr("malspark.core.paths.get_project_root", lambda *a, **k: root)
        monkeypatch.chdir(tmp_path / "one" / "run")
        return root

    @pytest.mark.parametrize("written", ["../evil.py", "./../evil.py", "scripts/../../evil.py"])
    def test_an_argument_that_leaves_the_project_is_left_as_written_and_said(
        self, project: Path, written: str, caplog: pytest.LogCaptureFixture
    ) -> None:
        import sys

        from malspark.core.config import MCPServerConfig

        config = MCPServerConfig(
            enabled=True, command=sys.executable, args=["-u", "scripts/server.py", written]
        )
        with caplog.at_level("WARNING", logger="malspark"):
            launch = stdio_launch(config, server="zq-args")
        assert launch.args == ["-u", str(project / "scripts" / "server.py"), written]
        said = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
        assert any("zq-args" in line and repr(written) in line for line in said), said

    def test_an_argument_into_the_project_is_not_said(
        self, project: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        import sys

        from malspark.core.config import MCPServerConfig

        config = MCPServerConfig(
            enabled=True,
            command=sys.executable,
            args=["scripts/../scripts/server.py", "--flag=../x", "owner/repo"],
        )
        with caplog.at_level("WARNING", logger="malspark"):
            launch = stdio_launch(config, server="zq-args")
        assert launch.args == [str(project / "scripts" / "server.py"), "--flag=../x", "owner/repo"]
        assert not [r for r in caplog.records if r.levelname == "WARNING"]

    def test_the_grant_reads_the_argument_the_launch_hands_the_child(
        self, project: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import os
        import sys

        from malspark.core import tool_declarations as td
        from malspark.core.config import MCPServerConfig
        from malspark.providers.servers import ServerHandle

        recorder = MagicMock()
        monkeypatch.setattr("mcp.StdioServerParameters", recorder)
        monkeypatch.setattr("malspark.agents.mcp_client.MCPLangChainToolkit", _toolkit_factory())
        config = MCPServerConfig(enabled=True, command=sys.executable, args=["../near.py"])
        ServerHandle("zq-args", config)._build_toolkit(None, 0, None)
        started = recorder.call_args.kwargs
        assert started["args"] == ["../near.py"]
        assert started["cwd"] is None
        # The child reads ``../near.py`` from the directory it is started in,
        # and so does the grant; never a file the project root steps out to.
        resolved = td._resolved_launch(config)
        assert resolved is not None
        assert resolved.get("args") == {"0": os.path.realpath(tmp_path / "one" / "near.py")}
        grant = td.granted_launch(config)
        monkeypatch.chdir(tmp_path / "two" / "run")
        assert td.granted_launch(config) != grant

    def test_an_argument_kept_inside_the_project_by_the_working_directory_is_not_said(
        self, project: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        import sys

        from malspark.core.config import MCPServerConfig

        (project / "services" / "foo").mkdir(parents=True)
        (project / "services" / "shared").mkdir()
        (project / "services" / "shared" / "util.py").write_text("")
        config = MCPServerConfig(
            enabled=True,
            command=sys.executable,
            args=["../shared/util.py", "../../../evil.py"],
            cwd="services/foo",
        )
        with caplog.at_level("WARNING", logger="malspark"):
            launch = stdio_launch(config, server="zq-args")
        assert launch.args == ["../shared/util.py", "../../../evil.py"]
        said = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
        assert len(said) == 1
        assert "'../../../evil.py'" in said[0]
        assert "util.py" not in said[0]

    def test_a_path_through_a_link_out_of_the_project_is_not_rooted_and_is_said(
        self, project: Path, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        import sys

        from malspark.core.config import MCPServerConfig
        from malspark.core.paths import resolve_mcp_command

        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "passwd").write_text("")
        (project / "link").symlink_to(outside)
        config = MCPServerConfig(enabled=True, command=sys.executable, args=["link/passwd"])
        with caplog.at_level("WARNING", logger="malspark"):
            launch = stdio_launch(config, server="zq-args")
        assert launch.args == ["link/passwd"]
        assert resolve_mcp_command("link/passwd") == "link/passwd"
        said = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
        assert any("'link/passwd'" in line for line in said), said

    def test_a_value_too_long_to_read_is_left_as_written_and_said_capped(
        self, project: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        import sys

        from malspark.core.config import MCPServerConfig

        long_name = "z" * 5000 + "/x.py"
        leaving = "../" + "z" * 5000
        config = MCPServerConfig(enabled=True, command=sys.executable, args=[long_name, leaving])
        with caplog.at_level("WARNING", logger="malspark"):
            launch = stdio_launch(config, server="zq-args")
        assert launch.args == [long_name, leaving]
        (said,) = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
        assert repr(leaving[:200]) in said
        assert len(said) < 600

    def test_a_trust_check_reads_the_launch_without_its_warnings(
        self, project: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        import sys
        from types import SimpleNamespace

        from malspark.core import tool_declarations as td

        secret = sorted(PLATFORM_SECRET_NAMES)[0]
        block = SimpleNamespace(
            transport="stdio",
            command=sys.executable,
            args=["../evil.py"],
            cwd=None,
            url=None,
            env={secret: "x"},
            env_allow=[secret],
            trusts_served_declaration=True,
            trust_granted_for="0" * 16,
        )
        with caplog.at_level("WARNING", logger="malspark"):
            assert td.granted_launch(block)
            td.trusts_served("mcp:zq-never-seen-server", block)
        assert not [r for r in caplog.records if r.levelname == "WARNING"]
        # The launch itself still says both.
        with caplog.at_level("WARNING", logger="malspark"):
            stdio_launch(block, server="zq-args")
        said = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
        assert any(secret in line for line in said)
        assert any("'../evil.py'" in line for line in said)

    def test_every_shipped_stdio_server_s_arguments_are_rooted_inside_the_project(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        import os

        from malspark.core.config import Settings
        from malspark.core.paths import get_project_root

        settings = Settings(_env_file=None)
        blocks = {**settings.mcp.servers, "ghidra": settings.static.ghidra}
        stdio = {n: c for n, c in blocks.items() if c.transport == "stdio" and c.args}
        assert stdio
        root = str(get_project_root())
        with caplog.at_level("WARNING", logger="malspark"):
            for name, config in stdio.items():
                launch = stdio_launch(config, server=name)
                for written, arg in zip(config.args, launch.args, strict=True):
                    if arg != written:
                        assert arg == os.path.normpath(os.path.join(root, written)), name
                        assert arg.startswith(root + os.sep), name
        assert not [r for r in caplog.records if r.levelname == "WARNING"]

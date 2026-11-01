"""Every reading of a tool reads the data path the operator configured (T-499).

``static.capa.rules_dir`` was honoured by the worker's own reading of capa and
by the static provider, while the analysis server's ``capa`` tool always read
``data/capa-rules``: an operator who pointed the setting elsewhere got two rule
sets, and an agent's capa call failed where only the configured directory
existed. A tool's data declaration that names both a core setting and a server
override now has the setting's value handed to a sidecar of this repository
under that override when it is launched, and the check before a job looks
where the server will then read. Nothing is handed under the defaults, to a
block that sets the override itself, or to a server the launch does not start.
"""

from __future__ import annotations

import asyncio
import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

from app.services.tool_availability import as_rows, unavailable_tools
from maljan.core.config import Settings
from maljan.providers.servers import ServerHandle
from maljan.tools import capabilities, emulated_strings, rules, sidecar_needs
from maljan.tools.capabilities import ToolNeeds, data, module

ROOT = Path(__file__).resolve().parents[3]
ANALYSIS_SERVER = ROOT / "services" / "analysis-mcp" / "server.py"
OVERRIDE = rules.CAPA_RULES_ENV


def _populated(directory: Path) -> Path:
    (directory / "nested").mkdir(parents=True)
    (directory / "nested" / "r.yml").write_text("rule:\n", encoding="utf-8")
    return directory


@pytest.fixture
def root(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """A project root of its own for relative data paths, holding nothing yet."""
    monkeypatch.setattr(capabilities, "_data_root", lambda: tmp_path)
    monkeypatch.delenv(OVERRIDE, raising=False)
    return tmp_path


@pytest.fixture
def host(monkeypatch: pytest.MonkeyPatch, root: Path) -> Path:
    """Every declared library and FLOSS present, and the Sigma corpus."""
    monkeypatch.setattr(importlib.util, "find_spec", lambda name, *a, **k: object())
    monkeypatch.setattr(emulated_strings, "find_floss", lambda environ=None: ("floss", ""))
    _populated(root / "data" / "sigma_rules")
    return root


class TestWhatTheLaunchIsHanded:
    def test_a_setting_naming_another_path_is_handed_under_the_override(self) -> None:
        settings = Settings()
        settings.static.capa.rules_dir = "/srv/rules/capa"
        block = settings.mcp.servers["analysis"]
        assert sidecar_needs.handed_env(block, settings) == {OVERRIDE: "/srv/rules/capa"}

    def test_the_default_hands_nothing(self) -> None:
        settings = Settings()
        assert sidecar_needs.handed_env(settings.mcp.servers["analysis"], settings) == {}

    def test_the_blocks_own_override_is_the_blocks(self) -> None:
        settings = Settings()
        settings.static.capa.rules_dir = "/srv/rules/capa"
        block = settings.mcp.servers["analysis"]
        block.env = {OVERRIDE: "/opt/own"}
        assert sidecar_needs.handed_env(block, settings) == {}

    def test_a_server_the_launch_does_not_start_keeps_its_own_environment(self) -> None:
        settings = Settings()
        settings.static.capa.rules_dir = "/srv/rules/capa"
        block = settings.mcp.servers["analysis"]
        remote = block.model_copy(update={"transport": "http", "url": "http://127.0.0.1:9/mcp"})
        container = block.model_copy(update={"command": "docker", "args": ["run", "img"]})
        assert sidecar_needs.handed_env(remote, settings) == {}
        assert sidecar_needs.handed_env(container, settings) == {}

    def test_a_declaration_without_an_override_or_a_setting_hands_nothing(self) -> None:
        settings = Settings()
        settings.static.capa.rules_dir = "/srv/rules/capa"
        assert data("d", setting="static.capa.rules_dir").handed(settings) == {}
        assert data("d", override="X").handed(settings) == {}
        assert module("capa").handed(settings) == {}

    def test_an_undeclared_tool_is_handed_nothing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setitem(
            sidecar_needs.BY_DIRECTORY, "analysis-mcp", [ToolNeeds("capa", (module("capa"),))]
        )
        settings = Settings()
        settings.static.capa.rules_dir = "/srv/rules/capa"
        assert sidecar_needs.handed_env(settings.mcp.servers["analysis"], settings) == {}


class _Toolkit:
    """Stands in for the MCP client: keeps what the child would be started with."""

    def __init__(self, params: Any = None, **_kwargs: Any) -> None:
        self.params = params


def _launch_env(monkeypatch: pytest.MonkeyPatch, settings: Settings) -> dict[str, str]:
    import maljan.agents.mcp_client as mcp_client

    monkeypatch.setattr(mcp_client, "MCPLangChainToolkit", _Toolkit)
    handle = ServerHandle("analysis", settings.mcp.servers["analysis"])
    handle.settings = settings
    toolkit = handle._build_toolkit(None, 0, None)
    return dict(toolkit.params.env)


class TestTheServerProcess:
    def test_its_environment_carries_the_override_when_the_setting_is_set(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        settings = Settings()
        settings.static.capa.rules_dir = "/srv/rules/capa"
        assert _launch_env(monkeypatch, settings)[OVERRIDE] == "/srv/rules/capa"

    def test_its_environment_is_unchanged_under_the_default(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        assert OVERRIDE not in _launch_env(monkeypatch, Settings())

    def test_its_capa_reads_the_handed_directory_else_the_default(
        self, root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.providers.static import capa_yara

        staging = root / "staging"
        staging.mkdir()
        monkeypatch.setenv("MALJAN_STAGING_DIR", str(staging))
        monkeypatch.setenv("MALJAN_SAMPLE_ROOTS", "")
        spec = importlib.util.spec_from_file_location("analysis_mcp_server_t499", ANALYSIS_SERVER)
        assert spec and spec.loader
        analysis = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = analysis
        spec.loader.exec_module(analysis)

        read: list[str] = []

        def _document(**kwargs: Any) -> dict[str, Any]:
            read.append(kwargs["rules_dir"])
            return {"rules": {}, "meta": {}}

        monkeypatch.setattr(capa_yara, "run_capa_document", _document)
        sample = staging / "s.bin"
        sample.write_bytes(b"MZ" + b"\x00" * 128)

        configured = _populated(root / "configured")
        monkeypatch.setenv(OVERRIDE, str(configured))
        answer = asyncio.run(analysis.capa(str(sample), timeout_s=5))
        assert "error" not in answer
        assert read == [str(configured)]

        # The default, read against a project root of the test's own.
        default = _populated(root / rules.DEFAULT_CAPA_RULES)
        monkeypatch.setattr(rules, "resolve_data", lambda value: root / value)
        monkeypatch.delenv(OVERRIDE)
        answer = asyncio.run(analysis.capa(str(sample), timeout_s=6))
        assert "error" not in answer
        assert read == [str(configured), str(default)]


class TestReadinessLooksWhereTheServerReads:
    def test_a_populated_configured_directory_is_not_named(self, host: Path) -> None:
        settings = Settings()
        settings.static.capa.rules_dir = str(_populated(host / "set"))
        assert unavailable_tools(settings) == []

    def test_a_missing_configured_directory_is_one_row_naming_the_setting(self, host: Path) -> None:
        _populated(host / "data" / "capa-rules")
        settings = Settings()
        settings.static.capa.rules_dir = "data/elsewhere"
        (row,) = as_rows(unavailable_tools(settings))
        assert (row["server"], row["tool"]) == ("analysis", "capa")
        assert row["reason"] == (
            "data/elsewhere is missing or empty (named by static.capa.rules_dir)"
        )

    def test_the_default_is_where_both_read_when_the_setting_is_unset(self, host: Path) -> None:
        _populated(host / "data" / "capa-rules")
        assert unavailable_tools(Settings()) == []

    def test_the_blocks_own_override_is_where_the_server_reads(self, host: Path) -> None:
        settings = Settings()
        settings.static.capa.rules_dir = str(_populated(host / "set"))
        settings.mcp.servers["analysis"].env = {OVERRIDE: "data/gone"}
        (row,) = as_rows(unavailable_tools(settings))
        assert row["reason"] == f"data/gone is missing or empty (named by {OVERRIDE})"

"""A tool whose declared data path is missing or empty is named before a job (T-492).

The haiku8 run was accepted with nothing named unavailable, and capa failed in
it: its library was installed, its rules directory was not there, because the
directory is fetched rather than tracked and the run's worktree had never had
it fetched. A tool declares the data it reads (``capabilities.data``) and the
check before a job looks at the path where the tool would read it, naming the
path and the setting or variable that named it. A tool that declares no data
is checked exactly as before.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

import pytest

from app.services.tool_availability import as_rows, unavailable_tools
from maljan.core.config import Settings
from maljan.tools import emulated_strings, sidecar_needs
from maljan.tools.capabilities import ToolNeeds, data, manifest, module


@pytest.fixture
def host(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every declared library and FLOSS present: only the data paths are the host's own."""

    def find_spec(name: str, *args: Any, **kwargs: Any) -> Any:
        return object()

    monkeypatch.setattr(importlib.util, "find_spec", find_spec)
    monkeypatch.setattr(emulated_strings, "find_floss", lambda environ=None: ("floss", ""))


def _populated(directory: Path) -> Path:
    (directory / "nested").mkdir(parents=True)
    (directory / "nested" / "r.yml").write_text("rule:\n", encoding="utf-8")
    return directory


def _settings(tmp_path: Path, capa_rules: Path) -> Settings:
    """Settings handing capa ``capa_rules``, with Sigma's corpus populated."""
    settings = Settings()
    settings.static.capa.rules_dir = str(capa_rules)
    sigma = _populated(tmp_path / "sigma")
    settings.mcp.servers["analysis"].env = {"MALJAN_SIGMA_RULES_DIR": str(sigma)}
    return settings


class TestTheLookAtAPath:
    def test_a_missing_directory_is_named_with_the_setting_that_names_it(
        self, tmp_path: Path
    ) -> None:
        settings = Settings()
        settings.static.capa.rules_dir = str(tmp_path / "absent")
        req = data("data/capa-rules", setting="static.capa.rules_dir")
        assert req.installed(None, settings) == (
            f"{tmp_path / 'absent'} is missing or empty (named by static.capa.rules_dir)"
        )

    def test_an_empty_directory_and_an_empty_file_are_named(self, tmp_path: Path) -> None:
        (tmp_path / "empty").mkdir()
        (tmp_path / "empty" / "sub").mkdir()
        (tmp_path / "zero.yaml").write_bytes(b"")
        for name in ("empty", "zero.yaml"):
            said = data(str(tmp_path / name)).installed()
            assert said == f"{tmp_path / name} is missing or empty (named by the default)"

    def test_a_directory_with_a_file_anywhere_in_it_and_a_non_empty_file_pass(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "rules.yaml").write_text("x", encoding="utf-8")
        assert data(str(_populated(tmp_path / "rules"))).installed() is None
        assert data(str(tmp_path / "rules.yaml")).installed() is None

    def test_the_override_in_the_servers_environment_replaces_the_default(
        self, tmp_path: Path
    ) -> None:
        req = data(str(tmp_path / "absent"), override="MALJAN_T492_RULES")
        populated = str(_populated(tmp_path / "given"))
        assert req.installed({"MALJAN_T492_RULES": populated}) is None
        assert req.installed({"MALJAN_T492_RULES": str(tmp_path / "gone")}) == (
            f"{tmp_path / 'gone'} is missing or empty (named by MALJAN_T492_RULES)"
        )
        assert "named by the default" in str(req.installed({}))

    def test_the_setting_wins_and_without_settings_the_default_is_looked_at(
        self, tmp_path: Path
    ) -> None:
        settings = Settings()
        settings.static.capa.rules_dir = str(_populated(tmp_path / "set"))
        req = data(str(tmp_path / "absent"), setting="static.capa.rules_dir")
        assert req.installed(None, settings) is None
        assert "named by the default" in str(req.installed(None, None))

    def test_a_setting_left_empty_names_no_path(self) -> None:
        settings = Settings()
        settings.static.capa.rules_dir = ""
        req = data("data/capa-rules", setting="static.capa.rules_dir")
        assert req.installed(None, settings) == "static.capa.rules_dir names no path"

    def test_the_server_does_not_probe_it_and_its_manifest_does_not_list_it(
        self, tmp_path: Path
    ) -> None:
        """The path a tool is handed is the caller's setting, which the server never reads."""
        req = data(str(tmp_path / "absent"), setting="static.capa.rules_dir")
        assert req.probe() is None
        (cell,) = manifest("x", [ToolNeeds("t", (module("colorsys"), req))])["tools"]
        assert cell["available"] is True
        assert cell["optional_dependency"] == "colorsys"

    def test_the_remedy_names_the_path_and_what_names_it(self) -> None:
        remedy = data("data/r", setting="a.b", override="MALJAN_R").remedy
        assert remedy.startswith("put the data in data/r, or point a.b or MALJAN_R at")
        assert "make external" in remedy


class TestTheSidecarsDeclarations:
    def test_every_declared_setting_is_a_setting_whose_default_is_the_declared_path(
        self,
    ) -> None:
        from maljan.tools.capabilities import _setting_value

        declared = [
            req
            for needs in sidecar_needs.BY_DIRECTORY.values()
            for need in needs
            for req in need.requires
            if req.kind == "data"
        ]
        assert declared, "the fetched corpora are declared"
        for req in declared:
            if req.setting:
                assert _setting_value(Settings(), req.setting) == req.name


class TestReadinessNamesAMissingDataPath:
    def test_capa_with_its_rules_directory_empty_is_named(self, host: None, tmp_path: Path) -> None:
        empty = tmp_path / "capa-rules"
        empty.mkdir()
        (row,) = as_rows(unavailable_tools(_settings(tmp_path, empty)))
        assert (row["server"], row["tool"]) == ("analysis", "capa")
        assert row["reason"] == f"{empty} is missing or empty (named by static.capa.rules_dir)"
        assert row["remediation"] == sidecar_needs.CAPA_RULES.remedy
        assert row["manifest_code"] == "missing_dependency"
        assert row["degradation_reason"].startswith("server.analysis.capa_unavailable(")

    def test_the_pack_reading_is_named_when_its_server_is_switched_off(
        self, host: None, tmp_path: Path
    ) -> None:
        settings = _settings(tmp_path, tmp_path / "absent")
        settings.mcp.servers["analysis"].enabled = False
        assert [(u.server, u.tool) for u in unavailable_tools(settings)] == [("analysis", "capa")]

    def test_a_populated_rules_directory_is_not_named(self, host: None, tmp_path: Path) -> None:
        settings = _settings(tmp_path, _populated(tmp_path / "capa-rules"))
        assert unavailable_tools(settings) == []

    def test_sigmas_default_corpus_missing_is_named_with_its_variable(
        self, host: None, tmp_path: Path
    ) -> None:
        settings = _settings(tmp_path, _populated(tmp_path / "capa-rules"))
        settings.mcp.servers["analysis"].env = {"MALJAN_SIGMA_RULES_DIR": str(tmp_path / "none")}
        found = unavailable_tools(settings)
        assert [u.tool for u in found] == ["sigma_match", "sigma_match_sandbox"]
        assert all("named by MALJAN_SIGMA_RULES_DIR" in u.reason for u in found)

    def test_a_tool_that_declares_no_data_is_checked_as_before(
        self, host: None, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Nothing new is asked of an undeclared tool, whatever data the host lacks."""
        monkeypatch.setitem(
            sidecar_needs.BY_DIRECTORY,
            "analysis-mcp",
            [ToolNeeds("capa", (module("capa"),)), ToolNeeds("sigma_match", (module("sigma"),))],
        )
        settings = Settings()
        settings.static.capa.rules_dir = str(tmp_path / "absent")
        assert unavailable_tools(settings) == []

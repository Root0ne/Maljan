"""A tool whose declared data path is missing or empty is named before a job (T-492).

The haiku8 run was accepted with nothing named unavailable, and capa failed in
it: its library was installed, its rules directory was not there, because the
directory is fetched rather than tracked and the run's worktree had never had
it fetched. A tool declares the data it reads (``capabilities.data``) and the
check before a job looks at the path where the tool would read it: a server's
tool its override or default, the worker's own reading the setting it is
handed. A tool that declares no data is checked exactly as before.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

import pytest

from app.services.tool_availability import as_rows, unavailable_tools
from maljan.core.config import Settings
from maljan.tools import capabilities, emulated_strings, sidecar_needs
from maljan.tools.capabilities import ToolNeeds, data, manifest, module, remedy_for


@pytest.fixture
def root(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """A project root of its own for relative data paths, holding nothing yet."""
    monkeypatch.setattr(capabilities, "_data_root", lambda: tmp_path)
    return tmp_path


@pytest.fixture
def host(monkeypatch: pytest.MonkeyPatch, root: Path) -> Path:
    """Every declared library and FLOSS present, and the Sigma corpus: capa's rules are not."""

    def find_spec(name: str, *args: Any, **kwargs: Any) -> Any:
        return object()

    monkeypatch.setattr(importlib.util, "find_spec", find_spec)
    monkeypatch.setattr(emulated_strings, "find_floss", lambda environ=None: ("floss", ""))
    _populated(root / "data" / "sigma_rules")
    return root


def _populated(directory: Path, name: str = "r.yml") -> Path:
    (directory / "nested").mkdir(parents=True)
    (directory / "nested" / name).write_text("rule:\n", encoding="utf-8")
    return directory


class TestTheLookAtAPath:
    def test_a_missing_directory_is_named_relative_to_the_project(self, root: Path) -> None:
        settings = Settings()
        settings.static.capa.rules_dir = "data/elsewhere"
        req = data("data/capa-rules", setting="static.capa.rules_dir")
        assert req.installed(None, settings) == (
            "data/elsewhere is missing or empty (named by static.capa.rules_dir)"
        )

    def test_a_path_outside_the_project_is_not_shown(self, root: Path, tmp_path_factory) -> None:
        outside = tmp_path_factory.mktemp("outside")
        settings = Settings()
        settings.static.capa.rules_dir = str(outside)
        said = data("data/capa-rules", setting="static.capa.rules_dir").installed(None, settings)
        assert said == "the path static.capa.rules_dir names is missing or empty"

    def test_an_empty_directory_and_an_empty_file_are_named(self, root: Path) -> None:
        (root / "empty" / "sub").mkdir(parents=True)
        (root / "zero.yaml").write_bytes(b"")
        for name in ("empty", "zero.yaml"):
            assert data(name).installed() == f"{name} is missing or empty (named by the default)"

    def test_a_directory_holding_no_file_of_the_pattern_is_named(self, root: Path) -> None:
        _populated(root / "rules", name="README.md")
        assert data("rules", pattern="*.yml").installed() is not None
        assert data("rules").installed() is None
        (root / "rules" / "nested" / "r.yaml").write_text("x", encoding="utf-8")
        assert data("rules", pattern="*.y*ml").installed() is None

    def test_a_directory_with_a_file_anywhere_in_it_and_a_non_empty_file_pass(
        self, root: Path
    ) -> None:
        (root / "rules.yaml").write_text("x", encoding="utf-8")
        _populated(root / "rules")
        assert data("rules", pattern="*.yml").installed() is None
        assert data("rules.yaml").installed() is None

    def test_the_override_in_the_servers_environment_replaces_the_default(self, root: Path) -> None:
        req = data("absent", override="MALJAN_T492_RULES")
        _populated(root / "given")
        assert req.installed({"MALJAN_T492_RULES": "given"}) is None
        assert req.installed({"MALJAN_T492_RULES": "gone"}) == (
            "gone is missing or empty (named by MALJAN_T492_RULES)"
        )
        assert "named by the default" in str(req.installed({}))

    def test_the_setting_is_read_only_where_settings_are_handed(self, root: Path) -> None:
        settings = Settings()
        settings.static.capa.rules_dir = str(_populated(root / "set"))
        req = data("absent", setting="static.capa.rules_dir")
        assert req.installed(None, settings) is None
        assert "named by the default" in str(req.installed(None, None))

    def test_a_setting_left_empty_names_no_path(self) -> None:
        settings = Settings()
        settings.static.capa.rules_dir = ""
        req = data("data/capa-rules", setting="static.capa.rules_dir")
        assert req.installed(None, settings) == "static.capa.rules_dir names no path"

    def test_the_server_does_not_probe_it_and_its_manifest_does_not_list_it(
        self, root: Path
    ) -> None:
        req = data("absent", setting="static.capa.rules_dir")
        assert req.probe() is None
        (cell,) = manifest("x", [ToolNeeds("t", (module("colorsys"), req))])["tools"]
        assert cell["available"] is True
        assert cell["optional_dependency"] == "colorsys"

    def test_the_remedy_names_the_path_and_what_names_it(self) -> None:
        remedy = data("data/r", setting="a.b", override="MALJAN_R").remedy
        assert remedy.startswith("put the data in data/r, or point a.b or MALJAN_R at")
        assert "make external" in remedy

    def test_a_missing_module_and_missing_data_keep_both_remedies(self) -> None:
        lib, corpus = module("x"), data("data/r")
        tool = ToolNeeds("t", (lib, corpus), remediation="install x")
        assert remedy_for(tool, [lib, corpus]) == f"install x; {corpus.remedy}"
        assert remedy_for(tool, [corpus, corpus]) == corpus.remedy


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
    def test_the_servers_tool_is_named_by_the_default_it_reads(self, host: Path) -> None:
        """The analysis server's capa reads its default, whatever the setting names."""
        settings = Settings()
        settings.static.capa.rules_dir = str(_populated(host / "set"))
        (row,) = as_rows(unavailable_tools(settings))
        assert (row["server"], row["tool"]) == ("analysis", "capa")
        assert row["reason"] == "data/capa-rules is missing or empty (named by the default)"
        assert row["remediation"] == sidecar_needs.CAPA_RULES.remedy
        assert row["manifest_code"] == "missing_dependency"
        assert row["degradation_reason"].startswith("server.analysis.capa_unavailable(")

    def test_the_workers_reading_is_named_by_the_setting_it_is_handed(self, host: Path) -> None:
        _populated(host / "data" / "capa-rules")
        settings = Settings()
        settings.static.capa.rules_dir = ""
        settings.mcp.servers["analysis"].enabled = False
        (row,) = as_rows(unavailable_tools(settings))
        assert (row["server"], row["tool"]) == ("analysis", "capa")
        assert row["reason"] == "static.capa.rules_dir names no path"

    def test_both_read_sites_missing_are_one_row_naming_each(self, host: Path) -> None:
        (row,) = as_rows(unavailable_tools(Settings()))
        assert row["reason"] == (
            "data/capa-rules is missing or empty (named by the default); "
            "data/capa-rules is missing or empty (named by static.capa.rules_dir)"
        )

    def test_populated_rules_are_not_named(self, host: Path) -> None:
        _populated(host / "data" / "capa-rules")
        assert unavailable_tools(Settings()) == []

    def test_sigmas_corpus_missing_is_named_with_its_variable(self, host: Path) -> None:
        _populated(host / "data" / "capa-rules")
        settings = Settings()
        settings.mcp.servers["analysis"].env = {"MALJAN_SIGMA_RULES_DIR": "none"}
        found = unavailable_tools(settings)
        assert [u.tool for u in found] == ["sigma_match", "sigma_match_sandbox"]
        assert all("named by MALJAN_SIGMA_RULES_DIR" in u.reason for u in found)

    def test_a_server_with_its_own_import_path_has_its_data_unchecked(self, host: Path) -> None:
        settings = Settings()
        settings.mcp.servers["analysis"].env = {"PYTHONPATH": "/opt/libs"}
        settings.static.capa.rules_dir = str(_populated(host / "set"))
        # The worker's own reading of capa is handed a populated setting.
        assert unavailable_tools(settings) == []

    def test_a_tool_that_declares_no_data_is_checked_as_before(
        self, host: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Nothing new is asked of an undeclared tool, whatever data the host lacks."""
        monkeypatch.setitem(
            sidecar_needs.BY_DIRECTORY,
            "analysis-mcp",
            [ToolNeeds("capa", (module("capa"),)), ToolNeeds("sigma_match", (module("sigma"),))],
        )
        assert unavailable_tools(Settings()) == []

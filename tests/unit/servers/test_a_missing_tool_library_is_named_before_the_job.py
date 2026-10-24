"""A tool whose library is missing on this host is named before a job starts (T-329).

A run whose analysis server had lost capa was accepted, paid for, and said
``DEGRADED RUN`` afterwards. The sidecars' declared needs are checked without
starting anything, and a missing one is named with the server's own reason and
the remedy, in the words the run's degraded block would use.
"""

from __future__ import annotations

import importlib.util
import sys
from typing import Any
from unittest.mock import MagicMock

import pytest

from app.services.tool_availability import as_rows, unavailable_tools
from maljan.core.config import Settings
from maljan.tools import emulated_strings, sidecar_needs
from maljan.tools.capabilities import Requirement, ToolNeeds, binary, env, manifest, module


def _without(monkeypatch: pytest.MonkeyPatch, *missing: str) -> list[str]:
    """A host holding every declared library and the pinned FLOSS but ``missing``.

    Whatever the test host has installed: the import path finds every module
    but the ones named, and FLOSS is found. Answers the names looked up.
    """
    asked: list[str] = []

    def find_spec(name: str, *args: Any, **kwargs: Any) -> Any:
        asked.append(name)
        return None if name in missing else object()

    monkeypatch.setattr(importlib.util, "find_spec", find_spec)
    monkeypatch.setattr(emulated_strings, "find_floss", lambda environ=None: ("floss", ""))
    return asked


class TestTheCheckBeforeAJob:
    def test_a_missing_module_is_named_in_the_imports_own_words(self) -> None:
        said = module("maljan_t329_no_such_library").installed()
        assert said == (
            "maljan_t329_no_such_library is not installed "
            "(No module named 'maljan_t329_no_such_library')"
        )

    def test_an_installed_module_is_not_named_and_is_not_imported(self) -> None:
        sys.modules.pop("colorsys", None)
        assert module("colorsys").installed() is None
        assert "colorsys" not in sys.modules

    def test_the_words_are_the_servers_own(self) -> None:
        req = module("maljan_t329_no_such_library")
        assert req.installed() == req.probe()

    def test_an_executable_is_looked_for_in_the_servers_environment(self) -> None:
        seen: list[Any] = []

        def locate(environ: Any = None) -> str | None:
            seen.append(environ)
            return "floss is not installed: nowhere"

        assert (
            binary("floss", locate).installed({"PATH": "/x"}) == "floss is not installed: nowhere"
        )
        assert seen == [{"PATH": "/x"}]
        assert binary("maljan-t329-no-such-program").installed({"PATH": ""}) == (
            "maljan-t329-no-such-program is not on PATH"
        )

    def test_a_setting_is_no_install(self) -> None:
        assert env("MALJAN_T329_NO_SUCH_KEY").installed({}) is None


class TestTheSidecarsDeclareTheirNeedsOnce:
    def test_the_manifest_a_sidecar_answers_is_built_from_the_shared_declaration(self) -> None:
        cells = {c["name"]: c for c in manifest("analysis", sidecar_needs.ANALYSIS)["tools"]}
        assert cells["capa"]["optional_dependency"] == "capa"
        assert cells["capa"]["long_running"] is True and cells["capa"]["timeout_s"] is None
        assert cells["yara_scan"]["timeout_s"] == sidecar_needs.YARA_TIMEOUT_S

    def test_capa_and_yara_name_their_own_extra(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(Requirement, "probe", lambda self: f"{self.name} is not installed")
        cells = {c["name"]: c for c in manifest("analysis", sidecar_needs.ANALYSIS)["tools"]}
        assert cells["capa"]["remediation"].endswith("uv sync --extra capa")
        assert cells["yara_scan"]["remediation"].endswith("uv sync --extra yara")
        assert cells["apk_info"]["remediation"].endswith("uv sync --extra tools")


class TestReadinessNamesWhatTheJobWouldCall:
    def test_floss_missing_is_named_with_its_own_remedy(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _without(monkeypatch)
        monkeypatch.setattr(
            emulated_strings, "find_floss", lambda environ=None: (None, "floss is not installed: x")
        )
        (row,) = as_rows(unavailable_tools(Settings()))
        assert (row["server"], row["tool"], row["reason"]) == (
            "analysis",
            "floss",
            "floss is not installed: x",
        )
        assert row["remediation"] == emulated_strings.FLOSS_REMEDIATION

    def test_a_server_whose_tool_library_is_missing_is_named_with_the_reason(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _without(monkeypatch, "capa")
        found = unavailable_tools(Settings())
        assert [(u.server, u.tool) for u in found] == [("analysis", "capa")]
        (row,) = as_rows(found)
        assert row["reason"] == "capa is not installed (No module named 'capa')"
        assert row["remediation"] == sidecar_needs.CAPA_REMEDIATION
        assert row["still_answers"] == ""
        assert row["degradation_reason"] == (
            "server.analysis.capa_unavailable(capa is not installed (No module named 'capa')); "
            "install capa on the host that runs this server: uv sync --extra capa"
        )

    def test_an_available_tool_is_not_named(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _without(monkeypatch)
        assert unavailable_tools(Settings()) == []
        monkeypatch.undo()
        # On the real import path too, for a library every host has.
        monkeypatch.setitem(
            sidecar_needs.BY_DIRECTORY,
            "analysis-mcp",
            [ToolNeeds("pe_info", (module("colorsys"),)), ToolNeeds("hashes")],
        )
        assert [u for u in unavailable_tools(Settings()) if u.server == "analysis"] == []

    def test_what_a_tool_still_answers_is_said(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _without(monkeypatch, "py7zr")
        (row,) = as_rows(unavailable_tools(Settings()))
        assert (row["tool"], row["still_answers"]) == (
            "archive_list",
            "zip and tar members; 7z needs py7zr",
        )

    def test_one_missing_module_is_looked_up_once_per_server(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        asked = _without(monkeypatch, "sigma")
        found = unavailable_tools(Settings())
        assert [u.tool for u in found] == ["sigma_match", "sigma_match_sandbox"]
        assert asked.count("sigma") == 1

    def test_a_tool_the_servers_block_does_not_offer_is_not_named(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # sigma_match is an agent's tool and no pack reading stands in for it.
        _without(monkeypatch, "sigma")
        settings = Settings()
        settings.mcp.servers["analysis"].tools = ["hashes", "pe_info", "capa"]
        assert unavailable_tools(settings) == []

    def test_a_pack_reading_is_named_whatever_tools_the_block_offers(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _without(monkeypatch, "capa")
        settings = Settings()
        settings.mcp.servers["analysis"].tools = ["hashes", "pe_info"]
        assert [(u.server, u.tool) for u in unavailable_tools(settings)] == [("analysis", "capa")]

    def test_a_pack_reading_is_named_when_its_server_is_switched_off(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The haiku5 shape: the reading runs in the worker whatever the server's switch says."""
        _without(monkeypatch, "capa")
        settings = Settings()
        settings.mcp.servers["analysis"].enabled = False
        (row,) = as_rows(unavailable_tools(settings))
        assert (row["server"], row["tool"]) == ("analysis", "capa")
        assert row["remediation"] == sidecar_needs.CAPA_REMEDIATION

    def test_a_switched_off_servers_agent_tools_are_not_named(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _without(monkeypatch, "sigma")
        settings = Settings()
        settings.mcp.servers["analysis"].enabled = False
        assert unavailable_tools(settings) == []

    def test_a_server_on_another_interpreter_is_left_to_its_own_manifest(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _without(monkeypatch, "sigma", "capa")
        settings = Settings()
        settings.mcp.servers["analysis"].command = "/opt/elsewhere/bin/python"
        # Its agent tools are its own manifest's to say; the pack's reading of
        # capa still runs in the worker.
        assert [u.tool for u in unavailable_tools(settings)] == ["capa"]

    def test_a_reading_runs_on_its_server_when_that_is_reached_at_an_address(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _without(monkeypatch, "capa")
        settings = Settings()
        analysis = settings.mcp.servers["analysis"]
        analysis.transport = "streamable-http"
        analysis.url = "http://analysis-mcp:8080/mcp"
        assert unavailable_tools(settings) == []
        analysis.enabled = False
        assert [u.tool for u in unavailable_tools(settings)] == ["capa"]

    def test_a_pack_step_switched_off_is_no_reading(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _without(monkeypatch, "capa")
        settings = Settings()
        settings.mcp.servers["analysis"].enabled = False
        settings.triage.steps = [{"id": "capa", "enabled": False}]
        assert unavailable_tools(settings) == []

    def test_a_server_that_sets_its_own_import_path_has_its_modules_unchecked(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _without(monkeypatch, "sigma", "capa")
        settings = Settings()
        settings.mcp.servers["analysis"].env = {"PYTHONPATH": "/opt/libs"}
        # The worker's own reading of capa is on the worker's import path.
        assert [u.tool for u in unavailable_tools(settings)] == ["capa"]

    def test_what_is_found_is_logged_at_the_level_asked(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import logging

        from app.services import tool_availability

        _without(monkeypatch, "capa")
        said = MagicMock()
        monkeypatch.setattr(tool_availability, "logger", said)
        unavailable_tools(Settings(), level=logging.WARNING)
        unavailable_tools(Settings())
        levels = [c.args[0] for c in said.log.call_args_list]
        assert levels == [logging.WARNING, logging.DEBUG]

    def test_an_executable_is_looked_for_again_in_another_servers_environment(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.services import tool_availability

        _without(monkeypatch)
        floss = next(n for n in sidecar_needs.ANALYSIS if n.name == "floss")
        bare: dict[str, str] = {}
        configured = {"MALJAN_FLOSS_PATH": "/opt/floss"}
        monkeypatch.setattr(
            tool_availability,
            "_in_process_readings",
            lambda settings, level=0: [("first", floss, bare), ("second", floss, configured)],
        )
        monkeypatch.setattr(
            emulated_strings,
            "find_floss",
            lambda environ=None: (
                (None, "floss is not installed: x") if environ is configured else ("floss", "")
            ),
        )
        assert [(u.server, u.tool) for u in unavailable_tools(Settings())] == [("second", "floss")]

    def test_the_status_reads_choice_of_a_switched_off_server_is_a_debug_line(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import logging

        from maljan.core import pack_servers

        _without(monkeypatch)
        said = MagicMock()
        monkeypatch.setattr(pack_servers, "logger", said)
        settings = Settings()
        settings.mcp.servers["analysis"].enabled = False

        def reading_levels() -> set[int]:
            # The worker's default is ``logger.info`` itself, as it always was.
            levels = {c.args[0] for c in said.log.call_args_list if "reading of" in str(c.args[2])}
            levels |= {
                logging.INFO for c in said.info.call_args_list if "reading of" in str(c.args[1])
            }
            said.reset_mock()
            return levels

        unavailable_tools(settings)
        assert reading_levels() == {logging.DEBUG}
        unavailable_tools(settings, level=logging.WARNING)
        assert reading_levels() == {logging.INFO}

    def test_a_profile_the_job_names_that_does_not_exist_names_nothing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _without(monkeypatch, "capa")
        assert unavailable_tools(Settings(), profile="no-such-team") == []

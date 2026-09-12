"""The sandbox report as tools, and what they say when there is no report.

The dynamic analyst has always been handed the report as chunked text. These
tools let it ask instead, and the answer that matters most is the one for a
job with no report at all: an explicit error, not an empty list. A tool that
returned ``{"processes": []}`` for a run where the sandbox never answered would
be telling the model the sample did nothing.
"""

from __future__ import annotations

from typing import Any

from maljan.providers import sandbox_tools

REPORT: dict[str, Any] = {
    "target": {"sha256": "a" * 64, "name": "invoice.exe"},
    "behavior": {
        "processes": [
            {
                "pid": 1234,
                "ppid": 1,
                "process_name": "invoice.exe",
                "command_line": "invoice.exe /q",
                "first_seen": 1.0,
                "calls": [{"api": "WriteProcessMemory"}, {"api": "CreateRemoteThread"}],
            },
            {
                "pid": 1240,
                "parent_id": 1234,
                "name": "cmd.exe",
                "cmd": "cmd.exe /c whoami",
                "calls": [],
            },
        ]
    },
    "network": {
        "dns": [{"request": "evil-c2-host.top", "type": "A"}],
        "hosts": ["45.77.12.34"],
        "http": [{"uri": "http://evil-c2-host.top/gate.php", "method": "POST"}],
    },
    "signatures": [
        {
            "name": "injection_createremotethread",
            "description": "Code injection via CreateRemoteThread",
            "severity": 3,
            "references": ["https://example.invalid/1"],
        }
    ],
    "dropped": [
        {
            "name": "svchost.exe",
            "filepath": "C:\\Users\\x\\AppData\\svchost.exe",
            "size": 4096,
            "sha256": "b" * 64,
            "type": "PE32 executable",
        }
    ],
    "channels": {
        "android.permissions": [{"name": "android.permission.SEND_SMS"}],
        "linux.systemd": [{"unit": "evil.service"}],
    },
}


class _Container:
    def __init__(self, report: Any) -> None:
        self.sandbox_report = report


class TestProcesses:
    def test_each_process_is_one_row_with_its_command_line(self) -> None:
        result = sandbox_tools.sandbox_processes(REPORT)

        assert result["total"] == 2
        first, second = result["processes"]
        assert first["pid"] == 1234
        assert first["name"] == "invoice.exe"
        assert first["command_line"] == "invoice.exe /q"
        # The second process uses the alternate key spellings a non-CAPE
        # sandbox publishes, and must read the same.
        assert second["ppid"] == 1234
        assert second["name"] == "cmd.exe"
        assert second["command_line"] == "cmd.exe /c whoami"

    def test_the_call_list_is_counted_rather_than_returned(self) -> None:
        """The calls are where a behaviour report's bulk is; a process tree is
        the thing an analyst reads first, and the two are separate questions."""
        first = sandbox_tools.sandbox_processes(REPORT)["processes"][0]
        assert first["call_count"] == 2
        assert "calls" not in first


class TestNetwork:
    def test_each_kind_comes_back_under_its_own_key(self) -> None:
        result = sandbox_tools.sandbox_network(REPORT)
        assert result["dns"] == [{"request": "evil-c2-host.top", "type": "A"}]
        assert result["hosts"] == ["45.77.12.34"]
        assert result["http"][0]["uri"] == "http://evil-c2-host.top/gate.php"

    def test_a_report_with_no_network_block_is_empty_lists_not_an_error(self) -> None:
        assert sandbox_tools.sandbox_network({"behavior": {}}) == {
            "dns": [],
            "hosts": [],
            "http": [],
            "tcp": [],
            "udp": [],
        }

    def test_a_busy_kind_is_bounded_and_says_how_many_there_were(self, monkeypatch) -> None:
        monkeypatch.setattr(sandbox_tools, "_ROW_LIMIT", 3)
        report = {"network": {"dns": [{"request": f"h{i}.example"} for i in range(10)]}}

        result = sandbox_tools.sandbox_network(report)

        assert len(result["dns"]) == 3
        assert result["dns_total"] == 10


class TestSignatures:
    def test_a_signature_is_reported_as_the_engine_s_opinion_with_its_severity(self) -> None:
        result = sandbox_tools.sandbox_signatures(REPORT)
        assert result["total"] == 1
        row = result["signatures"][0]
        assert row["name"] == "injection_createremotethread"
        assert row["severity"] == 3
        assert row["references"] == ["https://example.invalid/1"]


class TestDroppedFiles:
    def test_a_dropped_file_carries_the_hash_the_sandbox_computed(self) -> None:
        result = sandbox_tools.sandbox_dropped_files(REPORT)
        assert result["total"] == 1
        assert result["dropped"][0]["sha256"] == "b" * 64
        assert result["dropped"][0]["name"] == "svchost.exe"

    def test_the_alternate_key_is_read_too(self) -> None:
        result = sandbox_tools.sandbox_dropped_files({"dropped_files": [{"name": "x.bin"}]})
        assert result["dropped"][0]["name"] == "x.bin"


class TestChannels:
    def test_calling_it_with_no_name_lists_what_exists(self) -> None:
        """How an agent discovers a channel it did not know to ask for."""
        result = sandbox_tools.sandbox_channels(REPORT)
        assert result["channels"] == ["android.permissions", "linux.systemd"]
        assert result["rows"] == []

    def test_a_named_channel_returns_its_rows(self) -> None:
        result = sandbox_tools.sandbox_channels(REPORT, "linux.systemd")
        assert result["channel"] == "linux.systemd"
        assert result["rows"] == [{"unit": "evil.service"}]

    def test_an_unknown_channel_names_the_ones_that_do_exist(self) -> None:
        result = sandbox_tools.sandbox_channels(REPORT, "windows.wmi")
        assert "no channel" in result["error"]
        assert "linux.systemd" in result["channels"]


class TestReportSection:
    def test_a_known_section_comes_back_whole(self) -> None:
        result = sandbox_tools.sandbox_report_section(REPORT, "target")
        assert result["section"] == "target"
        assert result["value"]["name"] == "invoice.exe"

    def test_an_unknown_section_lists_the_sections_that_are_there(self) -> None:
        result = sandbox_tools.sandbox_report_section(REPORT, "static")
        assert "no section" in result["error"]
        assert "behavior" in result["sections"]

    def test_a_list_section_is_bounded_and_counted(self, monkeypatch) -> None:
        monkeypatch.setattr(sandbox_tools, "_ROW_LIMIT", 2)
        result = sandbox_tools.sandbox_report_section({"strings": list(range(9))}, "strings")
        assert result["rows"] == [0, 1]
        assert result["total"] == 9


class TestNoReport:
    def test_every_tool_says_there_is_no_report_rather_than_answering_empty(self) -> None:
        for call in (
            lambda: sandbox_tools.sandbox_processes(None),
            lambda: sandbox_tools.sandbox_network(None),
            lambda: sandbox_tools.sandbox_signatures(None),
            lambda: sandbox_tools.sandbox_dropped_files(None),
            lambda: sandbox_tools.sandbox_channels(None),
            lambda: sandbox_tools.sandbox_report_section(None, "target"),
            lambda: sandbox_tools.sandbox_registry_ops(None),
            lambda: sandbox_tools.sandbox_api_calls(None),
            lambda: sandbox_tools.sandbox_mutexes(None),
            lambda: sandbox_tools.sandbox_services_and_tasks(None),
        ):
            assert call() == {"error": "no sandbox report for this job", "tool": "sandbox"}


class TestToolSet:
    def test_the_tools_are_built_over_the_container_s_report(self) -> None:
        tools = sandbox_tools.sandbox_tools(_Container(REPORT))

        assert [t.name for t in tools] == [
            "sandbox_report_section",
            "sandbox_processes",
            "sandbox_network",
            "sandbox_signatures",
            "sandbox_dropped_files",
            "sandbox_registry_ops",
            "sandbox_api_calls",
            "sandbox_mutexes",
            "sandbox_services_and_tasks",
            "sandbox_channels",
        ]
        processes = next(t for t in tools if t.name == "sandbox_processes")
        assert processes.invoke({})["total"] == 2

    def test_a_container_with_no_report_still_offers_every_tool(self) -> None:
        tools = sandbox_tools.sandbox_tools(_Container(None))
        assert len(tools) == 10
        processes = next(t for t in tools if t.name == "sandbox_processes")
        assert processes.invoke({})["error"] == "no sandbox report for this job"

    def test_a_normalised_report_model_is_rendered_to_the_shape_the_tools_read(self) -> None:
        from maljan.schemas.sandbox_report import SandboxReport

        report = SandboxReport(provider="triage", source_format="triage")
        tools = sandbox_tools.sandbox_tools(_Container(report))
        processes = next(t for t in tools if t.name == "sandbox_processes")
        assert processes.invoke({})["total"] == 0

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

    def test_every_row_comes_back_when_no_page_is_asked_for(self) -> None:
        report = {"network": {"dns": [{"request": f"h{i}.example"} for i in range(500)]}}

        result = sandbox_tools.sandbox_network(report)

        assert len(result["dns"]) == 500
        assert "dns_total" not in result

    def test_a_page_says_how_many_there_were_and_where_the_next_starts(self) -> None:
        report = {"network": {"dns": [{"request": f"h{i}.example"} for i in range(10)]}}

        result = sandbox_tools.sandbox_network(report, offset=3, limit=3)

        assert [row["request"] for row in result["dns"]] == [
            "h3.example",
            "h4.example",
            "h5.example",
        ]
        assert result["dns_total"] == 10
        assert result["dns_next_offset"] == 6


class TestRegistryOps:
    """Every registry row comes back unless a page is asked for.

    The golden answers over the real corpus once held 200 rows per report
    while the tool already answered all of them, and nothing outside that
    corpus noticed; this pins the whole-list answer where CI runs it.
    """

    @staticmethod
    def _report(count: int) -> dict[str, Any]:
        keys = [f"HKEY_CURRENT_USER\\Software\\Example\\k{i}" for i in range(count)]
        return {"behavior": {"summary": {"keys": keys}}}

    def test_every_row_comes_back_when_no_page_is_asked_for(self) -> None:
        result = sandbox_tools.sandbox_registry_ops(self._report(500))

        assert len(result["registry"]) == 500
        assert result["total"] == 500
        assert "next_offset" not in result

    def test_a_page_says_where_the_next_starts(self) -> None:
        result = sandbox_tools.sandbox_registry_ops(self._report(10), limit=3, offset=3)

        assert [row["key"][-2:] for row in result["registry"]] == ["k3", "k4", "k5"]
        assert result["total"] == 10
        assert result["next_offset"] == 6

    @staticmethod
    def _one_call(api: str, arguments: list[dict[str, str]]) -> dict[str, Any]:
        return {"behavior": {"processes": [{"calls": [{"api": api, "arguments": arguments}]}]}}

    def test_an_open_or_create_listing_the_hive_handle_first_is_keyed_by_its_path(self) -> None:
        for api, operation in (("RegOpenKeyExW", "query"), ("RegCreateKeyExW", "create")):
            report = self._one_call(
                api,
                [
                    {"name": "Registry", "value": "0x80000002"},
                    {"name": "SubKey", "value": "SOFTWARE\\Example"},
                    {"name": "Handle", "value": "0x00000120"},
                    {"name": "FullName", "value": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Example"},
                ],
            )

            rows = sandbox_tools.sandbox_registry_ops(report)["registry"]

            assert rows == [
                {
                    "key": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Example",
                    "operation": operation,
                    "value": None,
                }
            ]

    def test_without_a_full_path_the_subkey_is_the_key_not_the_handle(self) -> None:
        report = self._one_call(
            "RegCreateKeyExW",
            [
                {"name": "Registry", "value": "0x80000001"},
                {"name": "SubKey", "value": "Software\\Example"},
            ],
        )

        rows = sandbox_tools.sandbox_registry_ops(report)["registry"]

        assert [row["key"] for row in rows] == ["Software\\Example"]

    def test_a_value_query_through_the_native_api_is_a_query_with_the_value_read(self) -> None:
        report = self._one_call(
            "NtQueryValueKey",
            [
                {"name": "KeyHandle", "value": "0x00000124"},
                {"name": "ValueName", "value": "Example"},
                {"name": "Information", "value": "1"},
                {"name": "FullName", "value": "HKEY_CURRENT_USER\\Software\\Example\\Example"},
            ],
        )
        report["behavior"]["summary"] = {"keys": ["HKEY_CURRENT_USER\\Software\\Example\\Example"]}

        rows = sandbox_tools.sandbox_registry_ops(report)["registry"]

        assert rows == [
            {
                "key": "HKEY_CURRENT_USER\\Software\\Example\\Example",
                "operation": "query",
                "value": "1",
            }
        ]

    @staticmethod
    def _calls(*calls: tuple[str, str | None]) -> dict[str, Any]:
        rows = []
        for api, value in calls:
            arguments = [{"name": "FullName", "value": "HKEY_CURRENT_USER\\Software\\Example\\v"}]
            if value is not None:
                arguments.insert(0, {"name": "Data", "value": value})
            rows.append({"api": api, "arguments": arguments})
        return {"behavior": {"processes": [{"calls": rows}]}}

    def test_a_read_after_a_write_leaves_the_write_and_what_was_written(self) -> None:
        report = self._calls(("RegSetValueExW", "written"), ("RegQueryValueExW", "read back"))

        [row] = sandbox_tools.sandbox_registry_ops(report)["registry"]

        assert (row["operation"], row["value"]) == ("modify", "written")

    def test_a_read_that_saw_nothing_leaves_an_earlier_read_s_value(self) -> None:
        report = self._calls(("RegQueryValueExW", "seen"), ("NtQueryValueKey", None))

        [row] = sandbox_tools.sandbox_registry_ops(report)["registry"]

        assert (row["operation"], row["value"]) == ("query", "seen")

    def test_between_writes_the_later_one_stands(self) -> None:
        report = self._calls(("RegSetValueExW", "written"), ("RegDeleteValueW", None))

        [row] = sandbox_tools.sandbox_registry_ops(report)["registry"]

        assert (row["operation"], row["value"]) == ("delete", None)

    @staticmethod
    def _create(api: str, disposition: str | None, status: bool = True) -> dict[str, Any]:
        arguments = [
            {"name": "Registry", "value": "0x80000001"},
            {"name": "SubKey", "value": "Software\\Example"},
            {"name": "FullName", "value": "HKEY_CURRENT_USER\\Software\\Example"},
        ]
        if disposition is not None:
            arguments.append({"name": "Disposition", "value": disposition})
        call = {"api": api, "status": status, "arguments": arguments}
        return {"behavior": {"processes": [{"calls": [call]}]}}

    def test_a_create_that_opened_an_existing_key_is_a_read(self) -> None:
        for api in ("RegCreateKeyExW", "RegCreateKeyExA", "NtCreateKey"):
            [row] = sandbox_tools.sandbox_registry_ops(self._create(api, "2"))["registry"]

            assert row["operation"] == "query", api

    def test_a_create_that_made_a_new_key_is_a_create(self) -> None:
        for api in ("RegCreateKeyExW", "RegCreateKeyExA", "NtCreateKey"):
            [row] = sandbox_tools.sandbox_registry_ops(self._create(api, "1"))["registry"]

            assert row["operation"] == "create", api

    def test_a_disposition_filed_as_an_integer_or_padded_reads_as_its_text_form(self) -> None:
        cases: tuple[tuple[object, str], ...] = (
            (2, "query"),
            (1, "create"),
            ("02", "query"),
            ("0x2", "query"),
        )
        for disposition, expected in cases:
            report = self._create("RegCreateKeyExW", None)
            report["behavior"]["processes"][0]["calls"][0]["arguments"].append(
                {"name": "Disposition", "value": disposition}
            )

            [row] = sandbox_tools.sandbox_registry_ops(report)["registry"]

            assert row["operation"] == expected, disposition

    def test_a_create_with_no_known_outcome_keeps_its_api_s_operation(self) -> None:
        for disposition in (None, "", "1701304", "not a number"):
            report = self._create("RegCreateKeyExW", disposition)

            [row] = sandbox_tools.sandbox_registry_ops(report)["registry"]

            assert row["operation"] == "create", disposition

    def test_an_opened_key_does_not_outrank_a_later_write(self) -> None:
        report = self._create("RegCreateKeyExW", "2")
        report["behavior"]["processes"][0]["calls"].append(
            {
                "api": "RegSetValueExW",
                "status": True,
                "arguments": [
                    {"name": "Buffer", "value": "x"},
                    {"name": "FullName", "value": "HKEY_CURRENT_USER\\Software\\Example"},
                ],
            }
        )

        [row] = sandbox_tools.sandbox_registry_ops(report)["registry"]

        assert (row["operation"], row["value"]) == ("modify", "x")

    def test_a_failed_write_is_bare_access_without_its_value(self) -> None:
        report = self._create("RegCreateKeyExW", "1", status=False)
        report["behavior"]["processes"][0]["calls"].append(
            {
                "api": "RegDeleteValueA",
                "status": False,
                "return": "0x00000002",
                "arguments": [
                    {"name": "Handle", "value": "0x00000120"},
                    {"name": "ValueName", "value": "Example"},
                    {"name": "FullName", "value": "HKEY_CURRENT_USER\\Software\\Run\\Example"},
                ],
            }
        )

        rows = sandbox_tools.sandbox_registry_ops(report)["registry"]

        assert [(row["operation"], row["value"]) for row in rows] == [
            ("access", None),
            ("access", None),
        ]

    def test_a_read_replaces_a_failed_write(self) -> None:
        report = self._calls(("RegSetValueExW", "never written"), ("RegQueryValueExW", "seen"))
        report["behavior"]["processes"][0]["calls"][0]["status"] = False

        [row] = sandbox_tools.sandbox_registry_ops(report)["registry"]

        assert (row["operation"], row["value"]) == ("query", "seen")

    def test_a_failed_read_is_still_a_read(self) -> None:
        report = self._calls(("NtQueryValueKey", None))
        report["behavior"]["processes"][0]["calls"][0]["status"] = False

        [row] = sandbox_tools.sandbox_registry_ops(report)["registry"]

        assert row["operation"] == "query"

    def test_the_extended_open_and_delete_calls_are_read(self) -> None:
        open_ex = {
            "api": "NtOpenKeyEx",
            "status": True,
            "arguments": [
                {"name": "KeyHandle", "value": "0x00000130"},
                {"name": "ObjectAttributes", "value": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Opened"},
            ],
        }
        delete_ex = {
            "api": "RegDeleteKeyExW",
            "status": True,
            "arguments": [
                {"name": "Handle", "value": "0x00000134"},
                {"name": "SubKey", "value": "Deleted"},
                {"name": "FullName", "value": "HKEY_CURRENT_USER\\Software\\Deleted"},
            ],
        }
        report = {"behavior": {"processes": [{"calls": [open_ex, delete_ex]}]}}

        rows = sandbox_tools.sandbox_registry_ops(report)["registry"]

        assert [(row["key"], row["operation"]) for row in rows] == [
            ("HKEY_LOCAL_MACHINE\\SOFTWARE\\Opened", "query"),
            ("HKEY_CURRENT_USER\\Software\\Deleted", "delete"),
        ]

    def test_every_outcome_refines_a_listed_operation_into_a_weighed_one(self) -> None:
        listed = set(sandbox_tools._REGISTRY_OPS.values())
        for operation, (_name, meanings) in sandbox_tools._REGISTRY_OUTCOMES.items():
            assert operation in listed
            assert set(meanings.values()) <= set(sandbox_tools._REGISTRY_OP_WEIGHT)
        assert sandbox_tools._FAILED_WRITE in sandbox_tools._REGISTRY_OP_WEIGHT

    def test_every_operation_the_table_names_has_a_weight(self) -> None:
        operations = set(sandbox_tools._REGISTRY_OPS.values()) | {"access"}
        assert operations <= set(sandbox_tools._REGISTRY_OP_WEIGHT)


class TestApiNameTables:
    """Every API a sandbox tool matches calls by is spelt as Windows exports it.

    A name the table spells wrong matches no call and fails silently: the
    native value query was once listed with a doubled letter and every one of
    its calls fell out of the registry view. The spelling list is the vendored
    export-name catalogue ``api_hashes`` reads.
    """

    @staticmethod
    def _exported() -> set[str]:
        from maljan.tools.api_hashes import load_export_names

        names: set[str] = set()
        stack: list[Any] = [load_export_names()]
        while stack:
            item = stack.pop()
            if isinstance(item, str):
                names.add(item.lower())
            elif isinstance(item, dict):
                stack.extend(item.values())
            elif isinstance(item, list):
                stack.extend(item)
        return names

    def test_every_listed_api_is_an_exported_windows_function(self) -> None:
        exported = self._exported()
        listed = (
            set(sandbox_tools._REGISTRY_OPS)
            | set(sandbox_tools._MUTEX_APIS)
            | set(sandbox_tools._SERVICE_APIS)
        )

        assert sorted(name for name in listed if name not in exported) == []

    def test_the_tables_are_lower_case_as_the_lookups_ask(self) -> None:
        for table in (
            sandbox_tools._REGISTRY_OPS,
            sandbox_tools._MUTEX_APIS,
            sandbox_tools._SERVICE_APIS,
        ):
            assert all(name == name.lower() for name in table)


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

    def test_a_list_section_comes_back_whole_and_counted(self) -> None:
        result = sandbox_tools.sandbox_report_section({"strings": list(range(900))}, "strings")
        assert result["rows"] == list(range(900))
        assert result["total"] == 900

    def test_a_page_of_a_list_section_names_the_next_offset(self) -> None:
        result = sandbox_tools.sandbox_report_section(
            {"strings": list(range(9))}, "strings", offset=0, limit=2
        )
        assert result["rows"] == [0, 1]
        assert result["total"] == 9
        assert result["shown"] == "2 of 9 rows, from offset 0"
        assert result["next_offset"] == 2


class TestApiCalls:
    """One row per API, carrying what the sandbox recorded and nothing else.

    The rows used to carry a behaviour category and a suspicious flag copied
    from the import table, and an analyst read the label as a finding. What
    an API is used for is the knowledge server's question.
    """

    def test_a_row_is_the_sandbox_s_facts_and_no_label(self) -> None:
        rows = sandbox_tools.sandbox_api_calls(REPORT)["apis"]

        assert [r["api"] for r in rows] == ["CreateRemoteThread", "WriteProcessMemory"]
        for row in rows:
            assert set(row) == {
                "api",
                "dll",
                "processes",
                "process_count",
                "count",
                "first_args",
                "first_seen",
            }
            assert row["processes"] == ["invoice.exe"]

    def test_the_first_call_s_arguments_module_and_time_are_kept(self) -> None:
        report = {
            "behavior": {
                "processes": [
                    {
                        "pid": 7,
                        "process_name": "a.exe",
                        "calls": [
                            {
                                "api": "CreateFileW",
                                "dll": "kernel32.dll",
                                "timestamp": "12:00:01",
                                "arguments": [{"name": "FileName", "value": "C:\\x"}],
                            },
                            {"api": "CreateFileW", "arguments": [{"name": "FileName"}]},
                        ],
                    }
                ]
            }
        }

        (row,) = sandbox_tools.sandbox_api_calls(report)["apis"]

        assert (row["dll"], row["first_seen"], row["count"]) == ("kernel32.dll", "12:00:01", 0)
        assert "C:" in row["first_args"]

    def test_a_name_substring_narrows_the_rows(self) -> None:
        answer = sandbox_tools.sandbox_api_calls(REPORT, name="remote")

        assert [r["api"] for r in answer["apis"]] == ["CreateRemoteThread"]
        assert answer["total"] == 1

    def test_a_process_narrows_by_pid_or_name(self) -> None:
        by_name = sandbox_tools.sandbox_api_calls(REPORT, process="invoice.exe")["apis"]
        by_pid = sandbox_tools.sandbox_api_calls(REPORT, process="1234")["apis"]
        other = sandbox_tools.sandbox_api_calls(REPORT, process="cmd.exe")["apis"]

        assert len(by_name) == len(by_pid) == 2
        assert other == []

    def test_the_tool_takes_a_name_filter_and_no_category(self) -> None:
        tool = next(
            t
            for t in sandbox_tools.sandbox_tools(_Container(REPORT))
            if t.name == "sandbox_api_calls"
        )

        fields = set(tool.args_schema.model_fields)
        assert fields == {"process", "name", "offset", "limit"}
        assert "api_capability" in tool.description


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

    def test_the_mock_s_stand_in_is_answered_as_no_sandbox_run(self) -> None:
        from maljan.pipeline.sandbox_status import sandbox_status

        stand_in = {"synthetic": True, "behavior": {"processes": []}, "signatures": []}
        statement = sandbox_status(stand_in).statement

        for call in (
            lambda: sandbox_tools.sandbox_processes(stand_in),
            lambda: sandbox_tools.sandbox_signatures(stand_in),
            lambda: sandbox_tools.sandbox_report_section(stand_in, "behavior"),
        ):
            assert call() == {"error": statement, "tool": "sandbox"}
        tools = sandbox_tools.sandbox_tools(_Container(stand_in))
        processes = next(t for t in tools if t.name == "sandbox_processes")
        assert processes.invoke({})["error"] == statement


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
            "sandbox_items",
        ]
        processes = next(t for t in tools if t.name == "sandbox_processes")
        assert processes.invoke({})["total"] == 2

    def test_a_container_with_no_report_still_offers_every_tool(self) -> None:
        tools = sandbox_tools.sandbox_tools(_Container(None))
        assert len(tools) == 11
        processes = next(t for t in tools if t.name == "sandbox_processes")
        assert processes.invoke({})["error"] == "no sandbox report for this job"

    def test_a_normalised_report_model_is_rendered_to_the_shape_the_tools_read(self) -> None:
        from maljan.schemas.sandbox_report import SandboxReport

        report = SandboxReport(provider="triage", source_format="triage")
        tools = sandbox_tools.sandbox_tools(_Container(report))
        processes = next(t for t in tools if t.name == "sandbox_processes")
        assert processes.invoke({})["total"] == 0

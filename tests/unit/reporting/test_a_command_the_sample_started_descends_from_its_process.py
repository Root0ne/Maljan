"""A command is the sample's only below a process that runs the sample (T-494, D8).

The haiku8 run's sandbox marked every desktop process as the sample's, and the
report listed ``explorer.exe /LOADSAVEDWINDOWS`` (pid 95, under sihost.exe) as a
command the sample started. A process the sample started descends, in the
process tree, from a process that runs the submitted file; the sandbox's mark
alone never makes it one. A command left out is said, never dropped silently.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from maljan.reporting.models import (
    DynamicBehavior,
    FileHashes,
    MalwareReport,
    ProcessNode,
    SampleIdentity,
)
from maljan.reporting.renderers.layout import ANALYST, FULL
from maljan.reporting.renderers.markdown import MarkdownRenderer, started_by_the_sample

_SHA = "60" * 32


def _report(*roots: ProcessNode) -> MalwareReport:
    fields: dict[str, Any] = {
        "identity": SampleIdentity(hashes=FileHashes(sha256=_SHA), file_name=f"{_SHA}.exe"),
        "verdict": "Malware",
        "overall_confidence": 0.8,
        "generated_at": datetime(2026, 1, 1, tzinfo=UTC),
        "dynamic": DynamicBehavior(process_tree=list(roots)),
    }
    return MalwareReport(**fields)


def _sample(pid: int, *children: ProcessNode) -> ProcessNode:
    return ProcessNode(
        pid=pid,
        ppid=56,
        name="C:\\Windows\\system32\\rundll32.exe",
        command_line=f"rundll32.exe C:\\Users\\a\\AppData\\Local\\Temp\\{_SHA}.dll,#1",
        marked=True,
        children=list(children),
    )


def _desktop() -> ProcessNode:
    explorer = ProcessNode(
        pid=95,
        ppid=93,
        name="C:\\Windows\\explorer.exe",
        command_line="explorer.exe /LOADSAVEDWINDOWS",
        marked=True,
    )
    return ProcessNode(
        pid=93,
        ppid=29,
        name="C:\\Windows\\system32\\sihost.exe",
        command_line="sihost.exe",
        marked=True,
        children=[explorer],
    )


def _child(pid: int, ppid: int, command: str) -> ProcessNode:
    return ProcessNode(
        pid=pid, ppid=ppid, name="C:\\Windows\\system32\\cmd.exe", command_line=command
    )


class TestWhichCommandIsTheSamples:
    def test_a_marked_desktop_process_is_no_command_the_sample_started(self) -> None:
        started, others = started_by_the_sample(_report(_sample(84), _desktop()))
        assert started == []
        assert [node.pid for node in others] == [95]

    def test_a_process_below_the_sample_is_one_at_any_depth(self) -> None:
        grandchild = _child(102, 101, "whoami /groups")
        child = _child(101, 84, "cmd.exe /c ipconfig /all")
        child.children.append(grandchild)
        started, others = started_by_the_sample(_report(_sample(84, child), _desktop()))
        assert [node.pid for node in started] == [101, 102]
        assert [node.pid for node in others] == [95]

    def test_a_marked_root_no_file_names_keeps_its_children(self) -> None:
        # A renamed or staged copy the sandbox marks, its name and digest unmatched:
        # the mark is then the one lineage fact, and its children are its own.
        renamed = ProcessNode(
            pid=70,
            ppid=4,
            name="C:\\Users\\a\\AppData\\Local\\Temp\\inner.exe",
            command_line="inner.exe",
            marked=True,
            children=[_child(71, 70, "cmd.exe /c whoami")],
        )
        report = _report(renamed)
        started, others = started_by_the_sample(report)
        assert [node.pid for node in started] == [71] and others == []

    def test_a_child_with_no_recorded_pid_is_placed_by_its_parent(self) -> None:
        started, others = started_by_the_sample(
            _report(_sample(84, _child(0, 84, "cmd.exe /c whoami")), _desktop())
        )
        assert [node.command_line for node in started] == ["cmd.exe /c whoami"]
        assert [node.pid for node in others] == [95]

    def test_no_lineage_fact_attributes_nothing(self) -> None:
        unmarked = ProcessNode(
            pid=93,
            ppid=29,
            name="C:\\Windows\\system32\\sihost.exe",
            command_line="sihost.exe",
            children=[_child(95, 93, "explorer.exe /LOADSAVEDWINDOWS")],
        )
        started, others = started_by_the_sample(_report(unmarked))
        assert started == [] and [node.pid for node in others] == [95]


class TestTheTablesSayWhatTheyLeaveOut:
    def test_no_table_and_no_line_when_the_sample_started_nothing(self) -> None:
        report = _report(_sample(84), _desktop())
        for layout in (ANALYST, FULL):
            markdown = MarkdownRenderer(layout=layout).render(report)
            assert "ommands the sample started" not in markdown
            assert "| 95 | `explorer.exe /LOADSAVEDWINDOWS` |" not in markdown
            assert "Not listed" not in markdown

    def test_the_analyst_table_keeps_the_sample_s_own_commands(self) -> None:
        child = _child(101, 84, "cmd.exe /c ipconfig /all")
        markdown = MarkdownRenderer(layout=ANALYST).render(_report(_sample(84, child), _desktop()))
        assert "Commands the sample started" in markdown
        assert "| 101 | `cmd.exe /c ipconfig /all` |" in markdown
        assert "| 95 |" not in markdown
        assert (
            "_Not listed: 1 command line not attributed to the sample (pid 95); the evidence "
            "bundle's process tree lists every process._"
        ) in markdown

    def test_the_full_report_says_it_too(self) -> None:
        child = _child(101, 84, "cmd.exe /c ipconfig /all")
        markdown = MarkdownRenderer(layout=FULL).render(_report(_sample(84, child), _desktop()))
        assert "commands the sample started" in markdown
        assert "| 101 | `cmd.exe /c ipconfig /all` |" in markdown
        assert "Not listed: 1 command line not attributed to the sample (pid 95)" in markdown

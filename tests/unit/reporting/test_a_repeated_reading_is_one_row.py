"""The same sandbox process, signature, lookup, recovery or left-out item read twice is one row.

A run calls the same tool more than once (the pack's call and an analyst's),
and the first answer an analyst gives can hold one text several times. Each
repeat is the same fact; what is distinct (another process, another entry id,
another reason) is still printed.
"""

from __future__ import annotations

from typing import Any

from maljan.pipeline.validation import retry_drop_row, retry_drop_sentences
from maljan.reporting.dedupe import distinct_processes
from maljan.reporting.ledger_projection import dynamic_from_ledger
from maljan.reporting.models import (
    EmulatedStrings,
    EvidenceIndexRow,
    ProcessNode,
    RecoveredValue,
    SandboxSignature,
)
from maljan.reporting.renderers.markdown import MarkdownRenderer, _reputation_line
from maljan.reporting.renderers.stix_renderer import ExtendedSTIXRenderer, recovered_by_words
from maljan.schemas.evidence import EvidenceCounter
from tests.unit._ledger_helpers import entry
from tests.unit.reporting._report_shapes import rich_report

_PROCESSES = {
    "total": 3,
    "processes": [
        {"pid": 410, "ppid": 12, "name": "C:\\example\\host.exe", "command_line": "host.exe a"},
        {"pid": 411, "ppid": 410, "name": "C:\\example\\child.exe", "command_line": "child.exe"},
        {"pid": 520, "ppid": 7, "name": "C:\\example\\svc.exe", "command_line": "svc.exe -k x"},
    ],
}
_SIGNATURES = {
    "signatures": [
        {"name": "Example family rule", "description": "Example family rule", "severity": 10},
        {"name": "Unsigned PE", "description": "No Authenticode signature.", "severity": 3},
    ]
}


def _tree_lines(roots: list[Any]) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    for node in roots:
        out.append((node.pid, node.ppid))
        out.extend(_tree_lines(node.children))
    return out


class TestTheProjection:
    def _dynamic(self, *payloads: tuple[str, Any]) -> Any:
        counter = EvidenceCounter()
        ledger = [entry(tool, data, counter, agent="dynamic") for tool, data in payloads]
        dynamic = dynamic_from_ledger(ledger)
        assert dynamic is not None
        return dynamic

    def test_two_calls_of_one_task_give_each_process_once(self) -> None:
        dynamic = self._dynamic(
            ("sandbox_processes", _PROCESSES),
            ("sandbox_processes", _PROCESSES),
        )
        assert _tree_lines(dynamic.process_tree) == [(410, 12), (411, 410), (520, 7)]

    def test_a_process_one_call_alone_read_is_kept(self) -> None:
        more = {
            "processes": [
                *_PROCESSES["processes"],
                {"pid": 600, "ppid": 410, "name": "C:\\example\\late.exe", "command_line": ""},
            ]
        }
        dynamic = self._dynamic(("sandbox_processes", _PROCESSES), ("sandbox_processes", more))
        assert _tree_lines(dynamic.process_tree) == [(410, 12), (411, 410), (600, 410), (520, 7)]

    def test_a_reused_pid_with_another_image_is_another_process(self) -> None:
        other = {"processes": [{"pid": 520, "ppid": 7, "name": "C:\\example\\other.exe"}]}
        dynamic = self._dynamic(("sandbox_processes", _PROCESSES), ("sandbox_processes", other))
        names = [node.name for node in dynamic.process_tree]
        assert names.count("C:\\example\\svc.exe") == 1
        assert names.count("C:\\example\\other.exe") == 1

    def test_two_calls_give_each_signature_once(self) -> None:
        dynamic = self._dynamic(
            ("sandbox_signatures", _SIGNATURES),
            ("sandbox_signatures", _SIGNATURES),
        )
        assert [sig.name for sig in dynamic.sandbox_signatures] == [
            "Example family rule",
            "Unsigned PE",
        ]


def _doubled_report() -> Any:
    """A stored report whose tree and signatures were projected from two calls."""
    report = rich_report()
    dynamic = report.dynamic
    assert dynamic is not None
    dynamic.process_tree = [
        ProcessNode(pid=410, ppid=12, name="C:\\example\\host.exe", command_line="host.exe a"),
        ProcessNode(pid=520, ppid=7, name="C:\\example\\svc.exe", command_line="svc.exe -k x"),
    ] * 2
    dynamic.process_tree[2] = dynamic.process_tree[2].model_copy(
        update={
            "children": [
                ProcessNode(
                    pid=411, ppid=410, name="C:\\example\\child.exe", command_line="child.exe"
                )
            ],
            "injected_into": [520],
        }
    )
    dynamic.sandbox_signatures = [
        SandboxSignature(name="Example family rule", description="d", severity=10),
        SandboxSignature(name="Unsigned PE", description="u", severity=3),
    ] * 2
    return report


class TestAStoredReport:
    def test_the_tree_prints_each_process_once_and_keeps_a_repeat_s_children(self) -> None:
        markdown = MarkdownRenderer().render(_doubled_report())
        tree = markdown.split("### Process tree", 1)[1].split("```", 2)[1]
        roots = [line.split(" ", 1)[0] for line in tree.splitlines() if line.startswith("pid=")]
        assert roots == ["pid=410", "pid=520"]
        assert "  └─ pid=411 ppid=410" in tree

    def test_the_signatures_print_once(self) -> None:
        markdown = MarkdownRenderer().render(_doubled_report())
        table = markdown.split("### Sandbox signatures", 1)[1].split("\n\n", 2)[1]
        assert table.count("| Example family rule |") == 1
        assert table.count("| Unsigned PE |") == 1

    def test_the_stored_tree_is_left_as_it_was(self) -> None:
        report = _doubled_report()
        assert report.dynamic is not None
        roots = distinct_processes(report.dynamic.process_tree)
        assert [node.pid for node in roots] == [410, 520]
        assert roots[0].injected_into == [520]
        assert len(report.dynamic.process_tree) == 4
        assert report.dynamic.process_tree[0].children == []

    def test_a_root_one_reading_held_and_a_child_another_held_is_one_process(self) -> None:
        """A reading that lacked the parent made the child a root of its own."""
        child = ProcessNode(
            pid=411,
            ppid=410,
            name="C:\\example\\child.exe",
            command_line="child.exe",
            injected_into=[520],
            children=[ProcessNode(pid=412, ppid=411, name="C:\\example\\grand.exe")],
        )
        parent = ProcessNode(
            pid=410,
            ppid=12,
            name="C:\\example\\host.exe",
            command_line="host.exe a",
            children=[child.model_copy(update={"children": [], "injected_into": []})],
        )
        for stored in ([parent, child], [child, parent]):
            roots = distinct_processes(stored)
            assert _tree_lines(roots) == [(410, 12), (411, 410), (412, 411)], stored
            assert roots[0].children[0].injected_into == [520]
        report = rich_report()
        assert report.dynamic is not None
        report.dynamic.process_tree = [parent, child]
        markdown = MarkdownRenderer().render(report)
        tree = markdown.split("### Process tree", 1)[1].split("```", 2)[1]
        pids = [
            line.split("pid=", 1)[1].split(" ", 1)[0]
            for line in tree.splitlines()
            if "pid=" in line
        ]
        assert pids == ["410", "411", "412"]

    def test_the_export_carries_each_process_once(self) -> None:
        bundle = ExtendedSTIXRenderer().render(_doubled_report())
        processes = [obj for obj in bundle.objects if getattr(obj, "type", "") == "process"]
        assert sorted(obj.pid for obj in processes) == [410, 411, 520]


class TestTheReputationLine:
    def test_the_tool_is_named_once_before_its_entries(self) -> None:
        report = rich_report()
        report.evidence_index = [
            EvidenceIndexRow(id=f"ev_000{n}", tool="get_file_report") for n in (1, 4, 7)
        ]
        line = _reputation_line(report)
        assert line.count("get_file_report") == 1
        assert "get_file_report, ev_0001, ev_0004, ev_0007" in line

    def test_one_lookup_reads_as_before(self) -> None:
        report = rich_report()
        report.evidence_index = [EvidenceIndexRow(id="ev_0002", tool="get_file_report")]
        assert "get_file_report, ev_0002" in _reputation_line(report)


class TestARecoveredValue:
    _VALUE = "example-c2.invalid"

    def _record(self, *how: RecoveredValue) -> EmulatedStrings:
        return EmulatedStrings(values={self._VALUE: "ev_0010"}, recovered_by={self._VALUE: [*how]})

    def test_one_place_from_two_calls_is_stated_once_with_both_entries(self) -> None:
        place = {"scheme": "xor8", "offset": "0x100", "functions": ["0x2000"]}
        said = recovered_by_words(
            self._record(
                RecoveredValue(tool="decode_string_blobs", entry="ev_0010", **place),
                RecoveredValue(tool="decode_string_blobs", entry="ev_0020", **place),
            ),
            "domain",
            self._VALUE,
        )
        assert said == (
            "decode_string_blobs, ev_0010, ev_0020 (xor8, at file offset 0x100, in function 0x2000)"
        )

    def test_two_places_stay_two(self) -> None:
        said = recovered_by_words(
            self._record(
                RecoveredValue(tool="decode_string_blobs", entry="ev_0010", offset="0x100"),
                RecoveredValue(tool="decode_string_blobs", entry="ev_0020", offset="0x180"),
            ),
            "domain",
            self._VALUE,
        )
        assert said == (
            "decode_string_blobs, ev_0010 (at file offset 0x100); "
            "decode_string_blobs, ev_0020 (at file offset 0x180)"
        )


class TestALeftOutItem:
    def _row(self, reason: str, *, state: str = "kept when asked", round_: int = 0) -> Any:
        return retry_drop_row(
            "reverser",
            round_,
            "claim",
            "Routine 0x2200 runs the listing",
            ["0x2200"],
            state,
            reason,
        )

    def test_one_text_answered_three_times_is_one_sentence_with_every_reason(self) -> None:
        rows = [self._row("first site"), self._row("second site"), self._row("first site")]
        sentences = retry_drop_sentences(rows)
        assert len(sentences) == 1
        assert sentences[0].endswith(
            "kept when asked (first site; second site). "
            "The record holds it 3 times, from revision round 0."
        )

    def test_rounds_are_named_when_they_differ(self) -> None:
        rows = [self._row("a"), self._row("a", round_=1)]
        assert retry_drop_sentences(rows)[0].endswith(
            "The record holds it 2 times, from revision rounds 0, 1."
        )

    def test_a_different_outcome_is_another_sentence(self) -> None:
        rows = [self._row("a"), self._row("b", state="withdrawn when asked")]
        assert retry_drop_sentences(rows) == [rows[0]["sentence"], rows[1]["sentence"]]

    def test_a_row_alone_prints_its_recorded_sentence(self) -> None:
        row = self._row("a")
        assert retry_drop_sentences([row]) == [row["sentence"]]


class TestAHostileStoredTree:
    """Every root is the child of the one before it, and every root is stored twice.

    Every root but the first folds into the tree before it: the case a fold
    that rescans the other roots after each fold turns cubic.
    """

    @staticmethod
    def _chain(count: int) -> list[ProcessNode]:
        roots = [
            ProcessNode(
                pid=1000 + index,
                ppid=999 + index,
                name="C:\\example\\step.exe",
                children=[
                    ProcessNode(pid=1001 + index, ppid=1000 + index, name="C:\\example\\step.exe")
                ],
            )
            for index in range(count)
        ]
        return roots + roots

    @staticmethod
    def _measure(count: int) -> tuple[float, int, list[ProcessNode]]:
        import time
        import tracemalloc

        stored = TestAHostileStoredTree._chain(count)
        took = []
        for _ in range(3):
            started = time.perf_counter()
            roots = distinct_processes(stored)
            took.append(time.perf_counter() - started)
        tracemalloc.start()
        distinct_processes(stored)
        peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
        return min(took), peak, roots

    def test_ten_times_the_roots_costs_about_ten_times(self) -> None:
        from maljan.reporting.dedupe import _descendants

        small_time, small_peak, small = self._measure(1_000)
        large_time, large_peak, large = self._measure(10_000)
        for roots, count in ((small, 1_000), (large, 10_000)):
            assert [root.pid for root in roots] == [1000]
            assert len(_descendants(roots[0])) == count
        assert large_peak <= small_peak * 15, (small_peak, large_peak)
        assert large_time <= small_time * 20, (small_time, large_time)

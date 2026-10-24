"""A process read twice and a code span drawn as code are not losses; a real loss still is.

The report's process tree can hold one sandbox process twice (the pack's call
and an analyst's read the same task), and the export carries each process once:
the checker reads the tree as the exporter folds it and counts processes by the
exporter's own identity (the raw pid, parent, image and command line), so the
repeat is no missing object, while two processes that differ in any of them,
whitespace included, still need two, and one process written as two objects is
carried twice. A section's text holds Markdown code spans, which
the HTML draws as ``<code>``: the text read with its spans as code is the
value, while a word the HTML drops is still missing.
"""

from __future__ import annotations

import copy
from typing import Any

from scripts.audit import surfaces

from tests.unit.scripts._surfaces_run import PROCESS, clean_run, clean_spec, defects


def _trees(run: dict[str, Any]) -> list[dict[str, Any]]:
    return [run["report_row"]["malware_report"], run["report_full"]]


def test_a_process_read_twice_is_one_process_object() -> None:
    run = clean_run()
    for mr in _trees(run):
        mr["dynamic"]["process_tree"] = [dict(PROCESS), dict(PROCESS)]

    result = surfaces.audit(run, clean_spec())

    assert defects(result) == []


def test_two_processes_with_one_pid_and_command_still_need_two_objects() -> None:
    run = clean_run()
    other = {**PROCESS, "ppid": 99}
    for mr in _trees(run):
        mr["dynamic"]["process_tree"] = [dict(PROCESS), dict(other)]

    result = surfaces.audit(run, clean_spec())

    assert defects(result) == [("missing", "process", "stix")]


_TEXT = "sandbox mutexes: no: the report carries no `mutexes`. sandbox files: no `files`."


def _code_span_section(run: dict[str, Any], html_text: str) -> None:
    section = {
        "key": "behaviour_code_links",
        "title": "Observed behaviour linked to code",
        "kind": "text",
        "columns": [],
        "rows": [],
        "items": [],
        "text": _TEXT,
        "evidence_ids": ["ev_0001"],
    }
    for mr in _trees(run):
        mr["sections"].append(copy.deepcopy(section))
    run["markdown"] += f"\n### {section['title']} · _Measured_\n\n{_TEXT}\n"
    run["html"] = run["html"].replace(
        "</body>",
        f"<h3>{section['title']} · <em>Measured</em></h3><p>{html_text}</p></body>",
    )


def test_a_code_span_the_html_draws_as_code_is_the_section_text() -> None:
    run = clean_run()
    _code_span_section(
        run,
        "sandbox mutexes: no: the report carries no <code>mutexes</code>. "
        "sandbox files: no <code>files</code>.",
    )

    result = surfaces.audit(run, clean_spec())

    assert defects(result) == []


def test_a_word_the_html_drops_beside_a_code_span_is_still_missing() -> None:
    run = clean_run()
    _code_span_section(
        run,
        "sandbox mutexes: no: the report carries no <code>mutexes</code>. sandbox files: no.",
    )

    result = surfaces.audit(run, clean_spec())

    assert defects(result) == [("missing", "section_item", "html:behaviour_code_links")]


def test_a_process_differing_only_in_whitespace_is_another_process() -> None:
    # The exporter's identity reads the raw command line and image, so these
    # are two processes, and one object for them is a missing one.
    for other in (
        {**PROCESS, "command_line": PROCESS["command_line"].replace(" ", "  ", 1)},
        {**PROCESS, "name": PROCESS["name"] + " "},
    ):
        run = clean_run()
        for mr in _trees(run):
            mr["dynamic"]["process_tree"] = [dict(PROCESS), dict(other)]

        result = surfaces.audit(run, clean_spec())

        assert defects(result) == [("missing", "process", "stix")], other


_CHILD = {"pid": 20, "ppid": 4, "name": "cmd.exe", "command_line": "cmd /c whoami", "children": []}


def _two_readings_of_a_parent(run: dict[str, Any], child_objects: int) -> None:
    # Two readings of pid 4 that differ in the command line, each holding pid 20.
    tree = [
        {**PROCESS, "children": [dict(_CHILD)]},
        {**PROCESS, "command_line": "", "children": [dict(_CHILD)]},
    ]
    for mr in _trees(run):
        mr["dynamic"]["process_tree"] = copy.deepcopy(tree)
    objects = run["stix"]["objects"]
    objects.append({"type": "process", "id": "process--2", "pid": 4})
    for n in range(child_objects):
        objects.append(
            {"type": "process", "id": f"process--c{n}", "pid": 20, "command_line": "cmd /c whoami"}
        )
    run["markdown"] += "\npid=20 cmd.exe (cmd /c whoami)"
    run["html"] = run["html"].replace("</body>", "<p>pid=20 cmd.exe</p></body>")
    for summary in (run["report_row"]["run_summary"], run["run_summary"]):
        summary["stix_object_count"] = len(objects)


def test_a_child_under_two_readings_of_its_parent_is_one_object() -> None:
    run = clean_run()
    _two_readings_of_a_parent(run, child_objects=1)

    result = surfaces.audit(run, clean_spec())

    assert defects(result) == []


def test_a_process_the_export_writes_twice_is_carried_twice() -> None:
    run = clean_run()
    _two_readings_of_a_parent(run, child_objects=2)

    result = surfaces.audit(run, clean_spec())

    assert defects(result) == [("duplicate", "process", "stix")]
    (found,) = result["defects"]
    assert "carried 2 times for 1 process(es)" in found["detail"]


def test_a_pid_written_as_text_is_the_number_the_report_reads() -> None:
    # The report's model reads "4" as 4, and the export writes the number.
    run = clean_run()
    for mr in _trees(run):
        mr["dynamic"]["process_tree"] = [{**PROCESS, "pid": "4", "ppid": "0"}]

    result = surfaces.audit(run, clean_spec())

    assert defects(result) == []

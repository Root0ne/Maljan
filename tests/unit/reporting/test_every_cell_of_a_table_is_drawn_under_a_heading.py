"""Every cell of a table is drawn, each under a heading.

A kind more than one analyst listed is one table headed as its first artifact
is, and a later artifact's cells the table has no place for follow its
columns. The columns stayed the first artifact's, so those cells had no
heading, and the Markdown cut every row to its columns: the HTML and the PDF
lost them (T-343). The table's columns are now the union: a cell past them is
headed by its own artifact's heading where that reads the table the same, by
its position otherwise. A stored report whose rows are wider than its columns
is drawn with the extra cells headed by position, as the console heads them.
"""

from __future__ import annotations

import random
from collections import Counter
from typing import Any

from maljan.reporting.ledger_projection import listed_cells, listed_columns
from maljan.reporting.ledger_report import (
    _in_the_union,
    analyst_persistence,
    build_sections,
    listed_headings,
    listed_rows,
)
from maljan.reporting.models import EvidenceSection, FileHashes, MalwareReport, SampleIdentity
from maljan.reporting.renderers.html import HtmlRenderer
from maljan.reporting.renderers.markdown import MarkdownRenderer
from maljan.schemas.isr_models import AgentISR, Artifact


def _merged(kind: str, *listed: tuple[list[str], list[list[str]]]) -> EvidenceSection:
    isrs = {
        name: AgentISR(
            agent_id=name,
            domain="static",
            artifacts=[Artifact(kind=kind, columns=columns, rows=rows, evidence_ids=[f"ev_{i}"])],
        )
        for i, (name, (columns, rows)) in enumerate(
            zip(("static", "dynamic", "network"), listed, strict=False)
        )
    }
    return next(s for s in build_sections([], isrs) if s.key == f"artifact_{kind}")


def _report(section: EvidenceSection) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)), sections=[section]
    )


def _wide(table: Any) -> list[list[str]]:
    return [row for row in table.rows if len(row) > len(table.columns)]


def test_a_later_artifact_s_extra_cell_is_headed_by_its_own_heading() -> None:
    table = _merged(
        "imports",
        (["Library"], [["KERNEL32.dll"]]),
        (["Library", "Function"], [["kernel32.dll", "VirtualAllocEx"]]),
    )

    assert table.columns == ["Listed by", "Evidence", "Library", "Function"]
    assert _wide(table) == []
    assert ["dynamic", "ev_1", "kernel32.dll", "VirtualAllocEx"] in table.rows


def test_a_payload_the_table_names_no_place_for_is_headed_as_it_is_read() -> None:
    table = _merged(
        "persistence",
        (["Type", "Value"], [["registry_run", "HKCU\\Run\\x"]]),
        (["Target", "Kind", "Payload"], [["Updater", "scheduled_task", "C:\\x.exe"]]),
    )

    assert table.columns == ["Listed by", "Evidence", "Type", "Value", "Payload"]
    assert _wide(table) == []
    # The payload is read from the same cell as before the heading was added.
    assert [r["payload"] for r in analyst_persistence([table])] == ["", "C:\\x.exe"]


def test_each_extra_cell_goes_under_its_own_heading() -> None:
    table = _merged(
        "persistence",
        (["Type", "Value"], [["registry_run", "HKCU\\Run\\x"]]),
        (["Type", "Value", "Notes"], [["service", "svc", "note-1"]]),
        (["Type", "Value", "Comment"], [["task", "Updater", "comment-1"]]),
    )

    assert table.columns == [
        "Listed by",
        "Evidence",
        "Type",
        "Value",
        "Payload",
        "Notes",
        "Comment",
    ]
    by_heading = [dict(zip(table.columns, row, strict=False)) for row in table.rows]
    assert by_heading[1]["Notes"] == "note-1"
    assert by_heading[2]["Comment"] == "comment-1"
    assert by_heading[2].get("Notes", "") == ""
    assert [r["payload"] for r in analyst_persistence([table])] == ["", "", ""]


def test_a_named_payload_stays_where_a_reader_takes_it() -> None:
    # The third artifact names its payload "Command": it stays in the payload
    # slot, never under a column of its own, and every row is read as dev read it.
    table = _merged(
        "persistence",
        (["Type", "Value"], [["registry_run", "k"]]),
        (["Type", "Value", "Notes"], [["service", "s", "note-1"]]),
        (["Type", "Value", "Command"], [["scheduled_task", "t", "cmd.exe"]]),
    )

    assert [(r["kind"], r["target"], r["payload"]) for r in analyst_persistence([table])] == [
        ("registry_run", "k", ""),
        ("service", "s", ""),
        ("scheduled_task", "t", "cmd.exe"),
    ]
    named = listed_columns(listed_headings(table))
    assert [listed_cells([c.strip() for c in row], named) for _, _, row in listed_rows(table)] == [
        ["registry_run", "k", ""],
        ["service", "s", ""],
        ["scheduled_task", "t", "cmd.exe"],
    ]
    assert _wide(table) == []


def test_a_heading_that_would_change_how_the_table_is_read_is_positional() -> None:
    table = _merged(
        "persistence",
        (["Category", "Target"], [["service", "svc"]]),
        (["Type", "Kind", "Value", "Payload"], [["service", "extra-kind", "evil", "c:\\e.exe"]]),
    )

    before = listed_columns(["Category", "Target"])
    assert listed_columns(listed_headings(table))[:2] == before[:2]
    assert _wide(table) == []
    assert all(not str(c).lower() == "type" for c in table.columns)


def test_a_row_wider_than_its_own_artifact_s_columns_is_headed_by_position() -> None:
    table = _merged(
        "endpoints",
        (["Value"], [["url", "https://example.invalid/live/"]]),
        (["Value"], [["domain", "example.invalid"]]),
    )

    assert table.columns == ["Listed by", "Evidence", "Value", "Column 4"]
    assert _wide(table) == []


def test_a_stored_table_wider_than_its_columns_draws_every_cell() -> None:
    stored = EvidenceSection(
        key="artifact_imports",
        title="Imports",
        kind="table",
        columns=["Listed by", "Evidence", "Library"],
        rows=[
            ["dynamic", "ev_0004", "KERNEL32.dll"],
            ["dynamic", "ev_0019", "kernel32.dll", "VirtualAllocEx"],
        ],
        source="artifact:dynamic",
    )

    markdown = MarkdownRenderer().render(_report(stored))
    html = HtmlRenderer().render(_report(stored))

    assert "| Listed by | Evidence | Library | Column 4 |" in markdown
    assert "| dynamic | ev_0019 | kernel32.dll | VirtualAllocEx |" in markdown
    assert "<td>VirtualAllocEx</td>" in html
    assert "<th>Column 4</th>" in html


def test_an_empty_cell_never_takes_the_slot_a_named_cell_holds() -> None:
    columns = ["Listed by", "Evidence", "Type", "Value", "Payload", "Column 6"]
    row = ["a1", "ev_1", "svc", "s", "", "note", ""]

    laid, added = _in_the_union(columns, row, 4, ["", "Notes", ""])

    assert "note" in laid
    assert Counter(c for c in laid if c) == Counter(c for c in row if c)
    assert len(laid) <= len(columns) + len(added)


def test_a_named_cell_after_unnamed_ones_is_kept_in_a_merge() -> None:
    table = _merged(
        "persistence",
        (["Type", "Value"], [["run", "k", "p", "q"]]),
        (["Type", "Value", "Notes"], [["svc", "s", "note1", "", ""]]),
    )

    by_heading = [dict(zip(table.columns, row, strict=False)) for row in table.rows]
    assert "note1" in table.rows[1]
    assert any(cell == "note1" and heading for heading, cell in by_heading[1].items())
    assert _wide(table) == []
    assert [r["payload"] for r in analyst_persistence([table])] == ["p", ""]


_HEADINGS = ["Type", "Value", "Payload", "Kind", "Target", "Command", "Notes", "Name", "Data"]
_HEADINGS += ["Indicator", "Path", "Comment", "Value", "", ""]
_CELLS = ["run", "service", "scheduled_task", "mutex", "path", "registry", "x", "C:\\a.exe"]
_CELLS += ["HKCU\\R", "", "n1", "cmd /c"]


def test_no_merge_loses_a_cell_or_leaves_one_headless() -> None:
    draw = random.Random(7)
    for _ in range(300):
        kind = draw.choice(["persistence", "iocs"])
        listed = []
        for _ in range(draw.randint(2, 3)):
            columns = draw.sample(_HEADINGS, draw.randint(1, 4))
            rows = {
                tuple(draw.choice(_CELLS) for _ in range(draw.randint(1, len(columns) + 2)))
                for _ in range(draw.randint(1, 2))
            }
            listed.append((columns, [list(row) for row in sorted(rows)]))
        table = _merged(kind, *listed)

        given = Counter(cell for _, rows in listed for row in rows for cell in row if cell)
        drawn = Counter(cell for row in table.rows for cell in row[2:] if cell)
        assert drawn == given, listed
        assert _wide(table) == [], listed

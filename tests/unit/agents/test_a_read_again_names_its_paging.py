"""A row the platform shortened, read again, names ``read_evidence``'s own paging (T-420).

The line under the read said "this tool takes no argument that pages it" while
the tool pages with ``offset`` and ``limit``: no narrowing is stored for a ledger
row, so both reads passed none. The names are read off the tool's own schema.
"""

from __future__ import annotations

from maljan.agents.evidence_recorder import EvidenceRecorder, record_tools
from maljan.agents.ledger_reads import LedgerReads
from maljan.agents.tool_answer_clearing import read_evidence_narrowing, read_evidence_tool
from maljan.schemas.answer_completeness import COMPLETENESS_PREFIX
from maljan.schemas.evidence import LedgerEntry

ROW = LedgerEntry(
    id="ev_0007",
    agent="network",
    tool="decode",
    output="decoded routine " * 40,
    truncated=True,
    chars_dropped=1200,
)


def _line(handed: str) -> str:
    lines = [x for x in handed.splitlines() if x.startswith(COMPLETENESS_PREFIX)]
    assert len(lines) == 1, handed
    return lines[0]


def test_the_names_come_from_the_tool_s_schema() -> None:
    assert read_evidence_narrowing() == ("offset", "limit")


def test_a_ledger_read_names_offset_and_limit() -> None:
    line = _line(LedgerReads([ROW]).read({"evidence_id": "ev_0007"}))
    assert "read further with `offset`, `limit`" in line
    assert "no argument that pages" not in line


def test_a_page_of_the_row_is_unchanged() -> None:
    said = LedgerReads([ROW]).read({"evidence_id": "ev_0007", "offset": 0, "limit": 20})
    assert "no argument that pages" not in said
    assert "`offset`, `limit`" not in said


def test_an_analyst_reading_an_outside_entry_names_offset_and_limit() -> None:
    recorder = EvidenceRecorder("mediator")
    recorder.outside = LedgerReads([ROW])
    (reader,) = record_tools([read_evidence_tool(lambda _id: None)], recorder)
    line = _line(str(reader.invoke({"evidence_id": "ev_0007"})))
    assert "read further with `offset`, `limit`" in line

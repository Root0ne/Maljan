"""A stored line carries a publisher number only if its run was numbered.

``agent_messages.seq`` used to be the message's position within the report —
``0, 1, 2, …`` — and is now the number the publisher gave the message when it
went out. The two are different numbers for the same run, so a client keying a
stored row on the old one would fail to collapse it onto its live twin and
draw the line twice, which is exactly the duplicate the derived id existed to
prevent.

The rows say which world they belong to on their own: the publisher counts the
whole run's events from 1, so a numbered conversation's largest ``seq`` is at
least its row count, while the old ``enumerate`` numbering's is exactly one
less. Reading it off the feed instead would have been the same answer only
until the retention sweep deleted it.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest

from app.api.v1.reports import _detail
from app.schemas.job import ReportDetailResponse


class _Row:
    def __init__(self, seq: int, text: str) -> None:
        self.seq = seq
        self.speaker = "static"
        self.role = "analyst"
        self.round = 0
        self.status = "complete"
        self.text = text
        self.report = None
        self.report_truncated = False
        self.confidence = None
        self.claims = []
        self.dissent = []
        self.addressed_to = None
        self.ts = None


class _Report:
    def __init__(self, rows: list[_Row]) -> None:
        self.id = uuid.uuid4()
        self.job_id = uuid.uuid4()
        self.verdict = "Malware"
        self.overall_confidence = 0.9
        self.malware_category = None
        self.stix_bundle = None
        self.mitre_techniques = None
        self.agent_reports = None
        self.negotiation_log = None
        self.run_summary = None
        self.malware_report = None
        self.agent_findings = []
        self.transcript = rows
        self.created_at = datetime.now(UTC)


class _Service:
    """The service is not consulted at all; the rows answer for themselves."""


def _legacy() -> list[_Row]:
    """The old numbering: ``enumerate(transcript)``, from zero."""
    return [_Row(0, "one"), _Row(1, "two"), _Row(2, "three")]


def _numbered() -> list[_Row]:
    """The publisher's numbering: from one, and sparse."""
    return [_Row(4, "one"), _Row(9, "two"), _Row(31, "three")]


@pytest.mark.asyncio
async def test_a_numbered_run_keeps_its_numbers() -> None:
    detail = await _detail(_Service(), _Report(_numbered()))
    assert [m.seq for m in detail.transcript] == [4, 9, 31]


@pytest.mark.asyncio
async def test_a_legacy_run_sends_no_numbers_at_all() -> None:
    """Every row, not only the first.

    The old column started at 0, so a check that treated only 0 as "no
    number" left rows 1..n looking like publisher numbers — which is the
    defect this exists for.
    """
    detail = await _detail(_Service(), _Report(_legacy()))
    assert [m.seq for m in detail.transcript] == [None, None, None]


@pytest.mark.asyncio
async def test_a_numbered_run_with_no_gaps_is_still_numbered() -> None:
    # The tightest a publisher-numbered run can be: 1..n, so the largest is
    # exactly the row count. The legacy shape is one less.
    detail = await _detail(_Service(), _Report([_Row(1, "one"), _Row(2, "two")]))
    assert [m.seq for m in detail.transcript] == [1, 2]


@pytest.mark.asyncio
async def test_a_one_line_run_is_told_apart_either_way() -> None:
    numbered = await _detail(_Service(), _Report([_Row(1, "only")]))
    legacy = await _detail(_Service(), _Report([_Row(0, "only")]))
    assert [m.seq for m in numbered.transcript] == [1]
    assert [m.seq for m in legacy.transcript] == [None]


@pytest.mark.asyncio
async def test_a_partly_stamped_run_is_numbered() -> None:
    # A line that missed its stamp carries 0 (see the worker's rule); the run
    # is still a numbered one and the stamped lines keep their identity.
    detail = await _detail(_Service(), _Report([_Row(1, "one"), _Row(0, "two"), _Row(7, "three")]))
    assert [m.seq for m in detail.transcript] == [1, 0, 7]


@pytest.mark.asyncio
async def test_an_empty_transcript_is_left_alone() -> None:
    detail = await _detail(_Service(), _Report([]))
    assert detail.transcript == []


@pytest.mark.asyncio
async def test_the_answer_outlives_the_feed_it_used_to_be_read_from() -> None:
    """The retention sweep must not silently un-number every finished run.

    The signal used to be "this job has a ``job_events`` row", which
    ``purge_old_job_events`` deletes after ``core.events.retention_days``.
    Nothing here consults the feed, so a report read on day 31 answers the
    same as one read on day 1.
    """
    import ast
    import inspect

    from app.api.v1 import reports

    # The code, without the docstrings — which say why the query went.
    code = ""
    for name in ("_is_numbered", "_detail"):
        tree = ast.parse(inspect.getsource(getattr(reports, name)))
        function = tree.body[0]
        body = function.body[1:] if ast.get_docstring(function) else function.body
        code += "\n".join(ast.unparse(node) for node in body)

    assert "job_events" not in code
    assert "JobEvent" not in code
    assert "transcript_is_numbered" not in code
    # And no round trip of any kind to decide it.
    assert not inspect.iscoroutinefunction(reports._is_numbered)
    assert "await" not in code


@pytest.mark.asyncio
async def test_the_numbers_go_out_as_null_on_the_wire() -> None:
    detail = await _detail(_Service(), _Report(_legacy()))
    assert all(line["seq"] is None for line in detail.model_dump()["transcript"])


@pytest.mark.asyncio
async def test_nothing_else_about_the_report_changes() -> None:
    report = _Report(_legacy())
    detail = await _detail(_Service(), report)
    assert detail.verdict == "Malware"
    assert [m.text for m in detail.transcript] == ["one", "two", "three"]
    assert detail.job_id == report.job_id


@pytest.mark.asyncio
async def test_the_schema_accepts_a_line_with_no_number() -> None:
    line = ReportDetailResponse.model_validate(_Report(_legacy())).transcript[0]
    assert line.model_copy(update={"seq": None}).seq is None


class TestTheStoredNumber:
    """What the worker writes into ``agent_messages.seq``.

    Read off the worker's source rather than by driving a run, which needs a
    queue and a database: the rule is one expression and what matters is that
    it cannot hand two messages the same number.
    """

    @staticmethod
    def _stored(transcript: list[dict[str, Any]]) -> list[int]:
        """The rule as the worker writes it, applied to one recording."""
        numbered = any(int(m.get("seq") or 0) > 0 for m in transcript)
        return [
            int(m.get("seq") or 0) or (0 if numbered else index)
            for index, m in enumerate(transcript)
        ]

    def test_the_expression_under_test_is_the_one_the_worker_uses(self) -> None:
        import inspect

        from app.worker import analysis_worker

        source = inspect.getsource(analysis_worker._store_the_report)
        assert '_numbered = any(int(m.get("seq") or 0) > 0 for m in transcript)' in source
        assert "seq=_stamped or (0 if _numbered else index)," in source

    def test_a_numbered_run_stores_the_publisher_s_numbers(self) -> None:
        assert self._stored([{"seq": 3}, {"seq": 7}, {"seq": 11}]) == [3, 7, 11]

    def test_a_run_the_publisher_never_reached_keeps_its_recorded_order(self) -> None:
        assert self._stored([{}, {}, {}]) == [0, 1, 2]

    def test_a_line_that_missed_its_stamp_borrows_nobody_s_number(self) -> None:
        """The collision the fallback used to make.

        The position and the publisher's count share the low integers, so a
        line that missed its stamp in an otherwise-numbered run took a number
        another line already owned and the console drew the two as one. It
        gets 0 instead, which is outside the publisher's range and which every
        reader already treats as "no number".
        """
        stored = self._stored([{"seq": 1}, {}, {"seq": 3}])
        assert stored == [1, 0, 3]
        assert len(set(stored)) == len(stored)

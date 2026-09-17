"""A stored line carries a publisher number only if its run was numbered.

``agent_messages.seq`` used to be the message's position within the report —
``0, 1, 2, …`` — and is now the number the publisher gave the message when it
went out. The two are different numbers for the same run, so a client keying a
stored row on the old one would fail to collapse it onto its live twin and
draw the line twice, which is exactly the duplicate the derived id existed to
prevent.

A run cannot be asked which world it belongs to, so its feed is asked instead:
a run published under this release has ``job_events`` rows and a run recorded
before it has none.
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
    """A report service whose only interesting answer is the feed check."""

    def __init__(self, numbered: bool) -> None:
        self.numbered = numbered
        self.asked: list[uuid.UUID] = []

    async def transcript_is_numbered(self, job_id: uuid.UUID) -> bool:
        self.asked.append(job_id)
        return self.numbered


def _rows() -> list[_Row]:
    return [_Row(0, "one"), _Row(1, "two"), _Row(2, "three")]


@pytest.mark.asyncio
async def test_a_run_with_a_feed_keeps_its_numbers() -> None:
    svc = _Service(numbered=True)
    report = _Report([_Row(4, "one"), _Row(9, "two")])
    detail = await _detail(svc, report)
    assert [m.seq for m in detail.transcript] == [4, 9]
    assert svc.asked == [report.job_id]


@pytest.mark.asyncio
async def test_a_run_with_no_feed_sends_no_numbers_at_all() -> None:
    """Every row, not only the first.

    The old column started at 0, so a check that treated only 0 as "no
    number" left rows 1..n looking like publisher numbers — which is the
    defect this exists for.
    """
    svc = _Service(numbered=False)
    detail = await _detail(svc, _Report(_rows()))
    assert [m.seq for m in detail.transcript] == [None, None, None]


@pytest.mark.asyncio
async def test_the_numbers_go_out_as_null_on_the_wire() -> None:
    detail = await _detail(_Service(numbered=False), _Report(_rows()))
    assert all(line["seq"] is None for line in detail.model_dump()["transcript"])


@pytest.mark.asyncio
async def test_nothing_else_about_the_report_changes() -> None:
    report = _Report(_rows())
    detail = await _detail(_Service(numbered=False), report)
    assert detail.verdict == "Malware"
    assert [m.text for m in detail.transcript] == ["one", "two", "three"]
    assert detail.job_id == report.job_id


@pytest.mark.asyncio
async def test_an_empty_transcript_does_not_ask_about_a_feed() -> None:
    svc = _Service(numbered=False)
    await _detail(svc, _Report([]))
    assert svc.asked == []


@pytest.mark.asyncio
async def test_the_schema_accepts_a_line_with_no_number() -> None:
    line = ReportDetailResponse.model_validate(_Report(_rows())).transcript[0]
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

        source = inspect.getsource(analysis_worker.run_analysis)
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


class TestTheFeedCheck:
    """``transcript_is_numbered`` itself: one existence query, never raising."""

    class _Result:
        def __init__(self, value: Any) -> None:
            self._value = value

        def scalar_one_or_none(self) -> Any:
            return self._value

    class _Db:
        def __init__(self, value: Any = None, raises: bool = False) -> None:
            self.value = value
            self.raises = raises
            self.statements: list[Any] = []

        async def execute(self, statement: Any) -> Any:
            self.statements.append(statement)
            if self.raises:
                raise RuntimeError("relation does not exist")
            return TestTheFeedCheck._Result(self.value)

    def _service(self, db: Any) -> Any:
        from app.services.report_service import ReportService

        return ReportService(db)

    @pytest.mark.asyncio
    async def test_a_job_with_a_feed_row_is_numbered(self) -> None:
        db = self._Db(value=uuid.uuid4())
        assert await self._service(db).transcript_is_numbered(uuid.uuid4()) is True

    @pytest.mark.asyncio
    async def test_a_job_with_no_feed_row_is_not(self) -> None:
        service = self._service(self._Db(value=None))
        assert await service.transcript_is_numbered(uuid.uuid4()) is False

    @pytest.mark.asyncio
    async def test_the_query_asks_for_one_row_only(self) -> None:
        db = self._Db(value=None)
        await self._service(db).transcript_is_numbered(uuid.uuid4())
        assert "LIMIT" in str(db.statements[0]).upper()

    @pytest.mark.asyncio
    async def test_a_database_that_refuses_the_check_costs_the_numbers_not_the_report(
        self,
    ) -> None:
        assert (
            await self._service(self._Db(raises=True)).transcript_is_numbered(uuid.uuid4())
        ) is False

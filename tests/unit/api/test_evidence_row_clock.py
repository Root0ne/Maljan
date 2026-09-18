"""A ledger row is stamped when its call returned, not when the batch was written.

Thirty entries of one run all carried the same ``created_at`` — the flush — so
the ledger sorted by it told a reader nothing about when anything happened. The
entry already knows: ``started_at`` is the call's own clock and ``duration_ms``
is how long it took, so the moment it returned is the sum, and that is what the
row is stamped with. A row whose entry was never stamped keeps the write time,
because inventing one would be worse than admitting it is not known.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from app.worker.analysis_worker import _evidence_row


def _entry(**over: object) -> dict[str, object]:
    base: dict[str, object] = {
        "id": "ev_0001",
        "stage": "analysis",
        "agent": "static",
        "tool": "strings",
        "ok": True,
        "duration_ms": 1500,
        "seq": 1,
        "output": "MZ",
    }
    base.update(over)
    return base


class TestWhenTheRowSaysItHappened:
    def test_the_stamp_is_the_moment_the_call_returned(self) -> None:
        started = datetime(2026, 9, 18, 10, 0, 0, tzinfo=UTC)
        row = _evidence_row(
            _entry(started_at=started.timestamp(), duration_ms=2_000), job_id=uuid.uuid4()
        )
        assert row.created_at == datetime(2026, 9, 18, 10, 0, 2, tzinfo=UTC)
        # The two fields it was derived from survive unchanged.
        assert row.started_at == started.timestamp()
        assert row.duration_ms == 2_000

    def test_two_calls_a_minute_apart_are_a_minute_apart_in_the_table(self) -> None:
        """What the flush time could not say: which call came first, and when."""
        first = datetime(2026, 9, 18, 10, 0, 0, tzinfo=UTC).timestamp()
        second = first + 60
        rows = [
            _evidence_row(_entry(started_at=first, duration_ms=0, seq=1), job_id=uuid.uuid4()),
            _evidence_row(_entry(started_at=second, duration_ms=0, seq=2), job_id=uuid.uuid4()),
        ]
        assert (rows[1].created_at - rows[0].created_at).total_seconds() == 60

    def test_an_unstamped_entry_keeps_the_write_time(self) -> None:
        """``started_at`` is absent on an entry the recorder never stamped."""
        row = _evidence_row(_entry(), job_id=uuid.uuid4())
        assert row.created_at is None, "the column's server default writes it"
        assert row.started_at is None

    def test_a_missing_duration_is_read_as_no_time_at_all(self) -> None:
        started = datetime(2026, 9, 18, 10, 0, 0, tzinfo=UTC)
        row = _evidence_row(
            _entry(started_at=started.timestamp(), duration_ms=0), job_id=uuid.uuid4()
        )
        assert row.created_at == started

    def test_a_clock_that_makes_no_sense_leaves_the_stamp_to_the_database(self) -> None:
        """A negative or absurd timestamp is not a fact about anything."""
        row = _evidence_row(_entry(started_at=-1.0), job_id=uuid.uuid4())
        assert row.created_at is None

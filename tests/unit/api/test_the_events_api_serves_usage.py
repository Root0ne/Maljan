"""The events API returns a job's per-call usage while its live stream exists, and totals it.

``model_usage`` events go to ``job_events`` alone: the live socket and the
1,000-entry replay stream are left to the events a reader follows. The events
endpoint reads the stream first, so while the stream lived it answered without
them and what the run spent was readable only a day later. The endpoint now
merges the table's usage events into the stream's page, in ``seq`` order and
once each; the socket's resume still never carries them. ``GET
/jobs/{id}/usage`` totals them with the run summary's own code, so cost is
readable during a run and after a worker that died before its summary.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest

from app.services.job_events import read_events
from maljan.analysis.run_summary import spend_blocks, usage_totals
from maljan.core.spend import SpendMeter
from maljan.core.token_ledger import TokenLedger
from maljan.llm.transient import FAILED_ATTEMPT_CALL
from maljan.pipeline.events import MODEL_USAGE

PRICES = {
    "m1": {
        "input_usd_per_mtok": 1.0,
        "output_usd_per_mtok": 4.0,
        "cached_input_usd_per_mtok": 0.1,
        "cache_write_input_usd_per_mtok": 1.25,
        "cache_write_1h_input_usd_per_mtok": 2.0,
    },
    "m2": {
        "input_usd_per_mtok": 0.5,
        "output_usd_per_mtok": 1.5,
        "windows": [
            {
                "utc_from": "16:30",
                "utc_to": "00:30",
                "input_usd_per_mtok": 0.25,
                "output_usd_per_mtok": 0.75,
            }
        ],
    },
}


class _Redis:
    def __init__(self, stream: list[dict[str, Any]]) -> None:
        self.stream = [(f"{i + 1}-0", {"payload": json.dumps(e)}) for i, e in enumerate(stream)]

    async def xrange(self, key: str, min: str, max: str, count: int) -> list[Any]:
        return self.stream[:count]


class _Row:
    def __init__(self, seq: int, event_type: str, payload: dict[str, Any] | None = None) -> None:
        self.seq = seq
        self.type = event_type
        self.payload = {**(payload or {}), "seq": seq}
        self.ts = None


class _Result:
    def __init__(self, rows: list[_Row]) -> None:
        self._rows = rows

    def scalars(self) -> _Result:
        return self

    def all(self) -> list[_Row]:
        return self._rows


class _Table:
    """A ``job_events`` stand-in that answers the reader's queries by their conditions.

    The type condition (``=`` or ``!=``), the ``seq`` floor and the ``LIMIT``
    are read off the compiled statement, so a query that asks for the wrong
    rows gets the wrong rows here too.
    """

    def __init__(self, rows: list[_Row]) -> None:
        self.rows = rows
        self.statements: list[str] = []

    async def execute(self, statement: Any) -> _Result:
        compiled = statement.compile()
        sql = str(compiled)
        params = compiled.params
        self.statements.append(sql)
        rows = sorted(self.rows, key=lambda r: r.seq)
        for name, value in params.items():
            if name.startswith("type_"):
                if f"job_events.type = :{name}" in sql:
                    rows = [r for r in rows if r.type == value]
                elif f"job_events.type != :{name}" in sql:
                    rows = [r for r in rows if r.type != value]
                else:
                    raise AssertionError(f"unread type condition in {sql}")
            elif name.startswith("seq_"):
                rows = [r for r in rows if r.seq > value]
            elif name.startswith("param_"):
                rows = rows[:value]
        return _Result(rows)


def _event(seq: int, event_type: str = "agent_message") -> dict[str, Any]:
    return {"type": event_type, "data": {"seq": seq}, "ts": "2026-09-25T00:00:00+00:00"}


def _seqs(events: list[dict[str, Any]]) -> list[int]:
    return [int(e["data"]["seq"]) for e in events]


def _types(events: list[dict[str, Any]]) -> list[str]:
    return [str(e["type"]) for e in events]


def _usage_row(seq: int, **figures: Any) -> _Row:
    return _Row(
        seq,
        MODEL_USAGE,
        {"agent": "static", "model": "m1", "call": "tool loop turn", "reported": True, **figures},
    )


class TestTheStreamPageCarriesUsage:
    """Stream alive, usage in the table: the page holds both, ordered, once each."""

    def _stores(self) -> tuple[_Redis, _Table]:
        # The stream holds the progress events; ``seq`` 3 and 6 are usage and
        # live in the table alone. The table also holds 1 and 2 (written by an
        # earlier batch), which the stream holds too.
        redis_conn = _Redis([_event(1), _event(2), _event(4), _event(5), _event(7)])
        table = _Table(
            [
                _Row(1, "agent_message"),
                _Row(2, "agent_message"),
                _usage_row(3, input_tokens=10, output_tokens=2),
                _usage_row(6, input_tokens=20, output_tokens=4),
            ]
        )
        return redis_conn, table

    def test_the_whole_feed_holds_both_in_sequence_order(self) -> None:
        redis_conn, table = self._stores()
        events = asyncio.run(read_events(table, redis_conn, uuid.uuid4(), usage=True))
        assert _seqs(events) == [1, 2, 3, 4, 5, 6, 7]
        assert _types(events) == [
            "agent_message",
            "agent_message",
            MODEL_USAGE,
            "agent_message",
            "agent_message",
            MODEL_USAGE,
            "agent_message",
        ]

    def test_an_event_both_stores_hold_is_returned_once(self) -> None:
        redis_conn = _Redis([_event(1), _event(2), _event(3, MODEL_USAGE)])
        table = _Table([_usage_row(3, input_tokens=1, output_tokens=1)])
        events = asyncio.run(read_events(table, redis_conn, uuid.uuid4(), usage=True))
        assert _seqs(events) == [1, 2, 3]

    def test_the_cursor_applies_to_usage_too(self) -> None:
        redis_conn, table = self._stores()
        events = asyncio.run(read_events(table, redis_conn, uuid.uuid4(), since=3, usage=True))
        assert _seqs(events) == [4, 5, 6, 7]

    def test_pages_walk_the_merged_feed_without_a_gap_or_a_repeat(self) -> None:
        redis_conn, table = self._stores()
        seen: list[int] = []
        cursor: int | None = None
        for _ in range(10):
            page = asyncio.run(
                read_events(table, redis_conn, uuid.uuid4(), since=cursor, limit=2, usage=True)
            )
            if not page:
                break
            assert len(page) <= 2
            seen += _seqs(page)
            cursor = max(_seqs(page))
        assert seen == [1, 2, 3, 4, 5, 6, 7]

    def test_a_full_stream_page_takes_no_usage_beyond_its_last_event(self) -> None:
        """A usage event past a full page waits for the next page.

        Otherwise the page would end at the usage event's ``seq`` and the
        stream events between the page's last one and it would fall behind
        the client's next cursor.
        """
        redis_conn = _Redis([_event(1), _event(2), _event(4)])
        table = _Table([_usage_row(3), _usage_row(9)])
        page = asyncio.run(read_events(table, redis_conn, uuid.uuid4(), limit=2, usage=True))
        assert _seqs(page) == [1, 2]
        page = asyncio.run(read_events(table, redis_conn, uuid.uuid4(), since=2, usage=True))
        assert _seqs(page) == [3, 4]
        # Past the stream's last event the stream has nothing newer, and the
        # table, which holds every type, answers the rest.
        page = asyncio.run(read_events(table, redis_conn, uuid.uuid4(), since=4, usage=True))
        assert _seqs(page) == [9]

    def test_a_short_page_takes_no_usage_beyond_its_last_event_either(self) -> None:
        """A progress event can reach the stream after a usage event with a higher ``seq``.

        The publisher takes the number first; a usage event is committed to
        the table by its own flush while the progress event before it is still
        on its way to the stream. A page read in between holds 1..9 from the
        stream and usage 11 from the table: ending the page at 11 would put
        the client's cursor past 10 for good.
        """
        redis_conn = _Redis([_event(seq) for seq in range(1, 10)])
        table = _Table([_Row(seq, "agent_message") for seq in range(1, 10)] + [_usage_row(11)])
        page = asyncio.run(read_events(table, redis_conn, uuid.uuid4(), usage=True))
        assert _seqs(page) == list(range(1, 10))
        # Progress event 10 reaches the stream and the table.
        redis_conn = _Redis([_event(seq) for seq in range(1, 11)])
        table.rows.append(_Row(10, "agent_message"))
        page = asyncio.run(read_events(table, redis_conn, uuid.uuid4(), since=9, usage=True))
        assert _seqs(page) == [10]
        page = asyncio.run(read_events(table, redis_conn, uuid.uuid4(), since=10, usage=True))
        assert _seqs(page) == [11]

    def test_a_resume_inside_a_stream_longer_than_one_read_loses_nothing(self) -> None:
        """The stream is trimmed approximately, so it holds more entries than one read takes.

        ``maxlen=1000, approximate=True`` leaves roughly a thousand to eleven
        hundred entries, and one read takes the oldest thousand. A resume
        inside them gets a short page although newer stream entries exist;
        the walk must still return every event once.
        """
        usage_seqs = set(range(10, 1201, 10))
        progress = [seq for seq in range(1, 1201) if seq not in usage_seqs]
        redis_conn = _Redis([_event(seq) for seq in progress[-1080:]])
        table = _Table(
            [
                _usage_row(seq) if seq in usage_seqs else _Row(seq, "agent_message")
                for seq in range(1, 1201)
            ]
        )
        seen: list[int] = []
        cursor = 600
        for _ in range(20):
            page = asyncio.run(
                read_events(table, redis_conn, uuid.uuid4(), since=cursor, limit=500, usage=True)
            )
            if not page:
                break
            seen += _seqs(page)
            cursor = max(_seqs(page))
        assert seen == list(range(601, 1201))

    def test_a_reader_that_filters_by_type_finds_only_progress_in_the_rest(self) -> None:
        redis_conn, table = self._stores()
        events = asyncio.run(read_events(table, redis_conn, uuid.uuid4(), usage=True))
        progress = [e for e in events if e["type"] != MODEL_USAGE]
        assert _seqs(progress) == [1, 2, 4, 5, 7]
        usage = [e for e in events if e["type"] == MODEL_USAGE]
        assert [e["data"]["input_tokens"] for e in usage] == [10, 20]


class TestTheSocketResumeStaysWithoutUsage:
    def test_the_stream_answer_carries_no_usage_and_asks_no_table(self) -> None:
        redis_conn = _Redis([_event(1), _event(2), _event(4)])
        table = _Table([_usage_row(3)])
        events = asyncio.run(read_events(table, redis_conn, uuid.uuid4()))
        assert _seqs(events) == [1, 2, 4]
        assert table.statements == []

    def test_the_table_answer_carries_no_usage_either(self) -> None:
        # The stream has expired; the table answers the resume.
        redis_conn = _Redis([])
        table = _Table([_Row(1, "agent_message"), _usage_row(2), _Row(3, "agent_message")])
        events = asyncio.run(read_events(table, redis_conn, uuid.uuid4()))
        assert _seqs(events) == [1, 3]
        assert MODEL_USAGE not in _types(events)

    def test_the_socket_reads_without_usage(self) -> None:
        import inspect

        from app.api import ws

        source = inspect.getsource(ws)
        assert "usage=True" not in source


class TestAnExpiredStreamIsUnchanged:
    def test_the_table_answers_every_event_as_before(self) -> None:
        redis_conn = _Redis([])
        table = _Table([_Row(1, "agent_message"), _usage_row(2), _Row(3, "agent_message")])
        events = asyncio.run(read_events(table, redis_conn, uuid.uuid4(), usage=True))
        assert _seqs(events) == [1, 2, 3]
        assert _types(events) == ["agent_message", MODEL_USAGE, "agent_message"]
        assert len(table.statements) == 1


CHARGE_PARTS = ("priced_usd", "price_source", "estimated_usd")


def _synthetic_job() -> tuple[TokenLedger, SpendMeter, list[dict[str, Any]]]:
    """A completed job's ledger and the ``model_usage`` payloads its calls published.

    Two models, cache reads, hour-long cache writes, a price window, a
    provider-reported cost, an unreported call, a call charged by stated
    estimate, an unpriced model, a retry and two failed attempts (one with the
    usage its error reported, one charged by estimate).
    """
    noon = datetime(2026, 9, 25, 12, 0, tzinfo=UTC).timestamp()
    evening = datetime(2026, 9, 25, 18, 0, tzinfo=UTC).timestamp()
    meter = SpendMeter(5.0, PRICES)
    ledger = TokenLedger(spend=meter)
    published: list[dict[str, Any]] = []
    ledger.on_call = lambda row: published.append({**row, "seq": len(published) + 1})
    ledger.add(
        {
            "input_tokens": 12_000,
            "output_tokens": 800,
            "cached_input_tokens": 9_000,
            "cache_write_input_tokens": 2_000,
            "cache_write_1h_input_tokens": 2_000,
            "sent_at": noon,
        },
        agent="static",
        model="m1",
        call="tool loop turn",
    )
    ledger.add_retry(agent="static", model="m2", reason="HTTP 529")
    ledger.charge_failed_attempt(
        {"input_tokens": 4_000, "output_tokens": 40},
        agent="static",
        model="m2",
        call=FAILED_ATTEMPT_CALL,
    )
    ledger.add(
        {"input_tokens": 4_000, "output_tokens": 300, "reasoning_tokens": 120, "sent_at": evening},
        agent="static",
        model="m2",
        call="tool loop turn",
    )
    ledger.charge_failed_attempt(
        None,
        agent="judge",
        model="m1",
        call=FAILED_ATTEMPT_CALL,
        estimated={"input_tokens": 2_000, "output_tokens": 30, "source": "estimated"},
    )
    ledger.add(
        {"input_tokens": 3_000, "output_tokens": 900, "cost": 0.0123},
        agent="judge",
        model="m1",
        call="verdict",
    )
    ledger.add(None, agent="judge", model="m1", call="verdict")
    ledger.add(
        None,
        agent="judge",
        model="m1",
        call="verdict",
        estimated={"input_tokens": 1_000, "output_tokens": 200, "source": "estimated"},
    )
    ledger.add({"input_tokens": 500, "output_tokens": 50}, agent="reporter", model="unpriced-x")
    return ledger, meter, published


class TestEachRecordCarriesItsCharge:
    def test_a_priced_call_carries_what_the_meter_charged(self) -> None:
        _ledger, _meter, published = _synthetic_job()
        first = published[0]
        assert first["priced_usd"] > 0
        assert first["price_source"] == "llm.model_prices"
        assert "estimated_usd" not in first

    def test_a_call_charged_by_estimate_says_so(self) -> None:
        _ledger, _meter, published = _synthetic_job()
        by_estimate = [p for p in published if "estimated" in p]
        assert len(by_estimate) == 2
        assert all(p["estimated_usd"] == p["priced_usd"] > 0 for p in by_estimate)

    def test_an_uncharged_call_carries_no_charge(self) -> None:
        _ledger, _meter, published = _synthetic_job()
        unreported = [p for p in published if p["call"] == "verdict" and not p["reported"]]
        assert not any(part in unreported[0] for part in CHARGE_PARTS)
        unpriced = [p for p in published if p["model"] == "unpriced-x"]
        assert not any(part in unpriced[0] for part in CHARGE_PARTS)


class TestTheTotalsMatchTheRunSummary:
    def test_the_tokens_are_the_run_summary_s_own(self) -> None:
        ledger, _meter, published = _synthetic_job()
        totals = usage_totals(published, lambda: SpendMeter(None, PRICES))
        assert totals["calls"] == 6
        assert totals["retries"] == 1
        assert totals["failed_attempts"] == 2
        assert totals["tokens"] == spend_blocks(ledger.snapshot())["tokens"]

    def test_the_spend_is_what_the_run_s_meter_settled(self) -> None:
        _ledger, meter, published = _synthetic_job()
        totals = usage_totals(published, lambda: SpendMeter(None, PRICES))
        summary_spend = meter.snapshot()
        assert summary_spend is not None
        spend = totals["spend"]
        assert spend["spent_usd"] == summary_spend["spent_usd"]
        assert spend["prices_from"] == summary_spend["prices_from"]
        assert spend["unpriced_models"] == summary_spend["unpriced_models"]
        assert spend["unreported_calls"] == summary_spend["unreported_calls"]
        assert spend["estimated_calls"] == summary_spend["estimated_calls"]
        assert spend["estimated_usd"] == summary_spend["estimated_usd"]
        assert spend["repriced_calls"] == 0
        assert spend["spent_is_at_least"] is True

    def test_prices_changed_after_the_run_leave_the_total_as_the_run_spent(self) -> None:
        _ledger, meter, published = _synthetic_job()
        dearer = {
            name: {**row, "input_usd_per_mtok": 99.0, "output_usd_per_mtok": 99.0}
            for name, row in PRICES.items()
        }
        for prices in ({}, dearer):
            totals = usage_totals(published, lambda prices=prices: SpendMeter(None, prices))
            summary_spend = meter.snapshot()
            assert summary_spend is not None
            assert totals["spend"]["spent_usd"] == summary_spend["spent_usd"]
            assert totals["spend"]["repriced_calls"] == 0

    def test_a_record_without_a_charge_is_repriced_and_counted(self) -> None:
        _ledger, meter, published = _synthetic_job()
        older = [{k: v for k, v in p.items() if k not in CHARGE_PARTS} for p in published]
        totals = usage_totals(older, lambda: SpendMeter(None, PRICES))
        summary_spend = meter.snapshot()
        assert summary_spend is not None
        charged = [p for p in published if "priced_usd" in p]
        assert totals["spend"]["repriced_calls"] == len(charged)
        assert totals["spend"]["repriced_usd"] == pytest.approx(summary_spend["spent_usd"])
        assert totals["spend"]["spent_usd"] == pytest.approx(summary_spend["spent_usd"])

    def test_each_agent_s_spend_adds_up_to_the_job_s(self) -> None:
        _ledger, _meter, published = _synthetic_job()
        totals = usage_totals(published, lambda: SpendMeter(None, PRICES))
        agents = totals["spend"]["per_agent"]
        assert set(agents) == {"static", "judge", "reporter"}
        assert agents["reporter"]["unpriced_models"] == {"unpriced-x": 1}
        assert agents["judge"]["estimated_calls"] == 2
        assert sum(row["spent_usd"] for row in agents.values()) == pytest.approx(
            totals["spend"]["spent_usd"]
        )

    def test_no_call_is_an_empty_total(self) -> None:
        totals = usage_totals([], lambda: SpendMeter(None, PRICES))
        assert totals["calls"] == 0
        assert totals["tokens"] == {}
        assert totals["spend"]["spent_usd"] == 0.0


class _Service:
    def __init__(self, job: Any) -> None:
        self._job = job

    async def get_job(self, job_id: uuid.UUID, user: Any) -> Any:
        return self._job


class TestTheUsageEndpoint:
    @pytest.mark.asyncio
    async def test_a_job_the_caller_does_not_own_is_not_found(self) -> None:
        from fastapi import HTTPException

        from app.api.v1.jobs import get_job_usage

        with pytest.raises(HTTPException) as exc:
            await get_job_usage(
                job_id=uuid.uuid4(), user=object(), svc=_Service(None), db=_Table([])
            )
        assert exc.value.status_code == 404

    @pytest.mark.asyncio
    async def test_the_totals_come_from_the_job_s_usage_events(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.api.v1.jobs import get_job_usage
        from maljan.core.config import Settings

        async def settings_now(db: Any) -> Settings:
            # No price at all now: the recorded charges still give the run's spend.
            return Settings(_env_file=None)

        monkeypatch.setattr("app.services.settings_service.effective_core_settings", settings_now)
        ledger, meter, published = _synthetic_job()
        rows = [_Row(1, "agent_message")]
        rows += [_Row(int(p["seq"]) + 1, MODEL_USAGE, p) for p in published]
        job_id = uuid.uuid4()
        body = await get_job_usage(
            job_id=job_id, user=object(), svc=_Service(object()), db=_Table(rows)
        )
        assert body["job_id"] == str(job_id)
        assert body["calls"] == 6
        assert body["tokens"] == spend_blocks(ledger.snapshot())["tokens"]
        snapshot = meter.snapshot()
        assert snapshot is not None
        assert body["spend"]["spent_usd"] == snapshot["spent_usd"]

    @pytest.mark.asyncio
    async def test_the_events_endpoint_asks_for_usage(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import app.api.v1.jobs as jobs_module

        seen: dict[str, Any] = {}

        async def fake_read(db, redis_conn, job_id, *, since=None, limit=500, usage=False):  # noqa: ANN001
            seen["usage"] = usage
            return []

        class _Conn:
            async def aclose(self) -> None:
                return None

        monkeypatch.setattr("app.services.job_events.read_events", fake_read)
        monkeypatch.setattr("redis.asyncio.from_url", lambda *a, **k: _Conn())
        await jobs_module.get_job_events(
            job_id=uuid.uuid4(),
            limit=10,
            since=None,
            user=object(),
            svc=_Service(object()),
            db=_Table([]),
        )
        assert seen == {"usage": True}

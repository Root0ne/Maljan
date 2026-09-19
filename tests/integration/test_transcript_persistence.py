"""The stored conversation must be the broadcast one.

The transcript exists twice: once as a live feed on the WebSocket, and once as
``agent_messages`` rows read back weeks later. Every previous attempt to keep
those two honest was a *reconstruction* — the frontend rebuilt a conversation
from ``agent_findings`` and ``negotiation_log`` and hoped it resembled what the
live viewer had seen. It could not: those tables hold each agent's final
position and the mediator's rounds, so the per-round replies, the sycophancy
intervention and the revised prose were simply absent from the replay.

The fix was to stop reconstructing. The worker tees every ``agent_message`` as
it publishes it and writes that list down verbatim, which makes parity a
property of the design rather than of two implementations agreeing. These tests
pin that property, because it is the one that silently rots: the day someone
"improves" the recorder by filtering, reordering or enriching a message, the
replay stops being the recording and nothing else would notice.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock

from app.worker.analysis_worker import (
    _evidence_row,
    _make_event_sink,
    _parse_event_ts,
    _transcript_row,
)
from maljan.pipeline.events import AGENT_MESSAGE, emit_agent_message
from tests.credential_shapes import prefixed_key


def _sink_with_recorder() -> tuple[Any, list[dict[str, Any]]]:
    """A sink wired exactly as the worker wires it, minus Redis."""
    recorded: list[dict[str, Any]] = []
    loop = MagicMock()
    # ``call_soon_threadsafe`` is fire-and-forget; the publish half is covered
    # elsewhere and a real loop here would only add flakiness.
    loop.call_soon_threadsafe = MagicMock()
    sink = _make_event_sink(AsyncMock(), "job-1", loop, recorder=recorded)
    return sink, recorded


class TestTheRecorderRecordsWhatIsSent:
    def test_every_agent_message_is_captured_in_order(self) -> None:
        sink, recorded = _sink_with_recorder()

        for i, speaker in enumerate(["static", "dynamic", "Mediator"]):
            emit_agent_message(
                sink,
                speaker=speaker,
                role="analyst" if i < 2 else "negotiator",
                text=f"message {i}",
                round_index=i,
            )

        assert [m["speaker"] for m in recorded] == ["static", "dynamic", "Mediator"]
        assert [m["text"] for m in recorded] == ["message 0", "message 1", "message 2"]
        # Order is the record. ``seq`` is assigned from this list's index, and
        # it is the only thing that can separate two speakers inside one round.
        assert [m["round"] for m in recorded] == [0, 1, 2]

    def test_the_payload_is_kept_field_for_field(self) -> None:
        """No filtering, no renaming, no enrichment — that is the whole point."""
        sink, recorded = _sink_with_recorder()

        emit_agent_message(
            sink,
            speaker="static",
            role="reviser",
            text="headline",
            round_index=2,
            status="complete",
            confidence=0.83,
            claims=[
                {
                    "claim": "Packed section",
                    "evidence_ref": ".text entropy 7.8",
                    "confidence": 0.8,
                    "technique_id": "T1027",
                }
            ],
            dissent=["dynamic claims no injection"],
            report="the rewritten write-up",
        )

        message = recorded[0]
        assert message["speaker"] == "static"
        assert message["role"] == "reviser"
        assert message["round"] == 2
        assert message["status"] == "complete"
        assert message["text"] == "headline"
        assert message["confidence"] == 0.83
        assert message["claims"][0]["technique_id"] == "T1027"
        assert message["dissent"] == ["dynamic claims no injection"]
        assert message["report"] == "the rewritten write-up"

    def test_a_timestamp_is_stamped_and_round_trips(self) -> None:
        sink, recorded = _sink_with_recorder()
        emit_agent_message(sink, speaker="static", role="analyst", text="hi")

        assert _parse_event_ts(recorded[0]["ts"]) is not None

    def test_non_transcript_events_are_not_recorded(self) -> None:
        """``agent_progress`` drives the status header, not the conversation."""
        sink, recorded = _sink_with_recorder()

        sink("agent_progress", {"agent": "static", "phase": "analyzing"})
        sink("phase_change", {"phase": "reporting"})
        sink(AGENT_MESSAGE, {"speaker": "static", "role": "analyst", "text": "hi"})

        assert len(recorded) == 1
        assert recorded[0]["speaker"] == "static"

    def test_recording_survives_a_dead_event_loop(self) -> None:
        """Publishing is best-effort; the permanent record is not.

        The sink appends before it schedules the publish, so a loop that has
        already closed — a cancelled job, a worker shutting down — costs the
        live viewers their last few lines but never costs the database the
        conversation.
        """
        recorded: list[dict[str, Any]] = []
        loop = MagicMock()
        loop.call_soon_threadsafe.side_effect = RuntimeError("event loop is closed")
        sink = _make_event_sink(AsyncMock(), "job-1", loop, recorder=recorded)

        emit_agent_message(sink, speaker="static", role="analyst", text="last words")

        assert [m["text"] for m in recorded] == ["last words"]

    def test_the_recorded_copy_is_scrubbed_where_it_is_taken(self) -> None:
        """Unconditionally, not as a side effect of the publish.

        The copy is appended synchronously on the pipeline's thread and the
        publish is scheduled afterwards, best-effort. Scrubbing it inside the
        publish left the row verbatim on exactly the paths the recorder exists
        for: a loop that has already closed, and a run whose last messages are
        still queued when the transcript is written.
        """
        recorded: list[dict[str, Any]] = []
        loop = MagicMock()
        loop.call_soon_threadsafe.side_effect = RuntimeError("event loop is closed")
        sink = _make_event_sink(AsyncMock(), "job-1", loop, recorder=recorded)
        secret = prefixed_key("key-")

        emit_agent_message(
            sink,
            speaker="static",
            role="analyst",
            text=f"the config held {secret}",
            report="read from /home/operator/maljan/data/samples/ab12/evil.exe",
        )

        (message,) = recorded
        assert secret not in message["text"]
        assert message["text"] == "the config held ***"
        assert "/home/operator" not in message["report"]
        assert message["report"] == "read from evil.exe"
        assert message["speaker"] == "static"

    def test_no_recorder_is_a_supported_configuration(self) -> None:
        """The CLI path passes no recorder and must not crash."""
        loop = MagicMock()
        sink = _make_event_sink(AsyncMock(), "job-1", loop)
        emit_agent_message(sink, speaker="static", role="analyst", text="hi")
        assert loop.call_soon_threadsafe.called


class TestTimestampParsing:
    def test_garbage_becomes_none_rather_than_raising(self) -> None:
        """Ordering comes from ``seq``; an unreadable clock must not drop a row."""
        assert _parse_event_ts("not-a-date") is None
        assert _parse_event_ts(None) is None
        assert _parse_event_ts("") is None
        assert _parse_event_ts(12345) is None


class TestSycophancyReachesTheRecord:
    def test_the_intervention_is_a_recorded_message(self) -> None:
        """It used to be live-only, so a day later a manufactured consensus and
        an earned one were indistinguishable."""
        sink, recorded = _sink_with_recorder()

        emit_agent_message(
            sink,
            speaker="Sycophancy detector",
            role="system",
            text="Agents converged without new evidence — flagged as sycophantic agreement.",
            round_index=3,
        )

        assert recorded[0]["role"] == "system"
        assert "without new evidence" in recorded[0]["text"]


def test_recording_is_synchronous_relative_to_emission() -> None:
    """The append happens on the calling thread, before the publish is queued.

    The analyst node runs in a LangGraph worker thread while the stage nodes run
    on the loop, so a recorder that deferred its append would interleave the two
    and produce a ``seq`` order that never happened.
    """
    sink, recorded = _sink_with_recorder()

    async def main() -> None:
        emit_agent_message(sink, speaker="static", role="analyst", text="first")
        # Nothing has been awaited; the record must already exist.
        assert len(recorded) == 1
        await asyncio.sleep(0)
        emit_agent_message(sink, speaker="dynamic", role="analyst", text="second")
        assert [m["text"] for m in recorded] == ["first", "second"]

    asyncio.run(main())


class TestTheRowKeepsEveryFieldTheRecordingCarried:
    """From the payload to the row, without losing a field on the way.

    The recorder above proves the *copy* is faithful; this proves the row
    built from that copy is. The three fields checked here are the ones the
    table had no column for until ``20260926000000``: a replay that has to
    re-derive the kind of a line draws a delegated ask and its answer as two
    plain lines, and a replay with no stage puts the whole conversation in one
    unnamed stage.
    """

    def _row(self, **kwargs: Any) -> Any:
        sink, recorded = _sink_with_recorder()
        emit_agent_message(sink, **kwargs)
        return _transcript_row(recorded[0], report_id=uuid.uuid4(), seq=7)

    def test_the_kind_the_stage_and_the_label_are_stored(self) -> None:
        row = self._row(
            speaker="static",
            role="analyst",
            text="asking the reverser",
            stage="analysis",
            kind="delegation_ask",
            addressed_to="reverser",
            display_name="Ahmet",
        )

        assert row.kind == "delegation_ask"
        assert row.stage == "analysis"
        assert row.display_name == "Ahmet"
        assert row.addressed_to == "reverser"

    def test_a_line_with_no_stage_and_no_label_stores_neither(self) -> None:
        """Absent is NULL, not a default the publisher never sent."""
        row = self._row(speaker="static", role="analyst", text="plain")

        assert row.stage is None
        assert row.display_name is None
        # ``kind`` is the one the publisher always sends, so it is always
        # stored; what must not happen is a *missing* kind becoming "says".
        assert row.kind == "says"
        assert _transcript_row({}, report_id=uuid.uuid4(), seq=1).kind is None

    def test_every_field_of_the_payload_has_somewhere_to_go(self) -> None:
        """The property ``AgentMessage`` is documented on, held by the code.

        ``seq`` and ``ts`` are stamped by the sink rather than by
        ``emit_agent_message``, and ``report_truncated`` is a flag the payload
        only carries when it applies; all three are columns.
        """
        sink, recorded = _sink_with_recorder()
        emit_agent_message(
            sink,
            speaker="static",
            role="analyst",
            text="headline",
            round_index=1,
            status="complete",
            confidence=0.5,
            claims=[{"claim": "c", "evidence_ref": "ev_0001", "confidence": 0.5}],
            dissent=["d"],
            report="prose",
            stage="analysis",
            addressed_to="judge",
            kind="says",
            display_name="Ahmet",
        )
        row = _transcript_row(recorded[0], report_id=uuid.uuid4(), seq=7)

        missing = [field for field in recorded[0] if not hasattr(row, field)]
        assert not missing, (
            f"the payload carries {missing} and the row has no column for it. "
            "AgentMessage is documented as mirroring the payload field for "
            "field; add the column or correct the docstring."
        )


class TestTheLedgerRowKeepsWhatTheEntryCarried:
    """The four fields the ledger row was dropping, and why one of them matters.

    ``truncated`` is the only thing that says an output was dropped to keep an
    agent inside its byte budget. A failed call also has an empty output, so a
    reader that infers the trim from the emptiness explains a failure with a
    cause that did not happen.
    """

    def test_a_trimmed_entry_says_so_in_the_row(self) -> None:
        row = _evidence_row(
            {
                "id": "ev_0007",
                "agent": "static",
                "tool": "decompile",
                "ok": True,
                "output": "",
                "truncated": True,
                "symbol": "sub_401000",
                "started_at": 1_700_000_000.5,
                "repeated_of": "ev_0003",
            },
            job_id=uuid.uuid4(),
        )

        assert row.truncated is True
        assert row.symbol == "sub_401000"
        assert row.started_at == 1_700_000_000.5
        assert row.repeated_of == "ev_0003"

    def test_a_failed_call_is_not_recorded_as_a_trimmed_one(self) -> None:
        row = _evidence_row(
            {
                "id": "ev_0008",
                "agent": "static",
                "tool": "pe_info",
                "ok": False,
                "error": "the tool server did not answer",
                "output": "",
            },
            job_id=uuid.uuid4(),
        )

        assert row.output == ""
        assert row.truncated is False
        assert row.repeated_of is None

    def test_every_field_of_a_ledger_entry_has_somewhere_to_go(self) -> None:
        from maljan.schemas.evidence import LedgerEntry

        row = _evidence_row(LedgerEntry(id="ev_0001").model_dump(), job_id=uuid.uuid4())
        # ``id`` is the citation string, which the row calls ``entry_id``: the
        # row's own ``id`` is its primary key.
        missing = [
            field
            for field in LedgerEntry(id="ev_0001").model_dump()
            if field != "id" and not hasattr(row, field)
        ]
        assert not missing, f"LedgerEntry carries {missing} and the row drops it."

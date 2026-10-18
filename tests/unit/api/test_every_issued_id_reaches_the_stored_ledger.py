"""Every id the job's counter issued is on the ledger a run stores.

An id is issued when a call is recorded, and the model, the live feed and the
report may show it from then on. In each path that persists a ledger — a
completed run, a stopped run and a report kept from a failed run — the stored
rows hold exactly the issued ids, in ``seq`` order, whatever held the entries
when the run ended: a delegation answered after its caller's loop ended, an
analyst whose revision raised before its node drained it, a judge mediation
loop, a triage pack stopped on its thread.

The container is the real one; the rows are the ones the worker adds to its
session, recorded by the session probe the other storage tests use.
"""

from __future__ import annotations

import time
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from tests.integration._session_probe import SessionFactory, fake_job, fake_sample, rows_for

from app.worker.analysis_worker import (
    _report_inputs,
    _store_the_report,
    keep_the_built_report,
    keep_the_stopped_run,
)
from maljan.agents.delegation import _hand_over_the_record
from maljan.core.config import Settings
from maljan.core.container import ServiceContainer
from maljan.pipeline.state import with_undrained_evidence
from maljan.pipeline.stopped_run import partial_report
from maljan.schemas.evidence import LedgerEntry, build_entry

NOTE = "Stopped by the operator 61 s into the run, node verdict."


@pytest.fixture
def container() -> ServiceContainer:
    container = ServiceContainer(Settings(_env_file=None), mock=True)
    llm = MagicMock()
    with (
        patch.object(container, "get_agent_llm", return_value=llm),
        patch.object(container, "get_judge_llm", return_value=llm),
        patch.object(container, "get_mediator_llm", return_value=llm),
    ):
        for key in ("static", "dynamic", "network"):
            container.get_agent(key)
        container.get_judge_agent("judge")
        container.get_judge_agent("expert")
    return container


def _issue(container: ServiceContainer, agent: str, count: int) -> list[LedgerEntry]:
    counter = container.get_evidence_counter()
    out = []
    for _ in range(count):
        entry_id, seq = counter.next_id()
        out.append(
            build_entry(
                entry_id=entry_id,
                seq=seq,
                agent=agent,
                tool="peek",
                args={"at": seq},
                server=None,
                output=f"answer {seq}",
            )
        )
    return out


def _dumps(entries: list[LedgerEntry]) -> list[dict[str, Any]]:
    return [entry.model_dump(mode="json") for entry in entries]


def _state(ledger: list[dict[str, Any]], **extra: Any) -> dict[str, Any]:
    return {
        "file_hash": "c" * 64,
        "file_name": "sample.exe",
        "run_started_at": time.time() - 61,
        "reports": {},
        "isr_reports": {},
        "evidence_ledger": ledger,
        "discussion_history": [],
        "degradation_reasons": [],
        "stage_results": {},
        "final_decision": "Malware",
        "run_summary": {"final_decision": "Malware", "degraded_mode": False},
        **extra,
    }


def _stored(factory: SessionFactory) -> list[Any]:
    from app.models.evidence import EvidenceEntry

    return [
        obj
        for session in factory.sessions
        for obj in session.added
        if isinstance(obj, EvidenceEntry)
    ]


def _assert_every_issued_id_is_stored(container: ServiceContainer, rows: list[Any]) -> int:
    issued = container.get_evidence_counter().issued
    seqs = [row.seq for row in rows]
    # Every issued id once, nothing else, and the rows in the order issued.
    assert seqs == list(range(1, issued + 1))
    assert [row.entry_id for row in rows] == [f"ev_{n:04d}" for n in range(1, issued + 1)]
    return issued


def _the_run_s_holders(container: ServiceContainer) -> list[dict[str, Any]]:
    """Entries on every kind of holder; returns the part a node wrote to the state.

    The pack wrote three and its node put them on the state. The static
    analyst's node drained two. The dynamic analyst asked the network analyst,
    whose answer came after the dynamic analyst's loop had ended. The static
    analyst's revision then recorded two calls and raised before its node
    drained them. The mediator's loop recorded calls after the negotiation
    node's drain.
    """
    pack = _issue(container, "pipeline", 3)
    container.register_evidence_holder(lambda: list(pack))
    static = container.get_agent("static")
    drained_static = _issue(container, "static", 2)

    dynamic = container.get_agent("dynamic")
    network = container.get_agent("network")
    network._evidence_entries = _issue(container, "network", 2)
    _hand_over_the_record(dynamic, network, still_running=False)
    assert dynamic._evidence_entries == []

    static._evidence_entries = _issue(container, "static", 2)

    expert = container.get_judge_agent("expert")
    drained_judge = _issue(container, "judge", 1)
    expert._evidence_entries = _issue(container, "judge", 2)
    return _dumps([*pack, *drained_static, *drained_judge])


@pytest.mark.asyncio
async def test_a_completed_run_stores_every_issued_id(container: ServiceContainer) -> None:
    state = with_undrained_evidence(_state(_the_run_s_holders(container)), container)
    state["malware_report"] = partial_report(state, container, note=NOTE)
    stix_bundle, run_summary = _report_inputs(
        state, core_settings=Settings(_env_file=None), override_keys=(), hash_mismatch_reason=None
    )
    job = fake_job()
    factory = SessionFactory(rows_for(job, fake_sample(job.sample_id)))
    async with factory() as db:
        await _store_the_report(
            db,
            job_uuid=job.id,
            job_id=str(job.id),
            pipeline_result=state,
            stix_bundle=stix_bundle,
            run_summary=run_summary,
            transcript=[],
            core_settings=Settings(_env_file=None),
        )

    issued = _assert_every_issued_id_is_stored(container, _stored(factory))
    assert issued == 12


@pytest.mark.asyncio
async def test_a_stopped_run_stores_every_issued_id(container: ServiceContainer) -> None:
    app = SimpleNamespace(
        container=container,
        built_report=None,
        latest_state=_state(_the_run_s_holders(container)),
    )
    job = fake_job()
    factory = SessionFactory(rows_for(job, fake_sample(job.sample_id)))

    kept = await keep_the_stopped_run(
        factory,
        job_uuid=job.id,
        job_id=str(job.id),
        app=app,
        note=NOTE,
        transcript=[],
        core_settings=Settings(_env_file=None),
        override_keys=(),
        hash_mismatch_reason=None,
    )

    assert kept is True
    assert _assert_every_issued_id_is_stored(container, _stored(factory)) == 12


@pytest.mark.asyncio
async def test_a_run_stopped_after_its_report_node_collected_stores_every_issued_id(
    container: ServiceContainer,
) -> None:
    """The report node collected, then was cancelled before it wrote what it got."""
    latest = _state(_the_run_s_holders(container))
    known = [row["id"] for row in latest["evidence_ledger"]]
    assert len(container.collect_undrained_evidence(known)) == 6
    app = SimpleNamespace(container=container, built_report=None, latest_state=latest)
    job = fake_job()
    factory = SessionFactory(rows_for(job, fake_sample(job.sample_id)))

    kept = await keep_the_stopped_run(
        factory,
        job_uuid=job.id,
        job_id=str(job.id),
        app=app,
        note=NOTE,
        transcript=[],
        core_settings=Settings(_env_file=None),
        override_keys=(),
        hash_mismatch_reason=None,
    )

    assert kept is True
    assert _assert_every_issued_id_is_stored(container, _stored(factory)) == 12


@pytest.mark.asyncio
async def test_a_report_kept_from_a_failed_run_stores_every_issued_id(
    container: ServiceContainer,
) -> None:
    built = _state(_the_run_s_holders(container))
    built["malware_report"] = partial_report(built, container, note=NOTE)
    job = fake_job()
    factory = SessionFactory(rows_for(job, fake_sample(job.sample_id)))

    kept = await keep_the_built_report(
        factory,
        job_uuid=job.id,
        job_id=str(job.id),
        built=built,
        note="the run failed after its report was built",
        transcript=[],
        core_settings=Settings(_env_file=None),
        override_keys=(),
        hash_mismatch_reason=None,
        container=container,
    )

    assert kept is True
    assert _assert_every_issued_id_is_stored(container, _stored(factory)) == 12


class TestEachHolderAlone:
    """Each holder on its own, collected once, written once."""

    def test_a_delegation_answered_after_its_caller_ended_reaches_the_ledger(
        self, container: ServiceContainer
    ) -> None:
        dynamic = container.get_agent("dynamic")
        network = container.get_agent("network")
        network._evidence_entries = _issue(container, "network", 3)

        _hand_over_the_record(dynamic, network, still_running=False)

        assert dynamic._evidence_entries == []
        assert network._evidence_entries == []
        late = container.collect_undrained_evidence()
        assert [entry.seq for entry in late] == [1, 2, 3]
        # Collected once, kept: a ledger that holds them gets nothing more,
        # and one that does not gets them again.
        assert container.collect_undrained_evidence(["ev_0001", "ev_0002", "ev_0003"]) == []
        assert [entry.seq for entry in container.collect_undrained_evidence()] == [1, 2, 3]

    def test_a_revision_that_raised_leaves_nothing_behind(
        self, container: ServiceContainer
    ) -> None:
        static = container.get_agent("static")
        static._evidence_entries = _issue(container, "static", 2)

        state = with_undrained_evidence(_state([]), container)

        assert [row["id"] for row in state["evidence_ledger"]] == ["ev_0001", "ev_0002"]
        assert static._evidence_entries == []

    def test_a_mediation_loop_s_late_calls_reach_the_ledger(
        self, container: ServiceContainer
    ) -> None:
        drained = _issue(container, "judge", 2)
        container.get_judge_agent("expert")._evidence_entries = _issue(container, "judge", 1)

        state = with_undrained_evidence(_state(_dumps(drained)), container)

        assert [row["seq"] for row in state["evidence_ledger"]] == [1, 2, 3]

    def test_an_entry_already_on_the_ledger_is_not_collected_twice(
        self, container: ServiceContainer
    ) -> None:
        pack = _issue(container, "pipeline", 2)
        container.register_evidence_holder(lambda: list(pack))

        state = with_undrained_evidence(_state(_dumps(pack[:1])), container)

        assert [row["id"] for row in state["evidence_ledger"]] == ["ev_0001", "ev_0002"]

    def test_a_holder_that_raises_does_not_stop_the_others(
        self, container: ServiceContainer
    ) -> None:
        def broken() -> list[Any]:
            raise RuntimeError("the holder is gone")

        container.register_evidence_holder(broken)
        container.get_agent("static")._evidence_entries = _issue(container, "static", 1)

        assert [entry.id for entry in container.collect_undrained_evidence()] == ["ev_0001"]

    def test_a_state_with_nothing_left_out_comes_back_as_it_was(
        self, container: ServiceContainer
    ) -> None:
        state = _state(_dumps(_issue(container, "static", 1)))
        assert with_undrained_evidence(state, container) is state
        assert with_undrained_evidence(state, None) is state

    def test_a_thousand_holders_are_collected_in_one_pass(
        self, container: ServiceContainer
    ) -> None:
        for entry in _issue(container, "static", 1000):
            container.register_evidence_holder(lambda entry=entry: [entry])
        started = time.perf_counter()
        collected = container.collect_undrained_evidence(f"ev_{n:04d}" for n in range(1, 501))
        assert len(collected) == 500
        assert time.perf_counter() - started < 2.0


class TestOneRowPerIdAndSeq:
    def test_a_repeated_id_or_seq_keeps_the_first_and_is_named(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        from app.worker.analysis_worker import rows_to_store

        ledger = [
            {"id": "ev_0002", "seq": 2, "output": "first"},
            {"id": "ev_0001", "seq": 1},
            {"id": "ev_0002", "seq": 2, "output": "second"},
            {"id": "ev_0009", "seq": 1},
            "not an entry",
        ]
        with caplog.at_level("WARNING"):
            rows = rows_to_store(ledger, job_id="job-1")

        assert [(row["id"], row["seq"]) for row in rows] == [("ev_0001", 1), ("ev_0002", 2)]
        assert rows[1]["output"] == "first"
        assert "ev_0002/seq 2" in caplog.text
        assert "ev_0009/seq 1" in caplog.text

    def test_a_clean_ledger_is_written_whole_without_a_warning(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        from app.worker.analysis_worker import rows_to_store

        with caplog.at_level("WARNING"):
            rows = rows_to_store(
                [{"id": "ev_0002", "seq": 2}, {"id": "ev_0001", "seq": 1}], job_id="j"
            )
        assert [row["seq"] for row in rows] == [1, 2]
        assert "already stored" not in caplog.text

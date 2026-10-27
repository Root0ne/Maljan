"""A job can start without an earlier run's memory of its sample (T-414).

Case memory is a feature for an analyst: a run on a sample is shown what an
earlier run on it stored, as hypotheses. A benchmark series runs one sample
again and again, and there each run's score was partly the run before it. A
job submitted with ``ignore_earlier_runs`` is shown no earlier run, however
much the store holds for its sample; the store is not asked, nothing stored is
changed, and the job still records its own case. Its run summary says so.
Without the switch every prompt and record is what it was.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock

import pytest

from maljan.analysis.run_summary import EARLIER_RUNS_IGNORED_SENTENCE, RunSummaryBuilder
from maljan.memory import embeddings
from maljan.memory.in_memory_store import InMemoryStore
from maljan.memory.long_term_memory import (
    EARLIER_RUN_HEADING,
    StoredCase,
    earlier_case,
    earlier_case_of,
    earlier_run_block,
    earlier_run_of,
    earlier_run_text,
)
from maljan.schemas.stix_models import EARLIER_RUN_PROPERTY, Bundle

SHA = "ab" * 32


def _case() -> StoredCase:
    return StoredCase(
        sample_id=SHA,
        summary_text="[STATIC] injects into explorer.exe [ev_0007] T1055",
        technique_ids=["T1055", "T1547.001"],
        malware_category="RAT",
        created_at=datetime(2026, 10, 1, 12, 0, tzinfo=UTC),
    )


@pytest.fixture
def fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(embeddings, "_try_load_fastembed", lambda: False)


@pytest.fixture
def store(fallback: None) -> InMemoryStore:
    held = InMemoryStore()
    held.store(_case())
    return held


class _Counting:
    """A store that counts every read of it."""

    def __init__(self, inner: InMemoryStore) -> None:
        self.inner = inner
        self.reads = 0

    def case_of(self, sample_id: str, owner: str | None = None) -> Any:
        self.reads += 1
        return self.inner.case_of(sample_id)


def _container(store: Any, *, ignore: bool | None) -> Any:
    from maljan.core.config import Settings
    from maljan.core.container import ServiceContainer

    kwargs = {} if ignore is None else {"ignore_earlier_runs": ignore}
    container = ServiceContainer(Settings(_env_file=None), mock=True, **kwargs)
    container.get_memory_store = lambda: store  # type: ignore[method-assign]
    return container


class TestTheSwitch:
    def test_it_is_off_unless_a_job_turns_it_on(self, store: InMemoryStore) -> None:
        assert _container(store, ignore=None).ignore_earlier_runs is False
        assert _container(store, ignore=True).ignore_earlier_runs is True

    def test_the_app_hands_it_to_its_container(self) -> None:
        from maljan.app import MaljanApp

        assert MaljanApp(mock=True).container.ignore_earlier_runs is False
        assert MaljanApp(mock=True, ignore_earlier_runs=True).container.ignore_earlier_runs

    def test_on_no_earlier_case_is_read_and_the_store_is_not_asked(
        self, store: InMemoryStore
    ) -> None:
        counting = _Counting(store)
        container = _container(counting, ignore=True)

        assert earlier_case_of(container, SHA) is None
        assert earlier_run_text(container, SHA) == ""
        assert earlier_run_of(container, SHA) is None
        assert counting.reads == 0
        # Nothing stored was changed: the case is there for a job without the switch.
        assert store.count() == 1
        assert earlier_case(store, SHA) == _case()
        assert earlier_run_text(_container(store, ignore=False), SHA) == earlier_run_block(_case())

    def test_a_value_that_is_not_true_is_not_the_switch(self, store: InMemoryStore) -> None:
        container = _container(store, ignore=None)
        # A test double's attribute, or any truthy stand-in, is not a job's choice.
        container.ignore_earlier_runs = "yes"
        assert earlier_case_of(container, SHA) == _case()


class TestNoPromptCarriesTheEarlierRun:
    def _state(self) -> dict[str, Any]:
        return {"file_hash": SHA, "evidence_ledger": []}

    def test_the_agents_pack_holds_no_block(self, store: InMemoryStore) -> None:
        from maljan.pipeline.nodes import pack_text

        container = _container(store, ignore=True)

        assert pack_text(self._state(), container) == ""
        assert pack_text(self._state(), container, for_reporter=True) == ""

    def test_off_the_agents_pack_is_what_it_was(self, store: InMemoryStore) -> None:
        from maljan.pipeline.nodes import pack_text

        container = _container(store, ignore=False)

        assert pack_text(self._state(), container) == earlier_run_block(_case())
        assert pack_text(self._state(), container, for_reporter=True) == ""


def _judge_run(store: Any, *, ignore: bool) -> tuple[dict[str, Any], list[str]]:
    """The judge node over a stored case for the sample, and every text its judge was handed."""
    from maljan.agents.judge_agent import JudgeVerdict
    from maljan.pipeline.nodes import make_judge_node
    from maljan.schemas.evidence import EvidenceCounter
    from tests.unit.pipeline.test_degraded_mode_at_the_judge_node import _Container, _state

    class _WithMemory(_Container):
        memory_owner = None

        def __init__(self) -> None:
            super().__init__(EvidenceCounter())
            self.earlier_cases: dict[str, Any] = {}
            self.ignore_earlier_runs = ignore

        def get_memory_store(self) -> Any:
            return store

    container = _WithMemory()
    judge = container.get_judge_agent(role="judge")
    judge.give_verdict = AsyncMock(
        return_value=JudgeVerdict(bundle=Bundle(objects=[]), violations=[], retries=0, fed_back={})
    )
    judge.decide_techniques = AsyncMock(return_value=None)
    update = asyncio.run(make_judge_node(container)({**_state([]), "file_hash": SHA}))
    texts: list[str] = []
    for call in [*judge.give_verdict.await_args_list, *judge.decide_techniques.await_args_list]:
        texts.extend(str(value) for value in (*call.args, *call.kwargs.values()))
    return update, texts


class TestTheJudgeNode:
    def test_on_the_judge_is_shown_no_earlier_run_and_the_summary_says_so(
        self, store: InMemoryStore
    ) -> None:
        update, texts = _judge_run(store, ignore=True)

        assert texts and not any(EARLIER_RUN_HEADING in text for text in texts)
        assert update["stix_output"].get(EARLIER_RUN_PROPERTY) is None
        assert update["run_summary"]["earlier_runs_ignored"] is True

    def test_off_the_judge_is_shown_it_and_the_summary_has_no_such_key(
        self, store: InMemoryStore
    ) -> None:
        update, texts = _judge_run(store, ignore=False)

        assert any(earlier_run_block(_case()) in text for text in texts)
        assert update["stix_output"][EARLIER_RUN_PROPERTY]["techniques"] == ["T1055", "T1547.001"]
        assert "earlier_runs_ignored" not in update["run_summary"]


class TestTheRunSummary:
    def test_off_the_summary_is_unchanged(self) -> None:
        plain = RunSummaryBuilder(start_time=0.0).build()
        off = RunSummaryBuilder(start_time=0.0).set_earlier_runs_ignored(False).build()
        plain.timestamp = off.timestamp = 0.0
        plain.elapsed_seconds = off.elapsed_seconds = 0.0

        assert off.to_dict() == plain.to_dict()
        assert "earlier_runs_ignored" not in off.to_dict()
        assert off.to_markdown() == plain.to_markdown()

    def test_on_the_dict_and_the_markdown_say_so(self) -> None:
        summary = RunSummaryBuilder(start_time=0.0).set_earlier_runs_ignored(True).build()

        assert summary.to_dict()["earlier_runs_ignored"] is True
        assert f"**Earlier runs**: {EARLIER_RUNS_IGNORED_SENTENCE}" in summary.to_markdown()


class TestARunStoppedBeforeItsJudge:
    """A timeout, a ceiling or a cancel before the judge still records the switch."""

    @pytest.mark.parametrize("ignore", [True, False])
    def test_the_summary_built_at_the_stop_says_what_the_judge_s_would(
        self, store: InMemoryStore, ignore: bool
    ) -> None:
        from maljan.pipeline.stopped_run import stopped_run_summary

        state = {"file_hash": SHA, "evidence_ledger": [], "degradation_reasons": []}

        summary = stopped_run_summary(state, _container(store, ignore=ignore), note="stopped")

        if ignore:
            assert summary["earlier_runs_ignored"] is True
        else:
            assert "earlier_runs_ignored" not in summary


class TestTheJobStillRecordsItsOwnCase:
    def test_a_completed_job_with_the_switch_stores_its_case(self, fallback: None) -> None:
        held = InMemoryStore()
        container = _container(held, ignore=True)
        container.pending_memory_case = _case()

        assert container.remember_the_run() is True
        assert earlier_case(held, SHA) == _case()

"""The analysis worker refuses to start with more than one job at a time.

A running analysis installs its settings as the process's, registers its
configured values with the event scrub under one ``job`` scope and records the
API names its hash resolution read in one process-wide set. Each is right only
while one analysis runs in the process, so ``max_jobs`` other than 1 is refused
at startup with the reason, before any job is taken.
"""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest

from app.worker import analysis_worker


class _Started(Exception):
    """Ends ``startup`` once the refusal has been passed."""


def _startup(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    log = MagicMock()
    monkeypatch.setattr(analysis_worker, "logger", log)
    monkeypatch.setattr(analysis_worker, "setup_logging", lambda: None)

    def started(_settings: object) -> None:
        raise _Started

    monkeypatch.setattr("app.bootstrap.require_bootstrap", started)
    return log


def test_the_shipped_worker_runs_one_analysis_at_a_time() -> None:
    assert analysis_worker.WorkerSettings.max_jobs == 1
    assert analysis_worker.concurrent_analyses_refusal(1) is None


@pytest.mark.parametrize("jobs", [2, 8])
def test_more_than_one_job_is_refused_with_the_state_that_is_per_process(jobs: int) -> None:
    refusal = analysis_worker.concurrent_analyses_refusal(jobs)
    assert refusal is not None
    assert refusal.startswith(f"max_jobs is {jobs};")
    for held in analysis_worker.PROCESS_WIDE_JOB_STATE:
        assert held in refusal
    assert "Set max_jobs to 1" in refusal


@pytest.mark.parametrize("value", [True, 1.9, "1"])
def test_a_value_that_only_converts_to_one_is_refused(value: object) -> None:
    refusal = analysis_worker.concurrent_analyses_refusal(value)
    assert refusal == f"max_jobs is {value!r}, which is not a number of jobs; set it to 1."


def test_the_refusal_names_no_secret_word() -> None:
    assert "secret" not in (analysis_worker.concurrent_analyses_refusal(2) or "").lower()


def test_a_value_that_is_no_number_is_refused() -> None:
    assert analysis_worker.concurrent_analyses_refusal("many") == (
        "max_jobs is 'many', which is not a number of jobs; set it to 1."
    )


def test_startup_refuses_before_any_job_is_taken(monkeypatch: pytest.MonkeyPatch) -> None:
    log = _startup(monkeypatch)
    monkeypatch.setattr(analysis_worker.WorkerSettings, "max_jobs", 2)

    with pytest.raises(RuntimeError, match="max_jobs is 2;"):
        asyncio.run(analysis_worker.startup({}))

    (call,) = log.critical.call_args_list
    assert call.args[0].startswith("max_jobs is 2;")


def test_startup_goes_on_with_one_job(monkeypatch: pytest.MonkeyPatch) -> None:
    log = _startup(monkeypatch)

    with pytest.raises(_Started):
        asyncio.run(analysis_worker.startup({}))

    assert not log.critical.call_args_list

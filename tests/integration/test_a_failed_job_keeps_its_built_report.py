"""A job that fails after its report was built stores that report, marked incomplete.

The job stays ``failed``. The report is stored the way a completed run stores
one, with ``incomplete_reason`` saying where the run failed and under which
error id, and the same sentence in the degradation reasons the report and the
run summary carry, so the console's degraded banner and the rendered report
say it too. A run that completes stores its report with no such mark.
"""

from __future__ import annotations

import re
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.worker.analysis_worker import run_analysis
from tests.integration._session_probe import updates_in
from tests.integration.test_worker_job_lifecycle import (  # noqa: F401 — fixtures
    _answer_reads,
    _isolated_runtime_settings,
    _make_job,
    _make_sample,
    _no_object_store,
    mock_ctx,
    mock_db_session,
)


def _reads(job: Any, sample: Any) -> list[Any]:
    def _result(obj: Any) -> MagicMock:
        m = MagicMock()
        if isinstance(getattr(obj, "status", None), str):
            m.scalar_one_or_none.return_value = obj
        else:
            m.scalar_one.return_value = obj
        return m

    return [_result(job), _result(sample)]


def _stored_reports(session: AsyncMock) -> list[Any]:
    from app.models.report import AnalysisReport

    return [
        call.args[0]
        for call in session.add.call_args_list
        if call.args and isinstance(call.args[0], AnalysisReport)
    ]


BUILT: dict[str, Any] = {
    "final_decision": "Malware",
    "judge_report": "the judge's prose",
    "reports": {"static": "static prose"},
    "revised_reports": {},
    "isr_reports": {},
    "evidence_ledger": [],
    "discussion_history": [],
    "run_summary": {"degraded_mode": False, "degradation_reasons": []},
    "malware_report": {"verdict": "Malware", "degradation_reasons": []},
    "stix_bundle_extended": {"type": "bundle", "id": "bundle--1", "objects": []},
}


@pytest.mark.asyncio
async def test_a_node_after_the_report_fails_and_the_report_is_kept(
    mock_ctx: dict[str, Any],  # noqa: F811
    mock_db_session: AsyncMock,  # noqa: F811
) -> None:
    job = _make_job()
    recorded = _answer_reads(mock_db_session, _reads(job, _make_sample()))

    async def _fails_after_the_report(self: Any, **_: Any) -> dict[str, Any]:
        self.built_report = {
            **BUILT,
            "malware_report": dict(BUILT["malware_report"]),
            "run_summary": dict(BUILT["run_summary"]),
        }
        self.failed_step = "node after_report"
        raise RuntimeError("a step after the report")

    from app import config as api_config

    api_config._settings = None
    with (
        patch.dict("os.environ", {"MALJAN_MOCK_MODE": "true"}, clear=False),
        patch("maljan.app.MaljanApp.arun", new=_fails_after_the_report),
    ):
        result = await run_analysis(mock_ctx, str(job.id))
    api_config._settings = None

    assert result["status"] == "failed"
    error_id = re.search(r"error id ([0-9a-f]{32})", result["error"]).group(1)  # type: ignore[union-attr]
    statuses = [u["status"] for u in updates_in(recorded, "analysis_jobs")]
    assert statuses == ["running", "failed"]

    stored = _stored_reports(mock_db_session)
    assert len(stored) == 1
    report = stored[0]
    expected = (
        "This report was built and the run failed after it: node after_report raised "
        f"RuntimeError (error id {error_id}). The job is failed and this report is "
        "incomplete: nothing the run would have done after it is in it."
    )
    assert report.incomplete_reason == expected
    # The exception's own message is never published.
    assert "a step after the report" not in report.incomplete_reason
    assert report.verdict == "Malware"
    assert report.malware_report["degradation_reasons"] == [expected]
    assert report.malware_report["degraded_mode"] is True
    assert report.run_summary["degradation_reasons"] == [expected]
    assert report.run_summary["degraded_mode"] is True
    assert report.stix_bundle["id"] == "bundle--1"


@pytest.mark.asyncio
async def test_a_failure_before_the_report_stores_nothing(
    mock_ctx: dict[str, Any],  # noqa: F811
    mock_db_session: AsyncMock,  # noqa: F811
) -> None:
    job = _make_job()
    recorded = _answer_reads(mock_db_session, _reads(job, _make_sample()))

    async def _fails_before_the_report(self: Any, **_: Any) -> dict[str, Any]:
        self.failed_step = "node judge"
        raise RuntimeError("the judge")

    from app import config as api_config

    api_config._settings = None
    with (
        patch.dict("os.environ", {"MALJAN_MOCK_MODE": "true"}, clear=False),
        patch("maljan.app.MaljanApp.arun", new=_fails_before_the_report),
    ):
        result = await run_analysis(mock_ctx, str(job.id))
    api_config._settings = None

    assert result["status"] == "failed"
    assert [u["status"] for u in updates_in(recorded, "analysis_jobs")] == ["running", "failed"]
    assert _stored_reports(mock_db_session) == []


@pytest.mark.asyncio
async def test_a_completed_run_stores_its_report_unmarked(
    mock_ctx: dict[str, Any],  # noqa: F811
    mock_db_session: AsyncMock,  # noqa: F811
) -> None:
    job = _make_job()
    recorded = _answer_reads(mock_db_session, _reads(job, _make_sample()))

    from app import config as api_config

    api_config._settings = None
    with patch.dict("os.environ", {"MALJAN_MOCK_MODE": "true"}, clear=False):
        result = await run_analysis(mock_ctx, str(job.id))
    api_config._settings = None

    assert result["status"] == "completed"
    assert [u["status"] for u in updates_in(recorded, "analysis_jobs")] == [
        "running",
        "completed",
    ]
    stored = _stored_reports(mock_db_session)
    assert len(stored) == 1
    assert stored[0].incomplete_reason is None
    reasons = (stored[0].run_summary or {}).get("degradation_reasons") or []
    assert not any("the run failed after it" in str(r) for r in reasons)


@pytest.mark.asyncio
async def test_a_graph_that_returned_and_a_worker_that_refused_it_stores_nothing(
    mock_ctx: dict[str, Any],  # noqa: F811
    mock_db_session: AsyncMock,  # noqa: F811
) -> None:
    """Only a graph that raised leaves a report to keep.

    A run the graph finished and the worker then refused — here a report node
    that answered with an error, elsewhere an absent analysis — is refused on
    purpose, and what the report node built is not published past it.
    """
    job = _make_job()
    _answer_reads(mock_db_session, _reads(job, _make_sample()))

    async def _returns_a_refused_result(self: Any, **_: Any) -> dict[str, Any]:
        self.built_report = dict(BUILT)
        self.failed_step = None
        return {"report_error": "ValueError: boom"}

    from app import config as api_config

    api_config._settings = None
    with (
        patch.dict("os.environ", {"MALJAN_MOCK_MODE": "true"}, clear=False),
        patch("maljan.app.MaljanApp.arun", new=_returns_a_refused_result),
    ):
        result = await run_analysis(mock_ctx, str(job.id))
    api_config._settings = None

    assert result["status"] == "failed"
    assert _stored_reports(mock_db_session) == []

"""A report kept from a failed run is served with the sentence that marks it.

The report routes read the row whatever the job's status, so a failed job's
kept report is served like any other; ``incomplete_reason`` is what tells a
client it is incomplete, and a report of a completed run carries ``None``.
The markdown and HTML renderings are rendered from the stored report, whose
degradation reasons carry the same sentence.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

from app.api.v1.reports import _detail
from maljan.reporting.renderers import MarkdownRenderer

NOTE = (
    "This report was built and the run failed after it: node judge raised "
    "InvalidUpdateError (error id 0123456789abcdef0123456789abcdef). The job is failed "
    "and this report is incomplete: nothing the run would have done after it is in it."
)


def _row(incomplete_reason: str | None) -> Any:
    return SimpleNamespace(
        id=uuid.uuid4(),
        job_id=uuid.uuid4(),
        verdict="Malware",
        overall_confidence=0.9,
        malware_category=None,
        stix_bundle=None,
        mitre_techniques=None,
        agent_reports=None,
        negotiation_log=None,
        run_summary={"degraded_mode": True, "degradation_reasons": [NOTE]},
        malware_report=None,
        incomplete_reason=incomplete_reason,
        agent_findings=[],
        transcript=[],
        created_at="2026-09-19T00:00:00+00:00",
    )


@pytest.mark.asyncio
async def test_the_kept_report_carries_its_mark() -> None:
    detail = await _detail(MagicMock(spec_set=["get_report"]), _row(NOTE))
    assert detail.incomplete_reason == NOTE
    assert detail.verdict == "Malware"


@pytest.mark.asyncio
async def test_a_completed_runs_report_carries_none() -> None:
    detail = await _detail(MagicMock(spec_set=["get_report"]), _row(None))
    assert detail.incomplete_reason is None


def test_the_migration_adds_the_column_and_takes_it_back() -> None:
    import importlib.util
    from pathlib import Path

    import sqlalchemy as sa
    from alembic.operations import Operations
    from alembic.runtime.migration import MigrationContext

    path = (
        Path(__file__).resolve().parents[2]
        / "apps"
        / "api"
        / "alembic"
        / "versions"
        / "20261001000000_report_incomplete_reason.py"
    )
    spec = importlib.util.spec_from_file_location(path.stem, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.down_revision == "20260930000000"

    engine = sa.create_engine("sqlite://")
    with engine.connect() as conn:
        conn.execute(sa.text("CREATE TABLE analysis_reports (id TEXT PRIMARY KEY)"))
        with Operations.context(MigrationContext.configure(conn)):
            module.upgrade()
            columns = {c["name"] for c in sa.inspect(conn).get_columns("analysis_reports")}
            assert "incomplete_reason" in columns
            module.downgrade()
        columns = {c["name"] for c in sa.inspect(conn).get_columns("analysis_reports")}
        assert "incomplete_reason" not in columns


def test_the_rendered_report_says_it_is_incomplete() -> None:
    from maljan.reporting.models import MalwareReport

    report = MalwareReport.model_validate(
        {
            "identity": {"hashes": {"sha256": "a" * 64}},
            "verdict": "Malware",
            "degraded_mode": True,
            "degradation_reasons": [NOTE],
        }
    )
    assert NOTE in MarkdownRenderer().render(report)

"""The judge's own bundle is on the run's record, beside the export.

Every export decline row ends "It is unchanged in the judge's own bundle", and
nothing stored that bundle: the worker persisted the export, or the judge's
bundle only when there was no export. Now the report keeps
``judge_stix_bundle`` — the judge's bundle as the pipeline read it and the map
from each label the judge wrote to the id it was published under — and
``/reports/{id}/stix?source=judge`` serves it where the export is served.
"""

from __future__ import annotations

import importlib.util
import uuid
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.compiler import compiles

from app.services.report_service import ReportService
from app.worker.analysis_worker import judge_bundle_record


@compiles(postgresql.JSONB, "sqlite")
def _jsonb_as_json(element, compiler, **kw):  # noqa: ANN001, ANN202
    return "JSON"


_API = Path(__file__).resolve().parents[3] / "apps" / "api"
_REV = _API / "alembic" / "versions" / "20260929000000_judge_stix_bundle.py"


def _judge_output() -> dict:
    stamp = datetime(2026, 9, 22, 23, 30, tzinfo=UTC)
    return {
        "type": "bundle",
        "id": "bundle--6b1d3c1e-6f0a-4d51-9f3a-0c9d2f1e4a01",
        "objects": [
            {
                "type": "malware",
                "id": "malware--0f1e2d3c-4b5a-4968-8776-655443332211",
                "spec_version": "2.1",
                "created": stamp,
                "modified": stamp,
                "name": "sample",
                "is_family": False,
            }
        ],
    }


class TestTheRecord:
    def test_it_holds_the_bundle_as_json_and_the_label_map(self) -> None:
        record = judge_bundle_record(
            {
                "stix_output": _judge_output(),
                "stix_labels": {"malware--1": "malware--0f1e2d3c-4b5a-4968-8776-655443332211"},
            }
        )

        assert record is not None
        (malware,) = record["bundle"]["objects"]
        assert malware["created"].startswith("2026-09-22T23:30:00")
        assert record["bundle"]["spec_version"] == "2.1"
        assert record["labels"] == {"malware--1": malware["id"]}

    def test_no_judge_bundle_is_no_record(self) -> None:
        assert judge_bundle_record({"stix_output": {}}) is None
        assert judge_bundle_record({}) is None


class TestItIsServedBesideTheExport:
    @pytest.mark.asyncio
    async def test_source_judge_serves_the_judges_bundle(self) -> None:
        report = MagicMock(stix_bundle={"type": "bundle", "id": "export"})
        report.judge_stix_bundle = {"bundle": {"id": "judge"}, "labels": {}}
        svc = ReportService(db=AsyncMock())
        svc.get_report = AsyncMock(return_value=report)  # type: ignore[method-assign]
        user = MagicMock(id=uuid.uuid4())

        assert (await svc.get_stix_bundle(report.id, user))["id"] == "export"
        judged = await svc.get_stix_bundle(report.id, user, source="judge")
        assert judged["bundle"]["id"] == "judge"


def _load():
    spec = importlib.util.spec_from_file_location("judge_stix_bundle", _REV)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestTheMigration:
    def test_it_follows_the_revision_it_names(self) -> None:
        assert _load().down_revision == "20260928000000"

    def test_the_revisions_form_one_chain_with_one_head(self) -> None:
        """Two revisions sharing an id, or two with the same parent, are what
        alembic cannot load; this one arrived beside another branch's. A later
        revision on top of the head is the chain growing and passes."""
        revisions: dict[str, str | None] = {}
        for path in (_API / "alembic" / "versions").glob("*.py"):
            spec = importlib.util.spec_from_file_location(path.stem, path)
            assert spec and spec.loader
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            assert module.revision not in revisions, f"{module.revision} is used twice"
            revisions[module.revision] = module.down_revision
        parents = [parent for parent in revisions.values() if parent is not None]

        assert len(parents) == len(set(parents)), "two revisions share a parent"
        heads = set(revisions) - set(parents)
        assert len(heads) == 1, heads

    def test_it_adds_the_column_and_takes_it_back(self) -> None:
        from alembic.operations import Operations
        from alembic.runtime.migration import MigrationContext

        module = _load()
        engine = sa.create_engine("sqlite://")
        with engine.connect() as conn:
            conn.execute(sa.text("CREATE TABLE analysis_reports (id TEXT PRIMARY KEY)"))
            with Operations.context(MigrationContext.configure(conn)):
                module.upgrade()
                columns = {c["name"] for c in sa.inspect(conn).get_columns("analysis_reports")}
                assert "judge_stix_bundle" in columns
                module.downgrade()
            columns = {c["name"] for c in sa.inspect(conn).get_columns("analysis_reports")}
            assert "judge_stix_bundle" not in columns


class TestTheEndpointSaysWhatIsTrue:
    @pytest.mark.asyncio
    async def test_a_report_stored_before_the_record_says_it_has_none(self) -> None:
        from app.api.v1.reports import get_stix_bundle

        report = MagicMock(judge_stix_bundle=None)
        svc = ReportService(db=AsyncMock())
        svc.get_report = AsyncMock(return_value=report)  # type: ignore[method-assign]

        answer = await get_stix_bundle(uuid.uuid4(), "judge", MagicMock(), svc)

        assert answer["kept"] is False
        assert "stored before" in answer["reason"]

    @pytest.mark.asyncio
    async def test_a_missing_report_is_a_404(self) -> None:
        from fastapi import HTTPException

        from app.api.v1.reports import get_stix_bundle

        svc = ReportService(db=AsyncMock())
        svc.get_report = AsyncMock(return_value=None)  # type: ignore[method-assign]

        with pytest.raises(HTTPException) as caught:
            await get_stix_bundle(uuid.uuid4(), "judge", MagicMock(), svc)
        assert caught.value.status_code == 404

    @pytest.mark.asyncio
    async def test_a_kept_record_is_served_whole(self) -> None:
        from app.api.v1.reports import get_stix_bundle

        report = MagicMock(judge_stix_bundle={"bundle": {"id": "judge"}, "labels": {"a": "b"}})
        svc = ReportService(db=AsyncMock())
        svc.get_report = AsyncMock(return_value=report)  # type: ignore[method-assign]

        answer = await get_stix_bundle(uuid.uuid4(), "judge", MagicMock(), svc)

        assert answer == {"kept": True, "bundle": {"id": "judge"}, "labels": {"a": "b"}}

"""``/iocs?include=all`` carries the analysts' listed rows as the report's IOC table shows them.

The report's IOC table shows each mutex, path, registry key, task and service
an analyst listed as an ``analyst`` row with the rule's refusal. The feed read
only the network block, the string table and the judge, so a reader triaging
through it saw fewer rows than the report. The feed now takes those rows from
the same table; the default feed, which is what may be published, is unchanged.
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1 import reports as module

REPORT_ID = uuid.uuid4()
MUTEX = "Global\\relay-mutex-7f3c"


def _malware_report() -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "generated_at": "2026-05-16T00:00:00+00:00",
        "verdict": "Malware",
        "identity": {"hashes": {"sha256": "f" * 64}, "file_type": "PE"},
        "sections": [
            {
                "key": "artifact_iocs",
                "title": "Iocs",
                "kind": "table",
                "columns": ["Type", "Value"],
                "rows": [["mutex", MUTEX]],
                "evidence_ids": ["ev_0001"],
                "source": "artifact:dynamic",
            }
        ],
    }


@pytest.fixture
def client() -> TestClient:
    from app.database import get_db
    from app.deps import get_current_user, require_active_user

    report = MagicMock()
    report.id = REPORT_ID
    report.malware_report = _malware_report()

    service = module.ReportService(db=AsyncMock())
    service.get_report = AsyncMock(return_value=report)  # type: ignore[method-assign]

    app = FastAPI()
    app.include_router(module.router, prefix="/api/v1")
    user = MagicMock(id=uuid.uuid4(), email="op@example.com")
    app.dependency_overrides[get_db] = lambda: AsyncMock()
    app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[require_active_user] = lambda: user
    app.dependency_overrides[module._get_service] = lambda: service
    return TestClient(app)


def _rows(client: TestClient, query: str = "") -> list[dict[str, Any]]:
    response = client.get(f"/api/v1/reports/{REPORT_ID}/iocs{query}")
    assert response.status_code == 200, response.text
    return response.json()["items"]


def test_the_whole_feed_carries_the_analyst_s_mutex_refused(client: TestClient) -> None:
    (row,) = [row for row in _rows(client, "?include=all") if row["value"] == MUTEX]

    assert (row["kind"], row["source"], row["published"]) == ("mutex", "analyst", False)
    assert str(row["notes"]).startswith("no: named only by an analyst")


def test_the_published_feed_does_not(client: TestClient) -> None:
    assert all(row["value"] != MUTEX for row in _rows(client))


def test_the_feed_reads_the_stored_table_rather_than_rebuilding_it() -> None:
    from app.services.report_service import _with_the_analysts_listed_rows
    from maljan.reporting.models import ConsolidatedIOC, FileHashes, MalwareReport, SampleIdentity

    stored = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="f" * 64)),
        verdict="Malware",
        consolidated_iocs=[
            ConsolidatedIOC(
                type="Mutex",
                kind="mutex",
                value=f"{MUTEX}-stored",
                source="analyst",
                context="listed by the dynamic analyst",
                published="no: named only by an analyst (an artifact of the dynamic analyst)",
            )
        ],
    )
    out: list[dict[str, Any]] = []

    _with_the_analysts_listed_rows(out, stored, None)

    assert [row["value"] for row in out] == [f"{MUTEX}-stored"]

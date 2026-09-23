"""The dashboard's "Tools used" list: what recent runs called, bounded and owned."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.dialects import postgresql

from app.api.v1.dashboard import router  # noqa: E402
from app.database import get_db  # noqa: E402
from app.deps import get_current_user  # noqa: E402
from app.services.analysis_service import (  # noqa: E402
    TOOL_USAGE_MAX_RUNS,
    TOOL_USAGE_RUNS,
    tally_tool_usage,
    tool_usage_query,
)


def test_calls_are_summed_and_runs_counted_per_tool():
    body = tally_tool_usage(
        [
            {"pe_info": 3, "strings_extract": 1},
            {"pe_info": 2},
            {"sandbox_network": 4},
        ],
        20,
    )
    assert body == {
        "limit": 20,
        "runs": 3,
        "tools": [
            {"tool": "pe_info", "calls": 5, "runs": 2},
            {"tool": "sandbox_network", "calls": 4, "runs": 1},
            {"tool": "strings_extract", "calls": 1, "runs": 1},
        ],
    }


def test_equal_counts_are_ordered_by_name_so_the_list_is_stable():
    body = tally_tool_usage([{"zeta": 2, "alpha": 2}], 5)
    assert [row["tool"] for row in body["tools"]] == ["alpha", "zeta"]


def test_a_run_without_an_evidence_block_still_counts_as_a_run_read():
    body = tally_tool_usage([None, {"pe_info": 1}, "not a map"], 20)
    assert body["runs"] == 3
    assert body["tools"] == [{"tool": "pe_info", "calls": 1, "runs": 1}]


def test_a_count_that_is_not_a_positive_integer_is_left_out():
    body = tally_tool_usage(
        [{"a": 0, "b": -1, "c": "3", "d": True, "e": 1.5, "": 2, "f": 1}],
        20,
    )
    assert body["tools"] == [{"tool": "f", "calls": 1, "runs": 1}]


def test_nothing_read_is_an_empty_list_not_an_error():
    assert tally_tool_usage([], 20) == {"limit": 20, "runs": 0, "tools": []}


def test_the_query_reads_only_the_callers_completed_runs_newest_first_and_bounded():
    user_id = uuid.uuid4()
    sql = str(
        tool_usage_query(user_id, 7).compile(
            dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}
        )
    )
    # One JSON path, not the whole summary. SQLAlchemy spells it as a
    # subscript on a server that has them and as `->` on one that does not.
    assert (
        "analysis_reports.run_summary['evidence']['by_tool']" in sql
        or "analysis_reports.run_summary -> 'evidence' -> 'by_tool'" in sql
    )
    assert "SELECT analysis_reports.run_summary FROM" not in sql
    assert f"analysis_jobs.created_by = '{user_id}'" in sql
    assert "analysis_jobs.status = 'completed'" in sql
    assert "ORDER BY analysis_reports.created_at DESC" in sql
    assert "LIMIT 7" in sql


@pytest.fixture
def client() -> TestClient:
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[get_current_user] = lambda: MagicMock(id=uuid.uuid4())
    app.dependency_overrides[get_db] = lambda: MagicMock()
    return TestClient(app)


def test_the_endpoint_answers_with_the_tally_for_the_default_window(client: TestClient):
    usage = AsyncMock(return_value={"limit": TOOL_USAGE_RUNS, "runs": 0, "tools": []})
    with patch("app.api.v1.dashboard.AnalysisService.get_tool_usage", usage):
        resp = client.get("/api/v1/dashboard/tools")
    assert resp.status_code == 200
    assert resp.json() == {"limit": TOOL_USAGE_RUNS, "runs": 0, "tools": []}
    assert usage.await_args.args[1] == TOOL_USAGE_RUNS


def test_the_endpoint_passes_a_window_the_caller_names(client: TestClient):
    usage = AsyncMock(return_value={"limit": 5, "runs": 0, "tools": []})
    with patch("app.api.v1.dashboard.AnalysisService.get_tool_usage", usage):
        resp = client.get("/api/v1/dashboard/tools?limit=5")
    assert resp.status_code == 200
    assert usage.await_args.args[1] == 5


@pytest.mark.parametrize("limit", [0, TOOL_USAGE_MAX_RUNS + 1])
def test_a_window_outside_the_bound_is_refused(client: TestClient, limit: int):
    usage = AsyncMock()
    with patch("app.api.v1.dashboard.AnalysisService.get_tool_usage", usage):
        resp = client.get(f"/api/v1/dashboard/tools?limit={limit}")
    assert resp.status_code == 422
    usage.assert_not_awaited()


def test_the_endpoint_needs_a_signed_in_caller():
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[get_db] = lambda: MagicMock()
    usage = AsyncMock()
    with (
        patch("app.deps.settings.auth_disabled", False),
        patch("app.api.v1.dashboard.AnalysisService.get_tool_usage", usage),
    ):
        resp = TestClient(app).get("/api/v1/dashboard/tools")
    assert resp.status_code == 401
    usage.assert_not_awaited()

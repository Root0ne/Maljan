"""``POST /jobs`` and the system status name a tool this host cannot run (T-329).

The ruling is to warn, not refuse: the job is accepted, and its answer carries
each unavailable tool with the server's reason and the remedy, so an operator
reads "capa is not installed ... uv sync --extra capa" before the run instead
of in its degraded block afterwards.
"""

from __future__ import annotations

import importlib.util
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1.jobs import router as jobs_router
from app.api.v1.system import router as system_router
from app.database import get_db
from app.deps import get_current_user, optional_current_user
from maljan.core.config import Settings
from maljan.tools import capabilities, emulated_strings

CAPA_ROW = {
    "server": "analysis",
    "tool": "capa",
    "reason": "capa is not installed (No module named 'capa')",
    "remediation": "install capa on the host that runs this server: uv sync --extra capa",
    "still_answers": "",
    "degradation_reason": (
        "server.analysis.capa_unavailable(capa is not installed (No module named 'capa')); "
        "install capa on the host that runs this server: uv sync --extra capa"
    ),
    # A library missing, never a setting left unset (T-338).
    "manifest_code": "missing_dependency",
}


@pytest.fixture
def host(monkeypatch: pytest.MonkeyPatch) -> Any:
    """A host with every declared library, data path and FLOSS but what the test removes."""
    missing: set[str] = set()

    def find_spec(name: str, *args: Any, **kwargs: Any) -> Any:
        return None if name in missing else object()

    monkeypatch.setattr(importlib.util, "find_spec", find_spec)
    monkeypatch.setattr(emulated_strings, "find_floss", lambda environ=None: ("floss", ""))
    monkeypatch.setattr(capabilities, "data_held", lambda path, pattern="*": True)
    return missing


def _jobs_client() -> TestClient:
    app = FastAPI()
    app.include_router(jobs_router, prefix="/api/v1")
    app.dependency_overrides[get_current_user] = lambda: MagicMock(id=uuid.uuid4(), role="user")
    app.dependency_overrides[get_db] = lambda: MagicMock()
    return TestClient(app)


def _submit(config: dict[str, Any] | None = None, settings: Settings | None = None) -> Any:
    created = MagicMock(
        id=uuid.uuid4(),
        sample_id=uuid.uuid4(),
        sample_sha256=None,
        sample_filename=None,
        status="pending",
        config=config,
        created_at=datetime.now(UTC),
        started_at=None,
        completed_at=None,
        duration_seconds=None,
        error_message=None,
        roster=None,
        # A stored job has no such column: the answer's warning is the submit's own.
        unavailable_tools=None,
    )
    with (
        patch("app.api.v1.jobs.AnalysisService.create_job", AsyncMock(return_value=created)),
        patch("app.api.v1.jobs._undecryptable_secrets", AsyncMock(return_value={})),
        patch("app.api.v1.jobs.audit.record", AsyncMock()),
        patch("app.api.v1.jobs._unprobed_models_for", AsyncMock(return_value=[])),
        patch("app.api.v1.jobs._unready_providers_for", AsyncMock(return_value=[])),
        patch(
            "app.services.settings_service.effective_core_settings",
            AsyncMock(return_value=settings or Settings()),
        ),
    ):
        return _jobs_client().post(
            "/api/v1/jobs", json={"sample_id": str(uuid.uuid4()), "config": config}
        )


class TestSubmit:
    def test_a_missing_tool_library_is_named_and_the_job_is_still_accepted(
        self, host: set[str]
    ) -> None:
        host.add("capa")
        response = _submit()
        assert response.status_code == 201
        assert response.json()["unavailable_tools"] == [CAPA_ROW]

    def test_nothing_is_named_when_every_tool_is_here(self, host: set[str]) -> None:
        response = _submit()
        assert response.status_code == 201
        assert response.json()["unavailable_tools"] is None

    def test_a_check_that_cannot_be_made_costs_the_submit_nothing(self, host: set[str]) -> None:
        host.add("capa")
        with patch(
            "app.services.tool_availability.unavailable_tools",
            side_effect=RuntimeError("settings unreadable"),
        ):
            response = _submit()
        assert response.status_code == 201
        assert response.json()["unavailable_tools"] is None

    def test_a_warning_that_does_not_validate_never_costs_an_accepted_job_its_answer(
        self, host: set[str]
    ) -> None:
        host.add("capa")
        with patch(
            "app.api.v1.jobs._unavailable_tools_for",
            AsyncMock(return_value=[{"server": "analysis"}]),
        ):
            response = _submit()
        assert response.status_code == 201
        assert response.json()["unavailable_tools"] is None


def _status(user: Any, settings: Settings | None = None) -> dict[str, Any]:
    app = FastAPI()
    app.include_router(system_router, prefix="/api/v1")
    app.dependency_overrides[optional_current_user] = lambda: user
    fake = MagicMock(app_name="Maljan", app_version="0.1.0")
    with (
        patch("app.api.v1.system.settings", fake),
        patch(
            "app.api.v1.system.runtime_config.get",
            AsyncMock(
                side_effect=lambda n: {
                    "enrichment_enabled": False,
                    "mock_mode_allowed": False,
                    "enrichment_sources": {},
                    "enrichment_reputation_servers": False,
                    "enrichment_dedicated_worker": False,
                }[n]
            ),
        ),
        patch(
            "app.api.v1.system.runtime_config.core",
            AsyncMock(return_value=settings or Settings()),
        ),
        patch("app.api.v1.system._enrichment_sources", AsyncMock(return_value=[])),
    ):
        response = TestClient(app).get("/api/v1/system/status")
    assert response.status_code == 200
    return dict(response.json())


class TestStatus:
    def test_a_signed_in_reader_sees_the_unavailable_tool(self, host: set[str]) -> None:
        host.add("capa")
        assert _status(MagicMock(role="user"))["unavailable_tools"] == [CAPA_ROW]

    def test_an_empty_list_when_every_tool_is_here(self, host: set[str]) -> None:
        assert _status(MagicMock(role="user"))["unavailable_tools"] == []

    def test_an_anonymous_reader_is_not_told(self, host: set[str]) -> None:
        host.add("capa")
        assert "unavailable_tools" not in _status(None)


# The real look at a path, kept before the ``host`` fixture stands one in.
_DATA_HELD = capabilities.data_held


def _host_data(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Settings:
    """A project root of ``tmp_path`` holding the Sigma corpus and no capa rules."""
    monkeypatch.setattr(capabilities, "data_held", _DATA_HELD)
    monkeypatch.setattr(capabilities, "_data_root", lambda: tmp_path)
    (tmp_path / "data" / "sigma_rules").mkdir(parents=True)
    (tmp_path / "data" / "sigma_rules" / "r.yml").write_text("title: r\n", encoding="utf-8")
    return Settings()


class TestADeclaredDataPath:
    """The haiku8 shape (T-492): capa installed, its rules directory not fetched."""

    def test_a_rules_directory_never_fetched_is_named_by_the_gate_and_the_status(
        self, host: set[str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        settings = _host_data(tmp_path, monkeypatch)

        response = _submit(settings=settings)
        assert response.status_code == 201
        (row,) = response.json()["unavailable_tools"]
        assert (row["server"], row["tool"]) == ("analysis", "capa")
        # The server's tool reads its default, the worker's reading the setting.
        assert row["reason"] == (
            "data/capa-rules is missing or empty (named by the default); "
            "data/capa-rules is missing or empty (named by static.capa.rules_dir)"
        )
        assert "static.capa.rules_dir" in row["remediation"]
        assert str(tmp_path) not in str(row)
        assert row["manifest_code"] == "missing_dependency"
        assert _status(MagicMock(role="user"), settings)["unavailable_tools"] == [row]

    def test_a_populated_rules_directory_is_not_named(
        self, host: set[str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        settings = _host_data(tmp_path, monkeypatch)
        (tmp_path / "data" / "capa-rules").mkdir()
        (tmp_path / "data" / "capa-rules" / "r.yml").write_text("rule:\n", encoding="utf-8")

        assert _submit(settings=settings).json()["unavailable_tools"] is None
        assert _status(MagicMock(role="user"), settings)["unavailable_tools"] == []

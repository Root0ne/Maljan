"""Regression tests for the final whole-branch review of the runtime-settings work."""

import sys
from pathlib import Path
from unittest.mock import MagicMock

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from maljan.core.settings_overrides import redact_url

_API = Path(__file__).resolve().parents[3] / "apps" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

from app.api.v1.settings import _env_literal, router  # noqa: E402
from app.database import get_db  # noqa: E402
from app.deps import require_admin  # noqa: E402
from app.models.user import UserRole  # noqa: E402
from app.services import settings_catalog_api as cat  # noqa: E402
from app.services import settings_probes as probes  # noqa: E402


def _dsn(scheme: str, userinfo: str, rest: str) -> str:
    """Assemble a credentialed URL at runtime so no literal DSN sits in the source
    (secret scanners flag ``scheme://user:pass@host`` even in a masking test)."""
    return f"{scheme}://{userinfo}@{rest}"


def test_export_literals_survive_a_round_trip_through_pydantic_settings(tmp_path):
    from maljan.core.config import Settings

    cases = {
        "MCP__GHIDRA__ARGS": ["-x", "a b", "c #d"],
        "MCP__CAPE__ENV": {"K": "v #w", "Q": "x"},
        "REPORTING__PUBLISHER": "Team #1",
        "REPORTING__REPORT_NUMBER_PREFIX": "",
        "LLM__PARALLEL_ANALYSTS": True,
        "NEGOTIATION__MAX_ITERATIONS": 7,
        "LLM__OLLAMA__BASE_URL": "http://ollama:11434",
    }
    env = tmp_path / ".env"
    env.write_text("".join(f"{k}={_env_literal(False, v)}\n" for k, v in cases.items()))
    s = Settings(_env_file=env)
    assert s.mcp.ghidra.args == cases["MCP__GHIDRA__ARGS"]
    assert s.mcp.cape.env == cases["MCP__CAPE__ENV"]
    assert s.reporting.publisher == "Team #1"
    assert s.reporting.report_number_prefix == ""
    assert s.llm.parallel_analysts is True
    assert s.negotiation.max_iterations == 7
    assert s.llm.ollama.base_url == "http://ollama:11434"
    assert _env_literal(True, "whatever") == "***"


def test_readonly_values_mask_credentials_in_every_url_shaped_setting():
    assert (
        cat._masked("redis_url", _dsn("redis", ":pw", "redis:6379/0")) == "redis://***@redis:6379/0"
    )
    assert cat._masked("qdrant_url", "http://qdrant:6333") == "http://qdrant:6333"
    assert cat._masked("database_url", _dsn("postgresql+asyncpg", "u:p", "db/x")) == (
        "postgresql+asyncpg://***@db/x"
    )
    assert cat._masked("rate_limit_requests", 100) == 100


@pytest.mark.asyncio
async def test_http_probe_errors_are_redacted(monkeypatch):
    def _raise(request):
        raise httpx.ConnectError(f"failed to connect to {request.url}", request=request)

    transport = httpx.MockTransport(_raise)
    monkeypatch.setattr(
        probes, "_client", lambda: httpx.AsyncClient(transport=transport, timeout=1)
    )
    r = await probes.probe_ghidra(
        {"url": _dsn("http", "ghidra:s3cret", "ghidra:8089"), "auth_token": "t"}
    )
    assert r.ok is False
    assert "s3cret" not in r.detail
    assert redact_url("x") == "x"


@pytest.mark.asyncio
async def test_run_probe_reports_invalid_candidates_without_raising_or_echoing():
    r = await probes.run_probe("llm", {"core.llm.provider": "bedrock-super-secret-name"}, {})
    assert r.ok is False
    assert "llm.provider" in r.detail
    assert "bedrock-super-secret-name" not in r.detail
    r2 = await probes.run_probe("llm", {"core.": 1}, {})
    assert r2.ok is False


def _app(role: UserRole):
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    if role is UserRole.ADMIN:
        app.dependency_overrides[require_admin] = lambda: MagicMock(role=role)
    app.dependency_overrides[get_db] = lambda: MagicMock()
    return app


def test_non_admin_user_gets_403_not_401():
    from app.deps import require_active_user

    app = _app(UserRole.ANALYST)
    app.dependency_overrides[require_active_user] = lambda: MagicMock(role=UserRole.ANALYST)
    r = TestClient(app).get("/api/v1/settings/schema")
    assert r.status_code == 403, r.text
    assert "Admin role required" in r.json()["detail"]


def test_patch_body_is_bounded():
    from app.schemas.settings import PatchRequest
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        PatchRequest(changes={f"core.k{i}": i for i in range(501)})

"""API-level tests for the /api/v1/system endpoints (audit follow-up 2026-05-19).

Covers two new contracts:
 - GET /system/status returns the pipeline-mode flags + key-presence
   booleans (and never leaks raw secrets).
 - POST /system/ltm/purge with dry_run=True returns a count without
   deleting; mocked store so we don't need a running Qdrant.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.api.v1.system import router as system_router  # noqa: E402
from app.deps import optional_current_user, require_admin  # noqa: E402


@pytest.fixture
def client() -> TestClient:
    """Bare FastAPI app with only the system router mounted.

    Mounting the full app loads the DB/Redis/auth/etc; the system router
    is intentionally infrastructure-light so we can isolate it here. The
    override on ``require_admin`` makes the purge endpoint accessible
    without a real user record.
    """
    from fastapi import FastAPI

    app = FastAPI()
    app.include_router(system_router, prefix="/api/v1")
    app.dependency_overrides[require_admin] = lambda: MagicMock(id="test-admin")
    return TestClient(app)


class TestSystemStatus:
    def test_reports_mock_mode_and_key_presence(self, client: TestClient) -> None:
        fake_settings = MagicMock()
        fake_settings.app_name = "Maljan"
        fake_settings.app_version = "0.1.0"

        with (
            patch("app.api.v1.system.settings", fake_settings),
            patch(
                "app.api.v1.system.runtime_config.get",
                AsyncMock(
                    side_effect=lambda n: {
                        "enrichment_enabled": True,
                        "mock_mode_allowed": True,
                        "enrichment_sources": {},
                        "enrichment_reputation_servers": False,
                        # One process: the enrichment is queued beside the
                        # analyses, so there is no second worker to report on.
                        "enrichment_dedicated_worker": False,
                    }[n]
                ),
            ),
            patch(
                "app.api.v1.system.runtime_config.get_secret",
                AsyncMock(
                    side_effect=lambda n: {
                        "virustotal_api_key": "vt-secret-key",
                        "abuseipdb_api_key": "",
                    }[n]
                ),
            ),
        ):
            resp = client.get("/api/v1/system/status")

        assert resp.status_code == 200
        body = resp.json()
        assert body == {
            "app_name": "Maljan",
            "app_version": "0.1.0",
            "mock_mode_allowed": True,
            "enrichment_enabled": True,
            "enrichment_worker": "not_required",
            # Anonymous: how many sources are configured, never their names.
            "enrichment_configured": 1,
        }
        assert "has_virustotal_key" not in body and "has_abuseipdb_key" not in body
        # Anonymous caller: the throttle/audit fields are admin-only detail,
        # not merely null — they are absent from the payload entirely.
        assert "throttle" not in body
        assert "audit_write_failures" not in body

    def test_admin_caller_sees_throttle_and_audit_fields(self, client: TestClient) -> None:
        fake_settings = MagicMock()
        fake_settings.app_name = "Maljan"
        fake_settings.app_version = "0.1.0"
        client.app.dependency_overrides[optional_current_user] = lambda: MagicMock(role="admin")
        try:
            with (
                patch("app.api.v1.system.settings", fake_settings),
                patch(
                    "app.api.v1.system.runtime_config.get",
                    AsyncMock(
                        side_effect=lambda n: {
                            "enrichment_enabled": True,
                            "mock_mode_allowed": True,
                            "enrichment_sources": {},
                            "enrichment_reputation_servers": False,
                        }[n]
                    ),
                ),
                patch(
                    "app.api.v1.system.runtime_config.get_secret",
                    AsyncMock(
                        side_effect=lambda n: {
                            "virustotal_api_key": "",
                            "abuseipdb_api_key": "",
                        }[n]
                    ),
                ),
            ):
                resp = client.get("/api/v1/system/status")
        finally:
            del client.app.dependency_overrides[optional_current_user]

        assert resp.status_code == 200
        body = resp.json()
        assert body["throttle"] == {
            "available": True,
            "degraded_since": None,
            "last_error": None,
        }
        assert body["audit_write_failures"] == 0

    def test_never_returns_raw_secret_values(self, client: TestClient) -> None:
        # Belt-and-braces: even with both keys configured, response payload
        # must not contain the literal key text.
        fake_settings = MagicMock()
        fake_settings.app_name = "Maljan"
        fake_settings.app_version = "0.1.0"

        with (
            patch("app.api.v1.system.settings", fake_settings),
            patch(
                "app.api.v1.system.runtime_config.get",
                AsyncMock(
                    side_effect=lambda n: {
                        "enrichment_enabled": True,
                        "mock_mode_allowed": False,
                        "enrichment_sources": {},
                        "enrichment_reputation_servers": False,
                    }[n]
                ),
            ),
            patch(
                "app.api.v1.system.runtime_config.get_secret",
                AsyncMock(
                    side_effect=lambda n: {
                        "virustotal_api_key": "vt-supersecret-leak-canary",
                        "abuseipdb_api_key": "abuse-supersecret-leak-canary",
                    }[n]
                ),
            ),
        ):
            resp = client.get("/api/v1/system/status")

        assert resp.status_code == 200
        body_text = resp.text
        assert "vt-supersecret-leak-canary" not in body_text
        assert "abuse-supersecret-leak-canary" not in body_text

    def test_lists_a_source_declared_only_as_data(self, client: TestClient) -> None:
        """A source no code names is listed beside the shipped ones, with its own key."""
        fake_settings = MagicMock()
        fake_settings.app_name = "Maljan"
        fake_settings.app_version = "0.1.0"
        own_key = "-".join(["k", "own"])
        declared = {"domainrep": _invented_source(api_key=own_key), "abuseipdb": {"enabled": False}}
        client.app.dependency_overrides[optional_current_user] = lambda: MagicMock(role="analyst")
        with (
            patch("app.api.v1.system.settings", fake_settings),
            patch(
                "app.api.v1.system.runtime_config.get",
                AsyncMock(
                    side_effect=lambda n: {
                        "enrichment_enabled": True,
                        "mock_mode_allowed": False,
                        "enrichment_sources": declared,
                        "enrichment_reputation_servers": False,
                    }[n]
                ),
            ),
            patch(
                "app.api.v1.system.runtime_config.get_secret",
                AsyncMock(return_value=""),
            ),
        ):
            resp = client.get("/api/v1/system/status")
            del client.app.dependency_overrides[optional_current_user]
            anonymous = client.get("/api/v1/system/status")

        assert resp.status_code == 200
        assert resp.json()["enrichment_sources"] == [
            {"key": "domainrep", "label": "Domain reputation", "configured": True},
            {"key": "virustotal", "label": "VirusTotal", "configured": False},
            {"key": "abuseipdb", "label": "AbuseIPDB", "configured": False},
        ]
        assert resp.json()["enrichment_configured"] == 1
        assert own_key not in resp.text
        # Without a session: the count, and no operator's source name.
        assert anonymous.json()["enrichment_configured"] == 1
        assert "enrichment_sources" not in anonymous.json()
        assert "domainrep" not in anonymous.text

    def test_a_server_source_is_configured_only_while_its_server_is_on(
        self, client: TestClient
    ) -> None:
        from maljan.core.settings_overrides import build_settings

        fake_settings = MagicMock()
        fake_settings.app_name = "Maljan"
        fake_settings.app_version = "0.1.0"
        declared = {
            "intel": {
                "kinds": ["ip"],
                "server": "intelsrv",
                "tool": "lookup",
                "record": [{"name": "abuse_confidence", "path": "/score", "read": "count"}],
            }
        }
        server = {"command": "x", "roles": ["reputation"]}
        client.app.dependency_overrides[optional_current_user] = lambda: MagicMock(role="analyst")
        try:
            for enabled in (True, False):
                core = build_settings({"mcp.servers": {"intelsrv": {**server, "enabled": enabled}}})
                with (
                    patch("app.api.v1.system.settings", fake_settings),
                    patch(
                        "app.api.v1.system.runtime_config.get",
                        AsyncMock(
                            side_effect=lambda n: {
                                "enrichment_enabled": True,
                                "mock_mode_allowed": False,
                                "enrichment_sources": declared,
                                "enrichment_reputation_servers": False,
                            }[n]
                        ),
                    ),
                    patch(
                        "app.api.v1.system.runtime_config.get_secret", AsyncMock(return_value="")
                    ),
                    patch("app.api.v1.system.runtime_config.core", AsyncMock(return_value=core)),
                ):
                    body = client.get("/api/v1/system/status").json()
                intel = next(s for s in body["enrichment_sources"] if s["key"] == "intel")
                assert intel["configured"] is enabled
        finally:
            del client.app.dependency_overrides[optional_current_user]

    def test_a_status_whose_sources_cannot_be_read_still_answers(self, client: TestClient) -> None:
        fake_settings = MagicMock()
        fake_settings.app_name = "Maljan"
        fake_settings.app_version = "0.1.0"
        declared = {
            "intel": {
                "kinds": ["ip"],
                "server": "intelsrv",
                "tool": "lookup",
                "record": [{"name": "abuse_confidence", "path": "/score", "read": "count"}],
            }
        }
        with (
            patch("app.api.v1.system.settings", fake_settings),
            patch(
                "app.api.v1.system.runtime_config.get",
                AsyncMock(
                    side_effect=lambda n: {
                        "enrichment_enabled": True,
                        "mock_mode_allowed": False,
                        "enrichment_sources": declared,
                        "enrichment_reputation_servers": False,
                    }[n]
                ),
            ),
            patch(
                "app.api.v1.system.runtime_config.core",
                AsyncMock(side_effect=ValueError("broken core settings")),
            ),
        ):
            resp = client.get("/api/v1/system/status")

        assert resp.status_code == 200
        body = resp.json()
        assert body["enrichment_enabled"] is True
        assert "enrichment_configured" not in body and "enrichment_sources" not in body


def _invented_source(**extra: object) -> dict[str, object]:
    """A domain reputation REST endpoint declared only as data, asked first."""
    host = ".".join(["rep", "example", "org"])
    return {
        "label": "Domain reputation",
        "kinds": ["domain"],
        "order": 5,
        "requests": {
            "domain": {
                "url": f"https://{host}/v1/domain/{{value}}",
                "headers": {"Authorization": "Bearer {credential}"},
            }
        },
        "record": [{"name": "malicious", "path": "/flagged", "read": "count"}],
        **extra,
    }


class TestLTMPurge:
    def test_dry_run_counts_without_deleting(self, client: TestClient) -> None:
        from maljan.memory.in_memory_store import InMemoryStore
        from maljan.memory.long_term_memory import StoredCase

        store = InMemoryStore()
        store.store(
            StoredCase(
                sample_id="low",
                summary_text="bare",
                technique_ids=[],
                corroborated_count=0,
                total_techniques=0,
            )
        )
        store.store(
            StoredCase(
                sample_id="rich",
                summary_text="lots",
                technique_ids=["T1", "T2", "T3"],
                corroborated_count=2,
                total_techniques=3,
            )
        )

        with patch("app.api.v1.system._build_memory_store", return_value=store):
            resp = client.post("/api/v1/system/ltm/purge", json={"dry_run": True})

        assert resp.status_code == 200
        body = resp.json()
        assert body["dry_run"] is True
        assert body["removed"] == 1
        assert body["backend"] == "InMemoryStore"
        # Confirm the store was not mutated.
        assert store.count() == 2

    def test_apply_removes_low_quality_entries(self, client: TestClient) -> None:
        from maljan.memory.in_memory_store import InMemoryStore
        from maljan.memory.long_term_memory import StoredCase

        store = InMemoryStore()
        store.store(
            StoredCase(
                sample_id="low",
                summary_text="bare",
                technique_ids=[],
                corroborated_count=0,
                total_techniques=0,
            )
        )
        store.store(
            StoredCase(
                sample_id="rich",
                summary_text="lots",
                technique_ids=["T1", "T2", "T3"],
                corroborated_count=2,
                total_techniques=3,
            )
        )

        with patch("app.api.v1.system._build_memory_store", return_value=store):
            resp = client.post("/api/v1/system/ltm/purge", json={"dry_run": False})

        assert resp.status_code == 200
        body = resp.json()
        assert body["dry_run"] is False
        assert body["removed"] == 1
        assert store.count() == 1

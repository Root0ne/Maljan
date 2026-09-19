"""``/iocs`` says where each row came from, and defaults to what may be published.

The service attached a ``source`` to every domain row — *"a name the sandbox
resolved and a run of bytes shaped like a hostname are not the same claim, and
this feed presented them identically"* — and ``IOCEntry`` declared only four
fields, so FastAPI's ``response_model`` dropped it on the way out. A live run's
seven uncorroborated string-derived names and seventeen cut-off URLs shipped
looking exactly like something the sandbox had watched.

Driven through the route rather than the service, because the dropping happened
in the response model and only the route exercises it.
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1 import reports as module

# One name the sandbox resolved, one the string sweep produced, and the same
# pair for an address and a URL.
NETWORK = {
    "domains": [
        {
            "fqdn": "c2.example.com",
            "source": "sandbox",
            "is_suspicious": True,
            "reason": "resolved by the sample",
            "queried_pids": [],
            "resolved_ips": [],
        },
        {
            "fqdn": "rosoft.com",
            "source": "strings",
            "is_suspicious": False,
            "reason": None,
            "queried_pids": [],
            "resolved_ips": [],
        },
    ],
    "ips": [
        {"address": "185.99.133.7", "source": "sandbox", "is_suspicious": True},
        {"address": "6.0.0.0", "source": "strings", "is_suspicious": False},
    ],
    "urls": [
        {"url": "http://c2.example.com/gate", "source": "sandbox", "method": "GET"},
        {"url": "http://localho", "source": "strings", "method": "GET"},
    ],
    "user_agents": ["Mozilla/5.0"],
    "ja3_fingerprints": [],
    "ja3s_fingerprints": [],
}

REPORT_ID = uuid.uuid4()


def _malware_report() -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "generated_at": "2026-05-16T00:00:00+00:00",
        "verdict": "Malware",
        "identity": {
            "hashes": {"sha256": "f" * 64},
            "file_name": "sample.exe",
            "file_type": "PE",
            "signing": {"is_signed": False},
        },
        "network": NETWORK,
        "executive_summary": "",
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
    # The router carries its own ``/reports`` prefix.
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


class TestTheSourceReachesTheClient:
    def test_a_domain_row_carries_it(self, client: TestClient) -> None:
        rows = _rows(client, "?include=all&kind=domain")

        assert {row["value"]: row["source"] for row in rows} == {
            "c2.example.com": "sandbox",
            "rosoft.com": "strings",
        }

    def test_an_address_and_a_url_carry_it_too(self, client: TestClient) -> None:
        rows = _rows(client, "?include=all")
        by_value = {row["value"]: row["source"] for row in rows}

        assert by_value["6.0.0.0"] == "strings"
        assert by_value["http://c2.example.com/gate"] == "sandbox"

    def test_the_sample_s_own_hash_says_where_it_came_from(self, client: TestClient) -> None:
        rows = _rows(client, "?kind=hash")

        assert rows and all(row["source"] == "identity" for row in rows)


class TestWhatTheFeedReturnsByDefault:
    def test_only_what_the_publish_rule_would_publish(self, client: TestClient) -> None:
        values = {row["value"] for row in _rows(client)}

        assert "c2.example.com" in values
        assert "185.99.133.7" in values
        assert "rosoft.com" not in values
        assert "6.0.0.0" not in values
        assert "http://localho" not in values

    def test_every_returned_row_says_it_is_published(self, client: TestClient) -> None:
        assert all(row["published"] for row in _rows(client))

    def test_the_total_counts_what_was_returned(self, client: TestClient) -> None:
        response = client.get(f"/api/v1/reports/{REPORT_ID}/iocs")

        body = response.json()
        assert body["total"] == len(body["items"])


class TestTheWiderModes:
    def test_all_returns_both_with_the_flag(self, client: TestClient) -> None:
        rows = {row["value"]: row["published"] for row in _rows(client, "?include=all")}

        assert rows["c2.example.com"] is True
        assert rows["rosoft.com"] is False
        assert rows["http://localho"] is False

    def test_unpublished_returns_only_the_withheld(self, client: TestClient) -> None:
        rows = _rows(client, "?include=unpublished")

        assert {row["value"] for row in rows} == {"rosoft.com", "6.0.0.0", "http://localho"}
        assert not any(row["published"] for row in rows)

    def test_a_mode_the_route_does_not_know_is_refused(self, client: TestClient) -> None:
        response = client.get(f"/api/v1/reports/{REPORT_ID}/iocs?include=everything")

        assert response.status_code == 422

    def test_the_kind_filter_still_narrows_in_every_mode(self, client: TestClient) -> None:
        for mode in ("published", "unpublished", "all"):
            rows = _rows(client, f"?include={mode}&kind=ip")
            assert {row["kind"] for row in rows} <= {"ip"}, mode

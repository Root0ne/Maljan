"""Two answers the console could not give: who did it, and where it was tried.

An audit row carried the actor's id and nothing else, so the log's actor column
showed eight characters of a UUID — an audit log that answers "who did this"
with "look it up somewhere else". And a probe that could not read a catalogue
said "model list: connection refused" whichever endpoint it had tried, which an
operator with two servers staged cannot act on.
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1.audit import router
from app.database import get_db
from app.deps import require_admin


def _log(user_id: uuid.UUID | None) -> MagicMock:
    from datetime import UTC, datetime

    row = MagicMock()
    row.id = uuid.uuid4()
    row.user_id = user_id
    # The ORM row carries no actor of its own; the route fills it in.
    row.actor = None
    row.action = "settings.update"
    row.resource_type = "settings"
    row.resource_id = "core.llm.provider"
    row.details = {"keys": ["core.llm.provider"]}
    row.ip_address = "127.0.0.1"
    row.created_at = datetime.now(UTC)
    return row


def _client(logs: list[MagicMock], users: list[tuple[Any, str, str]]) -> TestClient:
    db = MagicMock()
    answers: list[Any] = []

    logs_result = MagicMock()
    logs_result.scalars.return_value.all.return_value = logs
    count_result = MagicMock()
    count_result.scalar.return_value = len(logs)
    users_result = MagicMock()
    users_result.all.return_value = users

    async def _execute(statement: Any) -> Any:
        answers.append(statement)
        text = str(statement).lower()
        if "count(" in text:
            return count_result
        if "users" in text:
            return users_result
        return logs_result

    db.execute = _execute
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[require_admin] = lambda: MagicMock(id=uuid.uuid4())
    app.dependency_overrides[get_db] = lambda: db
    return TestClient(app)


class TestTheAuditRowNamesItsActor:
    def test_the_name_the_users_list_shows(self) -> None:
        actor = uuid.uuid4()
        client = _client([_log(actor)], [(actor, "Ada Lovelace", "ada@example.com")])

        body = client.get("/api/v1/audit/logs").json()

        assert body["items"][0]["actor"] == "Ada Lovelace"
        assert body["items"][0]["user_id"] == str(actor)

    def test_an_account_with_no_name_falls_back_to_the_local_part(self) -> None:
        actor = uuid.uuid4()
        client = _client([_log(actor)], [(actor, "", "ada@example.com")])

        body = client.get("/api/v1/audit/logs").json()

        assert body["items"][0]["actor"] == "ada"
        assert "@" not in body["items"][0]["actor"], "the domain is not the console's business"

    def test_an_event_with_no_principal_names_nobody(self) -> None:
        """A failed sign-in, a lockout, a replayed refresh token."""
        client = _client([_log(None)], [])

        body = client.get("/api/v1/audit/logs").json()

        assert body["items"][0]["actor"] is None

    def test_a_deleted_user_is_not_resurrected_from_the_row(self) -> None:
        client = _client([_log(uuid.uuid4())], [])

        body = client.get("/api/v1/audit/logs").json()

        assert body["items"][0]["actor"] is None

    def test_one_query_names_a_whole_page(self) -> None:
        """Twenty rows by one actor must not be twenty reads."""
        actor = uuid.uuid4()
        reads: list[str] = []
        logs = [_log(actor) for _ in range(20)]
        client = _client(logs, [(actor, "Ada Lovelace", "ada@example.com")])
        original = client.app.dependency_overrides[get_db]

        def _counting_db() -> Any:
            db = original()
            execute = db.execute

            async def _seen(statement: Any) -> Any:
                if "users" in str(statement).lower():
                    reads.append("users")
                return await execute(statement)

            db.execute = _seen
            return db

        client.app.dependency_overrides[get_db] = _counting_db
        body = client.get("/api/v1/audit/logs").json()

        assert len(body["items"]) == 20
        assert reads == ["users"]


class TestAProbeSaysWhereItWent:
    @pytest.mark.asyncio
    async def test_a_catalogue_that_refused_names_its_endpoint(self) -> None:
        import app.services.settings_probes as probes

        async def _refused(url: str, headers: Any = None) -> tuple[bool, str, Any]:
            return False, "connection refused", None

        original = probes._get
        probes._get = _refused  # type: ignore[assignment]
        try:
            result = await probes._probe_llm_ollama({"ollama_base_url": "http://box:11434"})
        finally:
            probes._get = original  # type: ignore[assignment]

        assert not result.ok
        assert "http://box:11434" in result.detail
        assert "connection refused" in result.detail

    @pytest.mark.asyncio
    async def test_the_label_carries_no_credential_and_no_path(self) -> None:
        import app.services.settings_probes as probes
        from tests.credential_shapes import lowercase_body

        secret = lowercase_body(28)

        async def _refused(url: str, headers: Any = None) -> tuple[bool, str, Any]:
            return False, "connection refused", None

        original = probes._get
        probes._get = _refused  # type: ignore[assignment]
        try:
            result = await probes._probe_llm_openai(
                {"base_url": f"http://user:{secret}@llm.internal:8080/v1", "api_key": "x"}
            )
        finally:
            probes._get = original  # type: ignore[assignment]

        assert not result.ok
        assert secret not in result.detail
        assert "llm.internal:8080" in result.detail
        assert "/v1" not in result.detail

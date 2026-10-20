"""The Low findings of the 2026-10-19 audit of the API, its worker and its services.

One test per finding, each written to fail on the code the audit read:

* API-L1 a busy WebSocket outlives its token.
* API-L2 the live feed is capped near ten events a second.
* API-L3 the WebSocket tells a missing job from somebody else's.
* API-L4 the anonymous deep health check serves a driver's own error text.
* API-L5 an LTM purge blocks the loop and leaves no audit row.
* API-L6 a sandbox-report delete removes the object first and ignores a run
  that is using the report.
* SW-L3 ``build_redis_settings`` ignores ``rediss://`` and keeps a password
  percent-encoded.
* SW-L4 a float is accepted for an integer setting.
* SW-L5 an undecryptable secret row is dropped and the job runs on a default.
* SW-L6 a sealed job whose ledger rows are gone reads ``not_sealed``.
* SW-L7 a provider's probe detail reaches a 422 with its URL userinfo.
* SW-L8 the agent map is checked against the stored server map, not the staged
  one.
* SW-L9 the sample mirrors are copied on the event loop.
"""

from __future__ import annotations

import threading
import time
import uuid
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.testclient import TestClient

from tests.credential_shapes import password

# ── API-L1 ───────────────────────────────────────────────────────────


def _owner_session(user_id: uuid.UUID) -> MagicMock:
    job = MagicMock()
    job.created_by = user_id
    job.token_generation = 0
    result = MagicMock()
    result.scalar_one_or_none.return_value = job
    session = AsyncMock()
    session.execute = AsyncMock(return_value=result)
    return session


@pytest.mark.asyncio
async def test_a_client_that_keeps_pinging_loses_its_socket_when_the_token_expires() -> None:
    from app.api.ws import ws_analysis

    user_id = uuid.uuid4()
    ws = MagicMock(spec=WebSocket)
    ws.headers = {"sec-websocket-protocol": "maljan.v1, maljan.v1.tok"}
    ws.close = AsyncMock()
    ws.accept = AsyncMock()
    ws.send_text = AsyncMock()
    # The page pings every few seconds: the read never times out, so the
    # heartbeat branch that used to be the only one to read ``exp`` never ran.
    ws.receive_text = AsyncMock(side_effect=["ping", "ping", "ping", WebSocketDisconnect()])
    payload = {"sub": str(user_id), "type": "access", "exp": time.time() - 5}

    with (
        patch("app.api.ws.decode_token", return_value=payload),
        patch("app.api.ws.async_session_factory") as factory,
        patch("app.api.ws.manager") as manager,
    ):
        factory.return_value.__aenter__ = AsyncMock(return_value=_owner_session(user_id))
        factory.return_value.__aexit__ = AsyncMock(return_value=False)
        manager.connect = AsyncMock()
        manager.disconnect = AsyncMock()
        await ws_analysis(ws, str(uuid.uuid4()))

    ws.close.assert_awaited_once()
    assert ws.close.await_args.kwargs["code"] == 1008
    assert "token expired" in ws.close.await_args.kwargs["reason"]
    assert ws.receive_text.await_count == 1, "the expired token was served once more"


# ── API-L2 ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_live_feed_is_not_paced_at_ten_events_a_second() -> None:
    from app.api import ws as ws_module

    count = 40
    manager = ws_module.ConnectionManager()
    job_id = "job-1"
    manager._active[job_id] = [MagicMock()]
    sent: list[str] = []

    async def _broadcast(_job: str, message: str) -> None:
        sent.append(message)
        if len(sent) == count:
            manager._active.clear()

    manager.broadcast = _broadcast  # type: ignore[method-assign]
    queue = [{"type": "message", "data": f"e{i}".encode()} for i in range(count)]

    pubsub = MagicMock()
    pubsub.subscribe = AsyncMock()
    pubsub.unsubscribe = AsyncMock()
    pubsub.aclose = AsyncMock()
    pubsub.get_message = AsyncMock(side_effect=lambda **_: queue.pop(0) if queue else None)
    conn = MagicMock()
    conn.pubsub.return_value = pubsub
    conn.aclose = AsyncMock()

    started = time.monotonic()
    with patch.object(ws_module.aioredis, "from_url", return_value=conn):
        await manager._redis_listener(job_id)
    elapsed = time.monotonic() - started

    assert len(sent) == count
    # A pause of 0.1 s after each message made this take four seconds.
    assert elapsed < 1.5, f"{count} queued events took {elapsed:.1f}s to forward"


# ── API-L3 ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_job_that_is_not_there_and_one_that_is_not_yours_are_refused_alike() -> None:
    from app.api.ws import ws_analysis

    user_id = uuid.uuid4()
    reasons: list[str] = []
    for owner in (None, uuid.uuid4()):
        ws = MagicMock(spec=WebSocket)
        ws.headers = {"sec-websocket-protocol": "maljan.v1, maljan.v1.tok"}
        ws.close = AsyncMock()
        ws.accept = AsyncMock()
        account = MagicMock(is_active=True, token_generation=0)
        first = MagicMock()
        first.scalar_one_or_none.return_value = account
        job = None if owner is None else MagicMock(created_by=owner, token_generation=0)
        second = MagicMock()
        second.scalar_one_or_none.return_value = job
        session = AsyncMock()
        session.execute = AsyncMock(side_effect=[first, second])
        with (
            patch(
                "app.api.ws.decode_token",
                return_value={"sub": str(user_id), "type": "access"},
            ),
            patch("app.api.ws.async_session_factory") as factory,
        ):
            factory.return_value.__aenter__ = AsyncMock(return_value=session)
            factory.return_value.__aexit__ = AsyncMock(return_value=False)
            await ws_analysis(ws, str(uuid.uuid4()))
        reasons.append(ws.close.await_args.kwargs["reason"])

    assert reasons[0] == reasons[1]


# ── API-L4 ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_deep_health_check_serves_the_kind_of_failure_not_the_drivers_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import app.main as main_mod

    secret_host = ".".join(["10", "9", "8", "7"])

    async def _boom() -> None:
        raise ConnectionError(f'password authentication failed for user "maljan" at {secret_host}')

    async def _ok() -> None:
        return None

    monkeypatch.setattr(main_mod, "_probe_database", _boom)
    monkeypatch.setattr(main_mod, "_probe_redis", _ok)
    monkeypatch.setattr(main_mod, "_probe_minio", _ok)
    monkeypatch.setattr(main_mod, "_probe_memory", _ok)

    components = await main_mod._probe_components()

    assert components["database"] == {"ok": False, "error": "ConnectionError"}
    assert secret_host not in str(components)


# ── API-L5 ───────────────────────────────────────────────────────────


class _ThreadNoting:
    """An in-memory store that records which thread each purge ran on."""

    def __init__(self) -> None:
        from maljan.memory.in_memory_store import InMemoryStore

        self.inner = InMemoryStore()
        self.threads: list[int] = []
        self.closed_on: list[int] = []

    def purge_low_quality(self, **kwargs: Any) -> int:
        self.threads.append(threading.get_ident())
        return int(self.inner.purge_low_quality(**kwargs))

    def close(self) -> None:
        self.closed_on.append(threading.get_ident())


def _system_client() -> TestClient:
    from app.api.v1.system import router
    from app.deps import require_admin

    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[require_admin] = lambda: MagicMock(id=uuid.uuid4())
    return TestClient(app)


def test_an_ltm_purge_runs_off_the_loop_and_leaves_an_audit_row() -> None:
    store = _ThreadNoting()
    record = AsyncMock()
    with (
        patch("app.api.v1.system._build_memory_store", return_value=store),
        patch("app.api.v1.system.audit.record", record),
        patch("app.api.v1.system.end_read_transaction", AsyncMock()),
    ):
        response = _system_client().post("/api/v1/system/ltm/purge", json={"dry_run": False})

    assert response.status_code == 200, response.text
    assert store.threads and store.threads[0] != threading.get_ident()
    record.assert_awaited_once()
    assert record.await_args.args[0] == "ltm.purge"
    assert record.await_args.kwargs["details"]["backend"] == "_ThreadNoting"


def test_a_dry_run_purge_deletes_nothing_and_is_not_audited() -> None:
    record = AsyncMock()
    with (
        patch("app.api.v1.system._build_memory_store", return_value=_ThreadNoting()),
        patch("app.api.v1.system.audit.record", record),
        patch("app.api.v1.system.end_read_transaction", AsyncMock()),
    ):
        response = _system_client().post("/api/v1/system/ltm/purge", json={"dry_run": True})

    assert response.status_code == 200
    record.assert_not_awaited()


# ── API-L6 ───────────────────────────────────────────────────────────


def _delete_client(db: MagicMock, monkeypatch: pytest.MonkeyPatch) -> tuple[TestClient, Any]:
    from app.api.v1 import sandbox_reports as module
    from app.database import get_db
    from app.deps import require_active_user

    user = MagicMock(id=uuid.uuid4())
    sample = MagicMock(id=uuid.uuid4(), sha256="a" * 64, uploaded_by=user.id)
    monkeypatch.setattr(module, "_load_sample", MagicMock(return_value=sample))
    monkeypatch.setattr(module, "_minio_client", lambda: MagicMock())
    app = FastAPI()
    app.include_router(module.router, prefix="/api/v1")
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[require_active_user] = lambda: user
    return TestClient(app), sample


def _results(row: Any, in_flight: int) -> list[Any]:
    found = MagicMock()
    found.scalar_one_or_none.return_value = row
    count = MagicMock()
    count.scalar.return_value = in_flight
    return [found, count, None]


def test_a_sandbox_report_row_is_deleted_and_committed_before_its_object(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.api.v1 import sandbox_reports as module

    events: list[str] = []
    row = MagicMock(id=uuid.uuid4(), storage_path="sandbox-reports/aa/x.json", format="cape2")
    answers = _results(row, 0)

    async def _execute(_statement: Any) -> Any:
        events.append("execute")
        return answers.pop(0)

    async def _commit() -> None:
        events.append("commit")

    db = MagicMock()
    db.execute = _execute
    db.commit = _commit
    monkeypatch.setattr(module.object_store, "remove", lambda *_a, **_k: events.append("remove"))
    monkeypatch.setattr(module.audit, "record", AsyncMock())
    client, sample = _delete_client(db, monkeypatch)

    response = client.delete(f"/api/v1/samples/{sample.id}/sandbox-reports/{row.id}")

    assert response.status_code == 204, response.text
    assert "commit" in events and "remove" in events
    assert events.index("commit") < events.index("remove")


def test_a_sandbox_report_a_running_job_uses_is_not_deleted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.api.v1 import sandbox_reports as module

    removed: list[str] = []
    row = MagicMock(id=uuid.uuid4(), storage_path="sandbox-reports/aa/x.json", format="cape2")
    db = MagicMock()
    db.execute = AsyncMock(side_effect=_results(row, 1))
    db.commit = AsyncMock()
    monkeypatch.setattr(module.object_store, "remove", lambda *_a, **_k: removed.append("x"))
    client, sample = _delete_client(db, monkeypatch)

    response = client.delete(f"/api/v1/samples/{sample.id}/sandbox-reports/{row.id}")

    assert response.status_code == 409
    assert "cancel it" in response.json()["detail"]
    assert removed == []
    db.commit.assert_not_awaited()


# ── SW-L3 ────────────────────────────────────────────────────────────


def test_a_rediss_url_is_dialled_over_tls() -> None:
    from app.worker.queues import build_redis_settings

    assert build_redis_settings("rediss://queue.example.org:6380/2").ssl is True
    assert build_redis_settings("redis://queue.example.org:6379/2").ssl is False


def test_a_percent_encoded_redis_password_is_decoded() -> None:
    from urllib.parse import quote

    from app.worker.queues import build_redis_settings

    plain = password() + "@:/"
    parsed = build_redis_settings(f"redis://user:{quote(plain, safe='')}@queue.example.org:6379/0")

    assert parsed.password == plain
    assert parsed.username == "user"


# ── SW-L4 ────────────────────────────────────────────────────────────


def test_a_float_is_not_an_integer_setting() -> None:
    from app.services.settings_catalog_api import catalog_index, validate_editable_api_value

    entry = next(e for e in catalog_index().values() if e.namespace == "api" and e.type == "int")

    assert validate_editable_api_value(entry, 1.5) == "Input should be a valid integer"
    # An integral float is what installs already store and send back as shown:
    # it must not block a later save.
    assert validate_editable_api_value(entry, 30.0) is None
    assert validate_editable_api_value(entry, True) == "Input should be a valid number"
    floor = entry.minimum if entry.minimum is not None else 0
    assert validate_editable_api_value(entry, int(floor) + 1) is None


# ── SW-L5 ────────────────────────────────────────────────────────────


def _secret_row(key: str) -> Any:
    return SimpleNamespace(key=key, value="gAAAA-not-decryptable", is_secret=True)


@pytest.mark.asyncio
async def test_a_job_read_of_the_settings_refuses_a_secret_it_cannot_decrypt() -> None:
    from app.services.settings_service import (
        SettingsService,
        load_core_overrides,
        refusing_undecryptable_secrets,
    )
    from maljan.core import settings_secrets as box
    from maljan.core.settings_overrides import StoredValueRefused

    rows = [_secret_row("core.llm.api_key"), _secret_row("api.cookie_secret")]
    scalars = MagicMock()
    scalars.all.return_value = rows
    result = MagicMock()
    result.scalars.return_value = scalars
    db = MagicMock()
    db.execute = AsyncMock(return_value=result)

    with patch.object(box, "decrypt", side_effect=box.SecretsUnavailable("rotated")):
        # The console and the API read keep dropping it, as they always did.
        assert await SettingsService(db).load_overrides() == {}
        with pytest.raises(StoredValueRefused) as refused, refusing_undecryptable_secrets():
            await load_core_overrides(db)
        # And the refusal ends with the block: the next read is the API's again.
        assert await load_core_overrides(db) == {}

    assert list(refused.value.refused) == ["core.llm.api_key"]
    assert "decrypt" in refused.value.refused["core.llm.api_key"]


# ── SW-L6 ────────────────────────────────────────────────────────────


def test_a_seal_kept_for_a_report_that_is_no_longer_stored_reads_superseded() -> None:
    from app.services import ledger_verify
    from tests.unit.api.test_a_ledger_is_verified_against_its_seal import (
        _audit,
        _report_row,
        _sealed,
    )

    job = _sealed()
    # The audit chain holds a seal for another report id and no report.delete
    # names it (a re-run while the platform key was missing): not a run that
    # predates sealing, and not proof of tampering either.
    verdict = ledger_verify.verify_ledger(
        job["job_id"],
        [],
        report=_report_row(job["job_id"]),
        audit=_audit(job["audit"].seals[0]),
    )

    assert verdict["status"] == "unverifiable"
    assert verdict["reason"] == ledger_verify.SEAL_SUPERSEDED


@pytest.mark.asyncio
async def test_a_job_whose_own_audit_rows_were_removed_with_its_ledger_is_not_unsealed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sqlalchemy as sa
    from sqlalchemy.dialects import postgresql
    from sqlalchemy.ext.compiler import compiles

    from app.models.audit import AuditChainHead, AuditLog
    from app.models.evidence import EvidenceEntry
    from app.models.report import AnalysisReport
    from app.services import audit_chain, ledger_chain, ledger_verify
    from tests.unit.api.test_a_ledger_is_verified_against_its_seal import (
        KEY,
        _AsyncConnection,
        _audit_row,
    )

    @compiles(postgresql.JSONB, "sqlite")
    def _json(element, compiler, **kw):  # noqa: ANN001, ANN202
        return "JSON"

    @compiles(postgresql.INET, "sqlite")
    def _inet(element, compiler, **kw):  # noqa: ANN001, ANN202
        return "TEXT"

    monkeypatch.setattr(ledger_chain, "platform_key_status", lambda: (KEY, None))
    job_id, other = uuid.uuid4(), uuid.uuid4()
    first = _audit_row(1, None, other, audit_chain.LEDGER_SEAL, {"seal": {}})
    # Row 2 was this job's ledger.seal; it is gone, with the job's evidence rows
    # and its report. The head still says three rows were written.
    last = _audit_row(3, "x" * 8, other, audit_chain.REPORT_AMEND, {})
    engine = sa.create_engine("sqlite://")
    with engine.begin() as conn:
        for model in (EvidenceEntry, AnalysisReport, AuditLog, AuditChainHead):
            model.__table__.create(conn)
        for audit_row in (first, last):
            conn.execute(AuditLog.__table__.insert().values(**audit_row))
        conn.execute(
            AuditChainHead.__table__.insert().values(
                name=audit_chain.HEAD_NAME,
                chain_seq=3,
                chain=last["chain"],
                key_id=KEY.key_id,
                rotated_at_seq=1,
                mac=audit_chain.head_mac(3, last["chain"], 1, KEY),
            )
        )
        verdict = await ledger_verify.verify_job(_AsyncConnection(conn), job_id)

    assert verdict["status"] == "unverifiable", verdict
    assert "not contiguous" in verdict["reason"]


# ── SW-L7 ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_provider_answer_reaches_the_422_with_its_url_masked() -> None:
    from app.services import provider_readiness
    from tests.api.test_a_team_that_needs_ghidra_waits_for_it import _team_settings

    userinfo = password(10)
    detail = f"refused at https://svc:{userinfo}@ghidra.example.org/mcp?token={userinfo}"

    class _Provider:
        capabilities = SimpleNamespace(degrade_on_failure=False)

        def switched_off(self) -> bool:
            return False

        async def readiness(self) -> Any:
            return SimpleNamespace(ok=False, detail=detail)

        def address(self) -> str:
            return "https://ghidra.example.org"

    with patch.object(provider_readiness, "_provider_for", return_value=_Provider()):
        refusals = await provider_readiness.unready_static_providers(
            _team_settings("http://127.0.0.1:1"), "team"
        )

    assert refusals
    assert userinfo not in " ".join(refusals)
    assert "ghidra.example.org" in " ".join(refusals)


# ── SW-L8 ────────────────────────────────────────────────────────────


def _mcp_agent(tool: str) -> dict[str, Any]:
    return {
        "strings": {
            "role": "generic",
            "prompt": "p",
            "tools": [{"kind": "mcp", "server": "mine", "name": tool}],
        }
    }


def _server(*tools: str) -> dict[str, Any]:
    return {"mine": {"enabled": True, "transport": "stdio", "command": "x", "tools": list(tools)}}


def test_a_tool_the_staged_server_map_allows_is_accepted() -> None:
    from app.services.agent_map import AGENT_DEFINITIONS_KEY, validate_agent_map

    out = validate_agent_map(
        {AGENT_DEFINITIONS_KEY: _mcp_agent("rm"), "core.mcp.servers": _server("grep", "rm")},
        stored={"core.mcp.servers": _server("grep")},
    )

    assert "strings" in out[AGENT_DEFINITIONS_KEY]


def test_a_tool_the_staged_server_map_withdraws_is_refused() -> None:
    from app.services.agent_map import AGENT_DEFINITIONS_KEY, AgentMapError, validate_agent_map

    with pytest.raises(AgentMapError) as exc:
        validate_agent_map(
            {AGENT_DEFINITIONS_KEY: _mcp_agent("rm"), "core.mcp.servers": _server("grep")},
            stored={"core.mcp.servers": _server("grep", "rm")},
        )

    assert "'rm' is not allowed" in exc.value.errors[f"{AGENT_DEFINITIONS_KEY}.strings.tools"]


# ── SW-L9 ────────────────────────────────────────────────────────────


def test_the_sample_mirrors_are_copied_off_the_event_loop() -> None:
    """``run_analysis`` awaits the two mirror loops through a worker thread."""
    import ast
    import inspect

    from app.worker import analysis_worker

    tree = ast.parse(inspect.getsource(analysis_worker))
    wanted = {"mirror_static_samples", "mirror_server_samples"}
    direct: list[str] = []
    threaded: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = getattr(node.func, "id", None)
        if name in wanted:
            direct.append(name)
        # ``asyncio.to_thread(functools.partial(mirror_x, ...))``
        if getattr(node.func, "attr", None) == "to_thread" and node.args:
            inner = node.args[0]
            if isinstance(inner, ast.Call) and inner.args:
                target = getattr(inner.args[0], "id", None)
                if target in wanted:
                    threaded.add(target)

    assert direct == [], f"called on the loop: {direct}"
    assert threaded == wanted


@pytest.mark.asyncio
async def test_a_server_map_save_that_withdraws_a_tool_a_stored_definition_uses_is_refused() -> (
    None
):
    from app.services.settings_service import SettingsService, SettingsValidationError

    definitions = "core.agents.definitions"
    servers = "core.mcp.servers"
    stored_definition = {
        "role": "generic",
        "label": "Strings",
        "prompt": "p",
        "tools": [{"kind": "mcp", "server": "mine", "name": "rm"}],
        "enabled": True,
    }
    service = SettingsService(MagicMock())
    service.load_overrides = AsyncMock(  # type: ignore[method-assign]
        return_value={definitions: {"strings": stored_definition}, servers: _server("grep", "rm")}
    )
    with patch.object(SettingsService, "_rows", AsyncMock(side_effect=AssertionError)):
        with pytest.raises(SettingsValidationError) as caught:
            await service.save({servers: _server("grep")}, user_id=None, ip=None)

    assert "'rm' is not allowed" in caught.value.errors[f"{definitions}.strings.tools"]


# ── SW-L5 at submit time, and through the worker's real read ─────────


@pytest.mark.asyncio
async def test_a_job_is_refused_at_submit_when_a_core_secret_cannot_be_decrypted() -> None:
    from app.api.v1.jobs import _undecryptable_secrets
    from maljan.core import settings_secrets as box

    scalars = MagicMock()
    scalars.all.return_value = [_secret_row("core.llm.api_key")]
    result = MagicMock()
    result.scalars.return_value = scalars
    db = MagicMock()
    db.execute = AsyncMock(return_value=result)

    with patch.object(box, "decrypt", side_effect=box.SecretsUnavailable("rotated")):
        named = await _undecryptable_secrets(db)

    assert len(named) == 1 and named[0].startswith("core.llm.api_key:")


# ── API-L5: a purge that fails partway is still recorded ─────────────


def test_a_purge_that_fails_partway_leaves_a_row_with_what_it_removed() -> None:
    from maljan.memory.in_memory_store import InMemoryStore
    from maljan.memory.long_term_memory import StoredCase

    class _Breaks(_ThreadNoting):
        def purge_low_quality(self, **kwargs: Any) -> int:
            self.inner.purge_low_quality(**kwargs)  # the deletion lands ...
            raise ConnectionError("store went away at 10.1.2.3")  # ... then it fails

        def count(self) -> int:
            return int(self.inner.count())

    store = _Breaks()
    assert isinstance(store.inner, InMemoryStore)
    store.inner.store(
        StoredCase(
            sample_id="low",
            summary_text="bare",
            technique_ids=[],
            corroborated_count=0,
            total_techniques=0,
        )
    )
    record = AsyncMock()
    with (
        patch("app.api.v1.system._build_memory_store", return_value=store),
        patch("app.api.v1.system.audit.record", record),
        patch("app.api.v1.system.end_read_transaction", AsyncMock()),
    ):
        client = TestClient(_system_client().app, raise_server_exceptions=False)
        response = client.post("/api/v1/system/ltm/purge", json={"dry_run": False})

    assert response.status_code == 500
    record.assert_awaited_once()
    details = record.await_args.kwargs["details"]
    assert details["outcome"] == "failed"
    assert details["error"] == "ConnectionError"
    assert details["removed"] == 1
    assert "10.1.2.3" not in str(details)


# ── API-L6: the report row is locked by a delete and by a job naming it ──


def test_a_sandbox_report_delete_locks_the_row_it_reads(monkeypatch: pytest.MonkeyPatch) -> None:
    from sqlalchemy.dialects import postgresql

    from app.api.v1 import sandbox_reports as module

    statements: list[str] = []
    row = MagicMock(id=uuid.uuid4(), storage_path="sandbox-reports/aa/x.json", format="cape2")
    answers = _results(row, 0)

    async def _execute(statement: Any) -> Any:
        statements.append(str(statement.compile(dialect=postgresql.dialect())))
        return answers.pop(0)

    db = MagicMock()
    db.execute = _execute
    db.commit = AsyncMock()
    monkeypatch.setattr(module.object_store, "remove", lambda *_a, **_k: None)
    monkeypatch.setattr(module.audit, "record", AsyncMock())
    client, sample = _delete_client(db, monkeypatch)

    assert client.delete(f"/api/v1/samples/{sample.id}/sandbox-reports/{row.id}").status_code == 204
    assert "FOR UPDATE" in statements[0]


@pytest.mark.asyncio
async def test_a_job_naming_a_sandbox_report_takes_the_rows_lock_first() -> None:
    from sqlalchemy.dialects import postgresql

    from app.services.analysis_service import AnalysisService

    statements: list[str] = []
    sample = MagicMock(id=uuid.uuid4())
    found = MagicMock()
    found.scalar_one_or_none.return_value = sample
    missing = MagicMock()
    missing.scalar_one_or_none.return_value = None
    answers = [found, missing]

    async def _execute(statement: Any) -> Any:
        statements.append(str(statement.compile(dialect=postgresql.dialect())))
        return answers.pop(0)

    db = MagicMock()
    db.execute = _execute
    with pytest.raises(ValueError, match="Sandbox report not found"):
        await AnalysisService(db).create_job(
            sample.id,
            MagicMock(id=uuid.uuid4()),
            {"sandbox_report_id": str(uuid.uuid4())},
        )

    assert "FOR UPDATE" in statements[1]

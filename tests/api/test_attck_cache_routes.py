"""The console's ATT&CK cache routes, end to end through the worker's functions.

The queue between the API and the worker is replaced by a direct call to the
worker's own job functions, so a route's answer is what the worker's code
produced from a cache directory of the test's own. The release index and the
downloads are stand-ins; nothing reaches the network.
"""

from __future__ import annotations

import asyncio
import json
import threading
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1 import settings as settings_routes
from app.api.v1.settings import router
from app.database import get_db
from app.deps import require_active_user, require_admin
from app.models.user import UserRole
from app.services import attck_cache
from app.worker import attck_worker
from maljan.memory import attck_loader, attck_update

ADMIN_ID = "00000000-0000-0000-0000-000000000001"
JOB_ID = "0" * 31 + "1"


def _bundle(version: str, techniques: int = 2) -> dict[str, Any]:
    return {
        "type": "bundle",
        "objects": [
            {"type": "x-mitre-collection", "x_mitre_version": version, "modified": "2026-10-13"},
            *(
                {
                    "type": "attack-pattern",
                    "name": f"T{n}",
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": f"T{1000 + n}"}
                    ],
                }
                for n in range(techniques)
            ),
        ],
    }


INDEX = {
    "collections": [
        {
            "name": f"{label} ATT&CK",
            "versions": [{"version": "20.0", "modified": "2026-10-13T17:53:10Z"}],
        }
        for label in ("Enterprise", "Mobile", "ICS")
    ]
}


class FakeQueue:
    """Runs each job at once, through the worker's own function, and keeps the result."""

    def __init__(self) -> None:
        self.results: dict[str, dict[str, Any]] = {}
        self.calls: list[tuple[str, tuple[Any, ...]]] = []

    async def ask(self, function: str, *args: Any, wait: float) -> dict[str, Any]:
        self.calls.append((function, args))
        return await getattr(attck_worker, function)({}, *args)

    async def start_update(self, triggered_by: dict[str, Any]) -> str:
        self.calls.append(("attck_update_now", (triggered_by,)))
        result = await attck_worker.attck_update_now({}, triggered_by)
        self.results[JOB_ID] = result
        return JOB_ID

    async def progress(self, job_id: str) -> dict[str, Any]:
        if job_id not in self.results:
            return {"job_id": job_id, "state": "unknown", "result": None}
        return {"job_id": job_id, "state": "done", "result": self.results[job_id]}


@pytest.fixture
def cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    directory = tmp_path / "attck"
    directory.mkdir()
    monkeypatch.setattr(attck_loader, "ATTCK_CACHE_DIR", directory)
    monkeypatch.setattr(
        attck_loader,
        "ATTCK_CACHE_FILES",
        {d: directory / f"{d}-attack.json" for d in attck_loader.DOMAINS},
    )
    return directory


@pytest.fixture
def queue(monkeypatch: pytest.MonkeyPatch, cache: Path) -> FakeQueue:
    fake = FakeQueue()
    monkeypatch.setattr(attck_cache, "_ask", fake.ask)
    monkeypatch.setattr(attck_cache, "start_update", fake.start_update)
    monkeypatch.setattr(attck_cache, "update_progress", fake.progress)
    monkeypatch.setattr(settings_routes, "_attck_refresh_days", AsyncMock(return_value=7))
    monkeypatch.setattr(settings_routes, "audit_record", AsyncMock())
    return fake


def _seed(cache: Path, versions: dict[str, str]) -> None:
    for domain, version in versions.items():
        (cache / f"{domain}-attack.json").write_text(json.dumps(_bundle(version)), "utf-8")


def _upstream(
    monkeypatch: pytest.MonkeyPatch, index: Any = INDEX, bodies: dict[str, Any] | None = None
) -> None:
    def fetch(url: str, timeout: float = 60) -> Any:
        assert url == attck_update.ATTCK_INDEX_URL
        if isinstance(index, Exception):
            raise index
        return index

    def download(url: str, target: Path, timeout: float = 300) -> None:
        name = url.rsplit("/", 1)[-1]
        body = (bodies or {}).get(name)
        if isinstance(body, Exception):
            raise body
        if body is None:
            body = _bundle(name.rsplit("-", 1)[-1].removesuffix(".json"))
        target.write_text(body if isinstance(body, str) else json.dumps(body), "utf-8")

    monkeypatch.setattr(attck_loader, "_fetch_bundle", fetch)
    monkeypatch.setattr(attck_loader, "_download_bundle_file", download)


def _app(role: UserRole = UserRole.ADMIN) -> FastAPI:
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    if role is UserRole.ADMIN:
        app.dependency_overrides[require_admin] = lambda: MagicMock(
            id=ADMIN_ID, role=role, full_name="Ada Admin"
        )
    else:
        app.dependency_overrides[require_active_user] = lambda: MagicMock(role=role)
    app.dependency_overrides[get_db] = lambda: MagicMock()
    return app


@pytest.fixture
def client() -> TestClient:
    return TestClient(_app())


class TestStatus:
    def test_each_domain_with_its_version_age_and_next_check(
        self, client: TestClient, queue: FakeQueue, cache: Path
    ) -> None:
        _seed(cache, {"enterprise": "19.2"})
        r = client.get("/api/v1/settings/attck")
        assert r.status_code == 200
        body = r.json()
        assert body["refresh_days"] == 7
        enterprise = body["domains"][0]
        assert enterprise["domain"] == "enterprise" and enterprise["version"] == "19.2"
        assert enterprise["next_check_at"] and body["next_check_at"] == enterprise["next_check_at"]
        assert body["domains"][1]["present"] is False
        assert queue.calls == [("attck_status", (7,))]

    def test_a_silent_worker_is_a_503_that_says_so(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(settings_routes, "_attck_refresh_days", AsyncMock(return_value=7))
        monkeypatch.setattr(attck_cache, "_ask", AsyncMock(side_effect=attck_cache._no_answer(15)))
        r = client.get("/api/v1/settings/attck")
        assert r.status_code == 503
        assert "did not answer within 15 seconds" in r.json()["detail"]


class TestCheck:
    def test_up_to_date(
        self, client: TestClient, queue: FakeQueue, cache: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed(cache, {"enterprise": "20.0", "mobile": "20.0", "ics": "20.0"})
        _upstream(monkeypatch)
        r = client.post("/api/v1/settings/attck/check")
        assert r.status_code == 200
        body = r.json()
        assert body["outcome"] == "up_to_date" and body["ok"]
        assert [d["cached"]["version"] for d in body["domains"]] == ["20.0"] * 3
        settings_routes.audit_record.assert_awaited_once()
        assert settings_routes.audit_record.await_args.args == ("settings.attck_check",)

    def test_outdated_names_both_versions_the_date_and_the_next_check(
        self, client: TestClient, queue: FakeQueue, cache: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed(cache, {"enterprise": "19.2", "mobile": "20.0", "ics": "20.0"})
        _upstream(monkeypatch)
        body = client.post("/api/v1/settings/attck/check").json()
        assert body["outcome"] == "outdated"
        enterprise = body["domains"][0]
        assert enterprise["state"] == "outdated"
        assert enterprise["cached"]["version"] == "19.2"
        assert enterprise["latest"] == {"version": "20.0", "released": "2026-10-13T17:53:10Z"}
        assert body["next_check_at"] and body["refresh_days"] == 7

    def test_a_network_failure_is_said_and_never_up_to_date(
        self, client: TestClient, queue: FakeQueue, cache: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed(cache, {"enterprise": "20.0", "mobile": "20.0", "ics": "20.0"})
        _upstream(monkeypatch, index=RuntimeError("Failed to fetch: Network is unreachable"))
        body = client.post("/api/v1/settings/attck/check").json()
        assert body["outcome"] == "failed" and body["ok"] is False
        assert "Network is unreachable" in body["reason"]

    def test_the_caller_is_who_the_worker_records(
        self, client: TestClient, queue: FakeQueue, cache: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _upstream(monkeypatch)
        client.post("/api/v1/settings/attck/check", json={"url": "http://169.254.169.254/"})
        (function, args) = queue.calls[0]
        assert function == "attck_check"
        assert args == ({"user_id": ADMIN_ID, "name": "Ada Admin"}, 7)
        assert attck_update.read_state()["last_check"]["triggered_by"]["user_id"] == ADMIN_ID


class TestUpdate:
    def test_success_swaps_in_the_new_release_and_keeps_a_backup(
        self, client: TestClient, queue: FakeQueue, cache: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed(cache, {"enterprise": "19.2", "mobile": "20.0", "ics": "20.0"})
        _upstream(monkeypatch)

        started = client.post("/api/v1/settings/attck/update")
        assert started.status_code == 202
        job_id = started.json()["job_id"]
        progress = client.get(f"/api/v1/settings/attck/update/{job_id}").json()

        assert progress["state"] == "done"
        result = progress["result"]
        assert result["ok"] and result["triggered_by"]["user_id"] == ADMIN_ID
        assert [(c["domain"], c["from"], c["to"]) for c in result["changes"]] == [
            ("enterprise", "19.2", "20.0")
        ]
        assert attck_update.cached_facts("enterprise")["version"] == "20.0"
        assert (cache / "enterprise-attack.json.bak").is_file()
        assert settings_routes.audit_record.await_args.args == ("settings.attck_update",)

    def test_an_invalid_bundle_is_rejected_and_the_old_cache_kept(
        self, client: TestClient, queue: FakeQueue, cache: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed(cache, {"enterprise": "19.2", "mobile": "20.0", "ics": "20.0"})
        before = (cache / "enterprise-attack.json").read_bytes()
        _upstream(monkeypatch, bodies={"enterprise-attack-20.0.json": _bundle("20.0", 0)})

        job_id = client.post("/api/v1/settings/attck/update").json()["job_id"]
        result = client.get(f"/api/v1/settings/attck/update/{job_id}").json()["result"]

        assert result["ok"] is False and result["kept_previous"]
        assert result["reason"] == "Enterprise: the download carries no techniques"
        assert (cache / "enterprise-attack.json").read_bytes() == before

    def test_a_second_update_while_one_runs_is_refused(
        self, cache: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _seed(cache, {"enterprise": "19.2", "mobile": "20.0", "ics": "20.0"})
        _upstream(monkeypatch)
        inside = threading.Event()
        release = threading.Event()
        plain = attck_loader._download_bundle_file

        def slow(url: str, target: Path, timeout: float = 300) -> None:
            inside.set()
            release.wait(10)
            plain(url, target, timeout)

        monkeypatch.setattr(attck_loader, "_download_bundle_file", slow)

        async def both() -> list[dict[str, Any]]:
            first = asyncio.create_task(attck_worker.attck_update_now({}, {"user_id": "a"}))
            await asyncio.to_thread(inside.wait, 10)
            second = await attck_worker.attck_update_now({}, {"user_id": "b"})
            release.set()
            return [await first, second]

        first, second = asyncio.run(both())

        assert first["ok"] and first["changes"][0]["to"] == "20.0"
        assert (
            second["outcome"] == "busy" and "another ATT&CK update is running" in second["reason"]
        )

    def test_an_unknown_or_malformed_job_id_reads_nothing(
        self, client: TestClient, queue: FakeQueue
    ) -> None:
        assert client.get("/api/v1/settings/attck/update/not-a-job").status_code == 404
        r = client.get(f"/api/v1/settings/attck/update/{'a' * 32}")
        assert r.status_code == 200 and r.json()["state"] == "unknown"


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("get", "/api/v1/settings/attck"),
        ("post", "/api/v1/settings/attck/check"),
        ("post", "/api/v1/settings/attck/update"),
        ("get", f"/api/v1/settings/attck/update/{JOB_ID}"),
    ],
)
def test_every_route_needs_an_administrator(
    method: str, path: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    asked = AsyncMock()
    monkeypatch.setattr(attck_cache, "_ask", asked)
    monkeypatch.setattr(attck_cache, "start_update", asked)
    monkeypatch.setattr(attck_cache, "update_progress", asked)
    r = getattr(TestClient(_app(UserRole.ANALYST)), method)(path)
    assert r.status_code == 403
    asked.assert_not_awaited()


class FakeJob:
    def __init__(self, function: str, status: Any, result: Any = None) -> None:
        self.job_id = JOB_ID
        self._function = function
        self._status = status
        self._result = result

    async def info(self) -> Any:
        return MagicMock(function=self._function)

    async def status(self) -> Any:
        return self._status

    async def result_info(self) -> Any:
        return MagicMock(result=self._result)

    async def result(self, timeout: float, poll_delay: float) -> Any:
        if self._result is TimeoutError:
            raise TimeoutError
        return self._result


class TestTheQueue:
    def test_a_job_nobody_takes_is_a_worker_that_did_not_answer(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pool = MagicMock()
        pool.enqueue_job = AsyncMock(return_value=FakeJob("attck_status", None, TimeoutError))
        monkeypatch.setattr(attck_cache, "_arq", AsyncMock(return_value=pool))
        with pytest.raises(attck_cache.WorkerDidNotAnswer, match="did not answer within"):
            asyncio.run(attck_cache.status(7))
        kwargs = pool.enqueue_job.await_args.kwargs
        assert kwargs["_queue_name"] == attck_worker.ATTCK_QUEUE
        assert kwargs["_expires"] == int(attck_cache.STATUS_WAIT_SECONDS) + 1

    def test_the_poll_reads_only_an_attck_update(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from arq.jobs import JobStatus

        jobs = {"job": FakeJob("run_analysis", JobStatus.complete, {"verdict": "x"})}
        monkeypatch.setattr(attck_cache, "_arq", AsyncMock(return_value=MagicMock()))
        monkeypatch.setattr(attck_cache, "Job", lambda *a, **k: jobs["job"])
        assert asyncio.run(attck_cache.update_progress(JOB_ID))["state"] == "unknown"

        jobs["job"] = FakeJob(attck_cache.UPDATE_FUNCTION, JobStatus.in_progress)
        assert asyncio.run(attck_cache.update_progress(JOB_ID))["state"] == "running"

        jobs["job"] = FakeJob(attck_cache.UPDATE_FUNCTION, JobStatus.complete, {"ok": True})
        done = asyncio.run(attck_cache.update_progress(JOB_ID))
        assert done == {"job_id": JOB_ID, "state": "done", "result": {"ok": True}}

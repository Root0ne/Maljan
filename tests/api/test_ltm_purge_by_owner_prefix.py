"""``POST /system/ltm/purge-owners``: an admin purges memory by owner prefix, audited.

The route takes an owner prefix and a dry run, runs the store's purge by
owner off the loop, and leaves an ``ltm.purge`` audit row with the prefix and
the counts when it deletes (none for a dry run), or with the error class and
what the store lost when it fails part way. A prefix that names no owner path
and a backend that cannot purge by owner are refused. A caller who is not an
admin is refused before any store is built.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from app.deps import require_admin
from maljan.memory.in_memory_store import InMemoryStore
from maljan.memory.long_term_memory import StoredCase

UID = "3f1c2b9e-6a1d-4f7e-9b2a-0c8d7e6f5a41"
ROUTE = "/api/v1/system/ltm/purge-owners"


def _client(*, admin: bool = True) -> tuple[TestClient, Any]:
    from app.api.v1.system import router
    from app.database import get_db

    caller = SimpleNamespace(id=uuid.uuid4(), role="admin")

    def _admin() -> Any:
        if not admin:
            raise HTTPException(status_code=403, detail="Admin role required")
        return caller

    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[require_admin] = _admin
    app.dependency_overrides[get_db] = lambda: MagicMock()
    return TestClient(app), caller


def _store() -> InMemoryStore:
    store = InMemoryStore()
    for index, owner in enumerate([UID, f"{UID}/job/1", f"{UID}/job/2", f"{UID}0/job/1", None]):
        store.store(StoredCase(sample_id=f"s{index}", summary_text="text", owner=owner))
    return store


def _post(store: Any, body: dict[str, Any], *, admin: bool = True) -> tuple[Any, AsyncMock, Any]:
    client, caller = _client(admin=admin)
    record = AsyncMock()
    build = AsyncMock(return_value=store)
    with (
        patch("app.api.v1.system._build_memory_store", build),
        patch("app.api.v1.system.audit.record", record),
        patch("app.api.v1.system.end_read_transaction", AsyncMock()),
    ):
        response = client.post(ROUTE, json=body)
    response.build = build  # type: ignore[attr-defined]
    return response, record, caller


def test_a_dry_run_counts_keeps_and_leaves_no_row() -> None:
    store = _store()

    response, record, _ = _post(store, {"owner_prefix": f"{UID}/job/", "dry_run": True})

    assert response.status_code == 200, response.text
    assert response.json() == {
        "owner_prefix": f"{UID}/job",
        "cases": 2,
        "function_hashes": 0,
        "backend": "InMemoryStore",
        "dry_run": True,
    }
    assert store.count() == 5
    record.assert_not_awaited()


def test_a_purge_removes_the_job_owners_alone_and_is_audited() -> None:
    store = _store()

    response, record, caller = _post(store, {"owner_prefix": f"{UID}/job/"})

    assert response.status_code == 200, response.text
    assert response.json()["cases"] == 2
    assert sorted(str(case.owner) for case, _v, _b in store._cases) == sorted(
        [UID, f"{UID}0/job/1", "None"]
    )
    (row,) = record.await_args_list
    assert row.args[0] == "ltm.purge"
    assert row.kwargs["user_id"] == caller.id
    assert row.kwargs["details"] == {
        "backend": "InMemoryStore",
        "owner_prefix": f"{UID}/job",
        "outcome": "completed",
        "removed": 2,
        "function_hashes": 0,
    }


@pytest.mark.parametrize("prefix", ["", "   ", "/"])
def test_a_prefix_naming_no_owner_path_is_refused_before_the_store(prefix: str) -> None:
    response, record, _ = _post(_store(), {"owner_prefix": prefix})

    assert response.status_code == 422
    response.build.assert_not_awaited()  # type: ignore[attr-defined]
    record.assert_not_awaited()


def test_a_backend_that_cannot_purge_by_owner_is_refused() -> None:
    class _Plain:
        closed = False

        def count(self) -> int:
            return 0

        def close(self) -> None:
            self.closed = True

    store = _Plain()
    response, record, _ = _post(store, {"owner_prefix": f"{UID}/job/"})

    assert response.status_code == 409
    assert store.closed
    record.assert_not_awaited()


def test_a_failure_part_way_is_audited_with_what_was_lost() -> None:
    class _Failing(InMemoryStore):
        def purge_owners(self, prefix: str, *, dry_run: bool = False) -> dict[str, int]:
            self._cases = self._cases[1:]
            raise RuntimeError("backend went away")

    store = _Failing()
    for index in range(3):
        store.store(StoredCase(sample_id=f"s{index}", summary_text="t", owner=f"{UID}/job/{index}"))

    client, _ = _client()
    record = AsyncMock()
    with (
        patch("app.api.v1.system._build_memory_store", AsyncMock(return_value=store)),
        patch("app.api.v1.system.audit.record", record),
        patch("app.api.v1.system.end_read_transaction", AsyncMock()),
        pytest.raises(RuntimeError),
    ):
        client.post(ROUTE, json={"owner_prefix": f"{UID}/job/"})

    (row,) = record.await_args_list
    assert row.kwargs["details"]["outcome"] == "failed"
    assert row.kwargs["details"]["error"] == "RuntimeError"
    assert row.kwargs["details"]["removed"] == 1


def test_a_caller_who_is_not_an_admin_is_refused() -> None:
    response, record, _ = _post(_store(), {"owner_prefix": f"{UID}/job/"}, admin=False)

    assert response.status_code == 403
    response.build.assert_not_awaited()  # type: ignore[attr-defined]
    record.assert_not_awaited()


def test_the_route_takes_the_admin_dependency_the_purge_takes() -> None:
    from fastapi.routing import APIRoute

    from app.api.v1.system import router

    deps = {
        route.path: {d.call for d in route.dependant.dependencies}
        for route in router.routes
        if isinstance(route, APIRoute)
    }
    purge = next(p for p in deps if p.endswith("/ltm/purge"))
    owners = next(p for p in deps if p.endswith("/ltm/purge-owners"))
    assert require_admin in deps[purge]
    assert require_admin in deps[owners]

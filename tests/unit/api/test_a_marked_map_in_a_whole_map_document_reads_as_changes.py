"""A map marked as changes in a ``maljan-settings/1`` document reads as it does in ``/2``.

Only ``/2`` writes the mark, so a ``/1`` document carrying it was relabelled
from one: the map is its changes, never a whole map that would remove every
shipped tool. The import stores exactly what the same ``/2`` document stores,
and an unmarked ``/1`` map is still read whole. Through the real router, over
a fake database.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.services import settings_service as svc
from maljan.core import settings_overrides as so
from maljan.core.tool_declarations import CHANGES_FORM, CHANGES_MARK

LEAF = "core.static.ghidra.tool_facts"
BLOCK = "static.ghidra"
SERVER_MAP = "core.mcp.servers"
DECLARED = {"kind": "strings", "display_name": "Strings"}


@pytest.fixture(autouse=True)
def _no_audit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(svc, "_audit", AsyncMock())


def _import(fmt: str, values: dict[str, Any]) -> dict[str, Any]:
    """What the import stores, by key."""
    from app.api.v1.settings import router
    from app.database import get_db
    from app.deps import require_admin

    db = MagicMock()
    db.execute = AsyncMock(
        return_value=SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: []))
    )
    db.add = MagicMock()
    db.delete = AsyncMock()
    db.commit = AsyncMock()
    db.flush = AsyncMock()
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[require_admin] = lambda: MagicMock(id=uuid.UUID(int=1))
    app.dependency_overrides[get_db] = lambda: db
    with (
        patch("app.api.v1.settings.audit_record", AsyncMock()),
        patch("app.api.v1.settings._agent_warnings", AsyncMock(return_value={})),
    ):
        answer = TestClient(app, raise_server_exceptions=False).post(
            "/api/v1/settings/import", json={"format": fmt, "values": values}
        )
    assert answer.status_code == 200, answer.text
    return {call.args[0].key: call.args[0].value for call in db.add.call_args_list}


def _server_entry(tool_facts: Any) -> dict[str, Any]:
    from app.services.server_map import validate_server_map

    shipped = validate_server_map({})["virustotal"]
    return {**{k: v for k, v in shipped.items() if k != "tool_facts"}, "tool_facts": tool_facts}


MARKED = [
    pytest.param({CHANGES_MARK: CHANGES_FORM}, set(), id="the-mark-alone"),
    pytest.param({CHANGES_MARK: CHANGES_FORM, "zz_mine": DECLARED}, {"zz_mine"}, id="with-a-tool"),
]


@pytest.mark.parametrize(("tool_facts", "added"), MARKED)
def test_a_marked_provider_leaf_reads_as_its_changes(
    tool_facts: dict[str, Any], added: set[str]
) -> None:
    stored = _import("maljan-settings/1", {LEAF: tool_facts})
    assert stored == _import("maljan-settings/2", {LEAF: tool_facts})
    built = so.build_settings({f"{BLOCK}.tool_facts": stored[LEAF]})
    assert set(built.static.ghidra.tool_facts) == set(so.shipped_tool_facts(BLOCK)) | added


@pytest.mark.parametrize(("tool_facts", "added"), MARKED)
def test_a_marked_server_map_entry_reads_as_its_changes(
    tool_facts: dict[str, Any], added: set[str]
) -> None:
    values = {SERVER_MAP: {"virustotal": _server_entry(tool_facts)}}
    stored = _import("maljan-settings/1", values)
    assert stored == _import("maljan-settings/2", values)
    built = so.build_settings({"mcp.servers": stored[SERVER_MAP]})
    shipped = set(so.shipped_tool_facts("mcp.servers.virustotal"))
    assert shipped
    assert set(built.mcp.servers["virustotal"].tool_facts) == shipped | added


def test_an_unmarked_whole_map_document_still_removes_what_it_does_not_name() -> None:
    stored = _import("maljan-settings/1", {LEAF: {"zz_mine": DECLARED}})
    built = so.build_settings({f"{BLOCK}.tool_facts": stored[LEAF]})
    assert set(built.static.ghidra.tool_facts) == {"zz_mine"}

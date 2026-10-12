"""A sent tool name no tool can have is a 422 naming the key, on every save path.

A provider block's tool declarations (``core.<block>.tool_facts``) sent
through ``PATCH /settings`` or either import format with an empty or padded
tool name, or with the mark's key holding anything but the mark, is refused
with the leaf named, as the settings model refuses it; never a failed
request. The tool-server map refuses the same under ``<server>.tool_facts``.
Through the real router, over a fake database.
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
from maljan.core.tool_declarations import (
    CHANGES_FORM,
    CHANGES_MARK,
    refused_names_message,
    with_mark,
)

LEAF = "core.static.ghidra.tool_facts"
SERVER_MAP = "core.mcp.servers"
DECLARED = {"kind": "strings", "display_name": "Strings"}


class _Result:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def scalars(self) -> SimpleNamespace:
        return SimpleNamespace(all=lambda: list(self._rows))


def _db(rows: list[Any]) -> MagicMock:
    db = MagicMock()
    db.execute = AsyncMock(return_value=_Result(rows))
    db.add = MagicMock()
    db.delete = AsyncMock()
    db.commit = AsyncMock()
    db.flush = AsyncMock()
    return db


@pytest.fixture(autouse=True)
def _no_audit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(svc, "_audit", AsyncMock())


def _client(db: MagicMock) -> TestClient:
    from app.api.v1.settings import router
    from app.database import get_db
    from app.deps import require_admin

    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[require_admin] = lambda: MagicMock(id=uuid.UUID(int=1))
    app.dependency_overrides[get_db] = lambda: db
    return TestClient(app, raise_server_exceptions=False)


def _send(method: str, path: str, body: dict[str, Any]) -> tuple[int, dict[str, Any], MagicMock]:
    db = _db([])
    with (
        patch("app.api.v1.settings.audit_record", AsyncMock()),
        patch("app.api.v1.settings._agent_warnings", AsyncMock(return_value={})),
    ):
        answer = getattr(_client(db), method)(path, json=body)
    return answer.status_code, answer.json(), db


# Each spelling, marked and unmarked: the names refused, as the refusal names them.
REFUSED = [
    pytest.param({CHANGES_MARK: CHANGES_FORM, " pad": DECLARED}, [" pad"], id="padded-marked"),
    pytest.param({" pad": DECLARED}, [" pad"], id="padded-unmarked"),
    pytest.param({CHANGES_MARK: CHANGES_FORM, "t\n": DECLARED}, ["t\n"], id="newline-marked"),
    pytest.param({"t\n": DECLARED}, ["t\n"], id="newline-unmarked"),
    pytest.param({CHANGES_MARK: DECLARED}, [""], id="empty-unmarked"),
    pytest.param({CHANGES_MARK: DECLARED, "x": DECLARED}, [""], id="empty-beside-a-tool"),
    pytest.param({CHANGES_MARK: "Changes"}, [""], id="a-mark-that-is-not-the-mark"),
    pytest.param({CHANGES_MARK: "Changes", "x": DECLARED}, [""], id="not-the-mark-beside-a-tool"),
]


def _refused_on_the_leaf(status: int, body: dict[str, Any], names: list[str], db: Any) -> None:
    assert status == 422, body
    errors = body["errors"]
    assert errors == {LEAF: refused_names_message(names)}
    db.add.assert_not_called()
    db.commit.assert_not_awaited()


@pytest.mark.parametrize(("value", "names"), REFUSED)
def test_a_patch_of_a_provider_leaf_with_a_refused_name_is_a_422_naming_the_leaf(
    value: dict[str, Any], names: list[str]
) -> None:
    status, body, db = _send("patch", "/api/v1/settings", {"changes": {LEAF: value}})
    _refused_on_the_leaf(status, body, names, db)


@pytest.mark.parametrize("fmt", ["maljan-settings/2", "maljan-settings/1"])
@pytest.mark.parametrize(("value", "names"), REFUSED)
def test_an_import_of_a_provider_leaf_with_a_refused_name_is_a_422_naming_the_leaf(
    fmt: str, value: dict[str, Any], names: list[str]
) -> None:
    status, body, db = _send(
        "post", "/api/v1/settings/import", {"format": fmt, "values": {LEAF: value}}
    )
    _refused_on_the_leaf(status, body, names, db)


@pytest.mark.parametrize("value", [["scan"], "scan", 1])
def test_a_provider_leaf_that_is_not_a_map_is_a_422_naming_the_leaf(value: Any) -> None:
    status, body, db = _send("patch", "/api/v1/settings", {"changes": {LEAF: value}})
    assert status == 422, body
    assert LEAF in body["errors"]
    db.commit.assert_not_awaited()


@pytest.mark.parametrize(("value", "names"), REFUSED)
def test_a_server_map_entry_with_a_refused_name_is_a_422_naming_the_entry(
    value: dict[str, Any], names: list[str]
) -> None:
    status, body, db = _send(
        "patch",
        "/api/v1/settings",
        {"changes": {SERVER_MAP: {"analysis": {"tool_facts": value}}}},
    )
    assert status == 422, body
    assert any(key.startswith(f"{SERVER_MAP}.analysis.tool_facts") for key in body["errors"])
    db.commit.assert_not_awaited()


def test_a_marked_map_with_a_well_named_tool_still_saves() -> None:
    status, body, db = _send(
        "patch", "/api/v1/settings", {"changes": {LEAF: with_mark({"zz_new": DECLARED})}}
    )
    assert status == 200, body
    db.commit.assert_awaited_once()


def test_a_refusal_the_checks_missed_is_still_a_settings_refusal_of_the_leaf() -> None:
    """The backstop: a refusal only the model says is the leaf's 422, never a failed request."""
    with (
        patch.object(svc, "changed_declaration_refusals", return_value={}),
        pytest.raises(svc.SettingsValidationError) as refused,
    ):
        svc.stored_declaration_leaves({LEAF: with_mark({" pad": DECLARED})}, {})
    assert list(refused.value.errors) == [LEAF]


def test_the_mark_always_wins_over_an_entry_under_its_key() -> None:
    assert with_mark({CHANGES_MARK: DECLARED, "x": DECLARED}) == {
        CHANGES_MARK: CHANGES_FORM,
        "x": DECLARED,
    }
    assert with_mark({CHANGES_MARK: "Changes"}) == {CHANGES_MARK: CHANGES_FORM}
    assert list(with_mark({"x": DECLARED, CHANGES_MARK: "Changes"})) == [CHANGES_MARK, "x"]


def test_an_empty_refused_name_is_shown_visibly() -> None:
    assert repr("") in refused_names_message([""])
    from maljan.core.tool_declarations import loggable_names

    assert loggable_names(["", "a"]) == '"", a'

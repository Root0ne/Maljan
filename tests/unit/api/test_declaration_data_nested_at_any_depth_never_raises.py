"""Stored or sent tool declaration data nested at any depth never raises.

A row or a request body may hold a value nested thousands of levels deep (the
JSON reader takes it). Every walk over declaration data on the paths that
build the settings or check a save is iterative, so no depth turns into a
``RecursionError``: the settings build, the schema answers, and a save is
refused with the key named, never a failed request. No depth limit applies.
Through the real router, over a fake database.
"""

from __future__ import annotations

import gc
import logging
import statistics
import time
import uuid
from collections.abc import Callable, Iterator
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.services import settings_service as svc
from maljan.core import tool_declarations
from maljan.core.settings_overrides import build_settings
from maljan.core.tool_declarations import CHANGES_FORM, CHANGES_MARK

LEAF = "core.static.ghidra.tool_facts"
SERVER_MAP = "core.mcp.servers"
DEPTH = 5_000


def _nested(depth: int) -> Any:
    value: Any = "v"
    for _ in range(depth):
        value = {"a": value}
    return value


def _nested_list(depth: int) -> Any:
    value: Any = "v"
    for _ in range(depth):
        value = [value]
    return value


def _deep_declarations() -> list[Any]:
    return [
        pytest.param(
            {CHANGES_MARK: CHANGES_FORM, "zz": {"kind": "strings", "places": _nested(DEPTH)}},
            id="field",
        ),
        pytest.param({CHANGES_MARK: CHANGES_FORM, "zz": _nested(DEPTH)}, id="declaration"),
        pytest.param(
            {CHANGES_MARK: CHANGES_FORM, "zz": {"kind": "strings", "zz_x": _nested_list(DEPTH)}},
            id="unknown-field",
        ),
        pytest.param({"zz": {"words": _nested_list(DEPTH)}}, id="unmarked"),
        pytest.param({CHANGES_MARK: _nested(DEPTH)}, id="mark-key"),
    ]


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
def _quiet(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(svc, "_audit", AsyncMock())
    logging.disable(logging.WARNING)
    yield
    logging.disable(logging.NOTSET)


def _call(method: str, path: str, body: Any = None, rows: list[Any] | None = None) -> Any:
    from app.api.v1.settings import router
    from app.database import get_db
    from app.deps import require_admin

    db = _db(list(rows or []))
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[require_admin] = lambda: MagicMock(id=uuid.UUID(int=1))
    app.dependency_overrides[get_db] = lambda: db
    client = TestClient(app, raise_server_exceptions=False)
    with (
        patch("app.api.v1.settings.audit_record", AsyncMock()),
        patch("app.api.v1.settings._agent_warnings", AsyncMock(return_value={})),
    ):
        answer = client.get(path) if method == "get" else getattr(client, method)(path, json=body)
    return answer, db


def _server_entry(tool_facts: Any) -> dict[str, Any]:
    from app.services.server_map import validate_server_map

    shipped = validate_server_map({})["analysis"]
    return {**{k: v for k, v in shipped.items() if k != "tool_facts"}, "tool_facts": tool_facts}


@pytest.mark.parametrize("value", _deep_declarations())
def test_a_deep_stored_leaf_builds_the_settings(value: Any) -> None:
    from app.worker.analysis_worker import build_job_settings

    build_settings({"static.ghidra.tool_facts": value})
    build_job_settings({"static.ghidra.tool_facts": value}, None)


@pytest.mark.parametrize("value", _deep_declarations())
def test_a_deep_stored_server_entry_builds_the_settings(value: Any) -> None:
    from app.worker.analysis_worker import build_job_settings

    overrides = {"mcp.servers": {"analysis": {"tool_facts": value}}}
    build_settings(overrides)
    build_job_settings(overrides, None)


def test_a_deep_stored_row_answers_the_schema_and_never_blocks_an_unrelated_save() -> None:
    from app.models import RuntimeSetting

    value = {CHANGES_MARK: CHANGES_FORM, "zz": {"kind": "strings", "places": _nested(DEPTH)}}
    rows = [RuntimeSetting(key=LEAF, value=value, is_secret=False)]
    answer, _ = _call("get", "/api/v1/settings/schema", rows=rows)
    assert answer.status_code == 200, answer.text
    answer, db = _call(
        "patch", "/api/v1/settings", {"changes": {"core.llm.provider": "ollama"}}, rows
    )
    assert answer.status_code == 200, answer.text
    db.commit.assert_awaited_once()


@pytest.mark.parametrize("path", ["patch", "maljan-settings/2", "maljan-settings/1"])
def test_a_deep_leaf_sent_is_refused_naming_the_leaf(path: str) -> None:
    value = {CHANGES_MARK: CHANGES_FORM, "zz": {"kind": "strings", "places": _nested(DEPTH)}}
    if path == "patch":
        answer, db = _call("patch", "/api/v1/settings", {"changes": {LEAF: value}})
    else:
        answer, db = _call(
            "post", "/api/v1/settings/import", {"format": path, "values": {LEAF: value}}
        )
    assert answer.status_code == 422, answer.text
    assert any(key.startswith(LEAF) for key in answer.json()["errors"])
    db.commit.assert_not_awaited()


@pytest.mark.parametrize("path", ["patch", "maljan-settings/2", "maljan-settings/1"])
def test_a_deep_server_entry_sent_is_refused_naming_the_entry(path: str) -> None:
    tool_facts = {CHANGES_MARK: CHANGES_FORM, "zz": {"kind": "strings", "places": _nested(DEPTH)}}
    values = {SERVER_MAP: {"analysis": _server_entry(tool_facts)}}
    if path == "patch":
        answer, db = _call("patch", "/api/v1/settings", {"changes": values})
    else:
        answer, db = _call("post", "/api/v1/settings/import", {"format": path, "values": values})
    assert answer.status_code == 422, answer.text
    assert any(
        key.startswith(f"{SERVER_MAP}.analysis.tool_facts") for key in answer.json()["errors"]
    )
    db.commit.assert_not_awaited()


def test_the_copy_of_declaration_data_keeps_order_and_is_independent() -> None:
    value = {"b": [1, {"c": [2, 3]}], "a": {"d": None}}
    copied = tool_declarations._copy(value)
    assert copied == value
    assert list(copied) == ["b", "a"]
    copied["b"][1]["c"].append(4)
    assert value["b"][1]["c"] == [2, 3]


def _seconds(work: Callable[[], Any]) -> float:
    """``work``'s wall time with the collector held, so its passes over the
    input built beforehand are not counted as the walk's own time."""
    gc.collect()
    gc.disable()
    try:
        began = time.perf_counter()
        work()
        return time.perf_counter() - began
    finally:
        gc.enable()


def _ratio(make: Callable[[int], Callable[[], Any]], small: int) -> float:
    """The median seconds at ten times ``small`` over the median at ``small``.

    Five runs each after a warm-up, at sizes where the walk, not the call,
    dominates: a linear walk gives about 10, a quadratic one about 100.
    """
    _seconds(make(small))
    low = statistics.median(_seconds(make(small)) for _ in range(5))
    high = statistics.median(_seconds(make(small * 10)) for _ in range(5))
    return high / max(low, 1e-6)


def _copying(depth: int) -> Callable[[], Any]:
    value = _nested(depth)
    return lambda: tool_declarations._copy(value)


def test_copying_deep_declaration_data_is_linear() -> None:
    assert _ratio(_copying, 10_000) < 25


def _refusing(n: int) -> Callable[[], Any]:
    sent = {f" t{i}": None for i in range(n)} | {f"own__t{i}": None for i in range(n)}

    def work() -> None:
        tool_declarations.sent_names_refusal(sent, (), server="own")
        tool_declarations.own_prefixed_names(sent, "own")

    return work


def test_the_names_a_sent_map_refuses_are_read_in_linear_time() -> None:
    assert _ratio(_refusing, 5_000) < 25

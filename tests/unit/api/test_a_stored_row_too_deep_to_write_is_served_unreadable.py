"""A stored row nested deeper than an answer can be written is served as unreadable.

``GET /settings`` serves it with no value and its reason, which the console
shows on the row, and the export leaves it out and lists it under
``unreadable``. One such row never fails either answer, and every other row
is served as before. The bound is the writers' own, so the rows here are
built from the interpreter's recursion limit, never a fixed depth. Through
the real router, over a fake database.
"""

from __future__ import annotations

import sys
import uuid
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.models import RuntimeSetting

LIMIT = sys.getrecursionlimit()


def _deep(depth: int) -> Any:
    value: Any = "x"
    for _ in range(depth):
        value = {"a": value}
    return value


def _db(rows: list[Any]) -> MagicMock:
    db = MagicMock()
    db.execute = AsyncMock(
        return_value=SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: list(rows)))
    )
    return db


def _get(rows: list[Any], path: str) -> Any:
    from app.api.v1.settings import router
    from app.database import get_db
    from app.deps import require_admin

    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.dependency_overrides[require_admin] = lambda: MagicMock(id=uuid.UUID(int=1))
    app.dependency_overrides[get_db] = lambda: _db(rows)
    with patch("app.api.v1.settings._agent_warnings", AsyncMock(return_value={})):
        answer = TestClient(app, raise_server_exceptions=False).get(path)
    assert answer.status_code == 200, answer.text[:300]
    return answer.json()


SHAPES = [
    pytest.param(
        "core.mcp.servers",
        lambda depth: {"analysis": {"command": "x", "zz": _deep(depth)}},
        id="a-server-field",
    ),
    pytest.param(
        "core.static.ghidra.tool_facts",
        lambda depth: {"": "changes", "t": _deep(depth)},
        id="a-tool-declaration",
    ),
    pytest.param("core.llm.provider", _deep, id="a-plain-leaf"),
]
# Past pydantic-core's nesting guard (well under the recursion limit), past
# the recursion limit itself, and ten times that.
DEPTHS = [LIMIT // 3, LIMIT * 2, LIMIT * 20]


@pytest.mark.parametrize("depth", DEPTHS)
@pytest.mark.parametrize(("key", "build"), SHAPES)
def test_a_row_too_deep_is_served_unreadable_and_the_rest_as_before(
    key: str, build: Any, depth: int
) -> None:
    rows = [
        RuntimeSetting(key=key, value=build(depth), is_secret=False),
        RuntimeSetting(key="core.llm.expert_max_tokens", value=4096, is_secret=False),
    ]
    values = _get(rows, "/api/v1/settings")["values"]
    assert values[key]["value"] is None
    assert values[key]["source"] == "ui"
    reason = values[key]["unreadable"]
    assert "the answer's writer refused it" in reason
    assert values["core.llm.expert_max_tokens"]["value"] == 4096
    assert values["core.llm.expert_max_tokens"]["unreadable"] is None

    export = _get(rows, "/api/v1/settings/export")
    assert key not in export["values"]
    assert list(export["unreadable"]) == [key]
    assert "the answer's writer refused it" in export["unreadable"][key]
    assert export["values"]["core.llm.expert_max_tokens"] == 4096


def test_a_row_the_writer_takes_is_served_whole() -> None:
    from app.api.v1.settings import unwritable_reason
    from app.schemas.settings import ValueDTO, ValuesResponse

    deep = _deep(LIMIT // 20)
    answer = ValuesResponse(values={"k": ValueDTO(value=deep, source="ui")})
    assert unwritable_reason(answer) is None
    rows = [RuntimeSetting(key="core.llm.provider", value=deep, is_secret=False)]
    values = _get(rows, "/api/v1/settings")["values"]
    assert values["core.llm.provider"]["value"] == deep
    assert values["core.llm.provider"]["unreadable"] is None
    assert _get(rows, "/api/v1/settings/export")["unreadable"] == {}

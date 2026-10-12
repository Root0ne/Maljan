"""The console's tool-declaration box accepts exactly what the API accepts.

The box reads the split of a declaration's fields, with each field's default,
from the served settings schema (``tool_declaration_fields``), so it never
holds a second copy of the list. Both sides are held to one case table
(``apps/web/src/test-fixtures/tool-declaration-cases.json``): this file runs
every case through the API's strict edit rules and ``reads_no_kind``, and the
console's ``declarationFields.test.ts`` runs the same cases through its box.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from maljan.core.tool_declarations import (
    KIND_DEPENDENT_FIELDS,
    KIND_FREE_FIELDS,
    NO_KIND,
    ToolFacts,
    declaration_fields,
    reads_no_kind,
    strict_declarations,
)

_WEB = Path(__file__).resolve().parents[3] / "apps/web/src"
_CASES = json.loads((_WEB / "test-fixtures/tool-declaration-cases.json").read_text("utf-8"))[
    "cases"
]


def _accepted(declaration: dict[str, Any]) -> bool:
    try:
        with strict_declarations():
            ToolFacts.model_validate(declaration)
    except ValueError:
        return False
    return True


@pytest.mark.parametrize("case", _CASES, ids=[case["name"] for case in _CASES])
def test_each_shared_case_reads_in_the_api_as_the_table_says(case: dict[str, Any]) -> None:
    assert _accepted(case["declaration"]) is case["accepted"]
    assert reads_no_kind(case["declaration"]) is case["reads_no_kind"]


def test_the_shared_table_covers_both_readings_of_the_no_kind_word() -> None:
    no_kind = [c for c in _CASES if c["declaration"].get("kind") == NO_KIND]
    assert {(c["accepted"], c["reads_no_kind"]) for c in no_kind} >= {
        (True, False),
        (True, True),
        (False, True),
    }


def test_the_served_schema_carries_the_one_split_with_each_default() -> None:
    from app.api.v1.settings import default_served_schema

    served = default_served_schema().tool_declaration_fields
    assert served == declaration_fields()
    assert served["no_kind"] == NO_KIND
    assert tuple(served["kind_free"]) == KIND_FREE_FIELDS
    assert tuple(served["kind_dependent"]) == KIND_DEPENDENT_FIELDS
    defaults = ToolFacts.model_construct().model_dump(mode="json")
    for name, value in {**served["kind_free"], **served["kind_dependent"]}.items():
        assert value == defaults[name]


def test_the_console_holds_no_second_copy_of_the_field_list() -> None:
    box = (_WEB / "app/(app)/settings/configuration/declarationFields.ts").read_text("utf-8")
    assert "tool_declaration_fields" in box or "ToolDeclarationFields" in box
    for name in (*KIND_FREE_FIELDS, *KIND_DEPENDENT_FIELDS):
        assert f'"{name}"' not in box, name
    assert f'"{NO_KIND}"' not in box

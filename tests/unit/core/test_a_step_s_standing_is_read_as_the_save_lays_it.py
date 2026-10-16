"""The console reads a declared step's standing and its values in force by the save's own layering.

``apps/web/src/test-fixtures/pack-step-layering-cases.json`` lists declared
steps, each with the standing the console must show (a step of one's own, one
that changes its shipped step field by field, or one that replaces it) and
the values the save puts in force for it. This holds every case to the real
layering (``_effective`` over the shipped list); the console's own test holds
the same cases to the editor. So a shipped value the save does not apply,
such as a swapped step's shipped formats, is never shown as in force, and an
explicit empty value over a shipped one reads as set.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic_core import to_jsonable_python

from maljan.core.pack_steps import (
    PackStep,
    _effective,
    _replaces,
    shipped_step,
    step_vocabulary,
)

ROOT = Path(__file__).resolve().parents[3]
CASES = ROOT / "apps" / "web" / "src" / "test-fixtures" / "pack-step-layering-cases.json"


def _cases() -> list[dict[str, Any]]:
    held = json.loads(CASES.read_text(encoding="utf-8"))
    assert isinstance(held, list) and held
    return held


def _name(case: dict[str, Any]) -> str:
    return json.dumps(case["declared"], sort_keys=True)


@pytest.mark.parametrize("case", _cases(), ids=_name)
def test_each_case_stands_and_holds_what_the_save_lays(case: dict[str, Any]) -> None:
    declared = PackStep.model_validate(case["declared"])
    shipped = shipped_step(declared.id)
    if shipped is None:
        standing = "own"
    else:
        standing = "replaces" if _replaces(shipped, declared) else "over"
    assert standing == case["standing"]

    found: dict[str, list[str]] = {}
    laid = next(step for step in _effective([declared], found) if step.id == declared.id)
    if standing == "over":
        assert laid.model_fields_set == shipped.model_fields_set | declared.model_fields_set
    else:
        assert laid.model_fields_set == declared.model_fields_set
    for name, value in case["in_force"].items():
        assert to_jsonable_python(getattr(laid, name)) == value, name


def test_the_cases_cover_every_standing_and_every_replacing_field() -> None:
    cases = _cases()
    assert {case["standing"] for case in cases} == {"own", "over", "replaces"}
    for rule in step_vocabulary()["replacing_fields"]:
        setting = [case for case in cases if rule["field"] in case["declared"]]
        assert {case["standing"] for case in setting} >= {"over", "replaces"}, rule

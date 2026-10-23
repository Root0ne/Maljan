"""The settings schema serves what a triage pack step may say, read from the step model itself.

The console's step editor offers and checks nothing of its own: the fields a
step may set with their types and defaults, the pattern a step id is read by,
the placeholders an argument template may name and the pattern a template is
read for them by, the routed formats, the renderers and the shipped steps all
ride on the steps' catalog entry (``pack_step_vocabulary``), built by
``core.pack_steps.step_vocabulary``. Through the real router, over a fake
database, and only to an administrator.
"""

from __future__ import annotations

import json
import re
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError
from pydantic_core import to_jsonable_python

from app.services import settings_service as svc
from maljan.core.pack_steps import (
    _REPLACING_FIELDS,
    ARGUMENT_PLACEHOLDERS,
    PACK_RENDERERS,
    PackStep,
    default_steps,
    step_vocabulary,
)
from maljan.extractors.sample_identity import routed_formats
from maljan.pipeline.conditions import pack_state_keys

ROOT = Path(__file__).resolve().parents[3]
CASES = ROOT / "apps" / "web" / "src" / "test-fixtures" / "pack-step-placeholder-cases.json"
STEPS_KEY = "core.triage.steps"


@pytest.fixture(autouse=True)
def _quiet(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(svc, "_audit", AsyncMock())


def _db() -> MagicMock:
    db = MagicMock()
    db.execute = AsyncMock(
        side_effect=lambda *_a, **_k: SimpleNamespace(
            scalars=lambda: SimpleNamespace(all=lambda: [])
        )
    )
    db.commit = AsyncMock()
    return db


def _app(*, admin: bool) -> FastAPI:
    from app.api.v1.settings import router
    from app.database import get_db
    from app.deps import require_admin

    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    if admin:
        app.dependency_overrides[require_admin] = lambda: MagicMock(id=uuid.UUID(int=1))
    app.dependency_overrides[get_db] = _db
    return app


def _served_entry() -> dict[str, Any]:
    with patch("app.api.v1.settings.audit_record", AsyncMock()):
        answer = TestClient(_app(admin=True)).get("/api/v1/settings/schema")
    assert answer.status_code == 200, answer.text
    entries = {e["key"]: e for g in answer.json()["groups"] for e in g["entries"]}
    return entries[STEPS_KEY]


@pytest.fixture(scope="module")
def served() -> dict[str, Any]:
    entry = _served_entry()
    vocabulary = entry["pack_step_vocabulary"]
    assert vocabulary is not None
    return vocabulary


def test_the_steps_entry_is_drawn_by_the_step_editor_with_the_model_s_vocabulary() -> None:
    entry = _served_entry()
    assert entry["editor"] == "pack_steps"
    assert entry["pack_step_vocabulary"] == json.loads(json.dumps(step_vocabulary()))


def test_no_other_entry_carries_the_vocabulary() -> None:
    with patch("app.api.v1.settings.audit_record", AsyncMock()):
        answer = TestClient(_app(admin=True)).get("/api/v1/settings/schema")
    carrying = [
        e["key"]
        for g in answer.json()["groups"]
        for e in g["entries"]
        if e.get("pack_step_vocabulary") is not None
    ]
    assert carrying == [STEPS_KEY]


def test_only_an_administrator_is_served_it() -> None:
    from app.deps import require_active_user
    from app.models.user import UserRole

    app = _app(admin=False)
    app.dependency_overrides[require_active_user] = lambda: MagicMock(role=UserRole.ANALYST)
    answer = TestClient(app).get("/api/v1/settings/schema")
    assert answer.status_code == 403, answer.text


class TestTheFieldsAreTheModelsFields:
    def test_every_declarable_field_in_the_model_s_order(self, served: dict[str, Any]) -> None:
        names = [name for name, field in PackStep.model_fields.items() if not field.exclude]
        assert [field["name"] for field in served["fields"]] == names
        assert "wall_clock" not in names

    def test_the_id_alone_is_required_and_every_default_is_the_model_s(
        self, served: dict[str, Any]
    ) -> None:
        by_name = {field["name"]: field for field in served["fields"]}
        assert [name for name, field in by_name.items() if field["required"]] == ["id"]
        for name, field in by_name.items():
            if field["required"]:
                continue
            model = PackStep.model_fields[name].get_default(call_default_factory=True)
            assert field["default"] == to_jsonable_python(model), name

    def test_types_bounds_and_nullability_are_read_from_the_json_schema(
        self, served: dict[str, Any]
    ) -> None:
        by_name = {field["name"]: field for field in served["fields"]}
        assert (by_name["budget_seconds"]["type"], by_name["budget_seconds"]["nullable"]) == (
            "number",
            True,
        )
        assert by_name["budget_seconds"]["bounds"] == {"exclusiveMinimum": 0}
        assert by_name["peak_mb"]["type"] == "integer"
        assert (by_name["formats"]["type"], by_name["formats"]["items"]) == ("array", "string")
        assert by_name["arguments"]["type"] == "object"
        assert (by_name["enabled"]["type"], by_name["enabled"]["default"]) == ("boolean", True)

    def test_a_step_holding_every_served_default_is_one_the_model_reads(
        self, served: dict[str, Any]
    ) -> None:
        written = {
            field["name"]: field["default"] for field in served["fields"] if not field["required"]
        }
        step = PackStep.model_validate({"id": "every_default", **written})
        assert step.model_fields_set == {"id", *written}


class TestThePlaceholderRuleIsTheSaves:
    def test_the_placeholders_are_the_model_s_list_in_its_order(
        self, served: dict[str, Any]
    ) -> None:
        assert served["placeholders"] == [
            {"name": name, "meaning": meaning} for name, meaning in ARGUMENT_PLACEHOLDERS.items()
        ]

    @pytest.mark.parametrize(
        "case", json.loads(CASES.read_text(encoding="utf-8")), ids=lambda case: case["text"]
    )
    def test_the_served_rule_flags_exactly_what_the_save_refuses(
        self, served: dict[str, Any], case: dict[str, Any]
    ) -> None:
        known = {term["name"] for term in served["placeholders"]}
        flagged = [
            name
            for name in re.findall(served["placeholder_pattern"], case["text"])
            if name not in known
        ]
        assert flagged == case["unknown"]
        step = {"id": "templated", "server": "inv", "tool": "t", "arguments": {"a": case["text"]}}
        if not case["unknown"]:
            PackStep.model_validate(step)
            return
        with pytest.raises(ValidationError) as caught:
            PackStep.model_validate(step)
        assert f"names {{{case['unknown'][0]}}}, which a template cannot name" in str(caught.value)

    def test_a_string_at_any_depth_is_read_by_the_same_rule(self, served: dict[str, Any]) -> None:
        nested = {"outer": [{"inner": ["{sample_path}", {"deep": "{nope}"}]}]}
        with pytest.raises(ValidationError) as caught:
            PackStep.model_validate({"id": "d", "server": "s", "tool": "t", "arguments": nested})
        assert "{nope}" in str(caught.value)
        assert re.findall(served["placeholder_pattern"], "{nope}") == ["nope"]


def test_the_id_pattern_reads_ids_as_the_model_does(served: dict[str, Any]) -> None:
    # The console reads the whole id by the served pattern, as ``fullmatch``
    # does; ``match`` would let ``$`` end an id before a trailing newline.
    rule = re.compile(served["id_pattern"])
    candidates = (
        "acme_scan",
        "a",
        "x" * 64,
        "Upper",
        "9lives",
        "with-dash",
        "x" * 65,
        "",
        "acme\n",
        "acme\n\n",
        "\nacme",
        "acme\r",
    )
    for candidate in candidates:
        accepted = True
        try:
            PackStep(id=candidate)
        except ValidationError:
            accepted = False
        assert bool(rule.fullmatch(candidate)) is accepted, repr(candidate)
    assert rule.match("acme\n") and not rule.fullmatch("acme\n")


def test_what_makes_a_step_replace_its_shipped_one_is_served_from_the_rule(
    served: dict[str, Any],
) -> None:
    assert served["replacing_fields"] == [
        {"field": name, "compared_with": compared_with, "empty_counts": empty_counts}
        for name, compared_with, empty_counts in _REPLACING_FIELDS
    ]
    assert set(served["shipped_compared"]) == {step.id for step in default_steps()}
    for step in default_steps():
        assert served["shipped_compared"][step.id] == {
            compared_with: getattr(step, compared_with)
            for _name, compared_with, _empty in _REPLACING_FIELDS
        }


def test_the_state_keys_are_the_pack_state_s_own_names_a_step_id_can_take(
    served: dict[str, Any],
) -> None:
    rule = re.compile(served["id_pattern"])
    assert served["state_keys"] == sorted(
        name for name in pack_state_keys() if rule.fullmatch(name)
    )
    assert "entries" in served["state_keys"]


def test_the_formats_are_every_routed_format(served: dict[str, Any]) -> None:
    assert served["formats"] == list(routed_formats())
    for step in default_steps():
        assert set(step.formats) <= set(served["formats"]), step.id


def test_the_renderers_and_the_shipped_steps_are_the_module_s(served: dict[str, Any]) -> None:
    assert served["renderers"] == [
        {"name": name, "meaning": meaning} for name, meaning in PACK_RENDERERS.items()
    ]
    assert served["shipped"] == [step.model_dump(mode="json") for step in default_steps()]
    assert all("wall_clock" not in step for step in served["shipped"])

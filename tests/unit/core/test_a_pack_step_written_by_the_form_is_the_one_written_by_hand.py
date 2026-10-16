"""A step the console's form writes is the step written by hand, as the model dumps it.

``apps/web/src/test-fixtures/pack-steps-written-by-hand.json`` holds two steps
written by hand: a server's tool with an argument template, formats and a
budget, and a shipped step turned off. The console's own test builds the same
steps through the form and compares the bytes; this one holds the file to the
settings model: the list saves, and each step dumps exactly the fields
written, key for key in the written order, so the form's order (the model's)
is the order a dump gives.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from maljan.core.config import Settings
from maljan.core.pack_steps import check_steps, effective_steps

ROOT = Path(__file__).resolve().parents[3]
WRITTEN = ROOT / "apps" / "web" / "src" / "test-fixtures" / "pack-steps-written-by-hand.json"


def _written() -> list[dict[str, Any]]:
    held = json.loads(WRITTEN.read_text(encoding="utf-8"))
    assert isinstance(held, list) and held
    return held


def test_each_step_dumps_the_fields_written_in_the_written_order() -> None:
    written = _written()
    steps = check_steps(written)
    for step, item in zip(steps, written, strict=True):
        dumped = step.model_dump(mode="json")
        assert dumped == item
        assert list(dumped) == list(item)


def test_the_list_saves_beside_the_server_it_calls() -> None:
    settings = Settings(
        _env_file=None,
        mcp={"servers": {"acmescan": {"command": "invented-acmescan", "enabled": True}}},
        triage={"steps": _written()},
    )
    ran = {step.id: step for step in effective_steps(settings.triage.steps)}
    assert ran["acme_scan"].arguments == {
        "path": "{sample_path}",
        "options": "--hash {sha256} --as {file_type}",
    }
    assert "strings" not in ran

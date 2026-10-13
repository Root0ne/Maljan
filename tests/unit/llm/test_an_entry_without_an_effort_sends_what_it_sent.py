"""An agent entry that names no effort sends the bodies it sent before the field existed.

The fixture holds what ``agent_entry_bodies.bodies()`` gave on the commit the
per-agent effort started from (9ed8d98d), built through the registry: an
Anthropic entry and the judge role at ``llm.anthropic.effort = max``, and a
DeepSeek entry, its fallback and the expert role at
``llm.openai.reasoning_effort = max``, each plain, with tools and as a framed
tool-loop turn. Today's must be the same, key for key.
"""

from __future__ import annotations

import json
from pathlib import Path

from .agent_entry_bodies import bodies

FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "agent_entry_bodies_before_effort.json"


def test_every_body_is_the_one_built_before() -> None:
    before = json.loads(FIXTURE.read_text(encoding="utf-8"))
    now = bodies()
    assert sorted(now) == sorted(before)
    for key in before:
        assert now[key] == before[key], key


def test_the_global_effort_is_in_every_body() -> None:
    before = json.loads(FIXTURE.read_text(encoding="utf-8"))
    for key, body in before.items():
        if key.startswith("anthropic"):
            assert body["output_config"] == {"effort": "max"}, key
        else:
            assert body["reasoning_effort"] == "max", key

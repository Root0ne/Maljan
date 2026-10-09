"""The OpenAI-compatible and Ollama providers build the requests they built before.

The Anthropic work touched code every provider shares: the token ledger's
reading of usage, the spend meter's prices, the window probe, the text an
answer is read as. The fixture holds what ``provider_bodies.bodies()`` gave on
the branch this work started from — DeepSeek, a llama.cpp server and a hosted
standard API through the OpenAI-compatible provider, and Ollama, each plain,
with tools and through structured output, plus a DeepSeek answer's usage as
the ledger and the spend meter read it. Today's must be the same, key for key.
"""

from __future__ import annotations

import json
from pathlib import Path

from .provider_bodies import bodies

FIXTURE = (
    Path(__file__).resolve().parents[2] / "fixtures" / "provider_bodies_before_anthropic_haiku.json"
)


def test_every_body_is_the_one_built_before() -> None:
    before = json.loads(FIXTURE.read_text(encoding="utf-8"))
    now = bodies()
    assert sorted(now) == sorted(before)
    for key in before:
        assert now[key] == before[key], key

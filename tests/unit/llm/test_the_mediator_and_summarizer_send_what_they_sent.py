"""With no entry of their own, the mediator and the summariser send the bodies they sent before.

The fixture holds what ``role_entry_bodies.bodies()`` gave on cdbcab91, before
``llm.agents.mediator`` and ``llm.agents.summarizer`` existed: the mediator and
the function summariser built through the container on Anthropic at
``llm.anthropic.effort = max`` and on DeepSeek at
``llm.openai.reasoning_effort = max``, under settings with an analyst entry and
a judge entry. The mediator's bodies must be the same key for key, so a judge
entry does not move it.

The summariser's are the same but for two keys. Its model was built with
``provider_override`` and ``model_override`` keyword arguments that no
provider reads; both providers passed them on as model kwargs, so every
summariser request carried ``"provider_override": "ollama"`` and
``"model_override": "llama3.2:3b"`` beside the real model. They named a model
nothing called, and the Anthropic API refuses a request with a field it does
not know. Those two keys, and nothing else, are gone.
"""

from __future__ import annotations

import json
from pathlib import Path

from .role_entry_bodies import bodies

FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "role_entry_bodies_before_entries.json"
# The two keyword arguments the summariser's model was built with that no
# provider reads, and which therefore travelled in its request body.
UNREAD_BUILD_ARGUMENTS = ("model_override", "provider_override")


def test_the_mediator_sends_every_body_it_sent() -> None:
    before = json.loads(FIXTURE.read_text(encoding="utf-8"))
    now = bodies()
    assert sorted(now) == sorted(before)
    for key in (k for k in before if "-mediator/" in k):
        assert now[key] == before[key], key


def test_the_summarizer_sends_what_it_sent_without_the_two_unread_arguments() -> None:
    before = json.loads(FIXTURE.read_text(encoding="utf-8"))
    now = bodies()
    for key in (k for k in before if "-summarizer/" in k):
        assert all(name in before[key] for name in UNREAD_BUILD_ARGUMENTS), key
        expected = {k: v for k, v in before[key].items() if k not in UNREAD_BUILD_ARGUMENTS}
        assert now[key] == expected, key


def test_both_roles_ran_on_the_global_expert_model_at_the_global_effort() -> None:
    before = json.loads(FIXTURE.read_text(encoding="utf-8"))
    for key, body in before.items():
        if key.startswith("anthropic"):
            assert body["model"] == "claude-haiku-5-5", key
            assert body["output_config"] == {"effort": "max"}, key
        else:
            assert body["model"] == "deepseek-flash", key
            assert body["reasoning_effort"] == "max", key

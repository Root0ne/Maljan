"""The request bodies an agent entry's model sends, built through the registry.

Read by ``test_an_entry_without_an_effort_sends_what_it_sent`` against the
bodies the same function produced on the branch the per-agent effort started
from (``tests/fixtures/agent_entry_bodies_before_effort.json``): an Anthropic
entry and role at a global effort, and a DeepSeek entry and role at a global
``reasoning_effort``, each plain, with tools and as a framed tool-loop turn.
The entries name no effort of their own, so every body must be the one built
before the field existed. Run as a script it writes the bodies as JSON to the
path it is given, which is how the fixture was written.
"""

from __future__ import annotations

import json
from typing import Any

from .provider_bodies import _bound, _history, _named, _payload

ANTHROPIC_MODEL = "claude-haiku-5-5"


def _anthropic_settings() -> Any:
    from maljan.core.config import Settings

    return Settings(
        _env_file=None,
        llm={
            "provider": "anthropic",
            "anthropic": {
                "api_key": "test-anthropic-key",
                "expert_model": ANTHROPIC_MODEL,
                "judge_model": ANTHROPIC_MODEL,
                "effort": "max",
            },
            "agents": {"reporter": {"provider": "anthropic", "model": ANTHROPIC_MODEL}},
        },
    )


def _deepseek_settings() -> Any:
    from maljan.core.config import Settings

    return Settings(
        _env_file=None,
        llm={
            "provider": "openai",
            "openai": {
                "api_key": "sk-test",
                "base_url": "https://api.deepseek.com",
                "compat": "deepseek",
                "expert_model": "deepseek-flash",
                "reasoning_effort": "max",
            },
            "agents": {
                "static": {
                    "provider": "openai",
                    "model": "deepseek-flash",
                    "fallbacks": [{"provider": "openai", "model": "deepseek-pro"}],
                }
            },
        },
    )


def _models() -> dict[str, Any]:
    from maljan.llm.registry import LLMProviderRegistry

    anthropic = LLMProviderRegistry(_anthropic_settings())
    deepseek = LLMProviderRegistry(_deepseek_settings())
    static = deepseek.build_model_for_agent("static", max_tokens=4096)
    return {
        "anthropic-entry": anthropic.build_model_for_agent(
            "reporter", fallback_role="judge", max_tokens=8192
        ),
        "anthropic-role": anthropic.build_model(role="judge", max_tokens=8192),
        "deepseek-entry": static.models[0],
        "deepseek-fallback": static.models[1],
        "deepseek-role": deepseek.build_model(role="expert", max_tokens=4096),
    }


def bodies() -> dict[str, Any]:
    """Every body, keyed by what built it."""
    from maljan.agents.base_agent import frame_messages

    history = _history()
    framed = frame_messages(history[:4], run_state="sample: c\nbudget remaining: 3 model turns")
    framed[-1] = framed[-1].model_copy(
        update={
            "response_metadata": {
                **(framed[-1].response_metadata or {}),
                "maljan_tool_loop_turn": True,
            }
        }
    )
    out: dict[str, Any] = {}
    for name, model in _models().items():
        out[f"{name}/plain"] = _payload(model, history)
        out[f"{name}/tools"] = _bound(model, history)
        out[f"{name}/framed"] = _bound(model, framed)
    return json.loads(json.dumps(out, sort_keys=True, default=_named))


if __name__ == "__main__":
    import sys
    from pathlib import Path

    Path(sys.argv[1]).write_text(json.dumps(bodies(), indent=1, sort_keys=True) + "\n")

"""The request bodies the mediator's and the function summariser's models send.

Built through the container, the way a run builds them: the mediator is the
judge agent the negotiation node asks for under ``role="expert"``, and the
summariser's model is ``get_summarizer_llm``. Read by
``test_the_mediator_and_summarizer_send_what_they_sent`` against the bodies the
same function produced on cdbcab91, before either role had an entry of its own
(``tests/fixtures/role_entry_bodies_before_entries.json``). The settings name
an analyst entry and a judge entry and neither a ``mediator`` nor a
``summarizer`` entry, so both roles run on the global expert model at the
global effort. Run as a script it writes the bodies as JSON to the path it is
given, which is how the fixture was written.
"""

from __future__ import annotations

import json
from typing import Any

from .provider_bodies import _bound, _history, _named, _payload

ANTHROPIC_MODEL = "claude-haiku-5-5"


def anthropic_settings(**agents: Any) -> Any:
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
            "agents": {
                "judge": {"provider": "anthropic", "model": "claude-sonnet-5", "effort": "high"},
                **agents,
            },
        },
    )


def deepseek_settings(**agents: Any) -> Any:
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
                "judge_model": "deepseek-flash",
                "reasoning_effort": "max",
            },
            "agents": {
                "static": {"provider": "openai", "model": "deepseek-pro"},
                "judge": {"provider": "openai", "model": "deepseek-pro", "effort": "high"},
                **agents,
            },
        },
    )


def container(settings: Any) -> Any:
    """A container that builds real models and asks no endpoint for anything."""
    from maljan.core.container import ServiceContainer
    from maljan.llm.registry import LLMProviderRegistry

    built = ServiceContainer(settings, mock=True)
    built._llm_registry = LLMProviderRegistry(settings)
    return built


def mediator_model(settings: Any) -> Any:
    return container(settings).get_judge_agent(role="expert").llm


def summarizer_model(settings: Any) -> Any:
    return container(settings).get_summarizer_llm()


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
    for name, settings in (("anthropic", anthropic_settings), ("deepseek", deepseek_settings)):
        mediator = mediator_model(settings())
        out[f"{name}-mediator/plain"] = _payload(mediator, history)
        out[f"{name}-mediator/tools"] = _bound(mediator, history)
        out[f"{name}-mediator/framed"] = _bound(mediator, framed)
        out[f"{name}-summarizer/plain"] = _payload(summarizer_model(settings()), history)
    return json.loads(json.dumps(out, sort_keys=True, default=_named))


if __name__ == "__main__":
    import sys
    from pathlib import Path

    Path(sys.argv[1]).write_text(json.dumps(bodies(), indent=1, sort_keys=True) + "\n")

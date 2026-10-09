"""The request bodies the OpenAI-compatible and Ollama providers build, for one fixed history.

Read by ``test_other_providers_send_what_they_sent`` against the bodies the
same function produced on the branch this work started from
(``tests/fixtures/provider_bodies_before_anthropic_haiku.json``): every dialect
of the OpenAI-compatible provider (DeepSeek, a llama.cpp server, a hosted
standard API), Ollama, each with and without tools, through structured output,
and the spend meter's prices and the token ledger's reading of each one's
usage. Run as a script it writes the bodies as JSON to the path it is given,
which is how the fixture was written.
"""

from __future__ import annotations

import json
from typing import Any

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.tools import StructuredTool
from pydantic import BaseModel


class _What(BaseModel):
    what: str = ""


class _Section(BaseModel):
    summary: str


def _lookup() -> StructuredTool:
    return StructuredTool.from_function(
        func=lambda what="": f"answer for {what}",
        name="lookup",
        description="Look it up.",
        args_schema=_What,
    )


def _history() -> list[Any]:
    return [
        SystemMessage(content="You are an analyst."),
        HumanMessage(content="Analyse the sample.\n\n=== RUN STATE ===\nx\n=== END RUN STATE ==="),
        AIMessage(
            content="",
            tool_calls=[{"name": "lookup", "args": {"what": "a"}, "id": "call_0"}],
            additional_kwargs={"reasoning_content": "first I look"},
        ),
        ToolMessage(content="answer for a", tool_call_id="call_0"),
        AIMessage(
            content="",
            tool_calls=[{"name": "lookup", "args": {"what": "b"}, "id": "call_1"}],
        ),
        HumanMessage(content="Write your report now."),
    ]


def _openai(base_url: str | None, compat: str, **extra: Any) -> Any:
    from maljan.core.config import Settings
    from maljan.llm.openai_provider import OpenAIProvider

    settings = Settings(
        _env_file=None,
        llm={
            "openai": {
                "api_key": "sk-test",
                "base_url": base_url,
                "compat": compat,
                **extra,
            }
        },
    )
    return OpenAIProvider(settings).build_model("m", 0.1, max_tokens=4096)


def _ollama() -> Any:
    from maljan.core.config import Settings
    from maljan.llm.ollama_provider import OllamaProvider

    settings = Settings(_env_file=None, llm={"ollama": {"disable_thinking": True}})
    return OllamaProvider(settings).build_model("qwen3:8b", 0.1, max_tokens=4096)


def _payload(model: Any, messages: list[Any], **kwargs: Any) -> Any:
    if hasattr(model, "_get_request_payload"):
        return model._get_request_payload(messages, **kwargs)
    return model._chat_params(messages, **kwargs)


def _bound(model: Any, messages: list[Any]) -> Any:
    binding = model.bind_tools([_lookup()])
    return _payload(binding.bound, messages, **binding.kwargs)


def _structured(model: Any, messages: list[Any]) -> Any:
    binding = model.with_structured_output(_Section).first
    return _payload(binding.bound, messages, **binding.kwargs)


def _usage_reading() -> Any:
    from maljan.core.spend import SpendMeter
    from maljan.core.token_ledger import TokenLedger, turn_usage

    answer = AIMessage(
        content="x",
        usage_metadata={
            "input_tokens": 500,
            "output_tokens": 40,
            "total_tokens": 540,
            "input_token_details": {"cache_read": 300},
            "output_token_details": {"reasoning": 12},
        },
        response_metadata={"token_usage": {"prompt_cache_hit_tokens": 300}},
    )
    usage = turn_usage(answer)
    ledger = TokenLedger()
    ledger.add(usage, agent="static", model="deepseek-flash")
    from datetime import UTC, datetime

    # A Tuesday at 02:00 UTC, inside DeepSeek's documented peak window.
    meter = SpendMeter(10.0, clock=lambda: datetime(2026, 10, 6, 2, 0, tzinfo=UTC))
    worst = {
        name: meter.worst_case(name, 200_000, 4_000)
        for name in ("deepseek-flash", "deepseek-v4-pro", "deepseek-v4-flash")
    }
    meter.settle(dict(usage or {}, sent_at=1_760_000_000.0), "deepseek-v4-pro")
    return {"usage": usage, "ledger": ledger.snapshot(), "worst": worst, "spent": meter.spent()}


def bodies() -> dict[str, Any]:
    """Every body, keyed by what built it."""
    history = _history()
    out: dict[str, Any] = {}
    builders = {
        "deepseek": lambda: _openai("https://api.deepseek.com", "deepseek", reasoning_effort="max"),
        "llama": lambda: _openai(
            "http://127.0.0.1:8080/v1", "auto", disable_thinking=True, repetition_penalty=1.1
        ),
        "standard": lambda: _openai(None, "auto"),
        "ollama": _ollama,
    }
    from maljan.agents.base_agent import frame_messages

    # A tool loop's turn as the analysts' loop sends it: the run-state block
    # on its newest turn, and a note on that turn's metadata (which the
    # Anthropic provider reads and no other client sends).
    framed = frame_messages(history[:4], run_state="sample: c\nbudget remaining: 3 model turns")
    framed[-1] = framed[-1].model_copy(
        update={
            "response_metadata": {
                **(framed[-1].response_metadata or {}),
                "maljan_tool_loop_turn": True,
            }
        }
    )
    for name, build in builders.items():
        model = build()
        out[f"{name}/plain"] = _payload(model, history)
        out[f"{name}/tools"] = _bound(model, history)
        out[f"{name}/framed"] = _bound(model, framed)
        try:
            out[f"{name}/structured"] = _structured(model, history[:2])
        except Exception as exc:  # noqa: BLE001 — a shape this helper cannot unwrap is named
            out[f"{name}/structured"] = f"not read: {type(exc).__name__}"
    out["usage"] = _usage_reading()
    return json.loads(json.dumps(out, sort_keys=True, default=_named))


def _named(value: Any) -> str:
    """A value JSON has no form for, by its name: a schema class is its class name."""
    return str(getattr(value, "__qualname__", None) or value)


if __name__ == "__main__":
    import sys
    from pathlib import Path

    Path(sys.argv[1]).write_text(json.dumps(bodies(), indent=1, sort_keys=True) + "\n")

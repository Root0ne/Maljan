"""A cap bound for one call reaches the field each provider's server reads.

The report stage holds a call to what the window leaves after its prompt when
its budget would not fit beside it, by handing that call its own output cap.
Each client takes the cap under its own name and each server reads its own
field: a name the client does not know is refused (Gemini's request config
forbids extra fields), and a field the server does not read caps nothing
(ik_llama.cpp ignores ``max_completion_tokens``). One case per provider,
through the request each client actually builds.
"""

from __future__ import annotations

from typing import Any

import pytest
from langchain_core.messages import HumanMessage
from pydantic import SecretStr

from maljan.core.config import Settings
from maljan.llm.context_window import (
    accepts_output_bound,
    output_bound_kwargs,
    prompt_overflow_sentence,
)

BUILT = 393216
BOUND = 100
ASK = [HumanMessage(content="write the report")]


def _openai(base_url: str, compat: str = "auto") -> Any:
    from maljan.llm.openai_provider import OpenAIProvider, forget_standard_only

    forget_standard_only()
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    settings.llm.openai.base_url = base_url
    settings.llm.openai.api_key = SecretStr("key")
    settings.llm.openai.compat = compat  # type: ignore[assignment]
    return OpenAIProvider(settings).build_model("m", 0.1, max_tokens=BUILT)


def _anthropic() -> Any:
    from maljan.llm.anthropic_provider import AnthropicProvider

    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    settings.llm.anthropic.api_key = SecretStr("key")
    return AnthropicProvider(settings).build_model("m", 0.1, max_tokens=BUILT)


def _gemini() -> Any:
    from maljan.llm.gemini_provider import GeminiProvider

    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    settings.llm.gemini.api_key = SecretStr("key")
    return GeminiProvider(settings).build_model("gemini-example", 0.1, max_output_tokens=BUILT)


def _openai_fields(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "max_completion_tokens": payload.get("max_completion_tokens"),
        "extra_body": dict(payload.get("extra_body") or {}),
    }


CASES = [
    pytest.param(
        lambda: _openai("https://api.example.com", "standard"),
        lambda model, kw: _openai_fields(model._get_request_payload(ASK, **kw)),
        {"max_completion_tokens": BOUND, "extra_body": {}},
        id="openai",
    ),
    pytest.param(
        lambda: _openai("https://api.example.com", "deepseek"),
        lambda model, kw: _openai_fields(model._get_request_payload(ASK, **kw)),
        {"max_completion_tokens": BOUND, "extra_body": {"max_tokens": BOUND}},
        id="deepseek",
    ),
    pytest.param(
        lambda: _openai("http://127.0.0.1:8080/v1", "llama_cpp"),
        lambda model, kw: {
            key: value
            for key, value in _openai_fields(model._get_request_payload(ASK, **kw))[
                "extra_body"
            ].items()
            if key in ("max_tokens", "n_predict")
        },
        {"max_tokens": BOUND, "n_predict": BOUND},
        id="llama.cpp",
    ),
    pytest.param(
        _anthropic,
        lambda model, kw: {"max_tokens": model._get_request_payload(ASK, **kw)["max_tokens"]},
        {"max_tokens": BOUND},
        id="anthropic",
    ),
    pytest.param(
        _gemini,
        lambda model, kw: {
            "max_output_tokens": model._prepare_request(ASK, **kw)["config"].max_output_tokens
        },
        {"max_output_tokens": BOUND},
        id="gemini",
    ),
]


@pytest.mark.parametrize(("build", "sent", "expected"), CASES)
def test_the_bound_reaches_the_field_the_server_reads(build: Any, sent: Any, expected: Any) -> None:
    model = build()

    assert accepts_output_bound(model)
    assert sent(model, output_bound_kwargs(model, BOUND)) == expected


@pytest.mark.parametrize(("build", "sent", "expected"), CASES)
def test_without_a_bound_the_built_cap_is_sent(build: Any, sent: Any, expected: Any) -> None:
    model = build()

    unbound = sent(model, {})

    assert BOUND not in (unbound.values() if isinstance(unbound, dict) else [unbound])


def test_ollama_takes_no_per_call_cap() -> None:
    from langchain_ollama import ChatOllama

    model = ChatOllama(model="m")

    assert not accepts_output_bound(model)
    assert output_bound_kwargs(model, BOUND) == {}


def test_a_list_whose_models_name_the_cap_differently_takes_none() -> None:
    class _List:
        def __init__(self, *models: Any) -> None:
            self.models = list(models)

    mixed = _List(_openai("https://api.example.com", "standard"), _gemini())
    same = _List(_openai("https://api.example.com", "standard"), _anthropic())

    assert output_bound_kwargs(mixed, BOUND) == {}
    assert output_bound_kwargs(same, BOUND) == {"max_tokens": BOUND}


class TestAPromptLargerThanTheWindow:
    def test_is_said(self) -> None:
        sentence = prompt_overflow_sentence("narrative round's", 3 * 9000, 8192)

        assert sentence is not None
        assert "8192-token context window" in sentence
        assert "system prompt" in sentence

    def test_a_prompt_that_fits_or_an_unknown_window_says_nothing(self) -> None:
        assert prompt_overflow_sentence("narrative round's", 3 * 8000, 8192) is None
        assert prompt_overflow_sentence("narrative round's", 3 * 9000, 0) is None


def test_the_sized_classes_are_named_where_they_are_made() -> None:
    from langchain_google_genai import ChatGoogleGenerativeAI

    from maljan.llm.generation_rate import with_sized_request_timeout

    sized = with_sized_request_timeout(ChatGoogleGenerativeAI)

    assert sized.__module__ == "maljan.llm.generation_rate"
    assert sized.__qualname__ == ChatGoogleGenerativeAI.__qualname__

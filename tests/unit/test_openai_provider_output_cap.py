"""OUTPUT-CAP-01 — the judge's output ceiling did not reach the server.

``ServiceContainer.get_judge_llm`` builds the verdict model with
``max_tokens=judge_max_tokens`` and says why in a comment: *"Bound the verdict
generation so a degenerate decode can't consume the full wall-clock timeout."*
The intent was right and the request was not. ``langchain-openai`` renames
``max_tokens`` to OpenAI's newer ``max_completion_tokens`` when it builds the
payload, and ik_llama.cpp's OpenAI-compatible endpoint does not know that key —
so it accepted the field, ignored it, and decoded without a ceiling.

Measured on 2026-08-15, not inferred: a judge call built with
``judge_max_tokens=8192`` generated **30,155 tokens** past a 1,403-token prompt
before the client's 600 s wrapper gave up, and the server was still generating.
Four of the eight fixtures in the C3 study never returned a verdict for this
reason, and the pipeline emitted a fallback bundle for each of them.

This is the same shape as every failure in the paper's instrument chapter — a
parameter accepted and ignored — and it is the one occurrence inside our own
production configuration rather than an evaluation harness.

The fix re-sends the cap through ``extra_body``, which reaches the server
verbatim, under both spellings the llama.cpp forks disagree about. These tests
pin the wire format, because the defect was invisible at every other level: the
config was right, the container was right, the ChatOpenAI attribute was right,
and only the serialised request was wrong.
"""

from __future__ import annotations

import pytest

from maljan.core.config import Settings
from maljan.llm.openai_provider import OpenAIProvider


def _provider(**openai_overrides: object) -> tuple[OpenAIProvider, Settings]:
    settings = Settings()
    settings.llm.openai.api_key = "sk-test-not-a-real-key"  # type: ignore[assignment]
    for key, value in openai_overrides.items():
        setattr(settings.llm.openai, key, value)
    return OpenAIProvider(config=settings), settings


class TestTheCapReachesTheWire:
    def test_a_local_server_receives_the_cap_in_extra_body(self) -> None:
        """The key the server actually reads, not the one LangChain renames."""
        provider, _ = _provider(base_url="http://127.0.0.1:8080/v1")
        llm = provider.build_model(model="qwen", temperature=0.0, max_tokens=8192)
        extra = llm.extra_body or {}
        assert extra.get("max_tokens") == 8192
        assert extra.get("n_predict") == 8192

    def test_both_spellings_are_sent_because_the_forks_disagree(self) -> None:
        """Unknown sampler keys are ignored rather than rejected, so sending
        both costs nothing and guessing wrong costs the whole decode budget."""
        provider, _ = _provider(base_url="http://127.0.0.1:8080/v1")
        llm = provider.build_model(model="qwen", temperature=0.0, max_tokens=512)
        assert (llm.extra_body or {}).get("max_tokens") == 512
        assert (llm.extra_body or {}).get("n_predict") == 512

    def test_the_serialised_payload_carries_it(self) -> None:
        """The level the defect lived at: everything above this was correct."""
        from langchain_core.messages import HumanMessage

        provider, _ = _provider(base_url="http://127.0.0.1:8080/v1")
        llm = provider.build_model(model="qwen", temperature=0.0, max_tokens=8192)
        payload = llm._get_request_payload([HumanMessage(content="hi")], stop=None)
        # LangChain still renames the top-level field; that is not ours to change.
        assert payload.get("max_completion_tokens") == 8192
        # What matters is that the cap also travels under a key the server reads.
        assert payload["extra_body"]["max_tokens"] == 8192

    def test_the_thinking_flag_is_not_clobbered(self) -> None:
        """Both guards write to ``extra_body``; the second must not erase the first."""
        provider, _ = _provider(base_url="http://127.0.0.1:8080/v1", disable_thinking=True)
        llm = provider.build_model(model="qwen", temperature=0.0, max_tokens=8192)
        extra = llm.extra_body or {}
        assert extra["max_tokens"] == 8192
        assert extra["chat_template_kwargs"]["enable_thinking"] is False


class TestItStaysOffTheWireWhereItWouldBeRejected:
    def test_hosted_openai_gets_no_extra_body_cap(self) -> None:
        """Vanilla OpenAI rejects unknown body fields, so the guard is local-only —
        the same rule the repetition-penalty guard above it follows."""
        provider, _ = _provider(base_url="")
        llm = provider.build_model(model="gpt-4o", temperature=0.0, max_tokens=8192)
        extra = llm.extra_body or {}
        assert "max_tokens" not in extra
        assert "n_predict" not in extra

    @pytest.mark.parametrize("cap", [0, None, -1, "8192"])
    def test_a_missing_or_nonsense_cap_is_not_forwarded(self, cap: object) -> None:
        """An uncapped model must not gain a cap of 0, which would return nothing."""
        provider, _ = _provider(base_url="http://127.0.0.1:8080/v1")
        kwargs = {} if cap is None else {"max_tokens": cap}
        llm = provider.build_model(model="qwen", temperature=0.0, **kwargs)  # type: ignore[arg-type]
        assert "n_predict" not in (llm.extra_body or {})

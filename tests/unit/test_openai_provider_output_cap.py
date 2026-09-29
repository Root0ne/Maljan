"""The judge's output ceiling did not reach the server.

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

from typing import Any

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


class TestACapForOneCallReachesAnUncappedLocalModel:
    """A model built without a cap (the function summarizer's in a run, or the
    provider called directly) holds no cap key in its extras. A cap handed to
    one call was copied only into keys already there, and so never reached the
    server: measured on ik_llama.cpp, a call held to 60 output units produced
    3,732. The container's other models carry a cap derived from the window."""

    ASK = "hi"

    def _uncapped_local(self, **openai_overrides: object) -> Any:
        provider, _ = _provider(base_url="http://127.0.0.1:8080/v1", **openai_overrides)
        return provider.build_model(model="qwen", temperature=0.0)

    def _extras(self, llm: Any, **call: object) -> dict[str, Any]:
        from langchain_core.messages import HumanMessage

        payload = llm._get_request_payload([HumanMessage(content=self.ASK)], stop=None, **call)
        return dict(payload.get("extra_body") or {})

    def test_the_call_cap_is_sent_under_both_keys(self) -> None:
        extra = self._extras(self._uncapped_local(), max_tokens=60)
        assert extra["max_tokens"] == 60
        assert extra["n_predict"] == 60

    def test_it_is_sent_when_the_model_has_no_other_extra_either(self) -> None:
        llm = self._uncapped_local(repetition_penalty=1.0, disable_thinking=False)
        extra = self._extras(llm, max_tokens=60)
        assert extra["max_tokens"] == 60
        assert extra["n_predict"] == 60

    def test_a_call_without_a_cap_sends_none(self) -> None:
        extra = self._extras(self._uncapped_local())
        assert "max_tokens" not in extra
        assert "n_predict" not in extra

    @pytest.mark.parametrize("cap", [0, -1, True])
    def test_a_nonsense_call_cap_is_not_forwarded(self, cap: object) -> None:
        extra = self._extras(self._uncapped_local(), max_tokens=cap)
        assert "max_tokens" not in extra
        assert "n_predict" not in extra

    def test_the_other_extras_are_kept(self) -> None:
        extra = self._extras(self._uncapped_local(disable_thinking=True), max_tokens=60)
        assert extra["chat_template_kwargs"]["enable_thinking"] is False
        assert extra["n_predict"] == 60

    def test_a_model_built_with_a_cap_is_held_to_the_call_cap(self) -> None:
        provider, _ = _provider(base_url="http://127.0.0.1:8080/v1")
        llm = provider.build_model(model="qwen", temperature=0.0, max_tokens=8192)
        extra = self._extras(llm, max_tokens=60)
        assert extra["max_tokens"] == 60
        assert extra["n_predict"] == 60
        assert self._extras(llm)["n_predict"] == 8192

    def test_the_call_deadline_reads_the_cap_that_is_sent(self) -> None:
        """The deadline's cap-at-pace sizes the call from the cap the server now reads."""
        import time

        from maljan.llm.generation_rate import _CallDeadline

        llm = self._uncapped_local()
        sent = self._extras(llm, max_tokens=60)
        deadline = _CallDeadline(llm, [self.ASK], {"max_tokens": 60}, time.monotonic)
        assert deadline.cap == sent["max_tokens"] == sent["n_predict"]

    def test_a_bound_call_puts_it_on_the_wire(self) -> None:
        """Through the request the client sends, by a stand-in transport."""
        import json

        import httpx
        from langchain_core.messages import HumanMessage

        from maljan.llm.openai_provider import forget_standard_only
        from tests.unit.llm.streamed_wire import reply

        bodies: list[dict[str, Any]] = []

        def _server(request: httpx.Request) -> httpx.Response:
            bodies.append(json.loads(request.content))
            return reply(
                request,
                {
                    "id": "r1",
                    "object": "chat.completion",
                    "created": 0,
                    "model": "qwen",
                    "choices": [
                        {
                            "index": 0,
                            "message": {"role": "assistant", "content": "ok"},
                            "finish_reason": "stop",
                        }
                    ],
                },
            )

        forget_standard_only()
        transport = httpx.MockTransport(_server)
        provider, _ = _provider(base_url="http://127.0.0.1:8080/v1")
        llm = provider.build_model(
            model="qwen",
            temperature=0.0,
            http_client=httpx.Client(transport=transport),
            http_async_client=httpx.AsyncClient(transport=transport),
        )
        llm.bind(max_tokens=60).invoke([HumanMessage(content=self.ASK)])
        llm.invoke([HumanMessage(content=self.ASK)])

        assert bodies[0]["max_tokens"] == 60
        assert bodies[0]["n_predict"] == 60
        assert "max_tokens" not in bodies[1]
        assert "n_predict" not in bodies[1]
        assert "max_completion_tokens" not in bodies[1]

    def test_hosted_openai_and_deepseek_payloads_are_unchanged(self) -> None:
        from langchain_core.messages import HumanMessage

        ask = [HumanMessage(content=self.ASK)]
        hosted, _ = _provider(base_url="", compat="standard")
        payload = hosted.build_model(model="gpt-4o", temperature=0.0)._get_request_payload(
            ask, stop=None, max_tokens=60
        )
        assert payload.get("max_completion_tokens") == 60
        assert "max_tokens" not in (payload.get("extra_body") or {})
        assert "n_predict" not in (payload.get("extra_body") or {})

        deepseek, _ = _provider(base_url="https://api.deepseek.example/v1", compat="deepseek")
        payload = deepseek.build_model(model="ds", temperature=0.0)._get_request_payload(
            ask, stop=None, max_tokens=60
        )
        assert payload.get("max_completion_tokens") == 60
        assert payload["extra_body"]["max_tokens"] == 60
        assert "n_predict" not in payload["extra_body"]

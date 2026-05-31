"""OpenAI LLM provider."""

from typing import Any

from langchain_core.language_models.chat_models import BaseChatModel

from maljan.core.config import Settings
from maljan.core.exceptions import LLMError
from maljan.llm.registry import register_provider


@register_provider("openai")
class OpenAIProvider:
    """Builds LangChain ChatOpenAI instances."""

    name = "openai"

    def __init__(self, config: Settings) -> None:
        self._config = config

    def build_model(
        self,
        model: str,
        temperature: float,
        **kwargs: Any,
    ) -> BaseChatModel:
        from langchain_openai import ChatOpenAI

        secret = self._config.llm.openai.api_key
        if not secret:
            raise LLMError("OPENAI_API_KEY is not set but provider is 'openai'.")

        from pydantic import SecretStr

        api_key = secret if isinstance(secret, SecretStr) else SecretStr(str(secret))
        build_kwargs: dict[str, Any] = {
            "model": model,
            "api_key": api_key,
            "temperature": temperature,
            **kwargs,
        }
        base_url = self._config.llm.openai.base_url
        if base_url:
            build_kwargs["base_url"] = base_url

        # Degenerate-loop guard (2026-06-01): forward a repetition penalty to
        # local OpenAI-compatible servers (llama.cpp / ik_llama.cpp) via
        # extra_body. The small reasoning model otherwise loops catastrophically
        # while trying to recall an ATT&CK technique ID, burning the whole decode
        # budget. Only when base_url is set (vanilla OpenAI would reject the param)
        # and the value is a real penalty. llama.cpp forks disagree on the key
        # name; send both — unknown sampler keys are ignored, not rejected.
        # Empirically (2026-06-01, live ik_llama probe): ``repeat_penalty`` is the
        # honored key (changes greedy output); ``repetition_penalty`` is silently
        # ignored. The penalty damps catastrophic single-token loops but does NOT
        # by itself make the small model converge on an ATT&CK ID — that is what
        # the deterministic TF-IDF re-grounding (correct_isr_reports) handles.
        rp = self._config.llm.openai.repetition_penalty
        if base_url and rp and rp != 1.0:
            extra = dict(build_kwargs.get("extra_body") or {})
            extra.setdefault("repeat_penalty", rp)
            extra.setdefault("repetition_penalty", rp)
            build_kwargs["extra_body"] = extra

        # Wave 5 HANG-01 + Wave 7 THROUGHPUT-01 (2026-05-28): explicit
        # ``request_timeout`` and ``max_retries`` so the openai SDK can't
        # silently retry a stalled request three times (3 x default 600s
        # = 30 min). Caller-supplied kwargs win.
        # ``request_timeout`` must be >= the longest agent ``wait_for``
        # budget; otherwise the HTTP layer truncates a still-decoding
        # response before the outer wrapper's hard cap fires (live trace
        # 2026-05-28 showed static analyst dropping at exactly 300s
        # because the previous Wave 5 value was tighter than its 600s
        # ReAct budget). 900s matches the worst case of static (600s) +
        # decode headroom on a cold-cache local 35B. ``max_retries=0``
        # keeps a single attempt regardless of size — the daemon-thread
        # cap in ``execute_tool_loop`` is the only retry policy we want.
        build_kwargs.setdefault("request_timeout", 900)
        build_kwargs.setdefault("max_retries", 0)

        return ChatOpenAI(**build_kwargs)

"""Ollama (local) LLM provider."""

from typing import Any

from langchain_core.language_models.chat_models import BaseChatModel

from maljan.core.config import Settings
from maljan.llm.registry import register_provider


@register_provider("ollama")
class OllamaProvider:
    """Builds LangChain ChatOllama instances for local models."""

    name = "ollama"

    def __init__(self, config: Settings) -> None:
        self._config = config

    def build_model(
        self,
        model: str,
        temperature: float,
        **kwargs: Any,
    ) -> BaseChatModel:
        from langchain_ollama import ChatOllama  # type: ignore[import-untyped]

        # A per-agent endpoint (``llm.agents.<key>.base_url``) wins over the
        # global one, so two agents can be served by two different Ollama hosts.
        base_url = kwargs.pop("base_url", None) or self._config.llm.ollama.base_url

        # ``reasoning=False`` is how langchain spells Ollama's ``think: false``.
        # Only sent when the deployment asked for it: a model with no thinking
        # mode is refused the field by Ollama, so "leave it alone" and "turn it
        # off" are different requests and the default is to leave it alone.
        if self._config.llm.ollama.disable_thinking:
            kwargs.setdefault("reasoning", False)

        # The output cap every other provider takes as ``max_tokens``. Ollama
        # spells it ``num_predict``, and ``ChatOllama`` drops a ``max_tokens``
        # it is handed without a word, so the judge's, the analysts' and a
        # composer section's caps reached an Ollama model as no cap at all.
        cap = kwargs.pop("max_tokens", None)
        if isinstance(cap, int) and cap > 0:
            kwargs.setdefault("num_predict", cap)

        # A request timeout, which the Ollama client has none of by default:
        # a server that stops answering otherwise holds the call until the
        # loop around it is cancelled. Caller-supplied client kwargs win.
        from maljan.llm.registry import PROVIDER_REQUEST_TIMEOUT_SECONDS

        client_kwargs = dict(kwargs.pop("client_kwargs", None) or {})
        client_kwargs.setdefault("timeout", PROVIDER_REQUEST_TIMEOUT_SECONDS)

        return ChatOllama(
            model=model,
            client_kwargs=client_kwargs,
            base_url=base_url,
            temperature=temperature,
            keep_alive=self._config.llm.ollama.keep_alive,
            num_ctx=self._config.llm.ollama.num_ctx,
            **kwargs,
        )

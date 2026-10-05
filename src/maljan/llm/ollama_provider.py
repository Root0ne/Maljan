"""Ollama (local) LLM provider."""

from typing import Any

from langchain_core.language_models.chat_models import BaseChatModel

from maljan.core.config import Settings
from maljan.llm.registry import register_provider

# One subclass per chat class seen, so pydantic builds each schema once.
_WATCHED_CLASSES: dict[type, type] = {}


def with_watched_streams(chat_class: Any) -> Any:
    """``chat_class`` reading each streamed answer under its caller's rule (``llm.stream_watch``).

    ``ChatOllama`` reads every answer as a stream, through
    ``_iterate_over_stream`` and ``_aiterate_over_stream``, whether it is
    invoked or streamed. Each piece is read under the rule the caller named for
    the call; once the rule says to end the answer, no further piece is read
    and the stream is closed, which ends the request, and the answer is the
    pieces read up to there, saying why (``stream_watch.ENDED_KEY``). Without
    a rule every piece is read. A transport failure while the answer streams,
    or before it, is raised as ``openai.APIConnectionError``
    (``generation_rate.as_connection_error``), as on the other streamed paths.
    Anything that is not such a class is returned as it is.
    """
    if not isinstance(chat_class, type) or not hasattr(chat_class, "_aiterate_over_stream"):
        return chat_class
    cached = _WATCHED_CLASSES.get(chat_class)
    if cached is not None:
        return cached
    base: Any = chat_class
    from maljan.llm.generation_rate import as_connection_error
    from maljan.llm.stream_watch import awatched, ends_recorded, mark_ended, watched

    def _iterate_over_stream(self: Any, messages: Any, stop: Any = None, **kwargs: Any) -> Any:
        try:
            yield from watched(base._iterate_over_stream(self, messages, stop, **kwargs))
        except Exception as exc:
            error = as_connection_error(exc)
            if error is exc:
                raise
            raise error from exc

    async def _aiterate_over_stream(
        self: Any, messages: Any, stop: Any = None, **kwargs: Any
    ) -> Any:
        try:
            async for chunk in awatched(base._aiterate_over_stream(self, messages, stop, **kwargs)):
                yield chunk
        except Exception as exc:
            error = as_connection_error(exc)
            if error is exc:
                raise
            raise error from exc

    def _generate(
        self: Any, messages: Any, stop: Any = None, run_manager: Any = None, **kwargs: Any
    ) -> Any:
        with ends_recorded() as ended:
            result = base._generate(self, messages, stop=stop, run_manager=run_manager, **kwargs)
        return mark_ended(result, ended[0]) if ended else result

    async def _agenerate(
        self: Any, messages: Any, stop: Any = None, run_manager: Any = None, **kwargs: Any
    ) -> Any:
        with ends_recorded() as ended:
            result = await base._agenerate(
                self, messages, stop=stop, run_manager=run_manager, **kwargs
            )
        return mark_ended(result, ended[0]) if ended else result

    watched_class = type(
        chat_class.__name__,
        (chat_class,),
        {
            "_iterate_over_stream": _iterate_over_stream,
            "_aiterate_over_stream": _aiterate_over_stream,
            "_generate": _generate,
            "_agenerate": _agenerate,
        },
    )
    watched_class.__module__ = __name__
    watched_class.__qualname__ = chat_class.__qualname__
    _WATCHED_CLASSES[chat_class] = watched_class
    return watched_class


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
        # ``ChatOllama`` streams every answer, so this bounds the silence
        # between two pieces of an answer rather than the whole answer: a long
        # answer is not cut by it, and no per-request sizing is needed here.
        from maljan.llm.registry import PROVIDER_REQUEST_TIMEOUT_SECONDS

        client_kwargs = dict(kwargs.pop("client_kwargs", None) or {})
        client_kwargs.setdefault("timeout", PROVIDER_REQUEST_TIMEOUT_SECONDS)

        # Every request held to a whole-call deadline sized for its answer
        # (``generation_rate.with_sized_request_timeout``): the client's
        # timeout above bounds only the silence between two pieces.
        from maljan.llm.generation_rate import with_sized_request_timeout

        # No request sends a tool call without a ``tool`` message after it,
        # whatever the history it was built from (``maljan.llm.tool_replies``).
        from maljan.llm.tool_replies import with_answered_tool_calls

        chat_class = with_answered_tool_calls(
            with_sized_request_timeout(with_watched_streams(ChatOllama)), "ollama"
        )
        return chat_class(  # type: ignore[no-any-return]
            model=model,
            client_kwargs=client_kwargs,
            base_url=base_url,
            temperature=temperature,
            keep_alive=self._config.llm.ollama.keep_alive,
            num_ctx=self._config.llm.ollama.num_ctx,
            **kwargs,
        )

"""Ollama (local) LLM provider."""

from typing import Any

from langchain_core.language_models.chat_models import BaseChatModel

from maljan.core.config import Settings
from maljan.llm.registry import register_provider

# One subclass per chat class seen, so pydantic builds each schema once.
_WATCHED_CLASSES: dict[type, type] = {}


def _text_joined(content: Any, pieces: list[str]) -> Any:
    """``content`` with the text ``pieces`` after it, joined as langchain joins message content."""
    from langchain_core.messages.base import merge_content

    return merge_content(content, "".join(pieces))


class _OllamaJoin:
    """``ChatOllama``'s own join of a stream (``final_chunk += chunk``), holding no chunk.

    Adding the whole chunks rebuilt the joined text and reasoning on every
    chunk, the square of the answer's length. The text and the reasoning are
    kept as pieces and joined once; the rest of each chunk, which is small, is
    added as it comes, and the joined chunk is the one langchain's join gives.
    """

    def __init__(self) -> None:
        self.joined: Any = None
        self.text: list[str] = []
        self.reasoning: list[str] = []

    def add(self, chunk: Any) -> None:
        # Its own message, so the chunk the run's callbacks were handed (a
        # LangSmith trace keeps it) stays as the server sent it.
        message = chunk.message
        message = message.model_copy(update={"additional_kwargs": dict(message.additional_kwargs)})
        chunk = chunk.model_copy(update={"message": message})
        if isinstance(message.content, str):
            if message.content:
                self.text.append(message.content)
                message.content = ""
        elif self.text:
            # Content that is not a string is added with langchain's own join,
            # so the text before it goes in first and keeps its place.
            self.joined.message.content = _text_joined(self.joined.message.content, self.text)
            self.text = []
        piece = message.additional_kwargs.get("reasoning_content")
        if isinstance(piece, str):
            self.reasoning.append(piece)
            del message.additional_kwargs["reasoning_content"]
        self.joined = chunk if self.joined is None else self.joined + chunk

    def result(self) -> Any:
        from langchain_core.outputs import ChatGenerationChunk

        if self.joined is None:
            raise ValueError("No data received from Ollama stream.")
        message = self.joined.message
        update: dict[str, Any] = {}
        if self.text:
            update["content"] = _text_joined(message.content, self.text)
        if self.reasoning:
            update["additional_kwargs"] = {
                **message.additional_kwargs,
                "reasoning_content": "".join(self.reasoning),
            }
        if update:
            message = message.model_copy(update=update)
        return ChatGenerationChunk(message=message, generation_info=self.joined.generation_info)


def with_watched_streams(chat_class: Any) -> Any:
    """``chat_class`` reading each streamed answer under its caller's rule (``llm.stream_watch``).

    ``ChatOllama`` reads every answer as a stream, through
    ``_iterate_over_stream`` and ``_aiterate_over_stream``, whether it is
    invoked or streamed. Each piece is read under the rule the caller named for
    the call; once the rule says to end the answer, no further piece is read
    and the stream is closed, which ends the request, and the answer is the
    pieces read up to there, saying why (``stream_watch.ENDED_KEY``). The
    pieces are joined as they arrive, holding no chunk (:class:`_OllamaJoin`). Without
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

    def _chat_stream_with_aggregation(
        self: Any,
        messages: Any,
        stop: Any = None,
        run_manager: Any = None,
        verbose: bool = False,  # noqa: FBT002
        **kwargs: Any,
    ) -> Any:
        join = _OllamaJoin()
        for chunk in self._iterate_over_stream(messages, stop, **kwargs):
            if run_manager:
                run_manager.on_llm_new_token(chunk.text, chunk=chunk, verbose=verbose)
            join.add(chunk)
        return join.result()

    async def _achat_stream_with_aggregation(
        self: Any,
        messages: Any,
        stop: Any = None,
        run_manager: Any = None,
        verbose: bool = False,  # noqa: FBT002
        **kwargs: Any,
    ) -> Any:
        join = _OllamaJoin()
        async for chunk in self._aiterate_over_stream(messages, stop, **kwargs):
            if run_manager:
                await run_manager.on_llm_new_token(chunk.text, chunk=chunk, verbose=verbose)
            join.add(chunk)
        return join.result()

    watched_class = type(
        chat_class.__name__,
        (chat_class,),
        {
            "_iterate_over_stream": _iterate_over_stream,
            "_aiterate_over_stream": _aiterate_over_stream,
            "_chat_stream_with_aggregation": _chat_stream_with_aggregation,
            "_achat_stream_with_aggregation": _achat_stream_with_aggregation,
            "_generate": _generate,
            "_agenerate": _agenerate,
        },
    )
    watched_class.__module__ = __name__
    watched_class.__qualname__ = chat_class.__qualname__
    _WATCHED_CLASSES[chat_class] = watched_class
    return watched_class


def _bind_async_client_per_loop(built: Any) -> None:
    """Give ``built``'s Ollama client async connections of each event loop's own.

    ``ChatOllama`` builds one ``ollama.AsyncClient`` (one httpx pool) per
    model, and one model is awaited on the agent loop and on the worker's own;
    a pooled connection reused across the two fails with "bound to a different
    event loop". Each loop gets an httpx client built by ``ollama.AsyncClient``
    from the same host and arguments ``ChatOllama`` used, so headers, the
    request timeout and the proxies httpx reads from the environment are what
    they were (``maljan.llm.loop_clients``); every request is still built by
    the original client.
    """
    from maljan.llm.loop_clients import layout_not_recognised, loop_bound_async_client

    holder: Any = getattr(built, "_async_client", None)
    import httpx

    original = getattr(holder, "_client", None)
    if not isinstance(original, httpx.AsyncClient):
        layout_not_recognised(
            "ollama", "ChatOllama holds no ollama.AsyncClient with an httpx client"
        )
        return
    try:
        from langchain_ollama._utils import merge_auth_headers, parse_url_with_auth
    except ImportError as exc:
        layout_not_recognised("ollama", f"langchain_ollama's URL helpers moved ({exc})")
        return
    client_class: Any = type(holder)
    client_kwargs = dict(built.client_kwargs or {})
    host, auth_headers = parse_url_with_auth(built.base_url)
    merge_auth_headers(client_kwargs, auth_headers)
    async_kwargs = {**client_kwargs, **(built.async_client_kwargs or {})}
    try:
        holder._client = loop_bound_async_client(
            lambda: client_class(host=host, **async_kwargs)._client, template=original
        )
    except TypeError as exc:
        layout_not_recognised("ollama", str(exc))


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
        from maljan.llm.transient import with_transient_retries

        # A server saying "not now" is asked again, a whole request at a time,
        # by the policy every provider's model uses (``maljan.llm.transient``).
        chat_class = with_answered_tool_calls(
            with_transient_retries(with_sized_request_timeout(with_watched_streams(ChatOllama))),
            "ollama",
        )
        built = chat_class(
            model=model,
            client_kwargs=client_kwargs,
            base_url=base_url,
            temperature=temperature,
            keep_alive=self._config.llm.ollama.keep_alive,
            num_ctx=self._config.llm.ollama.num_ctx,
            **kwargs,
        )
        # Its async connections never cross event loops.
        _bind_async_client_per_loop(built)
        return built  # type: ignore[no-any-return]

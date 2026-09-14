"""OpenAI LLM provider."""

from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urlparse

from langchain_core.language_models.chat_models import BaseChatModel

from maljan.core.config import Settings
from maljan.core.exceptions import LLMError
from maljan.core.logger import logger
from maljan.llm.registry import register_provider

# The request fields llama.cpp and its forks read and a hosted
# OpenAI-compatible API rejects. Named here because two things need the list:
# the builder, which decides whether to send them, and the 400 self-heal,
# which decides whether a rejection is about one of ours.
LLAMA_CPP_EXTRA_KEYS: tuple[str, ...] = (
    "repeat_penalty",
    "repetition_penalty",
    "n_predict",
    "max_tokens",
    "chat_template_kwargs",
)

# Base URLs already known to reject our extras, so the self-heal pays for the
# discovery once per process rather than on every call. Keyed by base URL: two
# endpoints behind one deployment can disagree.
_STANDARD_ONLY_ENDPOINTS: set[str] = set()

# "Unsupported parameter(s): n_predict", "unknown field \"repeat_penalty\"",
# "extra fields not permitted: chat_template_kwargs" — every phrasing seen has
# the parameter name in it, which is the only part worth matching.
_UNSUPPORTED_PARAM_RE = re.compile(
    r"unsupported|unrecognized|unknown|not permitted|invalid[_ ]?(?:request[_ ]?)?(?:param|field)",
    re.IGNORECASE,
)


def is_local_endpoint(base_url: str | None) -> bool:
    """Whether ``base_url`` names a server on this machine or this network.

    What ``compat: auto`` decides on. A loopback, link-local or RFC1918 host is
    a local server somebody started, and the only OpenAI-compatible servers
    people run there are llama.cpp and its forks. A public hostname is a hosted
    API, and hosted APIs validate their request bodies.
    """
    if not base_url:
        return False
    host = (urlparse(base_url).hostname or "").strip().lower()
    if not host:
        return False
    if host in ("localhost", "localhost.localdomain") or host.endswith(".localhost"):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        # A name, not an address. ``.local`` is mDNS on the local network;
        # anything else is resolved by somebody else and treated as hosted.
        return host.endswith(".local")
    return bool(address.is_loopback or address.is_link_local or address.is_private)


def sends_llama_cpp_extras(base_url: str | None, compat: str) -> bool:
    """Whether this endpoint gets the llama.cpp-only request fields."""
    if not base_url:
        # api.openai.com itself, which has always been left alone.
        return False
    if base_url in _STANDARD_ONLY_ENDPOINTS:
        return False
    if compat == "llama_cpp":
        return True
    if compat == "standard":
        return False
    return is_local_endpoint(base_url)


def unsupported_parameter(message: str) -> str | None:
    """The extra of ours a 400 is complaining about, or ``None``.

    Only ours: an endpoint rejecting ``temperature`` is telling us something
    else entirely, and dropping the llama.cpp extras would not fix it.
    """
    if not message or not _UNSUPPORTED_PARAM_RE.search(message):
        return None
    lowered = message.lower()
    for key in LLAMA_CPP_EXTRA_KEYS:
        # ``max_tokens`` is a standard field as well as an extra, so it is
        # matched last and only when nothing more specific is named.
        if key != "max_tokens" and key in lowered:
            return key
    return "max_tokens" if "max_tokens" in lowered or "n_predict" in lowered else None


def note_standard_only(base_url: str | None) -> bool:
    """Record that this endpoint refuses our extras. True the first time."""
    if not base_url or base_url in _STANDARD_ONLY_ENDPOINTS:
        return False
    _STANDARD_ONLY_ENDPOINTS.add(base_url)
    return True


def forget_standard_only(base_url: str | None = None) -> None:
    """Forget what the self-heal learned — for a test, or a changed endpoint."""
    if base_url is None:
        _STANDARD_ONLY_ENDPOINTS.clear()
    else:
        _STANDARD_ONLY_ENDPOINTS.discard(base_url)


def unshared_async_client(base_url: str | None, timeout: Any) -> Any | None:
    """An httpx async pool this model alone owns, or ``None`` if it cannot be built.

    ``langchain_openai`` caches its async client with ``@lru_cache`` keyed on
    ``(base_url, timeout, socket_options)``, so every model this provider builds
    for one endpoint — the analysts', the judge's, the reporter's — shares a
    single pool. An httpx pool belongs to the event loop that first awaited it,
    and this process has two that make LLM calls: the shared agent loop and the
    worker's own. The first call from the second loop dies inside httpx with
    "bound to a different event loop", which the openai SDK reports as a bare
    ``APIConnectionError("Connection error.")`` — the fault diagnosed for the
    judge and then seen again on the narrative round.

    Owning the pool is what makes the container's per-loop model cache mean
    anything: two models for two loops must not share one set of connections.
    The keepalive socket options langchain applies are kept by reusing its own
    builder; a version that no longer exposes it falls back to a plain client
    rather than to the shared one.
    """
    try:
        from langchain_openai.chat_models._client_utils import (  # noqa: PLC0415
            _build_async_httpx_client,
            _default_socket_options,
        )

        return _build_async_httpx_client(base_url, timeout, _default_socket_options())
    except Exception as exc:  # noqa: BLE001 — a private helper is allowed to move
        logger.debug("openai provider: langchain's client builder is unavailable (%s).", exc)
    try:
        import httpx  # noqa: PLC0415

        return httpx.AsyncClient(timeout=timeout)
    except Exception as exc:  # noqa: BLE001 — no client at all means the shared one
        logger.warning(
            "openai provider: could not build a private httpx pool (%s); this model "
            "shares langchain's cached one and must only be used from one event loop.",
            exc,
        )
        return None


def clear_shared_httpx_clients() -> None:
    """Empty ``langchain_openai``'s cached httpx clients. Never raises.

    The belt to :func:`unshared_async_client`'s braces: a model built somewhere
    that did not pass its own pool still holds a reference to the cached one,
    and after an agent loop is retired that pool is bound to a loop nothing will
    run again. Called from the container's retirement hook.
    """
    try:
        from langchain_openai.chat_models import _client_utils  # noqa: PLC0415

        for name in ("_cached_async_httpx_client", "_cached_sync_httpx_client"):
            cached = getattr(_client_utils, name, None)
            if cached is not None and hasattr(cached, "cache_clear"):
                cached.cache_clear()
    except Exception as exc:  # noqa: BLE001 — a cache that cannot be cleared is not a run
        logger.debug("openai provider: the shared httpx client cache was not cleared (%s).", exc)


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
        secret = self._config.llm.openai.api_key
        if not secret:
            raise LLMError("OPENAI_API_KEY is not set but provider is 'openai'.")

        # A per-agent endpoint (``llm.agents.<key>.base_url``) wins over the
        # global one, so two agents can sit on two different local servers.
        # The credential stays global: the key belongs to the provider, not to
        # the endpoint. Every local-server branch below keys off this resolved
        # value, so a per-agent server gets the same llama.cpp treatment.
        base_url = kwargs.pop("base_url", None) or self._config.llm.openai.base_url
        return self._build(model, temperature, base_url, dict(kwargs))

    def _build(
        self,
        model: str,
        temperature: float,
        base_url: str | None,
        kwargs: dict[str, Any],
        *,
        force_standard: bool = False,
    ) -> BaseChatModel:
        """One ``ChatOpenAI``, with or without the llama.cpp-only extras."""
        from langchain_openai import ChatOpenAI
        from pydantic import SecretStr

        secret = self._config.llm.openai.api_key
        api_key = secret if isinstance(secret, SecretStr) else SecretStr(str(secret))
        build_kwargs: dict[str, Any] = {
            "model": model,
            "api_key": api_key,
            "temperature": temperature,
            **kwargs,
        }
        if base_url:
            build_kwargs["base_url"] = base_url

        compat = str(getattr(self._config.llm.openai, "compat", "auto") or "auto")
        local = not force_standard and sends_llama_cpp_extras(base_url, compat)
        if local:
            self._add_llama_cpp_extras(build_kwargs, base_url)

        # Explicit ``request_timeout`` and ``max_retries`` so the openai SDK
        # can't silently retry a stalled request three times (3 x default
        # 600s = 30 min). Caller-supplied kwargs win.
        # ``request_timeout`` must be >= the longest agent ``wait_for``
        # budget; otherwise the HTTP layer truncates a still-decoding
        # response before the outer wrapper's hard cap fires (live trace
        # 2026-05-28 showed static analyst dropping at exactly 300s
        # because the previous value was tighter than its 600s
        # ReAct budget). 1800s (2026-07-13) stays >= the longest agent
        # ``wait_for`` hard cap: the deep-analysis restore raised static's
        # per-chunk budget to 1500s (hard cap timeout+30 = 1530s), plus decode
        # headroom on a cold-cache local 35B. ``max_retries=0`` keeps a single
        # attempt regardless of size — the daemon-thread cap in
        # ``execute_tool_loop`` is the only retry policy we want.
        build_kwargs.setdefault("request_timeout", 1800)
        build_kwargs.setdefault("max_retries", 0)

        # This model's own connection pool, so two models for two event loops
        # do not share one. See ``unshared_async_client``.
        if "http_async_client" not in build_kwargs:
            private = unshared_async_client(base_url, build_kwargs["request_timeout"])
            if private is not None:
                build_kwargs["http_async_client"] = private

        built = ChatOpenAI(**build_kwargs)
        if not local:
            return built
        # The rebuild the self-heal needs, carried on the model rather than
        # looked up again: only the provider knows what it sent.
        return _with_standard_retry(built, self, model, temperature, base_url, kwargs)

    def _add_llama_cpp_extras(self, build_kwargs: dict[str, Any], base_url: str | None) -> None:
        """The three request fields only llama.cpp and its forks read.

        Degenerate-loop guard: forward a repetition penalty. The small
        reasoning model otherwise loops catastrophically while trying to recall
        an ATT&CK technique ID, burning the whole decode budget. llama.cpp
        forks disagree on the key name; send both — empirically (live
        ik_llama probe) ``repeat_penalty`` is the honored key and
        ``repetition_penalty`` is silently ignored. The penalty damps
        catastrophic single-token loops but does NOT by itself make the small
        model converge on an ATT&CK ID — that is what the deterministic TF-IDF
        re-grounding (correct_isr_reports) handles.

        Output cap: ``ChatOpenAI(max_tokens=N)`` does not put ``max_tokens`` on
        the wire. ``langchain-openai`` renames it to OpenAI's newer
        ``max_completion_tokens``, and ik_llama.cpp's endpoint does not know
        that key — so it ignores the field and decodes without a ceiling.
        Measured: a judge call built with ``judge_max_tokens=8192`` generated
        30,155 tokens past a 1,403-token prompt before the client's 600 s
        wrapper gave up, and it was still going. Four of eight fixtures in the
        C3 study never returned a verdict for this reason.

        Thinking: disable a local reasoning model's chain-of-thought (Qwen3
        ``enable_thinking``) when configured. On a constrained host the model
        otherwise spends its whole decode budget inside ``<think>`` — empty
        answers and timeouts.

        All three go through ``extra_body``: it is the only channel that
        reaches the server verbatim, and an unknown sampler key is ignored by
        llama.cpp rather than rejected.
        """
        extra = dict(build_kwargs.get("extra_body") or {})

        rp = self._config.llm.openai.repetition_penalty
        if rp and rp != 1.0:
            extra.setdefault("repeat_penalty", rp)
            extra.setdefault("repetition_penalty", rp)

        cap = build_kwargs.get("max_tokens")
        if isinstance(cap, int) and cap > 0:
            extra.setdefault("max_tokens", cap)
            extra.setdefault("n_predict", cap)

        if self._config.llm.openai.disable_thinking:
            ctk = dict(extra.get("chat_template_kwargs") or {})
            ctk.setdefault("enable_thinking", False)
            extra["chat_template_kwargs"] = ctk

        if extra:
            build_kwargs["extra_body"] = extra
        logger.debug("openai provider: sending llama.cpp extras to %s.", base_url)


def _with_standard_retry(
    model_obj: BaseChatModel,
    provider: OpenAIProvider,
    model: str,
    temperature: float,
    base_url: str | None,
    kwargs: dict[str, Any],
) -> BaseChatModel:
    """Wrap the model so one 400 about our own extras rebuilds it without them.

    An endpoint that does not read the llama.cpp fields says so on the first
    request and every request after it, so the whole run is lost to a setting
    nobody knew was wrong. The rebuild happens once: the endpoint is recorded,
    every model built for it afterwards is standard, and the operator is told
    at warning level which setting to make explicit.
    """
    from openai import BadRequestError

    def _heal(exc: BadRequestError) -> BaseChatModel | None:
        parameter = unsupported_parameter(str(exc))
        if parameter is None:
            return None
        first = note_standard_only(base_url)
        if first:
            logger.warning(
                "openai provider: %s rejected %r, which only llama.cpp reads; retrying "
                "without the llama.cpp extras and sending standard fields to it from "
                "now on. Set llm.openai.compat to 'standard' to skip this.",
                base_url,
                parameter,
            )
        return provider._build(model, temperature, base_url, kwargs, force_standard=True)

    original_invoke = model_obj.invoke
    original_ainvoke = model_obj.ainvoke

    def invoke(*args: Any, **call_kwargs: Any) -> Any:
        try:
            return original_invoke(*args, **call_kwargs)
        except BadRequestError as exc:
            healed = _heal(exc)
            if healed is None:
                raise
            return healed.invoke(*args, **call_kwargs)

    async def ainvoke(*args: Any, **call_kwargs: Any) -> Any:
        try:
            return await original_ainvoke(*args, **call_kwargs)
        except BadRequestError as exc:
            healed = _heal(exc)
            if healed is None:
                raise
            return await healed.ainvoke(*args, **call_kwargs)

    # Assigned on the instance, not the class: a second model built for a
    # different endpoint must not inherit this one's retry.
    object.__setattr__(model_obj, "invoke", invoke)
    object.__setattr__(model_obj, "ainvoke", ainvoke)
    return model_obj

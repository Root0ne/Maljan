"""What an LLM provider says about itself, and where the platform asks it.

Every fact the platform needs about a model provider lives on that provider's
adapter class (``maljan.llm.<name>_provider``), declared on this base: which
metadata requests describe a model's window and which setting declares one,
the reasoning-effort setting and its levels, whether structured output is worth
asking for, which SDK packages raise its errors, whether its reasoning counts
against an output cap, how its prompt cache is priced, whether its endpoint
serves concurrent requests, whether an agent may point it at an endpoint of its
own, and the one short turn the settings probe asks it for and how that answer
is read. Shared modules ask through :func:`facts_of` and never compare a
provider's name, so a provider registered at runtime (``register_provider``)
gets every behaviour by subclassing :class:`LLMProvider` and answering for
itself.

The defaults below are the conservative answers for a provider that says
nothing: no window probe, no effort, no structured output, its endpoint judged
by where it is, no per-agent endpoint, no probe turn.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any, ClassVar, Literal

from maljan.core.logger import logger

# What every one-turn probe asks for and how much of an answer it takes: one
# turn, eight tokens, enough to prove the endpoint serves the model and short
# enough that a person at a button is not left waiting for prose.
COMPLETION_PROMPT = "Reply with OK."
COMPLETION_MAX_TOKENS = 8

Concurrency = Literal["serial", "hosted", "endpoint"]


@dataclass(frozen=True)
class OneTurnRequest:
    """The one short request a probe sends: where, with which headers, and the body."""

    url: str
    headers: dict[str, str]
    body: dict[str, Any]


@dataclass(frozen=True)
class ModelListing:
    """Where a provider lists its models, and how a model name is read out of the answer.

    ``where`` is the address an operator is told the listing was tried at.
    ``check`` reads the listed names against the settings and returns a
    sentence when a model the settings name is missing, ``None`` otherwise.
    """

    url: str
    headers: dict[str, str]
    names: Callable[[Any], list[str]]
    where: str
    noun: str = "models listed"
    check: Callable[[Any, list[str]], str | None] | None = None


def _text(value: Any) -> str:
    """One field as the text it holds, or nothing when it holds none."""
    return value.strip() if isinstance(value, str) else ""


class LLMProvider:
    """The interface every LLM provider adapter answers; the defaults are a silent provider's."""

    name: ClassVar[str] = ""
    # Where the provider stands among the choices the console offers; lower first.
    choice_order: ClassVar[int] = 100
    # The console's title and one-line description of this provider.
    label: ClassVar[str] = ""
    description: ClassVar[str] = ""
    # Whether the provider is a hosted API (a credential to enter) or a runtime
    # somebody runs (an address to enter).
    hosted: ClassVar[bool] = True
    # The settings leaf (under ``llm.<name>``) holding the credential, or empty.
    credential_leaf: ClassVar[str] = "api_key"
    # The leaves the console's setup step asks for first, under ``llm.<name>``.
    setup_leaves: ClassVar[tuple[str, ...]] = ()
    # The top-level packages whose exceptions are this provider's server answering.
    sdk_packages: ClassVar[frozenset[str]] = frozenset()
    # Whether the provider's own client retries a failed request, so the
    # platform's transient-retry policy leaves its errors alone.
    retries_inside_client: ClassVar[bool] = False
    # LangChain's ``_llm_type`` of the chat models this adapter builds.
    llm_types: ClassVar[tuple[str, ...]] = ()
    # The keyword a per-call output cap is passed under; ``None``: none is taken.
    per_call_cap_field: ClassVar[str | None] = "max_tokens"
    # The keyword the client's request timeout is passed under.
    timeout_kwarg: ClassVar[str] = "request_timeout"
    # Whether an agent's entry may name an endpoint of its own (``base_url``).
    supports_agent_base_url: ClassVar[bool] = False
    # The leaf under ``llm.<name>`` holding the provider's configured address, or ``None``.
    base_url_leaf: ClassVar[str | None] = None
    # Where calls go with no address configured: a URL, or the vendor's name.
    default_endpoint: ClassVar[str] = ""
    # The global setting a model's own effort inherits, or ``None``: no effort is sent.
    effort_setting: ClassVar[str | None] = None
    # ``serial``: taken to serve one request at a time; ``hosted``: a vendor API
    # serving any number; ``endpoint``: decided by where the endpoint is and
    # what its ``/props`` reports.
    concurrency: ClassVar[Concurrency] = "endpoint"
    # Whether a cached prefix is readable only once an answer to the request
    # that wrote it has begun, so concurrent first requests each write it.
    caches_once_answered: ClassVar[bool] = False
    # The ``additional_kwargs`` keys a rebuilt turn keeps, the reasoning this
    # provider asks to have sent back.
    reasoning_passback_keys: ClassVar[tuple[str, ...]] = ()
    # Whether the window-metadata request needs the credential to answer.
    window_probe_needs_key: ClassVar[bool] = False

    # ── Settings ──────────────────────────────────────────────────────────

    @classmethod
    def settings_block(cls, settings: Any) -> Any:
        """``llm.<name>``, the provider's own settings, or ``None``."""
        return getattr(getattr(settings, "llm", None), cls.name, None)

    @classmethod
    def api_key(cls, settings: Any) -> str:
        """The credential, as a plain string; ``""`` when none is set."""
        if not cls.credential_leaf:
            return ""
        secret = getattr(cls.settings_block(settings), cls.credential_leaf, None)
        if secret is None:
            return ""
        reveal = getattr(secret, "get_secret_value", None)
        return str(reveal() if callable(reveal) else secret)

    @classmethod
    def configured_base_url(cls, settings: Any) -> str | None:
        """The configured address of this provider, or ``None``."""
        if not cls.base_url_leaf:
            return None
        value = getattr(cls.settings_block(settings), cls.base_url_leaf, None)
        return str(value) if value else None

    @classmethod
    def endpoint(cls, own: object = None, configured: object = None) -> str:
        """Where a call goes: an entry's own address, the configured one, else the default."""
        from maljan.core.model_assignments import normalised_endpoint

        named = normalised_endpoint(own) if cls.supports_agent_base_url else ""
        address = normalised_endpoint(configured) if cls.base_url_leaf else ""
        return named or address or cls.default_endpoint or cls.name

    # ── Reasoning effort ──────────────────────────────────────────────────

    @classmethod
    def effort_levels(cls, model: str) -> tuple[list[str] | None, list[str], str]:
        """``(levels, undescribed, source)`` an effort field may offer for ``model``.

        ``levels`` ``None``: the endpoint names its own levels and the value is
        sent as written. Only asked of a provider with an ``effort_setting``.
        """
        return None, [], "none"

    @classmethod
    def effort_refusal(cls, effort: str) -> str | None:
        """Why ``effort`` cannot be sent to this provider, or ``None`` when it can."""
        return None

    # ── Structured output ─────────────────────────────────────────────────

    @classmethod
    def supports_structured_output(cls, settings: Any) -> bool:
        """Whether ``with_structured_output`` is worth asking of this provider."""
        return False

    @classmethod
    def model_declines_structured_output(cls, llm: Any) -> bool:
        """Whether a model object this provider built says structured output is not worth asking."""
        return False

    # ── Context window ────────────────────────────────────────────────────

    @classmethod
    def window_probes(cls, endpoint: object, model: str) -> tuple[Any, ...]:
        """The metadata requests (``context_window.Ask``) for ``model``'s window, best first."""
        return ()

    @classmethod
    def declared_window(cls, settings: Any) -> tuple[int, bool]:
        """``(tokens, is_default)`` for the window its settings name; ``(0, False)``: none."""
        return 0, False

    @classmethod
    def reasoning_counts_against_cap(cls, settings: Any) -> bool:
        """Whether a model left reasoning spends its output cap on it under ``settings``."""
        return False

    # ── Spend ─────────────────────────────────────────────────────────────

    @classmethod
    def writes_hour_caches(cls, settings: Any) -> bool:
        """Whether this provider's requests write the prompt cache for an hour."""
        return False

    # ── The settings probe's one turn ─────────────────────────────────────

    @classmethod
    def model_listing(cls, settings: Any) -> ModelListing | None:
        """Where the probe lists this provider's models, or ``None``: it lists none."""
        return None

    @classmethod
    def probed_model(cls, settings: Any, listed: list[str]) -> str:
        """The model the probe asks first: the configured expert model, else the first listed."""
        block = cls.settings_block(settings)
        return str(getattr(block, "expert_model", "") or (listed[0] if listed else ""))

    @classmethod
    def one_turn_request(
        cls, settings: Any, endpoint: str, model: str, effort: str | None = None
    ) -> OneTurnRequest | None:
        """The one short request the probe sends ``model`` at ``endpoint``, as a job would."""
        return None

    @classmethod
    def said_something(cls, payload: Any) -> bool:
        """Whether a decoded answer carries anything; an unknown shape counts as an answer."""
        return bool(payload)

    @classmethod
    def silence_remedy(cls, settings: Any) -> str:
        """A sentence on what to try when the model answered nothing, or ``""``."""
        return ""


# ── Lookup ────────────────────────────────────────────────────────────────

# Every adapter class ``register_provider`` saw, by name, kept apart from the
# build registry so a test that swaps a builder in leaves the facts in place.
_FACTS: dict[str, type[LLMProvider]] = {}


def remember_facts(name: str, cls: Any) -> None:
    """Keep ``cls``'s facts under ``name`` when it answers the interface."""
    if isinstance(cls, type) and issubclass(cls, LLMProvider):
        _FACTS[str(name)] = cls


def _discover() -> None:
    try:
        from maljan.llm.registry import discover_providers

        discover_providers()
    except Exception as exc:  # noqa: BLE001 — a registry that cannot load answers with defaults
        logger.debug("LLM providers could not all be discovered (%s).", type(exc).__name__)


def facts_of(name: object) -> type[LLMProvider]:
    """The adapter class answering for provider ``name``; the silent defaults when none does."""
    _discover()
    from maljan.llm.registry import _PROVIDER_REGISTRY

    key = str(name or "")
    built = _PROVIDER_REGISTRY.get(key)
    if isinstance(built, type) and issubclass(built, LLMProvider):
        return built
    return _FACTS.get(key, LLMProvider)


def provider_names() -> list[str]:
    """Every registered provider's name, in the order each declares (``choice_order``)."""
    _discover()
    from maljan.llm.registry import _PROVIDER_REGISTRY

    return sorted(_PROVIDER_REGISTRY, key=lambda name: (facts_of(name).choice_order, name))


def registered_facts() -> list[type[LLMProvider]]:
    """The facts of every registered provider, in their declared order."""
    return [facts_of(name) for name in provider_names()]


def _packages(facts: Iterable[type[LLMProvider]]) -> frozenset[str]:
    out: set[str] = set()
    for one in facts:
        out.update(one.sdk_packages)
    return frozenset(out)


def provider_error_packages() -> frozenset[str]:
    """The SDK packages whose exceptions are a provider's server answering."""
    return _packages(registered_facts())


def transient_error_packages() -> frozenset[str]:
    """The SDK packages whose errors the platform's retry policy reads.

    A provider whose own client retries (``retries_inside_client``) is left out,
    so the two never ask again on top of each other.
    """
    return _packages(f for f in registered_facts() if not f.retries_inside_client)


def provider_of_model(llm: Any) -> type[LLMProvider] | None:
    """The adapter that built ``llm``, read from its LangChain ``_llm_type``; ``None`` unknown."""
    try:
        kind = str(llm._llm_type)
    except Exception:  # noqa: BLE001 — a model that names no type is no provider's
        return None
    for one in registered_facts():
        if kind in one.llm_types:
            return one
    return None


def reasoning_passback_keys() -> frozenset[str]:
    """Every key any registered provider asks to have sent back with a rebuilt turn."""
    out: set[str] = set()
    for one in registered_facts():
        out.update(one.reasoning_passback_keys)
    return frozenset(out)


def effort_providers() -> list[str]:
    """The registered providers that send a reasoning effort."""
    return [name for name in provider_names() if facts_of(name).effort_setting]

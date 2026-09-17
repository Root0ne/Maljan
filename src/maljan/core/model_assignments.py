"""Which model each agent would call, and where it would call it.

A model name is the one part of a definition nothing checks until the run
reaches that agent. A typo in a per-agent override, an Ollama tag that was
never pulled, an endpoint that has been restarted with a different model
loaded: each of those fails minutes into an analysis, with a sample uploaded,
a queue slot spent and the failure surfacing as a provider error rather than
as the configuration mistake it is.

The settings probe already answers the question. What this module is for is
saying the question precisely: the pair a probe result is filed under is
``(endpoint, model)``, because those two are what a probe actually reached.
The provider is carried alongside for the sentence a refusal prints, but it is
not part of the key — two providers cannot serve one model at one endpoint.

An endpoint is a URL where a provider has one, and the vendor's own name where
it does not: Anthropic and Gemini are vendor APIs with nothing per-agent to
override, so "the Anthropic API" is the whole of what an address means there.

There is one function that answers where a call goes, and the settings probe
calls it too. A probe that worked the address out for itself and a gate that
worked it out from here would agree until they did not — a vendor with no URL,
a trailing slash on a base URL — and the operator would see a green test
followed by a refused job, with nothing on either screen saying why.
"""

from __future__ import annotations

from dataclasses import dataclass

# Where a provider with no configurable endpoint sends its calls. Not a URL,
# because nothing here would do anything with one: it is the name of the only
# place that provider can be reached.
_VENDOR_ENDPOINTS = {
    "anthropic": "the Anthropic API",
    "gemini": "the Gemini API",
}
# What an entry with no base_url of its own talks to.
_OPENAI_DEFAULT = "https://api.openai.com/v1"
_OLLAMA_DEFAULT = "http://localhost:11434"


@dataclass(frozen=True)
class ModelAssignment:
    """One agent, and the model it would call at the endpoint it would use."""

    agent: str
    provider: str
    endpoint: str
    model: str

    @property
    def key(self) -> tuple[str, str]:
        """What a stored probe result is filed under."""
        return (self.endpoint, self.model)


def normalised_endpoint(url: object) -> str:
    """One address, one spelling: trimmed, with no trailing slash.

    A base URL typed ``http://box:8080/v1/`` and the same one typed without the
    slash are one server. Folding them here, in the one place the endpoint is
    worked out, is what keeps a row filed under one spelling from being looked
    up under the other.
    """
    return str(url or "").strip().rstrip("/")


def endpoint_where(
    provider: str,
    base_url: object = None,
    *,
    openai_base_url: object = None,
    ollama_base_url: object = None,
) -> str:
    """Where ``provider`` sends its calls, an entry's own ``base_url`` first.

    The plain-value form of ``endpoint_for``, for the settings probe, which
    holds staged values rather than a settings object. One function under both
    so that the address a probe files its answer under and the address the gate
    looks that answer up under cannot be two.
    """
    named = normalised_endpoint(base_url)
    if provider == "openai":
        return named or normalised_endpoint(openai_base_url) or _OPENAI_DEFAULT
    if provider == "ollama":
        return named or normalised_endpoint(ollama_base_url) or _OLLAMA_DEFAULT
    return _VENDOR_ENDPOINTS.get(provider, provider)


def endpoint_for(settings: object, provider: str, base_url: str | None = None) -> str:
    """Where ``provider`` sends its calls under ``settings``, agent override first."""
    llm = settings.llm  # type: ignore[attr-defined]
    return endpoint_where(
        provider,
        base_url,
        openai_base_url=llm.openai.base_url,
        ollama_base_url=llm.ollama.base_url,
    )


def assignment_for(settings: object, agent: str) -> ModelAssignment:
    """What ``agent`` would call, its own override over the global expert model."""
    llm = settings.llm  # type: ignore[attr-defined]
    override = llm.agents.get(agent)
    if override is not None:
        provider = str(override.provider)
        return ModelAssignment(
            agent=agent,
            provider=provider,
            endpoint=endpoint_for(settings, provider, override.base_url),
            model=str(override.model),
        )
    provider = str(llm.provider)
    return ModelAssignment(
        agent=agent,
        provider=provider,
        endpoint=endpoint_for(settings, provider),
        model=str(llm.expert_model),
    )


def assignments_for(settings: object, agents: list[str]) -> list[ModelAssignment]:
    """One assignment per agent, in the order given, without repeating an agent."""
    return [assignment_for(settings, agent) for agent in dict.fromkeys(agents)]

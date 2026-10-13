"""What the console is told about each provider, read from the providers' own declarations.

Titles, descriptions, credential keys, hosted or run locally, connection-test
labels, per-agent endpoints and effort settings live on each registered
provider (``maljan.llm.provider_base.LLMProvider``, the static and sandbox
provider classes, the memory backends, the reputation sources). This module
gathers them for the settings schema, so the console keeps no table of
providers of its own and a provider registered tomorrow is described the day
it is registered.
"""

from __future__ import annotations

from typing import Any

# The labels of the probes that are the API's own rather than a provider's.
OWN_PROBE_LABELS: dict[str, str] = {
    "llm": "Test connection & fetch models",
    "mcp": "Test MCP server",
    "agent": "Resolve agent",
    "redis": "Test Redis",
}

LLM_SELECTOR = "core.llm.provider"
STATIC_SELECTOR = "core.static.provider"
SANDBOX_SELECTOR = "core.sandbox.provider"


def _llm_choices() -> tuple[dict[str, str], dict[str, str], dict[str, dict[str, Any]]]:
    from maljan.llm.provider_base import facts_of, provider_names

    titles: dict[str, str] = {}
    descriptions: dict[str, str] = {}
    facts: dict[str, dict[str, Any]] = {}
    for name in provider_names():
        provider = facts_of(name)
        prefix = f"core.llm.{name}."
        titles[name] = provider.label or name
        descriptions[name] = provider.description
        credential = [prefix + provider.credential_leaf] if provider.credential_leaf else []
        facts[name] = {
            "hosted": bool(provider.hosted),
            "credential_keys": credential
            + [f"core.{key}" for key in provider.legacy_credential_keys],
            "base_url_key": prefix + provider.base_url_leaf if provider.base_url_leaf else None,
            # Up front, then folded under "Advanced": the meaning both lists
            # have on every provider selector.
            "guide_keys": [
                prefix + leaf
                for leaf in provider.guide_leaves
                if leaf not in provider.guide_advanced_leaves
            ],
            "guide_advanced_keys": [prefix + leaf for leaf in provider.guide_advanced_leaves],
            "model_keys": [prefix + "expert_model", prefix + "judge_model"],
            "agent_base_url": bool(provider.supports_agent_base_url),
            "effort_key": f"core.{provider.effort_setting}" if provider.effort_setting else None,
            "probe": "llm",
            "probe_note": provider.probe_note,
        }
    return titles, descriptions, facts


def _expanded(prefix: str, leaves: tuple[str, ...], keys: list[str]) -> list[str]:
    """Catalog keys for a provider's declared leaves: a leaf ending in "." is every key under it."""
    out: list[str] = []
    for leaf in leaves:
        if leaf.endswith("."):
            out.extend(key for key in keys if key.startswith(prefix + leaf))
        elif prefix + leaf in keys:
            out.append(prefix + leaf)
    return list(dict.fromkeys(out))


def _registry_choices(
    selector: str, classes: dict[str, type], keys: list[str]
) -> tuple[dict[str, str], dict[str, str], dict[str, dict[str, Any]], dict[str, str]]:
    titles: dict[str, str] = {}
    descriptions: dict[str, str] = {}
    facts: dict[str, dict[str, Any]] = {}
    labels: dict[str, str] = {}
    namespace = selector.rsplit(".", 1)[0]
    for provider_id, cls in classes.items():
        titles[provider_id] = str(getattr(cls, "title", "") or provider_id)
        descriptions[provider_id] = str(getattr(cls, "description", "") or "")
        label = str(getattr(cls, "choice_label", "") or "")
        if label:
            labels[provider_id] = label
        prefix = f"{namespace}.{provider_id}."
        fact: dict[str, Any] = {
            # A provider with a test of its own names it by its id.
            "probe": provider_id if getattr(cls, "probe_label", "") else None,
            "intro": str(getattr(cls, "settings_intro", "") or ""),
        }
        guide = tuple(getattr(cls, "guide_leaves", ()) or ())
        folded = tuple(getattr(cls, "guide_advanced_leaves", ()) or ())
        if guide or folded:
            fact["guide_keys"] = _expanded(prefix, guide, keys)
            fact["guide_advanced_keys"] = _expanded(prefix, folded, keys)
        facts[provider_id] = fact
    return titles, descriptions, facts, labels


def selector_choices(
    keys: list[str],
) -> dict[str, tuple[dict[str, str], dict[str, str], dict[str, dict[str, Any]], dict[str, str]]]:
    """Each provider selector's per-choice titles, descriptions, facts and reader labels.

    ``keys`` are the catalog's keys in order, against which a provider's
    declared guide leaves are expanded.
    """
    from maljan.providers.registry import _SANDBOX_REGISTRY, _STATIC_REGISTRY, discover_providers

    discover_providers()
    titles, descriptions, facts = _llm_choices()
    return {
        LLM_SELECTOR: (titles, descriptions, facts, {}),
        STATIC_SELECTOR: _registry_choices(
            STATIC_SELECTOR, dict(sorted(_STATIC_REGISTRY.items())), keys
        ),
        SANDBOX_SELECTOR: _registry_choices(
            SANDBOX_SELECTOR, dict(sorted(_SANDBOX_REGISTRY.items())), keys
        ),
    }


def probe_labels(enrichment_sources: Any = None) -> dict[str, str]:
    """The label of every connection test the settings route answers, by probe id.

    ``enrichment_sources`` is the stored ``api.enrichment_sources`` map: each
    source in force that declares a test is labelled by its own title.
    """
    from maljan.enrichment.declared import effective_sources
    from maljan.memory.store_factory import registered_backends
    from maljan.providers.registry import _SANDBOX_REGISTRY, _STATIC_REGISTRY, discover_providers

    discover_providers()
    labels = dict(OWN_PROBE_LABELS)
    for registry in (_STATIC_REGISTRY, _SANDBOX_REGISTRY):
        for provider_id, cls in registry.items():
            label = str(getattr(cls, "probe_label", "") or "")
            if label:
                labels.setdefault(provider_id, label)
    for backend_id, backend in registered_backends().items():
        if backend.probe_label:
            labels.setdefault(backend_id, backend.probe_label)
    held = enrichment_sources if isinstance(enrichment_sources, dict) else {}
    for source_id, source in effective_sources(held).items():
        if source.probe is not None:
            labels.setdefault(source_id, f"Test {source.title(source_id)}")
    return labels


def server_keys() -> tuple[list[str], list[str]]:
    """The built-in tool-server keys, and the keys no operator's server may take."""
    from maljan.core.config import BUILTIN_SERVER_KEYS, RESERVED_SERVER_KEYS

    return list(BUILTIN_SERVER_KEYS), list(RESERVED_SERVER_KEYS)

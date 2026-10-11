"""The settings schema carries what each provider declares, so the console keeps no table.

Titles, descriptions, credential keys, hosted or run locally, connection-test
labels, per-agent endpoints and effort settings are read from the providers'
own declarations; the built-in and reserved tool-server keys from core. A
provider registered at runtime is described the day it is registered.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest

from app.services.provider_facts import OWN_PROBE_LABELS, probe_labels
from app.services.settings_catalog_api import resolved_catalog
from maljan.core.config import BUILTIN_SERVER_KEYS, RESERVED_SERVER_KEYS
from maljan.llm import registry
from maljan.llm.provider_base import _FACTS, LLMProvider, facts_of, provider_names


def _entry(key: str) -> Any:
    return next(e for e in resolved_catalog([]) if e.key == key)


def test_the_llm_selector_offers_every_registered_provider_with_its_own_facts():
    entry = _entry("core.llm.provider")
    assert entry.type == "enum"
    assert entry.choices == provider_names()
    for name in provider_names():
        facts = facts_of(name)
        assert entry.choice_titles[name] == facts.label
        served = entry.choice_facts[name]
        assert served["hosted"] is facts.hosted
        assert served["agent_base_url"] is facts.supports_agent_base_url
        expected_effort = f"core.{facts.effort_setting}" if facts.effort_setting else None
        assert served["effort_key"] == expected_effort
        assert served["probe"] == "llm"


def test_every_key_a_provider_names_is_a_catalog_key():
    keys = {e.key for e in resolved_catalog([])}
    for selector in ("core.llm.provider", "core.static.provider", "core.sandbox.provider"):
        for choice, served in (_entry(selector).choice_facts or {}).items():
            named = [
                *served.get("credential_keys", []),
                *served.get("guide_keys", []),
                *served.get("guide_advanced_keys", []),
                *served.get("model_keys", []),
                *([served["effort_key"]] if served.get("effort_key") else []),
                *([served["base_url_key"]] if served.get("base_url_key") else []),
            ]
            missing = [key for key in named if key not in keys]
            assert missing == [], (selector, choice, missing)


def test_a_static_or_sandbox_provider_with_a_test_names_one_the_route_answers():
    from app.services.settings_probes import known_probe

    labels = probe_labels()
    for selector in ("core.static.provider", "core.sandbox.provider"):
        entry = _entry(selector)
        assert set(entry.choice_titles) == set(entry.choices)
        for choice, served in entry.choice_facts.items():
            if served["probe"]:
                assert known_probe(served["probe"]) and served["probe"] in labels, choice


def test_every_probe_the_route_answers_is_labelled():
    from app.services.settings_probes import probe_names

    labels = probe_labels()
    for name, label in OWN_PROBE_LABELS.items():
        assert labels[name] == label
    assert set(labels) <= set(probe_names())


def test_the_server_map_carries_the_built_in_and_reserved_keys():
    entry = next(e for e in resolved_catalog([]) if e.editor == "server_map")
    assert entry.builtin_servers == list(BUILTIN_SERVER_KEYS)
    assert entry.reserved_servers == list(RESERVED_SERVER_KEYS)


class _Invented(LLMProvider):
    name = "invented"
    label = "Invented runtime"
    description = "A runtime registered while the API runs."
    hosted = False
    credential_leaf = ""

    def __init__(self, config: Any) -> None:
        self._config = config


@pytest.fixture
def _invented() -> Iterator[None]:
    registry.discover_providers()
    registry.register_provider("invented")(_Invented)
    try:
        yield
    finally:
        registry._PROVIDER_REGISTRY.pop("invented", None)
        _FACTS.pop("invented", None)


@pytest.mark.usefixtures("_invented")
def test_a_provider_registered_at_runtime_is_offered_and_described():
    entry = _entry("core.llm.provider")
    assert "invented" in entry.choices
    assert entry.choice_titles["invented"] == "Invented runtime"
    assert entry.choice_descriptions["invented"] == "A runtime registered while the API runs."
    assert entry.choice_facts["invented"]["hosted"] is False

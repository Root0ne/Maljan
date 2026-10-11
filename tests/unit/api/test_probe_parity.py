"""Every probe the catalog can name is wired up, and every provider answers for its own.

A catalog leaf naming a ``probe`` id the route does not answer is a broken
"Test" button. The route answers its own four probes (the model probe, a tool
server, an agent definition, the queue) and every registered provider's id,
static, sandbox, memory backend or reputation source, through that provider's
own test; there is no table of probes to fall behind.
"""

from __future__ import annotations

from app.services.settings_catalog_api import full_catalog
from app.services.settings_probes import OWN_PROBES, known_probe, probe_names
from maljan.llm.provider_base import facts_of, provider_names


def test_every_probe_the_catalog_names_is_answered():
    catalog_probe_ids = {e.probe for e in full_catalog() if e.probe}
    missing = sorted(probe for probe in catalog_probe_ids if not known_probe(probe))
    assert missing == [], missing


def test_every_registered_provider_has_a_probe_and_nothing_else_does():
    from maljan.enrichment.sources import reputation_sources
    from maljan.memory.store_factory import memory_backends
    from maljan.providers.registry import sandbox_provider_ids, static_provider_ids

    registered = {
        *static_provider_ids(),
        *sandbox_provider_ids(),
        *memory_backends(),
        *reputation_sources(),
    }
    assert set(probe_names()) == set(OWN_PROBES) | registered
    assert not known_probe("not-a-provider")


def test_every_llm_setting_the_probe_reads_is_annotated_with_the_llm_probe():
    """The staged value only travels if its own leaf declares the probe.

    The web collects the probe's key set from the catalog entries whose
    ``probe`` is ``llm``: a leaf an adapter reads for its test but no
    annotation names is one the backend silently falls back to a stored value
    for.
    """
    by_key = {e.key: e for e in full_catalog()}
    unannotated: list[str] = []
    for name in provider_names():
        facts = facts_of(name)
        leaves = {"expert_model", "judge_model", facts.credential_leaf, facts.base_url_leaf or ""}
        for leaf in sorted(leaf for leaf in leaves if leaf):
            key = f"core.llm.{name}.{leaf}"
            if key in by_key and by_key[key].probe != "llm":
                unannotated.append(key)
    assert unannotated == [], unannotated

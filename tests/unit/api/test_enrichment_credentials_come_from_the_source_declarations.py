"""The secret settings the enrichment sources read are generated from their declarations.

No table in the API names a source: each shipped declaration's ``credential``
makes one secret setting, titled by the source's label, described by what
leaves the host for which host, and tested by the source's own declared probe.
A source the platform has never seen makes its own the same way.
"""

from __future__ import annotations

from pathlib import Path

from app.services.enrichment_sources import credential_settings
from app.services.settings_catalog_api import API_DEFAULTS, catalog_index
from app.services.settings_probes import known_probe
from maljan.enrichment.builtin_sources import builtin_source_entries
from maljan.enrichment.declared import credential_settings_of, effective_sources

_ROOT = Path(__file__).resolve().parents[3]
HOST = ".".join(["rep", "acme-labs", "net"])


def test_every_shipped_source_s_credential_is_a_generated_secret_setting() -> None:
    shipped = effective_sources({})
    generated = credential_settings_of(builtin_source_entries())
    assert {s.key for s in generated.values()} == {
        source.credential for source in shipped.values() if source.credential
    }
    index = catalog_index()
    for setting in generated.values():
        source = shipped[setting.source]
        entry = index[setting.key]
        assert API_DEFAULTS[setting.path] == ""
        assert (entry.type, entry.secret, entry.group) == ("secret", True, "enrichment")
        assert entry.title == f"{source.title(setting.source)} API key"
        assert entry.probe == (setting.source if source.probe is not None else None)
        assert entry.probe is None or known_probe(entry.probe)
        for request in source.requests.values():
            assert request.host in entry.description
    # The secrets a source may name are exactly those.
    assert credential_settings() == frozenset(s.key for s in generated.values())


def test_a_never_seen_source_makes_its_own_setting() -> None:
    entries = {
        "acme": {
            "label": "Acme Rep",
            "kinds": ["domain", "ip"],
            "requests": {
                kind: {"url": f"https://{HOST}/{kind}/{{value}}", "headers": {"k": "{credential}"}}
                for kind in ("domain", "ip")
            },
            "credential": "api.acme_rep_key",
            "probe": {"url": f"https://{HOST}/ping", "headers": {"k": "{credential}"}},
            "record": [{"name": "malicious", "path": "/bad", "read": "count"}],
        },
        # One that does not validate makes none.
        "broken": {"kinds": ["domain"], "credential": "api.broken_key"},
    }
    made = credential_settings_of(entries)
    assert list(made) == ["acme_rep_key"]
    setting = made["acme_rep_key"]
    assert (setting.key, setting.title, setting.probe) == (
        "api.acme_rep_key",
        "Acme Rep API key",
        True,
    )
    assert HOST in setting.description
    assert "domains and IPs" in setting.description


def test_the_api_s_settings_and_probe_tables_name_no_source() -> None:
    names: set[str] = set()
    for key, entry in builtin_source_entries().items():
        names.add(key)
        names.add(str(entry.get("label") or ""))
        names.add(str(entry.get("credential") or "").partition(".")[2])
    names.discard("")
    for rel in (
        "apps/api/app/services/settings_catalog_api.py",
        "apps/api/app/services/settings_probes.py",
        "apps/api/app/services/enrichment_sources.py",
        "apps/api/app/services/enrichment_tools.py",
    ):
        text = (_ROOT / rel).read_text(encoding="utf-8").lower()
        assert not [name for name in names if name.lower() in text], rel

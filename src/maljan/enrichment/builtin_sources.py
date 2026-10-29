"""The enrichment sources the platform ships, as declarations of :mod:`maljan.enrichment.declared`.

Data only, in the schema every operator-declared source uses. With their keys
set they make the calls the enrichment has always made and store the record
it has always stored in ``network.domains[].reputation`` and
``network.ips[].reputation``: the domain and address lookups of VirusTotal's
v3 API (paced at one call per 16 s, its free tier's four a minute with a
margin) and AbuseIPDB's v2 check, which answers for an address VirusTotal had
nothing on. An operator turns one off, or changes any field, by storing an
entry under the same key in ``api.enrichment_sources``.

These declarations are the only place a shipped source is named: the secret
setting each reads its credential from, its title, description and connection
test are generated from its ``credential``, ``label``, ``kinds``, request
hosts and ``probe`` (``enrichment.declared.credential_settings_of``).
"""

from __future__ import annotations

from typing import Any

_VT_API = "https://www.virustotal.com/api/v3"
_VT_HEADERS = {"x-apikey": "{credential}", "accept": "application/json"}
_ABUSE_CHECK = "https://api.abuseipdb.com/api/v2/check"

_BUILTIN_SOURCES: dict[str, dict[str, Any]] = {
    "virustotal": {
        "label": "VirusTotal",
        "kinds": ["domain", "ip"],
        "order": 10,
        "requests": {
            "domain": {"url": f"{_VT_API}/domains/{{value}}", "headers": _VT_HEADERS},
            "ip": {"url": f"{_VT_API}/ip_addresses/{{value}}", "headers": _VT_HEADERS},
        },
        "credential": "api.virustotal_api_key",
        # A public address any valid key may look up (``/users/current`` needs a user key).
        "probe": {
            "url": f"{_VT_API}/ip_addresses/8.8.8.8",
            "headers": {"x-apikey": "{credential}"},
        },
        "timeout_seconds": 30.0,
        "rate_limit_seconds": 16.0,
        "answer_root": "/data",
        "record": [
            {
                "name": "malicious",
                "path": "/attributes/last_analysis_stats/malicious",
                "read": "count",
            },
            {
                "name": "suspicious",
                "path": "/attributes/last_analysis_stats/suspicious",
                "read": "count",
            },
            {
                "name": "harmless",
                "path": "/attributes/last_analysis_stats/harmless",
                "read": "count",
            },
            {
                "name": "undetected",
                "path": "/attributes/last_analysis_stats/undetected",
                "read": "count",
            },
            {"name": "reputation", "path": "/attributes/reputation", "read": "count"},
            {"name": "categories", "path": "/attributes/categories", "read": "texts", "limit": 5},
            {
                "name": "last_analysis_date_unix",
                "path": "/attributes/last_analysis_date",
                "read": "whole",
            },
        ],
        "malicious_when": [
            {"field": "malicious", "at_least": 1},
            {"field": "suspicious", "at_least": 3},
        ],
        "age_from": "last_analysis_date_unix",
    },
    "abuseipdb": {
        "label": "AbuseIPDB",
        "kinds": ["ip"],
        "order": 20,
        "requests": {
            "ip": {
                "url": _ABUSE_CHECK,
                "params": {"ipAddress": "{value}", "maxAgeInDays": "90"},
                "headers": {"Key": "{credential}", "Accept": "application/json"},
            },
        },
        "credential": "api.abuseipdb_api_key",
        # The cheapest call a key may make: one public address over the last day.
        "probe": {
            "url": _ABUSE_CHECK,
            "params": {"ipAddress": "8.8.8.8", "maxAgeInDays": "1"},
            "headers": {"Key": "{credential}", "Accept": "application/json"},
        },
        "timeout_seconds": 20.0,
        "answer_root": "/data",
        "record": [
            {"name": "abuse_confidence", "path": "/abuseConfidenceScore", "read": "count"},
            {"name": "country", "path": "/countryCode"},
            {"name": "isp", "path": "/isp"},
            {"name": "domain", "path": "/domain"},
            {"name": "total_reports", "path": "/totalReports", "read": "count"},
        ],
        "malicious_when": [{"field": "abuse_confidence", "at_least": 50}],
    },
}


def _deep(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _deep(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_deep(v) for v in value]
    return value


def builtin_source_entries() -> dict[str, dict[str, Any]]:
    """A fresh copy of every shipped source declaration, in the order they ship."""
    return {key: _deep(entry) for key, entry in _BUILTIN_SOURCES.items()}

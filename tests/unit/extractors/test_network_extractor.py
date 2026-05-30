"""Unit tests for the network IOC extractor.

Wave 10 W10-NET-01 (2026-05-30): primary focus is the
``merge_sandbox_cti_network`` helper that folds Triage SandboxCTI network
IOCs into the typed ``NetworkIOCs`` model so the NETWORK tab and SUMMARY
snapshot card render Triage-sourced indicators on the Android flow.
"""

from __future__ import annotations

from maljan.extractors.network_extractor import (
    build_network_iocs,
    merge_sandbox_cti_network,
)
from maljan.reporting.models import NetworkDomain, NetworkIOCs, NetworkIP, NetworkURL

# ---------------------------------------------------------------------------
# build_network_iocs sanity (CAPE-style sandbox_report)
# ---------------------------------------------------------------------------


def test_build_network_iocs_returns_none_for_empty_report() -> None:
    assert build_network_iocs(None) is None
    assert build_network_iocs({}) is None
    assert build_network_iocs({"network": {}}) is None


# ---------------------------------------------------------------------------
# merge_sandbox_cti_network
# ---------------------------------------------------------------------------


def test_merge_sandbox_cti_passthrough_when_cti_missing() -> None:
    """When sandbox_cti is None or has no network block, the input
    NetworkIOCs (or None) is returned unchanged."""
    assert merge_sandbox_cti_network(None, None) is None
    assert merge_sandbox_cti_network(None, {}) is None
    assert merge_sandbox_cti_network(None, {"network": {}}) is None
    existing = NetworkIOCs(domains=[NetworkDomain(fqdn="example.com")])
    assert merge_sandbox_cti_network(existing, None) is existing


def test_merge_sandbox_cti_builds_fresh_when_no_existing() -> None:
    """When sandbox_report yielded nothing but the Triage CTI has IOCs,
    a fresh NetworkIOCs is constructed. This is the 2026-05-30 zararli.apk
    case driving W10-NET-01."""
    cti = {
        "network": {
            "domains": ["nwp.t-mobile.com", "ssl.gstatic.com"],
            "ips": ["1.1.1.1", "216.239.38.133"],
            "http_urls": ["http://nwp.t-mobile.com/getcpid"],
            "tls_ja3": ["abc123"],
            "tls_sni": ["api.example.com"],
            "dns_queries": ["dl.google.com"],
        }
    }
    result = merge_sandbox_cti_network(None, cti)
    assert result is not None
    fqdns = {d.fqdn for d in result.domains}
    # tls_sni + dns_queries also fold into domains.
    assert fqdns == {
        "nwp.t-mobile.com",
        "ssl.gstatic.com",
        "api.example.com",
        "dl.google.com",
    }
    addrs = {ip.address for ip in result.ips}
    assert addrs == {"1.1.1.1", "216.239.38.133"}
    urls = {u.url for u in result.urls}
    assert urls == {"http://nwp.t-mobile.com/getcpid"}
    assert result.ja3_fingerprints == ["abc123"]


def test_merge_sandbox_cti_dedupes_against_existing() -> None:
    """When the input NetworkIOCs already has some entries, CTI rows are
    appended only when they don't collide with existing ones."""
    existing = NetworkIOCs(
        domains=[NetworkDomain(fqdn="nwp.t-mobile.com")],
        ips=[NetworkIP(address="1.1.1.1")],
        urls=[NetworkURL(url="http://nwp.t-mobile.com/getcpid")],
        ja3_fingerprints=["abc123"],
    )
    cti = {
        "network": {
            "domains": ["nwp.t-mobile.com", "fresh.example.com"],
            "ips": ["1.1.1.1", "2.2.2.2"],
            "http_urls": [
                "http://nwp.t-mobile.com/getcpid",
                "http://fresh.example.com/x",
            ],
            "tls_ja3": ["abc123", "def456"],
        }
    }
    result = merge_sandbox_cti_network(existing, cti)
    assert result is not None
    assert {d.fqdn for d in result.domains} == {
        "nwp.t-mobile.com",
        "fresh.example.com",
    }
    assert {ip.address for ip in result.ips} == {"1.1.1.1", "2.2.2.2"}
    assert {u.url for u in result.urls} == {
        "http://nwp.t-mobile.com/getcpid",
        "http://fresh.example.com/x",
    }
    assert set(result.ja3_fingerprints) == {"abc123", "def456"}


def test_merge_sandbox_cti_skips_invalid_ip_strings() -> None:
    """Malformed IP strings in the Triage block are silently skipped
    rather than poisoning the model with a Pydantic validation failure."""
    cti = {"network": {"ips": ["1.1.1.1", "not-an-ip", "999.999.999.999"]}}
    result = merge_sandbox_cti_network(None, cti)
    assert result is not None
    assert {ip.address for ip in result.ips} == {"1.1.1.1"}


def test_merge_sandbox_cti_flags_suspicious_domains() -> None:
    """The C2/commodity-infra heuristic still applies to CTI-sourced
    domains so the NETWORK tab marks shady FQDNs without waiting for
    threat-intel enrichment."""
    cti = {"network": {"domains": ["evil.duckdns.org", "cdn.fastly.net"]}}
    result = merge_sandbox_cti_network(None, cti)
    assert result is not None
    by_fqdn = {d.fqdn: d for d in result.domains}
    assert by_fqdn["evil.duckdns.org"].is_suspicious is True
    assert by_fqdn["evil.duckdns.org"].reason == "From Triage SandboxCTI"
    assert by_fqdn["cdn.fastly.net"].is_suspicious is False


def test_merge_sandbox_cti_returns_input_when_cti_network_empty() -> None:
    """A SandboxCTI dict whose ``network`` block is entirely empty must
    not cause an empty-but-non-None NetworkIOCs to be created."""
    assert merge_sandbox_cti_network(None, {"network": {"ips": []}}) is None

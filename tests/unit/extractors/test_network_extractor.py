"""Unit tests for the network IOC extractor.

Wave 10 W10-NET-01 (2026-05-30): primary focus is the
``merge_sandbox_cti_network`` helper that folds Triage SandboxCTI network
IOCs into the typed ``NetworkIOCs`` model so the NETWORK tab and SUMMARY
snapshot card render Triage-sourced indicators on the Android flow.
"""

from __future__ import annotations

from maljan.extractors.network_extractor import (
    _DGA_CLAIM_THRESHOLD,
    _DGA_SCORE_THRESHOLD,
    _assess_domain,
    _dga_score,
    build_dga_isr,
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
    threat-intel enrichment. The *real* reason is preserved (with a CTI
    provenance suffix) rather than overwritten with a generic string."""
    cti = {"network": {"domains": ["evil.duckdns.org", "cdn.fastly.net"]}}
    result = merge_sandbox_cti_network(None, cti)
    assert result is not None
    by_fqdn = {d.fqdn: d for d in result.domains}
    assert by_fqdn["evil.duckdns.org"].is_suspicious is True
    assert by_fqdn["evil.duckdns.org"].reason == "contains 'duckdns' [Triage CTI]"
    assert by_fqdn["cdn.fastly.net"].is_suspicious is False


def test_merge_sandbox_cti_returns_input_when_cti_network_empty() -> None:
    """A SandboxCTI dict whose ``network`` block is entirely empty must
    not cause an empty-but-non-None NetworkIOCs to be created."""
    assert merge_sandbox_cti_network(None, {"network": {"ips": []}}) is None


def test_merge_sandbox_cti_preserves_dga_score_and_reason() -> None:
    """CTI-sourced DGA domains carry the real reason + structured score
    through the merge (with a provenance suffix), not a generic string."""
    cti = {"network": {"domains": ["kq3x9zjptlvbq.top"]}}
    result = merge_sandbox_cti_network(None, cti)
    assert result is not None
    dom = result.domains[0]
    assert dom.is_suspicious is True
    assert dom.dga_score is not None and dom.dga_score >= _DGA_SCORE_THRESHOLD
    assert dom.reason is not None
    assert dom.reason.startswith("DGA-like")
    assert dom.reason.endswith("[Triage CTI]")


# ---------------------------------------------------------------------------
# DGA scoring (Shannon entropy + bigram rarity composite)
# ---------------------------------------------------------------------------


def test_dga_score_separates_random_from_dictionary() -> None:
    """Random/algorithmic labels score above threshold; real dictionary-ish
    labels score below it."""
    random_labels = ["kq3x9zjptlvbq", "xkzqwvbptlmn", "zxqwvbnmlkjh"]
    benign_labels = ["salesforce", "documentation", "stackoverflow", "newsletter"]
    for label in random_labels:
        assert _dga_score(label) >= _DGA_SCORE_THRESHOLD, label
    for label in benign_labels:
        assert _dga_score(label) < _DGA_SCORE_THRESHOLD, label


def test_dga_score_ignores_short_labels() -> None:
    """Labels shorter than the floor are never scored (avoids brand FPs like
    'facebook' / 'telegram')."""
    assert _dga_score("facebook") == 0.0
    assert _dga_score("google") == 0.0


def test_dga_legacy_consonant_heavy_still_flagged() -> None:
    """The pre-existing consonant-heavy case the old heuristic caught must
    still be flagged by the composite scorer."""
    assert _dga_score("wmplkvbxqdz") >= _DGA_SCORE_THRESHOLD


def test_build_flags_dga_domain_with_structured_fields() -> None:
    report = {"network": {"domains": ["kq3x9zjptlvbq.top", "google.com"]}}
    result = build_network_iocs(report)
    assert result is not None
    by_fqdn = {d.fqdn: d for d in result.domains}
    dga = by_fqdn["kq3x9zjptlvbq.top"]
    assert dga.is_suspicious is True
    assert dga.dga_score is not None and dga.dga_score >= _DGA_SCORE_THRESHOLD
    assert dga.reason is not None and dga.reason.startswith("DGA-like")
    # Benign allowlisted domain is untouched.
    assert by_fqdn["google.com"].is_suspicious is False


# ---------------------------------------------------------------------------
# IDN / punycode homograph
# ---------------------------------------------------------------------------


def test_punycode_brand_homograph_flagged() -> None:
    """A punycode label that decodes to a brand look-alike is flagged with the
    target brand and ``is_punycode``."""
    report = {"network": {"domains": ["xn--pypal-4ve.com"]}}
    result = build_network_iocs(report)
    assert result is not None
    dom = result.domains[0]
    assert dom.is_suspicious is True
    assert dom.is_punycode is True
    assert dom.homograph_target == "paypal"
    assert dom.reason is not None and "homograph" in dom.reason


def test_mixed_script_homograph_flagged() -> None:
    """A raw-unicode label mixing Latin + Cyrillic that skeletonises onto a
    brand is flagged (no punycode prefix)."""
    verdict = _assess_domain("pаypal.com")  # Cyrillic 'a' (U+0430)
    assert verdict.suspicious is True
    assert verdict.is_punycode is False
    assert verdict.homograph_target == "paypal"


def test_plain_ascii_domain_not_homograph() -> None:
    verdict = _assess_domain("example.com")
    assert verdict.is_punycode is False
    assert verdict.homograph_target is None


def test_subdomain_homograph_flagged() -> None:
    """A homograph in a non-leftmost label (the registrable brand under a
    benign-looking subdomain) is still caught."""
    verdict = _assess_domain("login.pаypal.com")  # Cyrillic 'a' in 'paypal'
    assert verdict.suspicious is True
    assert verdict.homograph_target == "paypal"


def test_dga_under_multilevel_tld_flagged() -> None:
    """DGA scanning inspects every non-TLD label, so an algorithmic label
    under a multi-level public suffix (.co.uk) is not missed."""
    verdict = _assess_domain("cdn.kq3x9zjptlvbq.co.uk")
    assert verdict.suspicious is True
    assert verdict.dga_score is not None and verdict.dga_score >= _DGA_SCORE_THRESHOLD


# ---------------------------------------------------------------------------
# build_dga_isr — deterministic T1568.002 claim producer
# ---------------------------------------------------------------------------


def test_build_dga_isr_emits_t1568_002_for_high_score() -> None:
    iocs = build_network_iocs({"network": {"domains": ["kq3x9zjptlvbq.top"]}})
    isr = build_dga_isr(iocs)
    assert isr is not None
    assert isr.domain == "network"
    assert isr.agent_id == "network_dga"
    assert len(isr.claims) == 1
    claim = isr.claims[0]
    assert claim.technique_id == "T1568.002"
    assert claim.rule_platforms == ["any"]
    # Confidence is capped at 0.75 so a lone heuristic can't dominate the verdict.
    assert 0.0 < claim.confidence <= 0.75
    assert "kq3x9zjptlvbq.top" in claim.evidence_ref


def test_build_dga_isr_skips_borderline_below_claim_threshold() -> None:
    """A domain suspicious enough to flag (>=0.55) but below the higher claim
    bar (0.65) must NOT assert a technique."""
    iocs = NetworkIOCs(
        domains=[
            NetworkDomain(fqdn="borderline.example", is_suspicious=True, dga_score=0.60),
        ]
    )
    assert build_dga_isr(iocs) is None
    # Sanity: the constant ordering the two-tier design depends on.
    assert _DGA_CLAIM_THRESHOLD > _DGA_SCORE_THRESHOLD


def test_build_dga_isr_none_for_empty_or_clean() -> None:
    assert build_dga_isr(None) is None
    assert build_dga_isr(NetworkIOCs()) is None
    clean = build_network_iocs({"network": {"domains": ["google.com"]}})
    assert build_dga_isr(clean) is None


# ---------------------------------------------------------------------------
# Signal-quality hardening (FP reduction + validation)
# ---------------------------------------------------------------------------


def test_drops_reserved_and_private_ips() -> None:
    report = {
        "network": {
            "tcp": [
                {"dst": "8.8.8.8", "dport": 443},
                {"dst": "127.0.0.1"},
                {"dst": "10.0.0.5"},
                {"dst": "169.254.1.1"},
                {"dst": "0.0.0.0"},
                {"dst": "255.255.255.255"},
            ]
        }
    }
    result = build_network_iocs(report)
    assert result is not None
    assert {ip.address for ip in result.ips} == {"8.8.8.8"}


def test_drops_reserved_and_single_label_domains() -> None:
    report = {
        "network": {
            "dns": [
                {"request": "evilsite.com"},
                {"request": "localhost"},
                {"request": "printer.local"},
                {"request": "server"},  # single label
                {"request": "doc.example"},  # reserved suffix
            ]
        }
    }
    result = build_network_iocs(report)
    assert result is not None
    assert {d.fqdn for d in result.domains} == {"evilsite.com"}


def test_cti_path_drops_reserved_ips() -> None:
    cti = {"network": {"ips": ["8.8.8.8", "127.0.0.1", "192.168.1.1"]}}
    result = merge_sandbox_cti_network(None, cti)
    assert result is not None
    assert {ip.address for ip in result.ips} == {"8.8.8.8"}


def test_url_host_lowercased_and_deduped() -> None:
    report = {
        "network": {
            "http": [
                {"host": "Example.COM", "uri": "/a"},
                {"host": "example.com", "uri": "/a"},
            ]
        }
    }
    result = build_network_iocs(report)
    assert result is not None
    assert [u.url for u in result.urls] == ["http://example.com/a"]


def test_url_https_scheme_inference_and_status_validation() -> None:
    report = {
        "network": {
            "http": [
                {"host": "a.com", "uri": "/", "port": 8443, "status": 999},
                {"host": "b.com", "uri": "/", "encrypted": True},
            ]
        }
    }
    result = build_network_iocs(report)
    assert result is not None
    urls = {u.url for u in result.urls}
    assert urls == {"https://a.com/", "https://b.com/"}
    a = next(u for u in result.urls if u.url == "https://a.com/")
    assert a.status is None  # 999 is out of range -> dropped


def test_invalid_port_dropped_ip_kept() -> None:
    report = {"network": {"tcp": [{"dst": "8.8.8.8", "dport": 99999}]}}
    result = build_network_iocs(report)
    assert result is not None
    assert result.ips[0].address == "8.8.8.8"
    assert result.ips[0].port is None


def test_user_agent_stripped_and_deduped() -> None:
    report = {
        "network": {
            "http": [
                {"host": "a.com", "user_agent": "  Evil/1.0  "},
                {"host": "b.com", "user_agent": "Evil/1.0"},
            ]
        }
    }
    result = build_network_iocs(report)
    assert result is not None
    assert result.user_agents == ["Evil/1.0"]

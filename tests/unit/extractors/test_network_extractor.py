"""Unit tests for the network IOC extractor."""

from __future__ import annotations

from maljan.extractors.network_extractor import (
    _DGA_CLAIM_THRESHOLD,
    _DGA_SCORE_THRESHOLD,
    _assess_domain,
    _dga_score,
    build_dga_isr,
    build_network_iocs,
)
from maljan.reporting.models import NetworkDomain, NetworkIOCs

# ---------------------------------------------------------------------------
# build_network_iocs sanity (CAPE-style sandbox_report)
# ---------------------------------------------------------------------------


def test_build_network_iocs_returns_none_for_empty_report() -> None:
    assert build_network_iocs(None) is None
    assert build_network_iocs({}) is None
    assert build_network_iocs({"network": {}}) is None


def test_build_network_iocs_extracts_ja3_and_ja3s_from_tls() -> None:
    """The CAPE-style ``network.tls[]`` entries carry both the client (ja3)
    and server (ja3s) fingerprints; both surface on the typed model."""
    report = {
        "network": {
            "tls": [
                {"ja3": "client-fp-1", "ja3s": "server-fp-1"},
                {"ja3_hash": "client-fp-2", "ja3s_hash": "server-fp-2"},
                {"ja3": "client-fp-1", "ja3s": "server-fp-1"},  # duplicate, dropped
            ]
        }
    }
    result = build_network_iocs(report)
    assert result is not None
    assert result.ja3_fingerprints == ["client-fp-1", "client-fp-2"]
    assert result.ja3s_fingerprints == ["server-fp-1", "server-fp-2"]


def test_build_network_iocs_returns_iocs_for_ja3s_only_report() -> None:
    """A report carrying only a server fingerprint is still non-empty."""
    result = build_network_iocs({"network": {"tls": [{"ja3s": "server-fp-1"}]}})
    assert result is not None
    assert result.ja3s_fingerprints == ["server-fp-1"]
    assert result.ja3_fingerprints == []


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

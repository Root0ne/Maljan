"""Domain scoring, and the claim the algorithmic ones produce.

The extraction half of this module is gone — the report's network block is
projected from the calls a run made (``reporting.ledger_projection``) — so what
is exercised here is the scorer itself, plus the projection where a rule about
what may be emitted lives.
"""

from __future__ import annotations

from maljan.extractors.network_extractor import (
    _DGA_CLAIM_THRESHOLD,
    _DGA_SCORE_THRESHOLD,
    _assess_domain,
    _dga_score,
    build_dga_isr,
)
from maljan.reporting.ledger_projection import network_from_sandbox_report
from maljan.reporting.models import NetworkDomain, NetworkIOCs

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


def test_the_projection_carries_the_verdict_onto_the_domain() -> None:
    report = {"network": {"domains": ["kq3x9zjptlvbq.top", "google.com"]}}
    result = network_from_sandbox_report(report)
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
    result = network_from_sandbox_report(report)
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
    iocs = network_from_sandbox_report({"network": {"domains": ["kq3x9zjptlvbq.top"]}})
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
    clean = network_from_sandbox_report({"network": {"domains": ["google.com"]}})
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
    result = network_from_sandbox_report(report)
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
    result = network_from_sandbox_report(report)
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
    result = network_from_sandbox_report(report)
    assert result is not None
    assert [u.url for u in result.urls] == ["http://example.com/a"]

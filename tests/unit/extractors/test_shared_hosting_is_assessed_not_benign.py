"""Shared hosting has two tiers: the provider's endpoints, and its tenants' names.

The benign-infrastructure list held multi-tenant hosting (cloud storage, CDNs,
package CDNs) whole, so a payload on ``evil-bucket.s3.amazonaws.com`` or a C2
behind ``d1234.cloudfront.net`` was benign by the provider's name alone. Now:

- a provider service host (``storage.googleapis.com``, ``s3.amazonaws.com``,
  ``cdn.jsdelivr.net``) stays well-known benign, as on dev;
- a tenant's name is not benign: it is assessed and marked shared hosting,
  and a label the provider assigned (a CloudFront distribution id, an Akamai
  edge label) is never DGA-scored, so it is not flagged on its randomness.
"""

from __future__ import annotations

import pytest

from maljan.extractors.network_extractor import (
    SHARED_HOSTING_REASON,
    _assess_domain,
    host_rides_a_url,
    is_shared_hosting,
    is_shared_hosting_tenant,
    is_well_known_benign_host,
)

SERVICE_HOSTS = [
    "www.googleapis.com",
    "storage.googleapis.com",
    "fonts.googleapis.com",
    "update.googleapis.com",
    "safebrowsing.googleapis.com",
    "s3.amazonaws.com",
    "s3.us-east-1.amazonaws.com",
    "s3-us-west-2.amazonaws.com",
    "sqs.eu-west-1.amazonaws.com",
    "cdn.jsdelivr.net",
    "cloudfront.net",
]
TENANT_HOSTS = [
    "evil-bucket.s3.amazonaws.com",
    "evil-bucket.s3.us-east-1.amazonaws.com",
    "evil-bucket.storage.googleapis.com",
    "ec2-1-2-3-4.compute-1.amazonaws.com",
    "d1234abcd5678e.cloudfront.net",
    "e1234.a.akamaiedge.net",
    "a248.e.akamai.net",
    "evil.global.ssl.fastly.net",
]
# Real-shaped CloudFront distribution names: a 'd' and thirteen base-36
# characters, random by construction.
DISTRIBUTIONS = [
    "d3kxq9ztq0v1fb.cloudfront.net",
    "d1zq8w5rxk2jvh.cloudfront.net",
    "dxq7kz3m9pbw2t.cloudfront.net",
]


@pytest.mark.parametrize("host", SERVICE_HOSTS)
def test_a_provider_service_host_stays_benign(host: str) -> None:
    assert is_well_known_benign_host(host)
    assert is_shared_hosting(host)
    assert not is_shared_hosting_tenant(host)
    assert not host_rides_a_url(host)
    verdict = _assess_domain(host)
    assert verdict.suspicious is False and verdict.reason is None


@pytest.mark.parametrize("host", TENANT_HOSTS)
def test_a_tenant_host_is_not_benign_and_does_not_ride_a_url(host: str) -> None:
    assert not is_well_known_benign_host(host)
    assert is_shared_hosting_tenant(host)
    assert not host_rides_a_url(host)


@pytest.mark.parametrize("host", DISTRIBUTIONS)
def test_a_distribution_id_is_never_dga_scored(host: str) -> None:
    verdict = _assess_domain(host)
    assert verdict.suspicious is False
    assert verdict.dga_score is None
    assert verdict.reason == SHARED_HOSTING_REASON


def test_an_independent_signal_still_flags_a_distribution() -> None:
    """A token in the name is independent of the provider's label."""
    edge = _assess_domain("pastebin-mirror.e1234.a.akamaiedge.net")
    assert edge.suspicious is True and edge.dga_score is None
    assert edge.reason == "contains 'pastebin' (shared hosting)"
    tokened = _assess_domain("pastebin-relay.global.ssl.fastly.net")
    assert tokened.suspicious is True
    assert tokened.reason is not None and tokened.reason.endswith("(shared hosting)")


def test_a_tenant_chosen_label_is_scored() -> None:
    dga = _assess_domain("kq3x9zjptlvbq.s3.amazonaws.com")
    assert dga.suspicious is True
    assert dga.reason is not None and dga.reason.endswith("(shared hosting)")
    plain = _assess_domain("evil.global.ssl.fastly.net")
    assert plain.suspicious is False
    assert plain.reason == SHARED_HOSTING_REASON


def test_other_names_are_untouched() -> None:
    assert not is_shared_hosting("update.googleapis.com.example")
    assert is_well_known_benign_host("www.microsoft.com")
    assert host_rides_a_url("relay.evil.top")
    assert _assess_domain("google.com").reason is None

"""A name the export will not publish is not one this pipeline posts to a provider.

The lookup gate and the export gate kept their own suffix lists, and the two
answering differently is a disclosure rather than a tidiness problem: once the
projection stopped dropping observed rows, a sandbox that resolved ``x.alt`` or
``localhost.localdomain`` reached the enrichment, was corroborated, and had the
operator's own naming sent to a public reputation provider — which is the thing
this gate exists to prevent. One list answers both now.
"""

import pytest

from maljan.enrichment.orchestrator import _is_public_fqdn
from maljan.extractors.network_extractor import host_is_public


@pytest.mark.parametrize(
    "name",
    ["example.com", "cdn.updates.microsoft.com", "xn--80ak6aa92e.com", "a.b.c.d.e.io"],
)
def test_public_names(name):
    assert _is_public_fqdn(name) is True


@pytest.mark.parametrize(
    "name",
    [
        "printer.local",
        "db.internal",
        "nas.lan",
        "router.home",
        "fs.corp",
        "wiki.intranet",
        "host.test",
        "www.example",
        "x.invalid",
        "abc.onion",
        "1.0.0.10.in-addr.arpa",
        "localhost",
        "LOCALHOST.",
        "localhost.localdomain",
        "printer.alt",
        "nas.home.arpa",
        "intranet",
        "10.0.0.5",
        "::1",
        "[fe80::1]",
        "",
        "a..b",
    ],
)
def test_private_or_malformed_names(name):
    assert _is_public_fqdn(name) is False


@pytest.mark.parametrize(
    "name",
    [
        "printer.local",
        "db.internal",
        "printer.alt",
        "nas.home.arpa",
        "nas.lan",
        "router.home",
        "fs.corp",
        "wiki.intranet",
        "host.test",
        "www.example",
        "x.invalid",
        "localhost.localdomain",
        "1.0.0.10.in-addr.arpa",
    ],
)
def test_a_name_the_export_holds_back_is_never_looked_up(name):
    assert host_is_public(name) is False
    assert _is_public_fqdn(name) is False


def test_the_one_name_the_two_answer_differently_is_a_hidden_service():
    """A valid Tor address is publishable and unaskable.

    Its own checksum stands in for the second source no sandbox can give it,
    so the export carries it; no reputation provider can resolve one, so
    asking spends quota on a certain "unknown".
    """
    address = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion"

    assert host_is_public(address) is True
    assert _is_public_fqdn(address) is False

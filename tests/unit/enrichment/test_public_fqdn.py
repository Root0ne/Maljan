import pytest

from maljan.enrichment.orchestrator import _is_public_fqdn


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

"""The analyst-mode decision reads the shared host rule and decides as before, but for three ranges.

Each endpoint below is classified with the resolver answering from a fixed
table, so nothing reaches the network. The answers are the ones the decision
gave before the rule was shared, except where an address of a transition or
documentation range carries a public IPv4 address (or none): those were local
under ``ipaddress.is_private`` and are hosted now, which is the stricter and
intended reading.
"""

from __future__ import annotations

import pytest

from maljan.pipeline import analyst_mode
from tests.credential_shapes import password

ANSWERS: dict[str, list[str]] = {
    "qdrant": ["172.18.0.3"],
    "llm": ["10.0.0.7"],
    "api.deepseek.com": ["104.18.1.1"],
    "box.lan": [],
    "2130706433": ["127.0.0.1"],
    "0x7f000001": ["127.0.0.1"],
    "example.internal.com": ["93.184.216.34"],
    "local": [],
    "internal": ["fe80::1"],
}

EXPECTED: dict[str, str] = {
    "127.0.0.1": "local",
    "10.1.2.3": "local",
    "172.31.0.1": "local",
    "192.168.0.9": "local",
    "169.254.9.9": "local",
    "100.64.0.1": "local",
    "100.128.0.1": "hosted",
    "8.8.8.8": "hosted",
    "[::1]": "local",
    "[fe80::1]": "local",
    "[fd00::5]": "local",
    "[::ffff:10.0.0.1]": "local",
    "[::ffff:8.8.8.8]": "hosted",
    # Local before: ``is_private`` counts these ranges; each carries no local IPv4 address.
    "[2002:808:808::1]": "hosted",
    "[2001:db8::1]": "hosted",
    "[64:ff9b:1::1]": "hosted",
    "localhost": "local",
    "LOCALHOST": "local",
    "localhost.localdomain": "local",
    "host.docker.internal": "local",
    "gateway.docker.internal": "local",
    "host.containers.internal": "local",
    "host.lima.internal": "local",
    "a.localhost": "local",
    "x.local": "local",
    "y.internal": "local",
    "qdrant": "local",
    "llm": "local",
    "api.deepseek.com": "hosted",
    "box.lan": "unknown",
    "0.0.0.0": "local",
    "[::]": "local",
    "2130706433": "local",
    "0x7f000001": "local",
    "example.internal.com": "hosted",
    "local": "unknown",
    "internal": "local",
    "localhost.": "local",
    "x.local.": "local",
}


@pytest.fixture(autouse=True)
def _resolver(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(analyst_mode, "_addresses", lambda host: list(ANSWERS.get(host, [])))


@pytest.mark.parametrize(("host", "kind"), sorted(EXPECTED.items()))
@pytest.mark.parametrize("form", ["http://{}/v1", "https://{}:8080/v1"])
def test_an_endpoint_is_decided_as_before(host: str, kind: str, form: str) -> None:
    assert analyst_mode.locality(form.format(host))[0] == kind


@pytest.mark.parametrize(
    "odd", ["", "not a url", "http://", "file:///x", f"http://user:{password()}@10.0.0.1/"]
)
def test_an_odd_endpoint_is_decided_without_raising(odd: str) -> None:
    kind, _fact = analyst_mode.locality(odd)
    assert kind in ("local", "hosted", "unknown")


# Every class of address whose decision changed when the rule was shared, each
# with what dev decided and what it is decided as now.
CHANGED_CLASSES: dict[str, tuple[str, str, list[str]]] = {
    # Conservative: an address that is not on this machine is never taken as local.
    "documentation": (
        "local",
        "hosted",
        ["192.0.2.1", "198.51.100.1", "203.0.113.1", "[2001:db8::1]", "[3fff::1]"],
    ),
    "benchmarking": ("local", "hosted", ["198.18.0.1", "198.19.255.1"]),
    "reserved": (
        "local",
        "hosted",
        [
            "240.0.0.1",
            "255.255.255.255",
            "0.1.2.3",
            "192.0.0.8",
            "[100::1]",
            "[2001:2::1]",
            "[2001:10::1]",
        ],
    ),
    # A transition address routes to the IPv4 address it carries.
    "transition carrying a public IPv4": (
        "local",
        "hosted",
        [
            "[2002:808:808::1]",
            "[2001:0:4136:e378:8000:63bf:3fff:fdd2]",
            "[64:ff9b:1::808:808]",
        ],
    ),
    # Less strict: the well-known NAT64 prefix carrying a private IPv4 address.
    "well-known NAT64 carrying a private IPv4": ("hosted", "local", ["[64:ff9b::a00:1]"]),
}


@pytest.mark.parametrize(
    ("name", "address"),
    [(name, address) for name, (_dev, _now, held) in CHANGED_CLASSES.items() for address in held],
)
def test_each_class_that_changed_is_decided_as_the_shared_rule_says(
    name: str, address: str
) -> None:
    dev, now, _held = CHANGED_CLASSES[name]
    assert dev != now
    assert analyst_mode.locality(f"http://{address}/v1")[0] == now


@pytest.mark.parametrize(
    ("address", "kind"),
    [
        # Transition addresses carrying a local IPv4 address stay local, as on dev.
        ("[2002:a00:5::1]", "local"),
        ("[2001:0:4136:e378:8000:63bf:f5ff:fffa]", "local"),
        ("[64:ff9b:1::a00:1]", "local"),
        # Unchanged: IPv4-mapped, the unspecified addresses, a zone id.
        ("[::ffff:10.0.0.1]", "local"),
        ("[::ffff:8.8.8.8]", "hosted"),
        ("[64:ff9b::808:808]", "hosted"),
        ("0.0.0.0", "local"),
        ("[::]", "local"),
        ("[fe80::1%25eth0]", "local"),
    ],
)
def test_each_class_that_did_not_change_is_decided_as_on_dev(address: str, kind: str) -> None:
    assert analyst_mode.locality(f"http://{address}/v1")[0] == kind

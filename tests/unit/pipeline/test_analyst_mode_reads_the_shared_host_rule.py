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

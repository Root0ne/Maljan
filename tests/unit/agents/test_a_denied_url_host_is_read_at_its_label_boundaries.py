"""A developer or package-registry host is denied as itself and its subdomains, never as a suffix.

The deny list was matched with ``host.endswith(entry) or entry in host``, so a
recovered C2 URL on ``ergo.dev`` was refused as ``go.dev`` and one on
``mango.devices-update.com`` as ``go.dev`` too, and the entries with a path
(``github.com/golang/``) could never match a bare host at all.
"""

from __future__ import annotations

import pytest

from maljan.agents._indicator_denylists import on_a_denied_url_host
from maljan.reporting.models import (
    FileHashes,
    MalwareReport,
    NetworkIOCs,
    NetworkURL,
    SampleIdentity,
)


@pytest.mark.parametrize(
    "url",
    [
        "https://go.dev/doc",
        "https://pkg.go.dev/fmt",
        "http://PYPI.org/simple/",
        "https://developer.android.com/reference",
        "https://github.com/golang/go/issues/1",
        "https://raw.githubusercontent.com/rust-lang/rust/master/x",
        "go.dev/x",
        "https://go.dev.:443/",
    ],
)
def test_a_denied_host_its_subdomain_and_its_path_are_denied(url: str) -> None:
    assert on_a_denied_url_host(url)


@pytest.mark.parametrize(
    "url",
    [
        "http://ergo.dev/gate.php",
        "http://api.mango.devices-update.com/x",
        "http://notpypi.org/",
        "http://go.dev.evil.example/",
        "https://github.com/someone/golang/",
        "https://github.com/golangx/",
        "https://github.com/",
        "not a url",
        "",
        "http://[::1/",
    ],
)
def test_a_host_that_only_ends_in_a_denied_name_is_not_denied(url: str) -> None:
    assert not on_a_denied_url_host(url)


def test_a_recovered_url_on_a_lookalike_host_is_published_and_a_denied_one_says_why() -> None:
    from maljan.reporting.renderers.stix_renderer import publish_answer

    recovered = "recovered by emulation (decoded strings), ev_0001"
    kept = publish_answer(
        "url", "http://ergo.dev/gate.php", "strings", None, recovered=recovered, verdict="Malware"
    )
    assert kept.startswith("yes"), kept
    denied = publish_answer(
        "url", "https://pkg.go.dev/fmt", "strings", None, recovered=recovered, verdict="Malware"
    )
    assert denied == f"no: {recovered}, but it is on a developer or package-registry host"


def test_the_export_carries_a_strings_url_on_a_lookalike_host_as_the_rule_answers() -> None:
    from maljan.reporting.renderers.stix_renderer import ExtendedSTIXRenderer

    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict="Malware",
        overall_confidence=0.9,
        network=NetworkIOCs(urls=[NetworkURL(url="http://ergo.dev/gate.php", source="sandbox")]),
    )
    patterns = [
        getattr(obj, "pattern", "") for obj in ExtendedSTIXRenderer().render(report).objects
    ]
    assert "[url:value = 'http://ergo.dev/gate.php']" in patterns


@pytest.mark.parametrize(
    ("url", "denied"),
    [
        ("https://github.com/golang/../attacker/x", False),
        ("https://github.com/golang/./go", True),
        ("https://github.com/x/../golang/go", True),
        ("//go.dev/x", True),
        ("//ergo.dev/x", False),
        ("http://go。dev/", True),
        ("http://go．dev/", True),
        ("http://go｡dev/", True),
        ("http://ergo。dev/", False),
    ],
)
def test_a_path_s_dot_segments_a_schemeless_host_and_idna_stops_are_read(
    url: str, denied: bool
) -> None:
    assert on_a_denied_url_host(url) is denied


@pytest.mark.parametrize(
    ("url", "denied"),
    [
        # Two parsers read these authorities differently: never denied.
        ("https://go.dev\\@evil.com/x", False),
        ("https://user@go.dev/x", False),
        ("https://go.dev%2eevil.com/x", False),
        # Unreserved escapes are decoded before the dot segments are resolved.
        ("https://github.com/golang/%2e%2e/evil/x", False),
        ("https://github.com/golang/%2E%2E/evil/x", False),
        ("https://github.com/%67olang/go", True),
        # A backslash in a special URL's path is a slash.
        ("https://github.com/golang\\go", True),
        ("https://github.com/golang\\..\\evil\\x", False),
    ],
)
def test_a_url_two_parsers_read_differently_stays_an_indicator(url: str, denied: bool) -> None:
    assert on_a_denied_url_host(url) is denied

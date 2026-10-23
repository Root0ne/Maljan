"""A network figure's red border means what its legend says: flagged, or published (RC-13)."""

from __future__ import annotations

from maljan.reporting.figures import build_network_graph
from maljan.reporting.models import (
    ConsolidatedIOC,
    FileHashes,
    MalwareReport,
    NetworkIOCs,
    NetworkIP,
    SampleIdentity,
)

_RED = 'stroke="#cf222e"'


def _report(*ips: NetworkIP, published: str | None = None) -> MalwareReport:
    rows = (
        [
            ConsolidatedIOC(
                type="IPv4",
                value=published,
                kind="ip",
                is_network=True,
                published="yes",
            )
        ]
        if published
        else []
    )
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        network=NetworkIOCs(ips=list(ips)),
        consolidated_iocs=rows,
    )


def test_an_unflagged_unpublished_address_is_grey() -> None:
    fig = build_network_graph(_report(NetworkIP(address="203.0.113.7", port=443)))
    assert fig is not None
    assert _RED not in fig.content


def test_a_flagged_address_is_red() -> None:
    fig = build_network_graph(_report(NetworkIP(address="203.0.113.7", is_suspicious=True)))
    assert fig is not None
    assert fig.content.count(_RED) == 1


def test_a_published_address_is_red_and_another_is_not() -> None:
    fig = build_network_graph(
        _report(
            NetworkIP(address="203.0.113.7"),
            NetworkIP(address="198.51.100.9"),
            published="203.0.113.7",
        )
    )
    assert fig is not None
    assert fig.content.count(_RED) == 1

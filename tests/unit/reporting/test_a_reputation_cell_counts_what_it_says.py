"""A network value's reputation cell says what it counts.

The cell counts engines that call the value malicious, out of every engine
that answered. With no malicious and three suspicious engines, "0 of 75
engines flag it" said nothing had flagged it, which the suspicious three had.
"""

from __future__ import annotations

from maljan.reporting.models import (
    FileHashes,
    MalwareReport,
    NetworkDomain,
    NetworkIOCs,
    SampleIdentity,
)
from maljan.reporting.renderers.markdown import _reputations


def test_the_cell_names_malicious_and_writes_no_fraction() -> None:
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        network=NetworkIOCs(
            domains=[
                NetworkDomain(
                    fqdn="one.example.org",
                    source="sandbox",
                    reputation={
                        "source": "VirusTotal",
                        "malicious": 0,
                        "suspicious": 3,
                        "harmless": 2,
                        "undetected": 70,
                    },
                )
            ]
        ),
    )

    cell = _reputations(report)["one.example.org"]

    assert cell == "VirusTotal: 0 of 75 engines flag it as malicious"
    assert "/" not in cell

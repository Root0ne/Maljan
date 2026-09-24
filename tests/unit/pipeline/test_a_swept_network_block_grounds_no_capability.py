"""The string sweep's own network rows ground no network capability.

A summary said "the primary risk is lateral movement" for a sample whose run
observed no traffic, and the ungrounded-capability check did not fire: the
report had a network block, and a network block counted as network evidence.
That block held only hosts and addresses the string sweep read out of the
file's bytes. It now grounds a capability only when something other than the
sweep recorded a row of it — a sandbox, an analyst, a capture's fingerprint.
"""

from __future__ import annotations

from typing import Any

from maljan.pipeline.validation import CapabilityGrounding, narrative_capability_violations
from maljan.reporting.models import (
    FileHashes,
    MalwareReport,
    NetworkDomain,
    NetworkIOCs,
    NetworkIP,
    SampleIdentity,
    StaticAnalysis,
)

SUMMARY = {"executive_summary": "The primary risk is lateral movement across the estate."}


def _paths(network: NetworkIOCs | None) -> list[str]:
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="f" * 64)),
        verdict="Malware",
        static=StaticAnalysis(),
        network=network,
    )
    grounding = CapabilityGrounding.from_report(report)
    return [v.path for v in narrative_capability_violations(SUMMARY, grounding)]


def _swept(**extra: Any) -> NetworkIOCs:
    return NetworkIOCs(
        domains=[NetworkDomain(fqdn="updates.example.org", source="strings")],
        ips=[NetworkIP(address="185.99.133.7", source="strings")],
        **extra,
    )


def test_a_block_of_swept_rows_grounds_nothing() -> None:
    assert _paths(_swept()) == ["lateral_movement"]


def test_a_row_with_no_source_is_read_as_the_sweep_s() -> None:
    assert _paths(NetworkIOCs(domains=[NetworkDomain(fqdn="updates.example.org")])) == [
        "lateral_movement"
    ]


def test_a_row_a_sandbox_recorded_grounds_the_block() -> None:
    network = _swept()
    network.domains.append(NetworkDomain(fqdn="gate9.example.org", source="sandbox"))

    assert _paths(network) == []


def test_a_captured_fingerprint_grounds_the_block() -> None:
    assert _paths(_swept(user_agents=["ExampleAgent/1.0"])) == []


def test_no_block_grounds_nothing() -> None:
    assert _paths(None) == ["lateral_movement"]

"""Reports of runs that drafted no detection rule, for the byte-identity pin of the rules gate.

Kept apart from the test that reads them, and built from nothing newer than
the report model and the IOC table's builder, so the same reports render under
the tree the pinned text was written from
(``tests/fixtures/golden/reporting/no_rules.json``, rendered from the tree before the gate).
"""

from __future__ import annotations

from datetime import UTC, datetime

from malspark.reporting.builder import build_consolidated_iocs
from malspark.reporting.models import (
    FileHashes,
    MalwareReport,
    NetworkDomain,
    NetworkIOCs,
    NetworkURL,
    SampleIdentity,
)

SHA256 = "ab" * 32
WHEN = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)
HOST = "gate9.example.org"
URL = f"https://{HOST}/live/"
AGENT = "Mozilla/4.0 (compatible; Tob 1.1)"


def _report(verdict: str, network: NetworkIOCs) -> MalwareReport:
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256=SHA256)),
        verdict=verdict,
        malware_category="loader",
        generated_at=WHEN,
        network=network,
    )
    report.consolidated_iocs = build_consolidated_iocs(report)
    report.detection_signatures = []
    return report


def no_rule_reports() -> dict[str, MalwareReport]:
    """By name: a Benign run, and two runs whose drafting was switched off."""
    domain = NetworkDomain(fqdn=HOST, source="sandbox")
    return {
        "benign": _report("Benign", NetworkIOCs()),
        "domain_only": _report("Malware", NetworkIOCs(domains=[domain])),
        "url_and_agent": _report(
            "Malware",
            NetworkIOCs(
                domains=[domain],
                urls=[NetworkURL(url=URL, method="POST", user_agent=AGENT, source="sandbox")],
                user_agents=[AGENT],
            ),
        ),
    }

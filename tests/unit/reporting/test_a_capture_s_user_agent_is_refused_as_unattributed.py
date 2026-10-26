"""A user agent, a JA3 or a JA3S the sandbox recorded publishes nowhere on its record alone.

The IOC table answered each of them ``yes: sandbox`` with no rule asked, so
``/iocs`` and the MISP attributes published them while the STIX export, which
has no object for one, did not; and the same capture's addresses that no
process of the sample's tree reached were refused because the sandbox report
did not say which process made the flows. A capture's user agent and
fingerprints name no process either: each is now refused under that rule, on
the table, the feed, the export and MISP alike. A false mark costs more than
a missed one.
"""

from __future__ import annotations

import json

import pytest

from app.services.report_service import ioc_feed_rows
from maljan.reporting.builder import build_consolidated_iocs
from maljan.reporting.misp import build_misp_attributes
from maljan.reporting.models import (
    FileHashes,
    MalwareReport,
    NetworkIOCs,
    NetworkIP,
    SampleIdentity,
)
from maljan.reporting.renderers.stix_renderer import (
    UNATTRIBUTED_CAPTURE_VALUE,
    ExtendedSTIXRenderer,
    indicator_publish_reason,
    publishes,
)

SHA256 = "36dabc40fa8983ce900a90b8156d2c754875fe1b5413a997843c4a0ef3908220"
AGENT = "ExampleAgent/2.1 (synthetic; capture)"
JA3 = "0123456789abcdef0123456789abcdef"
JA3S = "fedcba9876543210fedcba9876543210"
UNATTRIBUTED_IP = "185.220.101.7"
REFUSED = f"no: {UNATTRIBUTED_CAPTURE_VALUE}"


def _report() -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256=SHA256), file_name="sample.exe"),
        verdict="Malware",
        network=NetworkIOCs(
            ips=[NetworkIP(address=UNATTRIBUTED_IP, source="sandbox", sample_process_tree=None)],
            user_agents=[AGENT],
            ja3_fingerprints=[JA3],
            ja3s_fingerprints=[JA3S],
        ),
    )


@pytest.mark.parametrize(("kind", "value"), [("user_agent", AGENT), ("ja3", JA3), ("ja3s", JA3S)])
def test_the_table_refuses_a_capture_s_value_as_unattributed(kind: str, value: str) -> None:
    (row,) = [r for r in build_consolidated_iocs(_report()) if r.value == value]

    assert (row.kind, row.source) == (kind, "sandbox")
    assert row.published == REFUSED


def test_the_capture_s_unattributed_address_is_refused_the_same_way() -> None:
    (row,) = [r for r in build_consolidated_iocs(_report()) if r.value == UNATTRIBUTED_IP]

    assert row.published.startswith("no: the sandbox report does not say which process")


def test_no_surface_publishes_them() -> None:
    report = _report()
    rows = build_consolidated_iocs(report)
    feed = {row["value"]: row for row in ioc_feed_rows(report.model_dump(mode="json"))}
    attributes = build_misp_attributes(report, rows, owner="owner")
    exported = json.dumps(ExtendedSTIXRenderer().render(report).model_dump(mode="json"))

    for value in (AGENT, JA3, JA3S):
        assert not publishes(feed[value]["publish_answer"]), value
        assert value not in {a["value"] for a in attributes}, value
        assert value not in exported, value


def test_the_rule_admits_none_on_the_unattributed_fact() -> None:
    for kind, value in (("user_agent", AGENT), ("ja3", JA3), ("ja3s", JA3S)):
        assert (
            indicator_publish_reason(
                kind, value, "sandbox", unattributed=UNATTRIBUTED_CAPTURE_VALUE
            )
            is None
        )

"""A network value the sample hid, and only emulation recovered, is a source of its own.

The benchmark's C2 names were encrypted in the file and recovered by FLOSS
emulation; under the one publish rule they stayed unpublished, "seen only in
the file's strings", beside VirusTotal's own family label. A value the static
string sweep reads is routinely benign; a value hidden behind encoding rarely
is. So a domain, an address or a URL the run's FLOSS entry holds as a decoded,
stack or tight string is publishable when it passes every other question of the
rule — never a well-known benign host, never on a Benign verdict — and the
export, the IOC table and ``/iocs`` read that one decision.
"""

from __future__ import annotations

from typing import Any

from app.services.report_service import _publishable
from maljan.reporting.builder import build_consolidated_iocs
from maljan.reporting.models import (
    EvidenceIndexRow,
    EvidenceSection,
    FileHashes,
    JudgeIndicator,
    MalwareReport,
    NetworkDomain,
    NetworkIOCs,
    SampleIdentity,
)
from maljan.reporting.renderers.stix_renderer import (
    RECOVERED_BY_EMULATION,
    ExtendedSTIXRenderer,
    emulation_kwargs,
    emulation_record,
    indicator_publish_reason,
)
from maljan.schemas.stix_models import Bundle

C2 = "relay7.example.net"
C2_URL = f"https://{C2}/gate/"
BENIGN = "update.microsoft.com"


def _floss(*strings: tuple[str, str]) -> EvidenceSection:
    return EvidenceSection(
        key="tool_floss_strings",
        title="Floss: strings",
        kind="table",
        columns=["kind", "string", "encoding"],
        rows=[[kind, value, "ASCII"] for kind, value in strings],
        evidence_ids=["ev_0012"],
    )


def _report(verdict: str = "Malware", *, decoded: bool = True, **over: Any) -> MalwareReport:
    sections = [_floss(("decoded", C2_URL), ("decoded", BENIGN), ("static", "plain.example.org"))]
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict=verdict,
        malware_category="loader",
        evidence_index=[EvidenceIndexRow(id="ev_0012", agent="pipeline", tool="floss", ok=True)],
        sections=sections if decoded else [],
        judge_indicators=[
            JudgeIndicator(kind="domain", value=C2),
            JudgeIndicator(kind="domain", value=BENIGN),
        ],
        **over,
    )


def _judge_bundle() -> Bundle:
    return Bundle.model_validate(
        {
            "objects": [
                {
                    "type": "indicator",
                    "id": f"indicator--0f1e2d3c-4b5a-4968-8776-65544333221{i}",
                    "pattern": f"[domain-name:value = '{value}']",
                    "pattern_type": "stix",
                    "indicator_types": ["malicious-activity"],
                }
                for i, value in enumerate((C2, BENIGN))
            ]
        }
    )


def _exported(report: MalwareReport) -> str:
    return str(ExtendedSTIXRenderer().render(report, _judge_bundle()).model_dump(mode="json"))


def _published(report: MalwareReport, value: str) -> str:
    (row,) = [r for r in build_consolidated_iocs(report) if r.value == value]
    return str(row.published)


class TestTheRecord:
    def test_a_decoded_url_and_its_host_are_recorded_with_the_entry(self) -> None:
        record = emulation_record(_report())

        assert record[C2_URL] == "ev_0012" and record[C2] == "ev_0012"
        assert "plain.example.org" not in record

    def test_the_reason_names_the_entry(self) -> None:
        kwargs = emulation_kwargs(_report(), "domain", C2)

        assert indicator_publish_reason("domain", C2, "strings", **kwargs) == (
            f"{RECOVERED_BY_EMULATION}, ev_0012"
        )


class TestAMalwareVerdict:
    def test_a_decoded_c2_host_publishes_everywhere(self) -> None:
        report = _report()

        assert C2 in _exported(report)
        assert _published(report, C2) == "yes"
        assert _publishable("domain", C2, "strings", None, emulation_kwargs(report, "domain", C2))

    def test_a_swept_row_of_a_decoded_value_publishes_with_the_reason(self) -> None:
        report = _report(network=NetworkIOCs(domains=[NetworkDomain(fqdn=C2, source="strings")]))

        exported = ExtendedSTIXRenderer().render(report, None).model_dump(mode="json")

        (indicator,) = [
            o for o in exported["objects"] if o["type"] == "indicator" and C2 in o["pattern"]
        ]
        assert f"{RECOVERED_BY_EMULATION}, ev_0012" in indicator["description"]
        assert _published(report, C2) == "yes"

    def test_a_value_the_sweep_alone_read_stays_unpublished(self) -> None:
        report = _report(
            decoded=False,
            network=NetworkIOCs(domains=[NetworkDomain(fqdn=C2, source="strings")]),
        )

        assert C2 not in _exported(report)
        assert _published(report, C2) == "no: seen only in the file's strings"

    def test_a_decoded_well_known_benign_host_does_not_publish(self) -> None:
        report = _report()

        assert BENIGN not in _exported(report)
        assert _published(report, BENIGN) == (
            f"no: {RECOVERED_BY_EMULATION}, ev_0012, but it is a well-known benign host"
        )


class TestABenignVerdict:
    def test_publishes_none_and_says_why(self) -> None:
        report = _report("Benign")

        assert C2 not in _exported(report)
        assert _published(report, C2) == (
            f"no: {RECOVERED_BY_EMULATION}, ev_0012, but the verdict is Benign, which "
            "publishes no malicious indicator"
        )
        assert not _publishable(
            "domain", C2, "strings", None, emulation_kwargs(report, "domain", C2)
        )

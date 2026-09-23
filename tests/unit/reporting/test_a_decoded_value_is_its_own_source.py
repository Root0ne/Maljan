"""A network value the sample hid, and only emulation recovered, is a source of its own.

The benchmark's C2 names were encrypted in the file and recovered by FLOSS
emulation; under the one publish rule they stayed unpublished, "seen only in
the file's strings", beside VirusTotal's own family label. A value the static
string sweep reads is routinely benign; a value hidden behind encoding rarely
is. So a domain, an address or a URL the run's FLOSS entry holds as a decoded,
stack or tight string is publishable when it passes every other question of the
rule — never a well-known benign host, never on a Benign verdict, never on a
verdict the judge did not state — and the export, the IOC table and ``/iocs``
read that one decision. A value the static sweep also read as a plain string
was not hidden, whatever kind FLOSS gave it, and stays the sweep's. The record
is built from the ledger's own entries and stored on the report, so no row cap
of a section decides it; a report stored before it existed is read from its
kept rows and the reason says the record is partial.
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
    emulation_from_ledger,
    emulation_kwargs,
    emulation_record,
    indicator_publish_reason,
)
from maljan.schemas.evidence import LedgerEntry
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


def _floss_entry(*strings: tuple[str, str], entry: str = "ev_0012", **page: Any) -> LedgerEntry:
    rows = [{"kind": kind, "string": value, "encoding": "ASCII"} for kind, value in strings]
    return LedgerEntry(
        id=entry,
        agent="pipeline",
        tool="floss",
        structured={"total": len(rows), "strings": rows, "truncated": False, **page},
    )


def _strings_entry(*texts: str, entry: str = "ev_0005", **page: Any) -> LedgerEntry:
    rows = [{"enc": "ascii", "text": text, "offset": 16 * i} for i, text in enumerate(texts)]
    return LedgerEntry(
        id=entry,
        agent="pipeline",
        tool="strings",
        structured={"total": len(rows), "strings": rows, "truncated": False, **page},
    )


def _ledger() -> list[LedgerEntry]:
    return [
        _strings_entry("plain.example.org", "GetProcAddress"),
        _floss_entry(("decoded", C2_URL), ("decoded", BENIGN), ("static", "plain.example.org")),
    ]


def _report(verdict: str = "Malware", *, decoded: bool = True, **over: Any) -> MalwareReport:
    sections = [_floss(("decoded", C2_URL), ("decoded", BENIGN), ("static", "plain.example.org"))]
    over.setdefault("emulated_strings", emulation_from_ledger(_ledger() if decoded else []))
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

        assert record.values[C2_URL] == "ev_0012" and record.values[C2] == "ev_0012"
        assert "plain.example.org" not in record.values
        assert record.partial == ""

    def test_the_record_is_stored_on_the_report(self) -> None:
        stored = MalwareReport.model_validate(_report().model_dump(mode="json"))

        assert stored.emulated_strings == emulation_from_ledger(_ledger())

    def test_a_record_past_a_row_cap_is_whole(self) -> None:
        hosts = [f"relay{i}.example.net" for i in range(400)]
        record = emulation_from_ledger(
            [_strings_entry("x"), _floss_entry(*[("decoded", h) for h in hosts])]
        )

        assert set(hosts) <= set(record.values) and record.partial == ""

    def test_a_paged_floss_entry_makes_the_record_partial(self) -> None:
        record = emulation_from_ledger(
            [
                _strings_entry("x"),
                _floss_entry(("decoded", C2), truncated=True, next_offset=1, total_matched=9),
            ]
        )

        assert record.values == {C2: "ev_0012"}
        assert record.partial == "no FLOSS entry listed every string it recovered"
        assert emulation_kwargs(_report(emulated_strings=record), "domain", C2)["recovered"] == (
            f"{RECOVERED_BY_EMULATION}, ev_0012 (the record is partial: {record.partial})"
        )

    def test_a_filtered_floss_entry_alone_makes_the_record_partial(self) -> None:
        record = emulation_from_ledger(
            [_strings_entry("x"), _floss_entry(("decoded", C2), pattern="example")]
        )

        assert record.partial == "no FLOSS entry listed every string it recovered"

    def test_a_paged_strings_listing_makes_the_record_partial(self) -> None:
        record = emulation_from_ledger(
            [
                _strings_entry("x", truncated=True, next_offset=1, total_matched=900),
                _floss_entry(("decoded", C2)),
            ]
        )

        assert record.partial == "no strings entry listed every plain string in the file"

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


class TestAPlainStringTheSweepRead:
    def test_a_decoded_row_of_a_swept_value_is_the_sweep_s(self) -> None:
        swept = "ocsp.example.org"
        ledger = [
            _strings_entry(f"http://{swept}/", entry="ev_0005"),
            _floss_entry(("decoded", swept)),
        ]
        report = _report(
            emulated_strings=emulation_from_ledger(ledger),
            network=NetworkIOCs(domains=[NetworkDomain(fqdn=swept, source="strings")]),
        )

        assert swept not in _exported(report)
        assert _published(report, swept) == (
            "no: seen only in the file's strings — also a plain string in the file "
            "(ev_0005), so not recovered by emulation"
        )
        assert not _publishable(
            "domain", swept, "strings", None, emulation_kwargs(report, "domain", swept)
        )

    def test_a_value_inside_a_longer_name_is_not_held_as_swept(self) -> None:
        ledger = [_strings_entry(f"cdn-{C2}"), _floss_entry(("decoded", C2))]

        assert emulation_from_ledger(ledger).values == {C2: "ev_0012"}


class TestAVerdictNobodyStated:
    def test_a_fallback_verdict_publishes_nothing_emulation_alone_read(self) -> None:
        report = _report(overall_confidence=None)

        assert C2 not in _exported(report)
        assert _published(report, C2) == (
            f"no: {RECOVERED_BY_EMULATION}, ev_0012, but the judge stated no verdict with a "
            "confidence"
        )


class TestAReportStoredBeforeTheRecord:
    def test_is_read_from_its_kept_rows_and_says_so(self) -> None:
        report = _report(emulated_strings=None)

        record = emulation_record(report)

        assert record.values[C2] == "ev_0012"
        assert record.partial.startswith("read from the kept rows of a report stored")
        assert indicator_publish_reason(
            "domain", C2, "strings", **emulation_kwargs(report, "domain", C2)
        ) == (f"{RECOVERED_BY_EMULATION}, ev_0012 (the record is partial: {record.partial})")
        assert _published(report, C2) == "yes"


class TestAPublicSuffixName:
    def test_a_benign_name_under_a_country_second_level_is_known(self) -> None:
        from maljan.extractors import network_extractor

        name = next(iter(network_extractor._BENIGN_DOMAINS))
        assert network_extractor.is_well_known_benign_host(f"cdn.{name}")
        assert not network_extractor.is_well_known_benign_host("example.co.uk")

    def test_a_list_name_under_a_country_second_level_is_its_registered_name(self) -> None:
        from maljan.extractors import network_extractor

        assert not network_extractor.is_well_known_benign_host("microsoft.com.example.co.uk")
        assert network_extractor.is_well_known_benign_host("8.8.8.8")

"""Phase 3: deterministic front-matter / IOC population + section bundle isolation."""

from __future__ import annotations

from maljan.reporting.builder import _build_version_history, build_consolidated_iocs, defang
from maljan.reporting.evidence_bundles import bundle_for, is_empty
from maljan.reporting.models import (
    FileHashes,
    ImportRow,
    MalwareReport,
    NetworkDomain,
    NetworkIOCs,
    NetworkIP,
    ReportFrontMatter,
    SampleIdentity,
    StaticAnalysis,
    StringIOC,
)
from maljan.schemas.isr_models import AgentISR, ClaimEvidence


def _report(**over: object) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64, md5="b" * 32)),
        **over,  # type: ignore[arg-type]
    )


class TestDefang:
    def test_domain(self) -> None:
        assert defang("888kafa.com") == "888kafa[.]com"

    def test_url(self) -> None:
        assert defang("http://evil.com/a") == "hxxp[://]evil[.]com/a"

    def test_idempotent(self) -> None:
        assert defang(defang("evil.com")) == "evil[.]com"

    def test_hash_untouched(self) -> None:
        assert defang("a" * 64) == "a" * 64

    def test_registry_path_untouched(self) -> None:
        v = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
        assert defang(v) == v


class TestConsolidatedIOCs:
    def test_gathers_and_defangs_network(self) -> None:
        r = _report(
            network=NetworkIOCs(
                domains=[NetworkDomain(fqdn="888kafa.com", reason="C2")],
                ips=[NetworkIP(address="94.156.79.162", port=443)],
            )
        )
        iocs = build_consolidated_iocs(r)
        by_type = {i.type: i for i in iocs}
        assert by_type["Domain"].value == "888kafa[.]com"
        assert by_type["Domain"].is_network is True
        assert by_type["IPv4"].value == "94[.]156[.]79[.]162"
        # Hashes present, not defanged.
        assert by_type["SHA-256"].value == "a" * 64
        assert by_type["SHA-256"].is_network is False

    def test_dedupes(self) -> None:
        r = _report(
            network=NetworkIOCs(domains=[NetworkDomain(fqdn="x.com"), NetworkDomain(fqdn="x.com")])
        )
        domains = [i for i in build_consolidated_iocs(r) if i.type == "Domain"]
        assert len(domains) == 1

    def test_static_strings_typed(self) -> None:
        r = _report(
            static=StaticAnalysis(
                interesting_strings=[
                    StringIOC(value="http://c2.evil/x", kind="url"),
                    StringIOC(value=r"HKCU\Software\Run", kind="registry"),
                ]
            )
        )
        iocs = build_consolidated_iocs(r)
        types = {i.type for i in iocs}
        assert "URL" in types and "Registry Key" in types


class TestFrontMatter:
    def test_report_number_format(self) -> None:
        from maljan.reporting.builder import MalwareReportBuilder

        b = MalwareReportBuilder(
            file_hash="a" * 64,
            file_name="x.exe",
            sample_path=None,
            sandbox_report=None,
            reports={},
            isr_reports={},
            stix_output=None,
            run_summary=None,
            discussion_history=None,
            final_decision="Malware",
        )
        fm = b._build_front_matter(_report(malware_category="ransomware"))
        assert fm.report_number is not None
        assert fm.report_number.startswith("MJN")
        assert fm.report_number.endswith("aaaaaa")
        assert fm.malware_name == "Ransomware"

    def test_tlp_escalates_on_live_c2(self) -> None:
        from maljan.reporting.builder import MalwareReportBuilder

        b = MalwareReportBuilder(
            file_hash="a" * 64,
            file_name=None,
            sample_path=None,
            sandbox_report=None,
            reports={},
            isr_reports={},
            stix_output=None,
            run_summary=None,
            discussion_history=None,
            final_decision="Malware",
        )
        r = _report(network=NetworkIOCs(ips=[NetworkIP(address="1.2.3.4", port=80)]))
        assert b._build_front_matter(r).tlp == "AMBER"
        r2 = _report()
        assert b._build_front_matter(r2).tlp == "CLEAR"

    def test_version_history_single_row(self) -> None:
        fm = ReportFrontMatter(report_date="2026-07-13", team="Maljan")
        vh = _build_version_history(fm)
        assert len(vh) == 1
        assert vh[0].date == "2026-07-13"


class TestBundleIsolation:
    def _report_with_evidence(self) -> MalwareReport:
        r = _report(
            static=StaticAnalysis(imports=[ImportRow(dll="WS2_32.dll", function="connect")]),
            network=NetworkIOCs(domains=[NetworkDomain(fqdn="c2.evil")]),
            technical_evidence={
                "static": [
                    {
                        "tool_name": "detect_crypto_constants",
                        "symbol": "",
                        "output": "AES sbox found",
                    },
                    {"tool_name": "list_strings", "symbol": "", "output": "http://c2.evil/gate"},
                ]
            },
        )
        return r

    def test_encryption_bundle_excludes_network(self) -> None:
        r = self._report_with_evidence()
        isr = {
            "static": AgentISR(
                agent_id="static",
                domain="static",
                claims=[
                    ClaimEvidence(
                        claim="Uses AES-256 encryption",
                        evidence_ref="crypto: AES sbox",
                        confidence=0.8,
                    ),
                    ClaimEvidence(
                        claim="Connects to C2 over HTTP",
                        evidence_ref="network: c2.evil",
                        confidence=0.7,
                    ),
                ],
            )
        }
        enc = bundle_for("encryption_scheme", r, isr_reports=isr)
        tools = {t["tool"] for t in enc["tool_outputs"]}
        assert "detect_crypto_constants" in tools
        assert "list_strings" not in tools  # network/string tool excluded
        claims = " ".join(c["claim"] for c in enc["claims"]).lower()
        assert "aes" in claims
        assert "c2 over http" not in claims  # network claim excluded from crypto bundle

    def test_communications_bundle_has_network_facts(self) -> None:
        r = self._report_with_evidence()
        comm = bundle_for("communications", r)
        assert "c2.evil" in comm["facts"]["domains"]

    def test_empty_bundle_detected(self) -> None:
        r = _report()
        assert is_empty(bundle_for("encryption_scheme", r, isr_reports={}))

    def test_executive_summary_bundle_never_empty_with_verdict(self) -> None:
        r = _report(verdict="Malware")
        assert not is_empty(bundle_for("executive_summary", r))

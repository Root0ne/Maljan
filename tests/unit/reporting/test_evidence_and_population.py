"""Phase 3: deterministic front-matter / IOC population + section bundle isolation."""

from __future__ import annotations

from maljan.reporting.builder import _build_version_history, build_consolidated_iocs, defang
from maljan.reporting.evidence_bundles import SECTIONS, bundle_for, is_empty
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


class TestTheComposerCanFalsifyAWrongClaim:
    """The grounding defect observed on 2026-07-28, and the guards against it.

    A conclusion asserted the sample was a .NET executable calling
    ``_CorExeMain`` from ``mscoree.dll``. The report's own identity section said
    "Microsoft Visual C++ 2015-2022" and its import table named eleven native
    DLLs, none of them ``mscoree``. The claim came from the static analyst; the
    conclusion bundle passed it through and carried only
    verdict/severity/confidence/degraded as facts, so nothing in the prompt was
    capable of contradicting it.

    Bundle isolation is what keeps each call small enough for the local model to
    stay coherent. It must not also remove the evidence that falsifies a wrong
    claim — those are different things.
    """

    @staticmethod
    def _native_report() -> MalwareReport:
        return MalwareReport(
            identity=SampleIdentity(
                hashes=FileHashes(sha256="a" * 64),
                file_type="PE",
                language_or_compiler="Microsoft Visual C++ 2015-2022 (C/C++)",
            ),
            static=StaticAnalysis(
                pdb_path=r"E:\build\Release\BdUserHost.pdb",
                imports=[
                    ImportRow(dll="kernel32.dll", function="CreateFileW"),
                    ImportRow(dll="advapi32.dll", function="OpenProcessToken"),
                    ImportRow(dll="kernel32.dll", function="ReadFile"),
                ],
            ),
        )

    def test_the_conclusion_can_see_what_the_binary_is(self) -> None:
        bundle = bundle_for("conclusion", self._native_report())
        binary = bundle["binary"]
        assert "Microsoft Visual C++" in (binary["language_or_compiler"] or "")
        dll_key = next(k for k in binary if k.startswith("imported_dlls"))
        assert "complete list, 2 total" in dll_key
        assert binary[dll_key] == ["advapi32.dll", "kernel32.dll"]
        assert binary["imports_dotnet_runtime (mscoree.dll)"] is False
        assert "BdUserHost" in binary["pdb_path"]
        assert "mscoree" not in " ".join(binary[dll_key])

    def test_every_section_carries_it_not_just_the_introduction(self) -> None:
        report = self._native_report()
        for section in SECTIONS:
            binary = bundle_for(section, report).get("binary") or {}
            assert binary.get("language_or_compiler"), f"{section} cannot check the compiler"

    def test_the_binary_block_does_not_defeat_skip_on_empty(self) -> None:
        """The regression this refactor exists to avoid.

        ``is_empty`` is what makes the Composer state a section's absence rather
        than invent one. Folding an always-present block into ``facts`` would
        make every bundle look non-empty and turn skip-on-empty into
        write-something-anyway for every section — the exact opposite of the
        cardinal rule.
        """
        empty_subject = bundle_for("ransom_note", self._native_report())
        assert empty_subject["binary"], "the block is present"
        assert is_empty(empty_subject), "yet the section is still correctly skipped"

    def test_a_section_with_real_evidence_is_not_skipped(self) -> None:
        report = self._native_report()
        assert report.static is not None
        report.static.packer_hint = "UPX (packer)"
        assert not is_empty(bundle_for("packing_obfuscation", report))


class TestTechnicalSectionsSeeTheirOwnMeasurements:
    """Every generic technical-spine section carried ``facts: {}`` until
    2026-07-28 — each wrote prose about a subject the report had already
    measured deterministically, without being shown the measurement.
    """

    @staticmethod
    def _measured() -> MalwareReport:
        return _report(
            static=StaticAnalysis(
                packer_matches=[{"name": "UPX", "confidence": 0.85, "method": "section"}],
                obfuscation_indicators=["high-entropy sections"],
                api_capabilities={"discovery": 27, "crypto": 15, "anti_debug": 10},
                api_technique_hits=[
                    {"technique_id": "T1083", "name": "File Discovery", "confidence": 0.5},
                    {"technique_id": "T1622", "name": "Debugger Evasion", "confidence": 0.5},
                ],
                imports=[
                    ImportRow(dll="crypt32.dll", function="CryptEncrypt", category="crypto"),
                    ImportRow(dll="kernel32.dll", function="FindFirstFileW", category="discovery"),
                    ImportRow(
                        dll="kernel32.dll", function="IsDebuggerPresent", category="anti_debug"
                    ),
                ],
            )
        )

    def test_the_packing_section_sees_the_packer_detector(self) -> None:
        facts = bundle_for("packing_obfuscation", self._measured())["facts"]
        assert any("UPX" in m for m in facts["packer_matches"])

    def test_no_packer_is_stated_rather_than_omitted(self) -> None:
        """An absent key reads as "not measured"; "no packer was identified" is
        itself a finding."""
        facts = bundle_for("packing_obfuscation", _report(static=StaticAnalysis()))["facts"]
        assert facts["packer_detected"] is False

    def test_the_discovery_section_sees_discovery_apis_only(self) -> None:
        facts = bundle_for("discovery", self._measured())["facts"]
        assert facts["discovery_api_count"] == 27
        assert facts["discovery_imports"] == ["FindFirstFileW"]
        assert facts["discovery_techniques"] == ["T1083"], "and not the evasion technique"

    def test_the_evasion_section_sees_evasion_techniques_only(self) -> None:
        facts = bundle_for("evasion_antiforensics", self._measured())["facts"]
        assert facts["evasion_techniques"] == ["T1622"]
        assert facts["anti_debug_api_count"] == 10

    def test_the_encryption_section_sees_crypto_imports_only(self) -> None:
        facts = bundle_for("encryption_scheme", self._measured())["facts"]
        assert facts["crypto_imports"] == ["CryptEncrypt"]
        assert facts["crypto_api_count"] == 15

    def test_a_report_without_static_analysis_does_not_raise(self) -> None:
        assert bundle_for("discovery", _report())["facts"] == {}


class TestAbsenceMustBeProvableNotJustUnstated:
    """The residual failure after the first grounding pass.

    With the identity facts in the prompt the conclusion correctly opened with
    "compiled with Microsoft Visual C++ 2015-2022" and "not packed" — and then
    kept the static analyst's claim that the binary loads ``mscoree.dll``,
    reconciling the two into "a VC++ binary that is also a .NET wrapper". The
    DLL list refuted the claim, but nothing said the list was exhaustive, so
    absence from it was not treated as absence.
    """

    @staticmethod
    def _with_dlls(n: int) -> MalwareReport:
        return MalwareReport(
            identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
            static=StaticAnalysis(
                imports=[ImportRow(dll=f"lib{i:03d}.dll", function=f"Fn{i}") for i in range(n)]
            ),
        )

    def test_a_short_list_is_declared_complete(self) -> None:
        binary = bundle_for("conclusion", self._with_dlls(3))["binary"]
        key = next(k for k in binary if k.startswith("imported_dlls"))
        assert "complete list, 3 total" in key

    def test_a_truncated_list_is_never_declared_complete(self) -> None:
        """Trading one wrong inference for a worse one: telling the model an
        abridged list is exhaustive would license it to deny real imports."""
        binary = bundle_for("conclusion", self._with_dlls(40))["binary"]
        key = next(k for k in binary if k.startswith("imported_dlls"))
        assert "complete" not in key
        assert "NOT exhaustive" in key
        assert len(binary[key]) == 24

    def test_the_clr_shim_absence_is_its_own_fact(self) -> None:
        binary = bundle_for("conclusion", self._with_dlls(3))["binary"]
        assert binary["imports_dotnet_runtime (mscoree.dll)"] is False

    def test_a_real_dotnet_binary_is_not_denied(self) -> None:
        """The fact is named for what is measured. A binary that does import the
        CLR shim must read True, or the fix would create the opposite error."""
        report = MalwareReport(
            identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
            static=StaticAnalysis(imports=[ImportRow(dll="mscoree.dll", function="_CorExeMain")]),
        )
        binary = bundle_for("conclusion", report)["binary"]
        assert binary["imports_dotnet_runtime (mscoree.dll)"] is True

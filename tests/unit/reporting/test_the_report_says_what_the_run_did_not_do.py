"""What a run did not do, who spoke, and numbers nobody stated.

A report a reader cannot question has to say which of its sections are empty
because nothing was found and which because nothing looked; it has to name the
producer of every number it prints and print no number nobody stated; and its
first screen has to say, in one sentence, what a degraded run means for the
verdict, with the operator's details kept for §13.
"""

from __future__ import annotations

import re

from maljan.reporting.defang import ProseDefanger
from maljan.reporting.models import (
    DynamicBehavior,
    EvidenceSection,
    MalwareReport,
    StaticAnalysis,
)
from maljan.reporting.renderers.markdown import (
    JUDGE,
    MEASURED,
    PER_ROW,
    MarkdownRenderer,
    report_title,
)
from tests.unit.reporting._report_shapes import rich_report, stored_old_shape


def _render(report: MalwareReport) -> str:
    return MarkdownRenderer().render(report)


def _section(markdown: str, heading: str) -> str:
    return markdown.split(heading, 1)[1].split("\n## ", 1)[0]


def _head(markdown: str) -> str:
    return markdown.split("\n## 1.", 1)[0]


def _degraded() -> MalwareReport:
    """A run whose static analyst failed, whose other analysts claimed nothing,
    and whose sandbox answered empty; the reasons carry a code and an install
    command the way the pipeline writes them."""
    report = MalwareReport.model_validate(
        {
            "verdict": "Malware",
            "overall_confidence": 0.85,
            "degraded_mode": True,
            "identity": {"hashes": {"sha256": "e" * 64}, "file_type": "pe"},
            "degradation_reasons": [
                "server.analysis.tool_unavailable(the library is not installed); install the "
                "optional tool libraries on the host that runs this server: uv sync --extra tools",
                "analyst failures: static",
                "analysts produced no claims: static, dynamic, network",
            ],
            "evidence_index": [{"id": "ev_0001", "agent": "pipeline", "tool": "sandbox_network"}],
            "run_summary": {
                "failed_analysts": ["static"],
                "profile": {"name": "default", "analysts": ["static", "dynamic", "network"]},
                "negotiation": {"rounds_completed": 1, "termination_reason": "consensus"},
                "stages": [
                    {
                        "key": "analysis",
                        "kind": "analysis",
                        "ran": True,
                        "agents": ["static", "dynamic", "network"],
                        "agent_reasons": {
                            "static": "static failed",
                            "dynamic": "no sandbox fixture for this sample",
                        },
                    }
                ],
            },
        }
    )
    return report


class TestTheFirstScreenSaysWhatADegradedRunMeans:
    def test_one_reader_sentence_built_from_what_ran(self) -> None:
        head = _head(_render(_degraded()))
        assert (
            "> **[DEGRADED RUN]** The static analyst failed, the dynamic analyst was skipped "
            "(no sandbox fixture for this sample), the network analyst produced no claims and "
            "the sandbox recorded nothing for this sample; the verdict above is tentative. See "
            "§13 for what this run could not examine."
        ) in head

    def test_no_code_and_no_install_command_on_the_first_screen(self) -> None:
        head = _head(_render(_degraded()))
        assert "uv sync" not in head
        assert "server.analysis" not in head
        assert "below" not in head

    def test_section_13_lists_every_reason_verbatim_and_each_analyst_s_state(self) -> None:
        report = _degraded()
        limits = _section(_render(report), "## 13. Limitations and analysis notes")
        for reason in report.degradation_reasons:
            assert f"- {reason}" in limits
        assert (
            "- `analysis` ran; static: static failed; dynamic: no sandbox fixture for this sample"
        ) in limits

    def test_a_run_that_is_not_degraded_points_to_section_13_in_one_line(self) -> None:
        report = _degraded()
        report.degraded_mode = False
        head = _head(_render(report))
        assert "**Notes:** this run recorded 3 limitations; see §13." in head
        assert "uv sync" not in head

    def test_no_consensus_is_claimed_among_analysts_that_claimed_nothing(self) -> None:
        verdict = _section(_render(_degraded()), "## 3. Verdict and assessment")
        assert "reached consensus" not in verdict
        assert (
            "the negotiation ended by consensus after 1 round(s) with no analyst claims to agree on"
        ) in verdict


class TestEveryNumberedSectionIsPrinted:
    def test_the_thirteen_sections_and_four_appendices_are_all_there(self) -> None:
        markdown = _render(
            MalwareReport.model_validate({"identity": {"hashes": {"sha256": "0" * 64}}})
        )
        numbers = [int(n) for n in re.findall(r"^## (\d+)\. ", markdown, re.MULTILINE)]
        assert numbers == list(range(1, 14))
        assert re.findall(r"^## Appendix ([A-D])\. ", markdown, re.MULTILINE) == list("ABCD")

    def test_every_capability_subsection_is_there_with_its_line(self) -> None:
        technical = _section(_render(_degraded()), "## 5. Technical analysis")
        subsections = re.findall(r"^### (5\.\d) ", technical, re.MULTILINE)
        assert subsections == [f"5.{n}" for n in range(1, 10)]
        assert (
            "Not examined in this run: the sandbox recorded nothing for this sample, no tool "
            "looked at the file, and the report model wrote nothing on it."
        ) in technical

    def test_the_table_subsections_of_6_7_and_9_are_unnumbered(self) -> None:
        markdown = _render(rich_report())
        assert not re.findall(r"^### [679]\.\d", markdown, re.MULTILINE)
        assert "### Process tree" in markdown
        assert "### Sections" in markdown

    def test_an_absence_is_in_the_platform_s_voice(self) -> None:
        markdown = _render(_degraded())
        assert "## 4. Execution flow · _Measured_" in markdown
        assert "## 11. Recommendations · _Measured_" in markdown


class TestAnAbsenceIsClaimedOnlyWhereSomethingLooked:
    def test_one_sandbox_url_does_not_say_no_persistence_was_observed(self) -> None:
        stored = stored_old_shape()
        assert stored.dynamic is None
        technical = _section(_render(stored), "## 5. Technical analysis")
        assert "no persistence observed" not in technical

    def test_a_sandbox_blind_to_the_registry_does_not_say_it_either(self) -> None:
        report = rich_report()
        report.persistence = []
        report.dynamic = DynamicBehavior(unavailable=["registry"])
        technical = _section(_render(report), "## 5. Technical analysis")
        assert "no persistence observed" not in technical

    def test_a_sandbox_that_watched_says_it(self) -> None:
        report = rich_report()
        report.persistence = []
        report.technical_analysis.persistence_detail = None  # type: ignore[union-attr]
        technical = _section(_render(report), "## 5. Technical analysis")
        assert "_Observed in sandbox:_ no persistence observed." in technical

    def test_an_observed_step_with_no_observation_carries_the_note(self) -> None:
        report = _degraded()
        report.technical_analysis = rich_report().technical_analysis
        flow = _section(_render(report), "## 4. Execution flow")
        assert (
            "(observed in sandbox) [ev_0008] _(unresolved: report.flow_voice; no sandbox "
            "observation in this run)_"
        ) in flow


class TestNoNumberNobodyStated:
    def test_a_technique_with_no_stated_confidence_says_not_given(self) -> None:
        report = rich_report()
        report.capability_matrix[1].confidence = None
        attack = _section(_render(report), "## 8. MITRE ATT&CK mapping")
        (row,) = [line for line in attack.splitlines() if "| T1547.001 |" in line]
        assert "| rule match |" in row or "| not given |" in row
        assert "0.92" not in row

    def test_a_stated_confidence_names_its_producer(self) -> None:
        attack = _section(_render(rich_report()), "## 8. MITRE ATT&CK mapping")
        assert "high confidence, 0.92, stated by the judge" in attack
        assert "moderate-to-high confidence, 0.80, stated by the static analyst" in attack

    def test_a_stored_row_says_its_producer_is_not_recorded(self) -> None:
        report = rich_report()
        report.capability_matrix[0].confidence_source = ""
        attack = _section(_render(report), "## 8. MITRE ATT&CK mapping")
        assert "0.80, producer not recorded" in attack

    def test_packer_hash_and_payload_fields_say_not_recorded(self) -> None:
        report = rich_report()
        report.static = StaticAnalysis(
            packer_matches=[{"kind": "packer", "method": "section_name"}],
            embedded_resources=[{"id": "overlay+0x10", "carved": True}],
        )
        report.attribution.function_hash_matches = [{"shared_functions": 3}]
        report.attribution.family_rag_candidates = [{"malware_category": "loader"}]
        markdown = _render(report)
        assert "| not recorded | packer | not recorded | section_name |" in markdown
        assert "| `overlay+0x10` (-) | not recorded |" in markdown
        assert "| not recorded | not recorded | 3 |" in markdown
        assert "0.00" not in _section(markdown, "## 12. Attribution and related activity")
        assert "| ? |" not in markdown and "`?`" not in markdown


class TestTheVoiceNamesWhoSpoke:
    def test_the_platform_s_fallback_is_not_the_report_model_s(self) -> None:
        report = _degraded()
        findings = _section(_render(report), "## 1. Key findings")
        assert _render(report).count(f"## 1. Key findings · _{PER_ROW}_") == 1
        assert f"No summary was written: the report model wrote none. _({MEASURED})_" in findings

    def test_the_platform_is_measured_from_the_file_format(self) -> None:
        markdown = _render(rich_report())
        assert "| Platform | Windows (from the file format) |" in _section(
            markdown, "## 2. Sample overview"
        )
        assert "Affected platforms" not in markdown

    def test_the_family_subsection_names_who_named_the_family(self) -> None:
        report = rich_report()
        report.attribution.family_source = "sandbox"
        assert f"### 12.1 Family · _{MEASURED}_" in _render(report)
        report.attribution.family_source = "judge"
        assert f"### 12.1 Family · _{JUDGE}_" in _render(report)

    def test_a_placeholder_family_does_not_title_the_report(self) -> None:
        report = rich_report()
        report.attribution.family_evidence_ids = []
        assert report_title(report).startswith("PE sample ")

    def test_the_report_model_s_findings_on_section_1_are_beside_it(self) -> None:
        report = rich_report()
        report.run_summary["validation"]["unresolved"].append(
            {
                "agent": "narrative",
                "code": "narrative.ungrounded_capability",
                "message": "the text claims lateral movement, which nothing establishes",
            }
        )
        findings = _section(_render(report), "## 1. Key findings")
        assert (
            "- `narrative.ungrounded_capability`: the text claims lateral movement, which "
            "nothing establishes"
        ) in findings

    def test_a_stored_report_with_no_team_says_so(self) -> None:
        methodology = _render(stored_old_shape()).split("## Appendix D.", 1)[1]
        assert "- Team: not recorded in this report" in methodology
        assert "the default team" not in methodology


class TestTheMeasuredProofSitsBesideTheProse:
    def _capa(self) -> MalwareReport:
        report = rich_report()
        report.sections.append(
            EvidenceSection(
                key="capa_capabilities",
                title="capa capabilities",
                kind="table",
                columns=["Namespace", "Rule", "ATT&CK", "MBC"],
                rows=[
                    ["", "PEB access", "", "Anti-Behavioral Analysis::PEB [B0001.019]"],
                    ["data-manipulation/checksum/crc32", "hash data with CRC32", "", ""],
                    ["load-code/pe", "resolve function by parsing PE exports", "", ""],
                    ["data-manipulation/encryption/rc4", "encrypt data using RC4 PRGA", "", ""],
                ],
                evidence_ids=["ev_0007", "ev_0019"],
            )
        )
        return report

    def test_5_2_prints_every_resolution_rule_with_its_evidence(self) -> None:
        technical = _section(_render(self._capa()), "## 5. Technical analysis")
        resolution = technical.split("### 5.2", 1)[1].split("### 5.3", 1)[0]
        for rule in ("PEB access", "hash data with CRC32", "resolve function by parsing PE"):
            (row,) = [line for line in resolution.splitlines() if f"| {rule}" in line]
            assert row.endswith("| ev_0007, ev_0019 |"), row

    def test_5_1_prints_the_anti_analysis_and_obfuscation_rules(self) -> None:
        technical = _section(_render(self._capa()), "## 5. Technical analysis")
        packing = technical.split("### 5.1", 1)[1].split("### 5.2", 1)[0]
        assert "| encrypt data using RC4 PRGA |" in packing
        # PEB access speaks to API resolution and is printed there, once.
        assert "PEB access" not in packing
        assert "hash data with CRC32" not in packing

    def test_a_capa_row_in_section_8_carries_its_evidence(self) -> None:
        attack = _section(_render(rich_report()), "## 8. MITRE ATT&CK mapping")
        (row,) = [line for line in attack.splitlines() if "| T1055 |" in line]
        assert "rule inject code (capa)" in row
        assert row.endswith("| ev_0010, ev_0007 |"), row


class TestMinorLeaks:
    def test_a_private_address_a_model_wrote_is_marked(self) -> None:
        technical = _section(_render(rich_report()), "## 5. Technical analysis")
        assert "`10[.]0[.]0[.]5` (not an address this run may publish)" in technical

    def test_prose_never_leaves_a_scheme_live_in_front_of_a_defanged_host(self) -> None:
        defang = ProseDefanger([("c2.evil.tld", "domain")])
        assert defang("see http://c2.evil.tld/other") == "see hxxp://c2[.]evil[.]tld/other"
        assert defang("see https://other.example/") == "see https://other.example/"

    def test_a_model_s_list_is_printed_whole(self) -> None:
        from maljan.reporting.models import ServiceProcessKill

        report = rich_report()
        assert report.technical_analysis is not None
        names = [f"svc{n}" for n in range(45)]
        report.technical_analysis.service_process_kill = ServiceProcessKill(kill_list=names)
        report.technical_analysis.shadow_copy_destruction = [f"cmd {n}" for n in range(12)]
        technical = _section(_render(report), "## 5. Technical analysis")
        assert "`svc44`" in technical
        assert "`cmd 11`" in technical


class TestWhatLookedIsNamed:
    def test_the_skipped_analysts_are_said_to_be_skipped(self) -> None:
        report = _degraded()
        report.run_summary["agent_stats"] = [
            {"agent_id": "static", "claim_count": 0, "no_data": False},
            {"agent_id": "dynamic", "claim_count": 0, "no_data": True},
            {"agent_id": "network", "claim_count": 0, "no_data": True},
        ]
        head = _head(_render(report))
        assert "the dynamic and network analysts were skipped" in head
        assert "produced no claims" not in head

    def test_an_absence_names_the_tools_that_looked(self) -> None:
        report = _degraded()
        report.evidence_index.append(
            report.evidence_index[0].model_copy(update={"id": "ev_0002", "tool": "capa"})
        )
        technical = _section(_render(report), "## 5. Technical analysis")
        assert (
            "Nothing recorded in this run: the tools that ran over the file (capa) recorded no "
            "discovery command, and the sandbox recorded nothing for this sample; the report "
            "model wrote nothing on it."
        ) in technical

    def test_a_similarity_without_a_measure_is_said_plainly(self) -> None:
        report = rich_report()
        report.attribution.similar_samples = [{"sample_id": "a" * 64}, {"sample_id": "b" * 64}]
        similarity = _section(_render(report), "## 12. Attribution and related activity")
        assert (
            "2 previously analysed samples were returned by the long-term memory and are not "
            "listed. No similarity measure was recorded for these samples."
        ) in similarity


class TestAFamilySpecificSectionNeedsItsFamily:
    def test_a_loader_s_cipher_is_not_a_ransomware_section(self) -> None:
        from maljan.reporting.models import EncryptionScheme

        report = rich_report()
        assert report.technical_analysis is not None
        report.technical_analysis.encryption_scheme = EncryptionScheme(
            cipher="RC4",
            mode="PRGA",
            library="none",
            file_marker="none",
            extension="none",
            partial_threshold="none",
            evidence_ref="ev_0008",
        )
        technical = _section(_render(report), "## 5. Technical analysis")
        assert "### 5.9 Family-specific behaviour · _Measured_" in technical
        assert "Ransomware behaviour" not in technical
        packing = technical.split("### 5.1", 1)[1].split("### 5.2", 1)[0]
        assert "| Cipher | RC4 |" in packing
        assert "| none |" not in technical
        assert "File marker" not in technical

    def test_a_file_encryption_scheme_stays_under_the_ransomware_heading(self) -> None:
        from maljan.reporting.models import EncryptionScheme

        report = rich_report()
        assert report.technical_analysis is not None
        report.technical_analysis.encryption_scheme = EncryptionScheme(
            cipher="ChaCha20", extension=".example-locked"
        )
        technical = _section(_render(report), "## 5. Technical analysis")
        family = technical.split("### 5.9", 1)[1]
        assert "Ransomware behaviour" in family
        assert "| Extension | .example-locked |" in family

    def test_a_block_of_placeholders_is_no_content(self) -> None:
        from maljan.reporting.composer import _has_content
        from maljan.reporting.models import EncryptionScheme

        assert not _has_content(
            EncryptionScheme(cipher="none", mode="unknown", evidence_ref="ev_1")
        )
        assert _has_content(EncryptionScheme(cipher="RC4"))


class TestAnMbcIdIsNotAnAttackRow:
    def test_it_is_listed_as_a_behaviour_under_the_table(self) -> None:
        from maljan.reporting.models import CapabilityCell

        report = rich_report()
        report.capability_matrix.append(
            CapabilityCell(
                tactic="TA0000",
                tactic_name="Unknown",
                technique_id="B0001.019",
                technique_name="B0001.019",
                evidence=["PEB Access for Anti-Debugging"],
                confidence=0.9,
                contributing_layers=["static"],
                technique_id_valid=False,
                not_published="the ATT&CK catalogue has no entry for this id in any domain",
            )
        )
        attack = _section(_render(report), "## 8. MITRE ATT&CK mapping")
        assert not [line for line in attack.splitlines() if line.startswith("| Unknown")]
        assert (
            "- B0001.019: PEB Access for Anti-Debugging (claimed by static; not an ATT&CK "
            "technique, not published)"
        ) in attack
        assert "B0001.019 B0001.019" not in attack


class TestAnUnconfirmedCreditSitsBesideItsTechnique:
    def test_the_finding_prints_on_the_row_it_names_and_no_other(self) -> None:
        report = rich_report()
        report.run_summary["validation"]["unresolved"].append(
            {
                "agent": "judge",
                "code": "stix.credit_without_claim",
                "message": (
                    "the relationship at objects[3] credits 'dynamic' with T1055, and the "
                    "sources that named T1055 are static — the evidence summary lists who "
                    "named each technique."
                ),
            }
        )
        attack = _section(_render(report), "## 8. MITRE ATT&CK mapping")
        (injection,) = [line for line in attack.splitlines() if "| T1055 |" in line]
        (run_key,) = [line for line in attack.splitlines() if "| T1547.001 |" in line]
        assert "unresolved: stix.credit_without_claim" in injection
        assert "credit_without_claim" not in run_key

    def test_a_parent_id_does_not_take_a_sub_technique_s_finding(self) -> None:
        report = rich_report()
        report.run_summary["validation"]["unresolved"].append(
            {
                "agent": "judge",
                "code": "stix.credit_without_claim",
                "message": "the relationship credits 'dynamic' with T1055.012",
            }
        )
        attack = _section(_render(report), "## 8. MITRE ATT&CK mapping")
        (injection,) = [line for line in attack.splitlines() if "| T1055 |" in line]
        assert "credit_without_claim" not in injection


class TestTheSandboxStatusIsAStatementNotAnObservation:
    def _report(self) -> MalwareReport:
        report = _degraded()
        statement = (
            "No sandbox ran for this sample: the mock sandbox has no recorded report for it "
            "and answered with an empty stand-in, so nothing here was observed by executing "
            "the sample."
        )
        report.evidence_index.append(
            report.evidence_index[0].model_copy(update={"id": "ev_0009", "tool": "sandbox_status"})
        )
        report.sections.append(
            EvidenceSection(
                key="sandbox_status",
                title="Sandbox",
                kind="text",
                text=statement,
                evidence_ids=["ev_0009"],
            )
        )
        report.run_summary["sandbox"] = {"status": "not run", "statement": statement}
        return report

    def test_it_is_no_sandbox_entry_an_observed_step_may_cite(self) -> None:
        from maljan.reporting.evidence_bundles import sandbox_entry_ids

        assert sandbox_entry_ids(self._report()) == []

    def test_the_report_says_it_in_the_run_s_words(self) -> None:
        markdown = _render(self._report())
        observed = _section(markdown, "## 6. Observed behaviour")
        assert "No sandbox ran for this sample: the mock sandbox has no recorded report" in (
            observed
        )
        run = markdown.split("## Appendix B.", 1)[1]
        assert "- Sandbox: No sandbox ran for this sample" in run

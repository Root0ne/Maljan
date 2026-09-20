"""The capability profile every consumer reads is the pack's entry.

The extractor used to stamp a category and a suspicion flag on every import
row, and the report's "Suspicious Imports" table, the narrative prompt, the
YARA draft and the family profile all read the stamp. Now the profile is the
knowledge table's own rows, recorded by the triage pack as one ledger entry,
counted once and cited by id wherever it is shown; an import is worth a
detection string when one of the table's technique rules fired on it.
"""

from __future__ import annotations

from maljan.reporting.builder import MalwareReportBuilder
from maljan.reporting.detection_signatures import _build_yara
from maljan.reporting.models import MalwareReport
from maljan.reporting.narrative_agent import build_prompt_text
from maljan.reporting.renderers.markdown import MarkdownRenderer
from maljan.schemas.evidence import EvidenceCounter
from maljan.tools.knowledge import api_capability
from tests.unit._ledger_helpers import entry

_NAMES = ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "RegQueryValueExA"]


def _report() -> tuple[MalwareReport, str]:
    counter = EvidenceCounter()
    ledger = [
        entry(
            "pe_info",
            {"imports": [{"dll": "KERNEL32.dll", "function": n} for n in _NAMES]},
            counter,
        ),
        entry("api_capability", api_capability(_NAMES), counter),
    ]
    report = MalwareReportBuilder(
        file_hash="a" * 64,
        file_name="fixture.exe",
        sample_path=None,
        sandbox_report={},
        reports={},
        isr_reports={},
        stix_output={"objects": []},
        run_summary={},
        discussion_history=[],
        final_decision="Malware",
        overall_confidence=0.9,
        malware_category="loader",
        evidence_ledger=ledger,
    ).build_deterministic()
    return report, ledger[1].id


class TestTheMarkdownReport:
    def test_the_profile_line_cites_the_entry_and_no_import_is_called_suspicious(self) -> None:
        report, entry_id = _report()
        md = MarkdownRenderer().render(report)
        assert f"**Import capability profile** ({entry_id})" in md
        assert "process_injection ×3" in md
        assert "Suspicious Imports" not in md

    def test_the_rule_that_fired_is_a_row_with_its_source_and_entry(self) -> None:
        report, entry_id = _report()
        md = MarkdownRenderer().render(report)
        assert (
            "| T1055 | Process Injection "
            "| allocating or writing memory in another process and starting a thread in it "
            f"| api_capability ({entry_id}) " in md
        )

    def test_the_row_says_how_much_ordinary_software_the_same_rule_fires_on(self) -> None:
        """A deterministic association printed without its base rate reads as a
        finding. The last cell is the measurement, with the corpus named."""
        report, _entry_id = _report()
        md = MarkdownRenderer().render(report)
        assert "0.5% of benign software (13 of 2730 freely distributed Windows binaries" in md


class TestTheNarrativePrompt:
    def test_the_prompt_carries_the_profile_and_the_rule_hit_with_the_id(self) -> None:
        report, entry_id = _report()
        text = build_prompt_text(report)
        assert "Import capability profile" in text
        assert f"process_injection x3, registry x1 [{entry_id}]" in text
        assert "- T1055 Process Injection (allocating or writing memory in another process" in text
        assert "Suspicious imports" not in text


class TestTheYaraDraft:
    def test_the_strings_are_the_imports_a_rule_fired_on(self) -> None:
        report, _ = _report()
        rule = _build_yara(report)
        assert rule is not None
        body: str = rule.body
        assert '"WriteProcessMemory"' in body
        assert '"CreateRemoteThread"' in body
        # The API the rule did not match is not a string.
        assert "RegQueryValueExA" not in body

    def test_bare_names_not_dll_bang_function(self) -> None:
        report, _ = _report()
        rule = _build_yara(report)
        assert rule is not None
        assert "KERNEL32.dll!" not in rule.body


def _prompt_lines(report: MalwareReport) -> list[str]:
    return build_prompt_text(report).splitlines()


class TestWithoutThePackEntry:
    def test_nothing_is_stated(self) -> None:
        counter = EvidenceCounter()
        ledger = [entry("pe_info", {"imports": [{"dll": "k", "function": "ReadFile"}]}, counter)]
        report = MalwareReportBuilder(
            file_hash="a" * 64,
            file_name="fixture.exe",
            sample_path=None,
            sandbox_report={},
            reports={},
            isr_reports={},
            stix_output={"objects": []},
            run_summary={},
            discussion_history=[],
            final_decision="Malware",
            overall_confidence=0.9,
            malware_category="loader",
            evidence_ledger=ledger,
        ).build_deterministic()
        assert report.static is not None
        assert report.static.api_capabilities == {}
        assert "  (none stated)" in _prompt_lines(report)
        assert "Import capability profile" not in MarkdownRenderer().render(report)

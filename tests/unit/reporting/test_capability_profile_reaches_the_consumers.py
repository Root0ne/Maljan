"""The capability profile every consumer reads is the pack's entry.

The extractor used to stamp a category and a suspicion flag on every import
row, and the report's "Suspicious Imports" table, the narrative prompt, the
YARA draft and the family profile all read the stamp. Now the profile is the
knowledge table's own rows, recorded by the triage pack as one ledger entry,
counted once and cited by id wherever it is shown; an import is worth a
detection string when one of the table's technique rules fired on it.
"""

from __future__ import annotations

import re

import pytest

from maljan.reporting.builder import MalwareReportBuilder
from maljan.reporting.detection_signatures import _build_yara
from maljan.reporting.models import (
    FileHashes,
    MalwareReport,
    SampleIdentity,
    StaticAnalysis,
)
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
        (row,) = [line for line in md.splitlines() if "| T1055 | Process Injection |" in line]
        # The tactic is the catalogue's, not a dash.
        assert not row.startswith("| - |")
        assert (
            "| rule allocating or writing memory in another process and starting a thread "
            "in it (api_capability), imports " in row
        )
        # Nothing claimed T1055 in this run, so the rule's row is not a
        # published technique; it says so rather than borrowing the status.
        assert (
            "| api_capability (rule match) | rule match | not published: a rule matched it "
            f"and no producer claimed it | {entry_id} |"
        ) in row

    def test_the_row_says_how_much_ordinary_software_the_same_rule_fires_on(self) -> None:
        """A deterministic association printed without its base rate reads as a
        finding. The last cell is the measurement, with the corpus named and the
        support beside it: a rule that is rare in ordinary software and has
        fired on no held-out malware has told a reader both halves or neither.
        """
        report, _entry_id = _report()
        md = MarkdownRenderer().render(report)
        assert (
            "fires on 0.5% of benign software (13 of 2730 freely distributed Windows binaries"
        ) in md
        assert "held-out malware profiles support it" in md

    def test_the_profile_line_is_no_longer_a_count_with_nothing_to_weigh_it(self) -> None:
        """``process_injection ×3`` says nothing until a reader knows the group
        is on two ordinary Windows binaries in three."""
        report, _entry_id = _report()
        md = MarkdownRenderer().render(report)
        assert "process_injection ×3 (65.6%)" in md
        assert "The bracketed share is how much of 2730 freely distributed Windows" in md
        assert "nothing about how likely this sample is to be benign" in md


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


class TestASampleCannotReshapeTheTableItIsDescribedIn:
    """An import name is the sample's own bytes.

    ``pe_extractor`` decodes it with ``errors="replace"`` and asserts nothing
    else about it, and the import-technique table writes it into a Markdown
    cell. A pipe there adds a column and shifts every cell after it; a newline
    ends the row and orphans every row below — in a table a human reads to make
    a call. The same holds for the technique name, which comes from the data
    file, and for the producer key in the source column.
    """

    @staticmethod
    def _rows(**over: object) -> list[str]:
        hit: dict[str, object] = {
            "technique_id": "T1113",
            "name": "Screen Capture",
            "rule": "pulling the pixels back out",
            "matched_apis": ["GetDIBits", "PrintWindow"],
            "source": "api_capability",
            "benign_rate": "fires on 0.3% of benign software (8 of 2730 binaries)",
        }
        hit.update(over)
        report = MalwareReport(
            verdict="Malware",
            identity=SampleIdentity(file_name="s.exe", hashes=FileHashes(sha256="a" * 64)),
            static=StaticAnalysis(api_technique_hits=[hit]),
        )
        md = MarkdownRenderer().render(report)
        section = md.split("## 8. MITRE ATT&CK mapping", 1)[1].split("\n## ", 1)[0]
        return [
            line
            for line in section.splitlines()
            if line.startswith("|") and not line.startswith("|---")
        ]

    @staticmethod
    def _separators(row: str) -> int:
        """Pipes that still divide cells — an escaped one is text, not a column."""
        return len(re.findall(r"(?<!\\)\|", row))

    def test_an_undamaged_row_has_eight_cells(self) -> None:
        assert [self._separators(row) for row in self._rows()] == [9, 9]

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("matched_apis", ["Get|DIBits", "PrintWindow"]),
            ("matched_apis", ["Get\nDIBits", "PrintWindow"]),
            ("name", "Screen | Capture"),
            ("name", "Screen\nCapture"),
            ("source", "api|capability"),
            ("rule", "a rule | with a pipe"),
            ("benign_rate", "fires on 0.3% | of benign software"),
            ("technique_id", "T1113|T1055"),
        ],
    )
    def test_neither_a_pipe_nor_a_newline_moves_a_column(self, field: str, value: object) -> None:
        rows = self._rows(**{field: value})
        # One header and one data row, each with the cell count an undamaged
        # table has: nothing gained a column and nothing was cut in half.
        assert len(rows) == 2, rows
        assert [self._separators(row) for row in rows] == [9, 9], rows

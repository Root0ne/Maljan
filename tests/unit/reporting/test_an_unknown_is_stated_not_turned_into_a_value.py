"""A sandbox signature with no severity stays unknown, and unasked enrichment rows are stated."""

from __future__ import annotations

from typing import Any

from maljan.reporting.dedupe import distinct_signatures
from maljan.reporting.ledger_projection import dynamic_from_ledger
from maljan.reporting.models import MalwareReport, SandboxSignature
from maljan.reporting.renderers.markdown import MarkdownRenderer, _signature_row
from maljan.schemas.evidence import EvidenceCounter
from tests.unit._ledger_helpers import entry
from tests.unit.reporting._report_shapes import rich_report


def _projected(*rows: dict[str, Any]) -> list[SandboxSignature]:
    counter = EvidenceCounter()
    ledger = [entry("sandbox_signatures", {"signatures": list(rows)}, counter, agent="dynamic")]
    dynamic = dynamic_from_ledger(ledger)
    assert dynamic is not None
    return dynamic.sandbox_signatures


class TestSignatureSeverity:
    def test_a_row_without_a_severity_is_unknown_not_zero(self) -> None:
        (none, zero, absent) = _projected(
            {"name": "a", "severity": None},
            {"name": "b", "severity": 0},
            {"name": "c"},
        )
        assert none.severity is None
        assert zero.severity == 0
        assert absent.severity is None

    def test_unknown_and_zero_are_two_rows(self) -> None:
        rows = [
            SandboxSignature(name="a", severity=None),
            SandboxSignature(name="a", severity=0),
            SandboxSignature(name="a", severity=None),
        ]
        assert [r.severity for r in distinct_signatures(rows)] == [None, 0]

    def test_the_table_says_unknown(self) -> None:
        assert "| unknown |" in _signature_row(SandboxSignature(name="a", severity=None))
        assert "| 0 |" in _signature_row(SandboxSignature(name="a", severity=0))


class TestUnaskedEnrichmentRows:
    def _report(self, rows: list[dict[str, Any]] | None) -> MalwareReport:
        data = rich_report().model_dump(mode="json")
        if rows is not None:
            data["enrichment_not_asked"] = rows
        return MalwareReport.model_validate(data)

    def test_a_report_that_states_none_dumps_without_the_field(self) -> None:
        assert "enrichment_not_asked" not in self._report(None).model_dump(mode="json")

    def test_the_rendering_names_each_value_and_question(self) -> None:
        report = self._report(
            [{"kind": "ip", "value": "203.0.113.7", "questions": ["reputation", "asn"], "cap": 3}]
        )
        markdown = MarkdownRenderer().render(report)
        assert "did not ask about 1 network value" in markdown
        assert "203[.]0[.]113[.]7" in markdown
        assert "(reputation, asn)" in markdown

    def test_a_report_that_states_none_renders_without_the_line(self) -> None:
        assert "did not ask about" not in MarkdownRenderer().render(self._report(None))


class TestEverywhereASeverityIsRead:
    def _with(self, *signatures: SandboxSignature) -> MalwareReport:
        report = rich_report()
        assert report.dynamic is not None
        report.dynamic.sandbox_signatures = list(signatures)
        return report

    def test_the_draft_rule_names_sort_unknown_below_every_number(self) -> None:
        from maljan.reporting.detection_signatures import _collect_signature_names

        report = self._with(
            SandboxSignature(name="n1", description="unknown one", severity=None),
            SandboxSignature(name="z", description="zero", severity=0),
            SandboxSignature(name="h", description="high", severity=7),
            SandboxSignature(name="n2", description="unknown two", severity=None),
        )
        assert _collect_signature_names(report) == ["high", "zero", "unknown one", "unknown two"]

    def test_the_narrative_prompt_says_severity_unknown(self) -> None:
        from maljan.reporting.narrative_agent import build_prompt_text

        report = self._with(
            SandboxSignature(name="sigx", severity=None),
            SandboxSignature(name="sigy", severity=0),
        )
        prompt = build_prompt_text(report)
        assert "sigx" in prompt
        assert "(severity unknown," in prompt
        assert "(severity 0," in prompt

    def test_the_evasion_table_says_unknown(self) -> None:
        report = self._with(
            SandboxSignature(name="anti_vm_check", description="detects a vm", severity=None)
        )
        markdown = MarkdownRenderer().render(report)
        assert "| anti_vm_check | unknown |" in markdown

    def test_a_stored_dump_reads_back_as_it_was_written(self) -> None:
        for severity in (None, 0, 4):
            row = SandboxSignature(name="a", severity=severity)
            again = SandboxSignature.model_validate(row.model_dump(mode="json"))
            assert again.severity == severity
            assert again.model_dump(mode="json") == row.model_dump(mode="json")
        # A row written with no severity key at all is unknown, as it is when built.
        assert SandboxSignature.model_validate({"name": "a"}).severity is None
        assert SandboxSignature(name="a").severity is None

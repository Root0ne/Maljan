"""The export, the IOC table and the feed read one publish decision.

A run exported two C2 names the judge read out of decoded strings while the
report's IOC section and ``/reports/{id}/iocs`` listed four hashes. The first
fix made both surfaces read the export, and the export did not ask the judge's
values the rule's second half: a certificate authority's host the judge copied
out of the strings table would have been published, fed and drafted an alert
for. Now the export asks every judge indicator the one publish rule — the judge
asserting a value is not a second source for it — and declines one the rule
refuses, with a record; the table and the feed ask the same rule of the same
values. The export is compared with the surfaces only as a consistency test.
"""

from __future__ import annotations

from typing import Any

import pytest

from app.services.report_service import _with_the_judge_s_values
from maljan.reporting.builder import build_consolidated_iocs
from maljan.reporting.detection_signatures import build_detection_rules
from maljan.reporting.models import (
    DynamicBehavior,
    FileHashes,
    JudgeIndicator,
    MalwareReport,
    NetworkDomain,
    NetworkIOCs,
    SampleIdentity,
)
from maljan.reporting.renderers.stix_renderer import (
    UNPUBLISHED_VALUE_CODE,
    ExtendedSTIXRenderer,
    exported_indicator_values,
    indicator_publish_reason,
    publish_answer,
    rule_values,
)
from maljan.schemas.stix_models import Bundle

OBSERVED = "gate9.example.org"
SWEPT = "crl.example-authority.org"
SHA256 = "a" * 64
DROPPED = "b" * 64
FOREIGN = "d" * 64


def _indicator(index: int, pattern: str) -> dict[str, Any]:
    return {
        "type": "indicator",
        "id": f"indicator--0f1e2d3c-4b5a-4968-8776-65544333221{index}",
        "name": f"judge indicator {index}",
        "pattern": pattern,
        "pattern_type": "stix",
        "indicator_types": ["malicious-activity"],
        "valid_from": "2026-01-01T00:00:00Z",
    }


def _judge(*patterns: str) -> dict[str, Any]:
    return {"type": "bundle", "objects": [_indicator(i, p) for i, p in enumerate(patterns)]}


def _report(judge: dict[str, Any], **over: Any) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256=SHA256)),
        verdict="Malware",
        malware_category="loader",
        network=NetworkIOCs(
            domains=[
                NetworkDomain(fqdn=OBSERVED, source="sandbox"),
                NetworkDomain(fqdn=SWEPT, source="strings"),
            ]
        ),
        judge_indicators=[
            JudgeIndicator(kind=v.kind, value=v.value, algorithm=v.algorithm)
            for v in exported_indicator_values(judge)
        ],
        **over,
    )


def _export(report: MalwareReport, judge: dict[str, Any]) -> tuple[dict[str, Any], Any]:
    renderer = ExtendedSTIXRenderer()
    bundle = renderer.render(report, Bundle.model_validate(judge))
    return bundle.model_dump(mode="json"), renderer


def _row(report: MalwareReport, value: str) -> Any:
    (row,) = [r for r in build_consolidated_iocs(report) if r.value == value]
    return row


class TestAJudgeValueTheRuleRefuses:
    """sectigo-shaped: a host the judge copied out of the strings table."""

    def _setup(self) -> tuple[MalwareReport, dict[str, Any]]:
        judge = _judge(f"[domain-name:value = '{SWEPT}']")
        return _report(judge), judge

    def test_the_export_declines_it_with_a_record(self) -> None:
        report, judge = self._setup()
        exported, renderer = _export(report, judge)

        assert SWEPT not in str(exported)
        assert UNPUBLISHED_VALUE_CODE in [code for code, _why in renderer.declined]

    def test_the_table_prints_the_rule_s_refusal(self) -> None:
        report, _judge_bundle = self._setup()

        assert _row(report, SWEPT).published == "no: seen only in the file's strings"

    def test_the_feed_withholds_it(self) -> None:
        report, _judge_bundle = self._setup()
        out: list[dict[str, Any]] = [
            {"kind": "domain", "value": SWEPT, "source": "strings", "published": False}
        ]

        _with_the_judge_s_values(out, report.model_dump(mode="json"), None)

        assert [row["published"] for row in out if row["value"] == SWEPT] == [False]

    def test_no_draft_alerts_on_it(self) -> None:
        report, judge = self._setup()
        report.stix_bundle_extended, _renderer = _export(report, judge)
        report.consolidated_iocs = build_consolidated_iocs(report)

        assert all(SWEPT not in rule.body for rule in build_detection_rules(report))

    def test_a_value_no_row_has_is_added_as_the_judge_s_refused_row(self) -> None:
        judge = _judge("[domain-name:value = 'only-judge.example.net']")
        report = _report(judge)

        row = _row(report, "only-judge.example.net")

        assert (row.source, row.published) == ("judge", "no: seen only in the file's strings")


class TestAJudgeValueTheRulePublishes:
    def test_everywhere(self) -> None:
        judge = _judge(f"[domain-name:value = '{OBSERVED}']")
        report = _report(judge)
        exported, renderer = _export(report, judge)

        assert OBSERVED in str(exported)
        assert _row(report, OBSERVED).published == "yes"
        assert not [code for code, _why in renderer.declined if code == UNPUBLISHED_VALUE_CODE]


class TestTheKindsTheRuleNowAnswers:
    def test_the_sample_s_own_hash_is_published(self) -> None:
        assert publish_answer("hash", SHA256, "identity") == "yes"

    def test_a_hash_no_second_source_records_is_not(self) -> None:
        judge = _judge(f"[file:hashes.'SHA-256' = '{FOREIGN}']")
        report = _report(judge)
        exported, renderer = _export(report, judge)

        assert FOREIGN not in str(exported)
        assert _row(report, FOREIGN).published == "no: seen only in the file's strings"

    def test_a_hash_of_a_file_the_sandbox_saw_dropped_is(self) -> None:
        judge = _judge(f"[file:hashes.'SHA-256' = '{DROPPED}']")
        dynamic = DynamicBehavior(
            file_operations=[{"operation": "write", "path": "C:\\x\\a.bin", "sha256": DROPPED}]
        )
        report = _report(judge, dynamic=dynamic)
        exported, _renderer = _export(report, judge)

        assert DROPPED in str(exported)

    def test_a_truncated_digest_is_not(self) -> None:
        assert indicator_publish_reason("hash", "abc123", "identity") is None

    def test_a_command_line_is_never_published(self) -> None:
        judge = _judge("[process:command_line = 'cmd.exe /c example-tool --run']")
        report = _report(judge)
        exported, renderer = _export(report, judge)

        assert "example-tool" not in str(exported)
        assert publish_answer("command", "cmd.exe /c x", "judge").startswith(
            "no: a command line is not"
        )


class TestOneDecision:
    """The consistency test: what the export carries and what the table publishes agree."""

    @pytest.mark.parametrize(
        "patterns",
        [
            (f"[domain-name:value = '{OBSERVED}']", f"[domain-name:value = '{SWEPT}']"),
            (f"[file:hashes.'SHA-256' = '{SHA256}']", f"[file:hashes.'SHA-256' = '{FOREIGN}']"),
            ("[mutex:name = 'ExampleMarker']", f"[domain-name:value = '{OBSERVED}']"),
            ("[file:name = 'C:\\\\ProgramData\\\\relay.dat']",),
            (f"[domain-name:value IN ('{OBSERVED}', '{SWEPT}')]",),
            (f"[domain-name:value IN ('{OBSERVED}')]",),
            (f"[domain-name:value != '{SWEPT}']",),
            ("[process:command_line IN ('whoami /all')]",),
        ],
    )
    def test_the_export_and_the_table_agree(self, patterns: tuple[str, ...]) -> None:
        judge = _judge(*patterns)
        dynamic = DynamicBehavior(
            file_operations=[{"operation": "write", "path": "C:\\ProgramData\\relay.dat"}]
        )
        report = _report(judge, dynamic=dynamic)
        exported, _renderer = _export(report, judge)
        report.stix_bundle_extended = exported
        table = build_consolidated_iocs(report)

        published = {(r.kind, r.value.lower()) for r in table if r.published == "yes"}
        carried = {(v.kind, v.value.lower()) for v in exported_indicator_values(exported)}
        judged = {(j.kind, j.value.lower()) for j in report.judge_indicators}
        # Every value any exported indicator names, whatever its operator.
        named = {
            (v.kind, v.value.lower())
            for obj in exported["objects"]
            if obj.get("type") == "indicator"
            for v in rule_values(str(obj.get("pattern") or ""))
        }

        # Every value the export carries is published in the table ...
        assert carried <= published
        assert named <= published
        # ... and every judge value the table publishes is in the export.
        assert (published & judged) <= carried


class TestEveryOperatorIsAskedTheRule:
    """An ``IN`` list, a ``!=`` or a ``>`` carried the values ``=`` was refused."""

    @pytest.mark.parametrize(
        "pattern",
        [
            f"[domain-name:value IN ('{SWEPT}')]",
            f"[domain-name:value IN ('{OBSERVED}', '{SWEPT}')]",
            f"[domain-name:value != '{SWEPT}']",
            "[ipv4-addr:value IN ('45.77.12.9')]",
            "[process:command_line IN ('whoami /all')]",
            "[process:command_line > 'whoami']",
        ],
    )
    def test_a_value_the_rule_refuses_is_declined_on_every_operator(self, pattern: str) -> None:
        judge = _judge(pattern)
        report = _report(judge)
        exported, renderer = _export(report, judge)

        assert pattern not in str(exported)
        assert UNPUBLISHED_VALUE_CODE in [code for code, _why in renderer.declined]
        # The table and the feed read ``=`` alone and list nothing from it.
        assert not report.judge_indicators

    def test_an_in_list_of_values_the_rule_publishes_is_carried(self) -> None:
        pattern = f"[domain-name:value IN ('{OBSERVED}')]"
        judge = _judge(pattern)
        report = _report(judge)
        exported, _renderer = _export(report, judge)

        assert pattern in str(exported)
        assert _row(report, OBSERVED).published == "yes"

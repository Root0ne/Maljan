"""Tests for ``ExtendedSTIXRenderer``.

Verifies that the renderer adds the expected SDOs on top of a minimal judge
bundle, that the STIX patterns are well-formed, and that the bundle survives
a round-trip through ``Bundle.model_validate``.
"""

from __future__ import annotations

import re
from typing import Any

import pytest

from maljan.reporting.builder import MalwareReportBuilder
from maljan.reporting.models import MalwareReport
from maljan.reporting.renderers.stix_renderer import ExtendedSTIXRenderer
from maljan.schemas.stix_models import (
    Bundle,
    Identity,
    Indicator,
    Malware,
    Note,
    ObservedData,
    Report,
)


def _build(**kwargs: Any) -> MalwareReport:
    return MalwareReportBuilder(
        file_hash=kwargs.pop("file_hash", "c" * 64),
        file_name=kwargs.pop("file_name", "rat.exe"),
        sample_path=kwargs.pop("sample_path", None),
        sandbox_report=kwargs.pop("sandbox_report", {}),
        reports={},
        isr_reports={},
        stix_output={"objects": []},
        run_summary={},
        discussion_history=[],
        final_decision=kwargs.pop("final_decision", "Malware"),
        overall_confidence=kwargs.pop("overall_confidence", 0.8),
        cascade_summary=None,
        malware_category=kwargs.pop("malware_category", "rat"),
    ).build_deterministic()


def _types(bundle: Bundle) -> list[str]:
    return [getattr(obj, "type", "?") for obj in bundle.objects]


class TestEmptyBaseBundle:
    def test_identity_added(self) -> None:
        report = _build()
        bundle = ExtendedSTIXRenderer().render(report, base_bundle=None)
        assert any(isinstance(obj, Identity) for obj in bundle.objects)

    def test_report_sdo_added(self) -> None:
        report = _build()
        bundle = ExtendedSTIXRenderer().render(report, base_bundle=None)
        reports = [obj for obj in bundle.objects if isinstance(obj, Report)]
        assert len(reports) == 1
        assert reports[0].object_refs  # contains at least one object ref

    def test_indicator_for_sha256(self) -> None:
        report = _build()
        bundle = ExtendedSTIXRenderer().render(report, base_bundle=None)
        indicators = [obj for obj in bundle.objects if isinstance(obj, Indicator)]
        sha_pattern = re.compile(r"\[file:hashes\.'SHA-256' = '[a-f0-9]{64}'\]")
        assert any(sha_pattern.match(ind.pattern) for ind in indicators)


class TestNetworkIndicators:
    @pytest.fixture
    def report(self) -> MalwareReport:
        return _build(
            sandbox_report={
                "network": {
                    "dns": [{"request": "evil-c2.duckdns.org", "answers": []}],
                    "tcp": [{"dst": "8.8.8.8", "dport": 443}],
                    "http": [
                        {
                            "host": "evil-c2.duckdns.org",
                            "uri": "/beacon",
                            "method": "GET",
                        }
                    ],
                }
            }
        )

    def test_domain_indicator_pattern(self, report: MalwareReport) -> None:
        bundle = ExtendedSTIXRenderer().render(report, base_bundle=None)
        indicators = [obj for obj in bundle.objects if isinstance(obj, Indicator)]
        assert any("domain-name:value = 'evil-c2.duckdns.org'" in ind.pattern for ind in indicators)

    def test_ip_indicator_pattern(self, report: MalwareReport) -> None:
        bundle = ExtendedSTIXRenderer().render(report, base_bundle=None)
        indicators = [obj for obj in bundle.objects if isinstance(obj, Indicator)]
        assert any("ipv4-addr:value = '8.8.8.8'" in ind.pattern for ind in indicators)

    def test_url_indicator_pattern(self, report: MalwareReport) -> None:
        bundle = ExtendedSTIXRenderer().render(report, base_bundle=None)
        indicators = [obj for obj in bundle.objects if isinstance(obj, Indicator)]
        assert any("url:value = '" in ind.pattern for ind in indicators)


class TestBaseBundlePreserved:
    def test_existing_malware_kept(self) -> None:
        existing = Malware(name="pre-existing", malware_types=["trojan"])
        base = Bundle(objects=[existing])
        report = _build()
        bundle = ExtendedSTIXRenderer().render(report, base_bundle=base)
        names = [obj.name for obj in bundle.objects if isinstance(obj, Malware)]
        assert "pre-existing" in names


class TestObservedDataAndNote:
    @pytest.fixture
    def report(self) -> MalwareReport:
        report = _build(
            sandbox_report={
                "behavior": {
                    "processes": [
                        {
                            "name": "rat.exe",
                            "pid": 4242,
                            "ppid": 1,
                            "cmd": "rat.exe -beacon",
                        }
                    ],
                }
            }
        )
        return MalwareReportBuilder.apply_fallback_narrative(report)

    def test_observed_data_added(self, report: MalwareReport) -> None:
        bundle = ExtendedSTIXRenderer().render(report, base_bundle=None)
        assert any(isinstance(obj, ObservedData) for obj in bundle.objects)

    def test_note_carries_executive_summary(self, report: MalwareReport) -> None:
        bundle = ExtendedSTIXRenderer().render(report, base_bundle=None)
        notes = [obj for obj in bundle.objects if isinstance(obj, Note)]
        assert notes, "Note SDO missing"
        assert notes[0].content == report.executive_summary


class TestRoundTrip:
    def test_bundle_can_be_revalidated(self) -> None:
        report = _build()
        bundle = ExtendedSTIXRenderer().render(report, base_bundle=None)
        dumped = bundle.model_dump(mode="json")
        rebuilt = Bundle.model_validate(dumped)
        assert _types(rebuilt) == _types(bundle)


class TestTotalIndicatorCap:
    """Wave 9: cap total indicator count to MAX_TOTAL_INDICATORS with
    priority hashes > network > file:name."""

    def _packed_report(self) -> MalwareReport:
        from maljan.reporting.models import StaticAnalysis, StringIOC

        sandbox = {
            "network": {
                "dns": [{"request": f"d{i}.evil.test", "answers": []} for i in range(20)],
            }
        }
        report = _build(sandbox_report=sandbox)
        # Force a static block with 20 file:name candidates that pass
        # _accept_string_ioc (real-looking paths with known extensions).
        report.static = StaticAnalysis(
            interesting_strings=[
                StringIOC(value=f"/var/tmp/payload{i}.exe", kind="path", notes=None)
                for i in range(20)
            ]
        )
        return report

    def test_total_capped_to_15(self) -> None:
        from maljan.agents._indicator_denylists import MAX_TOTAL_INDICATORS

        report = self._packed_report()
        bundle = ExtendedSTIXRenderer().render(report, base_bundle=None)
        indicators = [obj for obj in bundle.objects if isinstance(obj, Indicator)]
        assert len(indicators) == MAX_TOTAL_INDICATORS == 15

    def test_priority_keeps_hash_and_network_first(self) -> None:
        report = self._packed_report()
        bundle = ExtendedSTIXRenderer().render(report, base_bundle=None)
        indicators = [obj for obj in bundle.objects if isinstance(obj, Indicator)]
        # sha256 hash MUST be kept (priority 0).
        assert any("file:hashes.'SHA-256'" in i.pattern for i in indicators)
        # At least one network indicator must survive.
        assert any("domain-name:value" in i.pattern for i in indicators)

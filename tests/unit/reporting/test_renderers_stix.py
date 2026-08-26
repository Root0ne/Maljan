"""Tests for ``ExtendedSTIXRenderer``.

Verifies that the renderer adds the expected SDOs on top of a minimal judge
bundle, that the STIX patterns are well-formed, and that the bundle survives
a round-trip through ``Bundle.model_validate``.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

import pytest

from maljan.reporting.builder import MalwareReportBuilder
from maljan.reporting.models import MalwareReport, StaticAnalysis, StringIOC
from maljan.reporting.renderers.stix_renderer import ExtendedSTIXRenderer
from maljan.schemas.stix_models import (
    AttackPattern,
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


class TestIndicatorTypes:
    def test_file_name_anomalous_hash_malicious(self) -> None:
        report = _build()
        if report.static is None:
            report.static = StaticAnalysis()
        report.static.interesting_strings = [
            StringIOC(kind="path", value="/data/local/tmp/payload.so")
        ]
        bundle = ExtendedSTIXRenderer().render(report, base_bundle=None)
        inds = [o for o in bundle.objects if isinstance(o, Indicator)]
        file_name = [i for i in inds if i.pattern.lstrip().startswith("[file:name")]
        hashes = [i for i in inds if "hashes" in i.pattern]
        assert file_name and file_name[0].indicator_types == ["anomalous-activity"]
        assert hashes and hashes[0].indicator_types == ["malicious-activity"]


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

    def test_judge_placeholder_timestamps_normalized(self) -> None:
        # Audit L7: the LLM copies STIX doc examples verbatim, stamping its
        # Malware/AttackPattern SDOs with the 2023-01-01 placeholder epoch and
        # a fake sequential id. The renderer must overwrite those bogus dates
        # with the real analysis time while leaving the id (and its relationship
        # refs) untouched.
        epoch = datetime(2023, 1, 1, tzinfo=UTC)
        stale_malware = Malware(
            id="malware--b2c3d4e5-f6a7-8901-bcde-f12345678901",
            name="Packed Dropper",
            malware_types=["dropper"],
            created=epoch,
            modified=epoch,
        )
        stale_ap = AttackPattern(
            id="attack-pattern--c3d4e5f6-a7b8-9012-cdef-123456789012",
            name="Process Injection",
            created=epoch,
            modified=epoch,
        )
        base = Bundle(objects=[stale_malware, stale_ap])
        bundle = ExtendedSTIXRenderer().render(_build(), base_bundle=base)

        for obj in bundle.objects:
            if isinstance(obj, Malware | AttackPattern):
                assert obj.created.year >= 2024, f"{obj.type} kept placeholder date"
                assert obj.modified >= obj.created
        # id (and therefore any relationship ref) is preserved verbatim
        malware_ids = [o.id for o in bundle.objects if isinstance(o, Malware)]
        assert "malware--b2c3d4e5-f6a7-8901-bcde-f12345678901" in malware_ids

    def test_judge_is_family_normalized_to_false(self) -> None:
        # Audit Bulgu #8: the LLM copies ``is_family: true`` from STIX docs, but
        # Maljan analyses a single specimen — the renderer must force it to False
        # so the SDO doesn't claim to represent a whole malware family.
        judge_malware = Malware(
            id="malware--b2c3d4e5-f6a7-8901-bcde-f12345678901",
            name="Packed Dropper",
            malware_types=["dropper"],
            is_family=True,
        )
        base = Bundle(objects=[judge_malware])
        bundle = ExtendedSTIXRenderer().render(_build(), base_bundle=base)
        malware_objs = [o for o in bundle.objects if isinstance(o, Malware)]
        assert malware_objs
        assert all(m.is_family is False for m in malware_objs)


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
                # Use a non-reserved TLD: ``.test`` is RFC 6761 reserved and is
                # now (correctly) dropped by the network extractor's IOC filter.
                "dns": [{"request": f"d{i}.evilc2.net", "answers": []} for i in range(20)],
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

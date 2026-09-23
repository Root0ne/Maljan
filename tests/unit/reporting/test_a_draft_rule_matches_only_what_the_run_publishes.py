"""A draft detection rule matches only on what the run publishes.

A signed benign tool got twenty Suricata alerts classed ``trojan-activity`` —
certificate-authority hosts, the vendor's home page, and a "C2 IP" rule for
``6.0.0.0`` — and a YARA branch of ``8 of them`` over common API names. The
drafts read every row the string sweep produced, published or not, and ran on
a Benign verdict. They are now drawn from the IOC table's published rows only,
and a Benign verdict, which publishes no malicious indicator, gets none; the
report says so. The version number that became an address is no longer read as
one.
"""

from __future__ import annotations

from typing import Any

import pytest
import yaml

from maljan.reporting.builder import build_consolidated_iocs
from maljan.reporting.detection_signatures import build_detection_rules
from maljan.reporting.models import (
    FileHashes,
    MalwareReport,
    NetworkDomain,
    NetworkIOCs,
    NetworkIP,
    NetworkURL,
    SampleIdentity,
    StaticAnalysis,
    StringIOC,
)
from maljan.reporting.renderers.markdown import MarkdownRenderer
from maljan.tools.strings import iter_string_iocs

OBSERVED = "gate9.example.org"
SWEPT = "crl.example-authority.org"
JUDGED = "relay4.example.net"


def _report(verdict: str = "Malware", **over: Any) -> MalwareReport:
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="c" * 64)),
        verdict=verdict,
        malware_category="loader",
        network=NetworkIOCs(
            domains=[
                NetworkDomain(fqdn=OBSERVED, source="sandbox"),
                NetworkDomain(fqdn=SWEPT, source="strings"),
            ],
            ips=[NetworkIP(address="185.99.133.7", source="strings")],
            urls=[NetworkURL(url=f"https://{SWEPT}/root.crl", source="strings")],
        ),
        static=StaticAnalysis(
            interesting_strings=[
                StringIOC(kind="mutex", value="ExampleMarkerSwept"),
            ],
        ),
        **over,
    )
    report.consolidated_iocs = build_consolidated_iocs(report)
    return report


def _rule(report: MalwareReport, kind: str) -> Any:
    return next((r for r in build_detection_rules(report) if r.kind == kind), None)


class TestABenignVerdict:
    def test_gets_no_draft(self) -> None:
        assert build_detection_rules(_report(verdict="Benign")) == []

    def test_the_report_says_why(self) -> None:
        text = MarkdownRenderer().render(_report(verdict="Benign"))

        assert "the verdict is Benign, and a Benign run publishes no malicious indicator" in text


class TestAMalwareVerdict:
    def test_suricata_alerts_on_a_published_name_only(self) -> None:
        body = _rule(_report(), "suricata").body

        assert OBSERVED in body
        assert SWEPT not in body
        assert "185.99.133.7" not in body

    def test_a_judge_value_the_rule_publishes_is_drafted(self) -> None:
        from maljan.reporting.models import DynamicBehavior, JudgeIndicator

        report = _report(
            judge_indicators=[JudgeIndicator(kind="path", value="C:\\ProgramData\\relay4.dat")],
            dynamic=DynamicBehavior(
                file_operations=[{"operation": "write", "path": "C:\\ProgramData\\relay4.dat"}]
            ),
        )

        assert "relay4.dat" in _rule(report, "yara").body

    def test_a_judge_value_the_rule_refuses_is_not_drafted(self) -> None:
        from maljan.reporting.models import JudgeIndicator

        report = _report(judge_indicators=[JudgeIndicator(kind="domain", value=JUDGED)])

        assert JUDGED not in _rule(report, "suricata").body
        assert JUDGED not in _rule(report, "yara").body

    def test_no_published_network_value_means_no_suricata(self) -> None:
        report = _report()
        report.network = NetworkIOCs(domains=[NetworkDomain(fqdn=SWEPT, source="strings")])
        report.consolidated_iocs = build_consolidated_iocs(report)

        assert _rule(report, "suricata") is None

    def test_yara_strings_are_published_rows_only(self) -> None:
        body = _rule(_report(), "yara").body

        assert "ExampleMarkerSwept" not in body
        assert SWEPT not in body
        assert OBSERVED in body


class TestSigma:
    """A Sigma selection is held to the same rule: published, or watched by a sandbox."""

    RUN_KEY = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"

    def _sigma(self, **over: Any) -> Any:
        return _rule(_report(**over), "sigma")

    def test_an_analyst_persistence_target_the_table_does_not_publish_makes_no_draft(
        self,
    ) -> None:
        from maljan.reporting.models import PersistenceMechanism

        mech = PersistenceMechanism(
            kind="registry_run", target=self.RUN_KEY, payload="C:\\Users\\Public\\example.exe"
        )

        assert self._sigma(persistence=[mech]) is None

    def test_a_key_the_sandbox_watched_is_selected(self) -> None:
        from maljan.reporting.models import DynamicBehavior, RegistryMod

        dynamic = DynamicBehavior(
            registry_mods=[
                RegistryMod(
                    hive="HKCU",
                    key=self.RUN_KEY,
                    value_name="example",
                    operation="create",
                )
            ]
        )

        rule = self._sigma(dynamic=dynamic)

        assert rule is not None and "CurrentVersion" in rule.body

    def test_a_key_the_sandbox_wrote_without_its_hive_in_the_key_is_selected(self) -> None:
        from maljan.reporting.models import DynamicBehavior, RegistryMod

        dynamic = DynamicBehavior(
            registry_mods=[
                RegistryMod(
                    hive="HKCU",
                    key="Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    value_name="example",
                    operation="create",
                )
            ]
        )

        rule = self._sigma(dynamic=dynamic)

        assert rule is not None
        assert (
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
            in yaml.safe_load(rule.body)["detection"]["selection_registry"]["TargetObject|contains"]
        )

    def test_every_admitted_key_is_selected(self) -> None:
        from maljan.reporting.models import DynamicBehavior, RegistryMod

        keys = [f"Software\\ExampleVendor\\Setting{i}" for i in range(30)]
        dynamic = DynamicBehavior(
            registry_mods=[RegistryMod(hive="HKLM", key=key, operation="modify") for key in keys]
        )

        rule = self._sigma(dynamic=dynamic)

        assert rule is not None
        selected = yaml.safe_load(rule.body)["detection"]["selection_registry"]
        assert selected["TargetObject|contains"] == [f"HKLM\\{key}" for key in keys]

    def test_an_analyst_s_long_hive_name_reads_as_the_sandbox_s_short_one(self) -> None:
        from maljan.reporting.models import DynamicBehavior, PersistenceMechanism, RegistryMod

        dynamic = DynamicBehavior(
            registry_mods=[
                RegistryMod(hive="HKCU", key="Software\\ExampleVendor\\Run", value_name="x")
            ]
        )
        mech = PersistenceMechanism(
            kind="registry_run", target="HKEY_CURRENT_USER\\Software\\ExampleVendor\\Run"
        )

        rule = self._sigma(dynamic=dynamic, persistence=[mech])

        assert rule is not None
        selected = yaml.safe_load(rule.body)["detection"]["selection_registry"]
        assert selected["TargetObject|contains"] == ["HKCU\\Software\\ExampleVendor\\Run"]

    @pytest.mark.parametrize(
        "written",
        [
            "HKCU\\Software\\ExampleVendor\\Run",
            "HKEY_CURRENT_USER\\Software\\ExampleVendor\\Run",
            "HKU\\S-1-5-21-1004\\Software\\ExampleVendor\\Run",
            "\\REGISTRY\\USER\\S-1-5-21-1004\\Software\\ExampleVendor\\Run",
            "Software\\ExampleVendor\\Run (ExampleValue)",
        ],
    )
    def test_every_spelling_of_a_key_reads_as_one(self, written: str) -> None:
        from maljan.reporting.detection_signatures import _registry_form

        assert _registry_form(written) == "software\\examplevendor\\run"

    def test_a_sandbox_signature_is_selected(self) -> None:
        from maljan.reporting.models import DynamicBehavior, SandboxSignature

        dynamic = DynamicBehavior(
            sandbox_signatures=[SandboxSignature(name="AutoRun", description="Installs autorun")]
        )

        rule = self._sigma(dynamic=dynamic)

        assert rule is not None and "Installs autorun" in rule.body


class TestTheReader:
    @pytest.mark.parametrize(
        "text",
        [
            b'<assemblyIdentity name="Example.Controls" version="6.0.0.0" type="win32"/>',
            b"FileVersion 10.0.19041.1",
            b"build v8.0.0.1 ready",
            b"ver: 7.1.2.3",
        ],
    )
    def test_a_version_number_is_not_an_address(self, text: bytes) -> None:
        found = [row for row in iter_string_iocs(b"\x00" + text + b"\x00") if row["kind"] == "ip"]

        assert found == []

    @pytest.mark.parametrize(
        ("text", "address"),
        [
            (b"server=185.23.44.10", "185.23.44.10"),
            (b"Server: 185.23.44.10", "185.23.44.10"),
            (b"c2server:91.200.10.4", "91.200.10.4"),
            (b"driver 185.23.44.10", "185.23.44.10"),
            (b"a_long_config_name_server=185.23.44.10", "185.23.44.10"),
            (b"x" * 60 + b"server=185.23.44.10", "185.23.44.10"),
            (b"an_example_setting_whose_name_ends_in_ver 185.23.44.10", "185.23.44.10"),
        ],
    )
    def test_a_word_that_ends_like_a_version_word_keeps_its_address(
        self, text: bytes, address: str
    ) -> None:
        found = [
            row["value"]
            for row in iter_string_iocs(b"\x00" + text + b"\x00")
            if row["kind"] == "ip"
        ]

        assert found == [address]

    def test_many_addresses_in_one_long_string_are_each_read(self) -> None:
        words = (b"ver", b"server")
        text = b" ".join(b"%s 185.%d.%d.7" % (words[i % 2], i // 200, i % 200) for i in range(2000))
        found = [
            row["value"]
            for row in iter_string_iocs(b"\x00" + text + b"\x00")
            if row["kind"] == "ip"
        ]

        expected = [f"185.{i // 200}.{i % 200}.7" for i in range(1, 2000, 2)]
        assert found and found == expected[: len(found)]

    def test_an_address_is_still_one(self) -> None:
        found = [
            row["value"]
            for row in iter_string_iocs(b"\x00connect to 185.99.133.7 now\x00")
            if row["kind"] == "ip"
        ]

        assert found == ["185.99.133.7"]

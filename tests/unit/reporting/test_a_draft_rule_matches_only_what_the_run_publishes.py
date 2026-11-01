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
            # The sample's process, staged under its digest, wrote the file.
            dynamic=DynamicBehavior(
                process_tree=[{"pid": 1, "name": f"{'c' * 64}.exe"}],
                file_operations=[
                    {"operation": "write", "path": "C:\\ProgramData\\relay4.dat", "pid": 1}
                ],
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


AGENT = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Tob 1.1)"


def _with_agent(report: MalwareReport, value: str = AGENT, *, published: bool = True) -> Any:
    from maljan.reporting.models import ConsolidatedIOC

    report.consolidated_iocs = [
        *report.consolidated_iocs,
        ConsolidatedIOC(
            type="User agent",
            kind="user_agent",
            value=value,
            source="call_argument",
            published=(
                "yes: the code passes it to InternetOpenW as argument 1"
                if published
                else "no: no call is shown to send it"
            ),
        ),
    ]
    return report


def _rule_lines(body: str) -> list[str]:
    return [line for line in body.splitlines() if line.startswith("alert")]


class TestAPublishedUserAgent:
    def test_gets_a_rule_on_the_request_header_after_the_other_rules(self) -> None:
        rule = _rule(_with_agent(_report()), "suricata")

        assert rule.compile_error is None
        *others, agent = _rule_lines(rule.body)
        assert others and all("http.user_agent" not in line for line in others)
        assert "flow:established,to_server; http.user_agent; content:" in agent
        # The header's parentheses, semicolons and commas are hex bytes, so
        # none of them ends the content or the rule.
        assert (
            'content:"Mozilla/4.0 |28|compatible|3B| MSIE 7.0|3B| Windows NT 5.1|3B| Tob 1.1|29|"'
            in agent
        )
        sids = [int(line.split("sid:")[1].split(";")[0]) for line in _rule_lines(rule.body)]
        assert sids == list(range(sids[0], sids[0] + len(sids)))
        assert f"user_agent:{AGENT}" in rule.source_evidence
        comment = rule.body.splitlines()[rule.body.splitlines().index(agent) - 1]
        assert comment == (
            f"# {AGENT}: published because the code passes it to InternetOpenW as argument 1"
        )

    def test_the_other_rules_keep_their_sids(self) -> None:
        before = _rule(_report(), "suricata").body
        after = _rule(_with_agent(_report()), "suricata").body

        assert _rule_lines(after)[: len(_rule_lines(before))] == _rule_lines(before)

    def test_alone_it_still_makes_a_draft(self) -> None:
        report = _report()
        report.network = NetworkIOCs()
        report.consolidated_iocs = build_consolidated_iocs(report)

        rule = _rule(_with_agent(report), "suricata")

        assert rule is not None and rule.compile_error is None
        assert len(_rule_lines(rule.body)) == 1 and "http.user_agent" in rule.body

    def test_an_unpublished_agent_gets_none(self) -> None:
        body = _rule(_with_agent(_report(), published=False), "suricata").body

        assert "http.user_agent" not in body

    def test_a_quote_or_a_line_break_cannot_end_the_rule(self) -> None:
        hostile = 'x"; sid:1; rev:1;)\nalert ip any any -> any any (msg:"y"\\'
        rule = _rule(_with_agent(_report(), hostile), "suricata")

        assert rule.compile_error is None
        (line,) = [line for line in _rule_lines(rule.body) if "http.user_agent" in line]
        # Two quoted strings, the message and the content, and one end.
        assert line.count('"') == 4 and line.count(";)") == 1
        content = line.split('content:"')[1].split('"')[0]
        assert not set(content) & set('";()\\\n')
        assert not [line for line in _rule_lines(rule.body) if 'msg:"y"' in line]

    def test_a_long_list_is_capped_and_says_so(self) -> None:
        from maljan.reporting.detection_signatures import _MAX_SURICATA_RULES, LEFT_OUT_COMMENT

        report = _report()
        for i in range(_MAX_SURICATA_RULES + 2):
            report = _with_agent(report, f"agent-{i}/1.0")

        body = _rule(report, "suricata").body

        assert body.count("http.user_agent") == _MAX_SURICATA_RULES
        assert "# " + LEFT_OUT_COMMENT.format(rest=2, what="user agents") in body

    def test_a_short_published_agent_is_matched_whole(self) -> None:
        """A published ``Mozilla/5.0`` matched anywhere in the header would
        alert on every browser; the rule matches the header that is exactly it."""
        rule = _rule(_with_agent(_report(), "Mozilla/5.0"), "suricata")

        (line,) = [line for line in _rule_lines(rule.body) if "http.user_agent" in line]
        assert 'http.user_agent; content:"Mozilla/5.0"; startswith; endswith; ' in line
        assert rule.compile_error is None

    def test_an_agent_is_drafted_trimmed_and_once(self) -> None:
        """A sensor's ``http.user_agent`` buffer is the header trimmed: an
        anchored content with a space at an edge matched no request."""
        report = _with_agent(_with_agent(_report(), " curl/7.81.0 "), "curl/7.81.0")

        rule = _rule(report, "suricata")

        (line,) = [line for line in _rule_lines(rule.body) if "http.user_agent" in line]
        assert 'http.user_agent; content:"curl/7.81.0"; startswith; endswith; ' in line
        assert rule.source_evidence[-1] == "user_agent:curl/7.81.0"
        assert rule.body.splitlines()[rule.body.splitlines().index(line) - 1].startswith(
            "#  curl/7.81.0 : published because"
        )
        assert rule.compile_error is None

    @pytest.mark.parametrize("value", ["   ", "\t\r\n", "A", "Mozilla", " Mozilla "])
    def test_a_blank_or_too_short_agent_gets_none(self, value: str) -> None:
        body = _rule(_with_agent(_report(), value), "suricata").body

        assert "http.user_agent" not in body

    @pytest.mark.parametrize(
        ("value", "bytes_written"),
        [
            ("Agent café/1.0", "Agent caf|C3||A9|/1.0"),
            ("Agent/1.0 \U0001f600", "Agent/1.0 |F0||9F||98||80|"),
            ("Agent\u2028tail/1.0", "Agent|E2||80||A8|tail/1.0"),
        ],
    )
    def test_a_character_beyond_ascii_is_written_as_its_utf8_bytes(
        self, value: str, bytes_written: str
    ) -> None:
        """A sensor compares bytes: the code point written as hex matched
        nothing, and one above U+00FF was not a byte a sensor reads."""
        rule = _rule(_with_agent(_report(), value), "suricata")

        (line,) = [line for line in _rule_lines(rule.body) if "http.user_agent" in line]
        assert f'content:"{bytes_written}"; startswith; endswith;' in line
        assert rule.compile_error is None

    def test_one_agent_longer_than_the_draft_is_left_out_whole_and_counted(self) -> None:
        rule = _rule(_with_agent(_report(), "Agent/" + "x" * 20_000), "suricata")

        assert "http.user_agent" not in rule.body
        assert "xxxx" not in rule.body
        assert rule.body.splitlines()[-1] == (
            "# (cut at the draft's size: 1 more indicators are not included; "
            "the report's IOC table carries every indicator)"
        )
        assert rule.compile_error is None


class TestTheSuricataSyntaxCheck:
    @pytest.mark.parametrize(
        "content",
        ["|E9 1|", "|2028|", "|1F600|", "open|41", "|GG|", "||"],
    )
    def test_a_content_group_that_is_not_hex_byte_pairs_is_refused(self, content: str) -> None:
        from maljan.reporting.detection_signatures import _validate_suricata

        line = (
            f'alert http any any -> any any (msg:"m"; http.user_agent; content:"{content}"; '
            "sid:1; rev:1;)"
        )

        assert _validate_suricata(line) is not None

    @pytest.mark.parametrize("content", ["plain", "a|41|b", "|C3 A9|", "|0D||0A|"])
    def test_hex_byte_pairs_pass(self, content: str) -> None:
        from maljan.reporting.detection_signatures import _validate_suricata

        line = (
            f'alert http any any -> any any (msg:"m"; http.user_agent; content:"{content}"; '
            "sid:1; rev:1;)"
        )

        assert _validate_suricata(line) is None

    def test_a_backslash_in_the_family_cannot_reach_a_message(self) -> None:
        from maljan.reporting.detection_signatures import (
            _suricata_dns_rule,
            _suricata_user_agent_rule,
            _validate_suricata,
        )
        from maljan.reporting.models import NetworkDomain

        family = 'Fam\\ily"; sid:2;\\'
        for line in (
            _suricata_dns_rule(NetworkDomain(fqdn="gate9.example.org"), 1, "c" * 64, family),
            _suricata_user_agent_rule(AGENT, 2, "c" * 64, family),
        ):
            assert line is not None
            msg = line.split('msg:"')[1].split('"')[0]
            assert "\\" not in msg and ";" not in msg
            assert _validate_suricata(line) is None


class TestSigma:
    """A Sigma selection is held to the same rule: published, or watched by a sandbox."""

    RUN_KEY = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"

    def _sigma(self, **over: Any) -> Any:
        return _rule(_report(**over), "sigma")

    def test_a_persistence_target_the_table_publishes_is_selected(self) -> None:
        # The run's persistence mechanisms are what its sandbox tools and the
        # Sigma rules over its events recorded (``persistence_from_ledger``),
        # never an analyst's table; the one rule publishes such a key, and the
        # table prints it so.
        from maljan.reporting.builder import build_consolidated_iocs
        from maljan.reporting.models import PersistenceMechanism

        mech = PersistenceMechanism(
            kind="registry_run", target=self.RUN_KEY, payload="C:\\Users\\Public\\example.exe"
        )
        (row,) = [
            r for r in build_consolidated_iocs(_report(persistence=[mech])) if r.kind == "registry"
        ]

        assert row.published == "yes: a persistence mechanism this run recorded"
        rule = self._sigma(persistence=[mech])
        assert rule is not None and "CurrentVersion" in rule.body

    def test_an_analyst_listed_key_the_table_does_not_publish_makes_no_draft(self) -> None:
        from maljan.reporting.models import ConsolidatedIOC

        report = _report()
        report.consolidated_iocs = [
            ConsolidatedIOC(
                type="Registry key",
                kind="registry",
                value=self.RUN_KEY,
                source="analyst",
                published="no: named only by an analyst",
            )
        ]

        assert _rule(report, "sigma") is None

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
            "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
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
        assert selected["TargetObject|contains"] == [f"\\{key}" for key in keys]

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
        assert selected["TargetObject|contains"] == ["\\Software\\ExampleVendor\\Run"]

    @pytest.mark.parametrize(
        "written",
        [
            "HKCU\\Software\\ExampleVendor\\Run",
            "HKEY_CURRENT_USER\\Software\\ExampleVendor\\Run",
            "HKU\\S-1-5-21-1004\\Software\\ExampleVendor\\Run",
            "\\REGISTRY\\USER\\S-1-5-21-1004\\Software\\ExampleVendor\\Run",
            "\\REGISTRY\\USER\\Software\\ExampleVendor\\Run",
            "HKCU\\HKEY_CURRENT_USER\\Software\\ExampleVendor\\Run",
            "Software\\ExampleVendor\\Run (ExampleValue)",
        ],
    )
    def test_every_spelling_of_a_key_reads_as_one(self, written: str) -> None:
        from maljan.reporting.detection_signatures import _registry_form

        assert _registry_form(written) == "software\\examplevendor\\run"

    @pytest.mark.parametrize(
        ("hive", "key"),
        [
            ("HKCU", "HKEY_CURRENT_USER\\Software\\ExampleVendor\\Run"),
            ("HKLM", "\\REGISTRY\\MACHINE\\SOFTWARE\\ExampleVendor\\Run"),
            ("HKU", "\\REGISTRY\\USER\\S-1-5-21-1004\\Software\\ExampleVendor\\Run"),
            ("HKLM", "HKLM\\SOFTWARE\\ExampleVendor\\Run"),
            ("HKCU", "Software\\ExampleVendor\\Run"),
        ],
    )
    def test_a_key_the_sandbox_wrote_in_any_hive_form_is_selected_without_it(
        self, hive: str, key: str
    ) -> None:
        from maljan.reporting.models import DynamicBehavior, RegistryMod

        dynamic = DynamicBehavior(
            registry_mods=[RegistryMod(hive=hive, key=key, value_name="x", operation="create")]
        )

        rule = self._sigma(dynamic=dynamic)

        assert rule is not None
        (selected,) = yaml.safe_load(rule.body)["detection"]["selection_registry"][
            "TargetObject|contains"
        ]
        assert selected.lower() == "\\software\\examplevendor\\run"

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

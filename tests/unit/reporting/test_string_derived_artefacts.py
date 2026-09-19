"""Every indicator the platform mints from a string row asks the one publish rule.

The rule covered the three network kinds. Everything else the string sweep
produces — an e-mail address, a file name, a registry key, a mutex — reached
the bundle with no question asked: a signed PuTTY that the run concluded is
Benign exported ten SSH algorithm identifiers as ``malicious-activity``
e-mail indicators, and a PE run exported a third party's address lifted out of
embedded library source beside a fragment of Python that happens to have an
``@`` in it.

The rows below are the recorded runs', trimmed, with the one real address
replaced by a made-up one at ``example.org``.
"""

from __future__ import annotations

from typing import Any

from maljan.reporting.models import (
    DynamicBehavior,
    EvidenceSection,
    FileHashes,
    MalwareReport,
    NetworkDomain,
    NetworkIOCs,
    ProcessNode,
    SampleIdentity,
    StaticAnalysis,
    StringIOC,
)
from maljan.reporting.renderers.stix_renderer import (
    ExtendedSTIXRenderer,
    email_is_publishable,
    minted_indicator_type,
    path_names_a_file,
)

# What PuTTY's string sweep typed as e-mail addresses. Ten of the eleven
# indicators the recorded Benign run exported.
PUTTY_ALGORITHMS = (
    "aes128-gcm@openssh.com",
    "aes256-gcm@openssh.com",
    "hmac-sha1-etm@openssh.com",
    "hmac-sha2-256-etm@openssh.com",
    "auth-agent-req@openssh.com",
    "SSHCONNECTION@putty.projects.tartarus.org",
)

# What sample A's sweep typed as e-mail addresses. The third value is a parse
# artefact out of embedded CPython source; the second stands in for the real
# third party's address the recorded run published.
SAMPLE_A_ADDRESSES = ("ping@lfw.org", "maintainer@example.org", "z@D.setdefault")


def _report(verdict: str, *iocs: StringIOC, **kwargs: Any) -> MalwareReport:
    return MalwareReport(
        verdict=verdict,  # type: ignore[arg-type]
        identity=SampleIdentity(hashes=FileHashes(sha256="d" * 64), file_name="sample.bin"),
        static=StaticAnalysis(interesting_strings=list(iocs)),
        executive_summary="",
        **kwargs,
    )


def _patterns(report: MalwareReport) -> list[str]:
    bundle = ExtendedSTIXRenderer().render(report)
    return [
        str(getattr(obj, "pattern", ""))
        for obj in bundle.objects
        if getattr(obj, "type", "") == "indicator"
    ]


class TestTheRecordedRunsExportNoAddress:
    def test_putty_s_algorithm_identifiers_are_not_indicators(self) -> None:
        report = _report("Benign", *(StringIOC(kind="email", value=v) for v in PUTTY_ALGORITHMS))

        assert not [p for p in _patterns(report) if "email-addr" in p]

    def test_sample_a_exports_none_of_the_three(self) -> None:
        report = _report("Malware", *(StringIOC(kind="email", value=v) for v in SAMPLE_A_ADDRESSES))

        patterns = _patterns(report)
        for value in SAMPLE_A_ADDRESSES:
            assert not [p for p in patterns if value in p], value

    def test_a_person_s_address_stays_in_the_report_s_own_table(self) -> None:
        """Withheld from the export, not deleted from the run's own record."""
        report = _report("Malware", StringIOC(kind="email", value="maintainer@example.org"))

        assert [ioc.value for ioc in report.static.interesting_strings] == [
            "maintainer@example.org"
        ]


class TestWhatASecondSourceLooksLike:
    def test_a_mutex_the_sandbox_watched_is_published(self) -> None:
        report = _report(
            "Malware",
            StringIOC(kind="mutex", value="Global\\ZararliMutex"),
            dynamic=DynamicBehavior(
                process_tree=[
                    ProcessNode(
                        pid=1,
                        name="sample.bin",
                        command_line="sample.bin --mutex Global\\ZararliMutex",
                    )
                ]
            ),
        )

        assert any("mutex:name = 'Global\\\\ZararliMutex'" in p for p in _patterns(report))

    def test_an_address_an_analyst_established_is_published(self) -> None:
        report = _report(
            "Malware",
            StringIOC(kind="email", value="operator@example.org"),
            sections=[
                EvidenceSection(
                    key="findings",
                    title="Findings",
                    kind="table",
                    columns=["Agent", "Finding"],
                    rows=[["static", "the drop mail is operator@example.org"]],
                    evidence_ids=["ev_0007"],
                    source="finding",
                )
            ],
        )

        assert any("email-addr:value = 'operator@example.org'" in p for p in _patterns(report))

    def test_a_tool_s_own_section_corroborates_nothing(self) -> None:
        """The string table arriving under another heading is not a second source."""
        report = _report(
            "Malware",
            StringIOC(kind="email", value="operator@example.org"),
            sections=[
                EvidenceSection(
                    key="tool_strings",
                    title="Printable strings",
                    kind="list",
                    items=["operator@example.org"],
                    evidence_ids=["ev_0003"],
                    source="tool",
                )
            ],
        )

        assert not [p for p in _patterns(report) if "email-addr" in p]


class TestTheValidityQuestions:
    def test_a_parse_artefact_is_not_an_address(self) -> None:
        assert email_is_publishable("z@") is False
        assert email_is_publishable("no-at-sign") is False
        assert email_is_publishable("a@b") is False
        assert email_is_publishable("a@localhost") is False
        assert email_is_publishable(".lead@example.org") is False

    def test_a_real_mailbox_is_one(self) -> None:
        assert email_is_publishable("operator@example.org") is True

    def test_a_directory_names_no_file(self) -> None:
        for value in ("/Users/", "C:\\", "C:", "/", "", "   "):
            assert path_names_a_file(value) is False, value

    def test_a_file_does(self) -> None:
        assert path_names_a_file("/tmp/dropper.so") is True
        assert path_names_a_file("C:\\Windows\\Temp\\a.exe") is True


class TestWhatAMintedIndicatorClaims:
    def test_nothing_is_malicious_by_default(self) -> None:
        for verdict in ("Malware", "Suspicious", "Benign", ""):
            assert minted_indicator_type(verdict) == "anomalous-activity", verdict

    def test_only_a_flagged_row_under_a_malware_verdict_is(self) -> None:
        assert minted_indicator_type("Malware", suspicious=True) == "malicious-activity"
        assert minted_indicator_type("Benign", suspicious=True) == "anomalous-activity"
        assert minted_indicator_type("Suspicious", suspicious=True) == "anomalous-activity"

    def test_a_corroborated_string_row_under_each_verdict(self) -> None:
        for verdict in ("Malware", "Suspicious", "Benign"):
            report = _report(
                verdict,
                StringIOC(kind="mutex", value="Global\\Zararli"),
                dynamic=DynamicBehavior(
                    process_tree=[ProcessNode(pid=1, name="x", command_line="Global\\Zararli")]
                ),
            )
            bundle = ExtendedSTIXRenderer().render(report)
            minted = next(
                obj
                for obj in bundle.objects
                if getattr(obj, "type", "") == "indicator" and "mutex" in obj.pattern
            )
            assert minted.indicator_types == ["anomalous-activity"], verdict


class TestThePrivacyPathsAreAllChecked:
    def test_the_iocs_feed_carries_no_address(self) -> None:
        """``/reports/{id}/iocs`` reads the network block and the hashes only."""
        import inspect

        from app.services.report_service import ReportService

        source = inspect.getsource(ReportService.get_malware_report_iocs)
        assert "interesting_strings" not in source
        assert "email" not in source

    def test_the_enrichment_looks_up_no_address(self) -> None:
        import inspect

        from maljan.enrichment import orchestrator

        source = inspect.getsource(orchestrator)
        assert "interesting_strings" not in source

    def test_no_event_carries_an_uncorroborated_address(self) -> None:
        """A string row is declined silently; only an observation is worth a row."""
        report = _report("Malware", StringIOC(kind="email", value="maintainer@example.org"))
        renderer = ExtendedSTIXRenderer()

        renderer.render(report)

        assert renderer.declined == []


class TestTheNetworkBlockIsUnchanged:
    def test_an_observed_domain_is_still_published(self) -> None:
        report = _report(
            "Malware",
            network=NetworkIOCs(
                domains=[NetworkDomain(fqdn="c2.example.com", source="sandbox", is_suspicious=True)]
            ),
        )

        assert any("domain-name:value = 'c2.example.com'" in p for p in _patterns(report))

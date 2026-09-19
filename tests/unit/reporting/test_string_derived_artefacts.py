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
    indicator_publish_reason,
    minted_indicator_type,
    path_names_a_file,
    reads_as_a_host_in_the_bytes,
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

# What sample A's sweep typed as e-mail addresses. Both mailboxes the recorded
# run published belonged to real people whose addresses were in embedded
# library source, so both are stood in for by made-up ones at ``example.org``;
# the third value is a fragment of Python and is written as it was read,
# because being a parse artefact is the whole point of it.
SAMPLE_A_ADDRESSES = ("pinger@example.org", "maintainer@example.org", "z@D.setdefault")


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

    def test_an_analyst_citing_a_tool_that_saw_it_is_a_second_source(self) -> None:
        report = _report(
            "Malware",
            StringIOC(kind="email", value="operator@example.org"),
            sections=[
                EvidenceSection(
                    key="tool_sandbox_network",
                    title="Sandbox channels",
                    kind="list",
                    items=["SMTP RCPT TO: operator@example.org"],
                    evidence_ids=["ev_0007"],
                    source="tool:sandbox_network",
                ),
                EvidenceSection(
                    key="findings",
                    title="Findings",
                    kind="table",
                    columns=["Agent", "Finding"],
                    rows=[["static", "the drop mail is the one the sandbox saw"]],
                    evidence_ids=["ev_0007"],
                    source="finding",
                ),
            ],
        )

        assert any("email-addr:value = 'operator@example.org'" in p for p in _patterns(report))

    def test_an_analyst_quoting_the_string_sweep_is_not(self) -> None:
        """One source said twice is one source."""
        report = _report(
            "Malware",
            StringIOC(kind="email", value="operator@example.org"),
            sections=[
                EvidenceSection(
                    key="iocs",
                    title="Indicators recovered from the sample",
                    kind="table",
                    columns=["Kind", "Value"],
                    rows=[["email", "operator@example.org"]],
                    evidence_ids=["ev_0003"],
                    source="tool:iocs_from_file",
                ),
                EvidenceSection(
                    key="findings",
                    title="Findings",
                    kind="table",
                    columns=["Agent", "Finding"],
                    rows=[["static", "the strings table lists operator@example.org"]],
                    evidence_ids=["ev_0003"],
                    source="finding",
                ),
            ],
        )

        assert not [p for p in _patterns(report) if "email-addr" in p]

    def test_a_tool_no_analyst_cited_corroborates_nothing(self) -> None:
        """A claim is a second source when it points at the entry that saw it."""
        report = _report(
            "Malware",
            StringIOC(kind="email", value="operator@example.org"),
            sections=[
                EvidenceSection(
                    key="tool_sandbox_network",
                    title="Sandbox channels",
                    kind="list",
                    items=["SMTP RCPT TO: operator@example.org"],
                    evidence_ids=["ev_0007"],
                    source="tool:sandbox_network",
                )
            ],
        )

        assert not [p for p in _patterns(report) if "email-addr" in p]

    def test_a_slice_of_a_longer_value_does_not_corroborate(self) -> None:
        """Containment is a whole value, the way a digest already was."""
        report = _report(
            "Malware",
            StringIOC(kind="mutex", value="Zararli"),
            dynamic=DynamicBehavior(
                process_tree=[
                    ProcessNode(pid=1, name="x", command_line="--mutex Global\\ZararliMutex")
                ]
            ),
        )

        assert not [p for p in _patterns(report) if "mutex" in p]


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


class TestANameLiftedOutOfTheBytes:
    """The host rule's last-label test is a shape, and code is shaped like one.

    ``setdefault`` matches ``^[a-z]{2,}$`` as squarely as ``com`` does, so
    ``z@D.setdefault`` passed every validity question the export had and was
    held back by corroboration alone. Capitalisation is the tell a byte image
    carries and a model's prose does not: an attribute access capitalises the
    thing it reaches into, and nothing capitalises a host name.
    """

    def test_a_python_attribute_chain_is_not_a_host(self) -> None:
        assert reads_as_a_host_in_the_bytes("D.setdefault") is False
        assert reads_as_a_host_in_the_bytes("r.Regsvr") is False

    def test_a_real_name_is(self) -> None:
        for name in ("openssh.com", "putty.projects.tartarus.org", "xn--80ak6aa92e.com"):
            assert reads_as_a_host_in_the_bytes(name) is True, name

    def test_a_single_label_is_not(self) -> None:
        assert reads_as_a_host_in_the_bytes("localhost") is False

    def test_the_two_recorded_artefacts_are_refused_on_validity_alone(self) -> None:
        for value in ("z@D.setdefault", "ExcelS@r.Regsvr"):
            assert (
                indicator_publish_reason(
                    "email", value, "strings", corroborated_by="the sandbox watched it"
                )
                is None
            ), value

    def test_an_observed_address_is_not_asked_about_its_case(self) -> None:
        """A model or a sandbox writing ``Example.COM`` has written a host."""
        assert indicator_publish_reason("email", "Bob@Example.COM", "sandbox") == "sandbox"
        assert email_is_publishable("Bob@Example.COM") is True

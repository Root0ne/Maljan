"""Text in a tool's answer is no sandbox observation, and a TLS name alone is no attributed one.

A value an analyst listed and a sandbox tool's *text* held — a signature's
description, a command line, the sample's own strings the sandbox re-serves —
was made a sandbox row, so a listed domain published as though the sample had
resolved it and a listed address read a flow reason with no flow behind it.
Only a structured sandbox network record (a flow, a DNS query, an HTTP request,
a capture conversation) makes a sandbox row; a text sighting gives the string
standing and names the entry. A name only the capture's TLS list recorded says
nothing about which process made the connection, and waits for the judge. A
lookup's answer that repeats the value it was asked about is no sighting of it.
Values are keyed one way on both sides, so an address written with brackets or
in capitals is still found.

Every value here is synthetic: routable addresses the reference run never
reached, and example names.
"""

from __future__ import annotations

from typing import Any

from maljan.reporting.builder import MalwareReportBuilder
from maljan.reporting.models import (
    EvidenceSection,
    FileHashes,
    JudgeIndicator,
    MalwareReport,
    NetworkDomain,
    NetworkIOCs,
    NetworkIP,
    SampleIdentity,
)
from maljan.reporting.renderers.stix_renderer import (
    CAPTURE_TLS_NAME,
    emulation_kwargs,
    publish_answer,
)
from maljan.schemas.evidence import LedgerEntry
from maljan.schemas.isr_models import AgentISR, Artifact

NAME = "relay-alpha-7f3c.top"
ADDRESS = "185.199.110.77"
V6 = "2a00:1450:4001:82b::2011"


def _entry(entry_id: str, tool: str, structured: dict[str, Any], **args: Any) -> LedgerEntry:
    return LedgerEntry(id=entry_id, agent="dynamic", tool=tool, structured=structured, args=args)


def _listed(*rows: list[str]) -> dict[str, Any]:
    return {
        "network": AgentISR(
            agent_id="network",
            domain="network",
            artifacts=[
                Artifact(kind="endpoints", rows=list(rows), evidence_ids=[], source="network")
            ],
        )
    }


def _build(ledger: list[LedgerEntry], isrs: dict[str, Any] | None = None, **extra: Any) -> Any:
    return MalwareReportBuilder(
        file_hash="a" * 64,
        file_name="fixture.bin",
        sample_path=None,
        sandbox_report={},
        reports={},
        isr_reports=isrs or {},
        stix_output=extra.get("stix_output") or {"objects": []},
        run_summary={},
        discussion_history=[],
        final_decision="Malware",
        overall_confidence=0.8,
        sample_platform="windows",
        sample_file_type="PE",
        evidence_ledger=ledger,
    ).build_deterministic()


def _row(report: MalwareReport, value: str) -> Any:
    (row,) = [r for r in report.consolidated_iocs if r.value == value]
    return row


_TEXT_SIGHTINGS = {
    "a signature's description": _entry(
        "ev_0003",
        "sandbox_signatures",
        {"signatures": [{"name": "x", "description": f"binary contains {NAME} and {ADDRESS}"}]},
    ),
    "a command line": _entry(
        "ev_0003",
        "sandbox_processes",
        {
            "processes": [
                {
                    "processes": [
                        {
                            "pid": 4,
                            "name": "a.exe",
                            "command_line": f"a.exe --host {NAME} {ADDRESS}",
                        }
                    ]
                },
            ]
        },
    ),
    "the sample's strings the sandbox re-serves": _entry(
        "ev_0003",
        "sandbox_report_section",
        {"section": "static", "value": {"strings": [NAME, ADDRESS]}},
    ),
}


class TestATextSightingInASandboxAnswer:
    def test_it_gives_string_standing_and_names_the_entry(self) -> None:
        for what, entry in _TEXT_SIGHTINGS.items():
            report = _build([entry], _listed(["domain", NAME], ["ip", ADDRESS]))
            assert report.network is not None
            for row in [*report.network.domains, *report.network.ips]:
                assert row.source == "strings", what
            tool = entry.tool
            for value in (NAME, ADDRESS):
                answer = _row(report, value).published
                assert answer.startswith(f"no: seen only in the text of ev_0003 ({tool})"), what
                assert "flows to it" not in answer, what


class TestACaptureOnlyName:
    @staticmethod
    def _capture(**more: Any) -> LedgerEntry:
        return _entry("ev_0001", "pcap_summary", {"conversations": [], "sni": {NAME: 3}, **more})

    def test_it_waits_for_the_judge(self) -> None:
        report = _build([self._capture()])

        assert report.network is not None
        (domain,) = report.network.domains
        assert (domain.source, domain.capture_only) == ("sandbox", True)
        assert _row(report, NAME).published == (
            f"no: {CAPTURE_TLS_NAME}, and no model kept it as an indicator"
        )

    def test_the_judge_keeping_it_publishes_it(self) -> None:
        judge = {
            "objects": [
                {
                    "type": "indicator",
                    "id": "indicator--0f1e2d3c-4b5a-4968-8776-655443332211",
                    "pattern": f"[domain-name:value = '{NAME}']",
                    "pattern_type": "stix",
                    "indicator_types": ["malicious-activity"],
                    "valid_from": "2026-01-01T00:00:00Z",
                }
            ]
        }
        report = _build([self._capture()], stix_output=judge)

        assert _row(report, NAME).published == "yes"

    def test_a_name_the_sandbox_also_resolved_keeps_the_name_rule(self) -> None:
        dns = _entry("ev_0002", "sandbox_network", {"dns": [{"request": NAME}]})
        report = _build([self._capture(), dns])

        assert report.network is not None
        assert report.network.domains[0].capture_only is False
        assert _row(report, NAME).published == "yes"


class TestAnAnswerToAQueryForTheValue:
    """Not a sighting of it, and not nothing: the reason says only a query's answer holds it."""

    def test_a_lookup_echo_is_named_as_the_answer_to_a_query(self) -> None:
        lookup = _entry(
            "ev_0004", "get_domain_report", {"domain": NAME, "detections": 0}, domain=NAME
        )
        report = _build([lookup], _listed(["domain", NAME]))

        assert report.tool_sightings == {NAME: []}
        assert report.tool_queries == {NAME: [("ev_0004", "get_domain_report")]}
        answer = _row(report, NAME).published
        assert answer == (
            "no: named only by an analyst (an artifact of the network analyst); only the "
            "answer to a query for it holds it (ev_0004 get_domain_report), and the judge "
            "did not keep it as an indicator"
        )

    def test_a_search_that_returns_the_match_from_the_file_is_named_too(self) -> None:
        search = _entry(
            "ev_0005",
            "search_strings",
            {"matches": [{"offset": "0x4010", "string": NAME}]},
            query=NAME,
        )
        answer = _row(_build([search], _listed(["domain", NAME])), NAME).published

        assert "only the answer to a query for it holds it (ev_0005 search_strings)" in answer
        assert "no tool in this run saw it" not in answer


class TestOneKeyOnBothSides:
    def test_a_bracketed_capitalised_address_is_found_where_a_tool_wrote_it(self) -> None:
        decompile = _entry("ev_0002", "decompile_function", {"code": f'connect("{V6}")'})
        report = _build([decompile], _listed(["ipv6", f"[{V6.upper()}]:443"]))

        assert report.network is not None
        (ip,) = report.network.ips
        assert (ip.address, ip.source) == (V6, "strings")
        assert _row(report, V6).published.startswith(
            "no: seen only in the text of ev_0002 (decompile_function)"
        )


class TestAStoredReportsCaptureHeldValue:
    """A report stored before the search: answered as a fresh build answers it."""

    def test_an_address_the_kept_capture_section_holds_reads_the_capture_s_reason(self) -> None:
        report = MalwareReport(
            identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
            verdict="Malware",
            overall_confidence=0.8,
            network=NetworkIOCs(
                ips=[
                    NetworkIP(
                        address=ADDRESS,
                        source="analyst",
                        kept_by=["an artifact of the network analyst"],
                    )
                ]
            ),
            sections=[
                EvidenceSection(
                    key="pcap_summary",
                    title="Capture",
                    kind="table",
                    columns=["dst", "dport"],
                    rows=[[ADDRESS, "443"]],
                    evidence_ids=["ev_0017"],
                    source="tool:pcap_summary",
                )
            ],
        )

        answer = publish_answer(
            "ip", ADDRESS, "analyst", None, **emulation_kwargs(report, "ip", ADDRESS)
        )

        assert answer.startswith(
            "no: the sandbox report does not say which process made the flows to it; "
            "an artifact of the network analyst lists it"
        )

    def test_the_judge_named_capture_value_publishes_in_both(self) -> None:
        report = MalwareReport(
            identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
            verdict="Malware",
            overall_confidence=0.8,
            network=NetworkIOCs(domains=[NetworkDomain(fqdn=NAME, source="analyst")]),
            judge_indicators=[JudgeIndicator(kind="domain", value=NAME)],
            sections=[
                EvidenceSection(
                    key="pcap_summary",
                    title="Capture",
                    kind="kv",
                    rows=[["sni", NAME]],
                    evidence_ids=["ev_0017"],
                    source="tool:pcap_summary",
                )
            ],
        )

        answer = publish_answer(
            "domain", NAME, "analyst", None, **emulation_kwargs(report, "domain", NAME)
        )

        assert answer == "yes"

"""A sandbox network row is the sample's observation when the sample's process tree made it.

A detonation guest talks to the internet whatever the sample does: its DNS
service asks a public resolver, its connectivity checks reach whoever answers
them. One live run published two such addresses as the sample's C2 and drafted
YARA and Suricata rules over them. Each flow now carries the process that made
it and whether that process is in the sample's tree — a platform fact, right or
absent — and a row the tree did not make is published only when a model kept it
as an indicator; otherwise the table carries it with the reason.

The normaliser's tests use documentation addresses. The publish rule's use one
routable address that is not the reference run's, because a documentation
address is refused by the address rule before attribution is asked, and the
resolver list's own entry that the reference run did not reach.
"""

from __future__ import annotations

import json
from typing import Any

from maljan.providers.sandbox_tools import sandbox_network
from maljan.reporting.ledger_projection import network_from_ledger
from maljan.reporting.models import JudgeIndicator, MalwareReport, NetworkDomain, NetworkIOCs
from maljan.reporting.renderers.stix_renderer import emulation_kwargs, publish_answer
from maljan.schemas.evidence import build_entry
from maljan.schemas.isr_models import AgentISR, Artifact, ClaimEvidence
from maljan.schemas.sandbox_report import triage_overview_to_sandbox_report

DOC = "198.51.100.23"
CONTACT = "185.199.108.153"
RESOLVER = "9.9.9.9"


def _triage(
    processes: list[dict[str, Any]], flows: list[dict[str, Any]], target: str = "invoice.exe"
) -> Any:
    overview = {"sample": {"id": "t1", "target": target, "sha256": "a" * 64}}
    task = {"processes": processes, "network": {"flows": flows}}
    return triage_overview_to_sandbox_report(overview, task_reports={"behavioral1": task})


_PROCESSES = [
    {"procid": 10, "procid_parent": 0, "image": "C:\\Users\\a\\invoice.exe", "cmd": "invoice.exe"},
    {"procid": 11, "procid_parent": 10, "image": "cmd.exe", "cmd": "cmd.exe /c whoami"},
    {"procid": 20, "procid_parent": 0, "image": "svchost.exe", "cmd": "svchost.exe -k netsvcs"},
]


class TestTheNormalisedFlowSaysWhichProcessMadeIt:
    def test_the_sample_and_its_children_are_its_tree(self) -> None:
        report = _triage(_PROCESSES, [{"proto": "tcp", "dst": f"{DOC}:443", "procid": 11}])

        assert report.network.tcp[0]["sample_process_tree"] is True
        assert report.network.tcp[0]["procid"] == 11

    def test_a_named_process_outside_the_tree_is_not(self) -> None:
        report = _triage(_PROCESSES, [{"proto": "udp", "dst": f"{DOC}:53", "procid": 20}])

        assert report.network.udp[0]["sample_process_tree"] is False

    def test_a_flow_the_report_does_not_attribute_says_nothing(self) -> None:
        report = _triage(
            _PROCESSES,
            [
                {"proto": "tcp", "dst": f"{DOC}:80"},
                {"proto": "tcp", "dst": f"{DOC}:81", "procid": 99},
            ],
        )

        assert all("sample_process_tree" not in row for row in report.network.tcp)

    def test_no_sample_process_leaves_every_flow_unattributed(self) -> None:
        report = _triage(_PROCESSES[2:], [{"proto": "tcp", "dst": f"{DOC}:443", "procid": 20}])

        assert "sample_process_tree" not in report.network.tcp[0]

    def test_triage_s_own_mark_is_the_only_answer_when_it_gave_one(self) -> None:
        processes = [
            {"procid": 5, "procid_parent": 0, "image": "x.exe", "orig": True},
            # Named like the submission, and not the process Triage marked.
            {"procid": 6, "procid_parent": 0, "image": "invoice.exe", "cmd": "invoice.exe"},
        ]
        report = _triage(
            processes,
            [
                {"proto": "tcp", "dst": f"{DOC}:443", "procid": 5},
                {"proto": "tcp", "dst": f"{DOC}:444", "procid": 6},
            ],
        )

        assert [row["sample_process_tree"] for row in report.network.tcp] == [True, False]

    def test_a_name_that_only_contains_the_submitted_name_is_not_the_sample(self) -> None:
        processes = [
            {
                "procid": 30,
                "procid_parent": 0,
                "image": "C:\\Program Files\\MicrosoftEdgeUpdate.exe",
            },
            {"procid": 31, "procid_parent": 0, "image": "C:\\Users\\a\\update.exe"},
        ]
        report = _triage(
            processes,
            [
                {"proto": "tcp", "dst": f"{DOC}:443", "procid": 30},
                {"proto": "tcp", "dst": f"{DOC}:444", "procid": 31},
            ],
            target="update.exe",
        )

        assert [row["sample_process_tree"] for row in report.network.tcp] == [False, True]

    def test_the_staged_copy_named_by_its_digest_is_the_sample(self) -> None:
        processes = [
            {
                "procid": 40,
                "procid_parent": 0,
                "image": "C:\\Windows\\system32\\rundll32.exe",
                "cmd": f"rundll32.exe C:\\Temp\\{'a' * 64}.dll,#1",
            }
        ]
        report = _triage(processes, [{"proto": "tcp", "dst": f"{DOC}:443", "procid": 40}])

        assert report.network.tcp[0]["sample_process_tree"] is True


class TestTheViewStatesTheResolver:
    def test_a_public_resolver_row_is_marked(self) -> None:
        view = sandbox_network(
            {"network": {"udp": [{"dst": RESOLVER, "dport": 53}], "tcp": [{"dst": DOC}]}}
        )

        assert view["udp"][0]["public_resolver"] is True
        assert "public_resolver" not in view["tcp"][0]


def _ledger(**view: Any) -> list[Any]:
    return [
        build_entry(
            entry_id="ev_0001",
            seq=1,
            agent="dynamic",
            tool="sandbox_network",
            args={},
            server=None,
            output=json.dumps(view),
        )
    ]


def _report(network: NetworkIOCs | None, **extra: Any) -> MalwareReport:
    return MalwareReport.model_validate(
        {
            "identity": {"hashes": {"sha256": "a" * 64}},
            "verdict": "Malware",
            "overall_confidence": 0.9,
            "network": network.model_dump() if network else None,
            **extra,
        }
    )


def _answer(report: MalwareReport, kind: str, value: str, source: str = "sandbox") -> str:
    return publish_answer(kind, value, source, None, **emulation_kwargs(report, kind, value))


def _network_analyst(claim: str = "", artifact_rows: list[list[str]] | None = None) -> Any:
    return {
        "network": AgentISR(
            agent_id="network",
            domain="network",
            claims=[ClaimEvidence(claim=claim, evidence_ref="ev_0001", confidence=0.7)]
            if claim
            else [],
            artifacts=[Artifact(kind="endpoints", rows=artifact_rows, evidence_ids=[])]
            if artifact_rows
            else [],
        )
    }


class TestThePublishRule:
    def test_an_unattributed_contact_is_carried_with_the_reason(self) -> None:
        network = network_from_ledger(_ledger(tcp=[{"dst": CONTACT, "dport": 80}]))

        answer = _answer(_report(network), "ip", CONTACT)

        assert answer == (
            "no: the sandbox report does not say which process made the flows to it, "
            "and no model kept it as an indicator"
        )

    def test_a_flow_of_the_tree_is_published(self) -> None:
        network = network_from_ledger(
            _ledger(tcp=[{"dst": CONTACT, "dport": 80, "sample_process_tree": True}])
        )

        assert _answer(_report(network), "ip", CONTACT) == "yes"

    def test_the_resolver_fact_is_in_the_reason(self) -> None:
        network = network_from_ledger(
            _ledger(udp=[{"dst": RESOLVER, "dport": 53, "sample_process_tree": False}])
        )
        assert network is not None and network.ips[0].public_resolver is True

        answer = _answer(_report(network), "ip", RESOLVER)

        assert answer.startswith("no: the sandbox report attributes its flows to a process")
        assert "public DNS resolver" in answer

    def test_a_claim_that_mentions_it_keeps_nothing_and_is_named_in_the_reason(self) -> None:
        isrs = _network_analyst(claim=f"The sandbox shows only {CONTACT}:80, background noise.")
        network = network_from_ledger(_ledger(tcp=[{"dst": CONTACT, "dport": 80}]), isrs)
        assert network is not None
        assert network.ips[0].kept_by == []
        assert network.ips[0].mentioned_by == ["a claim by the network analyst"]

        answer = _answer(_report(network), "ip", CONTACT)

        assert answer.startswith("no: ")
        assert answer.endswith(
            "and no model kept it as an indicator "
            "(a claim by the network analyst mentions it and does not keep it)"
        )

    def test_an_analyst_artifact_keeping_it_publishes_it(self) -> None:
        isrs = _network_analyst(artifact_rows=[["ip", CONTACT]])
        network = network_from_ledger(_ledger(tcp=[{"dst": CONTACT, "dport": 80}]), isrs)

        assert _answer(_report(network), "ip", CONTACT) == "yes"

    def test_the_judge_s_indicator_keeping_it_publishes_it(self) -> None:
        network = network_from_ledger(_ledger(tcp=[{"dst": CONTACT, "dport": 80}]))
        report = _report(network)
        report.judge_indicators = [JudgeIndicator(kind="ip", value=CONTACT)]

        assert _answer(report, "ip", CONTACT) == "yes"

    def test_an_address_is_one_address_in_any_case(self) -> None:
        upper = "2A00:1450:4001:82B::200E"
        network = network_from_ledger(_ledger(tcp=[{"dst": upper, "dport": 443}]))
        assert network is not None
        assert [ip.address for ip in network.ips] == ["2a00:1450:4001:82b::200e"]

        answer = _answer(_report(network), "ip", upper)

        assert answer.startswith("no: the sandbox report does not say")

    def test_a_well_known_name_the_guest_resolved_waits_for_a_model(self) -> None:
        report = _report(
            NetworkIOCs(domains=[NetworkDomain(fqdn="www.microsoft.com", source="sandbox")])
        )

        answer = _answer(report, "domain", "www.microsoft.com")

        assert answer.startswith("no: a well-known benign name the sandbox's guest resolved")

    def test_any_other_name_the_sandbox_resolved_is_judged_by_the_name(self) -> None:
        report = _report(
            NetworkIOCs(domains=[NetworkDomain(fqdn="relay-alpha-7f3c.top", source="sandbox")])
        )

        assert _answer(report, "domain", "relay-alpha-7f3c.top") == "yes"


class TestTheWholeReportIsRead:
    def test_attribution_and_every_address_come_from_the_whole_report(self) -> None:
        flows = [{"dst": f"185.199.{n // 250}.{n % 250 + 1}", "dport": 80} for n in range(300)]
        flows.append({"dst": CONTACT, "dport": 443, "sample_process_tree": True})
        report = {"network": {"tcp": flows}}

        network = network_from_ledger([], None, sandbox_report=report)

        assert network is not None
        assert len(network.ips) == 301
        assert next(ip for ip in network.ips if ip.address == CONTACT).sample_process_tree is True

    def test_a_page_of_a_view_never_states_that_the_tree_did_not_reach_an_address(self) -> None:
        page = build_entry(
            entry_id="ev_0002",
            seq=2,
            agent="dynamic",
            tool="sandbox_network",
            args={"offset": 0, "limit": 1},
            server=None,
            output=json.dumps(
                {
                    "tcp": [{"dst": CONTACT, "dport": 80, "sample_process_tree": False}],
                    "tcp_total": 2,
                    "tcp_next_offset": 1,
                }
            ),
        )

        network = network_from_ledger([page])

        assert network is not None and network.ips[0].sample_process_tree is None

    def test_a_shortened_view_never_states_it_either(self) -> None:
        shortened = build_entry(
            entry_id="ev_0003",
            seq=3,
            agent="dynamic",
            tool="sandbox_network",
            args={},
            server=None,
            output=json.dumps(
                {
                    "tcp": [{"dst": CONTACT, "dport": 80, "sample_process_tree": False}],
                    "shortened": {"/tcp": {"kept": 1, "omitted": 40}},
                    "truncated": True,
                }
            ),
        )

        network = network_from_ledger([shortened])

        assert network is not None and network.ips[0].sample_process_tree is None

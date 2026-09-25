"""A sandbox network row is the sample's observation when the sample's process tree made it.

A detonation guest talks to the internet whatever the sample does: its DNS
service asks a public resolver, its connectivity checks reach whoever answers
them. One live run published two such addresses as the sample's C2 and drafted
YARA and Suricata rules over them. Each flow now carries the process that made
it and whether that process is in the sample's tree — a platform fact, right or
absent — and a row the tree did not make is published only when a model names
it; otherwise the table carries it with the reason.
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

CONTACT = "185.199.108.153"
RESOLVER = "9.9.9.9"


def _triage(processes: list[dict[str, Any]], flows: list[dict[str, Any]]) -> Any:
    overview = {"sample": {"id": "t1", "target": "invoice.exe", "sha256": "a" * 64}}
    task = {"processes": processes, "network": {"flows": flows}}
    return triage_overview_to_sandbox_report(overview, task_reports={"behavioral1": task})


_PROCESSES = [
    {"procid": 10, "procid_parent": 0, "image": "invoice.exe", "cmd": "invoice.exe"},
    {"procid": 11, "procid_parent": 10, "image": "cmd.exe", "cmd": "cmd.exe /c whoami"},
    {"procid": 20, "procid_parent": 0, "image": "svchost.exe", "cmd": "svchost.exe -k netsvcs"},
]


class TestTheNormalisedFlowSaysWhichProcessMadeIt:
    def test_the_sample_and_its_children_are_its_tree(self) -> None:
        report = _triage(_PROCESSES, [{"proto": "tcp", "dst": f"{CONTACT}:443", "procid": 11}])

        assert report.network.tcp[0]["sample_process_tree"] is True
        assert report.network.tcp[0]["procid"] == 11

    def test_a_named_process_outside_the_tree_is_not(self) -> None:
        report = _triage(_PROCESSES, [{"proto": "udp", "dst": f"{RESOLVER}:53", "procid": 20}])

        assert report.network.udp[0]["sample_process_tree"] is False

    def test_a_flow_the_report_does_not_attribute_says_nothing(self) -> None:
        report = _triage(
            _PROCESSES,
            [
                {"proto": "tcp", "dst": f"{CONTACT}:80"},
                {"proto": "tcp", "dst": f"{CONTACT}:81", "procid": 99},
            ],
        )

        assert all("sample_process_tree" not in row for row in report.network.tcp)

    def test_no_sample_process_leaves_every_flow_unattributed(self) -> None:
        report = _triage(_PROCESSES[2:], [{"proto": "tcp", "dst": f"{CONTACT}:443", "procid": 20}])

        assert "sample_process_tree" not in report.network.tcp[0]

    def test_triage_s_own_mark_names_the_sample(self) -> None:
        processes = [{"procid": 5, "procid_parent": 0, "image": "x.exe", "orig": True}]
        report = _triage(processes, [{"proto": "tcp", "dst": f"{CONTACT}:443", "procid": 5}])

        assert report.network.tcp[0]["sample_process_tree"] is True


class TestTheViewStatesTheResolver:
    def test_a_public_resolver_row_is_marked(self) -> None:
        view = sandbox_network(
            {"network": {"udp": [{"dst": RESOLVER, "dport": 53}], "tcp": [{"dst": CONTACT}]}}
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


class TestThePublishRule:
    def test_an_unattributed_contact_is_carried_with_the_reason(self) -> None:
        network = network_from_ledger(_ledger(tcp=[{"dst": CONTACT, "dport": 80}]))

        answer = _answer(_report(network), "ip", CONTACT)

        assert answer == (
            "no: the sandbox report does not say which process made the flows to it, "
            "and no model named it"
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

    def test_an_analyst_claim_naming_it_publishes_it(self) -> None:
        isrs = {
            "network": AgentISR(
                agent_id="network",
                domain="network",
                claims=[
                    ClaimEvidence(
                        claim=f"The sample beacons to {CONTACT} over HTTP.",
                        evidence_ref="ev_0001",
                        confidence=0.7,
                    )
                ],
            )
        }
        network = network_from_ledger(_ledger(tcp=[{"dst": CONTACT, "dport": 80}]), isrs)
        assert network is not None
        assert network.ips[0].named_by == ["a claim by the network analyst"]

        assert _answer(_report(network), "ip", CONTACT) == "yes"

    def test_an_analyst_artifact_naming_it_publishes_it(self) -> None:
        isrs = {
            "network": AgentISR(
                agent_id="network",
                domain="network",
                artifacts=[Artifact(kind="endpoints", rows=[["ip", CONTACT]], evidence_ids=[])],
            )
        }
        network = network_from_ledger(_ledger(tcp=[{"dst": CONTACT, "dport": 80}]), isrs)

        assert _answer(_report(network), "ip", CONTACT) == "yes"

    def test_the_judge_s_indicator_naming_it_publishes_it(self) -> None:
        network = network_from_ledger(_ledger(tcp=[{"dst": CONTACT, "dport": 80}]))
        report = _report(network)
        report.judge_indicators = [JudgeIndicator(kind="ip", value=CONTACT)]

        assert _answer(report, "ip", CONTACT) == "yes"

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

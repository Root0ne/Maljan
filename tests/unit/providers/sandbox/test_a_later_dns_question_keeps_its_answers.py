"""A DNS request with several questions gives every question its answers, as dev did.

The Triage reader writes a request once: its first question's row carries the
answers and the request's id, and each later question's row names that id.
Every reader resolves the later question back to the request's answers in
memory (``schemas.sandbox_document.DnsAnswers``). So a report whose request
asks two names reads, for the second name, exactly as the same report with one
request per name, which is how dev read both: the network analyst's input, the
IOC block's resolved addresses, the attribution sentence the publish rule
reads, the published IOCs and the STIX export.
"""

from __future__ import annotations

import json
import re
from typing import Any

from maljan.parsers.network_parser import NetworkParser
from maljan.reporting.builder import ioc_table
from maljan.reporting.evidence_bundles import sample_flow_fact
from maljan.reporting.ledger_projection import network_from_sandbox_report
from maljan.reporting.models import FileHashes, MalwareReport, SampleIdentity
from maljan.reporting.renderers.markdown import MarkdownRenderer
from maljan.reporting.renderers.stix_renderer import ExtendedSTIXRenderer
from maljan.schemas.sandbox_document import (
    DNS_REQUEST_KEY,
    SAME_REQUEST_KEY,
    DnsAnswers,
    sandbox_document,
)
from maljan.schemas.sandbox_report import triage_overview_to_sandbox_report

ANSWERS = {"answers": [{"value": "45.33.32.7"}, {"value": "45.33.32.8"}]}
NAMES = ("relay-first-a1.net", "relay-second-b2.net")


def _task(requests: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "processes": [{"procid": 1, "procid_parent": 0, "image": "s.exe", "orig": True}],
        "network": {
            "flows": [{"proto": "tcp", "dst": "45.33.32.8:443", "procid": 1}],
            "requests": requests,
        },
    }


def _document(requests: list[dict[str, Any]]) -> dict[str, Any]:
    overview = {"sample": {"target": "s.exe", "sha256": "a" * 64}}
    report = triage_overview_to_sandbox_report(
        overview, task_reports={"behavioral1": _task(requests)}
    )
    return sandbox_document(report)


def _one_request_two_questions() -> dict[str, Any]:
    questions = [{"name": name, "type": "A"} for name in NAMES]
    return _document([{"domain_req": {"questions": questions}, "domain_resp": ANSWERS}])


def _one_request_per_name() -> dict[str, Any]:
    return _document(
        [
            {"domain_req": {"questions": [{"name": name, "type": "A"}]}, "domain_resp": ANSWERS}
            for name in NAMES
        ]
    )


_STAMP = re.compile(r"\d{4}-\d{2}-\d{2}[T ][\d:.]+(?:Z|[+-]\d{2}:?\d{2})?")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def _readings(document: dict[str, Any]) -> dict[str, Any]:
    network = network_from_sandbox_report(document)
    assert network is not None
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)), network=network
    )
    bundle = ExtendedSTIXRenderer().render(report)
    stix = _STAMP.sub(
        "T", _UUID.sub("U", json.dumps(bundle.model_dump(mode="json"), sort_keys=True))
    )
    second = next(d for d in network.domains if d.fqdn == NAMES[1])
    return {
        "analyst_input": NetworkParser().parse(document["network"]),
        "resolved_ips": list(second.resolved_ips),
        "attribution": sample_flow_fact(report)("domain", NAMES[1]),
        "iocs": [row.model_dump(mode="json") for row in ioc_table(report)],
        "markdown": _STAMP.sub("T", MarkdownRenderer().render(report)),
        "stix": stix,
    }


def test_the_request_is_written_once_and_named_by_its_id() -> None:
    rows = _one_request_two_questions()["network"]["dns"]
    first, second = rows
    assert [answer["data"] for answer in first["answers"]] == ["45.33.32.7", "45.33.32.8"]
    assert second[SAME_REQUEST_KEY] == first[DNS_REQUEST_KEY]
    assert "answers" not in second
    # Answers that name no name belong to the whole request, as dev read them.
    assert DnsAnswers(rows).of(second) == [{"data": "45.33.32.7"}, {"data": "45.33.32.8"}]


def test_a_single_question_request_is_written_as_before() -> None:
    rows = _one_request_per_name()["network"]["dns"]
    assert all(DNS_REQUEST_KEY not in row and SAME_REQUEST_KEY not in row for row in rows)


def test_two_requests_with_the_same_first_name_keep_their_own_answers() -> None:
    def request(answer: str) -> dict[str, Any]:
        questions = [
            {"name": "relay-x-c3.net", "type": "A"},
            {"name": "relay-y-d4.net", "type": "A"},
        ]
        return {
            "domain_req": {"questions": questions},
            "domain_resp": {"answers": [{"value": answer}]},
        }

    rows = _document([request("45.33.32.1"), request("45.33.32.2")])["network"]["dns"]
    answers_of = DnsAnswers(rows)
    later = [row for row in rows if SAME_REQUEST_KEY in row]
    assert [answers_of.of(row) for row in later] == [
        [{"data": "45.33.32.1"}],
        [{"data": "45.33.32.2"}],
    ]


def test_every_reader_reads_the_second_name_as_dev_did() -> None:
    together, apart = _readings(_one_request_two_questions()), _readings(_one_request_per_name())
    assert together["resolved_ips"] == ["45.33.32.7", "45.33.32.8"]
    assert "relay-second-b2.net | 45.33.32.7" in together["analyst_input"].replace("  ", " ")
    # A flow of the sample's tree reached one address the name resolved to.
    assert together["attribution"] == ""
    # The name reaches the published IOCs and the export, on both readings.
    assert NAMES[1] in json.dumps(together["iocs"])
    assert together == apart


def _named_request(answers: list[dict[str, str]], names: tuple[str, ...]) -> dict[str, Any]:
    return {
        "domain_req": {"questions": [{"name": name, "type": "A"} for name in names]},
        "domain_resp": {"answers": answers},
    }


def test_a_named_answer_goes_to_the_question_it_answers() -> None:
    answers = [
        {"name": NAMES[0], "type": "A", "value": "45.33.32.7"},
        {"name": NAMES[1], "type": "A", "value": "45.33.32.8"},
    ]
    rows = _document([_named_request(answers, NAMES)])["network"]["dns"]
    answers_of = DnsAnswers(rows)
    assert [answers_of.of(row) for row in rows] == [
        [{"data": "45.33.32.7"}],
        [{"data": "45.33.32.8"}],
    ]


def test_an_alias_chain_leads_a_name_to_its_addresses() -> None:
    answers = [
        {"name": "relay-alias-e5.net", "type": "CNAME", "value": "relay-middle-f6.net"},
        {"name": "relay-middle-f6.net", "type": "CNAME", "value": "relay-target-g7.net."},
        {"name": "relay-target-g7.net", "type": "A", "value": "45.33.32.9"},
        {"name": NAMES[0], "type": "A", "value": "45.33.32.7"},
    ]
    names = (NAMES[0], "relay-alias-e5.net")
    rows = _document([_named_request(answers, names)])["network"]["dns"]
    answers_of = DnsAnswers(rows)
    first, alias = rows
    assert answers_of.of(first) == [{"data": "45.33.32.7"}]
    assert answers_of.of(alias) == [
        {"data": "relay-middle-f6.net"},
        {"data": "relay-target-g7.net."},
        {"data": "45.33.32.9"},
    ]
    network = network_from_sandbox_report(_document([_named_request(answers, names)]))
    assert network is not None
    held = {d.fqdn: d.resolved_ips for d in network.domains}
    assert held["relay-alias-e5.net"] == ["45.33.32.9"]
    assert held[NAMES[0]] == ["45.33.32.7"]

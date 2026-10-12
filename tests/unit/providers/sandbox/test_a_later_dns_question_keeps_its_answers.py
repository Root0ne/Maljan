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
        [{"data": "45.33.32.7", "type": "A"}],
        [{"data": "45.33.32.8", "type": "A"}],
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
    assert answers_of.of(first) == [{"data": "45.33.32.7", "type": "A"}]
    assert answers_of.of(alias) == [
        {"data": "relay-middle-f6.net", "type": "CNAME"},
        {"data": "relay-target-g7.net.", "type": "CNAME"},
        {"data": "45.33.32.9", "type": "A"},
    ]
    network = network_from_sandbox_report(_document([_named_request(answers, names)]))
    assert network is not None
    held = {d.fqdn: d.resolved_ips for d in network.domains}
    assert held["relay-alias-e5.net"] == ["45.33.32.9"]
    assert held[NAMES[0]] == ["45.33.32.7"]


def _cape_upload(link_key: str) -> dict[str, Any]:
    """A CAPE report whose two DNS rows each carry ``link_key: 7``, read by the upload provider."""
    from maljan.core.config import Settings
    from maljan.providers.sandbox.upload import UploadSandboxProvider

    rows = [
        {
            "request": "relay-a-k1.net",
            "type": "A",
            "answers": [{"type": "A", "data": "45.33.32.1"}],
        },
        {
            "request": "relay-b-k2.net",
            "type": "A",
            "answers": [{"type": "A", "data": "45.33.32.9"}],
        },
    ]
    for row in rows:
        row[link_key] = 7
    payload = {"info": {"version": "2.4-CAPE", "id": 3}, "network": {"dns": rows}}
    cfg = Settings(_env_file=None)
    cfg.sandbox.provider = "upload"
    run = UploadSandboxProvider.from_settings(cfg).attach_report(
        json.dumps(payload).encode(), filename="r.json"
    )
    return sandbox_document(run.report)


class TestASourceReportCannotLinkItsOwnRows:
    """A source's own DNS link key is never read as the platform's: each row keeps its answers."""

    def _resolved(self, link_key: str) -> dict[str, list[str]]:
        network = network_from_sandbox_report(_cape_upload(link_key))
        assert network is not None
        return {d.fqdn: d.resolved_ips for d in network.domains}

    # Dev read each row's own answers.
    DEV = {"relay-a-k1.net": ["45.33.32.1"], "relay-b-k2.net": ["45.33.32.9"]}

    def test_a_plain_key_of_the_same_word(self) -> None:
        assert self._resolved("dns_request") == self.DEV
        assert self._resolved("same_request_as") == self.DEV

    def test_the_reserved_key_itself_is_removed_by_the_reader(self) -> None:
        assert self._resolved(DNS_REQUEST_KEY) == self.DEV
        assert self._resolved(SAME_REQUEST_KEY) == self.DEV
        rows = _cape_upload(DNS_REQUEST_KEY)["network"]["dns"]
        assert all(DNS_REQUEST_KEY not in row for row in rows)

    def test_a_link_not_in_the_reader_s_form_is_ignored(self) -> None:
        rows = [
            {"request": "a.relay-m3.net", DNS_REQUEST_KEY: 1, "answers": [{"data": "45.33.32.1"}]},
            {"request": "b.relay-m3.net", DNS_REQUEST_KEY: 1, "answers": [{"data": "45.33.32.2"}]},
            {"request": "c.relay-m3.net", SAME_REQUEST_KEY: 9, "answers": [{"data": "45.33.32.3"}]},
            {
                "request": "d.relay-m3.net",
                SAME_REQUEST_KEY: True,
                "answers": [{"data": "45.33.32.4"}],
            },
        ]
        answers_of = DnsAnswers(rows)
        assert [answers_of.of(row) for row in rows] == [row["answers"] for row in rows]

    def test_triage_multi_question_attribution_still_works(self) -> None:
        test_a_named_answer_goes_to_the_question_it_answers()


def test_only_an_address_record_names_an_address() -> None:
    answers = [
        {"name": NAMES[0], "type": "TXT", "value": "45.33.32.99"},
        {"name": NAMES[0], "type": "A", "value": "45.33.32.7"},
        {"name": NAMES[1], "type": "AAAA", "value": "2001:db8::7"},
    ]
    network = network_from_sandbox_report(_document([_named_request(answers, NAMES)]))
    assert network is not None
    held = {d.fqdn: d.resolved_ips for d in network.domains}
    assert held[NAMES[0]] == ["45.33.32.7"]
    assert held[NAMES[1]] == ["2001:db8::7"]


def test_a_cut_is_stated_on_the_names_it_withheld_from() -> None:
    from maljan.reporting.builder import _domain_context

    n = 300
    questions = [{"name": f"q{i}.relay-n4.net", "type": "A"} for i in range(n)]
    answers = [{"value": f"45.33.{i // 250}.{i % 250 + 1}"} for i in range(n)]
    request = {"domain_req": {"questions": questions}, "domain_resp": {"answers": answers}}
    network = network_from_sandbox_report(_document([request]))
    assert network is not None
    partial = [d for d in network.domains if d.resolved_ips_partial]
    assert partial, "a request this shared must reach the size bound"
    assert all(d.resolved_ips_withheld > 0 for d in partial)
    assert "withheld for size" in _domain_context(partial[0])
    whole = [d for d in network.domains if not d.resolved_ips_partial]
    # A name nothing was withheld from dumps as it always did.
    assert "resolved_ips_partial" not in whole[0].model_dump()
    assert partial[0].model_dump()["resolved_ips_partial"] is True


def _ledger_view(rows: list[dict[str, Any]], *, server: str | None, source: str | None) -> Any:
    """A ``sandbox_network`` ledger answer holding ``rows``, as one tool or another wrote it."""
    from maljan.schemas.evidence import build_entry

    return build_entry(
        entry_id="ev_0001",
        seq=1,
        agent="dynamic",
        tool="sandbox_network",
        args={},
        server=server,
        output=json.dumps({"dns": rows}),
        source=source,
    )


def _linked_rows() -> list[dict[str, Any]]:
    """Two DNS rows in the resolver's exact link form, each with its own address."""
    return [
        {"request": "relay-a-p5.net", DNS_REQUEST_KEY: 0, "answers": [{"data": "45.33.32.1"}]},
        {"request": "relay-b-p6.net", SAME_REQUEST_KEY: 0, "answers": [{"data": "45.33.32.9"}]},
    ]


def _resolved_from(entries: list[Any]) -> dict[str, list[str]]:
    from maljan.reporting.ledger_projection import network_from_ledger

    network = network_from_ledger(entries)
    assert network is not None
    return {d.fqdn: d.resolved_ips for d in network.domains}


class TestALedgerAnswerFromAServerCannotLinkItsRows:
    """With no report in hand, only the platform's own answers carry request links."""

    DEV = {"relay-a-p5.net": ["45.33.32.1"], "relay-b-p6.net": ["45.33.32.9"]}

    def test_a_server_s_answer_reads_each_row_s_own_answers(self) -> None:
        # As the reviewer recorded it: a server's tool of the view's name, no source.
        entry = _ledger_view(_linked_rows(), server="acme", source=None)
        assert _resolved_from([entry]) == self.DEV

    def test_a_server_named_like_a_platform_source_is_treated_alike(self) -> None:
        for name in ("sandbox", "pack"):
            entry = _ledger_view(_linked_rows(), server=name, source=None)
            assert _resolved_from([entry]) == self.DEV

    def test_an_answer_with_no_recorded_source_reads_its_own_answers(self) -> None:
        entry = _ledger_view(_linked_rows(), server=None, source=None)
        assert _resolved_from([entry]) == self.DEV

    def test_the_platform_s_own_answer_keeps_its_links(self) -> None:
        rows = [
            {
                "request": "relay-a-p5.net",
                DNS_REQUEST_KEY: 0,
                "answers": [{"data": "45.33.32.1"}, {"data": "45.33.32.2"}],
            },
            {"request": "relay-b-p6.net", SAME_REQUEST_KEY: 0},
        ]
        for source in ("sandbox", "pack"):
            entry = _ledger_view(rows, server=None, source=source)
            assert _resolved_from([entry])["relay-b-p6.net"] == ["45.33.32.1", "45.33.32.2"]


def test_two_views_of_one_report_withhold_the_count_once() -> None:
    n = 300
    questions = [{"name": f"q{i}.relay-n4.net", "type": "A"} for i in range(n)]
    answers = [{"value": f"45.33.{i // 250}.{i % 250 + 1}"} for i in range(n)]
    request = {"domain_req": {"questions": questions}, "domain_resp": {"answers": answers}}
    rows = _document([request])["network"]["dns"]
    one = _ledger_view(rows, server=None, source="sandbox")
    from maljan.reporting.ledger_projection import network_from_ledger

    single = {d.fqdn: d.resolved_ips_withheld for d in network_from_ledger([one]).domains}
    twice = network_from_ledger([one, one.model_copy(update={"id": "ev_0002", "seq": 2})])
    assert {d.fqdn: d.resolved_ips_withheld for d in twice.domains} == single
    assert max(single.values()) <= n

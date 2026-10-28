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

import pytest

from maljan.parsers.network_parser import NetworkParser
from maljan.providers.sandbox.readers import ReportReader
from maljan.reporting.builder import ioc_table
from maljan.reporting.evidence_bundles import sample_flow_fact
from maljan.reporting.ledger_projection import network_from_sandbox_report
from maljan.reporting.models import FileHashes, MalwareReport, SampleIdentity
from maljan.reporting.renderers.markdown import MarkdownRenderer
from maljan.reporting.renderers.stix_renderer import ExtendedSTIXRenderer
from maljan.schemas.sandbox_document import (
    DNS_AS_WRITTEN_KEY,
    DNS_REQUEST_KEY,
    SAME_REQUEST_KEY,
    DnsAnswers,
    sandbox_document,
)
from maljan.schemas.sandbox_report import (
    SandboxDnsRequest,
    SandboxNetwork,
    SandboxReport,
    triage_overview_to_sandbox_report,
)

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
        overview,
        provider="triage",
        source_format="triage",
        task_reports={"behavioral1": _task(requests)},
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


# -- the links are the platform's own: an operator reader cannot forge them ---------------------


def _forged_rows() -> list[dict[str, Any]]:
    """Two DNS rows a report wrote with the platform's link keys, each with its own address."""
    return [
        {"request": "relay-a-r7.net", DNS_REQUEST_KEY: 0, "answers": [{"data": "45.33.32.1"}]},
        {"request": "relay-b-r8.net", SAME_REQUEST_KEY: 0, "answers": [{"data": "45.33.32.9"}]},
    ]


# What dev read: each row's own answers.
FORGED_DEV = {"relay-a-r7.net": ["45.33.32.1"], "relay-b-r8.net": ["45.33.32.9"]}


class _KeepSourceReader(ReportReader):
    """An operator's reader built on ``keep_source``: the report kept as it was written."""

    id = "acmekeep"
    keeps_source_arrangement = True

    def read(
        self,
        payload: dict[str, Any],
        *,
        provider: str,
        task_id: str = "",
        fmt: Any = None,
        **c: Any,
    ) -> SandboxReport:
        return self.keep_source(SandboxReport(provider=provider, source_format=self.id), payload)


class _FieldsReader(ReportReader):
    """An operator's reader that builds its DNS rows from the report's own fields."""

    id = "acmefields"

    def read(
        self,
        payload: dict[str, Any],
        *,
        provider: str,
        task_id: str = "",
        fmt: Any = None,
        **c: Any,
    ) -> SandboxReport:
        return SandboxReport(
            provider=provider,
            source_format=self.id,
            network=SandboxNetwork(dns=list(payload["network"]["dns"])),
        )


class _StructuralReader(ReportReader):
    """An operator's reader that expresses a multi-name DNS request in the structural form."""

    id = "acmestruct"

    def read(
        self,
        payload: dict[str, Any],
        *,
        provider: str,
        task_id: str = "",
        fmt: Any = None,
        **c: Any,
    ) -> SandboxReport:
        message = payload["message"]
        request = SandboxDnsRequest(
            questions=[{"request": name, "type": "A"} for name in message["asked"]],
            answers=[{"data": a["ip"], "name": a["for"], "type": "A"} for a in message["answers"]],
        )
        return SandboxReport(
            provider=provider,
            source_format=self.id,
            network=SandboxNetwork(dns_requests=[request], domains=list(message["asked"])),
        )


def _resolved_by(reader: ReportReader, payload: dict[str, Any]) -> dict[str, list[str]]:
    document = sandbox_document(reader.read(payload, provider="upload"))
    network = network_from_sandbox_report(document)
    assert network is not None
    return {d.fqdn: d.resolved_ips for d in network.domains}


class TestAnOperatorReaderCannotForgeTheLinks:
    def test_a_reader_built_on_keep_source(self) -> None:
        payload = {"info": {"id": 1}, "network": {"dns": _forged_rows()}}
        assert _resolved_by(_KeepSourceReader(), payload) == FORGED_DEV
        rows = sandbox_document(_KeepSourceReader().read(payload, provider="upload"))
        assert all(
            not ({DNS_REQUEST_KEY, SAME_REQUEST_KEY} & set(row)) for row in rows["network"]["dns"]
        )

    def test_a_reader_that_builds_its_rows_from_the_report_s_fields(self) -> None:
        payload = {"network": {"dns": _forged_rows()}}
        assert _resolved_by(_FieldsReader(), payload) == FORGED_DEV
        rows = sandbox_document(_FieldsReader().read(payload, provider="upload"))
        assert all(
            not ({DNS_REQUEST_KEY, SAME_REQUEST_KEY} & set(row)) for row in rows["network"]["dns"]
        )

    def test_a_reader_using_the_structural_form_gets_each_name_its_own_answers(self) -> None:
        payload = {
            "message": {
                "asked": ["relay-a-r7.net", "relay-b-r8.net"],
                "answers": [
                    {"for": "relay-b-r8.net", "ip": "45.33.32.9"},
                    {"for": "relay-a-r7.net", "ip": "45.33.32.1"},
                ],
            }
        }
        document = sandbox_document(_StructuralReader().read(payload, provider="upload"))
        first, later = document["network"]["dns"]
        # The platform minted the links.
        assert later[SAME_REQUEST_KEY] == first[DNS_REQUEST_KEY] == 0
        assert _resolved_by(_StructuralReader(), payload) == FORGED_DEV

    def test_triage_multi_question_parity_is_unchanged(self) -> None:
        test_every_reader_reads_the_second_name_as_dev_did()
        test_a_named_answer_goes_to_the_question_it_answers()


# -- a link key on a row outside the DNS rows is never honoured --------------------------------


class _KeepSourceStructuralReader(ReportReader):
    """An operator's reader that keeps its source and expresses one DNS message structurally."""

    id = "acmekeepstruct"
    keeps_source_arrangement = True

    def read(
        self,
        payload: dict[str, Any],
        *,
        provider: str,
        task_id: str = "",
        fmt: Any = None,
        **c: Any,
    ) -> SandboxReport:
        report = SandboxReport(provider=provider, source_format=self.id)
        message = payload["message"]
        report.network.dns_requests.append(
            SandboxDnsRequest(
                questions=[{"request": name, "type": "A"} for name in message["asked"]],
                answers=[{"data": address} for address in message["answers"]],
            )
        )
        return self.keep_source(report, payload)


class _FieldsDomainsReader(ReportReader):
    """An operator's reader that lays its report out from fields, its domains rows as written."""

    id = "acmefielddomains"

    def read(
        self,
        payload: dict[str, Any],
        *,
        provider: str,
        task_id: str = "",
        fmt: Any = None,
        **c: Any,
    ) -> SandboxReport:
        message = payload["message"]
        request = SandboxDnsRequest(
            questions=[{"request": name, "type": "A"} for name in message["asked"]],
            answers=[{"data": address} for address in message["answers"]],
        )
        return SandboxReport(
            provider=provider,
            source_format=self.id,
            network=SandboxNetwork(dns_requests=[request], domains=list(payload["domains"])),
        )


UNRELATED = "unrelated-z9.net"


def _two_name_message() -> dict[str, Any]:
    return {"asked": ["relay-a-s1.net", "relay-b-s2.net"], "answers": ["45.33.32.50"]}


def _no_link_left(document: dict[str, Any]) -> bool:
    return all(
        not ({DNS_REQUEST_KEY, SAME_REQUEST_KEY} & set(row))
        for kind in ("domains", "hosts", "http", "tcp", "udp")
        for row in document["network"].get(kind) or []
        if isinstance(row, dict)
    )


class TestALinkOutsideTheDnsRowsIsNeverHonoured:
    def test_a_kept_source_s_domains_row_reads_its_own_answers(self) -> None:
        payload = {
            "info": {"id": 1},
            "network": {"domains": [{"domain": UNRELATED, SAME_REQUEST_KEY: 0}]},
            "message": _two_name_message(),
        }
        document = sandbox_document(_KeepSourceStructuralReader().read(payload, provider="upload"))
        assert _no_link_left(document)
        resolved = _resolved_by(_KeepSourceStructuralReader(), payload)
        assert resolved[UNRELATED] == []
        assert resolved["relay-b-s2.net"] == ["45.33.32.50"]

    def test_a_reader_s_own_domains_rows_lose_the_link_keys(self) -> None:
        for key in (SAME_REQUEST_KEY, DNS_REQUEST_KEY):
            payload = {"domains": [{"domain": UNRELATED, key: 0}], "message": _two_name_message()}
            document = sandbox_document(_FieldsDomainsReader().read(payload, provider="upload"))
            assert _no_link_left(document)
            assert _resolved_by(_FieldsDomainsReader(), payload)[UNRELATED] == []

    def test_the_platform_s_own_ledger_view_reads_a_domains_row_s_own_answers(self) -> None:
        from maljan.schemas.evidence import build_entry

        rows = [
            {"request": "relay-a-s1.net", DNS_REQUEST_KEY: 0, "answers": [{"data": "45.33.32.50"}]},
            {"request": "relay-b-s2.net", SAME_REQUEST_KEY: 0},
        ]
        for key in (SAME_REQUEST_KEY, DNS_REQUEST_KEY):
            output = {"dns": rows, "domains": [{"domain": UNRELATED, key: 0}]}
            for source in ("sandbox", "pack"):
                entry = build_entry(
                    entry_id="ev_0001",
                    seq=1,
                    agent="dynamic",
                    tool="sandbox_network",
                    args={},
                    server=None,
                    output=json.dumps(output),
                    source=source,
                )
                resolved = _resolved_from([entry])
                assert resolved[UNRELATED] == []
                assert resolved["relay-b-s2.net"] == ["45.33.32.50"]

    def test_the_resolver_honours_a_link_only_on_the_rows_it_was_built_over(self) -> None:
        rows = [
            {"request": "relay-a-s1.net", DNS_REQUEST_KEY: 0, "answers": [{"data": "45.33.32.50"}]},
            {"request": "relay-b-s2.net", SAME_REQUEST_KEY: 0},
        ]
        answers = DnsAnswers(rows)
        assert answers.of(rows[1]) == [{"data": "45.33.32.50"}]
        # An equal row that is not one of them, and a row of another list.
        assert answers.of(dict(rows[1])) == []
        stranger = {"domain": UNRELATED, SAME_REQUEST_KEY: 0, "answers": [{"data": "45.33.32.60"}]}
        assert answers.of(stranger) == [{"data": "45.33.32.60"}]
        assert answers.withheld(stranger) == 0


class TestAKeptSourceKeepsItsStructuralRequests:
    def test_a_source_with_no_network_block_gets_one(self) -> None:
        payload = {"info": {"id": 1}, "message": _two_name_message()}
        document = sandbox_document(_KeepSourceStructuralReader().read(payload, provider="upload"))
        assert list(document) == ["info", "message", "network"]
        assert [row["request"] for row in document["network"]["dns"]] == [
            "relay-a-s1.net",
            "relay-b-s2.net",
        ]
        assert _resolved_by(_KeepSourceStructuralReader(), payload)["relay-b-s2.net"] == [
            "45.33.32.50"
        ]

    def test_a_dns_value_that_is_not_a_list_is_kept_beside_the_requests(self) -> None:
        value = {"request": "own-c3.net", "answers": [{"data": "45.33.32.70"}], SAME_REQUEST_KEY: 0}
        payload = {"info": {"id": 1}, "network": {"dns": value}, "message": _two_name_message()}
        document = sandbox_document(_KeepSourceStructuralReader().read(payload, provider="upload"))
        first, *requested = document["network"]["dns"]
        # The source's value, kept as its first row, without the platform's link key.
        assert first == {"request": "own-c3.net", "answers": [{"data": "45.33.32.70"}]}
        assert [row["request"] for row in requested] == ["relay-a-s1.net", "relay-b-s2.net"]
        resolved = _resolved_by(_KeepSourceStructuralReader(), payload)
        assert resolved["own-c3.net"] == ["45.33.32.70"]
        assert resolved["relay-b-s2.net"] == ["45.33.32.50"]

    def test_a_dns_value_that_is_not_a_list_stays_as_written_with_no_request(self) -> None:
        value = {"request": "own-c3.net", "answers": [{"data": "45.33.32.70"}]}
        payload = {"info": {"id": 1}, "network": {"dns": value}}
        document = sandbox_document(_KeepSourceReader().read(payload, provider="upload"))
        assert document["network"]["dns"] == value

    def test_a_dns_value_no_row_reader_reads_is_no_row_and_no_indicator(self) -> None:
        from maljan.providers.sandbox_tools import sandbox_network

        shapeless = ({"weird": 1}, {"answers": []}, {"request": "  "})
        for value in ("N/A", "evil-string-c4.net", 0, 7, True, False, *shapeless):
            payload = {"info": {"id": 1}, "network": {"dns": value}, "message": _two_name_message()}
            document = sandbox_document(
                _KeepSourceStructuralReader().read(payload, provider="upload")
            )
            network = document["network"]
            # The structural rows, and nothing else, are the DNS rows.
            assert [row["request"] for row in network["dns"]] == [
                "relay-a-s1.net",
                "relay-b-s2.net",
            ]
            # The source's value is kept as written, beside the rows.
            assert network[DNS_AS_WRITTEN_KEY] == value
            assert type(network[DNS_AS_WRITTEN_KEY]) is type(value)
            resolved = _resolved_by(_KeepSourceStructuralReader(), payload)
            assert set(resolved) == {"relay-a-s1.net", "relay-b-s2.net"}, value
            # The model-facing text holds the two names' rows and no junk row.
            view = sandbox_network(document)
            assert [row["request"] for row in view["dns"]] == ["relay-a-s1.net", "relay-b-s2.net"]
            text = NetworkParser()._parse_sandbox_network(network)
            assert "relay-b-s2.net | 45.33.32.50" in text
            assert "N/A | N/A" not in text
            if isinstance(value, str):
                assert value not in text

    def test_a_null_dns_value_beside_requests_is_no_row(self) -> None:
        payload = {"info": {"id": 1}, "network": {"dns": None}, "message": _two_name_message()}
        document = sandbox_document(_KeepSourceStructuralReader().read(payload, provider="upload"))
        assert [row["request"] for row in document["network"]["dns"]] == [
            "relay-a-s1.net",
            "relay-b-s2.net",
        ]
        assert DNS_AS_WRITTEN_KEY not in document["network"]
        assert set(_resolved_by(_KeepSourceStructuralReader(), payload)) == {
            "relay-a-s1.net",
            "relay-b-s2.net",
        }

    def test_an_object_naming_a_name_under_any_reader_s_field_is_a_row(self) -> None:
        for key in ("request", "query", "hostname", "domain", "name"):
            value = {key: "own-c3.net", "answers": [{"data": "45.33.32.70"}]}
            payload = {"info": {"id": 1}, "network": {"dns": value}, "message": _two_name_message()}
            document = sandbox_document(
                _KeepSourceStructuralReader().read(payload, provider="upload")
            )
            assert document["network"]["dns"][0] == value
            assert DNS_AS_WRITTEN_KEY not in document["network"]

    def test_with_no_request_every_value_stays_as_written(self) -> None:
        for value in ("N/A", 0, True, None, {"weird": 1}):
            payload = {"info": {"id": 1}, "network": {"dns": value}}
            document = sandbox_document(_KeepSourceReader().read(payload, provider="upload"))
            assert document["network"] == {"dns": value}


class TestTheFillsAgreeWithTheDocument:
    def test_requests_with_no_place_fill_nothing(self) -> None:
        from maljan.schemas.sandbox_report import report_fills

        for network in ("unavailable", [1, 2], 5):
            payload = {"info": {"id": 1}, "network": network, "message": _two_name_message()}
            report = _KeepSourceStructuralReader().read(payload, provider="upload")
            document = sandbox_document(report)
            assert document["network"] == network
            assert "network.dns" not in report_fills(report)

    def test_requests_with_a_place_fill_the_dns_rows(self) -> None:
        from maljan.schemas.sandbox_report import report_fills

        for payload in (
            {"info": {"id": 1}, "message": _two_name_message()},
            {"info": {"id": 1}, "network": {}, "message": _two_name_message()},
            {"info": {"id": 1}, "network": {"dns": "N/A"}, "message": _two_name_message()},
        ):
            report = _KeepSourceStructuralReader().read(payload, provider="upload")
            assert sandbox_document(report)["network"]["dns"]
            assert "network.dns" in report_fills(report)

    def test_a_laid_out_report_s_requests_fill_the_dns_rows(self) -> None:
        from maljan.schemas.sandbox_report import report_fills

        report = SandboxReport(provider="x", source_format="y")
        report.network.dns_requests.append(
            SandboxDnsRequest(questions=[{"request": "relay-a-s1.net"}], answers=[])
        )
        assert sandbox_document(report)["network"]["dns"]
        assert "network.dns" in report_fills(report)


# -- one reading of a DNS row's name, the reserved written-as key, one place decision ----------


_NAME_KEYS = ("request", "query", "hostname", "domain", "name")


def _dns_item_root(row: dict[str, Any]) -> str:
    from maljan.analysis.evidence_roots import SECTION_OF_PREFIX, _item_root, _Joins

    prefix = next(p for p, section in SECTION_OF_PREFIX.items() if section == "network")
    joins = _Joins()
    joins.network_items[f"{prefix}:1"] = ("dns", row)
    return _item_root(f"{prefix}:1", joins)[0]


class TestEveryReaderReadsADnsRowSNameAlike:
    @pytest.mark.parametrize("key", _NAME_KEYS)
    def test_a_row_naming_its_name_under_any_field_is_read_by_every_reader(self, key: str) -> None:
        from maljan.parsers.dynamic_parser import DynamicParser
        from maljan.schemas.sandbox_document import dns_row_name, reads_as_dns_row

        row = {key: " own-z1.net ", "answers": [{"data": "45.33.32.81"}]}
        assert dns_row_name(row) == "own-z1.net"
        assert reads_as_dns_row(row)
        network = {"dns": [row]}
        text = NetworkParser()._parse_sandbox_network(network)
        assert "own-z1.net | 45.33.32.81" in text
        assert "N/A | N/A" not in text
        assert "own-z1.net" in DynamicParser().parse({"network": network})
        report = SandboxReport(provider="x", source_format="y", network=SandboxNetwork(dns=[row]))
        domains = network_from_sandbox_report(sandbox_document(report)).domains
        assert [d.fqdn for d in domains] == ["own-z1.net"]
        assert domains[0].resolved_ips == ["45.33.32.81"]
        assert _dns_item_root(row).endswith("own-z1.net")

    def test_a_kept_object_naming_its_name_only_under_hostname_prints_no_empty_line(self) -> None:
        for key in ("hostname", "domain", "name"):
            value = {key: "own-z1.net", "answers": [{"data": "45.33.32.81"}]}
            payload = {"info": {"id": 1}, "network": {"dns": value}, "message": _two_name_message()}
            document = sandbox_document(
                _KeepSourceStructuralReader().read(payload, provider="upload")
            )
            text = NetworkParser()._parse_sandbox_network(document["network"])
            assert "own-z1.net | 45.33.32.81" in text
            assert "N/A | N/A" not in text

    def test_no_reader_holds_its_own_copy_of_the_name_fields(self) -> None:
        from pathlib import Path

        root = Path(__file__).resolve().parents[4] / "src" / "maljan"
        readers = (
            "parsers/network_parser.py",
            "parsers/dynamic_parser.py",
            "analysis/evidence_roots.py",
            "reporting/ledger_projection.py",
        )
        for relative in readers:
            text = (root / relative).read_text(encoding="utf-8")
            assert "dns_row_name" in text, relative
            assert not re.search(r"get\(\s*\"request\"", text), relative

    def test_no_module_holds_a_copy_of_the_name_fields_of_its_own(self) -> None:
        """A tuple, list or set naming two DNS name keys is a second copy of the fields.

        Any two of them, ``request`` or not, and a ``.get(...) or .get(...)``
        chain over two of them alike (:func:`_name_field_copies`). Only the one
        reader's own tuple (``DNS_NAME_KEYS``) holds them, beside the Markdown
        table's keys of a row that is no DNS row (read past the DNS row reader
        for a DNS row), the shape test's DNS-specific question spellings (the
        evidence a list is DNS, never a reading of a row's name) and the word
        lists that hold two of the words with another meaning: an argument's
        role words (one shared copy, ``reputation.INDICATOR_ROLE_WORDS``, and
        the role a proposal returns), a description's vocabulary,
        a card's source fields, indicator kinds and code identifiers. Each is
        named by the name it is assigned to, or the function holding it.
        """
        from pathlib import Path

        root = Path(__file__).resolve().parents[4] / "src" / "maljan"
        allowed = {
            ("schemas/sandbox_document.py", "DNS_NAME_KEYS"),
            ("reporting/ledger_report.py", "_NON_DNS_ENDPOINT_KEYS"),
            ("core/report_shapes.py", "_GENERIC_QUESTION_KEYS"),
            ("core/declaration_proposals.py", "_DESCRIPTION_WORDS"),
            ("core/declaration_proposals.py", "_argument_role"),
            ("core/reputation.py", "INDICATOR_ROLE_WORDS"),
            ("memory/technique_cards.py", "SOURCE_FIELDS"),
            ("reporting/dedupe.py", "_CASE_BLIND"),
            ("tools/strings.py", "_CODE_IDENTIFIER_LABELS"),
        }
        found: list[str] = []
        for path in sorted(root.rglob("*.py")):
            relative = path.relative_to(root).as_posix()
            text = path.read_text(encoding="utf-8")
            found += [
                f"{relative}:{line}"
                for line, owner in _name_field_copies(text)
                if (relative, owner) not in allowed
            ]
            if relative != "schemas/sandbox_document.py":
                if re.search(r"get\(\s*\"request\"", text) and "dns" in relative:
                    found.append(f'{relative}: get("request")')
        assert found == []

    @pytest.mark.parametrize(
        "source",
        [
            'KEYS = ("query", "hostname", "domain")',
            'KEYS = {"hostname", "domain"}',
            'KEYS = ["name", "request"]',
            'def f(row):\n    return row.get("hostname") or row.get("domain")',
        ],
    )
    def test_the_guard_finds_a_copy_with_or_without_request(self, source: str) -> None:
        assert len(_name_field_copies(source)) == 1

    @pytest.mark.parametrize(
        "source",
        ['KEYS = ("hostname", "port")', 'def f(row):\n    return row.get("name") or ""'],
    )
    def test_one_name_field_is_no_copy(self, source: str) -> None:
        assert _name_field_copies(source) == []

    @pytest.mark.parametrize("key", ["request", "query", "hostname", "domain", "name"])
    def test_the_markdown_network_table_prints_a_row_named_under_any_name_key(
        self, key: str
    ) -> None:
        from maljan.reporting.ledger_report import build_sections
        from maljan.schemas.evidence import LedgerEntry
        from maljan.schemas.sandbox_document import DNS_NAME_KEYS

        assert key in DNS_NAME_KEYS
        row = {key: "own-z1.net", "type": "A", "answers": [{"data": "45.33.32.81"}]}
        entry = LedgerEntry(
            id="ev_0001",
            agent="dynamic",
            tool="sandbox_network",
            structured={"dns": [row]},
            output=json.dumps({"dns": [row]}),
        )
        [table] = [s for s in build_sections([entry]) if s.title == "Network activity observed"]
        assert [r[:2] for r in table.rows] == [["dns", "own-z1.net"]]

    def test_a_query_row_with_an_interface_name_prints_the_query(self) -> None:
        from maljan.reporting.ledger_report import build_sections
        from maljan.schemas.evidence import LedgerEntry

        row = {"query": "own-z1.net", "type": "A", "name": "eth0"}
        entry = LedgerEntry(
            id="ev_0001", agent="dynamic", tool="sandbox_network", structured={"dns": [row]}
        )
        [table] = [s for s in build_sections([entry]) if s.title == "Network activity observed"]
        assert [r[:2] for r in table.rows] == [["dns", "own-z1.net"]]


class TestTheWrittenAsKeyIsThePlatformS:
    @pytest.mark.parametrize(
        "network",
        [
            {"dns": [{"request": "own-z2.net"}]},
            {},
            {"dns": {"request": "own-z2.net"}},
            {"dns": "N/A"},
            {"dns": [{"request": "evil-z2.net", "answers": [{"data": "203.0.113.9"}]}]},
        ],
        ids=repr,
    )
    def test_a_source_s_value_under_the_key_is_removed_in_every_case(
        self, network: dict[str, Any]
    ) -> None:
        for reader in (_KeepSourceStructuralReader(), _KeepSourceReader()):
            payload = {
                "info": {"id": 1},
                "network": {**network, DNS_AS_WRITTEN_KEY: "FORGED-Z2"},
                "message": _two_name_message(),
            }
            document = sandbox_document(reader.read(payload, provider="upload"))
            held = document["network"].get(DNS_AS_WRITTEN_KEY)
            assert held != "FORGED-Z2"
            # Only the platform writes the key: a source's non-row value, beside requests.
            if held is not None:
                assert isinstance(reader, _KeepSourceStructuralReader)
                assert held == network["dns"]

    def test_a_laid_out_report_s_extras_never_hold_the_key(self) -> None:
        report = SandboxReport(
            provider="x",
            source_format="y",
            extras={"network": {DNS_AS_WRITTEN_KEY: "FORGED-Z2", "kept": 1}},
        )
        document = sandbox_document(report)
        assert DNS_AS_WRITTEN_KEY not in document["network"]
        assert document["network"]["kept"] == 1


_ARRANGEMENTS: tuple[Any, ...] = (
    "absent",
    {},
    {"dns": []},
    {"dns": "N/A"},
    {"dns": {"request": "own-z4.net"}},
    "unavailable",
    [1, 2],
    5,
    None,
    True,
)


class TestOnePlaceDecision:
    @pytest.mark.parametrize("network", _ARRANGEMENTS, ids=repr)
    @pytest.mark.parametrize("with_request", [True, False])
    def test_the_place_decision_is_the_document_s(self, network: Any, with_request: bool) -> None:
        from maljan.schemas.sandbox_document import dns_requests_have_place

        payload: dict[str, Any] = {"info": {"id": 1}}
        if network != "absent":
            payload["network"] = network
        reader: ReportReader = (
            _KeepSourceStructuralReader() if with_request else _KeepSourceReader()
        )
        if with_request:
            payload["message"] = _two_name_message()
        report = reader.read(payload, provider="upload")
        held = sandbox_document(report).get("network")
        rows = held.get("dns") if isinstance(held, dict) else None
        written = isinstance(rows, list) and any(
            isinstance(row, dict) and row.get("request") == "relay-b-s2.net" for row in rows
        )
        if with_request:
            assert dns_requests_have_place(report) == written
        else:
            assert not written


def test_a_bare_string_domains_row_is_projected_as_dev_projected_it() -> None:
    """``domains`` may hold bare names: dev projected each as a sandbox domain, and so does this.

    The expected rows were captured with dev's ``network_from_ledger``.
    """
    from maljan.reporting.ledger_projection import network_from_ledger
    from maljan.schemas.evidence import LedgerEntry

    data = {
        "domains": ["own-m6.example", " spaced-m6.example ", {"domain": "row-m6.example"}],
        "dns": [{"request": "dns-m6.example", "answers": [{"type": "A", "data": "45.33.32.9"}]}],
    }
    entry = LedgerEntry(id="ev_0001", agent="dynamic", tool="sandbox_network", structured=data)
    network = network_from_ledger([entry])
    assert network is not None
    assert sorted((d.fqdn, tuple(d.resolved_ips), d.source) for d in network.domains) == [
        ("dns-m6.example", ("45.33.32.9",), "sandbox"),
        ("own-m6.example", (), "sandbox"),
        ("row-m6.example", (), "sandbox"),
        ("spaced-m6.example", (), "sandbox"),
    ]


def _name_field_copies(source: str) -> list[tuple[int, str]]:
    """``(line, owner)`` of each tuple, list, set or ``.get`` chain naming two DNS name keys.

    The owner is the name the node is assigned to, else the function holding
    it, else empty.
    """
    import ast

    from maljan.schemas.sandbox_document import DNS_NAME_KEYS

    names = set(DNS_NAME_KEYS)
    tree = ast.parse(source)
    owner: dict[int, str] = {}
    stack: list[tuple[ast.AST, str]] = [(tree, "")]
    while stack:
        node, held = stack.pop()
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            held = node.name
        elif isinstance(node, ast.Assign | ast.AnnAssign):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            named = [t.id for t in targets if isinstance(t, ast.Name)]
            held = named[0] if named else held
        owner[id(node)] = held
        stack.extend((child, held) for child in ast.iter_child_nodes(node))

    def got(node: ast.AST) -> str:
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            return node.args[0].value
        return ""

    out: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Tuple | ast.List | ast.Set):
            words = {
                e.value
                for e in node.elts
                if isinstance(e, ast.Constant) and isinstance(e.value, str)
            }
        elif isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
            words = {got(value) for value in node.values} - {""}
        else:
            continue
        if len(words & names) >= 2:
            out.append((node.lineno, owner[id(node)]))
    return out

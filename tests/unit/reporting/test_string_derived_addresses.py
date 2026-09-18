"""A run of digits in a sample's bytes is not an address the sample reached for.

The domains got this rule, then the URLs. The addresses were the one network
kind with nothing asked of them at all: every value the string sweep read as an
address became an indicator, was charged to a reputation provider, and — once
the export's cap began ordering by how strong an origin was — ranked as though
a sandbox had watched it, because an address carried no origin to read. One
live bundle published ``[ipv4-addr:value = '6.0.0.0']``, a version number out
of the strings table.

Probed at fourteen such values against four observed C2 domains and four
observed C2 URLs, the export kept fourteen version numbers and no C2 endpoint.

Two questions, the same two the other kinds answer. Could this be somebody's
infrastructure: not loopback, unspecified, link-local, multicast, broadcast,
reserved or an address a document is written with, and a private address only
when somebody watched the sample reach it, because that is lateral movement
rather than a version number typed with dots in it. And does anything but the
file's own bytes know about it.
"""

from __future__ import annotations

import json
from typing import Any

from maljan.extractors.network_extractor import address_is_publishable, ip_corroboration_reason
from maljan.reporting.builder import MalwareReportBuilder
from maljan.reporting.ledger_projection import network_from_ledger
from maljan.reporting.models import (
    MalwareReport,
    NetworkDomain,
    NetworkIOCs,
    NetworkIP,
    NetworkURL,
)
from maljan.reporting.renderers.stix_renderer import ExtendedSTIXRenderer
from maljan.schemas.evidence import build_entry

# The shapes a string sweep produces: version numbers, build numbers, and the
# ranges a specification writes its examples with.
VERSION_SHAPED = (
    "6.0.0.0",
    "1.2.3.4",
    "5.0.0.0",
    "4.7.2.0",
    "8.0.1.0",
    "3.5.1.0",
    "2.0.5.0",
    "10.0.0.1",
    "172.16.0.1",
    "192.168.1.1",
    "192.0.2.5",
    "198.51.100.9",
    "203.0.113.7",
    "127.0.0.1",
)

# Real infrastructure, and the shape a live run's own C2 rows had.
C2_ADDRESSES = ("185.220.101.1", "194.5.212.124", "158.69.36.15", "45.147.230.9")


def _entry(seq: int, tool: str, payload: dict[str, Any]) -> Any:
    return build_entry(
        entry_id=f"ev_{seq:04d}",
        seq=seq,
        agent="static",
        tool=tool,
        args={},
        server="analysis",
        output=json.dumps(payload),
    )


def _report(network: NetworkIOCs) -> MalwareReport:
    report = MalwareReportBuilder(
        file_hash="c" * 64,
        file_name="sample.exe",
        sample_path=None,
        sandbox_report={},
        reports={},
        isr_reports={},
        stix_output={"objects": []},
        run_summary={},
        discussion_history=[],
        final_decision="Malware",
        overall_confidence=0.6,
        judge_assessment=None,
        malware_category="loader",
        sample_platform="windows",
        sample_file_type="pe",
        evidence_ledger=[],
    ).build_deterministic()
    report.network = network
    return report


def _patterns(bundle: Any) -> list[str]:
    return [
        str(getattr(obj, "pattern", ""))
        for obj in bundle.objects
        if getattr(obj, "type", "") == "indicator"
    ]


class TestWhetherAnAddressCouldBeInfrastructure:
    def test_the_classes_nothing_could_act_on_never_are(self) -> None:
        for address in (
            "127.0.0.1",
            "::1",
            "0.0.0.0",
            "169.254.1.1",
            "fe80::1",
            "224.0.0.1",
            "255.255.255.255",
            "not-an-address",
            "",
        ):
            for source in ("sandbox", "analyst", "strings", None):
                assert address_is_publishable(address, source) is False, (address, source)

    def test_the_ranges_a_document_is_written_with_never_are(self) -> None:
        for address in ("192.0.2.5", "198.51.100.9", "203.0.113.7", "2001:db8::1"):
            for source in ("sandbox", "strings"):
                assert address_is_publishable(address, source) is False, (address, source)

    def test_a_private_address_depends_on_who_saw_it(self) -> None:
        """A sandbox watching the sample reach 10.0.0.5 is lateral movement.

        ``100.64.0.0/10`` is the shared space a carrier puts between its
        subscribers and the internet. It belongs here rather than among the
        addresses nothing could act on, and it is named rather than reached
        through ``is_private``, which answers False for it.
        """
        for address in ("10.0.0.5", "172.16.0.1", "192.168.1.1", "100.64.0.1", "100.127.255.254"):
            assert address_is_publishable(address, "sandbox") is True, address
            assert address_is_publishable(address, "analyst") is True, address
            assert address_is_publishable(address, "strings") is False, address
            assert address_is_publishable(address, None) is False, address

    def test_a_routable_address_could(self) -> None:
        for address in (*C2_ADDRESSES, "2606:4700::1111"):
            assert address_is_publishable(address, "strings") is True, address


class TestWhoKnowsTheAddress:
    def test_a_string_derived_address_is_not_published_on_its_own(self) -> None:
        for address in C2_ADDRESSES:
            assert ip_corroboration_reason(address, "strings") is None, address

    def test_one_the_sandbox_watched_is(self) -> None:
        assert ip_corroboration_reason(C2_ADDRESSES[0], "sandbox") == "sandbox"

    def test_a_reputation_record_is_a_second_source(self) -> None:
        admitted = ip_corroboration_reason(C2_ADDRESSES[0], "strings", {"malicious": 7})

        assert admitted == "a reputation provider has a record of it"

    def test_a_version_number_is_refused_whatever_knows_it(self) -> None:
        assert ip_corroboration_reason("127.0.0.1", "sandbox") is None
        assert ip_corroboration_reason("192.0.2.5", "sandbox", {"malicious": 9}) is None


class TestWhereAnAddressCameFrom:
    def test_one_read_out_of_strings_says_so(self) -> None:
        network = network_from_ledger(
            [_entry(1, "iocs_from_file", {"iocs": [{"kind": "ip", "value": C2_ADDRESSES[0]}]})]
        )

        assert network is not None
        assert network.ips[0].source == "strings"

    def test_one_the_sandbox_watched_says_so(self) -> None:
        network = network_from_ledger(
            [_entry(1, "sandbox_network", {"hosts": [{"ip": C2_ADDRESSES[0]}]})]
        )

        assert network is not None
        assert network.ips[0].source == "sandbox"

    def test_a_destination_of_a_connection_says_so(self) -> None:
        network = network_from_ledger(
            [_entry(1, "sandbox_network", {"tcp": [{"dst": C2_ADDRESSES[1]}]})]
        )

        assert network is not None
        assert network.ips[0].source == "sandbox"

    def test_one_address_from_two_sources_is_credited_to_the_stronger(self) -> None:
        network = network_from_ledger(
            [
                _entry(1, "iocs_from_file", {"iocs": [{"kind": "ip", "value": C2_ADDRESSES[0]}]}),
                _entry(2, "sandbox_network", {"hosts": [{"ip": C2_ADDRESSES[0]}]}),
            ]
        )

        assert network is not None
        assert [ip.source for ip in network.ips] == ["sandbox"]

    def test_a_private_address_the_sandbox_watched_reaches_the_report(self) -> None:
        network = network_from_ledger(
            [_entry(1, "sandbox_network", {"tcp": [{"dst": "10.0.0.5"}]})]
        )

        assert network is not None
        assert [ip.address for ip in network.ips] == ["10.0.0.5"]

    def test_a_private_address_out_of_the_strings_does_not(self) -> None:
        network = network_from_ledger(
            [_entry(1, "iocs_from_file", {"iocs": [{"kind": "ip", "value": "10.0.0.5"}]})]
        )

        assert network is None


class TestWhatTheBundleCarries:
    def test_the_version_numbers_are_not_indicators(self) -> None:
        report = _report(
            NetworkIOCs(ips=[NetworkIP(address=a, source="strings") for a in VERSION_SHAPED])
        )

        bundle = ExtendedSTIXRenderer().render(report)

        assert not any("addr:value" in pattern for pattern in _patterns(bundle))

    def test_an_observed_address_is(self) -> None:
        report = _report(NetworkIOCs(ips=[NetworkIP(address=C2_ADDRESSES[0], source="sandbox")]))

        bundle = ExtendedSTIXRenderer().render(report)

        assert f"[ipv4-addr:value = '{C2_ADDRESSES[0]}']" in _patterns(bundle)

    def test_a_string_derived_one_a_provider_knows_is_published_with_the_reason(self) -> None:
        report = _report(
            NetworkIOCs(
                ips=[
                    NetworkIP(
                        address=C2_ADDRESSES[0], source="strings", reputation={"malicious": 7}
                    )
                ]
            )
        )

        bundle = ExtendedSTIXRenderer().render(report)

        indicator = next(
            obj
            for obj in bundle.objects
            if getattr(obj, "type", "") == "indicator" and "ipv4" in obj.pattern
        )
        assert indicator.description == "a reputation provider has a record of it"

    def test_a_page_of_version_numbers_does_not_crowd_out_the_endpoints(self) -> None:
        """Fourteen string-swept addresses against eight observed endpoints."""
        report = _report(
            NetworkIOCs(
                ips=[NetworkIP(address=a, source="strings") for a in VERSION_SHAPED],
                domains=[
                    NetworkDomain(fqdn=f"c2-{n}.example.org", source="sandbox") for n in range(4)
                ],
                urls=[
                    NetworkURL(url=f"https://c2-{n}.example.org/gate", source="sandbox")
                    for n in range(4)
                ],
            )
        )

        patterns = _patterns(ExtendedSTIXRenderer().render(report))

        assert not any("addr:value" in pattern for pattern in patterns)
        for n in range(4):
            assert f"[domain-name:value = 'c2-{n}.example.org']" in patterns
            assert f"[url:value = 'https://c2-{n}.example.org/gate']" in patterns


class TestWhatIsSentToAProvider:
    @staticmethod
    def _asked(ips: list[dict[str, Any]]) -> list[str]:
        import asyncio
        from unittest.mock import AsyncMock, MagicMock

        from maljan.enrichment.orchestrator import _enrich_ips

        vt = MagicMock()
        vt.ip_reputation = AsyncMock(return_value=None)
        abuse = MagicMock()
        abuse.ip_check = AsyncMock(return_value=None)
        whois = MagicMock()
        whois.asn_lookup = AsyncMock(return_value=None)
        whois.geoip = MagicMock(return_value=None)

        asyncio.run(_enrich_ips(ips, vt=vt, abuse=abuse, whois=whois, cap=25))
        return [call.args[0] for call in vt.ip_reputation.await_args_list]

    def test_a_string_derived_address_costs_no_lookup(self) -> None:
        asked = self._asked(
            [{"address": address, "source": "strings"} for address in VERSION_SHAPED]
        )

        assert asked == []

    def test_an_observed_address_is_looked_up(self) -> None:
        asked = self._asked([{"address": C2_ADDRESSES[0], "source": "sandbox"}])

        assert asked == [C2_ADDRESSES[0]]

    def test_the_budget_is_spent_on_what_is_worth_asking(self) -> None:
        """A page of string noise at the front used to spend the whole budget."""
        rows = [{"address": a, "source": "strings"} for a in VERSION_SHAPED]
        rows.append({"address": C2_ADDRESSES[0], "source": "sandbox"})

        assert self._asked(rows) == [C2_ADDRESSES[0]]

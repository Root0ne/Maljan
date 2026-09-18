"""A URL lying in a sample's bytes is not an endpoint the sample reached for.

The domain side of this rule was fixed; the URL side was not. One live bundle
published ``http://localho``, ``http://schq``, ``https://q``, ``http://3271``
and ``https://fs01n5.sends`` as ``url:value`` indicators — string-sweep
cut-offs, each one something a downstream consumer would block on — beside
GitHub and Microsoft schema URLs no one observed the sample request.

Two questions settle it, and keeping them apart is the point. Could this host
exist at all: a valid Tor address, an address literal that is not loopback,
unspecified or link-local, or a name whose labels are labels and whose last one
is a suffix rather than a word. And does anything but the file's own bytes know
about it, which is the one corroboration rule the domains already go through.
Four of the five above fail the first question; the fifth passes it and fails
the second, and the report says the true reason for each. Every path that mints
a ``url:value`` pattern asks both, including the judge's own indicator objects
— those are not published and the decline is recorded, never rewritten.

The cap is the same story from the other end: it counted the indicators this
renderer minted and not the ones it carried over from the judge, so a bundle
with two of the judge's and fourteen of its own shipped sixteen against a
ceiling of fifteen, and the report's own linter said so.
"""

from __future__ import annotations

import json
from typing import Any

from maljan.agents._indicator_denylists import MAX_TOTAL_INDICATORS
from maljan.extractors.network_extractor import host_is_public, url_corroboration_reason
from maljan.reporting.builder import MalwareReportBuilder
from maljan.reporting.ledger_projection import network_from_ledger
from maljan.reporting.models import MalwareReport, NetworkURL, StaticAnalysis, StringIOC
from maljan.reporting.renderers.stix_renderer import (
    UNPUBLISHABLE_URL_CODE,
    ExtendedSTIXRenderer,
    _indicator_for_url,
)
from maljan.schemas.evidence import build_entry
from maljan.schemas.stix_models import Bundle

# Four of the five the live bundle published: hosts nothing could ever answer
# for, whoever wrote them down.
CUT_OFF = (
    "http://localho",
    "http://schq",
    "https://q",
    "http://3271",
)

# The fifth. It is shaped like a host and could exist, so the host question
# passes it and the corroboration question is what holds it back — which is
# the difference the two questions are there to keep.
PLAUSIBLE = "https://fs01n5.sends"

REAL = (
    "http://schemas.microsoft.com/win/2004/08/events/event",
    "https://github.com/python/cpython/blob/abstract.c",
)


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


def _report(
    urls: list[NetworkURL], indicators: list[dict[str, Any]] | None = None
) -> MalwareReport:
    from maljan.reporting.models import NetworkIOCs

    report = MalwareReportBuilder(
        file_hash="b" * 64,
        file_name="sample.exe",
        sample_path=None,
        sandbox_report={},
        reports={},
        isr_reports={},
        stix_output={"objects": indicators or []},
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
    report.network = NetworkIOCs(urls=urls)
    return report


def _patterns(bundle: Bundle) -> list[str]:
    return [
        str(getattr(obj, "pattern", ""))
        for obj in bundle.objects
        if getattr(obj, "type", "") == "indicator"
    ]


def onion_address() -> str:
    """A v3 Tor address whose own checksum checks out.

    Built rather than written down, because the checksum is the only thing that
    makes one real and a literal in a file would be a literal somebody has to
    trust.
    """
    import base64
    import hashlib

    key = bytes(range(32))
    checksum = hashlib.sha3_256(b".onion checksum" + key + bytes([3])).digest()[:2]
    return base64.b32encode(key + checksum + bytes([3])).decode().lower() + ".onion"


class TestWhetherTheHostCouldExist:
    def test_a_cut_off_host_could_not(self) -> None:
        for url in CUT_OFF:
            assert url_corroboration_reason(url, "sandbox") is None, url

    def test_loopback_and_single_label_hosts_could_not(self) -> None:
        for host in ("localhost", "127.0.0.1", "::1", "0.0.0.0", "srv01", "localhost.localdomain"):
            assert host_is_public(host) is False, host

    def test_a_link_local_address_could_not(self) -> None:
        for host in ("169.254.1.1", "fe80::1"):
            assert host_is_public(host) is False, host

    def test_an_empty_label_could_not(self) -> None:
        """A residue of the same string-sweep family: ``http://.com``."""
        for host in (".com", "foo..com", "-lead.com", "trail-.com"):
            assert host_is_public(host) is False, host

    def test_a_real_name_or_address_could(self) -> None:
        for host in ("schemas.microsoft.com", "crl.sectigo.com", "185.220.101.1", "2001:db8::1"):
            assert host_is_public(host) is True, host

    def test_the_question_is_syntax_and_not_a_list_of_suffixes(self) -> None:
        """A list of the TLDs somebody wrote down is a list of the ones they knew.

        The one this replaces had 136 entries and no ``gov``, ``edu``,
        ``mobi``, no punycode TLD and most of two continents' ccTLDs missing,
        so a sandbox-observed request to a university host was dropped from the
        export with nothing said about it.
        """
        for host in (
            "files.compromised.university.edu",
            "portal.agency.gov",
            "a.mil",
            "x.mobi",
            "site.xn--p1ai",
            "host.iq",
            "host.qa",
            "host.et",
        ):
            assert host_is_public(host) is True, host

    def test_a_tor_address_could(self) -> None:
        """`.onion` never resolves; its own checksum is what confirms it."""
        assert host_is_public(onion_address()) is True

    def test_a_malformed_onion_could_not(self) -> None:
        assert host_is_public("notarealaddress.onion") is False

    def test_a_private_network_names_its_own_machines(self) -> None:
        """Publishing one is a low-value indicator and a small disclosure.

        Asked where an indicator is minted, so a name a sandbox resolved is
        still in the report's network block with the source that saw it. It
        used to be asked at the projection, which erased the observation.
        """
        for host in ("sub.corp.internal", "printer.alt", "nas.home.arpa"):
            assert host_is_public(host) is False, host

    def test_the_question_is_asked_of_every_source(self) -> None:
        """A sandbox that recorded a cut-off recorded a cut-off."""
        assert url_corroboration_reason("http://localhost:8080", "sandbox") is None


class TestWhoKnowsTheEndpoint:
    def test_a_string_derived_url_is_not_published_on_its_own(self) -> None:
        for url in REAL:
            assert url_corroboration_reason(url, "strings") is None, url

    def test_one_the_sandbox_watched_is(self) -> None:
        assert url_corroboration_reason(REAL[0], "sandbox") == "sandbox"

    def test_a_reputation_record_is_a_second_source(self) -> None:
        admitted = url_corroboration_reason(REAL[0], "strings", {"malicious": 3})

        assert admitted == "a reputation provider has a record of it"

    def test_a_tor_address_is_publishable_from_every_source(self) -> None:
        """The carve-out the domains have, for the reason the domains have it.

        Holding a hidden service to "a second source knows it" makes the
        strongest string-derived indicator there is unpublishable by any path,
        because nothing can ever be the second source.
        """
        url = f"http://{onion_address()}/gate.php"

        assert url_corroboration_reason(url, "strings") == (
            "tor hidden service address, valid on its own syntax"
        )
        for source in ("sandbox", "analyst", "judge"):
            assert url_corroboration_reason(url, source) == source, source

    def test_a_plausible_host_is_still_held_back_for_want_of_a_second_source(self) -> None:
        """The host question and the corroboration question are different questions.

        ``fs01n5.sends`` is shaped like a host and could exist; nothing but the
        file's own bytes says it does. It is unpublished for that reason and
        not for the shape of its name.
        """
        assert host_is_public("fs01n5.sends") is True
        assert url_corroboration_reason(PLAUSIBLE, "strings") is None
        assert url_corroboration_reason(PLAUSIBLE, "sandbox") == "sandbox"

    def test_the_indicator_shows_where_a_string_derived_one_came_from(self) -> None:
        from maljan.reporting.models import NetworkDomain

        url = NetworkURL(url="http://c2.example.org/gate.php", source="strings")
        report = _report([url])
        report.network.domains.append(
            NetworkDomain(fqdn="c2.example.org", source="strings", reputation={"malicious": 2})
        )

        indicator = _indicator_for_url(url, report)

        assert indicator is not None
        assert indicator.description == "a reputation provider has a record of it"


class TestWhereTheUrlCameFrom:
    def test_a_url_read_out_of_strings_says_so(self) -> None:
        network = network_from_ledger(
            [_entry(1, "iocs_from_file", {"iocs": [{"kind": "url", "value": REAL[0]}]})]
        )

        assert network is not None
        assert network.urls[0].source == "strings"

    def test_a_request_the_sandbox_watched_says_so(self) -> None:
        network = network_from_ledger(
            [
                _entry(
                    1,
                    "sandbox_network",
                    {"http": [{"host": "schemas.microsoft.com", "uri": "/win/2004/08"}]},
                )
            ]
        )

        assert network is not None
        assert network.urls[0].source == "sandbox"

    def test_one_endpoint_from_two_sources_is_credited_to_the_stronger(self) -> None:
        network = network_from_ledger(
            [
                _entry(1, "iocs_from_file", {"iocs": [{"kind": "url", "value": REAL[0]}]}),
                _entry(
                    2,
                    "sandbox_network",
                    {
                        "http": [
                            {"host": "schemas.microsoft.com", "uri": "/win/2004/08/events/event"}
                        ]
                    },
                ),
            ]
        )

        assert network is not None
        assert [u.source for u in network.urls] == ["sandbox"]


class TestWhatTheBundleCarries:
    def test_the_cut_offs_are_not_indicators(self) -> None:
        report = _report(
            [NetworkURL(url=url, source="strings") for url in (*CUT_OFF, PLAUSIBLE, *REAL)]
        )

        bundle = ExtendedSTIXRenderer().render(report)

        assert not any("url:value" in pattern for pattern in _patterns(bundle))

    def test_an_observed_url_is(self) -> None:
        report = _report([NetworkURL(url=REAL[0], source="sandbox")])

        bundle = ExtendedSTIXRenderer().render(report)

        assert f"[url:value = '{REAL[0]}']" in _patterns(bundle)

    def test_the_judge_own_unpublishable_url_is_declined_and_recorded(self) -> None:
        base = Bundle.model_validate(
            {
                "objects": [
                    {
                        "type": "indicator",
                        "id": "indicator--0f1e2d3c-4b5a-4968-8776-655443332201",
                        "pattern": "[url:value = 'http://localho']",
                        "pattern_type": "stix",
                    }
                ]
            }
        )
        renderer = ExtendedSTIXRenderer()

        bundle = renderer.render(_report([]), base_bundle=base)

        assert not any("localho" in pattern for pattern in _patterns(bundle))
        assert [code for code, _why in renderer.declined] == [UNPUBLISHABLE_URL_CODE]
        assert "http://localho" in renderer.declined[0][1]

    def test_the_judge_own_bundle_is_not_edited(self) -> None:
        base = Bundle.model_validate(
            {
                "objects": [
                    {
                        "type": "indicator",
                        "id": "indicator--0f1e2d3c-4b5a-4968-8776-655443332201",
                        "pattern": "[url:value = 'https://q']",
                        "pattern_type": "stix",
                    }
                ]
            }
        )

        ExtendedSTIXRenderer().render(_report([]), base_bundle=base)

        assert _patterns(base) == ["[url:value = 'https://q']"]

    def test_an_observed_url_that_is_declined_is_recorded(self) -> None:
        """A sandbox row is not a string sweep's leftover, and has a reader."""
        renderer = ExtendedSTIXRenderer()
        report = _report([NetworkURL(url="http://localho", source="sandbox")])

        renderer.render(report)

        assert [code for code, _why in renderer.declined] == [UNPUBLISHABLE_URL_CODE]
        assert "not a name or address that could exist" in renderer.declined[0][1]

    def test_a_string_derived_url_held_back_is_not_a_finding(self) -> None:
        """The corroboration rule working is not something to report."""
        renderer = ExtendedSTIXRenderer()

        renderer.render(_report([NetworkURL(url=REAL[0], source="strings")]))

        assert renderer.declined == []

    def test_a_row_with_no_recorded_source_is_read_as_string_derived(self) -> None:
        """One reading of "unrecorded", not two.

        The publish rule asked corroboration of a source-less row and got
        "recorded without a source", which publishes; the cap ranked the same
        row as an observation. Only rows persisted before the field existed
        reach this, and they are the weakest claim there is.
        """
        renderer = ExtendedSTIXRenderer()

        bundle = renderer.render(_report([NetworkURL(url=REAL[0], source=None)]))

        assert not any("url:value" in pattern for pattern in _patterns(bundle))
        assert renderer.declined == []

    def test_an_impossible_host_is_recorded_when_somebody_watched_the_row(self) -> None:
        for source in ("sandbox", "analyst"):
            renderer = ExtendedSTIXRenderer()

            renderer.render(_report([NetworkURL(url="http://localho", source=source)]))

            assert [code for code, _why in renderer.declined] == [UNPUBLISHABLE_URL_CODE], source

    def test_a_string_sweep_cut_off_is_not_a_finding_anybody_can_act_on(self) -> None:
        """One report's forty of them would bury the rows a reader can act on."""
        renderer = ExtendedSTIXRenderer()

        renderer.render(
            _report([NetworkURL(url=url, source="strings") for url in (*CUT_OFF, PLAUSIBLE)])
        )

        assert renderer.declined == []

    def test_a_declined_url_never_carries_a_credential_into_the_record(self) -> None:
        from tests.credential_shapes import prefixed_key

        secret = prefixed_key("ghs_")
        base = Bundle.model_validate(
            {
                "objects": [
                    {
                        "type": "indicator",
                        "id": "indicator--0f1e2d3c-4b5a-4968-8776-655443332201",
                        "pattern": f"[url:value = 'http://operator:{secret}@localho/']",
                        "pattern_type": "stix",
                    }
                ]
            }
        )
        renderer = ExtendedSTIXRenderer()

        renderer.render(_report([]), base_bundle=base)

        _code, why = renderer.declined[0]
        assert secret not in why
        assert "operator" not in why
        assert len(why) < 400

    def test_a_declined_url_is_bounded_however_long_the_model_wrote_it(self) -> None:
        base = Bundle.model_validate(
            {
                "objects": [
                    {
                        "type": "indicator",
                        "id": "indicator--0f1e2d3c-4b5a-4968-8776-655443332201",
                        "pattern": f"[url:value = 'http://{'n' * 4000}']",
                        "pattern_type": "stix",
                    }
                ]
            }
        )
        renderer = ExtendedSTIXRenderer()

        renderer.render(_report([]), base_bundle=base)

        assert len(renderer.declined[0][1]) < 400


class TestTheCapHoldsAtTheRenderer:
    @staticmethod
    def _judge_indicators(count: int) -> list[dict[str, Any]]:
        return [
            {
                "type": "indicator",
                "id": f"indicator--0f1e2d3c-4b5a-4968-8776-6554433322{n:02d}",
                "pattern": f"[file:name = 'judge{n}.exe']",
                "pattern_type": "stix",
            }
            for n in range(count)
        ]

    def test_the_judge_indicators_count_against_the_budget(self) -> None:
        base = Bundle.model_validate({"objects": self._judge_indicators(4)})
        report = _report(
            [
                NetworkURL(url=f"https://host{n}.example.org/p", source="sandbox")
                for n in range(MAX_TOTAL_INDICATORS)
            ]
        )

        bundle = ExtendedSTIXRenderer().render(report, base_bundle=base)

        assert len(_patterns(bundle)) == MAX_TOTAL_INDICATORS

    def test_the_priority_order_is_hashes_then_network_then_file_names(self) -> None:
        base = Bundle.model_validate({"objects": self._judge_indicators(MAX_TOTAL_INDICATORS)})
        report = _report(
            [
                NetworkURL(url=f"https://host{n}.example.org/p", source="sandbox")
                for n in range(MAX_TOTAL_INDICATORS)
            ]
        )

        patterns = _patterns(ExtendedSTIXRenderer().render(report, base_bundle=base))

        assert len(patterns) == MAX_TOTAL_INDICATORS
        assert patterns[0].startswith("[file:hashes")
        assert all(p.startswith("[url:value") for p in patterns[1:])

    def test_a_bundle_under_the_cap_keeps_everything(self) -> None:
        base = Bundle.model_validate({"objects": self._judge_indicators(2)})
        report = _report([NetworkURL(url=REAL[0], source="sandbox")])

        patterns = _patterns(ExtendedSTIXRenderer().render(report, base_bundle=base))

        assert len(patterns) == 4

    def test_the_sample_own_hash_is_never_pushed_out_by_the_judge_hashes(self) -> None:
        judged = [
            {
                "type": "indicator",
                "id": f"indicator--0f1e2d3c-4b5a-4968-8776-6554433321{n:02d}",
                "pattern": f"[file:hashes.'SHA-1' = '{n:040x}']",
                "pattern_type": "stix",
            }
            for n in range(MAX_TOTAL_INDICATORS + 5)
        ]
        report = _report([])

        patterns = _patterns(
            ExtendedSTIXRenderer().render(
                report, base_bundle=Bundle.model_validate({"objects": judged})
            )
        )

        assert len(patterns) == MAX_TOTAL_INDICATORS
        assert patterns[0] == f"[file:hashes.'SHA-256' = '{'b' * 64}']"

    def test_a_compound_hash_pattern_is_read_as_a_hash(self) -> None:
        """The judge writes one: an imphash or a SHA-1 in the same expression."""
        from maljan.reporting.renderers.stix_renderer import _BAND_JUDGE_HASH, _indicator_band

        compound = (
            "[file:extensions['pe'].pe_imphash = 'b15607f10222dbea' OR "
            "file:hashes.'SHA-1' = '0456c056dfb21549']"
        )

        assert _indicator_band(compound) == _BAND_JUDGE_HASH


class TestWhatTheCapSpendsItsBudgetOn:
    """The order the report's own linter describes, over what will be exported.

    A probe of 31 candidates against a ceiling of fifteen — four judge URLs,
    the sample's hash, eight sandbox domains that also appear in the string
    scan, five C2 addresses and five sandbox URLs — shipped thirteen: two slots
    went to string rows that duplicated a network row queued behind them and
    were deleted afterwards, and every observed address and URL was cut.
    """

    @staticmethod
    def _crowded() -> tuple[MalwareReport, Bundle]:
        from maljan.reporting.models import NetworkDomain, NetworkIOCs, NetworkIP

        judged = {
            "objects": [
                {
                    "type": "indicator",
                    "id": f"indicator--0f1e2d3c-4b5a-4968-8776-6554433322{n:02d}",
                    "pattern": f"[url:value = 'https://judge{n}.example.org/p']",
                    "pattern_type": "stix",
                }
                for n in range(4)
            ]
        }
        report = _report([], judged["objects"])
        report.network = NetworkIOCs(
            domains=[NetworkDomain(fqdn=f"c2-{n}.example.org", source="sandbox") for n in range(8)],
            ips=[NetworkIP(address=f"185.220.101.{n + 1}") for n in range(5)],
            urls=[
                NetworkURL(url=f"https://obs{n}.example.net/p", source="sandbox") for n in range(5)
            ],
        )
        report.static = StaticAnalysis(
            interesting_strings=[
                StringIOC(kind="domain", value=f"c2-{n}.example.org", notes="") for n in range(8)
            ]
        )
        return report, Bundle.model_validate(judged)

    def test_a_bundle_over_the_cap_ships_exactly_at_it(self) -> None:
        report, base = self._crowded()

        patterns = _patterns(ExtendedSTIXRenderer().render(report, base_bundle=base))

        assert len(patterns) == MAX_TOTAL_INDICATORS

    def test_the_observed_addresses_and_urls_are_kept(self) -> None:
        report, base = self._crowded()

        patterns = _patterns(ExtendedSTIXRenderer().render(report, base_bundle=base))

        for n in range(5):
            assert f"[ipv4-addr:value = '185.220.101.{n + 1}']" in patterns
            assert f"[url:value = 'https://obs{n}.example.net/p']" in patterns

    def test_a_string_row_never_outranks_the_network_row_it_duplicates(self) -> None:
        """They are one indicator written twice, and the observation is the one kept."""
        report, base = self._crowded()

        bundle = ExtendedSTIXRenderer().render(report, base_bundle=base)

        domains = [p for p in _patterns(bundle) if p.startswith("[domain-name:value")]
        assert domains, "the observed domains fill what is left of the budget"
        assert len(set(domains)) == len(domains), "no name is exported twice"

    def test_the_judge_assertions_give_way_to_what_was_observed(self) -> None:
        report, base = self._crowded()

        patterns = _patterns(ExtendedSTIXRenderer().render(report, base_bundle=base))

        assert not any("judge" in pattern for pattern in patterns)

"""A URL lying in a sample's bytes is not an endpoint the sample reached for.

The domain side of this rule was fixed; the URL side was not. One live bundle
published ``http://localho``, ``http://schq``, ``https://q``, ``http://3271``
and ``https://fs01n5.sends`` as ``url:value`` indicators — string-sweep
cut-offs, each one something a downstream consumer would block on — beside
GitHub and Microsoft schema URLs no one observed the sample request.

Two questions settle it, in the order they are asked. Could this host exist at
all: an address that is not loopback, or a name that is not reserved, has more
than one label and ends in a real TLD. And does anything but the file's own
bytes know about it, which is the one corroboration rule the domains already go
through. Every path that mints a ``url:value`` pattern asks both, including the
judge's own indicator objects — those are not published and the decline is
recorded, never rewritten.

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
from maljan.reporting.models import MalwareReport, NetworkURL
from maljan.reporting.renderers.stix_renderer import (
    UNPUBLISHABLE_URL_CODE,
    ExtendedSTIXRenderer,
    _indicator_for_url,
)
from maljan.schemas.evidence import build_entry
from maljan.schemas.stix_models import Bundle

# The five the live bundle published, and the two real ones beside them.
CUT_OFF = (
    "http://localho",
    "http://schq",
    "https://q",
    "http://3271",
    "https://fs01n5.sends",
)
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


class TestWhetherTheHostCouldExist:
    def test_a_cut_off_host_could_not(self) -> None:
        for url in CUT_OFF:
            assert url_corroboration_reason(url, "sandbox") is None, url

    def test_loopback_and_single_label_hosts_could_not(self) -> None:
        for host in ("localhost", "127.0.0.1", "::1", "0.0.0.0", "srv01", "localhost.localdomain"):
            assert host_is_public(host) is False, host

    def test_a_real_name_or_address_could(self) -> None:
        for host in ("schemas.microsoft.com", "crl.sectigo.com", "185.220.101.1"):
            assert host_is_public(host) is True, host

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
        report = _report([NetworkURL(url=url, source="strings") for url in (*CUT_OFF, *REAL)])

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

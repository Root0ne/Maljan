"""A published URL's well-known host waits for a model, and a table reads the report once.

A URL's host follows the URL's decision, except a well-known benign host: a
judge's URL on a CDN or a cloud API would otherwise publish the provider's
name as a C2 domain. And the rule's report-wide lookups — which URLs publish,
the network block's rows by value, the judge's values — are built once per
table, export or feed rather than once per row, which made a few hundred rows
take seconds.
"""

from __future__ import annotations

from typing import Any

from maljan.reporting import builder
from maljan.reporting.models import MalwareReport, NetworkDomain, NetworkIOCs, NetworkURL
from maljan.reporting.renderers import stix_renderer
from maljan.reporting.renderers.stix_renderer import ExtendedSTIXRenderer

CDN_URL = "https://www.googleapis.com/upload/x"


def _report(network: NetworkIOCs) -> MalwareReport:
    return MalwareReport.model_validate(
        {
            "identity": {"hashes": {"sha256": "a" * 64}},
            "verdict": "Malware",
            "overall_confidence": 0.9,
            "network": network.model_dump(),
        }
    )


def _row(report: MalwareReport, value: str) -> Any:
    return next(r for r in builder.build_consolidated_iocs(report) if r.value == value)


class TestAWellKnownHostOfAPublishedURL:
    def test_it_is_not_published_on_the_url_alone(self) -> None:
        report = _report(NetworkIOCs(urls=[NetworkURL(url=CDN_URL, source="sandbox")]))

        assert _row(report, CDN_URL).published == "yes"
        answer = _row(report, "www.googleapis.com").published

        assert answer == (
            f"no: a well-known benign name carried by a published URL ({CDN_URL}), and no "
            "model kept it as an indicator"
        )

    def test_an_analyst_keeping_the_host_itself_publishes_it(self) -> None:
        report = _report(
            NetworkIOCs(
                urls=[NetworkURL(url=CDN_URL, source="sandbox")],
                domains=[
                    NetworkDomain(
                        fqdn="www.googleapis.com",
                        source="analyst",
                        kept_by=["an artifact of the network analyst"],
                    )
                ],
            )
        )

        assert _row(report, "www.googleapis.com").published == "yes"


class TestTheReportIsReadOnce:
    @staticmethod
    def _big() -> MalwareReport:
        return _report(
            NetworkIOCs(
                urls=[
                    NetworkURL(url=f"https://relay-{n}.example-c2.top/p", source="sandbox")
                    for n in range(60)
                ],
                domains=[
                    NetworkDomain(fqdn=f"relay-{n}.example-c2.top", source="sandbox")
                    for n in range(60)
                ],
            )
        )

    def test_the_published_urls_are_computed_once_per_table(self, monkeypatch: Any) -> None:
        calls: list[int] = []
        real = stix_renderer._published_url_hosts

        def _counted(report: Any) -> Any:
            calls.append(1)
            return real(report)

        monkeypatch.setattr(stix_renderer, "_published_url_hosts", _counted)

        rows = builder.build_consolidated_iocs(self._big())

        assert len([r for r in rows if r.kind == "domain"]) == 60
        assert len(calls) == 1

    def test_and_once_per_export(self, monkeypatch: Any) -> None:
        calls: list[int] = []
        real = stix_renderer._published_url_hosts

        def _counted(report: Any) -> Any:
            calls.append(1)
            return real(report)

        monkeypatch.setattr(stix_renderer, "_published_url_hosts", _counted)

        ExtendedSTIXRenderer().render(self._big())

        assert len(calls) == 1

    def test_outside_a_reading_nothing_is_kept_between_calls(self) -> None:
        report = self._big()
        first = stix_renderer.published_url_hosts(report)
        report.network.urls.clear()  # type: ignore[union-attr]

        assert stix_renderer.published_url_hosts(report) != first


class TestTheExportCarriesEveryPublishedRow:
    def test_no_slice_of_the_network_block_cuts_what_the_table_publishes(
        self, monkeypatch: Any
    ) -> None:
        """The one indicator cap is the export's only bound, and it records what it drops."""
        report = _report(
            NetworkIOCs(
                urls=[
                    NetworkURL(url=f"https://relay-{n}.example-c2.top/p", source="sandbox")
                    for n in range(45)
                ]
            )
        )
        published = {
            r.value for r in builder.build_consolidated_iocs(report) if r.published == "yes"
        }

        bundle = ExtendedSTIXRenderer().render(report)
        patterns = {str(getattr(o, "pattern", "")) for o in bundle.objects}

        network = {v for v in published if v.startswith("https://") or v.startswith("relay-")}
        assert len(network) == 90
        for value in network:
            kind = "url" if value.startswith("https://") else "domain-name"
            assert f"[{kind}:value = '{value}']" in patterns

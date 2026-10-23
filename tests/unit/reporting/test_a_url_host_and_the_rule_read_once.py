"""A published URL's well-known host waits for the judge, and a table reads the report once.

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
from maljan.reporting.models import (
    JudgeIndicator,
    MalwareReport,
    NetworkDomain,
    NetworkIOCs,
    NetworkURL,
)
from maljan.reporting.renderers import stix_renderer
from maljan.reporting.renderers.stix_renderer import ExtendedSTIXRenderer, publishes

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

        assert publishes(_row(report, CDN_URL).published)
        answer = _row(report, "www.googleapis.com").published

        assert answer == (
            f"no: a well-known benign name carried by a published URL ({CDN_URL}), and no "
            "model kept it as an indicator"
        )

    @staticmethod
    def _listed() -> MalwareReport:
        return _report(
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

    def test_an_analyst_listing_the_host_itself_does_not_publish_it(self) -> None:
        answer = _row(self._listed(), "www.googleapis.com").published

        assert answer == (
            f"no: a well-known benign name carried by a published URL ({CDN_URL}); an "
            "artifact of the network analyst lists it, and a listing does not change what the "
            "sandbox recorded about it; the judge did not keep it as an indicator"
        )

    def test_the_judge_keeping_the_host_itself_publishes_it(self) -> None:
        report = self._listed()
        report.judge_indicators = [JudgeIndicator(kind="domain", value="www.googleapis.com")]

        assert publishes(_row(report, "www.googleapis.com").published)

    def test_a_storage_endpoint_is_not_published_through_a_url_on_it(self) -> None:
        url = "https://storage.googleapis.com/some-bucket/stage2.bin"
        report = _report(NetworkIOCs(urls=[NetworkURL(url=url, source="sandbox")]))

        assert publishes(_row(report, url).published)
        assert not publishes(_row(report, "storage.googleapis.com").published)


TENANT = "evil-bucket.s3.amazonaws.com"
TENANT_URL = f"https://{TENANT}/stage2.bin"


class TestATenantHostOfSharedHosting:
    """A bucket on shared hosting is its tenant's: not benign, and published on
    evidence of its own, never because a published URL carries it."""

    def test_the_url_alone_does_not_publish_it(self) -> None:
        report = _report(NetworkIOCs(urls=[NetworkURL(url=TENANT_URL, source="sandbox")]))

        assert publishes(_row(report, TENANT_URL).published)
        assert _row(report, TENANT).published == (
            "no: a tenant's name on shared hosting carried by a published URL, with no "
            f"evidence of its own ({TENANT_URL}), and no model kept it as an indicator"
        )

    def test_the_guests_resolution_alone_does_not_publish_it(self) -> None:
        """Guest DNS is not the tenant name's own evidence: the row is held as a
        name the guest resolved until a keep, a tree flow or a recovery backs it."""
        report = _report(
            NetworkIOCs(
                urls=[NetworkURL(url=TENANT_URL, source="sandbox")],
                domains=[NetworkDomain(fqdn=TENANT, source="sandbox")],
            )
        )

        answer = _row(report, TENANT).published
        assert not publishes(answer)
        assert "with no evidence of its own" in answer

    def test_the_judge_keeping_it_publishes_it(self) -> None:
        report = _report(NetworkIOCs(urls=[NetworkURL(url=TENANT_URL, source="sandbox")]))
        report.judge_indicators = [JudgeIndicator(kind="domain", value=TENANT)]

        assert publishes(_row(report, TENANT).published)


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
            r.value for r in builder.build_consolidated_iocs(report) if publishes(r.published)
        }

        bundle = ExtendedSTIXRenderer().render(report)
        patterns = {str(getattr(o, "pattern", "")) for o in bundle.objects}

        network = {v for v in published if v.startswith("https://") or v.startswith("relay-")}
        assert len(network) == 90
        for value in network:
            kind = "url" if value.startswith("https://") else "domain-name"
            assert f"[{kind}:value = '{value}']" in patterns

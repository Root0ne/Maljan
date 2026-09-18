"""A name lying in a sample's bytes is not a name the sample reached for.

The string sweep over one PE returned twenty-five domains, every one of them
published as a STIX indicator and charged to a reputation provider. Most were
fragments of longer names, identifiers or rows out of a detection-name table.
The scan still reports them — they are strings, and they are in the file — but
the report says where each came from, and only a name a second source knows
about is offered to the world as an indicator.
"""

from __future__ import annotations

import json
from typing import Any

from maljan.reporting.ledger_projection import network_from_ledger
from maljan.reporting.models import NetworkDomain, NetworkIOCs
from maljan.reporting.renderers.stix_renderer import _indicator_for_domain
from maljan.schemas.evidence import build_entry


def _entry(seq: int, tool: str, payload: dict[str, object]) -> object:
    return build_entry(
        entry_id=f"ev_{seq:04d}",
        seq=seq,
        agent="static",
        tool=tool,
        args={},
        server="analysis",
        output=json.dumps(payload),
    )


def _by_fqdn(network: NetworkIOCs | None) -> dict[str, NetworkDomain]:
    assert network is not None
    return {domain.fqdn: domain for domain in network.domains}


class TestWhereADomainCameFrom:
    def test_a_domain_read_out_of_strings_says_so(self) -> None:
        network = _by_fqdn(
            network_from_ledger(
                [
                    _entry(
                        1,
                        "iocs_from_file",
                        {"iocs": [{"kind": "domain", "value": "rosoft.com", "notes": None}]},
                    )
                ]
            )
        )
        assert network["rosoft.com"].source == "strings"

    def test_a_domain_the_sandbox_watched_says_so(self) -> None:
        network = _by_fqdn(
            network_from_ledger([_entry(1, "sandbox_network", {"dns": [{"request": "evil.com"}]})])
        )
        assert network["evil.com"].source == "sandbox"

    def test_a_name_both_sources_carry_is_credited_to_the_stronger_one(self) -> None:
        """Corroboration is the whole point: one source cannot supply it."""
        network = _by_fqdn(
            network_from_ledger(
                [
                    _entry(
                        1,
                        "iocs_from_file",
                        {"iocs": [{"kind": "domain", "value": "evil.com", "notes": None}]},
                    ),
                    _entry(2, "sandbox_network", {"dns": [{"request": "evil.com"}]}),
                ]
            )
        )
        assert network["evil.com"].source == "sandbox"


class TestWhichDomainsBecomeIndicators:
    def test_a_string_derived_name_alone_is_not_published_as_an_indicator(self) -> None:
        assert _indicator_for_domain(NetworkDomain(fqdn="rosoft.com", source="strings")) is None

    def test_a_sandbox_name_is_published(self) -> None:
        indicator = _indicator_for_domain(NetworkDomain(fqdn="evil.com", source="sandbox"))
        assert indicator is not None
        assert indicator.pattern == "[domain-name:value = 'evil.com']"

    def test_a_string_derived_name_a_provider_calls_malicious_is_published(self) -> None:
        """A reputation hit is the second source the rule asks for."""
        domain = NetworkDomain(
            fqdn="onclklnd.com",
            source="strings",
            reputation={"source": "virustotal", "malicious": 9},
        )
        assert _indicator_for_domain(domain) is not None

    def test_a_domain_with_no_recorded_source_is_published_as_before(self) -> None:
        """Every other producer of this block is unchanged by the rule."""
        assert _indicator_for_domain(NetworkDomain(fqdn="evil.com")) is not None


class TestNoStringDerivedDomainReachesTheBundle:
    """The gate has to be on every path that mints a domain indicator.

    Gating `_indicator_for_domain` alone left the other one open: the same
    rows also reach `static.interesting_strings`, and the renderer turns those
    into `[domain-name:value = …]` indicators of their own. A bundle rendered
    from a string sweep beside one sandbox resolution still shipped the
    fragments.
    """

    def _report(self) -> Any:
        from maljan.reporting.builder import MalwareReportBuilder

        rows = [
            {"kind": "domain", "value": "rosoft.com", "notes": None, "source": "strings"},
            {"kind": "domain", "value": "jector.sa", "notes": None, "source": "strings"},
            {"kind": "domain", "value": "c2.evil.tld", "notes": None, "source": "strings"},
        ]
        ledger = [
            _entry(1, "iocs_from_file", {"iocs": rows}),
            _entry(2, "sandbox_network", {"dns": [{"request": "c2.evil.tld"}]}),
        ]
        return MalwareReportBuilder(
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
            overall_confidence=0.8,
            judge_assessment=None,
            malware_category="rat",
            evidence_ledger=ledger,
        ).build_deterministic()

    def _patterns(self) -> list[str]:
        from maljan.reporting.renderers.stix_renderer import ExtendedSTIXRenderer
        from maljan.schemas.stix_models import Indicator

        bundle = ExtendedSTIXRenderer().render(self._report(), base_bundle=None)
        return [o.pattern for o in bundle.objects if isinstance(o, Indicator)]

    def test_the_fragments_are_in_no_stix_object(self) -> None:
        rendered = " ".join(self._patterns())
        assert "rosoft.com" not in rendered
        assert "jector.sa" not in rendered

    def test_a_corroborated_domain_is_published(self) -> None:
        assert "[domain-name:value = 'c2.evil.tld']" in self._patterns()

    def test_the_report_still_carries_every_name_it_read(self) -> None:
        """Withheld from the bundle is not deleted from the report."""
        report = self._report()
        assert report.network is not None
        assert {d.fqdn for d in report.network.domains} >= {"rosoft.com", "jector.sa"}


class TestTheReportSaysWhereEachNameCameFrom:
    """ "Labelled" has to be true where somebody reads it.

    The field was recorded and the bundle was gated on it, and the Markdown
    table still printed a byte-image fragment and a name the sandbox resolved
    in the same five columns. A reader comparing the table with the exported
    bundle had nothing to explain the difference.
    """

    def _markdown(self) -> str:
        from maljan.reporting.renderers.markdown import MarkdownRenderer

        report = TestNoStringDerivedDomainReachesTheBundle()._report()
        return MarkdownRenderer().render(report)

    def test_the_domains_table_carries_a_source_column(self) -> None:
        markdown = self._markdown()
        assert "| FQDN | Source | Suspicious |" in markdown

    def test_each_row_names_its_own_source(self) -> None:
        rows = [line for line in self._markdown().splitlines() if line.startswith("| `")]
        by_fqdn = {line.split("`")[1]: line for line in rows}
        assert "| strings |" in by_fqdn["rosoft.com"]
        assert "| sandbox |" in by_fqdn["c2.evil.tld"]


def _a_v3_onion() -> str:
    """A syntactically valid v3 address, built here rather than taken from a sample."""
    import base64
    import hashlib

    public_key = hashlib.sha256(b"maljan test onion service key").digest()
    version = b"\x03"
    checksum = hashlib.sha3_256(b".onion checksum" + public_key + version).digest()[:2]
    return base64.b32encode(public_key + checksum + version).decode().lower() + ".onion"


class TestATorAddressCorroboratesItself:
    """No sandbox can ever confirm one, because `.onion` does not resolve.

    A hard-coded onion C2 is among the strongest string-derived indicators
    there is, and it is not a coincidence of bytes the way a truncated
    hostname is: fifty-six base32 characters whose last three bytes check out
    against the first thirty-two do not occur by accident. Holding it to the
    same corroboration rule as `rosoft.com` made it unpublishable by any path.
    """

    def _patterns(self, value: str) -> list[str]:
        from maljan.reporting.builder import MalwareReportBuilder
        from maljan.reporting.renderers.stix_renderer import ExtendedSTIXRenderer
        from maljan.schemas.stix_models import Indicator

        rows = [{"kind": "domain", "value": value, "notes": "tor_hidden_service"}]
        report = MalwareReportBuilder(
            file_hash="d" * 64,
            file_name="sample.exe",
            sample_path=None,
            sandbox_report={},
            reports={},
            isr_reports={},
            stix_output={"objects": []},
            run_summary={},
            discussion_history=[],
            final_decision="Malware",
            overall_confidence=0.8,
            judge_assessment=None,
            malware_category="rat",
            evidence_ledger=[_entry(1, "iocs_from_file", {"iocs": rows})],
        ).build_deterministic()
        bundle = ExtendedSTIXRenderer().render(report, base_bundle=None)
        return [o.pattern for o in bundle.objects if isinstance(o, Indicator)]

    def test_a_valid_v3_address_is_published(self) -> None:
        onion = _a_v3_onion()
        assert f"[domain-name:value = '{onion}']" in self._patterns(onion)

    def test_a_v2_address_is_published(self) -> None:
        onion = "expyuzz4wqqyqhjn.onion"
        assert f"[domain-name:value = '{onion}']" in self._patterns(onion)

    def test_fifty_six_characters_that_fail_the_checksum_are_not(self) -> None:
        """Length and alphabet alone are a shape anything can wear."""
        broken = "a" * 56 + ".onion"
        assert not any("onion" in pattern for pattern in self._patterns(broken))

    def test_an_ordinary_string_derived_name_is_still_withheld(self) -> None:
        assert not any("rosoft" in pattern for pattern in self._patterns("rosoft.com"))

    def test_the_indicator_says_why_it_was_let_through(self) -> None:
        from maljan.reporting.models import NetworkDomain
        from maljan.reporting.renderers.stix_renderer import _indicator_for_domain

        indicator = _indicator_for_domain(NetworkDomain(fqdn=_a_v3_onion(), source="strings"))
        assert indicator is not None
        assert "hidden service" in (indicator.description or "").lower()

    def test_it_is_still_labelled_a_string_and_never_looked_up(self) -> None:
        from maljan.enrichment.orchestrator import _is_public_fqdn

        assert _is_public_fqdn(_a_v3_onion()) is False


class TestTheMachineReadableSurfacesSayItToo:
    """The same reader is served by the IOC feed and the consolidated table."""

    def test_the_consolidated_table_carries_the_source(self) -> None:
        report = TestNoStringDerivedDomainReachesTheBundle()._report()
        # The table defangs what it prints, so the rows are keyed on that.
        described = {
            row.value: row.description for row in report.consolidated_iocs if row.type == "Domain"
        }
        assert "strings" in described["rosoft[.]com"]
        assert "sandbox" in described["c2[.]evil[.]tld"]

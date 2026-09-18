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

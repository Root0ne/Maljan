"""An IPv6 address and a ``.onion`` name are network values to every reader, by their form.

The report's defanger read both by form, but the host reader the publish
checks, the run summary's sentences and a cell's "state unknown" note use
(``network_values_in``) read neither: an IPv6 address, bare or in brackets,
was no value at all, and a ``.onion`` name was read only when its last label
before ``.onion`` was base32 of a hidden service's length, and then without the
labels in front of it. Both readers now share one IPv6 reader and one onion
reader.
"""

from __future__ import annotations

from maljan.pipeline.claim_drops import defanged
from maljan.pipeline.validation import (
    NO_TABLE_ROW,
    network_values_in,
    unpublished_value_violations,
)
from maljan.reporting.renderers.markdown import _defanged_text, _names_a_network_value

V6 = "2001:db8::17"
ONION = "relay-panel.onion"
LONG_ONION = "mirror.abcdefghijklmnop.onion"


class TestTheHostReader:
    def test_reads_a_bare_ipv6_address(self) -> None:
        assert network_values_in(f"It connects to {V6} on port 443.") == [("ip", V6)]

    def test_reads_a_bracketed_ipv6_address_with_its_port(self) -> None:
        assert network_values_in(f"It connects to [{V6}]:443.") == [("ip", V6)]

    def test_reads_an_ipv6_address_inside_a_url(self) -> None:
        assert ("ip", V6) in network_values_in(f"It fetches http://[{V6}]:8080/gate.")

    def test_reads_a_defanged_ipv6_address(self) -> None:
        assert network_values_in(f"It connects to {V6.replace(':', '[:]', 1)}.") == [("ip", V6)]

    def test_reads_an_onion_name_of_any_form(self) -> None:
        for name in (ONION, "RELAY-PANEL.ONION", LONG_ONION):
            assert network_values_in(f"It beacons to {name} hourly.") == [
                ("domain", name.lower())
            ], name

    def test_colons_with_no_hex_digit_and_code_namespaces_are_no_address(self) -> None:
        for text in (
            "a :: b",
            "std::string and Data::Data::Modulo",
            "the ratio 3:4:5",
            "The loader calls ab::cd and dead::beef helpers.",
            "It builds a std::vector and calls a::b::c.",
            "Calls fe::be::add.",
        ):
            assert network_values_in(text) == [], text

    def test_an_embedded_ipv4_tail_is_read_whole_and_never_cut(self) -> None:
        assert network_values_in("It connects to ::ffff:192.0.2.1 on port 80.") == [
            ("ip", "::ffff:192.0.2.1")
        ]

    def test_a_short_address_is_read_in_brackets_only(self) -> None:
        assert network_values_in("It binds [fe80::1]:80.") == [("ip", "fe80::1")]
        assert network_values_in("It binds fe80::1 there.") == []
        assert network_values_in("It reaches 2001:db8:0:1::5 there.") == [("ip", "2001:db8:0:1::5")]

    def test_a_full_address_is_read(self) -> None:
        full = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        assert network_values_in(f"It reaches {full}.") == [("ip", full)]


class TestEverySurfaceDefangsThemAlike:
    def test_the_run_summary_sentence(self) -> None:
        said = defanged(f"It named {V6}, [{V6}]:443 and {ONION}.")

        assert V6 not in said
        assert ONION not in said
        assert "relay-panel[.]onion" in said

    def test_the_report_defanger(self) -> None:
        said = _defanged_text(f"It named {V6}, [{V6}]:443, {ONION} and {LONG_ONION}.")

        assert V6 not in said
        assert ONION not in said and "abcdefghijklmnop.onion" not in said

    def test_a_cell_naming_one_is_read_as_naming_a_network_value(self) -> None:
        assert _names_a_network_value(f"[{V6}]:443")
        assert _names_a_network_value(ONION)

    def test_the_report_still_defangs_every_bracketed_short_and_full_form(self) -> None:
        for written in ("[fe80::1]:80", "fe80::1", "[2001:db8::17]", "::ffff:192.0.2.1"):
            assert _defanged_text(f"It reaches {written}.") != f"It reaches {written}.", written

    def test_scope_names_stay_as_written(self) -> None:
        said = "It builds a std::vector and calls a::b::c."
        assert _defanged_text(said) == said


class TestThePublishCheck:
    def test_an_unpublished_ipv6_address_in_prose_is_named(self) -> None:
        payload = {"body": f"The sample connects to [{V6}]:443, its C2.", "evidence_refs": []}

        (found,) = unpublished_value_violations(payload, lambda kind, value: "")

        assert V6 in found.message
        assert NO_TABLE_ROW in found.message

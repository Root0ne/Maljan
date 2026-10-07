"""A two-label host whose first label is two characters: read by its digit, or by the evidence.

The sweep refused every two-label name with a two-character first label, so
a bare ``c2.ru`` in a sample's strings or an analyst's sentence was no host,
though the same name inside a URL or a mailbox was. Read wholesale, two
characters under 1,437 TLDs are prose and code ("to.do", "in.it", "me.so").
So such a name is read when its first label holds a digit and a letter
(``c2``, ``x1``, ``7z``), the shape a host takes and a word does not; one of
two letters is read only by a check that can ask the run's network evidence,
which drops it when no evidence holds it, and the report defangs it only where
the run recorded it.
"""

from __future__ import annotations

from maljan.pipeline.validation import (
    evidence_gated_values,
    network_values_in,
    unpublished_value_violations,
)
from maljan.reporting.defang import ProseDefanger
from maljan.reporting.renderers.markdown import _defanged_text
from maljan.tools.strings import iocs_from_text, iter_string_iocs


def _domains(text: str) -> list[str]:
    return [row["value"] for row in iocs_from_text(text, ["domain"])["iocs"]]


class TestALabelWithADigit:
    def test_the_sweep_reads_it(self) -> None:
        for name in ("c2.ru", "c2.sh", "x1.top", "7z.top", "C2.RU"):
            assert _domains(f"beacon {name} every minute") == [name], name

    def test_the_host_reader_and_the_report_read_it(self) -> None:
        assert network_values_in("It beacons to c2.ru every minute.") == [("domain", "c2.ru")]
        assert _defanged_text("It beacons to c2.ru every minute.") == (
            "It beacons to c2[.]ru every minute."
        )

    def test_digits_alone_are_a_number_not_a_name(self) -> None:
        for text in ("took 10.ms", "rated 42.de", "1.10.ru"):
            assert _domains(text) == [], text
            assert network_values_in(text) == [], text


class TestAStringOfItsOwn:
    """Five characters, one under the sweep's floor: read only when the whole run is such a host."""

    def _swept(self, blob: bytes) -> list[tuple[str, str]]:
        return [(row["kind"], row["value"]) for row in iter_string_iocs(blob)]

    def test_a_nul_terminated_value_is_read_in_ascii_and_in_utf16(self) -> None:
        for name in ("c2.ru", "C2.RU", "x1.io", "7z.su"):
            assert self._swept(b"\x00\x00" + name.encode() + b"\x00\x00") == [("domain", name)]
            wide = name.encode("utf-16-le")
            assert self._swept(b"\x00\x00" + wide + b"\x00\x00") == [("domain", name)], name

    def test_a_lone_value_is_read_and_defanged_in_text(self) -> None:
        assert network_values_in("c2.ru") == [("domain", "c2.ru")]
        assert _defanged_text("c2.ru") == "c2[.]ru"
        assert _defanged_text("| C2.RU |") == "| C2[.]RU |"

    def test_any_other_five_character_run_stays_below_the_floor(self) -> None:
        for run in (b"or.at", b"ab.ru", b"10.ru", b"c2.zz", b"c2.RU", b"a.b.c", b"GetIP"):
            assert self._swept(b"\x00" + run + b"\x00") == [], run

    def test_what_the_sweep_read_keeps_its_place_ahead_of_it(self) -> None:
        blob = b"\x00c2.ru\x00beacon to x1.top now\x00"

        assert self._swept(blob) == [("domain", "x1.top"), ("domain", "c2.ru")]
        assert self._swept(b"\x00c2.ru\x00c2.ru\x00") == [("domain", "c2.ru")]


class TestALabelOfTwoLetters:
    WORDS = ("to.do", "in.it", "is.am", "me.so", "ab.ru", "go.dev")

    def test_neither_the_sweep_nor_the_report_reads_it(self) -> None:
        for name in self.WORDS:
            assert _domains(f"see {name} here") == [], name
            assert network_values_in(f"see {name} here") == [], name
            assert _defanged_text(f"see {name} here") == f"see {name} here", name

    def test_a_check_that_asks_the_evidence_reads_it_and_drops_it_with_none(self) -> None:
        sentence = "It beacons to ab.ru every minute."

        assert network_values_in(sentence, packages=True) == [("domain", "ab.ru")]
        assert "ab.ru" in evidence_gated_values(sentence)
        payload = {"body": sentence, "evidence_refs": []}
        assert unpublished_value_violations(payload, lambda kind, value: "") == []

        held = {("domain", "ab.ru"): "no: seen only in the text of ev_0002 (strings)"}
        (found,) = unpublished_value_violations(
            payload, lambda kind, value: held.get((kind, value), "")
        )
        assert "ab.ru" in found.message

    def test_the_report_defangs_it_where_the_run_recorded_it(self) -> None:
        run_values = ProseDefanger([("ab.ru", "domain")])

        assert _defanged_text(run_values("It beacons to ab.ru.")) == "It beacons to ab[.]ru."


class TestWhatWasReadStaysRead:
    def test_inside_a_url_a_mailbox_and_a_longer_name(self) -> None:
        assert [row["value"] for row in iocs_from_text("http://ab.ru/a")["iocs"]] == [
            "http://ab.ru/a"
        ]
        assert [row["kind"] for row in iocs_from_text("op@ab.ru")["iocs"]] == ["email"]
        assert _domains("cdn.ab.example.com") == ["cdn.ab.example.com"]
        assert _domains("example.co.uk") == ["example.co.uk"]

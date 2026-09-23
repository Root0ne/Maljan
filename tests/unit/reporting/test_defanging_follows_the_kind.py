"""A value is defanged by what it is, never by what it looks like.

The rule the report used before read the shape of the string — a dot and no
backslash — and bracketed the dot in ``update_data.dat`` and ``LibraryTag.dll``
while writing URLs in a form nobody else uses. These pin the vendor form per
kind, the kinds that are never touched, and the prose pass that touches only
the run's own indicators.
"""

from __future__ import annotations

import pytest

from maljan.reporting.defang import defang, defang_text


class TestEachNetworkKindHasItsForm:
    @pytest.mark.parametrize(
        ("value", "kind", "expected"),
        [
            ("https://c2.example.org/submit/", "url", "hxxps://c2[.]example[.]org/submit/"),
            ("http://a.example.org/x.php?q=1.2", "url", "hxxp://a[.]example[.]org/x.php?q=1.2"),
            ("ftp://files.example.org/a.bin", "url", "fxp://files[.]example[.]org/a.bin"),
            ("HTTPS://A.EXAMPLE.ORG/", "url", "HXXPS://A[.]EXAMPLE[.]ORG/"),
            ("http://192.0.2.10:8080/gate", "url", "hxxp://192[.]0[.]2[.]10:8080/gate"),
            ("a.example.org/path.html", "url", "a[.]example[.]org/path.html"),
            ("beacon.example.net", "domain", "beacon[.]example[.]net"),
            ("192.0.2.10", "ipv4", "192[.]0[.]2[.]10"),
            ("192.0.2.10", "ip", "192[.]0[.]2[.]10"),
            ("2001:db8::1", "ipv6", "2001[:]db8::1"),
            ("2001:db8::1", "ip", "2001[:]db8::1"),
            ("ops@example.org", "email", "ops[@]example[.]org"),
        ],
    )
    def test_the_form(self, value: str, kind: str, expected: str) -> None:
        assert defang(value, kind) == expected

    @pytest.mark.parametrize(
        ("value", "kind"),
        [
            ("https://c2.example.org/submit/", "url"),
            ("beacon.example.net", "domain"),
            ("192.0.2.10", "ip"),
            ("2001:db8::1", "ipv6"),
            ("ops@example.org", "email"),
        ],
    )
    def test_defanging_twice_is_defanging_once(self, value: str, kind: str) -> None:
        once = defang(value, kind)
        assert defang(once, kind) == once

    def test_the_kind_is_read_whatever_its_case(self) -> None:
        assert defang("a.example.org", "Domain") == "a[.]example[.]org"
        assert defang("192.0.2.1", "IPv4") == "192[.]0[.]2[.]1"


class TestWhatIsNotANetworkIndicatorIsNeverTouched:
    @pytest.mark.parametrize(
        ("value", "kind"),
        [
            (r"%APPDATA%\ExampleApp\update_data.dat", "path"),
            ("update_data.dat", "path"),
            ("LibraryTag.dll", "file"),
            ("LibraryTag.dll", "File name"),
            ("a" * 64, "SHA-256"),
            (r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "Registry Key"),
            ("Global\\ExampleMutex", "mutex"),
            (r"\\.\pipe\x.y", "Named pipe"),
            ("Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "User-Agent"),
            ("cmd.exe /c ipconfig /all", "Command line"),
            ("ExampleTask", "Scheduled task"),
            ("6.0.0.0", "String"),
        ],
    )
    def test_returned_exactly(self, value: str, kind: str) -> None:
        assert defang(value, kind) == value

    def test_an_empty_value_stays_empty(self) -> None:
        assert defang("", "domain") == ""


class TestProseIsDefangedOnlyWhereTheRunsOwnIndicatorsStand:
    INDICATORS = (
        ("https://c2.example.org/submit/", "url"),
        ("c2.example.org", "domain"),
        ("192.0.2.10", "ip"),
        ("ops@example.org", "email"),
    )

    def test_a_url_is_defanged_as_a_url_and_not_as_the_domain_inside_it(self) -> None:
        text = "It posts to https://c2.example.org/submit/ every ten minutes."
        assert defang_text(text, self.INDICATORS) == (
            "It posts to hxxps://c2[.]example[.]org/submit/ every ten minutes."
        )

    def test_a_value_at_the_end_of_a_sentence_is_found(self) -> None:
        text = "The C2 is c2.example.org. It also contacts 192.0.2.10."
        assert defang_text(text, self.INDICATORS) == (
            "The C2 is c2[.]example[.]org. It also contacts 192[.]0[.]2[.]10."
        )

    def test_a_longer_name_that_contains_the_value_is_not_touched(self) -> None:
        text = "Unrelated: www.c2.example.org.example and c2.example.organic."
        assert defang_text(text, self.INDICATORS) == text

    def test_an_ordinary_word_and_a_file_name_are_never_touched(self) -> None:
        text = "It writes update_data.dat and loads LibraryTag.dll, version 1.2.3."
        assert defang_text(text, self.INDICATORS) == text

    def test_the_case_the_model_wrote_is_kept(self) -> None:
        assert defang_text("C2.Example.ORG", self.INDICATORS) == "C2[.]Example[.]ORG"

    def test_a_mailbox_is_defanged_whole(self) -> None:
        assert defang_text("mail ops@example.org now", self.INDICATORS) == (
            "mail ops[@]example[.]org now"
        )

    def test_nothing_to_defang_returns_the_text(self) -> None:
        assert defang_text("plain text", ()) == "plain text"
        assert defang_text("", self.INDICATORS) == ""

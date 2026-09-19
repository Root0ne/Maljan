"""One reader of a STIX pattern's comparisons, and what it refuses to guess.

The validator and the STIX renderer each used to split a pattern on its quotes.
Neither read an escaped quote — ``[file:name = 'it\\'s.exe']`` came back as
``it\\`` and the judge was told that value appears nowhere in the evidence — and
they disagreed about what a quoted key is, which is how one of them can publish
what the other vetoes. The tests below are about the one reader they now share.
"""

from __future__ import annotations

import time

from maljan.schemas.stix_pattern import read_comparisons


def _paths(pattern: str) -> list[tuple[str, str]]:
    return [(c.path, c.literal) for c in read_comparisons(pattern)]


class TestWhatOneComparisonSays:
    def test_the_path_the_operator_and_the_value(self) -> None:
        (comparison,) = read_comparisons("[url:value = 'http://gate.example.org/a']")

        assert comparison.object_type == "url"
        assert comparison.prop == "value"
        assert comparison.operator == "="
        assert comparison.literal == "http://gate.example.org/a"
        assert comparison.readable

    def test_the_object_path_is_read_whatever_case_it_is_written_in(self) -> None:
        (comparison,) = read_comparisons("[DOMAIN-NAME:Value = 'gate.example.org']")

        assert comparison.path == "domain-name:value"

    def test_a_value_carrying_something_shaped_like_a_path_is_still_a_value(self) -> None:
        url = "https://gate.example.org/x?next=domain-name:value"

        assert _paths(f"[url:value = '{url}']") == [("url:value", url)]


class TestTheQuoteThatIsEscaped:
    def test_an_escaped_quote_stays_inside_the_value(self) -> None:
        assert _paths(r"[file:name = 'it\'s.exe']") == [("file:name", "it's.exe")]

    def test_an_escaped_backslash_is_one_backslash(self) -> None:
        assert _paths(r"[file:name = 'a\\b.exe']") == [("file:name", r"a\b.exe")]

    def test_a_backslash_before_anything_else_is_a_backslash(self) -> None:
        r"""A judge writes ``C:\Windows\x.exe`` unescaped far more often than not."""
        assert _paths(r"[file:name = 'C:\Windows\x.exe']") == [("file:name", r"C:\Windows\x.exe")]

    def test_a_quote_that_never_closes_is_reported_unreadable(self) -> None:
        (comparison,) = read_comparisons("[url:value = 'http://gate.example.org/a")

        assert not comparison.readable


class TestTheQuoteThatIsAKey:
    def test_a_hash_algorithm_is_a_key_and_the_digest_is_the_value(self) -> None:
        digest = "a" * 64

        assert _paths(f"[file:hashes.'SHA-256' = '{digest}']") == [
            ("file:hashes.'sha-256'", digest)
        ]

    def test_an_extension_key_is_read_back_into_the_path(self) -> None:
        digest = "b" * 32

        assert _paths(f"[file:extensions['pe'].pe_imphash = '{digest}']") == [
            ("file:extensions['pe'].pe_imphash", digest)
        ]

    def test_a_key_does_not_swallow_the_comparison_after_it(self) -> None:
        digest = "c" * 40
        pattern = f"[file:hashes.'SHA-1' = '{digest}' AND file:name = 'x.exe']"

        assert _paths(pattern) == [("file:hashes.'sha-1'", digest), ("file:name", "x.exe")]


class TestAPatternIsNotOneComparison:
    def test_each_side_of_an_or_is_read_as_itself(self) -> None:
        pattern = "[domain-name:value = 'a.example.org'] OR [ipv4-addr:value = '185.220.101.1']"

        assert _paths(pattern) == [
            ("domain-name:value", "a.example.org"),
            ("ipv4-addr:value", "185.220.101.1"),
        ]

    def test_a_value_list_writes_its_path_once_and_quotes_twice(self) -> None:
        pattern = "[ipv4-addr:value IN ('185.220.101.1', '127.0.0.1')]"

        assert _paths(pattern) == [
            ("ipv4-addr:value", "185.220.101.1"),
            ("ipv4-addr:value", "127.0.0.1"),
        ]
        assert {c.operator for c in read_comparisons(pattern)} == {"in ("}

    def test_a_reference_path_is_read_whole(self) -> None:
        pattern = "[network-traffic:dst_ref.value = '127.0.0.1']"

        assert _paths(pattern) == [("network-traffic:dst_ref.value", "127.0.0.1")]

    def test_a_list_step_inside_a_path_is_read_whole(self) -> None:
        pattern = "[domain-name:resolves_to_refs[*].value = '10.0.0.5']"

        assert _paths(pattern) == [("domain-name:resolves_to_refs[*].value", "10.0.0.5")]


class TestWhatIsSkippedRatherThanMisread:
    def test_a_qualifier_timestamp_is_not_credited_to_the_comparison(self) -> None:
        """``START`` and ``STOP`` quote two timestamps after the brackets close."""
        pattern = (
            "[ipv4-addr:value = '185.220.101.1'] "
            "START '2026-01-01T00:00:00Z' STOP '2026-01-02T00:00:00Z'"
        )

        assert _paths(pattern) == [("ipv4-addr:value", "185.220.101.1")]

    def test_a_qualifier_after_a_value_list_is_skipped_too(self) -> None:
        pattern = "[ipv4-addr:value IN ('185.220.101.1', '10.0.0.5')] START '2026-01-01T00:00:00Z'"

        assert [literal for _path, literal in _paths(pattern)] == [
            "185.220.101.1",
            "10.0.0.5",
        ]

    def test_an_observation_after_a_qualifier_is_read_again(self) -> None:
        pattern = (
            "[ipv4-addr:value = '185.220.101.1'] START '2026-01-01T00:00:00Z' "
            "FOLLOWEDBY [domain-name:value = 'gate.example.org']"
        )

        assert _paths(pattern) == [
            ("ipv4-addr:value", "185.220.101.1"),
            ("domain-name:value", "gate.example.org"),
        ]


class TestWhatItCannotReadItSaysSo:
    def test_a_value_with_no_object_path_anywhere_is_unreadable(self) -> None:
        (comparison,) = read_comparisons("['gate.example.org']")

        assert not comparison.readable
        assert comparison.path == ""

    def test_the_operator_is_reported_rather_than_interpreted(self) -> None:
        (comparison,) = read_comparisons(r"[url:value MATCHES '^https?://.*\.evil\.example/']")

        assert comparison.operator == "matches"
        assert comparison.readable


class TestTheCostOfReadingOne:
    def test_a_thousand_literals_are_read_in_one_pass(self) -> None:
        values = ", ".join(f"'10.0.{index // 256}.{index % 256}'" for index in range(1000))
        pattern = f"[ipv4-addr:value IN ({values})]"

        started = time.monotonic()
        comparisons = read_comparisons(pattern)

        assert len(comparisons) == 1000
        assert time.monotonic() - started < 2.0

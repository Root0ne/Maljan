"""Two STIX indicators are one when each comparison they make is the same comparison.

``dedupe.pattern_fingerprint`` reads the pattern with the one pattern reader
(``schemas.stix_pattern``) and folds each value by the kind of its own object
path. It used to pick one kind for the whole text from the first known path
found anywhere in it, quoted values included, so a URL that quoted
``file:name`` was folded like a path and two URLs differing in case became one
indicator. Merging two indicators that are not one removes a fact; the
fingerprint errs toward two rows.
"""

from __future__ import annotations

import time

import pytest

from maljan.reporting.dedupe import pattern_fingerprint
from maljan.schemas.stix_pattern import canonical_pattern


def _same(a: str, b: str, pattern_type: str = "stix") -> bool:
    return pattern_fingerprint(pattern_type, a) == pattern_fingerprint(pattern_type, b)


class TestDistinctIndicatorsStayTwo:
    def test_a_url_quoting_a_path_keeps_its_case(self) -> None:
        assert not _same(
            "[url:value = 'http://a.example/file:name/X']",
            "[url:value = 'http://a.example/file:name/x']",
        )

    def test_a_url_quoting_a_drive_keeps_its_case(self) -> None:
        assert not _same(
            "[url:value = 'http://a.example/C:/Gate']", "[url:value = 'http://a.example/c:/gate']"
        )

    def test_and_is_not_or(self) -> None:
        assert not _same("[a:b = 'x' AND c:d = 'y']", "[a:b = 'x' OR c:d = 'y']")

    def test_two_paths_with_one_value_are_two(self) -> None:
        assert not _same("[file:name = 'a.exe']", "[process:name = 'a.exe']")

    def test_an_escaped_quote_is_part_of_the_value(self) -> None:
        assert not _same("[file:name = 'it\\'s.exe']", "[file:name = 'it\\'S.exe']")
        assert not _same("[file:name = 'it\\'s.exe']", "[file:name = 'it']")

    def test_a_like_or_matches_value_is_kept_as_written(self) -> None:
        # ``[.]`` in a LIKE value is three characters and in a regex a class.
        assert not _same(
            "[process:command_line LIKE '%a[.]exe%']", "[process:command_line LIKE '%a.exe%']"
        )
        assert not _same("[file:name MATCHES '^\\\\D']", "[file:name MATCHES '^\\\\d']")

    def test_an_unterminated_value_is_not_the_closed_one(self) -> None:
        assert not _same("[file:name = 'abc", "[file:name = 'abc']")

    def test_a_qualifier_keeps_its_own_literal(self) -> None:
        stop = "[file:name = 'a'] START t'2026-01-01T00:00:00Z' STOP t'2026-01-02T00:00:00Z'"
        assert not _same(stop, stop.replace("01-02", "01-03"))

    def test_another_pattern_language_is_compared_as_written(self) -> None:
        assert not _same('rule a { strings: $A = "x" }', 'rule a { strings: $a = "x" }', "yara")
        assert _same(" rule a {} ", "rule a {}", "yara")


class TestOneIndicatorWrittenTwoWaysIsOne:
    def test_whitespace_around_an_operator(self) -> None:
        assert _same("[file:name = 'a.exe']", "[file:name='a.exe']")

    def test_the_case_of_the_object_path_and_keywords(self) -> None:
        assert _same("[URL:value = 'http://a/b']", "[url:value = 'http://a/b']")
        assert _same("[process:command_line LIKE '%x%']", "[process:command_line like '%x%']")

    def test_each_comparison_folds_by_its_own_kind(self) -> None:
        assert _same(
            "[domain-name:value = 'A.example' AND file:hashes.MD5 = 'AB']",
            "[domain-name:value = 'a.example' AND file:hashes.md5 = 'ab']",
        )
        # The URL in the same pattern keeps its case.
        assert not _same(
            "[domain-name:value = 'a.example' AND url:value = 'http://a.example/X']",
            "[domain-name:value = 'a.example' AND url:value = 'http://a.example/x']",
        )

    def test_a_defanged_value_is_its_plain_spelling(self) -> None:
        assert _same(
            "[url:value = 'hxxp://a[.]example/Gate']", "[url:value = 'http://a.example/Gate']"
        )
        assert _same("[ipv4-addr:value = '10[.]0[.]0[.]1']", "[ipv4-addr:value='10.0.0.1']")

    def test_a_path_by_the_path_rules(self) -> None:
        assert _same(
            "[file:name = 'C:\\\\Users\\\\X\\\\a.exe']", "[file:name = 'c:/users/x/a.exe']"
        )
        assert not _same("[file:name = '/tmp/A']", "[file:name = '/tmp/a']")
        assert _same("[directory:path = '/opt/dist/']", "[directory:path = '/opt/dist']")


class TestTheCanonicalPattern:
    def test_the_caller_decides_each_value(self) -> None:
        assert (
            canonical_pattern("[A:b = 'x' AND c:d IN ('y', 'z')]", lambda c: c.literal.upper())
            == "[a:b='X'and c:d in('Y','Z')]"
        )

    def test_a_value_is_quoted_back_escaped(self) -> None:
        assert (
            canonical_pattern("[a:b = 'x']", lambda _c: "it's \\ here")
            == "[a:b='it\\'s \\\\ here']"
        )

    def test_a_key_folds_with_its_path(self) -> None:
        assert canonical_pattern("[file:hashes.'SHA-256' = 'Ab']", lambda c: c.literal) == (
            "[file:hashes.'sha-256'='Ab']"
        )


@pytest.mark.parametrize(
    "unit",
    [
        "[url:value = 'a'] AND ",
        "  \t ",
        "' '",
        "[file:hashes.'k'.'k' = 'v' ",
        "[a:b IN ('x', 'y', ",
    ],
)
def test_a_hostile_pattern_is_fingerprinted_in_linear_time(unit: str) -> None:
    # Ten times the text takes at most about ten times as long (twenty, for noise).
    def took(size: int) -> float:
        text = unit * size
        start = time.perf_counter()
        pattern_fingerprint("stix", text)
        return time.perf_counter() - start

    small = min(took(5_000) for _ in range(3))
    large = min(took(50_000) for _ in range(2))
    assert large < 20 * small + 0.05

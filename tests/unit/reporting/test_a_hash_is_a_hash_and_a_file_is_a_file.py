"""A digest is its algorithm's length, a file name names a file, and one path is one row.

A recorded run exported ``[file:hashes.'MD5' = '32066ff6369a7bd7']`` — sixteen
of the thirty-two characters of the real digest. It passed the grounding check
because the truncated prefix is present in the evidence, and no rule asked
whether the literal was a valid length for the algorithm it was written under.
The same bundle carried ``[file:name = '/Users/']`` and one directory twice,
once with a trailing separator and once without.
"""

from __future__ import annotations

from maljan.agents._indicator_denylists import hash_literal_is_wellformed, malformed_hash_in
from maljan.pipeline.validation import validate_verdict_bundle
from maljan.reporting.dedupe import canonical_path, pattern_fingerprint
from maljan.reporting.renderers.stix_renderer import (
    MALFORMED_HASH_CODE,
    UNPUBLISHABLE_ARTEFACT_CODE,
    ExtendedSTIXRenderer,
    _judge_indicator_problem,
)
from maljan.schemas.stix_models import Bundle, Indicator

# The real digest of the recorded sample, and the half of it that was exported.
FULL_MD5 = "32066ff6369a7bd794f03bdb77c399f3"
TRUNCATED_MD5 = FULL_MD5[:16]

# The directory the recorded run published, and the same one written twice.
DIRECTORY = "/Users/"
DIST = "/Users/analyst/.vscode/extensions/lang-tools-2025.8.3/dist"


def _indicator(pattern: str) -> Indicator:
    return Indicator(name="x", pattern=pattern, pattern_type="stix")


class TestAHashIsItsAlgorithmsLength:
    def test_the_table_answers_each_algorithm(self) -> None:
        assert hash_literal_is_wellformed("MD5", FULL_MD5) is True
        assert hash_literal_is_wellformed("MD5", TRUNCATED_MD5) is False
        assert hash_literal_is_wellformed("SHA-256", "a" * 64) is True
        assert hash_literal_is_wellformed("SHA-256", "a" * 63) is False
        assert hash_literal_is_wellformed("MD5", "z" * 32) is False

    def test_an_algorithm_it_does_not_know_is_left_alone(self) -> None:
        assert hash_literal_is_wellformed("TLSH", "T1A2B3") is True

    def test_it_reads_the_literal_out_of_a_pattern(self) -> None:
        found = malformed_hash_in(f"[file:hashes.'MD5' = '{TRUNCATED_MD5}']")

        assert found == ("MD5", TRUNCATED_MD5)
        assert malformed_hash_in(f"[file:hashes.'MD5' = '{FULL_MD5}']") is None

    def test_the_export_declines_the_judge_s_own_truncated_digest(self) -> None:
        problem = _judge_indicator_problem(_indicator(f"[file:hashes.'MD5' = '{TRUNCATED_MD5}']"))

        assert problem is not None
        code, sentence = problem
        assert code == MALFORMED_HASH_CODE
        assert "32 hexadecimal characters" in sentence
        assert "unchanged in the judge's own bundle" in sentence

    def test_a_well_formed_digest_is_carried(self) -> None:
        assert _judge_indicator_problem(_indicator(f"[file:hashes.'MD5' = '{FULL_MD5}']")) is None


class TestTheGroundingCheckMatchesAWholeToken:
    @staticmethod
    def _violations(pattern: str) -> list[str]:
        bundle = Bundle(objects=[_indicator(pattern)])
        return [
            v.code for v in validate_verdict_bundle(bundle, evidence_corpus={f"md5: {FULL_MD5}"})
        ]

    def test_a_truncated_digest_is_not_present_in_the_evidence(self) -> None:
        assert self._violations(f"[file:hashes.'MD5' = '{TRUNCATED_MD5}']") == [
            "stix.ungrounded_indicator"
        ]

    def test_the_whole_digest_is(self) -> None:
        assert self._violations(f"[file:hashes.'MD5' = '{FULL_MD5}']") == []

    def test_a_digest_of_the_wrong_length_is_not_found_inside_a_longer_one(self) -> None:
        """A digest-shaped literal that is only the head of the one the run saw."""
        sha256 = "a1b2c3d4" * 8
        bundle = Bundle(objects=[_indicator(f"[file:hashes.x = '{sha256[:32]}']")])

        codes = [
            v.code for v in validate_verdict_bundle(bundle, evidence_corpus={f"sha256: {sha256}"})
        ]

        assert codes == ["stix.ungrounded_indicator"]


class TestAFileNameNamesAFile:
    def test_the_export_declines_a_directory(self) -> None:
        problem = _judge_indicator_problem(_indicator(f"[file:name = '{DIRECTORY}']"))

        assert problem is not None
        assert problem[0] == UNPUBLISHABLE_ARTEFACT_CODE
        assert "names a directory or a root" in problem[1]

    def test_it_carries_a_file(self) -> None:
        assert _judge_indicator_problem(_indicator("[file:name = '/tmp/dropper.so']")) is None


class TestOnePathIsOneRow:
    def test_a_trailing_separator_is_not_a_second_path(self) -> None:
        assert pattern_fingerprint("stix", f"[file:name = '{DIST}']") == pattern_fingerprint(
            "stix", f"[file:name = '{DIST}/']"
        )

    def test_a_windows_path_folds_its_case(self) -> None:
        assert canonical_path("C:\\Users\\Analyst\\a.py") == canonical_path(
            "c:\\users\\analyst\\a.py"
        )

    def test_a_posix_path_does_not(self) -> None:
        assert canonical_path("/tmp/A") != canonical_path("/tmp/a")

    def test_duplicate_separators_collapse(self) -> None:
        assert canonical_path("/tmp//a///b") == "/tmp/a/b"

    def test_a_unc_path_is_not_a_posix_path(self) -> None:
        """Folding the leading pair merged two locations that cannot be one file."""
        assert canonical_path(r"\\SRV\Share\F") != canonical_path("/srv/share/f")

    def test_a_unc_path_still_folds_its_own_case(self) -> None:
        assert canonical_path(r"\\SRV\Share\F") == canonical_path(r"\\srv\share\f")

    def test_the_bundle_carries_the_path_once(self) -> None:
        judge = Bundle(
            objects=[_indicator(f"[file:name = '{DIST}']"), _indicator(f"[file:name = '{DIST}/']")]
        )

        bundle = _rendered(judge)
        names = [
            obj.pattern
            for obj in bundle.objects
            if getattr(obj, "type", "") == "indicator" and "file:name" in obj.pattern
        ]

        assert len(names) == 1


def _rendered(judge: Bundle) -> Bundle:
    from maljan.reporting.models import (
        FileHashes,
        MalwareReport,
        SampleIdentity,
    )

    report = MalwareReport(
        verdict="Malware",
        identity=SampleIdentity(hashes=FileHashes(sha256="e" * 64), file_name="sample.bin"),
        executive_summary="",
    )
    return ExtendedSTIXRenderer().render(report, base_bundle=judge)


# A pattern is not one comparison. The judge writes ``[a] AND [b]``, an ``IN``
# list, a compound over two object paths — and every check in the grounding
# function keyed on what the *pattern* started with, so the first comparison
# was asked and no other. Then the digest rule above was added in front of all
# of them and returned "no problem" for the whole expression as soon as one
# quoted literal was a grounded digest, which turned the URL denylist and the
# file-name anchor rule off for any pattern carrying a hash.
GROUNDED_SHA256 = "a1b2c3d4" * 8

# What each kind is refused for, paired with a grounded digest in both orders.
REFUSED_BESIDE_A_DIGEST = (
    ("[url:value = 'https://pypi.org/simple/requests/']", "vendor infrastructure"),
    ("[url:value = 'http://nowhere-in-the-evidence.example.com/x']", "appears nowhere"),
    ("[file:name = '/home/builder/toolchain/lib/libc.so']", "compiler or toolchain artefact"),
    ("[file:name = 'no-anchor-here']", "no file extension"),
)


class TestEveryComparisonIsAsked:
    @staticmethod
    def _problem(pattern: str) -> list[str]:
        bundle = Bundle(objects=[_indicator(pattern)])
        return [
            v.message
            for v in validate_verdict_bundle(bundle, evidence_corpus={f"sha256: {GROUNDED_SHA256}"})
        ]

    def test_a_grounded_digest_does_not_answer_for_the_comparison_beside_it(self) -> None:
        digest = f"[file:hashes.'SHA-256' = '{GROUNDED_SHA256}']"
        for comparison, why in REFUSED_BESIDE_A_DIGEST:
            for pattern in (f"{comparison} AND {digest}", f"{digest} AND {comparison}"):
                found = self._problem(pattern)
                assert found, f"{pattern} raised nothing; expected {why}"
                assert why in found[0], f"{pattern}: {found[0]}"

    def test_the_digest_alone_is_still_grounded(self) -> None:
        assert self._problem(f"[file:hashes.'SHA-256' = '{GROUNDED_SHA256}']") == []

    def test_a_clean_pair_raises_nothing(self) -> None:
        pattern = f"[file:name = 'dropper.exe'] AND [file:hashes.'SHA-256' = '{GROUNDED_SHA256}']"

        assert self._problem(pattern) == []

    def test_an_algorithm_name_is_not_read_as_a_value(self) -> None:
        """``file:hashes.'MD5'`` quotes the algorithm beside the digest."""
        assert self._problem(f"[file:hashes.'SHA-256' = '{GROUNDED_SHA256}']") == []

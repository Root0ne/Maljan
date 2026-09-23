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

    def test_a_list_of_digests_is_asked_the_same_question_as_one(self) -> None:
        """``IN`` asserts every member, and the length rule read ``=`` alone."""
        found = malformed_hash_in(f"[file:hashes.'MD5' IN ('{TRUNCATED_MD5}', '{FULL_MD5}')]")

        assert found == ("MD5", TRUNCATED_MD5)

    def test_a_list_whose_members_are_all_digests_is_carried(self) -> None:
        other = "a" * 32
        assert malformed_hash_in(f"[file:hashes.'MD5' IN ('{FULL_MD5}', '{other}')]") is None

    def test_an_operator_that_asserts_no_value_is_asked_nothing(self) -> None:
        assert malformed_hash_in("[file:hashes.'MD5' MATCHES '^[0-9a-f]+$']") is None

    def test_a_list_under_an_algorithm_with_no_length_is_left_alone(self) -> None:
        assert malformed_hash_in("[file:hashes.'SSDEEP' IN ('3:ab:cd', '6:ef:gh')]") is None

    def test_the_export_declines_a_malformed_member_of_a_list(self) -> None:
        problem = _judge_indicator_problem(
            _indicator(f"[file:hashes.'MD5' IN ('{TRUNCATED_MD5}', '{FULL_MD5}')]")
        )

        assert problem is not None
        code, sentence = problem
        assert code == MALFORMED_HASH_CODE
        assert TRUNCATED_MD5 in sentence
        assert "32 hexadecimal characters" in sentence

    def test_the_grounding_check_declines_a_malformed_member_of_a_list(self) -> None:
        bundle = Bundle(
            objects=[_indicator(f"[file:hashes.'MD5' IN ('{TRUNCATED_MD5}', '{FULL_MD5}')]")]
        )

        found = [v.message for v in validate_verdict_bundle(bundle, {FULL_MD5, TRUNCATED_MD5})]

        assert found and TRUNCATED_MD5 in found[0]
        assert "is not a MD5 digest" in found[0]

    def test_a_list_member_the_evidence_does_not_carry_is_ungrounded(self) -> None:
        """Every member is asked the whole-token question the ``=`` form is."""
        other = "b" * 32
        bundle = Bundle(objects=[_indicator(f"[file:hashes.'MD5' IN ('{FULL_MD5}', '{other}')]")])

        found = [v.message for v in validate_verdict_bundle(bundle, {FULL_MD5})]

        assert found and other in found[0]
        assert "appears nowhere in the evidence" in found[0]

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
        DynamicBehavior,
        FileHashes,
        MalwareReport,
        SampleIdentity,
    )

    # The sandbox saw the file written: the second source the one publish rule
    # asks of a judge value as of any other.
    report = MalwareReport(
        verdict="Malware",
        identity=SampleIdentity(hashes=FileHashes(sha256="e" * 64), file_name="sample.bin"),
        executive_summary="",
        dynamic=DynamicBehavior(file_operations=[{"operation": "write", "path": DIST}]),
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


# A fuzzy hash is a hash with no length. An ssdeep carries its block size and
# two slash-separated chunks; a TLSH opens with its version. Neither is a run
# of hex, so the prefix question the whole-token rule answers does not arise
# for either — and asking the length question of them would refuse every one.
# Skipping them entirely, which the per-comparison walk did at first, told a
# judge that the ssdeep the ``hashes`` tool had just reported appears nowhere
# in the evidence: a deterministic statement that is false, which spends the
# one retry and then drops the object.
SSDEEP = "3:abcd:efgh"
TLSH = "t1abc123def456"
FUZZY_EVIDENCE = f"hashes: ssdeep {SSDEEP}; tlsh {TLSH}"


class TestAHashWithNoLength:
    @staticmethod
    def _problem(pattern: str, evidence: str = FUZZY_EVIDENCE) -> list[str]:
        bundle = Bundle(objects=[_indicator(pattern)])
        return [v.code for v in validate_verdict_bundle(bundle, evidence_corpus={evidence})]

    def test_a_grounded_fuzzy_hash_is_accepted(self) -> None:
        for algorithm, value in (("SSDEEP", SSDEEP), ("TLSH", TLSH)):
            assert self._problem(f"[file:hashes.'{algorithm}' = '{value}']") == [], algorithm

    def test_an_invented_one_is_still_refused(self) -> None:
        for algorithm, value in (("SSDEEP", "9:zzzz:yyyy"), ("TLSH", "t1ffffffffffff")):
            assert self._problem(f"[file:hashes.'{algorithm}' = '{value}']") == [
                "stix.ungrounded_indicator"
            ], algorithm

    def test_its_length_is_not_asserted(self) -> None:
        """The table gives no length for it, so nothing claims one."""
        assert self._problem(f"[file:hashes.'SSDEEP' = '{SSDEEP}']") == []

    def test_it_grounds_a_compound_pattern_in_either_order(self) -> None:
        fuzzy = f"[file:hashes.'SSDEEP' = '{SSDEEP}']"
        named = "[file:name = '/tmp/dropper.so']"
        for pattern in (f"{fuzzy} AND {named}", f"{named} AND {fuzzy}"):
            assert self._problem(pattern) == [], pattern

    def test_an_ungrounded_one_beside_a_refusable_comparison_still_reports_that_one(self) -> None:
        fuzzy = "[file:hashes.'SSDEEP' = '9:zzzz:yyyy']"
        vendor = "[url:value = 'https://pypi.org/simple/requests/']"
        for pattern in (f"{fuzzy} AND {vendor}", f"{vendor} AND {fuzzy}"):
            bundle = Bundle(objects=[_indicator(pattern)])
            found = [
                v.message for v in validate_verdict_bundle(bundle, evidence_corpus={FUZZY_EVIDENCE})
            ]
            assert found and "vendor infrastructure" in found[0], pattern

    def test_the_algorithm_name_is_not_asked_the_question(self) -> None:
        """``file:hashes.'SSDEEP'`` names the algorithm inside the object path."""
        from maljan.pipeline.validation import _comparisons

        assert _comparisons(f"[file:hashes.'SSDEEP' = '{SSDEEP}']") == [
            ("file:hashes.'ssdeep'", SSDEEP)
        ]

    def test_a_named_algorithm_still_answers_for_its_length(self) -> None:
        bundle = Bundle(objects=[_indicator("[file:hashes.'MD5' = '3:abcd:efgh']")])

        found = [
            v.message for v in validate_verdict_bundle(bundle, evidence_corpus={FUZZY_EVIDENCE})
        ]

        assert found and "MD5 is 32 hexadecimal characters" in found[0]

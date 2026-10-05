"""The event and transcript scrub never reaches report text, and reads words as words.

A local run's report printed "T1134 Access Token ***" in its validation
findings, and its events masked a family name: the finding rows that the
report prints went through the event scrub, the scheme rule took the word
after "Token" for a secret, and the length rule took a family name with a
capitalised piece inside it for a key.

Masking now applies only to events and the transcript, which the publisher
scrubs where the wire begins. A finding row keeps the words of the evidence
and of the catalogue it quotes; only the operator's own configured values are
kept out of it by value. In events, a capitalised word after "Token" and words
joined by separators, a capitalised compound among them, are words. Every
credential shape is still masked in events, after "Token" too.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from maljan.pipeline import events as ev
from maljan.pipeline.events import safe_finding_value, scrub
from maljan.pipeline.validation import ValidationTally, Violation
from maljan.reporting.models import FileHashes, MalwareReport, SampleIdentity
from maljan.reporting.renderers.markdown import MarkdownRenderer
from tests.credential_shapes import password, prefixed_key
from tests.unit.pipeline.test_live_event_schema import _every_key_shape

TECHNIQUE = "T1134 Access Token Manipulation"
# An invented family name of the shape that was masked: three pieces joined by
# slashes, 24 characters, one piece a capitalised compound.
FAMILY = "Rivulet/NorthWind/Calder"


@pytest.fixture(autouse=True)
def _no_configured_values() -> Iterator[None]:
    ev.forget_secret_values()
    yield
    ev.forget_secret_values()


class TestTheEventScrubReadsWordsAsWords:
    def test_a_capitalised_word_after_token_is_kept(self) -> None:
        assert scrub(f"carries TECHNIQUE {TECHNIQUE}, and") == f"carries TECHNIQUE {TECHNIQUE}, and"

    def test_a_family_name_with_a_compound_piece_is_kept(self) -> None:
        assert len(FAMILY) >= 24
        assert scrub(f"associated with the {FAMILY} family") == (
            f"associated with the {FAMILY} family"
        )

    def test_every_key_shape_is_still_masked_after_token(self) -> None:
        for key in _every_key_shape():
            assert key not in scrub(f"Access Token {key} here"), key

    def test_a_lowercase_password_after_token_is_still_masked(self) -> None:
        for length in (4, 8, 12, 30):
            secret = password(length)
            assert secret not in scrub(f"token {secret}"), secret

    def test_bearer_and_basic_still_mask_any_word(self) -> None:
        assert scrub("Bearer Manipulation") == "Bearer ***"
        assert scrub("Basic Abcdefgh") == "Basic ***"

    def test_every_key_shape_is_still_masked_alone_and_in_a_sentence(self) -> None:
        for key in _every_key_shape():
            assert key not in scrub(key), key
            assert key not in scrub(f"the analyst quoted {key} as the key"), key

    def test_a_mixed_case_run_with_digits_joined_by_slashes_is_still_a_key(self) -> None:
        key = "Ab3dEf9h/Kl2nOp4r/St6vWx8z"
        assert key not in scrub(f"value {key}")


class TestAFindingRowIsNotMasked:
    def test_the_row_keeps_the_catalogue_name(self) -> None:
        assert safe_finding_value(TECHNIQUE) == TECHNIQUE

    def test_the_row_keeps_a_credential_shape_the_evidence_holds(self) -> None:
        key = prefixed_key("ghs_", 36)
        assert safe_finding_value(f"the string {key}") == f"the string {key}"

    def test_the_row_keeps_a_url_and_a_path_as_written(self) -> None:
        value = "http://gate.example.com/live/?id=1 C:\\Users\\op\\x.exe"
        assert safe_finding_value(value) == value

    def test_the_row_is_still_bounded(self) -> None:
        bounded = safe_finding_value("word " * 200)
        assert len(bounded) <= ev.FINDING_VALUE_LIMIT + 1
        assert bounded.endswith(ev.CUT_MARK)

    def test_a_bound_never_splits_a_digest(self) -> None:
        digest = "ab" * 32
        bounded = safe_finding_value("x " * 90 + digest + " tail " * 20)
        assert digest in bounded

    def test_an_operator_configured_value_is_still_kept_out(self) -> None:
        configured = password(16, variant=3)
        ev.remember_secret_values([configured], scope="job")

        assert configured not in safe_finding_value(f"echoed {configured} back")

    def test_the_event_carrying_the_row_is_masked(self) -> None:
        from app.worker.analysis_worker import scrubbed

        key = prefixed_key("ghs_", 36)
        row = safe_finding_value(f"the string {key}")

        assert key not in str(scrubbed({"message": row}))


class TestTheReportMatchesTheEvidence:
    def test_the_printed_finding_carries_the_technique_name_whole(self) -> None:
        tally = ValidationTally()
        tally.record_unresolved(
            "triage",
            [
                Violation(
                    code="attck.claim_does_not_describe",
                    message=f"CLAIM 'x' carries TECHNIQUE {safe_finding_value(TECHNIQUE)}, and …",
                )
            ],
        )
        report = MalwareReport(
            identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
            verdict="Malware",
            run_summary={"validation": tally.to_dict()},
        )

        text = MarkdownRenderer().render(report)

        assert f"TECHNIQUE {TECHNIQUE}, and" in text
        assert "***" not in text

"""The composer shows each section the object it has to answer with.

Six live runs on two unrelated models authored zero professional sections
between them, and the worker log says why: every section came back with
renamed or superset keys, and ``conclusion`` and ``technical_analysis`` ended
``null`` in all six. The prompt's own rule said "output MUST conform to the
provided JSON schema" on the manual-parse path — the *primary* path on a local
server, because structured output is skipped there — and no schema was
provided on it. The only key name the model ever saw was the bundle's opening
line, ``SECTION: <name>``, which is a key with a value beside it, and the
answers came back keyed ``SECTION``/``content`` and ``<section name>``
accordingly.

Two fixes, and only two: the exact object is in the prompt, and a wrapper key
that is the section's own name holding a single string is moved to the field
that holds the section's prose. Everything else — a renamed key, two keys, a
value that needs interpreting — is dropped and named, as before.
"""

from __future__ import annotations

from maljan.reporting.composer import (
    _bundle_text,
    _C2Out,
    _CliFlagsOut,
    _expected_object,
    _IntroOut,
    _ProseOut,
    _section_text_envelope,
    _the_prose_field,
)
from maljan.reporting.models import Conclusion, EncryptionScheme, RansomNote

# What the two models answered with, section by section, read off the worker
# log of the recorded runs.
RECORDED_WRAPPER_KEYS = {
    "introduction": _IntroOut,
    "conclusion": Conclusion,
    "communications": _C2Out,
    "packing_obfuscation": _ProseOut,
    "discovery": _ProseOut,
    "persistence_detail": _ProseOut,
    "evasion_antiforensics": _ProseOut,
    "cli_flags": _CliFlagsOut,
}


class TestTheExactObjectIsInThePrompt:
    def test_every_field_the_schema_declares_is_named(self) -> None:
        assert _expected_object(_IntroOut) == '{"text": "..."}'
        assert _expected_object(_ProseOut) == '{"body": "...", "evidence_refs": ["..."]}'
        assert _expected_object(Conclusion) == '{"sophistication_rating": "...", "text": "..."}'

    def test_a_list_of_objects_shows_one_of_them(self) -> None:
        shown = _expected_object(_CliFlagsOut)

        assert shown.startswith('{"flags": [{')
        assert '"flag": "..."' in shown
        assert '"evidence_ref": "..."' in shown

    def test_a_boolean_field_is_not_shown_as_prose(self) -> None:
        assert '"per_file_key": true' in _expected_object(EncryptionScheme)

    def test_the_bundle_no_longer_opens_with_a_key(self) -> None:
        text = _bundle_text("introduction", {"facts": {"verdict": "Malware"}})

        assert not text.startswith("SECTION:")
        assert "introduction section" in text


class TestTheSectionsOwnNameHoldingAString:
    def test_the_introduction_s_text_is_recovered(self) -> None:
        moved = _section_text_envelope(
            {"introduction": "The sample is a signed SSH client."}, _IntroOut, "introduction"
        )

        assert moved == {"text": "The sample is a signed SSH client."}

    def test_a_prose_subsection_goes_to_its_body(self) -> None:
        moved = _section_text_envelope(
            {"packing_obfuscation": "No packer was identified."},
            _ProseOut,
            "packing_obfuscation",
        )

        assert moved == {"body": "No packer was identified."}

    def test_the_conclusion_goes_to_its_text_and_not_its_rating(self) -> None:
        moved = _section_text_envelope({"conclusion": "Low risk."}, Conclusion, "conclusion")

        assert moved == {"text": "Low risk."}

    def test_every_recorded_section_has_a_field_or_is_left_alone(self) -> None:
        for section, schema in RECORDED_WRAPPER_KEYS.items():
            moved = _section_text_envelope({section: "some prose"}, schema, section)
            field = _the_prose_field(schema)
            assert moved == ({field: "some prose"} if field else {section: "some prose"}), section


class TestWhatIsStillNotAccepted:
    def test_a_renamed_key_is_left_to_be_dropped(self) -> None:
        payload = {"summary": "The sample is packed."}

        assert _section_text_envelope(payload, _IntroOut, "introduction") == payload

    def test_two_keys_are_left_alone(self) -> None:
        payload = {"SECTION": "introduction", "content": "The sample is packed."}

        assert _section_text_envelope(payload, _IntroOut, "introduction") == payload

    def test_a_schema_with_several_prose_fields_is_not_guessed_at(self) -> None:
        payload = {"ransom_note": "YOUR FILES ARE ENCRYPTED"}

        assert _the_prose_field(RansomNote) is None
        assert _section_text_envelope(payload, RansomNote, "ransom_note") == payload

    def test_a_schema_with_no_prose_field_is_not_guessed_at(self) -> None:
        payload = {"communications": "beacons over HTTPS"}

        assert _section_text_envelope(payload, _C2Out, "communications") == payload

    def test_a_field_name_that_happens_to_match_is_not_reopened(self) -> None:
        payload = {"text": "already where it belongs"}

        assert _section_text_envelope(payload, _IntroOut, "text") == payload

    def test_an_empty_string_is_not_a_section(self) -> None:
        payload = {"introduction": "   "}

        assert _section_text_envelope(payload, _IntroOut, "introduction") == payload

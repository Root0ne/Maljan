"""The manual-parse path has to accept the shapes a local model actually emits.

Structured output is skipped on local OpenAI-compatible servers (see
``structured_output_supported``), which makes the manual JSON parse below it the
*primary* path rather than a rarely-taken fallback. That promotion exposed a
mismatch it had been hiding.

Measured live 2026-08-07, every structured section failing the same way:

    ReportComposer: section 'encryption_scheme' failed (1 validation error for
      EncryptionScheme
      encryption_scheme
        Extra inputs are not permitted [input_value='RC4, XOR']); SKIPPED.
    ReportComposer: section 'ransom_note' failed (1 validation error for
      RansomNote
      ransom_note
        Extra inputs are not permitted [input_value=None]); SKIPPED.

The model wraps its answer in a key named after the section — ``{"ransom_note":
{...}}`` — which is a perfectly reasonable reading of a prompt that says
"SECTION: ransom_note". The composer validated that envelope against the inner
schema, and ``extra="forbid"`` (deliberate, and worth keeping) rejected it.

Unwrapping is only safe when the envelope is unambiguous: exactly one key, and
the payload underneath is an object. Anything else is passed through untouched
so a genuine single-field response is never silently reinterpreted.

The ``input_value=None`` shape above is the one exception, settled on 2026-09-08
after a full-profile run logged it three times for one report: ``{"<section>":
null}`` is the model declining the section, and ``_section_declined`` lets the
composer skip it without calling it a failure. The scalar envelope stays a
failure.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import BaseModel, ConfigDict, ValidationError

from maljan.reporting.composer import _section_declined, _unwrap_section_envelope


class _Demo(BaseModel):
    model_config = ConfigDict(extra="forbid")
    algorithm: str = ""
    key_source: str = ""


class TestASectionKeyedEnvelopeIsOpened:
    def test_a_single_wrapping_key_is_removed(self) -> None:
        payload = {"encryption_scheme": {"algorithm": "RC4", "key_source": "hardcoded"}}
        assert _unwrap_section_envelope(payload, _Demo) == {
            "algorithm": "RC4",
            "key_source": "hardcoded",
        }

    def test_the_unwrapped_payload_validates(self) -> None:
        payload = {"encryption_scheme": {"algorithm": "XOR"}}
        assert _Demo.model_validate(_unwrap_section_envelope(payload, _Demo)).algorithm == "XOR"

    def test_the_wrapping_key_name_does_not_matter(self) -> None:
        """The model names it after whatever the prompt called the section."""
        payload = {"ransom_note": {"algorithm": "AES"}}
        assert _unwrap_section_envelope(payload, _Demo) == {"algorithm": "AES"}


class TestAnAmbiguousPayloadIsLeftAlone:
    def test_a_flat_payload_is_untouched(self) -> None:
        payload = {"algorithm": "RC4", "key_source": "derived"}
        assert _unwrap_section_envelope(payload, _Demo) == payload

    def test_a_single_key_that_is_a_real_field_is_untouched(self) -> None:
        """``{"algorithm": {...}}`` is a field, not an envelope."""
        payload = {"algorithm": {"nested": "thing"}}
        assert _unwrap_section_envelope(payload, _Demo) == payload

    def test_a_single_key_with_a_scalar_value_is_untouched(self) -> None:
        """``{"encryption_scheme": "RC4, XOR"}`` carries no object to unwrap.

        This is the exact live payload. There is nothing to recover here, and
        inventing a mapping would be guessing — it must still be rejected.
        """
        payload = {"encryption_scheme": "RC4, XOR"}
        assert _unwrap_section_envelope(payload, _Demo) == payload
        with pytest.raises(ValidationError):
            _Demo.model_validate(_unwrap_section_envelope(payload, _Demo))

    def test_two_keys_are_never_an_envelope(self) -> None:
        payload = {"encryption_scheme": {"algorithm": "RC4"}, "note": "extra"}
        assert _unwrap_section_envelope(payload, _Demo) == payload

    @pytest.mark.parametrize("payload", [None, [], "text", 3])
    def test_non_dict_input_is_returned_unchanged(self, payload: Any) -> None:
        assert _unwrap_section_envelope(payload, _Demo) == payload


class TestANullEnvelopeIsADeclinedSection:
    def test_a_section_key_holding_null_is_declined(self) -> None:
        assert _section_declined({"ransom_note": None}, _Demo) is True

    def test_a_declined_section_is_not_unwrapped_into_the_schema(self) -> None:
        # The unwrapper leaves it alone (no object to recover), and validation
        # would reject it, which is exactly why the caller checks ``declined``
        # before validating.
        payload = {"ransom_note": None}
        assert _unwrap_section_envelope(payload, _Demo) == payload
        with pytest.raises(ValidationError):
            _Demo.model_validate(payload)

    def test_a_real_field_set_to_null_is_not_a_declined_section(self) -> None:
        assert _section_declined({"algorithm": None}, _Demo) is False

    def test_a_scalar_envelope_is_not_declined(self) -> None:
        assert _section_declined({"encryption_scheme": "RC4, XOR"}, _Demo) is False

    def test_an_object_envelope_is_not_declined(self) -> None:
        assert _section_declined({"encryption_scheme": {"algorithm": "XOR"}}, _Demo) is False

    def test_two_keys_are_never_a_declined_section(self) -> None:
        assert _section_declined({"a": None, "b": None}, _Demo) is False

    @pytest.mark.parametrize("payload", [None, "", [], 0, "null"])
    def test_non_dict_input_is_not_declined(self, payload: Any) -> None:
        assert _section_declined(payload, _Demo) is False

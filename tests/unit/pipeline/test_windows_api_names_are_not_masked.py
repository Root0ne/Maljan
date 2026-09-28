"""A Windows API name, or a hash-algorithm id, travels in events and the transcript as written.

The scrub's length rule reads an unbroken run of 24 characters or more as a
key. A long Windows function name is such a run, and so are two algorithm ids
joined by a slash. Both reached the live console and the stored transcript as
``***`` while the report printed them whole.

Three kinds of name are names and not keys:

- a name the vendored export-name catalogue holds;
- a name this run's hash resolution read on the analysis server;
- a hash-algorithm id from the vendored algorithm catalogue.

Each is kept alone, after a module and ``!``, or joined to others of its kind
by ``/``, ``|``, ``+`` or ``&``.

Nothing else changes. Every credential shape is still masked, whether alone,
after a module, or joined to a name. A configured value is still masked by
value, whatever it spells.
"""

from __future__ import annotations

import json
from collections.abc import Iterator

import pytest

from maljan.agents.evidence_recorder import EvidenceRecorder
from maljan.pipeline import events as ev
from tests.unit.pipeline.test_live_event_schema import _every_key_shape

# A real export past the length floor, a pair of real algorithm ids, and a name
# only a run resolved: made up, mixed case with a digit, so no word rule
# exempts it.
CATALOGUE_NAME = "ZwSetInformationJobObject"
ALGORITHMS = "ror13_module_add/fnv1a32_lower"
RESOLVED_ONLY = "SyntheticResolvedExport32NameW"


@pytest.fixture(autouse=True)
def _clean() -> Iterator[None]:
    ev.forget_resolved_names()
    ev.forget_secret_values()
    yield
    ev.forget_resolved_names()
    ev.forget_secret_values()


def _resolution(*names: str) -> dict[str, object]:
    return {
        "hits": [
            {
                "value": "0x12345678",
                "readings": [
                    {"algorithm": "crc32", "set": "exports", "name": name, "dlls": ["x.dll"]}
                    for name in names
                ],
            }
        ],
        "lone_hits": [
            {"value": "0x9abcdef0", "readings": [{"set": "exports", "name": "LoneHitName"}]}
        ],
    }


class TestTheCatalogue:
    def test_a_long_catalogue_name_is_written_as_it_is(self) -> None:
        assert len(CATALOGUE_NAME) >= 24
        assert ev.scrub(f"calls {CATALOGUE_NAME} to limit a job") == (
            f"calls {CATALOGUE_NAME} to limit a job"
        )

    def test_inside_json_and_with_its_module(self) -> None:
        text = json.dumps({"api": CATALOGUE_NAME, "at": f"kernel32.dll!{CATALOGUE_NAME}"})
        assert ev.scrub(text) == text

    def test_a_module_name_and_a_key_after_it_is_masked(self) -> None:
        for shape in _every_key_shape():
            assert shape not in ev.scrub(f"kernel32.dll!{shape}"), shape
            assert shape not in ev.scrub(f"{shape}!{CATALOGUE_NAME}"), shape

    def test_joined_algorithm_ids_are_written_as_they_are(self) -> None:
        assert len(ALGORITHMS) >= 24
        assert ev.scrub(f"algorithms {ALGORITHMS} matched") == f"algorithms {ALGORITHMS} matched"
        assert (
            ev.scrub("crc32_ascii_lower|djb2_lower+ror13") == "crc32_ascii_lower|djb2_lower+ror13"
        )

    def test_an_algorithm_id_joined_to_a_key_is_masked(self) -> None:
        for shape in _every_key_shape():
            for joined in (f"djb2_lower/{shape}", f"{shape}/djb2_lower", f"{shape}|ror13"):
                assert shape not in ev.scrub(joined), joined

    def test_only_the_key_shaped_piece_of_a_joined_run_is_masked(self) -> None:
        # A random segment of 24 or more characters: read as a key by its shape.
        segment = "Q" * 26
        cases = {
            f"example.com/gate/{segment}/x.php": "example.com/gate/***/x.php",
            f"to %APPDATA%/Vendor/{segment}/svc.exe": "to %APPDATA%/Vendor/***/svc.exe",
            f"samples/extracted/{segment}/payload.bin": "samples/extracted/***/payload.bin",
            f"Assembly.GetCallingAssembly/{segment}": "Assembly.GetCallingAssembly/***",
        }
        for text, said in cases.items():
            assert ev.scrub(text) == said, text
            assert ev.safe_finding_value(text) == said, text

    def test_every_key_shape_in_every_joined_form_is_masked(self) -> None:
        for shape in _every_key_shape():
            for joined in (
                *(f"left{joiner}{shape}{joiner}right" for joiner in "/|+&"),
                *(f"{shape}{joiner}right" for joiner in "/|+&"),
                *(f"left{joiner}{shape}" for joiner in "/|+&"),
                f"kernel32.dll!{shape}",
                f"{shape}!{CATALOGUE_NAME}",
            ):
                for scrubbed in (
                    ev.scrub(joined),
                    ev.scrub_keeping_layout(joined),
                    ev.safe_finding_value(joined),
                ):
                    assert shape not in scrubbed, joined

    def test_a_name_the_catalogue_does_not_hold_is_still_read_by_shape(self) -> None:
        assert ev.scrub(RESOLVED_ONLY) == "***"

    def test_the_transcript_scrub_keeps_it_too(self) -> None:
        text = f"Claim 3: limits a job with {CATALOGUE_NAME}\n  Evidence: [ev_0004]"
        assert ev.scrub_keeping_layout(text) == text


class TestTheNamesThisRunResolved:
    def test_a_resolved_name_is_written_as_it_is(self) -> None:
        ev.remember_resolved_names(_resolution(RESOLVED_ONLY))
        assert ev.scrub(f"resolves {RESOLVED_ONLY}") == f"resolves {RESOLVED_ONLY}"

    def test_the_answer_may_arrive_as_its_json_text(self) -> None:
        ev.remember_resolved_names(json.dumps(_resolution(RESOLVED_ONLY)))
        assert ev.scrub(RESOLVED_ONLY) == RESOLVED_ONLY

    def test_forgotten_at_the_next_job(self) -> None:
        ev.remember_resolved_names(_resolution(RESOLVED_ONLY))
        ev.forget_resolved_names()
        assert ev.scrub(RESOLVED_ONLY) == "***"

    def test_the_recorder_hands_the_scrub_a_resolution_it_records(self) -> None:
        for server in ("analysis", "pipeline"):
            ev.forget_resolved_names()
            recorder = EvidenceRecorder("static")
            recorder.record(
                tool="resolve_api_hashes",
                args={"path": "s.exe"},
                server=server,
                output=json.dumps(_resolution(RESOLVED_ONLY)),
            )
            assert ev.scrub(RESOLVED_ONLY) == RESOLVED_ONLY, server

    def test_another_server_s_tool_of_that_name_registers_nothing(self) -> None:
        for server in ("custom", None):
            recorder = EvidenceRecorder("static")
            recorder.record(
                tool="resolve_api_hashes",
                args={"path": "s.exe"},
                server=server,
                output=json.dumps(_resolution(RESOLVED_ONLY)),
            )
            assert ev.scrub(RESOLVED_ONLY) == "***", server

    def test_another_tool_s_answer_registers_nothing(self) -> None:
        recorder = EvidenceRecorder("static")
        recorder.record(
            tool="strings",
            args={"path": "s.exe"},
            server="analysis",
            output=json.dumps(_resolution(RESOLVED_ONLY)),
        )
        assert ev.scrub(RESOLVED_ONLY) == "***"

    def test_a_reading_that_is_no_identifier_is_not_taken(self) -> None:
        ev.remember_resolved_names(_resolution("two words here and more past the floor"))
        # The lone hit's name alone.
        assert ev.resolved_names_held() == 1


class TestNothingElseChanges:
    def test_every_credential_shape_is_still_masked(self) -> None:
        ev.remember_resolved_names(_resolution(RESOLVED_ONLY))
        for shape in _every_key_shape():
            assert shape not in ev.scrub(f"{CATALOGUE_NAME} {shape} {RESOLVED_ONLY}"), shape
            assert CATALOGUE_NAME in ev.scrub(f"{CATALOGUE_NAME} {shape}")
            assert shape not in ev.scrub(f"{ALGORITHMS} {shape} {CATALOGUE_NAME}/{shape}"), shape

    def test_a_credential_shape_a_resolution_names_is_still_masked(self) -> None:
        # Only a real identifier shape is taken, and a vendor prefix is a key
        # whatever else reads it.
        shapes = _every_key_shape()
        ev.remember_resolved_names(_resolution(*shapes))
        for shape in shapes:
            assert shape not in ev.scrub(f"value {shape}"), shape

    def test_a_configured_value_is_masked_by_value_whatever_it_spells(self) -> None:
        ev.remember_secret_values([CATALOGUE_NAME], scope="job")
        ev.remember_resolved_names(_resolution(CATALOGUE_NAME))
        assert CATALOGUE_NAME not in ev.scrub(f"calls {CATALOGUE_NAME}")

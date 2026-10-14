"""An attack-pattern declares a technique by an id, never by a name that begins with a T.

"Timestomp" and "Token Impersonation" are behaviours. The validator, the
capability matrix and the STIX export read what an attack-pattern writes
(``technique_ids.written_technique_id``): its ATT&CK reference as written, so a
malformed one is asked about or marked, else an id its name opens with. A
reader that keys something by the technique (a credit) reads
``declared_technique_id``, where a tactic, group or software reference is no
technique.
"""

from __future__ import annotations

from typing import Any

import pytest

from maljan.analysis.technique_ids import (
    attack_reference_id,
    declared_reference_id,
    declared_technique_id,
    name_technique_id,
    written_technique_id,
)
from maljan.extractors.capability_matrix import bundle_technique_ids, unmapped_behaviours
from maljan.pipeline.validation import MISSING_ID_CODE, validate_verdict_bundle
from maljan.reporting.renderers.stix_renderer import _declared_technique
from maljan.schemas.stix_models import Bundle

_STAMP = "2026-01-01T00:00:00.000Z"
_PATTERN_ID = "attack-pattern--11111111-1111-4111-8111-111111111111"
_MALWARE_ID = "malware--22222222-2222-4222-8222-222222222222"


def _mitre(external_id: str) -> dict[str, str]:
    return {"source_name": "mitre-attack", "external_id": external_id}


def _pattern(**extra: Any) -> dict[str, Any]:
    return {
        "type": "attack-pattern",
        "spec_version": "2.1",
        "id": _PATTERN_ID,
        "created": _STAMP,
        "modified": _STAMP,
        **extra,
    }


def _bundle(pattern: dict[str, Any]) -> dict[str, Any]:
    malware = {
        "type": "malware",
        "spec_version": "2.1",
        "id": _MALWARE_ID,
        "created": _STAMP,
        "modified": _STAMP,
        "name": "sample",
        "is_family": False,
    }
    uses = {
        "type": "relationship",
        "spec_version": "2.1",
        "id": "relationship--33333333-3333-4333-8333-333333333333",
        "created": _STAMP,
        "modified": _STAMP,
        "relationship_type": "uses",
        "source_ref": _MALWARE_ID,
        "target_ref": _PATTERN_ID,
        "x_maljan_contributing_agents": ["static"],
    }
    return {
        "type": "bundle",
        "id": "bundle--44444444-4444-4444-8444-444444444444",
        "objects": [malware, pattern, uses],
    }


def _codes_and_messages(raw: dict[str, Any]) -> list[tuple[str, str]]:
    found = validate_verdict_bundle(
        Bundle.model_validate(raw), None, technique_sources={"T1027": ["static"]}
    )
    return [(v.code, v.message) for v in found]


class TestTheReader:
    @pytest.mark.parametrize("name", ["Timestomp", "Token Impersonation", "TA0005 tactic"])
    def test_a_name_that_begins_with_t_declares_nothing(self, name: str) -> None:
        assert name_technique_id({"name": name}) == ""
        assert declared_technique_id(_pattern(name=name)) == ""

    @pytest.mark.parametrize(
        "name",
        [
            "T1055 Process Injection",
            "t1055: Process Injection",
            "T1055-Process Injection",
            "T1055, Process Injection",
            "[T1055] Process Injection",
            "(T1055) Process Injection",
            "T1055",
            "T1055.",
        ],
    )
    def test_a_name_that_opens_with_an_id_declares_it(self, name: str) -> None:
        assert name_technique_id({"name": name}) == "T1055"

    @pytest.mark.parametrize(
        "name", ["T1055.0123 x", "T1055.012x", "T1055_x", "AT1055 x", "x T1055", "T10555"]
    )
    def test_a_name_that_opens_with_no_whole_id_declares_none(self, name: str) -> None:
        assert name_technique_id({"name": name}) == ""

    def test_a_sub_technique_opens_a_name_whole(self) -> None:
        assert name_technique_id({"name": "T1055.012: Process Hollowing"}) == "T1055.012"

    @pytest.mark.parametrize("external_id", ["TA0005", "S0154", "G0016", "T1055.1", "CAPEC-1"])
    def test_an_attack_reference_that_is_no_technique_is_not_read_as_one(
        self, external_id: str
    ) -> None:
        obj = _pattern(name="x", external_references=[_mitre(external_id)])
        assert attack_reference_id(obj) == ""
        # The id as written stays readable for a check that has to say it is malformed.
        assert declared_reference_id(obj) == external_id

    def test_the_first_technique_reference_answers(self) -> None:
        obj = _pattern(name="x", external_references=[_mitre("TA0005"), _mitre("t1055.012")])
        assert attack_reference_id(obj) == "T1055.012"
        assert declared_technique_id(obj) == "T1055.012"
        # What was written first is what a check of the declaration reads.
        assert written_technique_id(obj) == "TA0005"

    def test_the_written_reader_takes_the_name_only_when_it_opens_with_an_id(self) -> None:
        assert written_technique_id(_pattern(name="T1055 Process Injection")) == "T1055"
        assert written_technique_id(_pattern(name="Timestomp")) == ""

    def test_a_model_reads_like_a_dict(self) -> None:
        raw = _bundle(_pattern(name="Token Impersonation"))
        model = Bundle.model_validate(raw).objects[1]
        assert declared_technique_id(model) == declared_technique_id(raw["objects"][1]) == ""


class TestTheValidator:
    def test_a_name_only_behaviour_is_asked_for_its_id(self) -> None:
        found = _codes_and_messages(_bundle(_pattern(name="Timestomp")))
        assert [code for code, _ in found] == [MISSING_ID_CODE]
        assert "'Timestomp' names no MITRE ATT&CK technique id" in found[0][1]
        # And no credit is asked about against a word that is not an id.
        assert not any("TIMESTOMP" in message for _, message in found)

    def test_a_malformed_reference_is_still_asked_about_as_malformed(self) -> None:
        raw = _bundle(_pattern(name="Defense Evasion", external_references=[_mitre("TA0005")]))
        found = _codes_and_messages(raw)
        assert ("stix.unknown_technique") in [code for code, _ in found]
        assert any("names TA0005, which is not shaped like" in m for _, m in found)
        # The credit question is about techniques: none is keyed by the tactic.
        assert not any(code == "stix.credit_without_claim" for code, _ in found)


class TestTheMatrixAndTheExport:
    def test_a_behaviour_is_listed_and_not_lost_from_both_lists(self) -> None:
        raw = _bundle(_pattern(name="Token Impersonation"))
        assert unmapped_behaviours(raw) == ["Token Impersonation"]
        assert bundle_technique_ids(raw) == set()

    def test_an_id_the_name_opens_with_is_a_technique_in_the_matrix(self) -> None:
        raw = _bundle(_pattern(name="T1055 Process Injection"))
        assert unmapped_behaviours(raw) == []
        assert bundle_technique_ids(raw) == {"T1055"}

    def test_a_tactic_reference_stays_a_row_the_matrix_marks(self) -> None:
        # The matrix shows what the judge wrote and marks an id the catalogue
        # refuses; it is neither dropped nor turned into a behaviour.
        raw = _bundle(_pattern(name="Defense Evasion", external_references=[_mitre("TA0005")]))
        assert bundle_technique_ids(raw) == {"TA0005"}
        assert unmapped_behaviours(raw) == []

    def test_the_export_names_a_behaviour_by_its_name(self) -> None:
        model = Bundle.model_validate(_bundle(_pattern(name="Timestomp"))).objects[1]
        assert _declared_technique(model) == ""

"""The ids a bundle is published under are the platform's, never copied ones.

An id is a label, not a claim: nothing the judge decides is carried by the hex
digits after ``--``. The judge wrote them anyway, and wrote them the way a model
writes a UUID it cannot generate — a run of sequential hex out of the STIX
documentation. The stored exports held one ``malware--b2c3d4e5-…`` in fourteen
runs of six different samples, so a consumer merging on id folds fourteen
analyses into one malware object; and its version digit is ``8``, which no RFC
4122 UUID has, so the OASIS validator refused every object carrying it or
pointing at it. The id check only asked for eight-four-four-four-twelve hex.
"""

from __future__ import annotations

import copy
import re

from maljan.agents.judge_postprocess import postprocess_judge_bundle

# The identifier pattern of the STIX 2.1 JSON schemas: an RFC 4122 UUID, its
# version digit 1-5 and its variant digit 8, 9, a or b.
STIX_ID_RE = re.compile(
    r"^[a-z][a-z0-9-]+[a-z0-9]--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}"
    r"-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)

MALWARE = "malware--b2c3d4e5-f6a7-8901-bcde-f12345678901"
INDICATOR = "indicator--c3d4e5f6-a7b8-9012-cdef-123456789012"
PATTERN = "attack-pattern--d4e5f6a7-b8c9-0123-defa-234567890123"


def _judge_bundle() -> dict:
    return {
        "type": "bundle",
        "id": "bundle--a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "objects": [
            {"type": "malware", "id": MALWARE, "name": "sample", "is_family": False},
            {
                "type": "indicator",
                "id": INDICATOR,
                "pattern": "[ipv4-addr:value = '82.157.13.47']",
                "pattern_type": "stix",
                "valid_from": "2026-09-22T00:00:00Z",
            },
            {
                "type": "attack-pattern",
                "id": PATTERN,
                "name": "Application Layer Protocol",
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1071"}],
            },
            {
                "type": "relationship",
                "id": "relationship--a7b8c9d0-e1f2-3456-abcd-567890123456",
                "relationship_type": "indicates",
                "source_ref": INDICATOR,
                "target_ref": MALWARE,
            },
            {
                "type": "relationship",
                "id": "relationship--d0e1f2a3-b4c5-6789-defa-890123456789",
                "relationship_type": "uses",
                "source_ref": MALWARE,
                "target_ref": PATTERN,
                "x_maljan_confidence": 0.95,
            },
        ],
    }


def _by_type(bundle: dict) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for obj in bundle["objects"]:
        out.setdefault(obj["type"], []).append(obj)
    return out


class TestEveryPublishedIdIsAUuid:
    def test_a_hex_run_that_is_no_uuid_is_replaced(self) -> None:
        bundle = postprocess_judge_bundle(_judge_bundle())

        for obj in bundle["objects"]:
            assert STIX_ID_RE.match(obj["id"]), obj["id"]
            for key in ("source_ref", "target_ref"):
                if key in obj:
                    assert STIX_ID_RE.match(obj[key]), obj[key]

    def test_the_references_follow_the_objects_they_named(self) -> None:
        bundle = postprocess_judge_bundle(_judge_bundle())
        kinds = _by_type(bundle)
        malware = kinds["malware"][0]["id"]
        indicator = kinds["indicator"][0]["id"]
        pattern = kinds["attack-pattern"][0]["id"]

        indicates, uses = kinds["relationship"]
        assert (indicates["source_ref"], indicates["target_ref"]) == (indicator, malware)
        assert (uses["source_ref"], uses["target_ref"]) == (malware, pattern)
        # The annotation travels with the edge; only the labels changed.
        assert uses["x_maljan_confidence"] == 0.95

    def test_two_runs_that_copied_the_same_id_publish_two_objects(self) -> None:
        first = postprocess_judge_bundle(_judge_bundle())
        second = postprocess_judge_bundle(_judge_bundle())

        first_malware = _by_type(first)["malware"][0]["id"]
        second_malware = _by_type(second)["malware"][0]["id"]
        assert first_malware != second_malware
        assert MALWARE not in (first_malware, second_malware)

    def test_a_short_label_is_enough_to_link_objects(self) -> None:
        bundle = {
            "type": "bundle",
            "objects": [
                {"type": "malware", "id": "malware--1", "name": "sample", "is_family": False},
                {
                    "type": "indicator",
                    "id": "indicator--1",
                    "pattern": "[url:value = 'http://example.org/a']",
                    "pattern_type": "stix",
                },
                {
                    "type": "relationship",
                    "id": "relationship--1",
                    "relationship_type": "indicates",
                    "source_ref": "indicator--1",
                    "target_ref": "malware--1",
                },
            ],
        }
        out = postprocess_judge_bundle(bundle)
        kinds = _by_type(out)

        edge = kinds["relationship"][0]
        assert edge["source_ref"] == kinds["indicator"][0]["id"]
        assert edge["target_ref"] == kinds["malware"][0]["id"]
        assert all(STIX_ID_RE.match(obj["id"]) for obj in out["objects"])

    def test_the_id_names_the_type_the_object_is(self) -> None:
        bundle = {
            "type": "bundle",
            "objects": [
                {
                    "type": "indicator",
                    "id": "malware--3",
                    "pattern": "[url:value = 'http://example.org/a']",
                    "pattern_type": "stix",
                }
            ],
        }
        out = postprocess_judge_bundle(copy.deepcopy(bundle))

        assert out["objects"][0]["id"].startswith("indicator--")


class TestTheJudgeIsNotAskedForUuids:
    def test_the_prompt_asks_for_labels_and_says_who_assigns_the_ids(self) -> None:
        from maljan.agents.judge_agent import JUDGE_VERDICT_SYSTEM

        assert "uuid4" not in JUDGE_VERDICT_SYSTEM
        assert "<type>--<label>" in JUDGE_VERDICT_SYSTEM
        assert "the published ids are assigned after you answer" in JUDGE_VERDICT_SYSTEM

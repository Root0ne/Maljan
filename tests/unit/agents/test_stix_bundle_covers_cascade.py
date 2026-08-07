"""The STIX bundle must carry what the report says it found.

Measured across two live runs of the same sample on 2026-08-07:

    judge LLM timed out -> deterministic fallback:  33 attack-patterns, 33 with external_id
    judge LLM succeeded                          :   5 attack-patterns,  0 with external_id

The successful run was strictly the worse artefact. Its five patterns carried
free-form names and no ``external_references`` at all — two of them not even
canonical ATT&CK names ("Standard Application Layer Protocol", "File and
Directory Enumeration") — while ``ttp_mappings`` in the very same report listed
39 techniques. An ``attack-pattern`` with no ``external_id`` is unusable to a
downstream consumer: the technique ID *is* the ATT&CK mapping.

Both existing guards missed it because both key off a technique ID the LLM
never supplied. REP-02 drops orphans via ``if tid and tid not in valid_ids`` —
a ``None`` tid keeps the object. REP-01 back-fills references only once a tid
resolves. When the model writes prose names with no IDs anywhere, both are
no-ops, and nothing in the pipeline ever *adds* the techniques the model left
out: the bundle was only ever a filtered view of the LLM's output.

So the bundle is now reconciled against the cascade, which is the same set the
report's own capability matrix is built from.
"""

from __future__ import annotations

import re
from typing import Any

from maljan.agents.judge_postprocess import postprocess_judge_bundle

_TID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def _bundle(*objects: dict[str, Any]) -> dict[str, Any]:
    return {"type": "bundle", "id": "bundle--x", "objects": list(objects)}


def _malware() -> dict[str, Any]:
    return {"type": "malware", "id": "malware--m", "name": "sample", "is_family": False}


def _ap(name: str, tid: str | None = None) -> dict[str, Any]:
    obj: dict[str, Any] = {"type": "attack-pattern", "id": f"attack-pattern--{name}", "name": name}
    if tid:
        obj["external_references"] = [{"source_name": "mitre-attack", "external_id": tid}]
    return obj


def _patterns(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    return [o for o in bundle["objects"] if o.get("type") == "attack-pattern"]


def _ids(bundle: dict[str, Any]) -> set[str]:
    out = set()
    for o in _patterns(bundle):
        for ref in o.get("external_references") or []:
            ext = ref.get("external_id")
            if isinstance(ext, str) and _TID_RE.match(ext):
                out.add(ext)
    return out


class TestEveryCascadeTechniqueReachesTheBundle:
    def test_techniques_the_model_omitted_are_added(self) -> None:
        """The live failure: 5 emitted, 39 in the cascade."""
        cascade = frozenset({"T1055", "T1055.012", "T1027", "T1071.001", "T1547.001"})
        out = postprocess_judge_bundle(
            _bundle(_malware(), _ap("Process Hollowing", "T1055.012")),
            valid_technique_ids=cascade,
        )
        assert _ids(out) == cascade

    def test_each_added_pattern_carries_a_mitre_external_id(self) -> None:
        cascade = frozenset({"T1083", "T1112"})
        out = postprocess_judge_bundle(_bundle(_malware()), valid_technique_ids=cascade)

        for ap in _patterns(out):
            refs = ap.get("external_references") or []
            assert any(
                r.get("source_name") == "mitre-attack" and _TID_RE.match(str(r.get("external_id")))
                for r in refs
            ), f"attack-pattern without a MITRE external_id is unusable: {ap}"

    def test_added_patterns_are_linked_to_the_malware(self) -> None:
        """An attack-pattern nothing points at says nothing about this sample."""
        out = postprocess_judge_bundle(
            _bundle(_malware()), valid_technique_ids=frozenset({"T1083"})
        )
        rels = [o for o in out["objects"] if o.get("type") == "relationship"]
        ap_ids = {o["id"] for o in _patterns(out)}
        assert any(r.get("target_ref") in ap_ids for r in rels)

    def test_a_technique_the_model_supplied_is_not_duplicated(self) -> None:
        cascade = frozenset({"T1055", "T1083"})
        out = postprocess_judge_bundle(
            _bundle(_malware(), _ap("Process Injection", "T1055")),
            valid_technique_ids=cascade,
        )
        assert len(_patterns(out)) == 2
        assert _ids(out) == cascade


class TestAnUnidentifiablePatternIsNotPassedThrough:
    def test_a_pattern_with_no_resolvable_id_is_dropped(self) -> None:
        """ "Standard Application Layer Protocol" with no external_id, verbatim."""
        out = postprocess_judge_bundle(
            _bundle(_malware(), _ap("Standard Application Layer Protocol")),
            valid_technique_ids=frozenset({"T1071.001"}),
        )
        names = {o.get("name") for o in _patterns(out)}
        assert "Standard Application Layer Protocol" not in names

    def test_its_dangling_relationships_go_with_it(self) -> None:
        ap = _ap("File and Directory Enumeration")
        rel = {
            "type": "relationship",
            "id": "relationship--r",
            "relationship_type": "uses",
            "source_ref": "malware--m",
            "target_ref": ap["id"],
        }
        out = postprocess_judge_bundle(
            _bundle(_malware(), ap, rel), valid_technique_ids=frozenset({"T1083"})
        )
        assert all(o.get("target_ref") != ap["id"] for o in out["objects"])


class TestTheReconciliationIsOptIn:
    def test_without_a_cascade_the_bundle_is_left_alone(self) -> None:
        """No cascade means no authority to add anything — callers may omit it."""
        out = postprocess_judge_bundle(_bundle(_malware(), _ap("Process Injection", "T1055")))
        assert _ids(out) == {"T1055"}
        assert len(_patterns(out)) == 1

    def test_an_empty_cascade_adds_nothing(self) -> None:
        out = postprocess_judge_bundle(
            _bundle(_malware(), _ap("Process Injection", "T1055")),
            valid_technique_ids=frozenset(),
        )
        assert len(_patterns(out)) <= 1

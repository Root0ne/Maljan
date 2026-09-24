"""The export carries the ledger ids the run's record ties to its objects.

A graph of the bundle had nothing to link a reader to: no exported object held
a ledger id in a property, so every node said it carried none. The record
already holds the ties. An analyst finding names its techniques and cites its
entries, an asserting tool's entry names a technique in its own structured
output, and the attribution cites the entries its family name was read from.
The export writes those, as ``x_maljan_evidence_refs``, on the sample's
``uses`` edge to each technique and on a malware object it mints from the
family. It writes nothing it would have to infer: no id read out of a
sentence, no object matched by value, and no property where the record ties
nothing.
"""

from __future__ import annotations

import json
import random
from typing import Any

from stix2validator import ValidationOptions, validate_instance

from maljan.agents.judge_postprocess import (
    PROPERTY_NOT_CARRIED_CODE,
    lift_misplaced_extensions,
    postprocess_judge_bundle,
)
from maljan.pipeline.evidence_summary import technique_evidence
from maljan.reporting.builder import MalwareReportBuilder
from maljan.reporting.models import MalwareReport
from maljan.reporting.renderers.stix_renderer import (
    EVIDENCE_REF_NOT_IN_LEDGER_CODE,
    ExtendedSTIXRenderer,
)
from maljan.schemas.evidence import LedgerEntry
from maljan.schemas.isr_models import AgentISR, ClaimEvidence, Finding
from maljan.schemas.stix_models import EVIDENCE_REFS_PROPERTY, Bundle, attack_pattern_id

SHA256 = "36dabc40fa8983ce900a90b8156d2c754875fe1b5413a997843c4a0ef3908220"

# The run's ledger in its order, for the export tests: out of numeric order on
# purpose, so ledger order and id order can be told apart.
LEDGER_IDS = ["ev_0001", "ev_0002", "ev_0004", "ev_0003", "ev_0007", "ev_0012"]


def _entry(eid: str, tool: str = "pe_info", structured: Any = None, seq: int = 0) -> LedgerEntry:
    return LedgerEntry(id=eid, tool=tool, structured=structured, seq=seq)


def _ledger() -> list[LedgerEntry]:
    return [
        _entry("ev_0001", seq=1),
        _entry("ev_0002", tool="capa", structured={"rules": [{"attck": ["T1055"]}]}, seq=2),
        _entry("ev_0003", seq=3),
        _entry("ev_0004", tool="attck_lookup", structured={"technique_id": "T1071"}, seq=4),
        _entry("ev_0010", seq=10),
    ]


def _isr(*, findings: list[Finding] = (), claims: list[ClaimEvidence] = ()) -> AgentISR:
    return AgentISR(
        agent_id="static", domain="static", claims=list(claims), findings=list(findings)
    )


class TestTheRecordReader:
    def test_a_finding_ties_its_techniques_to_the_entries_it_cites(self) -> None:
        isr = _isr(
            findings=[
                Finding(
                    title="injects", technique_ids=["t1055"], evidence_ids=["ev_0003", "ev_0001"]
                )
            ]
        )

        assert technique_evidence({"static": isr}, _ledger())["T1055"] == [
            "ev_0001",
            "ev_0002",
            "ev_0003",
        ]

    def test_an_asserting_tool_entry_is_its_own_evidence_and_a_lookup_is_not(self) -> None:
        ties = technique_evidence({}, _ledger())

        assert ties == {"T1055": ["ev_0002"]}

    def test_an_id_in_a_claims_sentence_stays_in_the_sentence(self) -> None:
        isr = _isr(
            claims=[
                ClaimEvidence(
                    claim="Uses HTTP for C2",
                    evidence_ref="PCAP frame 42: dst=198.51.100.5:443 [ev_0010]",
                    confidence=0.8,
                    technique_id="T1071",
                )
            ]
        )

        assert "T1071" not in technique_evidence({"static": isr}, _ledger())

    def test_an_id_the_ledger_does_not_hold_is_left_out_and_repeats_are_one(self) -> None:
        isr = _isr(
            findings=[
                Finding(title="a", technique_ids=["T1082"], evidence_ids=["ev_0010", "ev_0099"]),
                Finding(title="b", technique_ids=["T1082"], evidence_ids=["ev_0010", "note"]),
            ]
        )

        assert technique_evidence({"static": isr}, _ledger())["T1082"] == ["ev_0010"]

    def test_a_finding_that_cites_nothing_ties_nothing(self) -> None:
        isr = _isr(findings=[Finding(title="a", technique_ids=["T1082"])])

        assert "T1082" not in technique_evidence({"static": isr}, _ledger())

    def test_a_run_with_no_ledger_ties_nothing(self) -> None:
        isr = _isr(findings=[Finding(title="a", technique_ids=["T1082"], evidence_ids=["ev_0003"])])

        assert technique_evidence({"static": isr}, []) == {}
        assert technique_evidence({"static": isr}, None) == {}

    def test_a_finding_ties_its_entries_to_every_technique_it_names(self) -> None:
        isr = _isr(
            findings=[
                Finding(title="a", technique_ids=["T1082", "T1012"], evidence_ids=["ev_0003"])
            ]
        )

        ties = technique_evidence({"static": isr}, _ledger())
        assert ties["T1082"] == ties["T1012"] == ["ev_0003"]


def _report(verdict: str, judge: Bundle | None, **attribution: Any) -> MalwareReport:
    report = MalwareReportBuilder(
        file_hash=SHA256,
        file_name="sample.exe",
        sample_path=None,
        sandbox_report={},
        reports={},
        isr_reports={},
        stix_output=judge.model_dump(mode="json") if judge is not None else {"objects": []},
        run_summary={},
        discussion_history=[],
        final_decision=verdict,
        overall_confidence=0.9,
        judge_assessment=None,
        malware_category="loader",
        evidence_ledger=[],
    ).build_deterministic()
    for key, value in attribution.items():
        setattr(report.attribution, key, value)
    return report


def _judge() -> Bundle:
    data = json.loads(
        json.dumps(
            {
                "type": "bundle",
                "objects": [
                    {"type": "malware", "id": "malware--1", "name": "loader", "is_family": False},
                    {
                        "type": "attack-pattern",
                        "id": "attack-pattern--1",
                        "name": "Process Injection",
                        "external_references": [
                            {"source_name": "mitre-attack", "external_id": "T1055"}
                        ],
                    },
                    {
                        "type": "attack-pattern",
                        "id": "attack-pattern--2",
                        "name": "Application Layer Protocol",
                        "external_references": [
                            {"source_name": "mitre-attack", "external_id": "T1071"}
                        ],
                    },
                    {
                        "type": "relationship",
                        "id": "relationship--1",
                        "relationship_type": "uses",
                        "source_ref": "malware--1",
                        "target_ref": "attack-pattern--1",
                        "x_maljan_confidence": 0.9,
                    },
                    {
                        "type": "relationship",
                        "id": "relationship--2",
                        "relationship_type": "uses",
                        "source_ref": "malware--1",
                        "target_ref": "attack-pattern--2",
                    },
                ],
            }
        )
    )
    lift_misplaced_extensions(data)
    return Bundle.model_validate(postprocess_judge_bundle(data))


def _render(
    ties: dict[str, list[str]] | None,
    judge: Bundle | None = None,
    *,
    ledger: list[str] | None = None,
    renderer: ExtendedSTIXRenderer | None = None,
    **attribution: Any,
):
    judge = _judge() if judge is None else judge
    report = _report("Malware", judge, **attribution)
    return (renderer or ExtendedSTIXRenderer()).render(
        report,
        judge,
        technique_evidence=ties,
        ledger_ids=LEDGER_IDS if ledger is None else ledger,
    )


def _dumped(bundle: Bundle) -> list[dict[str, Any]]:
    return bundle.model_dump(mode="json")["objects"]


def _uses(objects: list[dict[str, Any]], tid: str) -> dict[str, Any]:
    (edge,) = [
        o
        for o in objects
        if o["type"] == "relationship"
        and o["relationship_type"] == "uses"
        and o["target_ref"] == attack_pattern_id(tid)
    ]
    return edge


def _carrying(objects: list[dict[str, Any]]) -> list[str]:
    return [o["id"] for o in objects if EVIDENCE_REFS_PROPERTY in o]


class TestTheExport:
    def test_the_sample_uses_edge_carries_the_techniques_entries_in_ledger_order(self) -> None:
        objects = _dumped(_render({"T1055": ["ev_0012", "ev_0003", "ev_0004", "ev_0012"]}))

        assert _uses(objects, "T1055")[EVIDENCE_REFS_PROPERTY] == ["ev_0004", "ev_0003", "ev_0012"]

    def test_only_what_the_record_ties_carries_the_property(self) -> None:
        objects = _dumped(_render({"T1055": ["ev_0002"]}))

        assert _carrying(objects) == [_uses(objects, "T1055")["id"]]
        assert EVIDENCE_REFS_PROPERTY not in _uses(objects, "T1071")

    def test_a_run_whose_record_ties_nothing_publishes_no_such_property(self) -> None:
        for ties in (None, {}, {"T1055": []}, {"T1055": ["not an id"]}):
            assert _carrying(_dumped(_render(ties))) == [], ties

    def test_the_attack_pattern_keeps_the_same_content_in_every_export(self) -> None:
        objects = _dumped(_render({"T1055": ["ev_0002"]}))

        pattern = next(o for o in objects if o["id"] == attack_pattern_id("T1055"))
        assert EVIDENCE_REFS_PROPERTY not in pattern

    def test_the_judges_own_bundle_is_not_changed(self) -> None:
        judge = _judge()
        _render({"T1055": ["ev_0002"]}, judge=judge)

        assert all(getattr(o, EVIDENCE_REFS_PROPERTY, None) is None for o in judge.objects)

    def test_a_malware_object_minted_from_the_family_carries_the_familys_entries(self) -> None:
        empty = Bundle(objects=[])
        objects = _dumped(
            _render(
                None,
                judge=empty,
                family="Latrodectus",
                family_evidence_ids=["ev_0007", "ev_0004", "ev_0007"],
            )
        )

        (malware,) = [o for o in objects if o["type"] == "malware"]
        assert malware["name"] == "Latrodectus"
        assert malware[EVIDENCE_REFS_PROPERTY] == ["ev_0004", "ev_0007"]

    def test_a_family_id_the_ledger_does_not_hold_is_left_out_and_recorded(self) -> None:
        renderer = ExtendedSTIXRenderer()
        objects = _dumped(
            _render(
                None,
                judge=Bundle(objects=[]),
                renderer=renderer,
                family="Latrodectus",
                family_evidence_ids=["ev_0107", "ev_0007"],
            )
        )

        (malware,) = [o for o in objects if o["type"] == "malware"]
        assert malware[EVIDENCE_REFS_PROPERTY] == ["ev_0007"]
        notes = [why for code, why in renderer.declined if code == EVIDENCE_REF_NOT_IN_LEDGER_CODE]
        assert len(notes) == 1 and "ev_0107" in notes[0]

    def test_a_run_with_no_ledger_exports_no_ids(self) -> None:
        objects = _dumped(
            _render(
                {"T1055": ["ev_0002"]},
                ledger=[],
                family="Latrodectus",
                family_evidence_ids=["ev_0007"],
            )
        )

        assert _carrying(objects) == []

    def test_a_malware_object_named_from_anything_else_carries_none(self) -> None:
        objects = _dumped(_render(None, judge=Bundle(objects=[]), family=None))

        (malware,) = [o for o in objects if o["type"] == "malware"]
        assert EVIDENCE_REFS_PROPERTY not in malware

    def test_the_judges_malware_object_is_not_lent_the_familys_entries(self) -> None:
        objects = _dumped(_render(None, family="Latrodectus", family_evidence_ids=["ev_0007"]))

        assert _carrying(objects) == []


class TestTheJudgesCopyIsNotCarried:
    """The property is the platform's. A judge object that writes it is read
    without it, with the record every undeclared key gets and no retry, and the
    export's edge carries the record's ids instead."""

    def _answer(self) -> dict[str, Any]:
        return {
            "type": "bundle",
            "objects": [
                {"type": "malware", "id": "malware--1", "name": "loader", "is_family": False},
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--1",
                    "name": "Process Injection",
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "T1055"}
                    ],
                },
                {
                    "type": "relationship",
                    "id": "relationship--1",
                    "relationship_type": "uses",
                    "source_ref": "malware--1",
                    "target_ref": "attack-pattern--1",
                    EVIDENCE_REFS_PROPERTY: ["ev_9999", "ev_0001"],
                },
            ],
        }

    def test_the_not_carried_record_is_written(self) -> None:
        data = json.loads(json.dumps(self._answer()))
        found = lift_misplaced_extensions(data)

        rows = [v for v in found if v.code == PROPERTY_NOT_CARRIED_CODE]
        assert len(rows) == 1 and EVIDENCE_REFS_PROPERTY in rows[0].message

    def test_the_export_carries_the_records_ids_and_not_the_judges(self) -> None:
        data = json.loads(json.dumps(self._answer()))
        lift_misplaced_extensions(data)
        judge = Bundle.model_validate(postprocess_judge_bundle(data))
        assert all(getattr(o, EVIDENCE_REFS_PROPERTY, None) is None for o in judge.objects)

        objects = _dumped(_render({"T1055": ["ev_0002"]}, judge=judge))
        assert _uses(objects, "T1055")[EVIDENCE_REFS_PROPERTY] == ["ev_0002"]
        assert "ev_9999" not in json.dumps(objects)

    def test_a_judge_value_that_reaches_the_renderer_anyway_is_replaced(self) -> None:
        judge = _judge()
        smuggled = Bundle(
            objects=[
                o.model_copy(update={EVIDENCE_REFS_PROPERTY: ["ev_9999"]})
                if o.type in ("relationship", "malware")
                else o
                for o in judge.objects
            ]
        )

        objects = _dumped(_render(None, judge=smuggled))
        assert _carrying(objects) == []


def test_no_id_the_ledger_does_not_hold_reaches_the_export() -> None:
    """Every source of ids, fed ids the ledger does not hold: none is exported."""
    rng = random.Random(7)
    ledger = [_entry(eid, seq=i) for i, eid in enumerate(LEDGER_IDS)]
    for _round in range(40):
        absent = [f"ev_{rng.randint(13, 9999):04d}" for _ in range(rng.randint(1, 6))]
        present = rng.sample(LEDGER_IDS, rng.randint(0, 3))
        mixed = absent + present
        rng.shuffle(mixed)
        isr = _isr(
            findings=[
                Finding(title="f", technique_ids=["T1055", "T1071"], evidence_ids=list(mixed))
            ]
        )
        ties = technique_evidence({"static": isr}, ledger)
        # The ties a caller could hand the renderer directly, unfiltered.
        raw_ties = {"T1055": list(mixed), "T1071": list(absent)}
        judge_answer = TestTheJudgesCopyIsNotCarried()._answer()
        judge_answer["objects"][2][EVIDENCE_REFS_PROPERTY] = list(mixed)
        judge_answer["objects"][0][EVIDENCE_REFS_PROPERTY] = list(absent)
        data = json.loads(json.dumps(judge_answer))
        lift_misplaced_extensions(data)
        judge = Bundle.model_validate(postprocess_judge_bundle(data))
        for bundle in (
            _render(ties, judge=judge),
            _render(raw_ties, judge=judge),
            _render(raw_ties, judge=Bundle(objects=[]), family="F", family_evidence_ids=mixed),
            _render(raw_ties, ledger=[], family="F", family_evidence_ids=mixed),
        ):
            exported = {eid for o in _dumped(bundle) for eid in o.get(EVIDENCE_REFS_PROPERTY, [])}
            assert exported <= set(LEDGER_IDS), exported - set(LEDGER_IDS)
            assert not exported & set(absent)


def _report_of(bundle: Bundle) -> tuple[list[str], list[str]]:
    result = validate_instance(bundle.model_dump(mode="json"), ValidationOptions(version="2.1"))
    return (
        [str(getattr(e, "message", e)) for e in result.errors],
        [str(getattr(w, "message", w)) for w in result.warnings],
    )


def test_the_official_validator_finds_no_error_and_no_new_kind_of_warning() -> None:
    """No error, and no warning of a kind the export did not already carry.

    Every ``x_maljan_`` property draws the validator's best-practice note that
    a custom property should be declared through an extension definition, and
    this one draws the same note, once per object that carries it. Everything
    else the validator says about the bundle is unchanged.
    """
    note = f"Custom property '{EVIDENCE_REFS_PROPERTY}' should be implemented using an extension"
    empty = Bundle(objects=[])
    pairs = [
        (_render(None), _render({"T1055": ["ev_0002"], "T1071": ["ev_0004"]}), 2),
        (
            _render(None, judge=empty, family="Latrodectus"),
            _render(None, judge=empty, family="Latrodectus", family_evidence_ids=["ev_0007"]),
            1,
        ),
    ]
    for bare, cited, carrying in pairs:
        bare_errors, bare_warnings = _report_of(bare)
        errors, warnings = _report_of(cited)

        assert errors == bare_errors == []
        assert len([w for w in warnings if note in w]) == carrying
        assert _without_ids([w for w in warnings if note not in w]) == _without_ids(bare_warnings)


def _without_ids(warnings: list[str]) -> list[str]:
    """Warnings with the object ids taken out: fresh ids are minted per render."""
    return sorted(w.split(": ", 1)[-1] for w in warnings)

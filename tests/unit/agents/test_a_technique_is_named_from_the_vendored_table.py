"""Every technique name the platform writes comes from the vendored ATT&CK table.

The judge was asked about ids with no names beside them and wrote its own:
it dropped a Winlogon Helper DLL id "(Scheduled Task/Job)" and a Direct Volume
Access id "(Platform ID)", and the report printed those reasons under the
catalogue's names. The question now names each id as the table does, and so
do the evidence summary and the reference the export back-fills on an
attack-pattern, which read a short hand-written list and an index that is not
always built.
"""

from __future__ import annotations

from maljan.agents.judge_agent import technique_question_head, technique_question_text
from maljan.agents.judge_postprocess import postprocess_judge_bundle
from maljan.extractors.capability_matrix import TechniqueQuestion
from maljan.memory.attck_loader import technique_entry, technique_label
from maljan.pipeline.evidence_summary import summarise
from maljan.schemas.isr_models import AgentISR, ClaimEvidence


def _name(tid: str) -> str:
    entry = technique_entry(tid)
    assert entry is not None
    return entry.name


def test_the_label_is_the_id_and_the_tables_name() -> None:
    assert technique_label("T1547.004") == f"T1547.004 {_name('T1547.004')}"


def test_an_id_the_table_does_not_have_is_labelled_by_the_id_alone() -> None:
    assert technique_label("T9998") == "T9998"


def test_the_judges_technique_question_names_each_id_from_the_table() -> None:
    questions = [
        TechniqueQuestion("T1547.004", "finding", [("static", "Persistence", ["ev_0001"])]),
        TechniqueQuestion("T1006", "finding", [("static", "Hashing", [])]),
    ]

    text = technique_question_text(questions, {})

    assert f"1. T1547.004 {_name('T1547.004')} — " in text
    assert f"2. T1006 {_name('T1006')} — " in text


def test_the_question_head_names_the_techniques_the_bundle_carries() -> None:
    head = technique_question_head("r", "Malware", ["T1027"])

    assert f"T1027 {_name('T1027')}" in head


def test_the_evidence_summary_names_each_id_from_the_table() -> None:
    isr = AgentISR(
        agent_id="static",
        domain="static",
        claims=[
            ClaimEvidence(
                claim="It reads the volume directly.",
                evidence_ref="[ev_0001]",
                confidence=0.5,
                technique_id="T1006",
            )
        ],
    )

    assert f"- T1006 {_name('T1006')}: 1 source(s)" in summarise({"static": isr})


def test_the_back_filled_reference_names_the_technique_from_the_table() -> None:
    bundle = {
        "type": "bundle",
        "id": "bundle--1",
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--00000000-0000-4000-8000-0000000000aa",
                "name": "T1620",
                "external_references": [],
            }
        ],
    }

    (pattern,) = postprocess_judge_bundle(bundle)["objects"]

    assert pattern["name"] == _name("T1620")
    assert pattern["external_references"][0]["external_id"] == "T1620"

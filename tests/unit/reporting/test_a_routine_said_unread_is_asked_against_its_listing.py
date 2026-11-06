"""A sentence calling a listed routine unread, and an ATT&CK procedure, are asked too (T-494).

The haiku8 report said "Its body was not read" of the copy routine 0x7504 and
"their code is not in this evidence" of 0x7504 and 0xd1c8 while ev_0175 held
both listings (D7), and its ATT&CK table called the hidden window "not
established" beside a section 5 that states SW_HIDE (D9). The agreement round
is now shown, as a fact, each routine whose code an entry lists where a passage
names it in a sentence that, or whose next sentence, calls code not read; and
each procedure of the ATT&CK table, as a passage written without the code.
Every address, entry and tool name here is a neutral synthetic value.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from typing import Any

from langchain_core.messages import AIMessage, BaseMessage

from maljan.pipeline.validation import EntryTexts
from maljan.reporting.agreement_facts import ledger_facts
from maljan.reporting.models import (
    CapabilityCell,
    FileHashes,
    MalwareReport,
    SampleIdentity,
    TechnicalAnalysis,
    TechnicalSubsection,
    TechniqueProcedure,
)
from maljan.reporting.section_agreement import (
    CLAIM_LED,
    FACT,
    REWRITTEN_CODE,
    SYSTEM_PROMPT,
    ask_section_agreement,
    passages_of,
    prompt_text,
)
from maljan.schemas.evidence import LedgerEntry

BASE = 0x2470000
INSTALL, COPY = BASE + 0x33AC, BASE + 0x7504
_DECOMPILE = {"v": 1, "kind": "decompile", "reader": "listing"}

UNREAD = "Its body was not read, so we assess from the arguments that it copies the module."
HIDDEN = "The runner 0x1030 starts each command, but the hidden window is not established."
SHOWN = "The runner 0x1030 starts each command with wShowWindow 0 (SW_HIDE) [ev_0109]."


def _lifted(entry_id: str, address: int, body: str) -> LedgerEntry:
    return LedgerEntry(
        id=entry_id,
        tool="lift_routine",
        args={"address": hex(address)},
        output=f"int FUN_{address:x}(int a)\n{{\n{body}\n}}\n",
        facts=_DECOMPILE,
    )


def _ledger() -> list[LedgerEntry]:
    return [
        _lifted("ev_0107", INSTALL, f"  FUN_{COPY:x}(a, a);\n  return 1;"),
        _lifted("ev_0175", COPY, "  return a;"),
        LedgerEntry(id="ev_0109", tool="image_facts", output='{"image_base": "0x2470000"}'),
    ]


def _report(persistence: str = "") -> MalwareReport:
    body = persistence or (
        f"In 0x33ac the copy routine 0x7504 is called with two paths [ev_0107]. {UNREAD}"
    )
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="b" * 64), file_type="PE32+ DLL"),
        verdict="Malware",
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
        technical_analysis=TechnicalAnalysis(
            persistence_detail=TechnicalSubsection(
                title="Persistence", body=body, evidence_refs=["ev_0107"]
            ),
            discovery=TechnicalSubsection(title="Discovery", body=SHOWN),
            technique_procedures=[
                TechniqueProcedure(technique_id="T1564.003", procedure=HIDDEN),
            ],
        ),
        capability_matrix=[
            CapabilityCell(
                tactic="TA0005",
                tactic_name="Defense Evasion",
                technique_id="T1564.003",
                technique_name="Hidden Window",
                evidence=["The runner 0x1030 starts each command in a hidden window [ev_0109]."],
            )
        ],
    )


class _Reporter:
    def __init__(self, *answers: Any) -> None:
        self.answers = [a if isinstance(a, str) else json.dumps(a) for a in answers]
        self.asked: list[list[BaseMessage]] = []
        self.degradations: list[str] = []

    async def ask(self, turns: list[BaseMessage], *, call: str, what: str) -> AIMessage:
        self.asked.append(list(turns))
        return AIMessage(content=self.answers.pop(0) if self.answers else '{"sentences": []}')


def _ask(report: MalwareReport, *answers: Any) -> Any:
    ledger = _ledger()
    return asyncio.run(
        ask_section_agreement(
            _Reporter(*answers),
            report,
            citable_ids=[str(e.id) for e in ledger],
            evidence_texts=EntryTexts.from_ledger(ledger),
        )
    )


def _row(passage: str, sentence: str, sources: list[str], rewrite: str) -> dict[str, Any]:
    return {
        "passage": passage,
        "sentence": sentence,
        "sources": sources,
        "decision": "rewrite",
        "rewrite": rewrite,
    }


def test_the_ledger_facts_list_each_read_routine_with_its_listings() -> None:
    listed = {r.address: r.listed_in for r in ledger_facts(_ledger()).listed}
    assert listed == {INSTALL: ("ev_0107",), COPY: ("ev_0175",)}


def test_a_routine_a_sentence_calls_unread_is_shown_with_its_listing() -> None:
    passages = passages_of(_report(), entries=_ledger())
    facts = {p.id: p for p in passages if p.kind == FACT and p.id.startswith("listed.")}
    # "Its body was not read" is about the routine named last before it.
    assert sorted(f.text for f in facts.values()) == [
        f"{hex(COPY)} (offset 0x7504): ev_0175 lists its code (decompiled or disassembled)",
    ]
    assert "A routine an entry lists was read" in SYSTEM_PROMPT
    assert "ev_0175 lists its code" in prompt_text(passages)


def test_only_the_routine_the_absence_is_about_is_a_fact() -> None:
    # The address in the clause that says the code is not read, not another one
    # the sentence names; an active "does not read" says nothing of code.
    said = "Routine 0x33ac copies the module, and the code of 0x7504 was not read [ev_0107]."
    passages = passages_of(_report(said), entries=_ledger())
    assert [p.text.split(":")[0] for p in passages if p.id.startswith("listed.")] == [
        f"{hex(COPY)} (offset 0x7504)"
    ]
    active = "Routine 0x33ac does not read the key, and 0x7504 copies the module [ev_0107]."
    passages = passages_of(_report(active), entries=_ledger())
    assert not [p for p in passages if p.id.startswith("listed.")]


def test_a_routine_no_sentence_calls_unread_is_no_fact() -> None:
    report = _report("In 0x33ac the copy routine 0x7504 is called with two paths [ev_0107].")
    passages = passages_of(report, entries=_ledger())
    assert not [p for p in passages if p.id.startswith("listed.")]


def test_the_platform_s_own_unread_clause_makes_no_routine_a_fact() -> None:
    clause = (
        "The copy runs [ev_0107]; the routine at offset 0x9000, called by the read routines at "
        "offsets 0x33ac, 0x7504, has no listed code (decompiled or disassembled)."
    )
    passages = passages_of(_report(clause), entries=_ledger())
    assert not [p for p in passages if p.id.startswith("listed.")]


def test_a_section_5_sentence_calling_a_listed_routine_unread_is_qualified() -> None:
    report = _report()
    row = _row("persistence_detail", UNREAD, ["listed.1"], "Its body was read [ev_0175].")
    done = _ask(report, {"sentences": [row]})
    body = report.technical_analysis.persistence_detail.body
    assert body.endswith(
        "it copies the module; ev_0175 lists the code of the routine at offset 0x7504 "
        "(decompiled or disassembled) [ev_0175]."
    )
    assert done.summary["rewritten"] == 1
    assert [r["code"] for r in done.tally.unresolved] == [REWRITTEN_CODE]


def test_a_procedure_is_a_passage_written_without_the_code_and_may_be_rewritten() -> None:
    report = _report()
    (procedure,) = [p for p in passages_of(report) if p.id == "procedures.1"]
    assert procedure.kind == CLAIM_LED and procedure.write is not None
    assert "procedure for T1564.003" in procedure.label
    rewrite = "The runner 0x1030 starts each command with SW_HIDE [ev_0109]."
    # The persistence sentence calling 0x7504's body not read is held (T-562):
    # the answer lists it too, kept.
    unread = {
        "passage": "persistence_detail",
        "sentence": UNREAD,
        "sources": ["listed.1"],
        "decision": "keep",
    }
    done = _ask(
        report,
        {"sentences": [_row("procedures.1", HIDDEN, ["discovery"], rewrite), unread]},
    )
    (row,) = report.technical_analysis.technique_procedures
    assert row.procedure == rewrite
    assert row.evidence_refs == ["ev_0109"]
    assert done.summary["rewritten"] == 1


def test_a_procedure_rewrite_is_held_to_what_a_procedure_is_held_to() -> None:
    # Two sentences, or a rewrite dropping the value of the technique's claim, is
    # not put in: the composer would not have taken it as a procedure.
    for rewrite in (
        "The runner 0x1030 starts each command. It hides the window with SW_HIDE [ev_0109].",
        "Each command starts with SW_HIDE [ev_0109].",
    ):
        report = _report()
        row = _row("procedures.1", HIDDEN, ["discovery"], rewrite)
        done = _ask(report, {"sentences": [row]}, {"sentences": [row]})
        assert report.technical_analysis.technique_procedures[0].procedure == HIDDEN
        assert done.summary["rewritten"] == 0 and done.summary["not_applied"] == 1

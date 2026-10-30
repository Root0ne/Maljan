"""A section 5 sentence is asked against the ledger's own facts, and rewritten on a fact alone.

The agreement round showed section 5 only the decoded texts bound to an API
argument, and a section 5 sentence could only be listed: "no anti-debugging is
established" stood beside a gate whose callee no entry read (T-404), and "the
decompile failed twice" beside the later calls that decompiled both routines
(T-396). The round is now shown each routine a read routine calls that no
entry reads and each failed call linked to the later call that answered for
its address, and a section 5 sentence may be rewritten where such a fact
contradicts it, never on another passage's words (T-398c). Every address,
entry and tool name here is a neutral synthetic value, read by declared kinds.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from typing import Any

import pytest
from langchain_core.messages import AIMessage, BaseMessage

from maljan.pipeline.validation import EntryTexts
from maljan.reporting.agreement_facts import answered_later, ledger_facts
from maljan.reporting.models import (
    FileHashes,
    MalwareReport,
    SampleIdentity,
    TechnicalAnalysis,
    TechnicalSubsection,
)
from maljan.reporting.section_agreement import (
    FACT,
    LISTED_CODE,
    REWRITE_UNGROUNDED_CODE,
    REWRITTEN_CODE,
    UNKNOWN_SOURCE_CODE,
    ask_section_agreement,
    passages_of,
    prompt_text,
)
from maljan.schemas.evidence import LedgerEntry

BASE = 0x2470000
GATE, CHECK = BASE + 0x5A10, BASE + 0x5A38
_DECOMPILE = {"v": 1, "kind": "decompile", "reader": "listing"}
_LOOKUP = {"v": 1, "kind": "string_lookup", "reader": "plain"}

ABSENT = "No environment check is established."
FAILED = "The listing of 0x5a10 failed twice."


def _lifted(entry_id: str, address: int, body: str, **kw: Any) -> LedgerEntry:
    listing = f"int FUN_{address:x}(int a)\n{{\n{body}\n}}\n"
    return LedgerEntry(
        id=entry_id,
        tool="lift_routine",
        args={"address": hex(address)},
        output=listing,
        facts=_DECOMPILE,
        **kw,
    )


def _ledger() -> list[LedgerEntry]:
    return [
        LedgerEntry(
            id="ev_0102",
            tool="lift_routine",
            args={"address": hex(GATE)},
            ok=False,
            error="no function there",
            facts=_DECOMPILE,
        ),
        LedgerEntry(
            id="ev_0103",
            tool="lift_routine",
            args={"address": hex(GATE)},
            ok=False,
            error="no function there",
            facts=_DECOMPILE,
        ),
        _lifted("ev_0107", GATE, f"  if (FUN_{CHECK:x}(a) == 0) {{ return 0; }}\n  return 1;"),
        LedgerEntry(id="ev_0109", tool="image_facts", output='{"image_base": "0x2470000"}'),
    ]


def _report() -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="b" * 64), file_type="PE32+ DLL"),
        verdict="Malware",
        generated_at=datetime(2026, 1, 1, tzinfo=UTC),
        intro_background="The sample is a library; its gate calls 0x5a38 [ev_0107].",
        technical_analysis=TechnicalAnalysis(
            evasion_antiforensics=TechnicalSubsection(
                title="Defense Evasion & Anti-Forensics",
                body=f"The gate at 0x5a10 returns early [ev_0107]. {ABSENT}",
                evidence_refs=["ev_0107"],
            ),
            string_resolution=TechnicalSubsection(
                title="API and String Resolution",
                body=f"Names resolve at run time [ev_0107]. {FAILED}",
            ),
        ),
    )


class _Reporter:
    def __init__(self, *answers: Any) -> None:
        self.answers = [a if isinstance(a, str) else json.dumps(a) for a in answers]
        self.asked: list[list[BaseMessage]] = []
        self.degradations: list[str] = []

    async def ask(self, turns: list[BaseMessage], *, call: str, what: str) -> AIMessage:
        self.asked.append(list(turns))
        return AIMessage(content=self.answers.pop(0) if self.answers else '{"sentences": []}')


def _row(passage: str, sentence: str, sources: list[str], rewrite: str = "") -> dict[str, Any]:
    return {
        "passage": passage,
        "sentence": sentence,
        "sources": sources,
        "decision": "rewrite" if rewrite else "keep",
        "rewrite": rewrite,
    }


def _ask(report: MalwareReport, reporter: _Reporter, ledger: list[LedgerEntry]) -> Any:
    entries = EntryTexts.from_ledger(ledger)
    citable = [str(e.id) for e in ledger]
    return asyncio.run(
        ask_section_agreement(reporter, report, citable_ids=citable, evidence_texts=entries)
    )


def test_the_ledger_facts_name_the_unread_callee_and_the_later_answer() -> None:
    found = ledger_facts(_ledger())
    assert [(u.address, u.callers, u.read_in) for u in found.unread] == [
        (CHECK, (GATE,), ("ev_0107",))
    ]
    assert [(a.failed, a.answered) for a in found.answered] == [
        ("ev_0102", "ev_0107"),
        ("ev_0103", "ev_0107"),
    ]


def test_a_failed_call_no_later_call_answered_is_linked_to_nothing() -> None:
    failed = LedgerEntry(
        id="ev_0102", tool="lift_routine", args={"address": hex(GATE)}, ok=False, facts=_DECOMPILE
    )
    other = _lifted("ev_0107", GATE + 0x400, "  return a;")
    # A later answer of another kind for the same address is no listing of it.
    lookup = LedgerEntry(
        id="ev_0108", tool="find_text", args={"address": hex(GATE)}, output="{}", facts=_LOOKUP
    )
    earlier = _lifted("ev_0101", GATE, "  return a;")
    assert answered_later([earlier, failed, other, lookup]) == []


def test_a_later_listing_of_another_listing_tool_answers_a_failed_listing() -> None:
    failed = LedgerEntry(
        id="ev_0102", tool="lift_routine", args={"address": hex(GATE)}, ok=False, facts=_DECOMPILE
    )
    batch = LedgerEntry(
        id="ev_0110",
        tool="lift_many",
        args={"functions": f"{GATE:x}"},
        output=json.dumps({f"{GATE:x}": f"int FUN_{GATE:x}(void)\n{{\n}}\n"}),
        facts={"v": 1, "kind": "decompile_batch", "reader": "listing"},
    )
    assert [(a.failed, a.answered) for a in answered_later([failed, batch])] == [
        ("ev_0102", "ev_0110")
    ]


def test_the_round_is_shown_the_facts_with_the_entries_they_rest_on() -> None:
    passages = passages_of(_report(), entries=_ledger())
    facts = {p.id: p for p in passages if p.kind == FACT}
    assert set(facts) == {"unread.1", "answered.1", "answered.2"}
    assert facts["unread.1"].cites == frozenset({"ev_0107"})
    assert facts["answered.1"].cites == frozenset({"ev_0102", "ev_0107"})
    text = prompt_text(passages)
    assert (
        f"(cites ev_0107): {hex(CHECK)} (offset 0x5a38) is called by the read routine at "
        "offset 0x5a10; no entry lists its code (decompiled or disassembled)"
    ) in text
    assert (
        'ev_0102 ("lift_routine") for 0x2475a10 (offset 0x5a10) failed; the later call ev_0107'
        in text
    )


# The clause the platform adds for the unlisted routine behind the gate.
CLAUSE = (
    "the routine at offset 0x5a38, called by the read routine at offset 0x5a10, has no "
    "listed code (decompiled or disassembled) [ev_0107]"
)


def _qualify(model_words: str, sentence: str = ABSENT, body: str = "") -> Any:
    """Ask one row qualifying ``sentence`` on the unlisted routine, in the model's words."""
    report = _report()
    if body:
        report.technical_analysis.evasion_antiforensics.body = body
    row = _row("evasion_antiforensics", sentence, ["unread.1"], model_words)
    done = _ask(report, _Reporter({"sentences": [row]}, {"sentences": [row]}), _ledger())
    return report.technical_analysis.evasion_antiforensics.body, done


@pytest.mark.parametrize(
    "model_words",
    [
        # An appended claim, an inserted contradiction, an inserted negation, a
        # prefixed denial and a flipped claim: each read as the model's choice
        # to qualify, never as the words that stand.
        "No environment check is established; 0x5a38 is an environment check [ev_0107].",
        "No environment check is established, which is false: 0x5a38 checks it [ev_0107].",
        "No environment check is not established; 0x5a38 [ev_0107].",
        "It is wrong that no environment check is established; see 0x5a38 [ev_0107].",
        "An environment check is established by 0x5a38 [ev_0107].",
    ],
)
def test_the_platform_writes_the_qualification_whatever_the_model_wrote(model_words: str) -> None:
    body, done = _qualify(model_words)
    gate = "The gate at 0x5a10 returns early [ev_0107]."
    assert body == f"{gate} No environment check is established; {CLAUSE}."
    assert done.summary["rewritten"] == 1
    assert [r["code"] for r in done.tally.unresolved] == [REWRITTEN_CODE]


@pytest.mark.parametrize(
    "model_words",
    [
        "Routine 0x5a38 performs an environment check and returns early [ev_0107].",
        "Routine 0x5a10 is an environment check [ev_0107].",
    ],
)
def test_a_sentence_naming_the_routine_is_qualified_in_the_platform_s_words(
    model_words: str,
) -> None:
    sentence = "Routine 0x5a38 performs no check."
    body, done = _qualify(
        model_words, sentence, f"The gate at 0x5a10 returns early [ev_0107]. {sentence}"
    )
    assert body.endswith(f"Routine 0x5a38 performs no check; {CLAUSE}.")
    assert done.summary["rewritten"] == 1


def test_an_unlisted_routine_qualifies_no_passage_that_names_neither_it_nor_its_caller() -> None:
    # The model's words name the routine and keep the sentence's: the passage
    # still names neither it nor its caller.
    body, done = _qualify(
        "No environment check is established; 0x5a38 was not examined [ev_0107].",
        body=f"Nothing in the listing probes the host [ev_0107]. {ABSENT}",
    )
    assert body.endswith(ABSENT)
    assert done.tally.by_code[REWRITE_UNGROUNDED_CODE] == 2
    assert done.summary["rewritten"] == 0


ANSWERED = (
    "The listing of 0x5a10 failed twice; a later call for offset 0x5a10 answered it, so the "
    "address was not left unread [ev_0102][ev_0103][ev_0107]."
)


@pytest.mark.parametrize(
    "model_words",
    [
        # A rewording, an appended contradiction, an inserted negation and a
        # flipped claim: the platform's clause stands whatever the model wrote.
        "The listing of 0x5a10 failed twice and a later call listed it [ev_0102, ev_0107].",
        "The listing of 0x5a10 failed twice; it was never read [ev_0102].",
        "The listing of 0x5a10 never failed twice [ev_0107].",
        "The listing of 0x5a10 succeeded at once [ev_0107].",
    ],
)
def test_an_answered_failure_is_added_in_the_platform_s_words(model_words: str) -> None:
    report = _report()
    row = _row("string_resolution", FAILED, ["answered.1", "answered.2"], model_words)
    done = _ask(report, _Reporter({"sentences": [row]}), _ledger())
    assert report.technical_analysis.string_resolution.body == (
        f"Names resolve at run time [ev_0107]. {ANSWERED}"
    )
    assert done.summary["rewritten"] == 1


def test_a_section_5_sentence_is_never_pulled_toward_a_passage_written_without_the_code() -> None:
    report = _report()
    report.intro_background = "The sample checks for a debugger [ev_0107]."
    wrong = "The gate checks for a debugger [ev_0107]."
    row = _row("evasion_antiforensics", ABSENT, ["introduction"], wrong)
    reporter = _Reporter({"sentences": [row]}, {"sentences": [row]})
    done = _ask(report, reporter, _ledger())
    assert report.technical_analysis.evasion_antiforensics.body.endswith(ABSENT)
    assert done.tally.by_code[UNKNOWN_SOURCE_CODE] == 2
    assert done.summary["rewritten"] == 0 and done.summary["not_applied"] == 1


def test_a_section_5_rewrite_on_a_fact_and_a_passage_is_not_applied() -> None:
    report = _report()
    report.intro_background = "The sample checks for a debugger [ev_0107]."
    row = _row(
        "evasion_antiforensics",
        ABSENT,
        ["unread.1", "introduction"],
        "It checks for a debugger [ev_0107].",
    )
    done = _ask(report, _Reporter({"sentences": [row]}, {"sentences": [row]}), _ledger())
    assert report.technical_analysis.evasion_antiforensics.body.endswith(ABSENT)
    assert done.summary["rewritten"] == 0


def test_a_kept_section_5_sentence_is_still_listed() -> None:
    report = _report()
    done = _ask(
        report,
        _Reporter({"sentences": [_row("evasion_antiforensics", ABSENT, ["unread.1"])]}),
        _ledger(),
    )
    assert report.technical_analysis.evasion_antiforensics.body.endswith(ABSENT)
    assert done.summary["listed"] == 1
    assert [r["code"] for r in done.tally.unresolved] == [LISTED_CODE]


def test_section_5_alone_is_asked_when_the_ledger_states_a_fact() -> None:
    report = _report()
    report.intro_background = ""
    reporter = _Reporter({"sentences": []})
    _ask(report, reporter, _ledger())
    assert len(reporter.asked) == 1


def test_without_a_ledger_no_fact_is_shown_and_section_5_alone_asks_nothing() -> None:
    report = _report()
    report.intro_background = ""
    assert not [p for p in passages_of(report) if p.kind == FACT]
    reporter = _Reporter()
    done = asyncio.run(ask_section_agreement(reporter, report))
    assert reporter.asked == [] and done.summary == {}


def test_a_callee_a_passage_names_is_a_fact_of_its_own_and_the_rest_are_counted() -> None:
    report = _report()
    report.intro_background = "The gate's helper 0x5a38 is not described [ev_0107]."
    other = BASE + 0x9C40
    ledger = [*_ledger(), _lifted("ev_0111", BASE + 0x9000, f"  FUN_{other:x}(a);")]
    facts = {p.id: p for p in passages_of(report, entries=ledger) if p.kind == FACT}
    assert facts["unread.1"].text == (
        f"{hex(CHECK)} (offset 0x5a38) is called by the read routine at offset 0x5a10; "
        "no entry lists its code (decompiled or disassembled)"
    )
    # Neither the callee nor its caller is named anywhere: counted, citing nothing.
    assert facts["unread.2"].text.startswith("1 more routine that read routines call")
    assert facts["unread.2"].cites == frozenset()


def test_the_prompt_says_an_unlisted_routine_is_unexamined_not_absent() -> None:
    from maljan.reporting.section_agreement import SYSTEM_PROMPT

    assert "its code was not examined, not that it does or does not do anything" in SYSTEM_PROMPT
    assert (
        "it never contradicts what another entry (a rule match, an emulation, a call graph) "
        "states about that routine"
    ) in SYSTEM_PROMPT


def test_an_emulated_or_rule_matched_callee_is_only_said_unlisted() -> None:
    # A rule match and an emulation speak of the callee; neither lists its code.
    report = _report()
    report.intro_background = f"A rule matches a hash routine at {hex(CHECK)} [ev_0112]."
    ledger = [
        *_ledger(),
        LedgerEntry(
            id="ev_0112",
            tool="rule_scan",
            output=json.dumps({"matches": [{"rule": "hash routine", "address": hex(CHECK)}]}),
            facts={"v": 1, "kind": "capability_rules", "reader": "plain"},
        ),
        LedgerEntry(
            id="ev_0113",
            tool="run_emulator",
            args={"address": hex(CHECK)},
            output="returned 0x1",
            facts={"v": 1, "kind": "emulation", "reader": "plain"},
        ),
    ]
    fact = next(p for p in passages_of(report, entries=ledger) if p.id == "unread.1")
    assert fact.text.endswith("no entry lists its code (decompiled or disassembled)")
    assert "reads it" not in fact.text and "ev_0112" not in fact.cites


def _bound_report(body: str, value: str = "qorvel-77") -> MalwareReport:
    from maljan.reporting.models import BoundValue

    report = _report()
    report.technical_analysis.evasion_antiforensics.body = body
    report.bound_values = [
        BoundValue(
            value=value,
            kind="mutex",
            role="mutex_name",
            role_words="the name of the mutex the call creates or opens",
            api="CreateMutexW",
            argument=3,
            parameter="lpName",
            entry="ev_0107",
            tool="decoder",
        )
    ]
    return report


GATED = "The gate creates a mutex through CreateMutexW and exits if it exists [ev_0107]."
NAMELESS = "The mutex name is not established."


@pytest.mark.parametrize(
    "model_words",
    [
        'The mutex name is not established; the code passes "qorvel-77" [ev_0107].',
        'The mutex name is not established, so "qorvel-77" is not the name [ev_0107].',
        'The mutex name "qorvel-77" is not established [ev_0107].',
        "The mutex is unnamed [ev_0107].",
    ],
)
def test_a_bound_value_is_added_in_the_platform_s_words(model_words: str) -> None:
    report = _bound_report(f"{GATED} {NAMELESS}")
    row = _row("evasion_antiforensics", NAMELESS, ["bound.1"], model_words)
    done = _ask(report, _Reporter({"sentences": [row]}), _ledger())
    assert report.technical_analysis.evasion_antiforensics.body == (
        f'{GATED} The mutex name is not established; the code passes "qorvel-77" to '
        "CreateMutexW as argument 3 (lpName) [ev_0107]."
    )
    assert done.summary["rewritten"] == 1


def test_a_bound_value_qualifies_no_passage_that_names_neither_it_nor_its_call() -> None:
    report = _bound_report(f"The gate exits early [ev_0107]. {NAMELESS}")
    row = _row(
        "evasion_antiforensics", NAMELESS, ["bound.1"], 'Not established; "qorvel-77" [ev_0107].'
    )
    done = _ask(report, _Reporter({"sentences": [row]}, {"sentences": [row]}), _ledger())
    assert report.technical_analysis.evasion_antiforensics.body.endswith(NAMELESS)
    assert done.tally.by_code[REWRITE_UNGROUNDED_CODE] == 2
    assert done.summary["rewritten"] == 0


def test_a_later_listing_that_is_error_text_answers_nothing() -> None:
    failed = LedgerEntry(
        id="ev_0102", tool="lift_routine", args={"address": hex(GATE)}, ok=False, facts=_DECOMPILE
    )
    erred = LedgerEntry(
        id="ev_0104",
        tool="lift_routine",
        args={"address": hex(GATE)},
        output="Error: decompiler timed out",
        facts=_DECOMPILE,
    )
    assert answered_later([failed, erred]) == []
    later = _lifted("ev_0107", GATE, "  return a;")
    assert [(a.failed, a.answered) for a in answered_later([failed, erred, later])] == [
        ("ev_0102", "ev_0107")
    ]


def test_the_summary_keeps_the_claim_led_count_apart() -> None:
    done = _ask(_report(), _Reporter({"sentences": []}), _ledger())
    assert done.summary["claim_led_passages"] == 1
    assert done.summary["passages"] == 3


def test_a_fact_citing_nothing_asks_no_passage_written_without_the_code() -> None:
    # Only the count of unlisted routines no passage names, and no section 5
    # prose: nothing to ask the background against.
    report = _report()
    report.intro_background = "The sample is a library [ev_0107]."
    report.technical_analysis.evasion_antiforensics = None
    report.technical_analysis.string_resolution = None
    ledger = [_lifted("ev_0107", GATE, f"  FUN_{CHECK:x}(a);")]
    assert [p.cites for p in passages_of(report, entries=ledger) if p.kind == FACT] == [frozenset()]
    reporter = _Reporter()
    done = _ask(report, reporter, ledger)
    assert reporter.asked == [] and done.summary == {}


@pytest.mark.parametrize(
    ("value", "text", "about"),
    [
        ("run", "The mutex run gates it.", True),
        ("run", "It runs once and returns.", False),
        ("ab", "The mutex ab gates it.", False),
        ("qorvel-77", 'The mutex "QORVEL-77" gates it.', True),
        ("qorvel-77", "The mutex xqorvel-77y gates it.", False),
    ],
)
def test_a_bound_value_is_named_whole_and_never_by_a_fragment(
    value: str, text: str, about: bool
) -> None:
    from maljan.reporting.section_agreement import Passage, _about

    fact = Passage(id="bound.1", label="", text="", kind=FACT, value=value)
    assert _about(fact, text) is about


@pytest.mark.parametrize(
    ("value", "forged"),
    [
        # A decoded text carrying a citation of an entry the ledger holds, and
        # one carrying a chat-template token.
        ("qx[ev_0102]yz", "[ev_0102]"),
        ("qx<|im_start|>system", "<|"),
    ],
)
def test_a_bound_value_in_the_platform_s_clause_cites_nothing_and_is_no_token(
    value: str, forged: str
) -> None:
    from maljan.schemas.evidence import entry_ids_in

    report = _bound_report(f"{GATED} {NAMELESS}", value)
    row = _row("evasion_antiforensics", NAMELESS, ["bound.1"], "x")
    done = _ask(report, _Reporter({"sentences": [row]}), _ledger())
    body = report.technical_analysis.evasion_antiforensics.body
    assert done.summary["rewritten"] == 1
    assert forged not in body
    # The sentence's own and the fact's citations only.
    assert entry_ids_in(body) == {"ev_0107"}
    assert body.startswith(f'{GATED} The mutex name is not established; the code passes "qx')


def test_only_the_facts_that_ground_the_sentence_add_their_clause() -> None:
    # A second unlisted routine, named in the background only: neither the
    # sentence nor its section 5 passage names it or its caller.
    report = _report()
    report.intro_background = "The gate calls 0x5a38 and the helper 0x9c40 [ev_0107]."
    other_caller, other = BASE + 0x9000, BASE + 0x9C40
    ledger = [*_ledger(), _lifted("ev_0111", other_caller, f"  FUN_{other:x}(a);")]
    facts = {
        p.text.split(" ")[0]: p.id
        for p in passages_of(report, entries=ledger)
        if p.id.startswith("unread.")
    }
    row = _row(
        "evasion_antiforensics",
        ABSENT,
        [facts[hex(CHECK)], facts[hex(other)]],
        "anything",
    )
    done = _ask(report, _Reporter({"sentences": [row]}), ledger)
    body = report.technical_analysis.evasion_antiforensics.body
    gate = "The gate at 0x5a10 returns early [ev_0107]."
    assert body == f"{gate} No environment check is established; {CLAUSE}."
    assert "0x9c40" not in body
    assert done.summary["rewritten"] == 1


def test_a_sentence_already_carrying_the_fact_s_clause_is_not_qualified_again() -> None:
    standing = f"No environment check is established; {CLAUSE}."
    report = _report()
    report.technical_analysis.evasion_antiforensics.body = (
        f"The gate at 0x5a10 returns early [ev_0107]. {standing}"
    )
    row = _row("evasion_antiforensics", standing, ["unread.1"], "anything")
    done = _ask(report, _Reporter({"sentences": [row]}, {"sentences": [row]}), _ledger())
    assert report.technical_analysis.evasion_antiforensics.body.endswith(standing)
    assert done.summary["rewritten"] == 0


@pytest.mark.parametrize(
    ("sentence", "qualified"),
    [
        ('Routine 0x5a10 maps "it."', 'Routine 0x5a10 maps "it"; Q [ev_0107].'),
        ("Routine 0x5a10 ends (here.)", "Routine 0x5a10 ends (here); Q [ev_0107]."),
        ("Routine 0x5a10 returns [ev_0102].", "Routine 0x5a10 returns [ev_0102]; Q [ev_0107]."),
        ("Does routine 0x5a10 return?", "Does routine 0x5a10 return; Q [ev_0107]?"),
    ],
)
def test_a_quote_or_bracket_after_the_end_mark_stays_with_its_words(
    sentence: str, qualified: str
) -> None:
    from maljan.reporting.section_agreement import Passage, _qualified

    fact = Passage(
        id="f", label="", text="", kind=FACT, cites=frozenset({"ev_0107"}), qualifier="Q"
    )
    assert _qualified(sentence, [fact]) == qualified


def test_an_answer_that_lists_no_code_does_not_say_the_address_was_read() -> None:
    lookup = {"v": 1, "kind": "string_lookup", "reader": "plain"}
    ledger = [
        LedgerEntry(
            id="ev_0121", tool="find_text", args={"address": hex(GATE)}, ok=False, facts=lookup
        ),
        LedgerEntry(
            id="ev_0122", tool="find_text", args={"address": hex(GATE)}, output="{}", facts=lookup
        ),
        LedgerEntry(id="ev_0109", tool="image_facts", output='{"image_base": "0x2470000"}'),
    ]
    fact = next(p for p in passages_of(_report(), entries=ledger) if p.id == "answered.1")
    assert fact.qualifier == "a later call for offset 0x5a10 answered it"
    listed = next(p for p in passages_of(_report(), entries=_ledger()) if p.id == "answered.1")
    assert listed.qualifier.endswith(", so the address was not left unread")

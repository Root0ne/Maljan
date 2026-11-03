"""One question once the report body is written: does a passage say otherwise than section 5?

The key findings, the summary, the execution flow, the host identifiers, the
background, the ATT&CK table's procedures and the composed sections shown no
function's code (the cipher table, the channel table, the packing prose) are
written from the analysts' claims, at the same time as section 5 is written
from the code and the tool answers; none of them is shown section 5. A claim
that calls a routine's body "not read", a key's use "not established" or a
mutex name "open" is that analyst's view, and a writer shown only the claim
repeats it beside a section 5 that states the thing (T-390). The absence
check (``validation.ledger_absence_contradictions``) decides such a sentence
only where it names an address, an entry or a value; "the sleep constants"
names none.

So, after every section is written, the reporter's model is shown, once:

- the facts the platform states: each decoded text the code passes to an API
  argument (``report.bound_values``), in the words every surface that
  publishes it uses (``call_bindings.binding_words``); each routine a read
  routine calls whose code no entry lists, a fact of its own where a passage
  names it (the rest counted), each routine whose code an entry lists where a
  passage calls code it names not read (``_said_unread``), and each failed
  call for an address with the later call that answered for it
  (``reporting.agreement_facts``), read off the ledger;
- section 5's passages written from the code: each prose subsection and each
  row of the configuration, command and flag tables, with the ids it cites;
- the debate's mediations, in round order, as the mediator wrote them;
- every passage written without the code, under an id naming where it stands;
  the composed limitations paragraph among them where a sentence of it says a
  call failed or a reading could not be made and the ledger says otherwise
  (a later call redid the call, or an entry lists the code), with the facts it
  rests on: the failed calls and the later calls that answered them, the tools
  not run, the recorded limitations and the open questions
  (``reporting.limitation_facts``, T-526).

It lists each sentence of a passage written without the code that calls
absent, unknown or open, or states the opposite of, what a section 5 passage,
a fact or a closed debate line states, and each sentence of a section 5
passage a fact contradicts; names the sources; and keeps the sentence or
rewrites it. Nothing here reads a sentence's words to decide: which
sentences, and on which subject, is the model's call (the words that call
code not read only choose which listed routines are shown). A sentence of a
passage written without the code may be rewritten on any source; a sentence of
a section 5 prose passage only on the platform's facts, never on another
model's words (a section 5 sentence was pulled toward an analyst's wrong claim
when it could be), and kept, it is listed, the listing recorded as the model's answer; a
table cell's value is shown for reading, and a sentence of one is listed and
kept. Code checks the answer's structure: the passage is one it
was shown, the copied text is one whole sentence of it standing there once,
a section 5 passage is answered by a fact alone, about an address or a value
the sentence or its rewrite names, and a rewrite keeps every id
its sentence cites, cites at least one id its sources cite (sources citing no
id ground no rewrite) and no id that neither they nor the passage cite;
and it reads each rewrite as the report rounds read their prose (its
citations, a value beside an entry that does not hold it, an entry said to
hold nothing, an absence the ledger contradicts); a rewrite of a limitations
sentence that still says a call failed that a later call redid is not one. The
model is told what is wrong and asked once more. A rewrite that passes takes
its sentence's place, read against the passage as it was written, its new ids
added to the record's own list, and what it replaced is recorded as the model's
answer; a sentence kept, or a rewrite that still fails, stays as written, and
the finding is recorded.

Every step is one pass over the passages and the answer's rows.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field, replace
from functools import cached_property
from typing import TYPE_CHECKING, Any, Literal

from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage
from pydantic import BaseModel, ConfigDict, Field, model_validator

from maljan.agents.tool_fence import (
    QUOTED_VALUE_STATEMENT,
    quoted_value,
    template_tokens_written_out,
)
from maljan.core.logger import logger
from maljan.core.spend import SpendCeilingStop
from maljan.pipeline.events import safe_finding_value
from maljan.pipeline.validation import (
    _BARE_ADDRESS,
    _HEX_ADDRESS,
    _SUFFIXED_ADDRESS,
    EntryTexts,
    ValidationTally,
    Violation,
    _NegationReader,
    _read_dashes,
    citation_violations,
    generic_function_name,
    ledger_absence_contradictions,
    misstated_entry_contents,
    retry_with_feedback,
    schema_violations,
    wrong_entry_citations,
)
from maljan.reporting.models import (
    C2Channel,
    EncryptionScheme,
    FlowStep,
    HostIdentifier,
    KeyFinding,
    MalwareReport,
    TechnicalSubsection,
)
from maljan.schemas.evidence import entry_ids_in
from maljan.utils.written_forms import pack_escaped, pack_reads

if TYPE_CHECKING:
    from maljan.reporting.agreement_facts import LedgerFacts
    from maljan.reporting.limitation_facts import FailedCall

# The producer the round's unresolved findings are recorded under.
AGREEMENT_PRODUCER = "agreement"
# The token ledger's name for the round's calls (``core.spend.TAIL_CALLS``).
AGREEMENT_CALL = "agreement"

# The round's answer, or one row of it, does not fit the object asked for.
SCHEMA_CODE = "agreement.schema"
# A row names a passage the round was not shown as one it may answer for.
UNKNOWN_PASSAGE_CODE = "agreement.unknown_passage"
# A row's sentence does not stand in its passage as copied.
SENTENCE_NOT_FOUND_CODE = "agreement.sentence_not_found"
# A row names a source the round was not shown, or answers a section 5
# passage with a source that is not a platform fact.
UNKNOWN_SOURCE_CODE = "agreement.unknown_source"
# A rewrite cites an id that neither its sources nor its passage cite.
REWRITE_CITES_ELSEWHERE_CODE = "agreement.rewrite_cites_elsewhere"
# A rewrite that leaves out an id the sentence it replaces cites.
REWRITE_DROPS_CITATION_CODE = "agreement.rewrite_drops_citation"
# A rewrite that cites none of the ids its sources cite, or rests only on
# sources that cite none; for a section 5 sentence, one resting only on facts
# about nothing the sentence names (the routine or its caller, the address, the
# value or the call), or, for a routine or bound-value fact on a sentence
# stating an absence and naming no address, nothing its passage names, or with
# no clause of their own.
REWRITE_UNGROUNDED_CODE = "agreement.rewrite_ungrounded"
# A sentence the agreement question rewrote: what stood, what replaced it and
# on which sources, recorded as the model's answer.
REWRITTEN_CODE = "agreement.rewritten"
# A sentence of a passage shown for reading only (a section 5 passage, a
# record's value field), listed as saying otherwise than its sources and kept
# as written: the model's answer, recorded where a reader finds it.
LISTED_CODE = "agreement.listed"
# A rewrite of a limitations sentence that still says a call failed, or a
# reading could not be made, where a later call redid it (T-526).
FAILURE_REDONE_CODE = "agreement.failure_redone"


# The kinds of passage the round is shown, by who wrote them from what.
CLAIM_LED = "claim-led"
SECTION_5 = "section 5"
FACT = "fact"
DEBATE = "debate"

# The fields of each record that hold the report model's sentences, which a
# rewrite may replace, and the fields that hold a value in a record's cell (a
# cipher's name, a channel's protocol), shown for reading and never rewritten.
# A host identifier's value or a channel's endpoint is the indicator itself
# and is not shown at all.
_PROSE_FIELDS: dict[type[BaseModel], tuple[str, ...]] = {
    KeyFinding: ("text",),
    FlowStep: ("action",),
    HostIdentifier: ("purpose",),
    EncryptionScheme: ("key_source", "key_management", "partial_threshold"),
}
_VALUE_FIELDS: dict[type[BaseModel], tuple[str, ...]] = {
    EncryptionScheme: ("cipher", "mode", "library", "iv"),
    C2Channel: ("protocol", "encryption", "packet_layout"),
}


@dataclass
class Passage:
    """One text the round is shown, under its id, with the ids it cites.

    ``write`` puts a rewritten text where the passage stands; a passage with
    none (a fact, a debate round, a table row) is a source only.
    """

    id: str
    label: str
    text: str
    kind: str
    cites: frozenset[str] = frozenset()
    write: Callable[[str], None] | None = None
    # What a fact is about, which a section 5 sentence it grounds a rewrite of
    # must name: the addresses it names, in every spelling, or its value.
    addresses: frozenset[int] = frozenset()
    value: str = ""
    # The call a bound value is passed to, by the API's name.
    call: str = ""
    # The fact's own clause, which the platform adds to a section 5 sentence
    # the model chose to qualify on it (``_qualified``); none for a fact that
    # grounds no rewrite.
    qualifier: str = ""
    # A fact about a routine (one whose code no entry lists, or one an entry
    # lists) or a decoded value bound to a call: it grounds a section 5 sentence
    # stating an absence wherever the sentence's passage names it (``_grounds``).
    on_absence: bool = False
    # The checks the field a passage stands in holds its text to, run on a
    # rewrite before it is put in (an ATT&CK procedure: one sentence, carrying
    # its technique's values); none for a passage held to the round's alone.
    check: Callable[[str], list[Violation]] | None = None
    # The same, for a check that reads the sources the row names beside the
    # rewrite (the limitations paragraph: a failure a later call redid).
    sourced_check: Callable[[str, Sequence[str]], list[Violation]] | None = None


def _ids(*sources: Any) -> frozenset[str]:
    """The entry ids in every text and list given, in the spelling the counter issues."""
    found: set[str] = set()
    for source in sources:
        if isinstance(source, str):
            found |= entry_ids_in(source)
        elif isinstance(source, Iterable):
            for item in source:
                found |= entry_ids_in(str(item or ""))
    return frozenset(found)


def _setter(obj: Any, name: str) -> Callable[[str], None]:
    """Write ``name`` on ``obj``, and add each id the text cites to the object's own list.

    A record that lists its entries (``evidence_ids``, ``evidence_refs``)
    gains the ids a rewrite cites that it did not list, after the ones it did.
    """

    def _write(text: str) -> None:
        setattr(obj, name, text)
        for listing in ("evidence_ids", "evidence_refs"):
            held = getattr(obj, listing, None)
            if isinstance(held, list):
                known = {str(value).strip().lower() for value in held}
                held.extend(found for found in sorted(entry_ids_in(text)) if found not in known)

    return _write


def _record_passages(
    prefix: str, label: str, rows: Sequence[Any], kind: str, *, number: bool = True
) -> list[Passage]:
    """The written fields of each record of a list, one passage each, numbered from 1."""
    out: list[Passage] = []
    for index, row in enumerate(rows, 1):
        prose = _PROSE_FIELDS.get(type(row), ())
        fields = (*prose, *_VALUE_FIELDS.get(type(row), ()))
        refs = [
            *(getattr(row, "evidence_refs", None) or []),
            *(getattr(row, "evidence_ids", None) or []),
            getattr(row, "evidence_ref", None) or "",
        ]
        for name in fields:
            text = getattr(row, name, None)
            if not isinstance(text, str) or not text.strip():
                continue
            where = f"{prefix}.{index}" if number else prefix
            single = len(fields) == 1
            said = label + (f" {index}" if number else "")
            out.append(
                Passage(
                    id=where if single else f"{where}.{name}",
                    label=said if single else f"{said}, {name.replace('_', ' ')}",
                    text=text,
                    kind=kind,
                    cites=_ids(refs, text),
                    write=_setter(row, name) if name in prose else None,
                )
            )
    return out


def passages_of(
    report: MalwareReport,
    *,
    narrative_written: bool = True,
    discussion: Iterable[Any] = (),
    entries: Iterable[Any] = (),
) -> list[Passage]:
    """Every passage the round is shown, in the order the prompt lists them.

    The facts first, then section 5's passages written from the code, then
    the debate's mediations, then the passages written without the code. The
    key findings and the summary are asked about only when the narrative round
    wrote them (``narrative_written``): the platform's own fallback is not the
    report model's to rewrite. ``entries`` is the run's ledger, in its order,
    which the facts after the bound values are read off.
    """
    from maljan.reporting.call_bindings import binding_words
    from maljan.reporting.composer import COMPOSED_SECTIONS
    from maljan.reporting.evidence_bundles import reads_code

    facts: list[Passage] = []
    for index, bound in enumerate(report.bound_values, 1):
        facts.append(
            Passage(
                id=f"bound.{index}",
                label="decoded text passed to an API argument",
                # The value and the chain both carry the sample's own text (an
                # import's name, a decoder's): each one quoted value.
                text=f"{quoted_value(bound.value)}: {quoted_value(binding_words(bound))}",
                kind=FACT,
                cites=_ids([bound.entry, bound.named_by]),
                addresses=frozenset(
                    address
                    for address in (
                        _hex_address(where)
                        for where in (bound.function, bound.site, bound.decoder_call, bound.call_at)
                    )
                    if address is not None
                ),
                value=str(bound.value or ""),
                call=str(bound.api or ""),
                on_absence=True,
                qualifier=(
                    f'the code passes "{_sample_text(bound.value)}" to '
                    f"{_sample_text(bound.api)} as argument {bound.argument}"
                    + (f" ({_sample_text(bound.parameter)})" if bound.parameter else "")
                ),
            )
        )

    ta = report.technical_analysis
    coded: list[Passage] = []
    uncoded: list[Passage] = []
    for section in COMPOSED_SECTIONS:
        sub = getattr(ta, section, None) if ta is not None else None
        if not isinstance(sub, TechnicalSubsection) or not sub.body.strip():
            continue
        group, kind = (coded, SECTION_5) if reads_code(section) else (uncoded, CLAIM_LED)
        group.append(
            Passage(
                id=section,
                label=f"5. Technical analysis, '{sub.title}'",
                text=sub.body,
                kind=kind,
                cites=_ids(sub.evidence_refs, sub.body),
                # A section 5 sentence is rewritten on a platform fact alone
                # (``_row_violations`` names the sources it may rest on).
                write=_setter(sub, "body"),
            )
        )
    if ta is not None:
        # The table rows read from the code are sources: their cells are values.
        for section, rows, cells in (
            ("configuration", ta.configuration, ("key", "value", "how_obtained")),
            ("commands", ta.commands, ("id", "name", "description")),
            ("cli_flags", ta.cli_flags, ("flag", "description")),
        ):
            if not reads_code(section):
                continue
            for index, row in enumerate(rows, 1):
                said = " | ".join(str(getattr(row, cell, None) or "-") for cell in cells)
                refs = [
                    *(getattr(row, "evidence_refs", None) or []),
                    getattr(row, "evidence_ref", None) or "",
                ]
                coded.append(
                    Passage(
                        id=f"{section}.{index}",
                        label=f"5. Technical analysis, {section.replace('_', ' ')} row {index}",
                        text=said,
                        kind=SECTION_5,
                        cites=_ids(refs, said),
                    )
                )

    debate: list[Passage] = []
    rounds = [
        arg
        for arg in discussion or ()
        if str(_field(arg, "agent_name") or "") == _mediator_name()
        and str(_field(arg, "finding") or "").strip()
    ]
    for index, arg in enumerate(rounds, 1):
        finding = str(_field(arg, "finding") or "")
        debate.append(
            Passage(
                id=f"debate.{index}",
                label=f"debate round {index}, the mediator's words",
                text=finding,
                kind=DEBATE,
                cites=_ids(finding),
            )
        )

    if narrative_written:
        uncoded[:0] = [
            *_record_passages(
                "key_findings", "1. Key findings, bullet", report.key_findings, CLAIM_LED
            ),
            *(
                [
                    Passage(
                        id="executive_summary",
                        label="1. Key findings, the summary paragraph",
                        text=report.executive_summary,
                        kind=CLAIM_LED,
                        cites=_ids(report.executive_summary),
                        write=_setter(report, "executive_summary"),
                    )
                ]
                if report.executive_summary.strip()
                else []
            ),
        ]
    if ta is not None:
        steps = sorted(ta.execution_flow, key=lambda step: step.order)
        uncoded.extend(
            _record_passages("execution_flow", "4. Execution flow, step", steps, CLAIM_LED)
        )
        uncoded.extend(
            _record_passages(
                "host_identifiers", "9. Host identifiers, row", ta.host_identifiers, CLAIM_LED
            )
        )
        if ta.encryption_scheme is not None and not reads_code("encryption_scheme"):
            uncoded.extend(
                _record_passages(
                    "encryption_scheme",
                    "5. Technical analysis, encryption scheme",
                    [ta.encryption_scheme],
                    CLAIM_LED,
                    number=False,
                )
            )
    if not reads_code("communications"):
        uncoded.extend(
            _record_passages(
                "communications",
                "5. Technical analysis, channel row",
                report.c2_channels,
                CLAIM_LED,
            )
        )
    if ta is not None and ta.technique_procedures:
        # The ATT&CK table's procedures are written from the claims, one sentence
        # each, beside section 5 (T-494): asked like every other such passage,
        # and a rewrite held to what the composer holds a procedure to.
        held_to = _procedure_check(report)
        for index, row in enumerate(ta.technique_procedures, 1):
            if not row.procedure.strip():
                continue
            uncoded.append(
                Passage(
                    id=f"procedures.{index}",
                    label=(
                        "ATT&CK table, the procedure for "
                        f"{_sample_text(_one_line(row.technique_id))}"
                    ),
                    text=row.procedure,
                    kind=CLAIM_LED,
                    cites=_ids(row.evidence_refs, row.procedure),
                    write=_setter(row, "procedure"),
                    check=held_to(row.technique_id),
                )
            )
    if report.intro_background.strip():
        uncoded.append(
            Passage(
                id="introduction",
                label="12.3 Background",
                text=report.intro_background,
                kind=CLAIM_LED,
                cites=_ids(report.intro_background),
                write=_setter(report, "intro_background"),
            )
        )
    held = list(entries or ())
    found = None
    if held:
        from maljan.reporting.agreement_facts import ledger_facts

        found = ledger_facts(held)
    shown = [*facts, *coded, *debate, *uncoded]
    facts.extend(_ledger_passages(held, shown, found))
    # The limitations paragraph joins only where a sentence of it says a call
    # failed that the ledger says otherwise of (T-526), its facts after the
    # ledger's own, which it leaves as they were: every other request stays
    # as it was.
    limitations, limitation_facts = _limitation_passages(report, held, found, facts)
    uncoded.extend(limitations)
    facts.extend(limitation_facts)
    return [*facts, *coded, *debate, *uncoded]


def _procedure_check(report: MalwareReport) -> Callable[[str], Callable[[str], list[Violation]]]:
    """For a technique, the check a rewrite of its procedure passes: one sentence, for a
    technique the report publishes, carrying its claims' values
    (``composer_pro.procedure_violations``, ``procedure_value_violations``). The
    technique's claims are read once for every procedure."""
    from maljan.reporting.composer_pro import (
        ValueReader,
        first_claim_sentences,
        procedure_value_violations,
        procedure_violations,
        published_techniques,
    )

    published = list(published_techniques(report))
    firsts = first_claim_sentences(report)
    reader = ValueReader.of(report)

    def _for(tid: str) -> Callable[[str], list[Violation]]:
        def _check(text: str) -> list[Violation]:
            payload = {"procedures": [{"technique_id": tid, "procedure": text}]}
            return [
                *procedure_violations(payload, published),
                *procedure_value_violations(payload, firsts, reader),
            ]

        return _check

    return _for


def _one_line(text: Any, limit: int = 40) -> str:
    """A short field as one line: whitespace collapsed, cut at ``limit`` characters."""
    return " ".join(str(text or "").split())[:limit]


def _sample_text(text: Any) -> str:
    """Text the sample may control, as the composer writes it in prose: escaped, every
    ledger id and every chat-template token written out, so it can neither cite an
    entry nor speak as the template."""
    return template_tokens_written_out(pack_escaped(str(text or ""), ids=True, delimiters=True))


def _hex_address(where: str) -> int | None:
    """An address a bound value's record writes (``0x…``), or ``None``."""
    found = re.fullmatch(r"\s*0x([0-9a-fA-F]{1,16})\s*", str(where or ""))
    return int(found.group(1), 16) if found else None


# Where a word ends, for reading an address a text names: a space, a bracket, a
# quote, a list or clause mark, an operator, an arrow. A path, a file name, a URL
# or a registry key is one word, and a longer identifier is one word.
_WORD_BREAK = re.compile(
    r"(?:->|<-|=>|[\s()\[\]{}<>\"'`,;:!?=*+&@|~#%"
    r"\u2014\u2018\u2019\u201c\u201d\u2190-\u21ff])+"
)
# What joins addresses into one word: a range or a pair (``0x10-0x40``,
# ``0x10..0x40``, ``0x7504/0xd1c8``). Every part of such a word is an address,
# or none is.
_ADDRESS_JOIN = re.compile(r"\.\.|[/\\\-\u2013]")


# A decompiler's name for a function written with ``0x`` before its address
# (``fcn.0x33ac``): the word before the address is read as a declared one.
_NAMED_HEX = re.compile(r"([A-Za-z]\w*?)([_.])0x([0-9a-f]{1,16})", re.IGNORECASE)


def _whole_address(part: str, function: re.Pattern[str]) -> int | None:
    """The address ``part`` is, written whole in a spelling the absence check reads, or
    ``None``. ``function`` is the declared decompiler names' pattern."""
    for pattern in (_HEX_ADDRESS, function, _SUFFIXED_ADDRESS, _BARE_ADDRESS):
        found = pattern.fullmatch(part)
        if found:
            return int(found.group(1), 16)
    named = _NAMED_HEX.fullmatch(part)
    if named and function.fullmatch(f"{named.group(1)}{named.group(2)}0"):
        return int(named.group(3), 16)
    return None


def _addresses_named(text: str) -> list[int]:
    """Every address ``text`` names as an address: a word that is one (``0x6f48``,
    ``FUN_00406f48``, ``6f48h``, bare hex), or a range or pair of them.

    A hex run inside a path, a file name, a URL, a registry key or a longer
    identifier (``files/0x00020000000003ba-104.dat``) names no address: it is
    part of a word that is not one. A slash with nothing on its other side
    (``0x401000/``, ``/0x5a10``) joins no path segment. One pass over the text.
    """
    function = generic_function_name()
    out: list[int] = []
    for word in _WORD_BREAK.split(text):
        word = word.rstrip(".\u2026").strip("/")
        if not word:
            continue
        found = [_whole_address(part, function) for part in _ADDRESS_JOIN.split(word)]
        if all(value is not None for value in found):
            out.extend(value for value in found if value is not None)
    return out


def _named_addresses(passages: Iterable[Passage]) -> set[int]:
    """Every address the passages name, in a spelling the absence check reads (``0x…``,
    a decompiler's name, ``…h``, bare hex), as a word of its own (:func:`_addresses_named`).
    One pass over each text."""
    named: set[int] = set()
    for passage in passages:
        named.update(_addresses_named(passage.text))
    return named


def _spelled_both(addresses: Iterable[int], bases: Sequence[int]) -> frozenset[int]:
    """Each address and its offset, where the one image base read makes one."""
    out: set[int] = set()
    for address in addresses:
        out.add(address)
        if len(bases) == 1 and address >= bases[0]:
            out.add(address - bases[0])
    return frozenset(out)


def _offsets(addresses: Sequence[int], bases: Sequence[int]) -> str:
    """Addresses by their offsets where the one base read makes them offsets, else as written."""
    if len(bases) == 1 and all(a >= bases[0] for a in addresses):
        word = "offset " if len(addresses) == 1 else "offsets "
        return word + ", ".join(hex(a - bases[0]) for a in addresses)
    return ", ".join(hex(a) for a in addresses)


# What a fact about a routine whose code no entry lists says, in the facts' words.
_NOT_LISTED = "no entry lists its code (decompiled or disassembled)"


# Words that call code not read, not listed or not in the evidence: what makes a
# listed routine a passage names a fact worth showing (``_said_unread``). Which
# sentence the listing contradicts is still the model's call.
_UNREAD_VERB = r"(?:read|decompiled|disassembled|listed|examined|opened|obtained)"
_SAID_UNREAD = re.compile(
    r"\b(?:is|are|was|were|be|been|being|has|have|had|remains?|remained)\s+(?:still\s+)?"
    rf"(?:not|never)\s+(?:yet\s+)?(?:been\s+)?{_UNREAD_VERB}\b"
    rf"|\b(?:code|body|bodies|listing|listings)\s+(?:not|never)\s+{_UNREAD_VERB}\b"
    r"|\b(?:is|are|was|were)\s+not\s+(?:in|part\s+of)\s+(?:this|the|my)\s+"
    r"(?:evidence|ledger|rows)\b"
    r"|\bunread\b",
    re.IGNORECASE,
)
# Where a clause ends inside a sentence: the code an absence is about stands in
# its own clause, or right before it ("0x7504 is called. Its body was not read.").
_CLAUSE_BREAK = re.compile(r"[;:,()\u2014\u2013]|\s(?:but|while|whereas|although|so)\s")


# The clause the platform adds to a section 5 sentence on an unread callee
# (``unread_callee_clause``): its callers are read routines, named by the fact.
_UNREAD_CLAUSE = re.compile(
    r"the routine at [^;]*?, called by the read routines? at [^;]*?, has no listed code "
    r"\(decompiled or disassembled\)",
    re.IGNORECASE,
)


def _addresses_before(text: str) -> set[int]:
    """The last address ``text`` names, read word by word from its end."""
    for word in reversed(text.split()):
        found = _addresses_named(word)
        if found:
            return set(found)
    return set()


def _said_unread(passages: Iterable[Passage]) -> set[int]:
    """Every address a passage says the code of is not read or not in the evidence.

    The passive statement only ("was not read", "is not in this evidence", never
    "does not read the key"), and only the addresses in its own clause, else the
    nearest one before it in the sentence, else the last one of the sentence
    before ("0x7504 is called. Its body was not read."). The platform's own
    clause on an unread callee names none. One pass over each text.
    """
    out: set[int] = set()
    for passage in passages:
        starts, _ends = _sentence_units(_UNREAD_CLAUSE.sub("", passage.text))
        ordered = [s for _at, s in sorted((at, s) for s, ats in starts.items() for at in ats)]
        for index, sentence in enumerate(ordered):
            for match in _SAID_UNREAD.finditer(sentence):
                before = sentence[: match.start()]
                breaks = [m.end() for m in _CLAUSE_BREAK.finditer(before)]
                after = _CLAUSE_BREAK.search(sentence, match.end())
                clause = sentence[breaks[-1] if breaks else 0 : after.start() if after else None]
                found = set(_addresses_named(clause)) or _addresses_before(before)
                if not found and index:
                    found = _addresses_before(ordered[index - 1])
                out.update(found)
    return out


# How a listed routine's code was read, in the facts' words.
_LISTED_AS = "decompiled or disassembled"


def listed_routine_clause(routine: str, ids: str, verb: str) -> str:
    """The clause a section 5 sentence qualified on a listed routine gains, in its words."""
    return f"{ids} {verb} the code of the routine at {routine} ({_LISTED_AS})"


def unread_callee_clause(routine: str, callers: str, plural: str) -> str:
    """The clause a section 5 sentence qualified on an unread callee gains, in its words.

    The renderers read it back by these words (``renderers.prose_forms``) to
    print a long caller list as a list.
    """
    return (
        f"the routine at {routine}, called by the read {plural} at {callers}, has no listed "
        "code (decompiled or disassembled)"
    )


def _ledger_passages(
    entries: Sequence[Any], shown: Sequence[Passage], found: LedgerFacts | None = None
) -> list[Passage]:
    """The ledger's facts as passages: the unread callees, the listed routines, then each
    failed call answered later.

    An unread callee is a fact of its own where a passage shown names its
    address; the ones no passage names are one count, citing nothing: a
    routine no passage names bears on no sentence by its address, and listing
    each one per caller cost the prompt more than every fact of its own. A
    routine whose code an entry lists is a fact only where a passage shown
    names it in a sentence that, or whose next sentence, calls code not read or
    not in the evidence (:func:`_said_unread`): it bears on such a sentence
    (T-494) and on no other, and every read routine a passage names would be
    most of the prompt. Which passage a fact bears on is the model's call. The addresses are the
    platform's own; a tool's name is the run's record of a server's word, one
    quoted value. ``found`` is what the ledger's facts were read as, read here
    when not given.
    """
    from maljan.reporting.agreement_facts import ledger_facts, spelled

    if not entries:
        return []
    if found is None:
        found = ledger_facts(entries)
    bases = found.image_bases
    named = _named_addresses(shown)
    out: list[Passage] = []
    left = 0
    for unread in found.unread:
        cites = _ids([*unread.read_in, *unread.stated_in])
        if _spelled_both([unread.address], bases) & named:
            plural = "routine" if len(unread.callers) == 1 else "routines"
            out.append(
                Passage(
                    id=f"unread.{len(out) + 1}",
                    label="routine a read routine calls whose code no entry lists",
                    # The entries that read the callers and state the calls are
                    # the passage's citations, listed beside it.
                    text=(
                        f"{spelled(unread.address, bases)} is called by the read {plural} at "
                        f"{_offsets(unread.callers, bases)}; {_NOT_LISTED}"
                    ),
                    kind=FACT,
                    cites=cites,
                    addresses=_spelled_both([unread.address, *unread.callers], bases),
                    on_absence=True,
                    qualifier=unread_callee_clause(
                        _offsets([unread.address], bases), _offsets(unread.callers, bases), plural
                    ),
                )
            )
            continue
        left += 1
    if left:
        out.append(
            Passage(
                id=f"unread.{len(out) + 1}",
                label="routines read routines call whose code no entry lists",
                text=(
                    f"{left} more {'routine' if left == 1 else 'routines'} that read routines "
                    f"call, none of them named by a passage; for each, {_NOT_LISTED}"
                ),
                kind=FACT,
            )
        )
    listed_facts = 0
    said_unread = _said_unread(shown) if found.listed else set()
    for listed in found.listed:
        cites = _ids(listed.listed_in)
        if not cites or not _spelled_both([listed.address], bases) & said_unread:
            continue
        ids = ", ".join(sorted(cites))
        verb = "lists" if len(cites) == 1 else "list"
        listed_facts += 1
        out.append(
            Passage(
                id=f"listed.{listed_facts}",
                label="routine whose code an entry lists",
                text=f"{spelled(listed.address, bases)}: {ids} {verb} its code ({_LISTED_AS})",
                kind=FACT,
                cites=cites,
                addresses=_spelled_both([listed.address], bases),
                on_absence=True,
                qualifier=listed_routine_clause(_offsets([listed.address], bases), ids, verb),
            )
        )
    for index, link in enumerate(found.answered, 1):
        out.append(
            Passage(
                id=f"answered.{index}",
                label="failed call answered by a later call for the same address",
                text=(
                    f"{link.failed} ({quoted_value(link.failed_tool)}) for "
                    f"{spelled(link.address, bases)} failed; the later call {link.answered} "
                    f"({quoted_value(link.answered_tool)}) for the same address answered"
                ),
                kind=FACT,
                cites=_ids([link.failed, link.answered]),
                addresses=_spelled_both([link.address], bases),
                qualifier=(
                    f"a later call for {_offsets([link.address], bases)} answered it"
                    # Read only where the answer is a listing of the code there.
                    + (", so the address was not left unread" if link.answered_lists_code else "")
                ),
            )
        )
    return out


# Words that say a call failed or a reading could not be made: what holds a
# sentence of the limitations paragraph to the ledger's failed calls (T-526).
# Which sentence a fact contradicts is still the model's call.
_SAYS_FAILED = re.compile(
    r"\b(?:failed|fails|failing|errored|impossible)\b"
    r"|\b(?:was|were|is|are)\s+not\s+possible\b"
    r"|\b(?:could|can)\s*not\s+(?:be\s+)?(?:read|run|decompiled?|disassembled?|emulated?|"
    r"listed|lifted|loaded|opened|reached)\b"
    r"|\bdid\s+not\s+(?:run|complete|succeed|answer)\b",
    re.IGNORECASE,
)
# Words that say the call was redone. Read only where no negation stands within
# the three words before it ("never redone", "no later call answered it"), and
# only to tell which sentences are held: a rewrite is decided by what it cites.
_SAYS_REDONE = re.compile(
    r"\b(?:redone|redid|re-?ran|re-?run|retried|re-?read|re-?issued|later\s+calls?|"
    r"answered\s+later)\b",
    re.IGNORECASE,
)
_NEGATION = frozenset({"no", "not", "never", "without"})
# The words before a redo word read for a negation.
_NEGATION_REACH = 3
# What a call's kind is called in prose, by the stem of the word: a sentence
# naming one names every call of that kind.
_KIND_STEMS = ("decompil", "disassembl", "listing", "emulat")
# A tool's name shorter than this is never read as named by a sentence.
_TOOL_NAME_FLOOR = 3
# What a fact quotes of a tool's message or an analyst's question, at most.
_QUOTED_CHARS = 200


def _capped(text: Any, limit: int = _QUOTED_CHARS) -> str:
    """Text on one line, cut at ``limit`` characters with the cut marked."""
    line = " ".join(str(text or "").split())
    return line if len(line) <= limit else line[: limit - 1].rstrip() + "…"


def _says_redone(sentence: str) -> bool:
    """Whether the sentence says a call was redone, in words no negation stands before."""
    for match in _SAYS_REDONE.finditer(sentence):
        before = re.findall(r"[a-z']+", sentence[: match.start()].lower())[-_NEGATION_REACH:]
        if not _NEGATION.intersection(before):
            return True
    return False


def _sentences_of(text: str) -> list[str]:
    """The sentences of ``text`` in the order they stand."""
    starts, _ends = _sentence_units(text)
    return [s for _at, s in sorted((at, s) for s, ats in starts.items() for at in ats)]


def _kind_words(call: FailedCall) -> set[str]:
    """What a sentence may call the failed call by: its tool's name, and the stems of the
    kind its entry stored (never read off the tool's name)."""
    tool = call.tool.lower()
    words = {tool, tool.replace("_", " ")} if len(tool) >= _TOOL_NAME_FLOOR else set()
    words.update(stem for stem in _KIND_STEMS if stem in call.kind.lower())
    if call.lists_code:
        words.add("listing")
    return words


def _stale_citations(sentence: str, redone: Sequence[FailedCall]) -> list[FailedCall]:
    """The redone calls a sentence cites without citing a call that redid them."""
    cited = entry_ids_in(sentence)
    return [
        call
        for call in redone
        if call.entry.lower() in cited and not cited & {by.lower() for by in call.redone_by}
    ]


def held_limitation_sentences(
    text: str, failed: Sequence[FailedCall], listed: Iterable[int], bases: Sequence[int]
) -> list[str]:
    """The sentences of a limitations paragraph held to the ledger's failed calls.

    A sentence that says a call failed or a reading could not be made is held
    where it cites a failed call a later call redid and none of the calls that
    redid it, whatever else it says; and, where it does not say the call was
    redone, where it names an address a redone call was asked for or whose
    code an entry lists, or names the tool of a redone call or its kind
    (decompiling, disassembling, a listing, emulating), whatever it cites. A
    sentence of a sample's behaviour ("the beacon failed to connect") names
    none. One pass over the sentences.
    """
    redone = [call for call in failed if call.redone]
    listed = list(listed)
    if not redone and not listed:
        return []
    known = _spelled_both((a for call in redone for a in call.asked), bases)
    known |= _spelled_both(listed, bases)
    words: set[str] = set()
    for call in redone:
        words |= _kind_words(call)
    held: list[str] = []
    for sentence in _sentences_of(text):
        if not _SAYS_FAILED.search(sentence):
            continue
        if _stale_citations(sentence, redone):
            held.append(sentence)
            continue
        if _says_redone(sentence):
            continue
        lowered = sentence.lower()
        if set(_addresses_named(sentence)) & known or any(w in lowered for w in words):
            held.append(sentence)
    return held


def _failure_redone_check(
    failed: Sequence[FailedCall], facts: Sequence[Passage]
) -> Callable[[str, Sequence[str]], list[Violation]]:
    """What a rewrite of a limitations sentence is held to: it says no call failed for
    good that a later call redid.

    Decided by what the rewrite cites, never by its words for a redo: a rewrite
    that says a call failed passes only where, for each redone call it cites
    or rests on (a fact among its sources citing that call: a failed-call
    fact, an answered-later fact, an open question), it cites a call that
    redid it. ``facts`` are the facts shown, read when the check runs.
    """
    redone = {call.entry.lower(): call for call in failed if call.redone}

    def _check(rewrite: str, sources: Sequence[str]) -> list[Violation]:
        if not redone or not _SAYS_FAILED.search(rewrite):
            return []
        cited = entry_ids_in(rewrite)
        named = [redone[i] for i in sorted(cited & redone.keys())]
        by_id = {fact.id: fact for fact in facts}
        for source in sources:
            fact = by_id.get(_form(source))
            for entry in sorted(fact.cites & redone.keys()) if fact is not None else ():
                if redone[entry] not in named:
                    named.append(redone[entry])
        stale = [call for call in named if not cited & {by.lower() for by in call.redone_by}]
        if not stale:
            return []
        said = "; ".join(f"{call.entry} by {', '.join(call.redone_by)}" for call in stale)
        return [
            Violation(
                code=FAILURE_REDONE_CODE,
                message=(
                    "the rewrite still says a call failed or a reading could not be made, but "
                    f"a later call redid it ({safe_finding_value(said)}). Cite the call that "
                    "redid it and say what it answered, or keep the sentence."
                ),
                path="rewrite",
            )
        ]

    return _check


def _limitation_passages(
    report: MalwareReport,
    entries: Sequence[Any],
    found: LedgerFacts | None,
    shown_facts: Sequence[Passage] = (),
) -> tuple[list[Passage], list[Passage]]:
    """The limitations paragraph and the facts it rests on, or neither.

    Shown only where a sentence of the composed paragraph is held to the
    ledger (:func:`held_limitation_sentences`): a paragraph that agrees with
    the ledger, or one written where no call failed, leaves the request as it
    was. The facts are each failed call with the later calls that redid it
    (``redone_calls.redone_failures``), or, where none did, the ones that
    answered for some of its addresses,
    each tool not run, the count of tools withheld, each limitation the run
    recorded, each open question filed on a failed call or a missing tool
    (marked where a later call answered a failed call for an address it names
    or an entry it cites) and the count of the others by why they are open.
    A tool's message and a model's question are each one quoted value, cut at
    :data:`_QUOTED_CHARS` characters with the cut marked. ``shown_facts`` are the
    facts shown before these, which a rewrite may rest on too.
    """
    from maljan.reporting.limitation_facts import limitation_facts

    ta = report.technical_analysis
    sub = ta.analyst_limitations if ta is not None else None
    if not isinstance(sub, TechnicalSubsection) or not sub.body.strip() or found is None:
        return [], []
    if not _SAYS_FAILED.search(sub.body):
        return [], []
    bases = found.image_bases
    read = limitation_facts(report, entries, found.answered, bases)
    listed = [routine.address for routine in found.listed]
    if not held_limitation_sentences(sub.body, read.failed, listed, bases):
        return [], []

    facts: list[Passage] = []
    for index, call in enumerate(read.failed, 1):
        if call.redone:
            ids = ", ".join(call.redone_by)
            after = (
                f"the later call{'s' if len(call.redone_by) > 1 else ''} {ids} answered for "
                f"every address it asked ({_offsets(list(call.asked), bases)}), so it did not "
                "fail for good"
            )
        elif call.answered:
            answered = dict(call.answered)
            missing = [a for a in call.asked if a not in answered]
            by = ", ".join(dict.fromkeys(answered.values()))
            after = f"later calls answered for {_offsets(list(answered), bases)} ({by})" + (
                f"; none for {_offsets(missing, bases)}"
                if missing
                else "; none asked the same question whole, so it is not read as redone"
            )
        elif call.asked:
            after = f"no later call answered for {_offsets(list(call.asked), bases)}"
        else:
            after = "it asked for no address, so no later call is read as its redo"
        fact = Passage(
            id=f"failed.{index}",
            label="tool call that failed, and whether a later call redid it",
            text=(
                f"{call.entry} ({quoted_value(call.tool)}) failed: "
                f"{quoted_value(_capped(call.error))}; {after}"
            ),
            kind=FACT,
            cites=_ids([call.entry, *call.redone_by]),
            addresses=_spelled_both(call.asked, bases),
        )
        facts.append(fact)
    for index, tool in enumerate(read.not_run, 1):
        facts.append(
            Passage(
                id=f"not_run.{index}",
                label="tool the run could not offer",
                text=f"{quoted_value(tool.tool)} was not run: {quoted_value(_capped(tool.reason))}",
                kind=FACT,
            )
        )
    if read.withheld:
        facts.append(
            Passage(
                id=f"not_run.{len(read.not_run) + 1}",
                label="tools withheld from the agents",
                text=(
                    f"{read.withheld} {'tool' if read.withheld == 1 else 'tools'} a server "
                    "offers, withheld from the agents by the job, not run"
                ),
                kind=FACT,
            )
        )
    for index, reason in enumerate(read.recorded, 1):
        facts.append(
            Passage(
                id=f"recorded.{index}",
                label="limitation the run recorded",
                text=quoted_value(_capped(reason)),
                kind=FACT,
            )
        )
    facts.extend(_open_question_facts(read.questions, read.failed, bases))
    paragraph = Passage(
        id="limitations",
        label=(
            "11. Limitations, the composed paragraph (each sentence saying a call failed or a "
            "reading could not be made is held to the failed calls, the tools not run, the "
            "recorded limitations and the open questions among the facts)"
        ),
        text=sub.body,
        kind=CLAIM_LED,
        cites=_ids(sub.evidence_refs, sub.body),
        write=_setter(sub, "body"),
        sourced_check=_failure_redone_check(read.failed, [*shown_facts, *facts]),
    )
    return [paragraph], facts


def _open_question_facts(
    questions: Sequence[Any], failed: Sequence[FailedCall], bases: Sequence[int]
) -> list[Passage]:
    """Each open question filed on a failed call or a missing tool, then the others counted.

    A question is marked where a later call redid a failed call for an
    address it names, or a failed call it cites: an analyst may have
    filed it on that failure, which did not stand. Whether the question is
    answered is the model's reading; the mark says only what the ledger says.
    It is shown, never dropped.
    """
    from maljan.reporting.limitation_facts import FAILURE_REASONS

    redid: dict[int, tuple[str, str]] = {}
    for call in failed:
        if not call.redone:
            continue
        for address in call.asked:
            for spelling in _spelled_both([address], bases):
                redid.setdefault(spelling, (call.entry, ", ".join(call.redone_by)))
    by_entry = {call.entry.lower(): call for call in failed if call.redone}
    out: list[Passage] = []
    others: dict[str, int] = {}
    for question in questions:
        if question.reason not in FAILURE_REASONS:
            others[question.reason] = others.get(question.reason, 0) + 1
            continue
        marks: dict[str, tuple[str, str]] = {}
        for address in question.addresses:
            if address in redid:
                failed_id, by = redid[address]
                marks.setdefault(
                    f"the failed call {failed_id} for {_offsets([address], bases)}, an address "
                    "it names,",
                    (failed_id, by),
                )
        for cited in question.cites:
            redone = by_entry.get(cited.lower())
            if redone is not None:
                marks.setdefault(
                    f"the failed call {redone.entry} it cites",
                    (redone.entry, ", ".join(redone.redone_by)),
                )
        said = "; ".join(f"{what} was answered by {by}" for what, (_id, by) in marks.items())
        out.append(
            Passage(
                id=f"open.{len(out) + 1}",
                label="open question an analyst filed on a failed call or a missing tool",
                text=(
                    f"{quoted_value(_capped(question.question))}, filed as {question.reason}"
                    + (f"; redone: {said}" if said else "")
                ),
                kind=FACT,
                cites=_ids([*question.cites, *(i for pair in marks.values() for i in pair)]),
                addresses=_spelled_both(question.addresses, bases),
            )
        )
    if others:
        count = sum(others.values())
        out.append(
            Passage(
                id=f"open.{len(out) + 1}",
                label="the other open questions",
                text=(
                    f"{count} more open {'question' if count == 1 else 'questions'}, filed as "
                    + ", ".join(f"{reason} ({n})" for reason, n in sorted(others.items()))
                ),
                kind=FACT,
            )
        )
    return out


def _field(obj: Any, name: str) -> Any:
    return obj.get(name) if isinstance(obj, dict) else getattr(obj, name, None)


def _mediator_name() -> str:
    from maljan.core.config import MEDIATOR_AGENT_NAME

    return MEDIATOR_AGENT_NAME


# ---------------------------------------------------------------------------
# The answer
# ---------------------------------------------------------------------------


class AgreementRow(BaseModel):
    """One sentence as the report model answers for it."""

    model_config = ConfigDict(extra="ignore")

    passage: str = Field(min_length=1)
    sentence: str = Field(min_length=1)
    sources: list[str] = Field(min_length=1)
    decision: Literal["keep", "rewrite"]
    rewrite: str = ""

    @model_validator(mode="after")
    def _a_rewrite_is_written(self) -> AgreementRow:
        if self.decision == "rewrite" and not self.rewrite.strip():
            raise ValueError("a row whose decision is rewrite gives the rewritten sentence")
        return self


class AgreementOutput(BaseModel):
    """The round's answer: one row per sentence that says otherwise, or none."""

    model_config = ConfigDict(extra="ignore")

    sentences: list[AgreementRow] = Field(default_factory=list)


def _rows(payload: Any) -> list[tuple[int, AgreementRow]]:
    """Each row of the payload that fits the schema, with its place.

    A row that does not fit costs only itself.
    """
    raw = payload.get("sentences") if isinstance(payload, dict) else None
    out: list[tuple[int, AgreementRow]] = []
    for index, row in enumerate(raw if isinstance(raw, list) else []):
        try:
            out.append((index, AgreementRow.model_validate(row)))
        except Exception:  # noqa: BLE001 — the schema check says why
            continue
    return out


def _sentence_units(text: str) -> tuple[dict[str, list[int]], set[int]]:
    """Where each sentence of ``text`` starts, by its words, and where each one ends.

    A sentence ends after a ``.``, ``!`` or ``?`` (and any closing quote or
    bracket after it) that a space or the end follows, or at a line break,
    or at the end of the text. One pass. A sentence is keyed by its text from
    its first character to its end, so a copied sentence is found whole by its
    words.
    """
    starts: dict[str, list[int]] = {}
    ends: set[int] = set()
    length = len(text)
    at = 0
    while at < length and text[at].isspace():
        at += 1
    begin = at
    while at < length:
        char = text[at]
        stop = None
        if char in "\n\r":
            stop = at
        elif char in ".!?":
            after = at + 1
            while after < length and text[after] in "\"')]":
                after += 1
            if after == length or text[after].isspace():
                stop = after
                at = after - 1
        if stop is not None:
            end = stop
            while end > begin and text[end - 1].isspace():
                end -= 1
            if end > begin:
                starts.setdefault(text[begin:end], []).append(begin)
                ends.add(end)
            at = stop
            while at < length and text[at].isspace():
                at += 1
            begin = at
            continue
        at += 1
    end = length
    while end > begin and text[end - 1].isspace():
        end -= 1
    if end > begin:
        starts.setdefault(text[begin:end], []).append(begin)
        ends.add(end)
    return starts, ends


class _Sentences:
    """One passage's sentences, cut once, for every row about the passage."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.starts, self.ends = _sentence_units(text)

    def span(self, sentence: str) -> tuple[int, int, str, int] | None:
        """Where the one sentence copied stands, once, or ``None``.

        As copied, or with the escapes a quoted value is shown with read back
        (``written_forms.pack_reads``): the model was shown each passage quoted.
        The last item says which: ``-1`` as copied, else the reading's place in
        ``pack_reads``, so a rewrite is read back the same way. It has to be
        exactly one sentence of the passage, standing there exactly once; a
        fragment, a word, a run of sentences or a sentence the passage writes
        twice is not one.
        """
        for reading, form in enumerate((sentence, *pack_reads(sentence)), -1):
            copied = form.strip()
            found = self.starts.get(copied, []) if copied else []
            if len(found) == 1:
                return found[0], found[0] + len(copied), copied, reading
        return None


def located(text: str, sentence: str) -> str | None:
    """The spelling of ``sentence`` that stands whole and once in ``text``, or ``None``."""
    span = _Sentences(text).span(sentence)
    return span[2] if span else None


def _form(value: Any) -> str:
    return str(value or "").strip().strip("[]").strip()


def _writable(passage: Passage) -> bool:
    """Whether a sentence of the passage may be rewritten: prose written without the code,
    or section 5 prose, whose rows rest on facts alone (``_row_violations``)."""
    return passage.write is not None and passage.kind in (CLAIM_LED, SECTION_5)


def _listed_when_kept(passage: Passage) -> bool:
    """Whether a kept sentence of the passage is recorded as listed: section 5, or read only."""
    return passage.kind == SECTION_5 or not _writable(passage)


def _row_violations(
    row: AgreementRow,
    index: int,
    by_id: dict[str, Passage],
    sentences_of: Callable[[Passage], _Sentences],
) -> list[Violation]:
    """What is structurally wrong with one row, against the passages shown."""
    path = f"sentences.{index}"
    passage = by_id.get(_form(row.passage))
    if passage is None or passage.kind not in (CLAIM_LED, SECTION_5):
        return [
            Violation(
                code=UNKNOWN_PASSAGE_CODE,
                message=(
                    f"row {safe_finding_value(index + 1)} names the passage "
                    f"{safe_finding_value(row.passage)!r}, "
                    "which is not one of the passages listed for you to answer for. Name a "
                    "passage by its id in square brackets as the list writes it."
                ),
                path=f"{path}.passage",
            )
        ]
    out: list[Violation] = []
    if row.decision == "rewrite" and not _writable(passage):
        out.append(
            Violation(
                code=UNKNOWN_PASSAGE_CODE,
                message=(
                    f"row {safe_finding_value(index + 1)}: {safe_finding_value(passage.id)} is "
                    "shown for reading: list its sentence with the decision keep; it is not "
                    "rewritten."
                ),
                path=f"{path}.decision",
            )
        )
    span = sentences_of(passage).span(row.sentence)
    if span is None:
        out.append(
            Violation(
                code=SENTENCE_NOT_FOUND_CODE,
                message=(
                    f"row {safe_finding_value(index + 1)}: the sentence does not stand in "
                    f"{safe_finding_value(passage.id)} as copied. Copy the whole sentence as "
                    "the passage writes it; it must stand there once."
                ),
                path=f"{path}.sentence",
            )
        )
    sources = [by_id.get(_form(source)) for source in row.sources]
    allowed = (FACT,) if passage.kind == SECTION_5 else (FACT, SECTION_5, DEBATE)
    wrong = [
        _form(name)
        for name, source in zip(row.sources, sources, strict=True)
        if source is None or source.kind not in allowed
    ]
    if wrong:
        out.append(
            Violation(
                code=UNKNOWN_SOURCE_CODE,
                message=(
                    f"row {safe_finding_value(index + 1)} names "
                    f"{safe_finding_value(', '.join(wrong))} as what "
                    f"states otherwise than {safe_finding_value(passage.id)}, but "
                    + (
                        "a section 5 passage is answered by a platform fact (bound.N, "
                        "unread.N, listed.N, answered.N) alone."
                        if passage.kind == SECTION_5
                        else "only the facts, the section 5 passages and the debate rounds "
                        "listed are sources."
                    )
                    + " Name the sources by their ids."
                ),
                path=f"{path}.sources",
            )
        )
    if row.decision == "rewrite" and passage.check is not None:
        # What the field the passage stands in holds its text to holds the
        # rewrite too: a procedure stays one sentence carrying its values.
        out.extend(
            replace(
                violation,
                message=(
                    f"row {safe_finding_value(index + 1)}: the rewrite of "
                    f"{safe_finding_value(passage.id)}: {safe_finding_value(violation.message)}"
                ),
                sentence="",
                path=f"{path}.rewrite",
            )
            for violation in passage.check(row.rewrite)
        )
    if row.decision == "rewrite" and passage.sourced_check is not None:
        out.extend(
            replace(
                violation,
                message=(
                    f"row {safe_finding_value(index + 1)}: the rewrite of "
                    f"{safe_finding_value(passage.id)}: {safe_finding_value(violation.message)}"
                ),
                sentence="",
                path=f"{path}.rewrite",
            )
            for violation in passage.sourced_check(row.rewrite, row.sources)
        )
    if row.decision == "rewrite" and _writable(passage):
        # Only a source the passage may rest on grounds its rewrite: a section
        # 5 sentence's, a fact about what the sentence or its rewrite names.
        grounds = [s for s in sources if s is not None and s.kind in allowed]
        if passage.kind == SECTION_5:
            reading = _Reading(row.sentence, passage.text)
            about = [s for s in grounds if _grounds_section_5(s, reading)]
            if about and span is not None and row.rewrite != _qualified(span[2], about):
                # Every section 5 rewrite is the platform's (``_platform_rewrites``):
                # a row carrying other words is not one.
                about = []
            if grounds and not about:
                out.append(
                    Violation(
                        code=REWRITE_UNGROUNDED_CODE,
                        message=(
                            f"row {safe_finding_value(index + 1)}: "
                            f"{safe_finding_value(', '.join(s.id for s in grounds))} "
                            "is about nothing the sentence names. A fact qualifies a "
                            "section 5 sentence only where the sentence names the routine, "
                            "the address, the value or the call it is about, or, for a "
                            "fact about a routine or a bound value, where the sentence "
                            "states an absence, names no address and its passage names "
                            "what the fact is about. Keep the sentence."
                        ),
                        path=f"{path}.rewrite",
                    )
                )
                out.extend(
                    _grounding_violations(row, index, passage, grounds, span, ungrounded=False)
                )
                return out
            grounds = about
        out.extend(_grounding_violations(row, index, passage, grounds, span))
    return out


def _grounds_section_5(fact: Passage, reading: _Reading) -> bool:
    """Whether a fact grounds a rewrite of a section 5 sentence: where the sentence names
    what the fact is about (a routine whose code no entry lists or its caller, the address
    of an answered call, a bound value, its call or where it is passed), or, for a
    fact about a routine or a bound value, where the sentence states an absence, names no
    address and its passage names what the fact is about. The platform writes the rewrite
    (``_qualified``); a fact with no clause of its own grounds none."""
    return _grounds(fact, reading)


class _Reading:
    """What a section 5 sentence and its passage name, read once for every fact asked
    about the sentence."""

    def __init__(self, sentence: str, passage: str) -> None:
        self.sentence = sentence
        self.lowered = sentence.lower()
        self.passage = passage

    @cached_property
    def named(self) -> frozenset[int]:
        return frozenset(_addresses_named(self.sentence))

    @cached_property
    def passage_named(self) -> frozenset[int]:
        return frozenset(_addresses_named(self.passage))

    @cached_property
    def absence(self) -> bool:
        return _states_an_absence(self.sentence)


def _grounds(fact: Passage, reading: _Reading) -> bool:
    """:func:`_grounds_section_5` for a sentence as copied: a fact with a clause of its
    own, whose clause the sentence does not already carry, about what the sentence
    names; or a fact about a routine or a bound value, about what the passage names,
    where the sentence states an absence and names no address of its own ("No
    environment check is established.", T-404; "The mutex name is not
    established.", T-398). An absence naming an address is about that address
    ("The call at 0x3808 was not read").

    Any other fact is about the sentence alone: a section names many routines, and
    a failed call answered later is not about every sentence beside the one naming
    it (a sentence on dropped files gained a clause on a download routine two
    paragraphs on).
    """
    if not fact.qualifier or fact.qualifier.lower() in reading.lowered:
        return False
    if _about(fact, reading.sentence, reading.named):
        return True
    return (
        fact.on_absence
        and reading.absence
        and not reading.named
        and _about(fact, reading.passage, reading.passage_named)
    )


# A word an absence may be stated of.
_A_WORD = re.compile(r"[A-Za-z][\w-]*")


def _states_an_absence(sentence: str) -> bool:
    """Whether the sentence names something to say it is absent: a word of it the absence
    question reads as named absent (``validation.states_absence``'s reading of a
    mention)."""
    reader = _NegationReader(_read_dashes(sentence))
    return any(reader.named_as_absent(m.start(), m.end()) for m in _A_WORD.finditer(sentence))


def _qualified(sentence: str, facts: Sequence[Passage]) -> str:
    """The sentence as written, with each fact's own clause and the entries they cite added.

    The rewrite of a section 5 sentence on a fact is the platform's: the model
    decides that the sentence is qualified, and its words for it are not read.
    """
    base = sentence.rstrip()
    # A quote or a bracket closing after the end mark stays with the words it
    # closes; the end mark moves after the clauses.
    core = base.rstrip("\"')]")
    closers = base[len(core) :]
    end = "."
    if core and core[-1] in ".!?":
        end = core[-1]
        base = core[:-1].rstrip() + closers
    clauses = "; ".join(dict.fromkeys(fact.qualifier for fact in facts))
    cites = "".join(f"[{c}]" for c in sorted(set().union(*(fact.cites for fact in facts))))
    return f"{base}; {clauses} {cites}{end}"


def _platform_rewrites(payload: Any, by_id: dict[str, Passage]) -> Any:
    """The payload with each section 5 rewrite resting on a fact written by the platform:
    the sentence unchanged and the facts' clauses (``_qualified``). Every other row as the
    model wrote it. One pass over the rows."""
    rows = payload.get("sentences") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        return payload
    out: list[Any] = []
    for row in rows:
        passage = by_id.get(_form(row.get("passage"))) if isinstance(row, dict) else None
        if (
            passage is not None
            and passage.kind == SECTION_5
            and isinstance(row, dict)
            and row.get("decision") == "rewrite"
        ):
            named = row.get("sources")
            standing = located(passage.text, str(row.get("sentence") or ""))
            reading = _Reading(standing or "", passage.text)
            facts = [
                fact
                for fact in (
                    by_id.get(_form(n)) for n in (named if isinstance(named, list) else [])
                )
                if fact is not None and fact.kind == FACT and standing and _grounds(fact, reading)
            ]
            if standing and facts:
                row = {**row, "rewrite": _qualified(standing, facts)}
        out.append(row)
    return {**payload, "sentences": out}


# A bound value is named only whole and at least this long: a shorter one is
# part of too many words.
_VALUE_FLOOR = 3


def _about(fact: Passage, text: str, named: frozenset[int] | None = None) -> bool:
    """Whether a fact is about what the text names: an address it names, in any spelling
    the absence check reads, as a word of its own (:func:`_addresses_named`; ``named``
    when already read), or the value it binds or the call it is passed to, written
    whole."""
    for word in (fact.value, fact.call):
        if len(word) >= _VALUE_FLOOR and re.search(
            r"(?<!\w)" + re.escape(word) + r"(?!\w)", text, re.IGNORECASE
        ):
            return True
    if not fact.addresses:
        return False
    return not fact.addresses.isdisjoint(_addresses_named(text) if named is None else named)


def _grounding_violations(
    row: AgreementRow,
    index: int,
    passage: Passage,
    sources: list[Passage],
    span: tuple[int, int, str, int] | None,
    *,
    ungrounded: bool = True,
) -> list[Violation]:
    """What a rewrite cites against what its sources, its passage and its sentence cite.

    ``ungrounded`` off: the caller has said already why no source grounds it.
    """
    path = f"sentences.{index}.rewrite"
    number = safe_finding_value(index + 1)
    out: list[Violation] = []
    cited = entry_ids_in(row.rewrite)
    grounds = set().union(*(source.cites for source in sources))
    elsewhere = sorted(cited - grounds - set(passage.cites))
    if elsewhere:
        out.append(
            Violation(
                code=REWRITE_CITES_ELSEWHERE_CODE,
                message=(
                    f"row {number}: the rewrite cites "
                    f"{safe_finding_value(', '.join(elsewhere))}, which neither its sources "
                    f"nor {safe_finding_value(passage.id)} cite. Cite only what the sources "
                    "you name, or the passage itself, cite."
                ),
                path=path,
            )
        )
    dropped = sorted(entry_ids_in(span[2]) - cited) if span is not None else []
    if dropped:
        out.append(
            Violation(
                code=REWRITE_DROPS_CITATION_CODE,
                message=(
                    f"row {number}: the sentence cites "
                    f"{safe_finding_value(', '.join(dropped))}, which the rewrite does not. "
                    "Keep every id the sentence cites, or keep the sentence."
                ),
                path=path,
            )
        )
    if ungrounded and not cited & grounds:
        out.append(
            Violation(
                code=REWRITE_UNGROUNDED_CODE,
                message=(
                    f"row {number}: the rewrite cites none of the ids its sources cite"
                    + ("" if grounds else ", and sources that cite none ground no rewrite")
                    + ". Cite the entry a source rests on, or keep the sentence."
                ),
                path=path,
            )
        )
    return out


def agreement_violations(payload: Any, passages: Sequence[Passage]) -> list[Violation]:
    """What is structurally wrong with the answer's rows, as the retry turn shows it.

    Nothing for an answer that does not fit the schema: the schema check
    speaks for it. Each passage is cut into sentences once; a section 5
    rewrite on a fact is read as the platform writes it (``_platform_rewrites``).
    """
    by_id = {passage.id: passage for passage in passages}
    payload = _platform_rewrites(payload, by_id)
    cut: dict[str, _Sentences] = {}

    def _sentences(passage: Passage) -> _Sentences:
        if passage.id not in cut:
            cut[passage.id] = _Sentences(passage.text)
        return cut[passage.id]

    out: list[Violation] = []
    for index, row in _rows(payload):
        out.extend(_row_violations(row, index, by_id, _sentences))
    return out


def _rewrite_violations(
    text: str,
    citable: Sequence[str],
    items: Any,
    entries: EntryTexts | None,
) -> list[Violation]:
    """A rewrite read as the report rounds read their prose."""
    prose = {"rewrite": text}
    return [
        *citation_violations(prose, citable, prose=("rewrite",), items=items),
        *wrong_entry_citations(prose, entries, prose=("rewrite",)),
        *misstated_entry_contents(prose, entries, prose=("rewrite",)),
        *ledger_absence_contradictions(prose, entries),
    ]


def rewrites_violations(
    payload: Any, citable: Sequence[str], items: Any, entries: EntryTexts | None
) -> list[Violation]:
    """Each rewrite's prose findings, its row named in the path."""
    out: list[Violation] = []
    for index, row in _rows(payload):
        if row.decision != "rewrite":
            continue
        for violation in _rewrite_violations(row.rewrite, citable, items, entries):
            out.append(
                replace(
                    violation,
                    message=(
                        f"row {safe_finding_value(index + 1)}: "
                        f"{safe_finding_value(violation.message)}"
                    ),
                    sentence="",
                    path=f"sentences.{index}.rewrite",
                )
            )
    return out


# ---------------------------------------------------------------------------
# Prompt
# ---------------------------------------------------------------------------

EXPECTED_OBJECT = """{
  "sentences": [
    {
      "passage": "execution_flow.3",
      "sentence": "The sentence exactly as the passage writes it.",
      "sources": ["persistence_detail"],
      "decision": "rewrite",
      "rewrite": "The sentence as it should read, stating what the sources state [ev_0007]."
    }
  ]
}"""

SYSTEM_PROMPT = (
    "You are a senior malware reverse engineer reading one analysis report for agreement "
    "between its parts. Its sections were written at the same time by separate calls: the "
    "passages under PASSAGES WRITTEN WITHOUT THE CODE from the analysts' claims, shown "
    "neither the code nor section 5; section 5's passages from the code and the tool "
    "answers. The facts were read from the evidence by code and outrank every model's "
    "words. A routine no entry lists means its code was not examined, not that it does or "
    "does not do anything; it contradicts only a sentence that says that code was read, or "
    "that calls a behaviour absent from the sample on the grounds of the code read; it never "
    "contradicts what another entry (a rule match, an emulation, a call graph) states about "
    "that routine. A routine an entry lists was read: the listing contradicts a sentence that "
    "calls that routine's code or body not read, not shown or not in the evidence. "
    "A call a later call answered did not fail for good. "
    "A debate round is the mediator's words: a line it closed counts as settled only "
    "with the entry it closed it on. " + QUOTED_VALUE_STATEMENT + "\n"
    "List each sentence of a passage written without the code that calls absent, unknown, "
    "open, unresolved, not shown or not established what a section 5 passage, a fact or a "
    "closed debate line states, or that states the opposite of what one of them states; and "
    "each sentence of a section 5 passage that a fact contradicts. For each, give the "
    "passage's id, the whole sentence copied exactly as it stands, the ids of the sources "
    "that state otherwise (a section 5 passage is answered by a fact alone), and one "
    "decision:\n"
    "  - rewrite: the sentence as it should read, stating what the sources state with their "
    "certainty (what they assess, it assesses; what they say is not shown, it says is not "
    "shown), in the passage's style, keeping every ev_ id the sentence cites and citing in "
    "square brackets at least one ev_ id its sources cite, and no id that neither the "
    "sources nor the passage cite;\n"
    "  - keep: the sources do not state otherwise on reading (they speak of another routine, "
    "value or run), or the passage is marked (read only): a table cell is listed with keep "
    "and never rewritten. A section 5 sentence is rewritten only where a fact contradicts it, "
    "and then states what the fact states and nothing a passage written without the code or "
    "a debate round says. A section 5 sentence answered by a fact is not reworded: the "
    "decision rewrite only asks that it be qualified, and the platform adds the fact's own "
    "words and its ids to the sentence as it stands; it is qualified only where the "
    "sentence names the routine, the address, the value or the call the fact is about, or, "
    "for a fact about a routine or a bound value, where the sentence states an absence, names "
    "no address and its passage names what the fact is about.\n"
    "Leave out every sentence no source states otherwise than. List each sentence once. "
    "Answer with exactly this JSON object, with an empty list when no sentence disagrees:\n"
    + EXPECTED_OBJECT
)

_HEADINGS = (
    (FACT, "FACTS THE PLATFORM STATES"),
    (SECTION_5, "SECTION 5, WRITTEN FROM THE CODE AND THE TOOL ANSWERS"),
    (DEBATE, "THE DEBATE'S MEDIATIONS, IN ROUND ORDER"),
    (CLAIM_LED, "PASSAGES WRITTEN WITHOUT THE CODE"),
)


def prompt_text(passages: Sequence[Passage]) -> str:
    """The round's human turn: each kind of passage under its heading, then the task."""
    lines: list[str] = []
    for kind, heading in _HEADINGS:
        group = [passage for passage in passages if passage.kind == kind]
        if not group:
            continue
        lines.extend([heading, "-" * len(heading)])
        for passage in group:
            cites = f" (cites {', '.join(sorted(passage.cites))})" if passage.cites else ""
            # Model-written text and the sample's own: one quoted value each.
            text = passage.text if passage.kind == FACT else quoted_value(passage.text)
            shown = (
                " (read only)"
                if passage.kind in (CLAIM_LED, SECTION_5) and passage.write is None
                else ""
            )
            lines.append(f"- [{passage.id}] {passage.label}{shown}{cites}: {text}")
        lines.append("")
    lines.extend(
        [
            "TASK",
            "----",
            "List each sentence that says otherwise than its sources, as the system prompt "
            "asks. Return ONLY the JSON object shown there.",
        ]
    )
    return "\n".join(lines)


def build_messages(passages: Sequence[Passage]) -> list[BaseMessage]:
    """The system turn and the human turn."""
    return [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=prompt_text(passages))]


# ---------------------------------------------------------------------------
# The round
# ---------------------------------------------------------------------------


@dataclass
class AgreementRound:
    """What the round did: its counts, what it was told, and what it could not do."""

    summary: dict[str, int] = field(default_factory=dict)
    tally: ValidationTally = field(default_factory=ValidationTally)
    degradations: list[str] = field(default_factory=list)


def apply_rows(
    payload: Any,
    passages: Sequence[Passage],
    *,
    citable: Sequence[str] = (),
    items: Any = None,
    entries: EntryTexts | None = None,
) -> tuple[dict[str, int], list[Violation]]:
    """Put each rewrite that passes every check where its sentence stands; the counts.

    Every row is read against each passage as it was written, so a row never
    finds its sentence inside another row's rewrite; a row whose sentence
    overlaps one an earlier row already rewrites is not applied. The rewrites
    of one passage are put in together, from its end; a sentence found through
    its escapes read back has its rewrite read back the same way. Each rewrite
    put in is returned as a finding the model answered (``REWRITTEN_CODE``),
    with what stood; a sentence of a passage shown for reading is listed:
    kept, and returned the same way (``LISTED_CODE``). A section 5 rewrite
    resting on a routine whose code no entry lists is the platform's
    (``_platform_rewrites``).
    """
    by_id = {passage.id: passage for passage in passages}
    payload = _platform_rewrites(payload, by_id)
    cut: dict[str, _Sentences] = {}

    def _sentences(passage: Passage) -> _Sentences:
        if passage.id not in cut:
            cut[passage.id] = _Sentences(passage.text)
        return cut[passage.id]

    counts = {
        "passages": sum(1 for passage in passages if _writable(passage)),
        "claim_led_passages": sum(
            1 for passage in passages if _writable(passage) and passage.kind == CLAIM_LED
        ),
        "sentences": 0,
        "rewritten": 0,
        "kept": 0,
        "listed": 0,
        "not_applied": 0,
    }
    listed: list[Violation] = []
    written: list[Violation] = []
    spans: dict[str, list[tuple[int, int, str]]] = {}
    for index, row in _rows(payload):
        counts["sentences"] += 1
        passage = by_id.get(_form(row.passage))
        found = _row_violations(row, index, by_id, _sentences)
        if row.decision == "keep":
            # A section 5 sentence a fact was listed against is recorded as
            # listed, as it was before it could be rewritten.
            if passage is not None and _listed_when_kept(passage) and not found:
                counts["listed"] += 1
                listed.append(
                    Violation(
                        code=LISTED_CODE,
                        message=(
                            f"The agreement question lists a sentence of "
                            f"{safe_finding_value(passage.label)} as saying otherwise than "
                            f"{safe_finding_value(', '.join(_form(s) for s in row.sources))}; "
                            "the sentence stands as written."
                        ),
                        path=f"sentences.{index}",
                        answered=True,
                    )
                )
            else:
                counts["kept"] += 1
            continue
        found += _rewrite_violations(row.rewrite, citable, items, entries)
        span = _sentences(passage).span(row.sentence) if passage is not None else None
        taken = spans.setdefault(passage.id, []) if passage is not None else []
        if (
            found
            or passage is None
            or span is None
            or any(span[0] < end and start < span[1] for start, end, _ in taken)
        ):
            counts["not_applied"] += 1
            continue
        # A section 5 rewrite is the platform's, built from the passage's own
        # text: put in as it stands, never read back.
        rewrite = row.rewrite if passage.kind == SECTION_5 else " ".join(row.rewrite.split())
        if span[3] >= 0 and passage.kind != SECTION_5:
            # Read back as the sentence was: the model copied both from quoted text.
            reads = pack_reads(rewrite)
            rewrite = reads[min(span[3], len(reads) - 1)] if reads else rewrite
        taken.append((span[0], span[1], rewrite))
        counts["rewritten"] += 1
        written.append(
            Violation(
                code=REWRITTEN_CODE,
                message=(
                    "The agreement question rewrote a sentence of "
                    f"{safe_finding_value(passage.label)} on "
                    f"{safe_finding_value(', '.join(_form(s) for s in row.sources))}: "
                    f"{safe_finding_value(span[2])!r} now reads "
                    f"{safe_finding_value(rewrite)!r}."
                ),
                path=f"sentences.{index}",
                answered=True,
            )
        )
    for pid, rewrites in spans.items():
        if not rewrites:
            continue
        passage = by_id[pid]
        text = passage.text
        for start, end, rewrite in sorted(rewrites, reverse=True):
            text = text[:start] + rewrite + text[end:]
        if passage.write is not None:
            passage.write(text)
    return counts, [*listed, *written]


async def ask_section_agreement(
    reporter: Any,
    report: MalwareReport,
    *,
    narrative_written: bool = True,
    discussion: Iterable[Any] = (),
    citable_ids: Iterable[str] = (),
    items: Any = None,
    evidence_texts: EntryTexts | None = None,
    call: str = AGREEMENT_CALL,
) -> AgreementRound:
    """Ask the reporter's model once whether a passage says otherwise than its sources.

    ``reporter`` is the narrative round's agent (``NarrativeAgent.ask``). No
    reporter, no passage written without the code or no source asks nothing.
    A round that fails, wherever it fails, leaves the report as written (or
    with the rewrites already put in), with the reason said. Never raises.
    """
    tally = ValidationTally()
    mark = len(list(getattr(reporter, "degradations", None) or []))

    def _said() -> list[str]:
        return [str(r) for r in list(getattr(reporter, "degradations", None) or [])[mark:]]

    try:
        return await _ask(
            reporter,
            report,
            tally,
            _said,
            narrative_written=narrative_written,
            discussion=discussion,
            citable_ids=citable_ids,
            items=items,
            evidence_texts=evidence_texts,
            call=call,
        )
    except SpendCeilingStop as stop:
        said = f"The section agreement question was not asked: {stop}."
        logger.warning("section agreement: %s", said)
        return AgreementRound(tally=tally, degradations=[*_said(), said])
    except Exception as exc:  # noqa: BLE001 — a failed round leaves the report as written
        logger.error("section agreement: the round failed (%s).", exc)
        said = f"The section agreement question was not answered ({type(exc).__name__})."
        return AgreementRound(tally=tally, degradations=[*_said(), said])


async def _ask(
    reporter: Any,
    report: MalwareReport,
    tally: ValidationTally,
    said: Callable[[], list[str]],
    *,
    narrative_written: bool,
    discussion: Iterable[Any],
    citable_ids: Iterable[str],
    items: Any,
    evidence_texts: EntryTexts | None,
    call: str,
) -> AgreementRound:
    """:func:`ask_section_agreement`'s body, which may raise."""
    from maljan.llm.answer_text import structured_answer_text
    from maljan.reporting.narrative_agent import _message_text
    from maljan.utils.json_cleaner import safe_parse_json

    if reporter is None:
        return AgreementRound(tally=tally)
    passages = passages_of(
        report,
        narrative_written=narrative_written,
        discussion=discussion,
        entries=(evidence_texts.entries.values() if evidence_texts is not None else ()),
    )
    claim_led = any(_writable(p) and p.kind == CLAIM_LED for p in passages)
    coded = any(_writable(p) and p.kind == SECTION_5 for p in passages)
    # A fact that rests on entries: the count of routines no passage names
    # grounds no rewrite, and asks nothing on its own.
    facts = any(p.kind == FACT and p.cites for p in passages)
    # A passage written without the code is asked against any source; a
    # section 5 passage against a fact alone.
    sourced = any((p.kind == FACT and p.cites) or p.kind in (SECTION_5, DEBATE) for p in passages)
    if not (claim_led and sourced) and not (coded and facts):
        return AgreementRound(tally=tally)
    citable = list(dict.fromkeys(str(value) for value in citable_ids))
    by_id = {passage.id: passage for passage in passages}
    answer_read = [""]

    def _parse(answer: Any) -> Any:
        answer_read[0] = structured_answer_text(answer, _message_text)
        parsed = safe_parse_json(answer_read[0])
        # Shape only: a bare list of rows is the object the schema names.
        if isinstance(parsed, list):
            parsed = {"sentences": parsed}
        return _platform_rewrites(parsed, by_id) if isinstance(parsed, dict) else None

    payload, violations, retries = await retry_with_feedback(
        lambda turns: reporter.ask(turns, call=call, what="section agreement question's"),
        build_messages(passages),
        [
            lambda p: schema_violations(
                AgreementOutput, p, code=SCHEMA_CODE, answer=answer_read[0]
            ),
            lambda p: agreement_violations(p, passages),
            lambda p: rewrites_violations(p, citable, items, evidence_texts),
        ],
        parse=_parse,
        on_feedback=tally.count,
    )
    tally.retries += retries
    tally.count(violations)
    if violations:
        tally.record_unresolved(AGREEMENT_PRODUCER, violations)
    counts, listed = apply_rows(
        payload, passages, citable=citable, items=items, entries=evidence_texts
    )
    if listed:
        tally.count(listed)
        tally.record_unresolved(AGREEMENT_PRODUCER, listed)
    logger.info(
        "section agreement: %d passage(s) asked about; %d sentence(s) listed, %d rewritten, "
        "%d kept, %d listed for reading, %d not applied.",
        counts["passages"],
        counts["sentences"],
        counts["rewritten"],
        counts["kept"],
        counts["listed"],
        counts["not_applied"],
    )
    return AgreementRound(summary=counts, tally=tally, degradations=said())

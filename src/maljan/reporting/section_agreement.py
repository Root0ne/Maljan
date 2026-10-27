"""One question once the report body is written: does a passage say otherwise than section 5?

The key findings, the summary, the execution flow, the host identifiers, the
background and the composed sections shown no function's code (the cipher
table, the channel table, the packing prose) are written from the analysts'
claims, at the same time as section 5 is written from the code and the tool
answers; none of them is shown section 5. A claim that calls a routine's body
"not read", a key's use "not established" or a mutex name "open" is that
analyst's view, and a writer shown only the claim repeats it beside a section
5 that states the thing (T-390). The absence check (``validation.
ledger_absence_contradictions``) decides such a sentence only where it names
an address, an entry or a value; "the sleep constants" names none.

So, after every section is written, the reporter's model is shown, once:

- the facts the platform states: each decoded text the code passes to an API
  argument (``report.bound_values``), in the words every surface that
  publishes it uses (``call_bindings.binding_words``);
- section 5's passages written from the code: each prose subsection and each
  row of the configuration, command and flag tables, with the ids it cites;
- the debate's mediations, in round order, as the mediator wrote them;
- every passage written without the code, under an id naming where it stands.

It lists each sentence of a passage written without the code that calls
absent, unknown or open, or states the opposite of, what a section 5 passage,
a fact or a closed debate line states, and each sentence of a section 5
passage a fact contradicts; names the sources; and keeps the sentence or
rewrites it. Nothing here reads a sentence's words: which sentences, and on
which subject, is the model's call. A sentence of a passage written without
the code may be rewritten; a section 5 passage and a table cell's value are
shown for reading, and a sentence of one is listed and kept (no structure
tells which fact a sentence of section 5 is about), the listing recorded as
the model's answer. Code checks the answer's structure: the passage is one it
was shown, the copied text is one whole sentence of it standing there once,
a section 5 passage is answered by a fact alone, and a rewrite keeps every id
its sentence cites, cites at least one id its sources cite (sources citing no
id ground no rewrite) and no id that neither they nor the passage cite;
and it reads each rewrite as the report rounds read their prose (its
citations, a value beside an entry that does not hold it, an entry said to
hold nothing, an absence the ledger contradicts). The model is told what is
wrong and asked once more. A rewrite that passes takes its sentence's place,
read against the passage as it was written, its new ids added to the record's
own list, and what it replaced is recorded as the model's answer; a sentence
kept, or a rewrite that still fails, stays as written, and the finding is
recorded.

Every step is one pass over the passages and the answer's rows.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field, replace
from typing import Any, Literal

from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage
from pydantic import BaseModel, ConfigDict, Field, model_validator

from maljan.agents.tool_fence import QUOTED_VALUE_STATEMENT, quoted_value
from maljan.core.logger import logger
from maljan.core.spend import SpendCeilingStop
from maljan.pipeline.events import safe_finding_value
from maljan.pipeline.validation import (
    EntryTexts,
    ValidationTally,
    Violation,
    citation_violations,
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
from maljan.utils.written_forms import pack_reads

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
# sources that cite none.
REWRITE_UNGROUNDED_CODE = "agreement.rewrite_ungrounded"
# A sentence the agreement question rewrote: what stood, what replaced it and
# on which sources, recorded as the model's answer.
REWRITTEN_CODE = "agreement.rewritten"
# A sentence of a passage shown for reading only (a section 5 passage, a
# record's value field), listed as saying otherwise than its sources and kept
# as written: the model's answer, recorded where a reader finds it.
LISTED_CODE = "agreement.listed"


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
) -> list[Passage]:
    """Every passage the round is shown, in the order the prompt lists them.

    The facts first, then section 5's passages written from the code, then
    the debate's mediations, then the passages written without the code. The
    key findings and the summary are asked about only when the narrative round
    wrote them (``narrative_written``): the platform's own fallback is not the
    report model's to rewrite.
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
                # Section 5 is read, not rewritten: no structure tells which
                # fact a sentence of it is about.
                write=None if kind == SECTION_5 else _setter(sub, "body"),
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
    return [*facts, *coded, *debate, *uncoded]


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
    return passage.write is not None and passage.kind == CLAIM_LED


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
                        "a section 5 passage is answered by a platform fact (bound.N) alone."
                        if passage.kind == SECTION_5
                        else "only the facts, the section 5 passages and the debate rounds "
                        "listed are sources."
                    )
                    + " Name the sources by their ids."
                ),
                path=f"{path}.sources",
            )
        )
    if row.decision == "rewrite" and _writable(passage):
        out.extend(_grounding_violations(row, index, passage, [s for s in sources if s], span))
    return out


def _grounding_violations(
    row: AgreementRow,
    index: int,
    passage: Passage,
    sources: list[Passage],
    span: tuple[int, int, str, int] | None,
) -> list[Violation]:
    """What a rewrite cites against what its sources, its passage and its sentence cite."""
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
    if not cited & grounds:
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
    speaks for it. Each passage is cut into sentences once.
    """
    by_id = {passage.id: passage for passage in passages}
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
    "words. A debate round is the mediator's words: a line it closed counts as settled only "
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
    "value or run), or the passage is marked (read only): a section 5 passage and a table "
    "cell are listed with keep and never rewritten.\n"
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
            shown = " (read only)" if passage.kind == CLAIM_LED and passage.write is None else ""
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
    kept, and returned the same way (``LISTED_CODE``).
    """
    by_id = {passage.id: passage for passage in passages}
    cut: dict[str, _Sentences] = {}

    def _sentences(passage: Passage) -> _Sentences:
        if passage.id not in cut:
            cut[passage.id] = _Sentences(passage.text)
        return cut[passage.id]

    counts = {
        "passages": sum(1 for passage in passages if _writable(passage)),
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
            if passage is not None and not _writable(passage) and not found:
                counts["listed"] += 1
                listed.append(
                    Violation(
                        code=LISTED_CODE,
                        message=(
                            f"The agreement question lists a sentence of "
                            f"{safe_finding_value(passage.label)} as saying otherwise than "
                            f"{safe_finding_value(', '.join(_form(s) for s in row.sources))}; "
                            "the passage is shown for reading, and the sentence stands as "
                            "written."
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
        rewrite = " ".join(row.rewrite.split())
        if span[3] >= 0:
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
    passages = passages_of(report, narrative_written=narrative_written, discussion=discussion)
    if not any(_writable(p) for p in passages) or not any(
        p.kind in (FACT, SECTION_5, DEBATE) for p in passages
    ):
        return AgreementRound(tally=tally)
    citable = list(dict.fromkeys(str(value) for value in citable_ids))
    answer_read = [""]

    def _parse(answer: Any) -> Any:
        answer_read[0] = structured_answer_text(answer, _message_text)
        parsed = safe_parse_json(answer_read[0])
        # Shape only: a bare list of rows is the object the schema names.
        if isinstance(parsed, list):
            parsed = {"sentences": parsed}
        return parsed if isinstance(parsed, dict) else None

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

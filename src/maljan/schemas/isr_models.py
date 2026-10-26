"""Intermediate Structural Representation (ISR) models for inter-agent communication.

Instead of passing raw text between agents in the negotiation loop,
agents exchange structured ISR objects. This prevents context bloat and
forces agents to cite concrete evidence for every claim they make.

Literature basis:
  - MalEval (arXiv:2509.14335): LLMs fail when passing raw code slices between agents.
  - CONSENSAGENT (arXiv): Structured formats reduce sycophancy.
  - Multi-Agent Malware Analysis Framework Research (internal report).
"""

from __future__ import annotations

from typing import Any, Literal, get_args

from pydantic import BaseModel, Field, PrivateAttr, model_validator

# What a claim carrying an id the catalogue does not have is labelled with,
# wherever it is printed. One string so the ISR summary the judge reads, the
# Markdown report and the HTML report cannot word it three different ways.
UNVERIFIED_TECHNIQUE_MARKER = "technique id not in the ATT&CK catalog"
# The note on a technique whose claim reads as absence and whose analyst kept
# the id when asked. The technique is published as the analyst stated it; the
# note travels with it to the judge's summary and the report's ATT&CK table.
ABSENCE_TECHNIQUE_MARKER = (
    "the claim naming it reads as absence; the analyst kept the technique when asked"
)
# The note on a claim whose every cited entry is a tool call that failed, and
# on a technique every claim naming it is such a claim. A failed call read
# nothing from the sample; the claim and the technique are published as the
# analyst stated them, and the note travels with them to the judge's summary
# and the report's ATT&CK table.
FAILED_CALLS_MARKER = "the claim cites only tool calls that failed"


def retry_added_marker(revision_round: int) -> str:
    """The note on a claim a validation retry added beside the answer in force.

    The retry is a turn with no tools, written after a revision that wrote no
    claim (``ClaimEvidence.added_by_retry_in_round``). The claim is published
    as the analyst wrote it; the note travels with it to the judge's summary,
    the transcript and the report.
    """
    return f"added by a tool-less retry, round {int(revision_round)}"


# The note on a technique the judge named in its bundle and no analyst claimed.
# The rule it is published by: a technique the judge states is the judge's own
# claim, asked the catalogue and platform questions every claim is asked, and
# published with the judge as its source and the judge's own number.
JUDGE_ONLY_TECHNIQUE_MARKER = (
    "stated by the judge and claimed by no analyst; a technique the judge states is "
    "published as its own claim"
)


def judge_and_findings_note(agents: list[str]) -> str:
    """The note on a technique the judge named and analysts named on findings only.

    The judge's rule publishes it; no analyst claim carries it, and the
    analysts that named it on a finding are named, since they are the
    sources the run's corroboration record lists for it. Said instead of
    ``JUDGE_ONLY_TECHNIQUE_MARKER``, which would deny that any analyst named it.
    """
    named = ", ".join(dict.fromkeys(str(a) for a in agents if str(a).strip()))
    return (
        f"stated by the judge; named on a finding, not on a claim, by {named}; a technique "
        "the judge states is published as its own claim"
    )


# The note on a technique the judge was asked about after its verdict and gave
# no answer for: it is published, or not, as it would have been without the
# question, and the row says the judge did not confirm it.
JUDGE_UNCONFIRMED_TECHNIQUE_MARKER = "not confirmed by the judge"


def judge_dropped_reason(reason: str) -> str:
    """Why a technique the judge dropped when asked is not published, in its own words."""
    said = str(reason or "").strip()
    return f"the judge dropped it ({said})" if said else "the judge dropped it"


def judge_kept_note(reason: str) -> str:
    """The note on a technique the judge kept when asked, with the reason it gave."""
    said = str(reason or "").strip()
    return f"kept by the judge when asked ({said})" if said else "kept by the judge when asked"


class ClaimEvidence(BaseModel):
    """A single verifiable claim with supporting evidence.

    Agents must cite a concrete artifact reference for each claim.
    This prevents hallucinated capabilities and forces grounded reasoning.
    """

    claim: str = Field(..., description="The specific finding or assertion.")
    evidence_ref: str = Field(
        ...,
        description=(
            "Concrete artifact reference naming the ledger entry it was read from, e.g. "
            "'API call: VirtualAllocEx @ 0x401234 (import table) [ev_0002]', "
            "'PCAP frame 42: dst=185.220.101.5:443 [ev_0007]', "
            "'string at .data+0x10: /api/c2 [ev_0003]'."
        ),
    )
    confidence: float = Field(
        ..., ge=0.0, le=1.0, description="Agent self-reported confidence (0-1)."
    )
    technique_id: str | None = Field(
        None,
        description="MITRE ATT&CK technique ID if applicable, e.g. 'T1055.001'.",
        pattern=r"^T\d{4}(\.\d{3})?$",
    )
    # The claim's TECHNIQUE line as written, when it is more than ids or
    # NONE: a qualifier, a negation, a list joined by "or". No id is read from
    # it — "T1027.002 not supported" is not a claim of T1027.002 — and the
    # validation turn asks the analyst for the ids alone
    # (``pipeline.validation.TECHNIQUE_LINE_UNREAD_CODE``). A list of ids
    # separated by commas or "and" is read as one claim per id.
    technique_line: str | None = Field(
        default=None,
        description="The claim's TECHNIQUE line as written, when no technique id could be read.",
    )
    # The note the claim's heading wrote between its number and its delimiter
    # (``CLAIM 2 [REVISED — retracts claim 5]: …``), as written, brackets and
    # all: the model's own words on what the claim is to the debate. Kept
    # beside the sentence, never in it, so no check that reads the sentence
    # and no published text carries it; left out of the serialised claim when
    # there is none (``claim_headings.heading_note``).
    heading_note: str | None = Field(
        default=None,
        description="The note the claim's heading wrote before its delimiter, as written.",
        exclude_if=lambda value: value is None,
    )
    # Whether that id survived validation. ``pipeline.validation`` sets this
    # ``False`` when the analyst kept an id the ATT&CK catalogue does not have,
    # after being told so and given another turn. The id itself stays exactly
    # as the analyst wrote it — a wrong id that says it is wrong is worth more
    # than a right-looking id somebody else substituted — and the flag is what
    # the report, the FP linter and the STIX minting step read instead.
    technique_id_valid: bool = Field(
        default=True,
        description="False when the technique id is not in the ATT&CK catalogue.",
    )
    # Whether the claim reads as absence and its analyst kept the technique id
    # after being asked (``pipeline.validation.ABSENCE_CLAIM_CODE``). Set only
    # when the question was sent. The claim, its id and its publication are
    # unchanged: the flag is a note the report and the judge print beside the
    # id, and long-term memory stores no past-case technique from it.
    kept_after_absence_question: bool = Field(
        default=False,
        description=(
            "True when the claim reads as absence and the analyst kept its id when asked."
        ),
    )
    # Whether every entry the claim cites is a tool call that failed
    # (``pipeline.validation.mark_claims_citing_only_failed_calls``), set once
    # the run's ledger is known. A note, never a drop: the claim, its id and
    # its publication are unchanged. Left out of the serialised claim when
    # false, so a claim stored before it was read reads the same.
    cites_only_failed_calls: bool = Field(
        default=False,
        description="True when every entry the claim cites is a tool call that failed.",
        exclude_if=lambda value: not value,
    )
    # The revision round whose validation retry added this claim beside the
    # answer in force, after the revision itself wrote no claim
    # (``nodes.answer_with_retry_additions``). The retry is a turn with no tools: what
    # it writes is added and replaces no claim the answer in force holds.
    # Left out of the serialised claim when unset.
    added_by_retry_in_round: int | None = Field(
        default=None,
        description=(
            "The revision round whose validation retry, written without tools, added this "
            "claim beside the answer in force."
        ),
        exclude_if=lambda value: value is None,
    )
    # The entries a debate showed this claim's analyst from another agent's
    # calls, when they are every entry the claim cites
    # (``nodes._mark_claims_on_shown_entries``): the claim restates what it
    # was shown, and is no support of its own for corroboration
    # (``validation.shown_claim_unbacked``). Left out of the serialised claim
    # when empty.
    rests_on_shown_entries: list[str] = Field(
        default_factory=list,
        description=(
            "The entries of other agents a debate round showed this claim's analyst, when they "
            "are every entry the claim cites."
        ),
        exclude_if=lambda value: not value,
    )
    # What the ATT&CK index made of the claim text against the id the analyst
    # chose: the id's own gate score and the index's top candidates with
    # theirs. Recorded by ``pipeline.validation`` when the index was warm, so
    # the judge and the report can see the ranking beside the choice. The id
    # itself is never replaced by any of the candidates.
    alignment: dict[str, Any] | None = Field(
        default=None,
        description="The index's gate score for the claimed id and its top candidates.",
    )
    # The ordinal of the claim block the reader read this claim from
    # (``base_agent.read_claim_blocks``): a block whose TECHNIQUE line listed
    # several ids is one claim per id, all with the block's ordinal. Recorded
    # where the claim is read, never serialised; ``None`` for a claim built any
    # other way, whose block is then read from its words
    # (``validation.claim_block_indexes``).
    _block: int | None = PrivateAttr(default=None)

    @property
    def block(self) -> int | None:
        """The ordinal of the block this claim was read from, or ``None``."""
        return self._block

    def note_block(self, ordinal: int) -> None:
        """Record the ordinal of the block this claim was read from."""
        self._block = int(ordinal)

    # The number the claim's heading wrote (``CLAIM 7:`` is ``"7"``, ``CLAIM
    # R7:`` is ``"R7"``), as written, or ``None`` for a heading that wrote
    # none and a claim built any other way (``claim_headings.heading_number``).
    # Recorded where the claim is read, never serialised: a validation retry
    # names the claims it changes by it (``pipeline.retry_merge``).
    _number: str | None = PrivateAttr(default=None)

    @property
    def number(self) -> str | None:
        """The number this claim's heading wrote, or ``None``."""
        return self._number

    def note_number(self, number: str | None) -> None:
        """Record the number this claim's heading wrote."""
        self._number = None if number is None else str(number)


class Artifact(BaseModel):
    """One concrete thing an analyst established, in the shape it has.

    A hash is a value; an import list is a table; a set of C2 endpoints is a
    table with two columns. The model carries both shapes rather than forcing
    one, because forcing one is how a table becomes a comma-joined string
    nobody can sort.

    ``kind`` groups artifacts across agents into a report section — ``hashes``,
    ``imports``, ``permissions``, ``iocs``, ``processes``, ``persistence``,
    ``endpoints``. It is a free string on purpose: an analyst that found
    something the vocabulary has no word for should say the word, not the
    nearest wrong one.
    """

    kind: str = Field(..., description="What this artifact is, e.g. 'imports' or 'iocs'.")
    label: str = Field("", description="Human name for this artifact.")
    value: str | None = Field(None, description="The value, when the artifact is a single fact.")
    columns: list[str] | None = Field(None, description="Column headings, when it is a table.")
    rows: list[list[str]] | None = Field(None, description="Rows, when it is a table.")
    evidence_ids: list[str] = Field(
        default_factory=list,
        description="Ledger entry ids this artifact was read from, e.g. ['ev_0007'].",
    )
    source: str = Field("", description="Which agent or tool established it.")


class Finding(BaseModel):
    """A conclusion an analyst reached, with what it was drawn from.

    Deliberately not a ``ClaimEvidence``: a claim is what the negotiation
    argues about and carries one prose evidence reference, while a finding is
    what the report prints and carries the ledger ids behind it plus the
    artifacts it established. The two channels coexist; neither replaces the
    other.
    """

    title: str = Field(..., description="One line naming the finding.")
    detail: str = Field("", description="What was observed, in the analyst's own words.")
    category: str = Field("", description="Free-form grouping, e.g. 'persistence'.")
    technique_ids: list[str] = Field(
        default_factory=list, description="MITRE ATT&CK technique ids, e.g. ['T1055']."
    )
    # ``None`` when the analyst put no number on the finding: a default of 0.0
    # would read downstream as a confidence of zero somebody stated.
    confidence: float | None = Field(
        None, ge=0.0, le=1.0, description="Analyst self-reported confidence, if stated."
    )
    evidence_ids: list[str] = Field(
        default_factory=list, description="Ledger entry ids supporting this finding."
    )
    artifacts: list[Artifact] = Field(
        default_factory=list, description="Artifacts established alongside it."
    )


# Why a question stays open, in the words an analyst picks from. A fixed set,
# so the report can group the run's unknowns by cause and a later run can be
# compared against this one; ``other`` keeps a cause the set has no word for,
# said in the question's ``detail``.
OpenQuestionReason = Literal[
    "no_capable_tool",
    "tool_failed",
    "obfuscated",
    "out_of_turns",
    "needs_sandbox_run",
    "other",
]
OPEN_QUESTION_REASONS: tuple[str, ...] = get_args(OpenQuestionReason)


class OpenQuestion(BaseModel):
    """One thing an analyst knows it did not establish, and what would answer it.

    Not a claim and not a finding: an open question names an unknown, and it
    is never read as an absence. "Whether the beacon interval is fixed" left
    open says nothing about whether the sample beacons. Nothing that reads
    claims, findings or artifacts reads it; the report prints it in its own
    section and the analysts' summaries carry it to whoever can answer it.
    """

    question: str = Field(..., min_length=1, description="The question left open, in one line.")
    why_open: OpenQuestionReason = Field(..., description="Why the analyst could not answer it.")
    detail: str = Field("", description="What the analyst tried or saw, in its own words.")
    would_answer: str = Field(
        "", description="What would answer it: a kind of tool, another agent, a run."
    )
    # The declared tool kind that would answer it (``core.tool_declarations``),
    # when the analyst names one: what the report's routing column reads.
    tool_kind: str = Field("", description="The kind of tool that would answer it, if named.")
    agent: str = Field("", description="The team agent that could answer it, if named.")
    evidence_ids: list[str] = Field(
        default_factory=list, description="Ledger entry ids the question rests on, if any."
    )
    # Which agent left it open, when it is not the agent whose ISR carries it:
    # a specialist's question handed to the lead that asked it
    # (``agents.delegation``). Empty for an agent's own question.
    source: str = Field("", description="The agent that left the question open, if not this one.")

    @model_validator(mode="before")
    @classmethod
    def _a_reason_outside_the_set_is_other(cls, data: Any) -> Any:
        """A ``why_open`` outside the set, or none, is ``other``, its word kept in ``detail``.

        The question is what matters; a cause written in a word of the model's
        own is kept, not a reason to lose the question.
        """
        if not isinstance(data, dict):
            return data
        said = data.get("why_open")
        if isinstance(said, str) and said in OPEN_QUESTION_REASONS:
            return data
        word = "" if said is None else " ".join(str(said).split())
        detail = " ".join(str(data.get("detail") or "").split())
        noted = f"why open, as written: {word}" if word else ""
        return {
            **data,
            "why_open": "other",
            "detail": "; ".join(part for part in (detail, noted) if part),
        }


def _one_line(value: Any) -> str:
    """``value`` with every run of whitespace one space: a model's text keeps no line of its own."""
    return " ".join(str(value or "").split())


def would_answer_text(question: OpenQuestion) -> str:
    """What would answer ``question``, in its own words, with the kind and agent it names."""
    named = ", ".join(
        part
        for part in (
            f"tool kind {_one_line(question.tool_kind)}" if question.tool_kind.strip() else "",
            f"agent {_one_line(question.agent)}" if question.agent.strip() else "",
        )
        if part
    )
    said = _one_line(question.would_answer)
    if not named:
        return said
    return f"{said} ({named})" if said else named


def open_question_line(question: OpenQuestion) -> str:
    """One open question as an ISR summary shows it to a model, on one line.

    Every field is the model's text with its whitespace collapsed, so nothing
    in a question can open a line the summary reads as its own (a claim, a
    convergence signal).
    """
    parts = [f"{_one_line(question.question)} | Why open: {question.why_open}"]
    if question.detail.strip():
        parts.append(f"Detail: {_one_line(question.detail)}")
    answer = would_answer_text(question)
    if answer:
        parts.append(f"Would answer it: {answer}")
    if question.evidence_ids:
        parts.append(f"Evidence: {_one_line(', '.join(question.evidence_ids))}")
    return " | ".join(parts)


def claim_summary_line(number: int, claim: ClaimEvidence) -> str:
    """One claim as an ISR summary shows it to a model (``AgentISR.to_text_summary``).

    The marker travels with the id rather than replacing it. The analyst was
    told and kept its answer; the judge is entitled to see both the answer and
    that it does not resolve.
    """
    tech = f" ({claim.technique_id})" if claim.technique_id else ""
    if claim.technique_id and not claim.technique_id_valid:
        tech = f" ({claim.technique_id} — {UNVERIFIED_TECHNIQUE_MARKER})"
    elif claim.technique_id and claim.kept_after_absence_question:
        tech = f" ({claim.technique_id} — {ABSENCE_TECHNIQUE_MARKER})"
    noted = f" {claim.heading_note}" if claim.heading_note else ""
    failed = f" ({FAILED_CALLS_MARKER})" if claim.cites_only_failed_calls else ""
    retried = (
        f" ({retry_added_marker(claim.added_by_retry_in_round)})"
        if claim.added_by_retry_in_round is not None
        else ""
    )
    return (
        f"Claim {number}{noted}: {claim.claim}{tech}"
        f" | Evidence: {claim.evidence_ref}{failed}{retried}"
        f" | Confidence: {claim.confidence:.2f}"
    )


class AgentISR(BaseModel):
    """Full Intermediate Structural Representation from one analyst agent.

    This replaces the raw `str` report in the negotiation loop. The agent
    must enumerate its claims and explicitly list any items from peer reports
    it still disputes after each revision round.
    """

    agent_id: str = Field(..., description="Registry name of the agent, e.g. 'static'.")
    domain: Literal["static", "dynamic", "network", "yara", "sigma"] | str = Field(
        ..., description="Analysis domain this agent covers."
    )
    claims: list[ClaimEvidence] = Field(
        default_factory=list,
        description="Ordered list of evidence-backed claims.",
    )
    dissent_items: list[str] = Field(
        default_factory=list,
        description=(
            "Claims from peer ISRs that this agent still disputes. "
            "An empty list signals active convergence (not passive silence). "
            "Round > 0 with empty dissent is treated as a convergence signal."
        ),
    )
    revision_round: int = Field(
        0, ge=0, description="Which negotiation round produced this ISR (0 = initial)."
    )
    # The optional structured channel (``agents.findings_block``). Empty for an
    # agent that wrote only prose, which is every agent that ignores the
    # channel — it adds to the ISR contract and replaces nothing in it.
    findings: list[Finding] = Field(
        default_factory=list,
        description="Structured conclusions this agent emitted, with their evidence ids.",
    )
    artifacts: list[Artifact] = Field(
        default_factory=list,
        description="Concrete artifacts this agent established, for the report's sections.",
    )
    # What the analyst knows it left unanswered (``OpenQuestion``), from the
    # same optional block. Left out of the serialised ISR when empty, so an
    # ISR stored before the channel existed reads and dumps the same.
    open_questions: list[OpenQuestion] = Field(
        default_factory=list,
        description="Questions this agent left open, why, and what would answer them.",
        exclude_if=lambda value: not value,
    )
    # Why this ISR looks the way it does, when the analyst knows something the
    # claim list cannot say. An analyst that ended its loop on an intention
    # sentence produced no claims *and* no report, and the two are different
    # findings: the first is an analyst with nothing to say, the second is a
    # model that never answered. Left unset on the ordinary path, where the
    # claim list speaks for itself.
    status: str | None = Field(
        default=None,
        description="Lifecycle status the analyst reports for itself, e.g. 'no_claims'.",
    )
    status_reason: str | None = Field(
        default=None, description="Why the analyst reports that status, in one sentence."
    )
    # What the parser could not read out of the answer this ISR was parsed
    # from, for the validation turn to ask about and the stage to keep. Not
    # fields: they describe one parse, not the analyst's answer, and they are
    # never serialised. ``unparsed_answer`` is the prose of an answer that
    # yielded no claim at all, kept as the analyst wrote it; the count is the
    # CLAIM blocks that stated no confidence, which are not claims — a number
    # nobody stated is not put on one.
    _unparsed_answer: str = PrivateAttr(default="")
    _blocks_without_confidence: int = PrivateAttr(default=0)
    # The CONFIDENCE values the parse found and could not read, one per block,
    # as written: those blocks stated a confidence, so they are asked about
    # with the value quoted rather than as blocks that stated none.
    _confidence_unreadable: list[str] = PrivateAttr(default_factory=list)
    # The answer this ISR was parsed from, as the model wrote it: its CLAIM
    # blocks and its findings block included. What the validation turn shows
    # the analyst as its own previous answer; a rendering of the parsed claims
    # in another shape is copied back in that shape, and the parser reads none
    # of it.
    _answer_text: str = PrivateAttr(default="")
    # The claims of that answer the consistency gate set aside, as written:
    # the answer is shown back whole, and the question says which of its
    # claims no longer stand.
    _gate_removed: list[str] = PrivateAttr(default_factory=list)
    # Why claims this answer began are not in its findings, as the reader
    # found it (``BaseAnalyst._claims_shortfall``), or ``""``. Kept with the
    # answer rather than the run, so the judge node states it only for an
    # answer in force: a retry or a later round that replaced this answer
    # carries its own.
    _claims_unread_reason: str = PrivateAttr(default="")
    # The claim headings this answer wrote under its DISPUTES section beside
    # its own claims read: a peer's claims quoted, or its own written in the
    # wrong place. The validation turn asks once which.
    _claims_under_disputes: int = PrivateAttr(default=0)
    # Whether this answer is the one the validation turn kept after asking
    # about those headings. Asked and kept, they are the analyst's answer; a
    # question never put leaves their status unknown, and the judge node
    # states them as a degradation reason (``nodes.claims_under_disputes_unasked``).
    _claims_under_disputes_asked: bool = PrivateAttr(default=False)
    # Whether the revision this ISR answers for wrote no claim and no
    # structured report itself, before any validation retry wrote claims for
    # it. Such a revision decided nothing about the claims in force: the
    # revision node keeps them and adds what the retry wrote beside them.
    _revision_wrote_no_claim: bool = PrivateAttr(default=False)

    # The report a revision's answer in force is read as, when the validation
    # turn changed the answer the revision wrote (``base_agent
    # .answer_in_force_text``), and the kept retry's own words when the answer
    # in force is a retry; both ``""`` when the written answer stands. The
    # revision node puts the report in the prompts and keeps the written
    # answer, and the retry's words, on the record.
    _report_in_force: str = PrivateAttr(default="")
    _retry_words: str = PrivateAttr(default="")
    # The claims summary the platform put at the head of this answer's report
    # (a first answer's report, a revision's answer in force), exactly as it
    # was rendered: the part a prompt may render again with marks set since.
    # ``""`` when the report is text the analyst wrote.
    _rendered_summary: str = PrivateAttr(default="")

    @property
    def rendered_summary(self) -> str:
        """The claims summary the platform put at the head of this answer's report, or ``""``."""
        return self._rendered_summary

    def note_rendered_summary(self, summary: str) -> None:
        """Record the claims summary the platform put at the head of this answer's report."""
        self._rendered_summary = str(summary or "")

    @property
    def report_in_force(self) -> str:
        """The report this answer in force is read as, or ``""`` when the written one stands."""
        return self._report_in_force

    @property
    def retry_words(self) -> str:
        """The kept validation retry's own words, or ``""`` when no retry is in force."""
        return self._retry_words

    def note_report_in_force(self, report: str, retry_words: str = "") -> None:
        """Record the report this answer in force is read as, and the kept retry's words."""
        self._report_in_force = str(report or "")
        self._retry_words = str(retry_words or "")

    @property
    def revision_wrote_no_claim(self) -> bool:
        """Whether the revision itself wrote no claim, whatever a retry wrote after it."""
        return self._revision_wrote_no_claim

    def note_revision_wrote_no_claim(self) -> None:
        """Record that the revision itself wrote no claim and no structured report."""
        self._revision_wrote_no_claim = True

    @property
    def unparsed_answer(self) -> str:
        """The prose of an answer that parsed into no claim, or ``""``."""
        return self._unparsed_answer

    @property
    def answer_text(self) -> str:
        """The answer this ISR was parsed from, as written, or ``""`` when it has none."""
        return self._answer_text

    def note_answer_text(self, text: str) -> None:
        """Record the answer this ISR was parsed from, as the model wrote it."""
        self._answer_text = str(text or "")

    @property
    def gate_removed(self) -> list[str]:
        """The claims of the written answer the consistency gate set aside."""
        return list(self._gate_removed)

    def note_gate_removed(self, claims: list[str]) -> None:
        """Record the claims of the written answer the consistency gate set aside."""
        self._gate_removed = [str(c) for c in claims]

    @property
    def claims_unread_reason(self) -> str:
        """Why claims this answer began are not in its findings, or ``""``."""
        return self._claims_unread_reason

    def note_claims_unread(self, reason: str) -> None:
        """Record why claims this answer began are not in its findings."""
        self._claims_unread_reason = str(reason or "")

    @property
    def claims_under_disputes(self) -> int:
        """How many claim headings stand under this answer's DISPUTES section, beside its own."""
        return self._claims_under_disputes

    def note_claims_under_disputes(self, count: int) -> None:
        """Record the claim headings under the DISPUTES section, beside the answer's own."""
        self._claims_under_disputes = max(0, int(count or 0))

    @property
    def claims_under_disputes_asked(self) -> bool:
        """Whether the analyst was asked about those headings and this answer kept them."""
        return self._claims_under_disputes_asked

    def note_claims_under_disputes_asked(self) -> None:
        """Record that the analyst was asked about those headings and kept them there."""
        self._claims_under_disputes_asked = True

    @property
    def blocks_without_confidence(self) -> int:
        """How many CLAIM blocks of the parsed answer stated no confidence."""
        return self._blocks_without_confidence

    @property
    def confidence_unreadable(self) -> list[str]:
        """The CONFIDENCE values of the parsed answer that could not be read, as written."""
        return list(self._confidence_unreadable)

    def note_parse(
        self,
        *,
        unparsed_answer: str = "",
        blocks_without_confidence: int = 0,
        confidence_unreadable: Any = (),
    ) -> None:
        """Record what the parse of this ISR's answer could not read."""
        self._unparsed_answer = str(unparsed_answer or "")
        self._blocks_without_confidence = max(0, int(blocks_without_confidence or 0))
        self._confidence_unreadable = [str(v) for v in (confidence_unreadable or ())]

    @property
    def mean_confidence(self) -> float:
        """Average confidence across all claims. Returns 0.0 if no claims."""
        if not self.claims:
            return 0.0
        return sum(c.confidence for c in self.claims) / len(self.claims)

    def to_text_summary(self) -> str:
        """Render this ISR as a concise human-readable text block.

        Used when the ISR must be passed to an LLM prompt as context.
        The format is compact to minimise token consumption.
        """
        lines: list[str] = [
            f"[{self.agent_id.upper()} ANALYST — round {self.revision_round}]",
            f"Domain: {self.domain} | Mean confidence: {self.mean_confidence:.2f}",
        ]

        for i, claim in enumerate(self.claims, 1):
            lines.append(f"  {claim_summary_line(i, claim)}")

        # An unknown the analyst names, for a peer, the mediator, the judge
        # or the lead that asked to route: never an absence, and absent from
        # the summary when the analyst named none.
        if self.open_questions:
            lines.append("  Open questions (unknowns, not absences):")
            for question in self.open_questions:
                lines.append(f"    - {open_question_line(question)}")

        if self.dissent_items:
            lines.append("  Disputes:")
            for item in self.dissent_items:
                lines.append(f"    - {item}")
        else:
            if self.revision_round > 0:
                lines.append("  [CONVERGENCE SIGNAL: no remaining disputes]")

        return "\n".join(lines)

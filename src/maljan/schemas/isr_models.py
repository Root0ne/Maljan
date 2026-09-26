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

from typing import Any, Literal

from pydantic import BaseModel, Field, PrivateAttr

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
# The note on a technique the judge named in its bundle and no analyst claimed.
# The rule it is published by: a technique the judge states is the judge's own
# claim, asked the catalogue and platform questions every claim is asked, and
# published with the judge as its source and the judge's own number.
JUDGE_ONLY_TECHNIQUE_MARKER = (
    "stated by the judge and claimed by no analyst; a technique the judge states is "
    "published as its own claim"
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
    # The claim's TECHNIQUE line as written, when it is more than one id or
    # NONE: a qualifier, a negation, several ids. No id is read from it —
    # "T1027.002 not supported" is not a claim of T1027.002 — and the
    # validation turn asks the analyst for one id per claim
    # (``pipeline.validation.TECHNIQUE_LINE_UNREAD_CODE``).
    technique_line: str | None = Field(
        default=None,
        description="The claim's TECHNIQUE line as written, when no single id could be read.",
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
    # What the ATT&CK index made of the claim text against the id the analyst
    # chose: the id's own gate score and the index's top candidates with
    # theirs. Recorded by ``pipeline.validation`` when the index was warm, so
    # the judge and the report can see the ranking beside the choice. The id
    # itself is never replaced by any of the candidates.
    alignment: dict[str, Any] | None = Field(
        default=None,
        description="The index's gate score for the claimed id and its top candidates.",
    )


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
            # The marker travels with the id rather than replacing it. The
            # analyst was told and kept its answer; the judge is entitled to
            # see both the answer and that it does not resolve.
            tech = f" ({claim.technique_id})" if claim.technique_id else ""
            if claim.technique_id and not claim.technique_id_valid:
                tech = f" ({claim.technique_id} — {UNVERIFIED_TECHNIQUE_MARKER})"
            elif claim.technique_id and claim.kept_after_absence_question:
                tech = f" ({claim.technique_id} — {ABSENCE_TECHNIQUE_MARKER})"
            lines.append(
                f"  Claim {i}: {claim.claim}{tech}"
                f" | Evidence: {claim.evidence_ref}"
                f" | Confidence: {claim.confidence:.2f}"
            )

        if self.dissent_items:
            lines.append("  Disputes:")
            for item in self.dissent_items:
                lines.append(f"    - {item}")
        else:
            if self.revision_round > 0:
                lines.append("  [CONVERGENCE SIGNAL: no remaining disputes]")

        return "\n".join(lines)

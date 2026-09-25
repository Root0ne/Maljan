"""What a model got wrong, said back to the model, once.

Every layer this module replaces used to do the same thing silently: read an
agent's answer, decide it was wrong, and write a different answer in its place.
The claim in the report was then nobody's — not the analyst's, because it had
been overwritten, and not the pipeline's, because the pipeline never said so.

Here the finding is a :class:`Violation` instead of an edit. The producer is
told what is wrong in the same conversation that produced the answer and gets
one more turn to fix it. What is still wrong after that turn stays wrong, on
the record, under ``run_summary.validation.unresolved`` — an unfixed claim that
says it is unfixed is worth more than a corrected claim nobody can attribute.

This module and ``schemas``/``tools`` are the only places allowed to write a
claim's ``technique_id`` or ``confidence``, or a report's ``severity``,
``malware_category`` or ``family``; ``tests/unit/test_no_silent_overrides.py``
enforces that. Even here the writes are narrow: the technique-id validity flag
and the drop of an indicator that named a value no tool ever saw.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import Any, get_args, get_origin

from pydantic import ValidationError

# The row helpers live with the shape (``analysis.corroboration``) and are
# re-exported here, where every reader of a run's validation looks for them.
from maljan.agents.run_evidence_corpus import CorpusState, both_searched
from maljan.analysis.corroboration import corroboration_row as corroboration_row
from maljan.analysis.corroboration import corroboration_sources as corroboration_sources
from maljan.analysis.technique_ids import MITRE_ATTACK_SOURCES, TECHNIQUE_ID_EXACT_RE
from maljan.core.logger import logger
from maljan.pipeline.events import (
    VALIDATION_RESOLVED,
    VALIDATION_RETRIED,
    VALIDATION_SURVIVED,
    EventSink,
    emit_validation_feedback,
    safe_finding_value,
)
from maljan.schemas.evidence import entry_ids_in
from maljan.schemas.judgement import BENIGN_VERDICT, SEVERITY_RATINGS, VERDICT_VALUES
from maljan.schemas.stix_pattern import read_comparisons
from maljan.utils.written_forms import written_forms

# How many alternatives a suggestion list carries. Three is what fits in one
# line of feedback; a longer list reads as a menu and the model picks from the
# middle of it.
MAX_SUGGESTIONS = 3

# How far a candidate has to beat the claimed id's own score before the gate
# says anything. The index scores a *correct* id near zero often enough that a
# bare threshold questioned almost every claim: 81 of the 92 feedback rows in
# one audited run, 33 of 33 in another. The default is the measured one — see
# ``tests/fixtures/attck_alignment_recorded.json`` and docs/architecture.md.
ALIGNMENT_MARGIN = 0.20

# How many schema complaints one feedback turn carries. A model that answered
# with the wrong shape produces one error per field, and a wall of them reads
# as noise rather than as a correction.
MAX_SCHEMA_VIOLATIONS = 6


# The sentence the retry turn opens with. A constant because two call sites
# send it and a test reads it.
FEEDBACK_PREAMBLE = "Your previous answer had these problems:"
FEEDBACK_CLOSING = "Fix them and answer again in the same format."
# The analyst's closing names the format its parser reads. "The same format"
# was read as the shape of the previous answer as it was shown back, and an
# answer written in any shape but CLAIM blocks parses into no claim at all.
ANALYST_FEEDBACK_CLOSING = (
    "Fix them and write your whole answer again in the format it is read in: every claim "
    "as its own block of CLAIM:, EVIDENCE:, CONFIDENCE: and TECHNIQUE: lines, the blocks "
    "separated by a line of three dashes (---), then your fenced maljan-findings block if "
    "your answer had one. Only CLAIM blocks are read as claims: a claim written another "
    "way, or left out, is not in the answer."
)


# What joins the agents of a route inside one serialised row. A unit separator
# rather than a comma: an agent key is an operator's word and a comma in one
# would split a name in half on the way back.
ROUTE_SEPARATOR = "\x1f"


@dataclass(frozen=True)
class Violation:
    """One thing wrong with an answer, in the words the producer will read."""

    code: str
    message: str
    path: str = ""
    # A finding the producer is shown and asked about, that nothing acts on by
    # removing something. It exists for one situation: the check could not
    # search this run's whole record — the grounding corpus hit its ceiling,
    # or there is no corpus and the stored entries it fell back to had been
    # blanked by the evidence byte budget — so "this value is in no tool
    # output" is not a statement the platform is entitled to make. The row
    # says what was searched and what was not; the object stays.
    advisory: bool = False
    # The agents this row was handed through, outermost first, and the
    # finding's own words. Two values rather than one string: a hand-over adds
    # a name in front of the sentence and the whole is bounded, and a bound
    # applied to one string has to work out where the route ends — which it
    # cannot do, and which cost a sentence opening ``T1055: `` its identifier.
    # Carried apart, the bound can only ever shorten the route.
    route: tuple[str, ...] = ()
    sentence: str = ""
    # The sentences of the checked text this row is about, as written, for a
    # renderer to mark where they stand. Never shown to the producer and never
    # stored on the channel: the text they come from is.
    quoted: tuple[str, ...] = ()
    # Whether the producer was shown this finding and asked to fix it. False
    # for one it never saw: raised first by the answer to its only retry, or
    # found where no turn was left to ask on. A row that says the producer
    # "kept" something when asked is only true of a row that was asked.
    asked: bool = True
    # What the finding is about, by a fact that survives the retry: the
    # technique a credit names, the malware object's name. Two answers of one
    # judge number their objects afresh, and an answer to a credit question
    # renames the credited source — so "was this asked" is keyed on this where
    # a check sets it, never on the words of the message.
    subject: str = ""

    def __post_init__(self) -> None:
        # A row written by a validator has no route, and its message is its
        # sentence. Everything downstream may then read either.
        if not self.sentence:
            object.__setattr__(self, "sentence", self.message)

    def to_dict(self) -> dict[str, str]:
        return {
            "code": self.code,
            "message": self.message,
            "path": self.path,
            # Strings, because every other value in the row is one and the
            # channel that carries it is ``dict[str, list[dict[str, str]]]``.
            "advisory": "true" if self.advisory else "",
            "sentence": self.sentence,
            "route": ROUTE_SEPARATOR.join(self.route),
            **({} if self.asked else {"asked": "false"}),
            **({"subject": self.subject} if self.subject else {}),
        }


@dataclass
class ValidationTally:
    """How much correction one producer needed, by code.

    ``run_summary.validation.by_code`` used to be built from the unresolved
    list alone, so a run whose judge was corrected once and answered properly
    the second time reported ``retries: 1`` beside an empty ``by_code`` and
    nothing said what the retry had been about. Every violation a producer is
    *shown* is counted here, and so is every one it never fixed, which is the
    only reading under which the two numbers agree.
    """

    retries: int = 0
    by_code: dict[str, int] = field(default_factory=dict)
    # What this producer was told and did not fix, with the producer's name, in
    # the shape ``run_summary.validation.unresolved`` carries. The report
    # stage's two rounds run after the summary is built and have nowhere else
    # to put theirs.
    unresolved: list[dict[str, str]] = field(default_factory=list)

    def count(self, violations: Sequence[Violation]) -> None:
        """Count a set of violations. The shape ``on_feedback`` is called with."""
        for violation in violations:
            self.by_code[violation.code] = self.by_code.get(violation.code, 0) + 1

    def record_unresolved(
        self, producer: str, violations: Sequence[Violation], *, asked: bool = True
    ) -> None:
        """Keep what survived the retry, as a row naming who was told.

        ``asked=False`` is a finding the producer was never shown — no turn to
        ask on, or first raised by the answer to its only retry — and the row
        says so (``"asked": "false"``), so a reader counting rows can tell it
        from one the producer was told and left.

        ``advisory`` travels with it. Rebuilt without the flag, a row the
        platform explicitly declined to act on was stored, printed and drawn as
        an ordinary unfixed finding, and an operator had to read inside the
        message to learn that nothing had been dropped for it.
        """
        self.unresolved.extend(
            {
                "agent": producer,
                "code": v.code,
                "message": v.message,
                **({"advisory": "true"} if v.advisory else {}),
                **({} if asked and v.asked else {"asked": "false"}),
                **({"subject": v.subject} if v.subject else {}),
            }
            for v in violations
        )

    def merge(self, other: ValidationTally) -> None:
        self.retries += other.retries
        for code, count in other.by_code.items():
            self.by_code[code] = self.by_code.get(code, 0) + count
        self.unresolved.extend(other.unresolved)

    def to_dict(self) -> dict[str, Any]:
        """The tally as the run summary carries it.

        ``unresolved`` is part of it whenever there is any: a serialisation
        that dropped the rows would leave a reader the counts and none of the
        claims they were counted for. An empty list is left out, so a run that
        over-claimed nothing does not carry an empty key saying so.
        """
        out: dict[str, Any] = {
            "retries": int(self.retries),
            "by_code": dict(sorted(self.by_code.items())),
        }
        if self.unresolved:
            out["unresolved"] = [dict(row) for row in self.unresolved]
        return out


# A validator reads a produced object and says what is wrong with it. It never
# changes the object: the whole point of the type is that the caller decides
# what to do with the answer.
Validator = Callable[[Any], list[Violation]]


# ---------------------------------------------------------------------------
# Feedback
# ---------------------------------------------------------------------------


def feedback_text(violations: Sequence[Violation], *, closing: str = FEEDBACK_CLOSING) -> str:
    """The retry turn's text for a set of violations, ending on ``closing``."""
    lines = [FEEDBACK_PREAMBLE]
    for violation in violations:
        where = f" ({violation.path})" if violation.path else ""
        lines.append(f"- [{violation.code}]{where} {violation.message}")
    lines.append(closing)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Analyst ISRs
# ---------------------------------------------------------------------------


UNGROUNDED_TECHNIQUE_CODE = "isr.ungrounded_technique"

# What the parse of an analyst's answer could not read. Neither is corrected:
# prose is not cut into claims and a block with no confidence is not given
# one. Each is asked about once in the analyst's own validation turn, and what
# is still unread after it is recorded.
UNPARSED_ANSWER_CODE = "isr.unparsed_answer"
CLAIM_WITHOUT_CONFIDENCE_CODE = "isr.claim_without_confidence"

_UNPARSED_ANSWER_MESSAGE = (
    "Your answer has no CLAIM block that can be read, so it carries no claim and "
    "is kept as prose. Restate each finding as a block, with the confidence you "
    "hold it at:\n"
    "CLAIM: <claim text>\n"
    "EVIDENCE: <artifact reference, naming the tool result you read it from, "
    "for example [ev_0002]>\n"
    "CONFIDENCE: <0.0-1.0>\n"
    "TECHNIQUE: <T-ID or NONE>\n"
    "---\n"
    "A finding you cannot put a confidence on stays in your prose."
)


def parse_violations(isr: Any) -> list[Violation]:
    """What the parse of one analyst answer could not read, as questions to it.

    Two, each asked once: an answer with no CLAIM block that parses, which is
    otherwise the analyst's prose and nothing more, and CLAIM blocks that state
    no confidence, which are not claims because the confidence on a claim is
    the analyst's own statement. An ISR built without a parse says nothing.
    """
    found: list[Violation] = []
    if not getattr(isr, "claims", None) and str(getattr(isr, "unparsed_answer", "") or ""):
        found.append(Violation(code=UNPARSED_ANSWER_CODE, message=_UNPARSED_ANSWER_MESSAGE))
    try:
        declined = int(getattr(isr, "blocks_without_confidence", 0) or 0)
    except (TypeError, ValueError):
        declined = 0
    if declined:
        found.append(
            Violation(
                code=CLAIM_WITHOUT_CONFIDENCE_CODE,
                message=(
                    f"{declined} CLAIM block(s) state no CONFIDENCE that reads as a number "
                    "between 0.0 and 1.0, so they are not claims. Give each the confidence "
                    "you hold it at, or leave it out."
                ),
            )
        )
    return found


def _techniques_cited_by_findings(isr: Any, citable: set[str]) -> set[str]:
    """The techniques the findings block already cites one of this run's entries for.

    The structured channel is where the analyst is asked for ids by machine,
    and an analyst that used it has answered the question the claim line asks
    in prose. Asking it twice for one technique is a feedback turn spent on
    bookkeeping.
    """
    cited: set[str] = set()
    for finding in getattr(isr, "findings", None) or []:
        ids = " ".join(str(value) for value in (getattr(finding, "evidence_ids", None) or []))
        if not entry_ids_in(ids) & citable:
            continue
        for technique in getattr(finding, "technique_ids", None) or []:
            text = str(technique).strip().upper()
            if text:
                cited.add(text)
    return cited


def _cites_a_ledger_entry(claim: Any, cited_by_findings: set[str], citable: set[str]) -> bool:
    """Whether a claim points at something the run actually recorded.

    Two ways, and only two. The evidence line is where the claim format asks
    for the id, and the findings block is where the same analyst may already
    have cited one for this technique. The claim's own prose is deliberately
    not searched: "as ev_0001 does not show, this may be injection" is not a
    citation, and reading it as one is how a validator stops validating.

    The id has to be one this run issued. The feedback names three real ones,
    so the shape of an id is no proof of anything, and an ``ev_9999`` the run
    never recorded is a citation of nothing.
    """
    if entry_ids_in(str(getattr(claim, "evidence_ref", "") or "")) & citable:
        return True
    technique = str(getattr(claim, "technique_id", "") or "").strip().upper()
    return bool(technique and technique in cited_by_findings)


def validate_isr(
    isr: Any,
    *,
    attck: Any = None,
    ledger_ids: Sequence[str] | None = None,
    sample: Mapping[str, Any] | None = None,
    alignment: Any = None,
    alignment_threshold: float = 0.05,
    alignment_margin: float = ALIGNMENT_MARGIN,
    weak_alignment_challenges: bool = False,
) -> list[Violation]:
    """What is wrong with one analyst's structured answer.

    ``attck`` is the knowledge module the technique ids are checked against —
    ``maljan.tools.knowledge`` in production, a stub in a test that must not
    load a fifty-megabyte bundle. Passing ``None`` skips the catalogue check
    rather than failing it: a box that cannot read ATT&CK has a thinner report,
    not a run full of invented violations.

    ``ledger_ids`` are the entries this analyst may cite: what its own tool
    calls produced in this run, and the triage pack's entries, which every
    agent is shown. They decide one thing: a technique claim that cites none
    of them is asked for one. An analyst with nothing citable at all — a
    measurement profile, which has no tools and no pack — is exempt, because
    it has nothing it could cite.

    ``sample`` carries the routed ``platform`` and ``file_type``; a known
    technique whose catalogue domain or platforms cannot apply to them is
    ``attck.platform_mismatch``. ``alignment`` is the gate — a callable of
    ``(claim_text, technique_id)`` answering the index's gate score and
    candidates, or ``None`` when the index is cold or the gate is off. The
    ranking is narrowed to the sample's own domain and platforms and written on
    the claim whatever it says; it becomes ``attck.weak_alignment`` only with
    ``weak_alignment_challenges`` on, and then only for a claimed id that scores
    under ``alignment_threshold`` while an in-scope candidate from another
    tactic beats it by ``alignment_margin``. No id is ever replaced by a
    candidate.
    """
    citable = [str(i) for i in (ledger_ids or []) if str(i).strip()]
    known = {i.strip().lower() for i in citable}
    cited_by_findings = _techniques_cited_by_findings(isr, known)
    violations: list[Violation] = []
    claims = list(getattr(isr, "claims", None) or [])
    agent = str(getattr(isr, "agent_id", "") or "")
    scope = expected_technique_scope(sample)

    for index, claim in enumerate(claims):
        path = f"{agent}.claims[{index}]" if agent else f"claims[{index}]"

        confidence: Any = getattr(claim, "confidence", None)
        try:
            numeric: float | None = float(confidence)
        except (TypeError, ValueError):
            numeric = None
        if numeric is None or not (0.0 <= numeric <= 1.0):
            violations.append(
                Violation(
                    code="isr.confidence_range",
                    message=(
                        f"CONFIDENCE is {safe_finding_value(confidence)!r}; it must be a number "
                        "between 0.0 and 1.0."
                    ),
                    path=path,
                )
            )

        evidence = str(getattr(claim, "evidence_ref", "") or "").strip()
        if not evidence:
            violations.append(
                Violation(
                    code="isr.empty_evidence",
                    message=(
                        "the claim cites no evidence; give the concrete artifact it "
                        "rests on, or drop the claim."
                    ),
                    path=path,
                )
            )

        tid = str(getattr(claim, "technique_id", "") or "").strip().upper()
        # A technique with nothing behind it. A live run on a signed PuTTY
        # produced sixteen of these in one ISR — "may exhibit process injection
        # (T1055) | Evidence: no specific imports were provided; this claim is
        # speculative" — and the judge read them as sixteen techniques and said
        # Malware. The analyst is asked to cite the entry it read the technique
        # from or to drop it; nothing here removes the claim or the id.
        if tid and citable and not _cites_a_ledger_entry(claim, cited_by_findings, known):
            shown = ", ".join(citable[:3])
            violations.append(
                Violation(
                    code=UNGROUNDED_TECHNIQUE_CODE,
                    message=(
                        f"TECHNIQUE {safe_finding_value(tid)} cites no evidence id from this "
                        f"run. Name the ledger entry it was read from, for example {shown}, "
                        "or drop the "
                        "technique: a technique nothing in the run establishes is read "
                        "downstream as a finding."
                    ),
                    path=path,
                )
            )
        if not tid:
            continue
        if attck is None:
            absence = absence_claim_violation(claim, tid, None, path=path)
            if absence is not None:
                violations.append(absence)
            continue
        if not _technique_is_known(tid, attck):
            suggestions = _suggest_techniques(str(getattr(claim, "claim", "") or ""), attck)
            hint = (
                f" The closest real techniques are {', '.join(suggestions)}." if suggestions else ""
            )
            violations.append(
                Violation(
                    code="attck.unknown_id",
                    message=(
                        f"TECHNIQUE {safe_finding_value(tid)} is not in the MITRE ATT&CK catalogue"
                        f"{_retired_note(tid, attck)}.{hint} "
                        "Use one of them, or omit the technique id."
                    ),
                    path=path,
                )
            )
            continue
        # A claim that says the behaviour is absent asserts no technique, and
        # that is the one question its id is asked: where the id sits in the
        # catalogue is beside the point of a claim that says it is not there.
        # The index's ranking is still written on the claim, as on every claim.
        absence = absence_claim_violation(claim, tid, attck, path=path)
        if absence is not None:
            violations.append(absence)
        else:
            mismatch = platform_mismatch_message(tid, attck, scope)
            if mismatch:
                violations.append(
                    Violation(code=PLATFORM_MISMATCH_CODE, message=mismatch, path=path)
                )
            else:
                # A claim that names the behaviour to say it is absent is asked
                # that question, and an id the sample's platform cannot host is
                # asked about the platform; one whose sentence never names its
                # technique is asked this one. The weak-alignment challenge,
                # when it is on, may still be asked of the same claim.
                undescribed = claim_does_not_describe_violation(claim, tid, attck, path=path)
                if undescribed is not None:
                    violations.append(undescribed)
        weak = _weak_alignment(
            claim,
            tid,
            alignment,
            alignment_threshold,
            attck=attck,
            scope=scope,
            margin=alignment_margin,
            challenge=weak_alignment_challenges and absence is None,
        )
        if weak:
            violations.append(Violation(code=WEAK_ALIGNMENT_CODE, message=weak, path=path))

    return violations


# ---------------------------------------------------------------------------
# A claim that states the absence of a behaviour
# ---------------------------------------------------------------------------

ABSENCE_CLAIM_CODE = "attck.absence_claim"

# The spellings of a tactic a claim may use. The catalogue gives the current
# name; ATT&CK 19 split Defense Evasion into Stealth and Defense Impairment,
# and a claim written in the older name is about the same tactic.
_TACTIC_SPELLINGS: dict[str, tuple[str, ...]] = {
    "stealth": ("stealth", "defense evasion", "defence evasion"),
    "defense-impairment": ("defense impairment", "defense evasion", "defence evasion"),
}


def _phrase(words: str) -> str:
    """``words`` as a pattern: whole words, any run of spaces or hyphens between them."""
    parts = [re.escape(word) for word in words.split() if word]
    return r"\b" + r"[\s-]+".join(parts) + r"\b" if parts else ""


def behaviour_pattern(technique_id: str, attck: Any = None) -> re.Pattern[str] | None:
    """The words a claim names a technique's behaviour with, or ``None`` when it has none.

    Three sources, none of them written for a sample: the capability terms the
    report's prose is checked against that list the technique, and — where the
    catalogue can be read — the technique's own name and the names of its
    tactics. A tactic name alone is an ordinary word ("execution",
    "collection", "discovery", "impact"), so it names the behaviour only as a
    category of mechanism: the tactic followed by a word such as "mechanisms"
    or "techniques" ("discovery mechanisms").
    """
    base = _base_technique(technique_id)
    parts = [
        pattern for _label, pattern, techniques, _keys in CAPABILITY_TERMS if base in techniques
    ]
    if attck is not None:
        answer = _catalogue_answer(str(technique_id), attck, "attck_lookup")
        name = _phrase(str(answer.get("name") or ""))
        if name:
            parts.append(name)
        for tactic in answer.get("tactics") or []:
            slug = str(tactic).strip().lower()
            for spelling in _TACTIC_SPELLINGS.get(slug, (slug.replace("-", " "),)):
                phrase = _phrase(spelling)
                if phrase:
                    parts.append(phrase + _CATEGORY_NOUN)
    if not parts:
        return None
    return re.compile("|".join(f"(?:{part})" for part in parts), re.IGNORECASE)


# What a tactic name must be followed by to name a category of behaviour.
_CATEGORY_NOUN = (
    r"\s+(?:mechanisms?|techniques?|capabilit(?:y|ies)|behaviou?rs?|activit(?:y|ies)"
    r"|functionality|methods?|patterns?)\b"
)

# Between a negation and the behaviour it is read to govern, what makes the
# behaviour something the sentence asserts after all: a comma (a new clause,
# "Without encryption, the sample exfiltrates data"; a comma splice), or a
# coordinator that joins a second statement ("No persistence exists and
# process injection is used", "lacks persistence and instead injects").
_ASSERTION_BETWEEN_RE = re.compile(
    r",|\b(?:and|instead|only|but|yet|so|then|rather|while)\b", re.IGNORECASE
)
# A cue that opens a phrase asserting the verb after it: "no longer checks",
# "not merely reads", "never stops beaconing", "not just", "not only".
_CUE_THAT_ASSERTS_RE = re.compile(
    r"^\W*(?:longer|merely|only|just|simply|stops?|ceases?|fails?\s+to\s+stop|end)\b",
    re.IGNORECASE,
)
# A negated verb of need: "does not require administrator rights for
# persistence" says what the behaviour does without, and claims the behaviour.
# The cue negates the need, not the purpose it names.
_NEED_VERB_RE = re.compile(r"^\s+(?:require|need|depend|rely)\w*\b", re.IGNORECASE)


def _governed_absence(text: str, start: int) -> bool:
    """Whether a negation in the mention's own clause governs it, nothing asserting between.

    The strict reading the absence question needs. The capability check errs
    toward reading a negation, because its mistake costs a feedback turn; here a
    mistake asks an analyst to reconsider a positive claim, so only a cue that
    stands directly over the mention counts — with no comma and no coordinator
    between them, and not a cue that opens an assertion of its own ("no
    longer", "never stops").
    """
    window = text[max(0, start - _NEGATION_WINDOW) : start]
    breaks = list(_CLAUSE_BREAK_RE.finditer(window))
    if breaks:
        window = window[breaks[-1].end() :]
    lowered = window.lower()
    for cue in _NEGATION_RE.finditer(window):
        if lowered.startswith(_NOT_A_NEGATION, cue.start()):
            continue
        after = window[cue.end() :]
        if _CUE_THAT_ASSERTS_RE.match(after) or _NEED_VERB_RE.match(after):
            continue
        if _ASSERTION_BETWEEN_RE.search(after) or _reach_ends(after):
            continue
        return True
    return False


# A negated noun list: items joined by commas and a final "or"/"and", ending at
# the list's head noun — "does not contain persistence, lateral movement, or
# exfiltration mechanisms". Determiners and hedges may open it. Each item is up
# to four words, so a list never swallows a clause that has its own verb and
# object before any head noun.
_LIST_ITEM = r"[A-Za-z][\w-]*(?:\s+[A-Za-z(][\w()-]*){0,3}"
_NEGATED_NOUN_LIST_RE = re.compile(
    r"^\s*(?:(?:any|obvious|apparent|clear|signs?\s+of|evidence\s+of|indications?\s+of)\s+)*"
    rf"(?P<items>{_LIST_ITEM}(?:\s*,\s*{_LIST_ITEM})*\s*,?\s+(?:or|and)\s+{_LIST_ITEM})"
    r"\s+(?:mechanisms?|techniques?|capabilit(?:y|ies)|behaviou?rs?|activit(?:y|ies)"
    r"|functionality|methods?|patterns?)\b",
    re.IGNORECASE,
)


def _absent_by_its_own_statement(text: str, start: int, end: int) -> bool:
    """The readings of absence that do not rest on a cue next to the mention.

    The mention is in the subject of "is absent", "is not present" or "was not
    observed" — opening its clause, or ending the subject's noun phrase ("the
    specific APIs required for persistence are absent"); it is an item of a
    noun list a cue in its own clause negates, the list ending at its head noun
    ("does not contain persistence, lateral movement, or exfiltration
    mechanisms"); or it ends the object of a negated verb ("does not import the
    registry APIs required for persistence"). The same cue words and clause
    breaks as the capability check's reader, and a cue that opens an assertion
    ("no longer") negates no list and no object. One reading, asked by the
    absence question and by the capability check alike.
    """
    if _subject_is_absent(text, start, end):
        return True
    if _in_a_negated_object(text, start):
        return True
    head = text[:start]
    breaks = list(_CLAUSE_BREAK_RE.finditer(head))
    clause_start = breaks[-1].end() if breaks else 0
    tail_break = _CLAUSE_BREAK_RE.search(text, end)
    clause = text[clause_start : tail_break.start() if tail_break else len(text)]
    at = start - clause_start
    lowered = clause.lower()
    for cue in _NEGATION_RE.finditer(clause[:at]):
        if lowered.startswith(_NOT_A_NEGATION, cue.start()):
            continue
        rest = clause[cue.end() :]
        if _CUE_THAT_ASSERTS_RE.match(rest):
            continue
        listed = _NEGATED_NOUN_LIST_RE.match(rest)
        if listed and cue.end() + listed.start("items") <= at < cue.end() + listed.end("items"):
            return True
    return False


# What stands right before a mention that ends a noun phrase rather than
# opening a clause: a preposition attaching it to the noun before it, a
# determiner or "common"/"typical" allowed ("the APIs required for
# persistence", "strings associated with common persistence locations").
_NOUN_COMPLEMENT_BEFORE_RE = re.compile(
    r"\b(?:for|of|to|with)\s+(?:(?:any|the|its|their|common|typical|such)\s+)?$",
    re.IGNORECASE,
)


def _subject_is_absent(text: str, start: int, end: int) -> bool:
    """Whether the mention is in the subject of "is absent" and its like.

    The mention is followed by the absence predicate (a category noun may stand
    between them) and either opens its clause or ends the subject's noun
    phrase, attached by a preposition to the noun before it.
    """
    if not _SUBJECT_ABSENT_RE.match(text[end:]):
        return False
    return _starts_its_clause(text, start) or bool(
        _NOUN_COMPLEMENT_BEFORE_RE.search(text[max(0, start - _NEGATION_WINDOW) : start])
    )


# A negated verb: "does not import", "did not contain", "never calls".
_NEGATED_VERB_RE = re.compile(
    r"\b(?:does|do|did|could|can|will|would|should)\s+not\b"
    r"|\b(?:doesn't|don't|didn't|cannot|can't|won't|never)\b",
    re.IGNORECASE,
)
# The verb and its object up to the mention: a few words and then the
# preposition that attaches the mention to the object's head noun.
_NEGATED_OBJECT_RE = re.compile(
    r"^\s+[A-Za-z]+\s+(?:[\w./()-]+\s+){0,6}?"
    r"(?:(?:required|needed|necessary|used|associated|related|linked|typical|indicative"
    r"|specific)\s+)?(?:for|of|to|with)\s+(?:(?:any|the|its|their|common|typical|such)\s+)?$",
    re.IGNORECASE,
)


def _in_a_negated_object(text: str, start: int) -> bool:
    """Whether the mention ends the object of a negated verb in its own clause.

    "It does not import the registry APIs required for persistence" names
    persistence to say what the sample lacks. The object runs from the verb to
    the mention with no comma, no coordinator, and nothing that ends the
    negation's reach between them, and the mention is attached to the object's
    head noun by a preposition; "does not hide its use of injection" is read as
    absence too, which costs a flag, never a withheld claim.
    """
    head = text[:start]
    breaks = list(_CLAUSE_BREAK_RE.finditer(head))
    clause = head[breaks[-1].end() :] if breaks else head
    cues = list(_NEGATED_VERB_RE.finditer(clause))
    if not cues:
        return False
    after = clause[cues[-1].end() :]
    if _CUE_THAT_ASSERTS_RE.match(after) or _NEED_VERB_RE.match(after):
        return False
    if "," in after or _ASSERTION_BETWEEN_RE.search(after) or _reach_ends(after):
        return False
    return bool(_NEGATED_OBJECT_RE.match(after))


def states_absence(text: str, pattern: re.Pattern[str] | None) -> bool:
    """Whether ``text`` names the behaviour only to say it is absent.

    The capability check's own reader (:func:`_is_negated`), asked of every
    place the behaviour is named, and held to a stricter reading of which cue
    governs the mention (:func:`_governed_absence`). A mention both find
    negated is a statement of absence. A later mention in the same phrase —
    nothing between them that ends a clause, a negation's reach, or joins a
    second statement — is read with the negation that governs the first: "does
    not contain any command and control (C2) patterns" names the behaviour
    twice in one negated phrase. Any other mention is a claim that the
    behaviour is there, and one is enough. A text that never names the
    behaviour states nothing about it. The reading decides only whether the
    analyst is asked (``ABSENCE_CLAIM_CODE``); what the analyst answers stands.
    """
    if not text or pattern is None:
        return False
    matches = list(pattern.finditer(text))
    if not matches:
        return False
    negated_to: int | None = None
    for match in matches:
        if (
            _is_negated(text, match.start(), match.end()) and _governed_absence(text, match.start())
        ) or _absent_by_its_own_statement(text, match.start(), match.end()):
            negated_to = match.end()
            continue
        if negated_to is not None:
            between = text[negated_to : match.start()]
            if (
                not _CLAUSE_BREAK_RE.search(between)
                and not _reach_ends(between)
                and not _ASSERTION_BETWEEN_RE.search(between)
            ):
                negated_to = match.end()
                continue
        return False
    return True


def absence_claim_violation(
    claim: Any, technique_id: str, attck: Any = None, *, path: str = ""
) -> Violation | None:
    """The question for a claim that states a behaviour is absent and carries a technique id.

    A technique id on a claim is read everywhere downstream as something the
    sample does: a benign control run published thirteen techniques from claims
    such as "does not contain any obvious persistence mechanisms". The analyst
    is asked once; the claim and its id are never edited. An analyst that drops
    the id has removed it; an id kept after the question is published as
    usual, and the claim is noted (:func:`mark_invalid_technique_ids`) so the
    report and the judge say the claim reads as absence and the analyst kept
    the technique when asked. The platform withholds nothing on this reading.
    """
    text = str(getattr(claim, "claim", "") or "")
    if not states_absence(text, behaviour_pattern(technique_id, attck)):
        return None
    tid = safe_finding_value(technique_id)
    return Violation(
        code=ABSENCE_CLAIM_CODE,
        message=(
            f"CLAIM {safe_finding_value(text)!r} reads as saying the behaviour is absent, "
            f"and carries TECHNIQUE {tid}. A technique on a claim is read as something the "
            f"sample does, so {tid} is published as a finding of this run. If the behaviour "
            "is absent, write TECHNIQUE: NONE on this claim; if the sample does do it, keep "
            "the technique and say what the sample does."
        ),
        path=path,
    )


CLAIM_DOES_NOT_DESCRIBE_CODE = "attck.claim_does_not_describe"

# The words of a catalogue name that name no behaviour of their own.
_NAME_FILLER_WORDS = frozenset(
    {"and", "or", "from", "of", "the", "a", "an", "to", "for", "with", "via", "in", "on", "by"}
)
# What a word loses before two words are compared: its common endings, taken
# off while at least four letters stay, so "obfuscated", "obfuscation" and
# "obfuscates" are one term and "dumping" and "dumps" another.
_WORD_ENDINGS = (
    "ations",
    "ation",
    "ating",
    "ated",
    "ates",
    "ions",
    "ion",
    "ings",
    "ing",
    "ery",
    "ers",
    "er",
    "ies",
    "es",
    "ed",
    "s",
    "y",
)


def _stem(word: str) -> str:
    """``word`` lower-cased with its common endings taken off, four letters kept."""
    stem = word.lower()
    changed = True
    while changed:
        changed = False
        for ending in _WORD_ENDINGS:
            if stem.endswith(ending) and len(stem) - len(ending) >= 4:
                stem = stem[: -len(ending)]
                changed = True
                break
    return stem


def _name_terms(technique_id: str, attck: Any) -> tuple[str, set[str]]:
    """The catalogue name of a technique and the stems of its words, parent's included.

    ``("", set())`` when the catalogue gives no name.
    """
    answer = _catalogue_answer(str(technique_id), attck, "attck_lookup")
    name = str(answer.get("name") or "").strip()
    if not name:
        return "", set()
    names = [name]
    if "." in str(technique_id):
        parent = _catalogue_answer(str(technique_id).split(".")[0], attck, "attck_lookup")
        names.append(str(parent.get("name") or ""))
    stems = {
        _stem(word)
        for text in names
        for word in re.findall(r"[A-Za-z0-9]+", text)
        if len(word) >= 3 and word.lower() not in _NAME_FILLER_WORDS
    }
    return name, stems


def claim_does_not_describe_violation(
    claim: Any, technique_id: str, attck: Any, *, path: str = ""
) -> Violation | None:
    """The question for a claim whose sentence shares no term with the technique it names.

    The technique's vocabulary is the one the absence reader uses
    (:func:`behaviour_pattern`): the capability terms that list its id, its
    catalogue name and its tactics as a category phrase. The catalogue name is
    compared word by word, each word with its common endings off
    (:func:`_stem`), so a claim that writes "obfuscation" shares a term with
    "Obfuscated Files or Information". Only a sentence that shares none of them
    is asked about, once: "accesses the PEB to bypass sandboxing" under OS
    Credential Dumping. What the analyst answers stands, and a technique kept
    after the question is published as the analyst stated it. Nothing is
    decided without the catalogue's name for the id.
    """
    text = str(getattr(claim, "claim", "") or "")
    if not text.strip() or attck is None:
        return None
    name, stems = _name_terms(technique_id, attck)
    if not name:
        return None
    pattern = behaviour_pattern(technique_id, attck)
    if pattern is not None and pattern.search(text):
        return None
    if any(_stem(word) in stems for word in re.findall(r"[A-Za-z0-9]+", text) if len(word) >= 3):
        return None
    tid = safe_finding_value(technique_id)
    return Violation(
        code=CLAIM_DOES_NOT_DESCRIBE_CODE,
        message=(
            f"CLAIM {safe_finding_value(text)!r} carries TECHNIQUE {tid} "
            f"{safe_finding_value(name)}, and its sentence shares no term with that "
            f"technique: not its name, its tactic or the words that describe it. A technique "
            f"on a claim is published as something the sample does. Keep {tid} only if the "
            f"sample does it, and then say in the claim what it does that is {tid}; if the "
            "claim describes another behaviour, give that behaviour's technique or write "
            "TECHNIQUE: NONE."
        ),
        path=path,
    )


# ---------------------------------------------------------------------------
# Domain and platform consistency
# ---------------------------------------------------------------------------

PLATFORM_MISMATCH_CODE = "attck.platform_mismatch"

# The ATT&CK domain a routed platform belongs to. A platform this table does
# not name has no domain to check against, and an ``ics`` sample is not a
# thing the router produces.
_DOMAIN_BY_PLATFORM: dict[str, str] = {
    "windows": "enterprise",
    "linux": "enterprise",
    "macos": "enterprise",
    "android": "mobile",
    "ios": "mobile",
}

# The routed file types that settle the platform on their own, in the words
# the catalogue uses. The router's platform is read first; these are for a
# state whose platform is missing but whose format is not.
_PLATFORM_BY_FILE_TYPE: dict[str, str] = {
    "pe": "windows",
    "elf": "linux",
    "mach-o": "macos",
    "apk": "android",
    "dex": "android",
    "ipa": "ios",
}


def expected_technique_scope(
    sample: Mapping[str, Any] | None,
) -> tuple[str | None, tuple[str, ...]]:
    """``(domain, MITRE platforms)`` a technique must fit for this sample.

    ``(None, ())`` for a sample whose platform is unknown or cross-platform,
    which is "do not check": a comparison the router could not make is not
    one a validator should make either.
    """
    from maljan.memory.attck_loader import mitre_platforms

    data = sample if isinstance(sample, Mapping) else {}
    platform = str(data.get("platform") or "").strip().lower()
    file_type = str(data.get("file_type") or "").strip().lower()
    if platform not in _DOMAIN_BY_PLATFORM:
        platform = _PLATFORM_BY_FILE_TYPE.get(file_type, "")
    domain = _DOMAIN_BY_PLATFORM.get(platform)
    if domain is None:
        return None, ()
    return domain, tuple(mitre_platforms(platform))


def platform_mismatch_message(
    technique_id: str, attck: Any, scope: tuple[str | None, tuple[str, ...]]
) -> str:
    """Why ``technique_id`` cannot apply to a sample in ``scope``, or ``""``.

    The catalogue's own domain and platforms for the id, against the routed
    ones. Two ways to miss: the id belongs to another domain, or it declares
    platforms and none of them is the sample's.

    Four things are not a miss, and the function answers ``""`` for each in
    turn before it compares anything. A sample whose platform the router could
    not settle, or that is cross-platform, has no scope to check against. A
    knowledge object with no lookup cannot be asked. A lookup that raises or
    answers something other than a mapping has not answered. And a technique
    whose only platform is ``PRE`` happens before any host is touched, so no
    sample's platform can contradict it — including its *domain*, which is why
    that carve-out is asked before the domain comparison and not after it.
    ATT&CK keeps every PRE technique in the enterprise matrix and mobile has
    none, so asking the domain first made every PRE id cross-domain on an
    Android sample. While this check only annotated, that produced a warning;
    now that the report reads it to decide what to publish, it removed real
    techniques — ``T1583 Acquire Infrastructure`` off an Android infostealer's
    C2 registration — from every published surface.

    A fifth is not a miss on the platform comparison alone: a technique the
    catalogue carries no platforms for is not questioned there, because no
    information is not a mismatch. It is still questioned on its domain, which
    the catalogue did answer.

    ``attck_scope`` is asked first: it answers from the vendored files and
    loads nothing, which is what lets this run inside an analyst's turn.
    ``attck_lookup`` is the fallback for a knowledge object without it.
    """
    expected_domain, expected_platforms = scope
    if expected_domain is None:
        return ""
    lookup = getattr(attck, "attck_scope", None) or getattr(attck, "attck_lookup", None)
    if lookup is None:
        return ""
    try:
        answer = lookup(technique_id)
    except Exception as exc:  # noqa: BLE001 — an unanswered lookup is no mismatch
        logger.debug("validation: the ATT&CK lookup for %s failed (%s).", technique_id, exc)
        return ""
    if not isinstance(answer, dict):
        return ""
    domain = str(answer.get("domain") or "").strip().lower()
    platforms = [str(p) for p in (answer.get("platforms") or []) if str(p).strip()]
    if _pre_only(platforms):
        return ""
    sample_words = f"{expected_domain}-domain, {'/'.join(expected_platforms) or 'any platform'}"
    if domain and domain != expected_domain:
        return (
            f"TECHNIQUE {safe_finding_value(technique_id)} belongs to the ATT&CK {domain} domain"
            f"{f' (platforms {", ".join(platforms)})' if platforms else ''}; this sample is "
            f"{sample_words}. Use a technique from the sample's domain, or drop the technique id."
        )
    if expected_platforms and platforms:
        wanted = {p.lower() for p in expected_platforms}
        if not any(p.lower() in wanted for p in platforms):
            return (
                f"TECHNIQUE {safe_finding_value(technique_id)} declares the platforms "
                f"{', '.join(platforms)}; this "
                f"sample is {sample_words}. Use a technique that applies to it, or drop the "
                "technique id."
            )
    return ""


def _pre_only(platforms: Sequence[str]) -> bool:
    """Whether ``PRE`` is the technique's only platform."""
    return len(platforms) == 1 and str(platforms[0]).strip().upper() == "PRE"


# ---------------------------------------------------------------------------
# The alignment gate
# ---------------------------------------------------------------------------

WEAK_ALIGNMENT_CODE = "attck.weak_alignment"

# How many of the index's candidates a claim carries and the feedback names.
ALIGNMENT_CANDIDATES = 5


def _base_id(technique_id: str) -> str:
    """The parent technique of an id: ``T1055.001`` -> ``T1055``."""
    return str(technique_id or "").split(".")[0]


def _catalogue_answer(technique_id: str, attck: Any, question: str) -> dict[str, Any]:
    """One catalogue answer about an id, or ``{}`` when it cannot be had."""
    lookup = getattr(attck, question, None)
    if lookup is None:
        return {}
    try:
        answer = lookup(technique_id)
    except Exception as exc:  # noqa: BLE001 — an unanswered lookup narrows nothing
        logger.debug("validation: the %s lookup for %s failed (%s).", question, technique_id, exc)
        return {}
    return answer if isinstance(answer, dict) else {}


def _within_scope(technique_id: str, attck: Any, scope: tuple[str | None, tuple[str, ...]]) -> bool:
    """Whether a technique could apply to a sample in ``scope``.

    The same question ``platform_mismatch_message`` answers about a claimed id,
    asked about a *candidate* before it is proposed. Without it the index
    offered Mobile and ICS techniques as better fits for a Windows PE — the
    ranking is domain-blind, so ``T1406`` and ``T0885`` came back for a claim
    about a PE's imports and the analyst was asked to consider them.
    """
    expected_domain, expected_platforms = scope
    if expected_domain is None:
        return True
    answer = _catalogue_answer(technique_id, attck, "attck_scope") or _catalogue_answer(
        technique_id, attck, "attck_lookup"
    )
    if not answer:
        return True
    domain = str(answer.get("domain") or "").strip().lower()
    if domain and domain != expected_domain:
        return False
    platforms = [str(p) for p in (answer.get("platforms") or []) if str(p).strip()]
    if not platforms or _pre_only(platforms):
        return True
    wanted = {p.lower() for p in expected_platforms}
    return not wanted or any(p.lower() in wanted for p in platforms)


def _tactics(technique_id: str, attck: Any) -> set[str]:
    """The tactics the catalogue gives a technique, lowercased."""
    answer = _catalogue_answer(technique_id, attck, "attck_lookup")
    return {str(t).strip().lower() for t in (answer.get("tactics") or []) if str(t).strip()}


def _disagrees_with(candidate_id: str, tid: str, attck: Any) -> bool:
    """Whether proposing ``candidate_id`` contradicts the claim's own id.

    A candidate from the same technique family (``T1055`` beside ``T1055.001``)
    or from the same tactic is the index naming another rung of the behaviour
    the analyst already named, which is a ranking preference and not a reason
    to spend a model turn. A candidate from another tactic is the index saying
    the claim describes something else.
    """
    if _base_id(candidate_id) == _base_id(tid):
        return False
    claimed = _tactics(tid, attck)
    return not (claimed and claimed & _tactics(candidate_id, attck))


def _weak_alignment(
    claim: Any,
    tid: str,
    alignment: Any,
    threshold: float,
    *,
    attck: Any = None,
    scope: tuple[str | None, tuple[str, ...]] = (None, ()),
    margin: float = ALIGNMENT_MARGIN,
    challenge: bool = False,
) -> str:
    """Record the index's ranking on the claim; the feedback when it disagrees.

    ``alignment(text, tid)`` answers ``{gate_score, candidates: [{technique_id,
    score_gate}, ...]}`` or ``None`` when the index has nothing to say. The
    ranking is written to ``claim.alignment`` whatever it says — narrowed to
    the sample's own ATT&CK domain and platforms, so nothing out of scope is
    ever proposed — and the judge and the report see it beside the analyst's
    choice.

    The feedback is the narrow case: the gate challenges only when it is turned
    on, the claimed id scores under the threshold, the index did not rank the
    claimed id itself among its in-scope candidates, no in-scope candidate
    names the same family or tactic, and the best of the ones that do disagree
    beats the claimed id by ``margin``. Everything else is a ranking the model
    may disagree with, and the id is never replaced either way.
    """
    if alignment is None:
        return ""
    # The claim's own words. ``evidence_ref`` is a ledger id and a quoted
    # fragment, which is noise in the one input the gate score comes from.
    text = str(getattr(claim, "claim", "") or "").strip()
    if not text:
        return ""
    try:
        answer = alignment(text, tid, k=ALIGNMENT_CANDIDATES)
    except Exception as exc:  # noqa: BLE001 — a gate that cannot answer gates nothing
        logger.debug("validation: the alignment gate failed for %s (%s).", tid, exc)
        return ""
    if not isinstance(answer, dict):
        return ""
    candidates: list[dict[str, Any]] = [
        {
            "technique_id": str(c.get("technique_id") or "").strip().upper(),
            "score_gate": float(c.get("score_gate") or 0.0),
        }
        for c in answer.get("candidates") or []
        if isinstance(c, dict) and c.get("technique_id")
    ]
    candidates = [c for c in candidates if _within_scope(str(c["technique_id"]), attck, scope)]
    try:
        gate_score = float(answer.get("gate_score") or 0.0)
    except (TypeError, ValueError):
        gate_score = 0.0
    record = {"gate_score": round(gate_score, 4), "candidates": candidates}
    if hasattr(claim, "alignment"):
        claim.alignment = record
    if not challenge or gate_score >= threshold:
        return ""
    if scope[0] is None:
        # A sample whose domain the router could not settle has no scope to
        # score inside, and a comparison that cannot be made is not one to
        # challenge on.
        return ""
    if any(str(c["technique_id"]) == tid for c in candidates):
        # The index ranked the claimed id itself, in scope. Wherever it put it,
        # it did not fail to think of it, and a candidate it happened to score
        # higher is a preference between two techniques the index considers
        # applicable — not the disagreement this check is for.
        return ""
    disagreeing = [c for c in candidates if _disagrees_with(str(c["technique_id"]), tid, attck)]
    if not disagreeing:
        return ""
    best = max(disagreeing, key=lambda c: float(c["score_gate"]))
    if float(best["score_gate"]) - gate_score < margin:
        return ""
    ranked = ", ".join(f"{c['technique_id']} ({c['score_gate']:.2f})" for c in disagreeing)
    return (
        f"TECHNIQUE {safe_finding_value(tid)} aligns weakly with the claim's own text (gate score "
        f"{gate_score:.2f}, threshold {threshold:.2f}), and the ATT&CK index ranks "
        f"{best['technique_id']} ({best['score_gate']:.2f}) and other techniques from this "
        f"sample's own domain above it: {ranked}. Keep {safe_finding_value(tid)} if the evidence "
        "says so and say "
        "why in the claim, choose one of the ranked techniques, or drop the technique id."
    )


def technique_check_note(findings: Any) -> str:
    """What the judge is told about technique claims the check questioned and the analyst kept.

    The platform mismatches and weak alignments that survived their retry,
    read off the unresolved rows so the judge weighs the same messages the
    analyst was shown — the domain, the platforms, the candidates. Empty when
    there are none.
    """
    rows: list[Any] = []
    if isinstance(findings, dict):
        for entries in findings.values():
            rows.extend(entries or [])
    else:
        rows.extend(findings or [])
    lines: list[str] = []
    for row in rows:
        data = row if isinstance(row, dict) else getattr(row, "__dict__", {}) or {}
        code = str(data.get("code") or "")
        if code not in (PLATFORM_MISMATCH_CODE, WEAK_ALIGNMENT_CODE):
            continue
        message = " ".join(str(data.get("message") or "").split())
        lines.append(f"- {code}: {message}")
    if not lines:
        return ""
    return (
        "TECHNIQUE CHECK — claims the ATT&CK check questioned and the analyst kept. The ids "
        "are the analysts' own; the check names what disagrees with them and nothing here "
        "changed them.\n" + "\n".join(lines)
    )


# The id inside an ``isr.ungrounded_technique`` message, which is where the
# technique the analyst kept is written down.
_TID_IN_MESSAGE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def ungrounded_technique_note(findings: Any) -> str:
    """What the judge is told about technique claims that cite nothing.

    Read off the unresolved rows rather than recomputed: these are the claims
    an analyst was already asked about and kept, and the judge weighing them
    is entitled to know which of the techniques in front of it nothing in the
    run establishes. Empty when there are none, which is the usual case.
    """
    rows: list[Any] = []
    if isinstance(findings, dict):
        for entries in findings.values():
            rows.extend(entries or [])
    else:
        rows.extend(findings or [])
    named: list[str] = []
    for row in rows:
        data = row if isinstance(row, dict) else getattr(row, "__dict__", {}) or {}
        if str(data.get("code") or "") != UNGROUNDED_TECHNIQUE_CODE:
            continue
        match = _TID_IN_MESSAGE_RE.search(str(data.get("message") or ""))
        if match and match.group(0) not in named:
            named.append(match.group(0))
    if not named:
        return ""
    return "technique claims citing no evidence from this run: " + ", ".join(named)


VALIDITY_CODE = "attck.unknown_id"

# A technique named with no id. Its own code because the answer is different
# from an id that does not resolve: there is nothing to look up, and a
# behaviour the model could not map is still a behaviour the report can carry.
MISSING_ID_CODE = "attck.missing_id"


# What the run-quality note says for a check that could not run, per code.
# A code this table does not know is still named rather than described as
# something it is not.
NOT_RUN_SENTENCES: dict[str, str] = {
    "attck.unknown_id": (
        "the ATT&CK catalogue could not be read; technique ids were not checked (attck.unknown_id)"
    ),
}


def not_run_sentence(code: str) -> str:
    """The run-quality sentence for one check that could not run."""
    return NOT_RUN_SENTENCES.get(code, f"a validation check could not run ({code})")


def validity_check_available(attck: Any) -> bool:
    """Whether the validity check can run at all on this box.

    ``unknown_technique_ids`` answers "nothing unknown" when the catalogue
    cannot be read, which is the right thing to *return* and the wrong thing
    to *report*: a run that checked nothing has to say so. A knowledge module
    without the question is read as available, so a stub in a test is not
    told it is broken.
    """
    probe = getattr(attck, "catalogue_available", None)
    if attck is None or probe is None:
        return attck is not None
    try:
        return bool(probe())
    except Exception as exc:  # noqa: BLE001 — a probe that raises is a catalogue that is not there
        logger.debug("validation: the catalogue probe failed (%s).", exc)
        return False


def unknown_technique_ids(ids: Sequence[str], attck: Any) -> set[str]:
    """Which of ``ids`` the ATT&CK catalogue has no entry for, across all domains.

    The single place that answers "is this a real technique", so the analyst
    loop, the judge's bundle check and the report's capability matrix cannot
    disagree about one id. A lookup that fails is not a verdict: an unreachable
    catalogue returns nothing unknown rather than calling everything invented.

    ``attck_validate`` is the cheap question — it answers from the vendored id
    universe and only touches the fifty-megabyte catalogue once an id has
    already failed — and every id is asked in one call, so a report with forty
    techniques costs one lookup rather than forty.
    """
    wanted = [str(i).strip().upper() for i in ids if str(i).strip()]
    if not wanted or attck is None:
        return set()

    check = getattr(attck, "attck_validate", None)
    if check is not None:
        try:
            answer = check(wanted)
        except Exception as exc:  # noqa: BLE001 — a knowledge failure is not a violation
            logger.debug("validation: the ATT&CK check failed (%s).", exc)
            return set()
        return {
            str(row.get("id") or "").strip().upper()
            for row in (answer or {}).get("invalid") or []
            if row.get("id")
        }

    lookup = getattr(attck, "attck_lookup", None)
    if lookup is None:
        return set()
    unknown: set[str] = set()
    for tid in wanted:
        try:
            answer = lookup(tid)
        except Exception as exc:  # noqa: BLE001 — a knowledge failure is not a violation
            logger.debug("validation: the ATT&CK lookup for %s failed (%s).", tid, exc)
            continue
        if isinstance(answer, dict) and not answer.get("valid"):
            unknown.add(tid)
    return unknown


def _technique_is_known(technique_id: str, attck: Any) -> bool:
    """Whether the id is a real technique."""
    return not unknown_technique_ids([technique_id], attck)


def _retired_note(technique_id: str, attck: Any) -> str:
    """`` (retired in ATT&CK 19.2)`` when a previous vendored catalogue had the id."""
    ask = getattr(attck, "attck_retired_in", None)
    if ask is None:
        return ""
    try:
        release = ask(technique_id)
    except Exception as exc:  # noqa: BLE001 — a note, not a check
        logger.debug("validation: the retired-id lookup for %s failed (%s).", technique_id, exc)
        return ""
    return f" (retired in ATT&CK {release})" if release else ""


def _suggest_techniques(claim_text: str, attck: Any) -> list[str]:
    """Up to :data:`MAX_SUGGESTIONS` real ids for what the claim describes."""
    resolve = getattr(attck, "resolve_technique", None)
    if resolve is None or not claim_text.strip():
        return []
    try:
        answer = resolve(claim_text, MAX_SUGGESTIONS)
    except Exception as exc:  # noqa: BLE001 — a suggestion is a courtesy, not a contract
        logger.debug("validation: technique suggestions unavailable (%s).", exc)
        return []
    candidates = (answer or {}).get("candidates") if isinstance(answer, dict) else None
    out: list[str] = []
    for candidate in candidates or []:
        tid = str((candidate or {}).get("technique_id") or "").strip().upper()
        if tid and tid not in out:
            out.append(tid)
        if len(out) >= MAX_SUGGESTIONS:
            break
    return out


def mark_invalid_technique_ids(isr: Any, violations: Iterable[Violation]) -> None:
    """Flag the claims whose technique id survived the retry unresolved.

    The id itself is left exactly as the analyst wrote it. What changes is the
    report's description of it: ``technique_id_valid=False`` is how a reader,
    the STIX minting step and the FP linter learn that this one is not real.
    ``kept_after_absence_question=True`` is a note, not a verdict: the claim
    reads as absence and the analyst kept its id when asked, so the technique
    is published and the report and the judge say so beside it. Call it only
    with violations the analyst was shown: an absence question that was never
    sent leaves the claim unnoted (see ``BaseAnalyst._validate_isr``).
    """
    claims = list(getattr(isr, "claims", None) or [])
    for violation in violations:
        if violation.code not in (VALIDITY_CODE, ABSENCE_CLAIM_CODE):
            continue
        index = _claim_index(violation.path)
        if index is None or index >= len(claims):
            continue
        claim = claims[index]
        if violation.code == VALIDITY_CODE and hasattr(claim, "technique_id_valid"):
            claim.technique_id_valid = False
        if violation.code == ABSENCE_CLAIM_CODE and hasattr(claim, "kept_after_absence_question"):
            claim.kept_after_absence_question = True


def _claim_index(path: str) -> int | None:
    match = re.search(r"claims\[(\d+)\]", path or "")
    return int(match.group(1)) if match else None


# ---------------------------------------------------------------------------
# Anything with a pydantic schema
# ---------------------------------------------------------------------------


def keep_known_keys(model: Any, payload: Any) -> tuple[Any, list[str]]:
    """``payload`` narrowed to the fields ``model`` declares, and what was dropped.

    The report sections forbid unknown keys, deliberately: a model that invents
    a field has invented its content too. But refusing the whole object over
    one extra key cost two reports their conclusion and their technical
    analysis — ``sophistication_rating`` and ``text`` beside fields that were
    all correct — and the report then simply had no conclusion, with nothing
    saying why. The known subset is kept, the extra keys are named, and the
    caller records them as a degradation reason.

    Recursive through the declared sub-models, because the keys the models
    invented were nested inside the section objects rather than beside them.
    Paths come back dotted, as a reader of the reason reads them.
    """
    dropped: list[str] = []

    def _walk(target: Any, value: Any, path: str) -> Any:
        fields = getattr(target, "model_fields", None)
        if not isinstance(value, dict) or not isinstance(fields, dict):
            return value
        kept: dict[str, Any] = {}
        for key, item in value.items():
            if key not in fields:
                dropped.append(f"{path}{key}")
                continue
            kept[key] = _walk_field(fields[key], item, f"{path}{key}.")
        return kept

    def _walk_field(field: Any, value: Any, path: str) -> Any:
        annotation = getattr(field, "annotation", None)
        origin = get_origin(annotation)
        nested = [
            arg
            for arg in ([annotation, *get_args(annotation)])
            if isinstance(arg, type) and hasattr(arg, "model_fields")
        ]
        if not nested:
            return value
        if isinstance(value, list):
            return [_walk(nested[0], item, f"{path}{index}.") for index, item in enumerate(value)]
        if origin in (dict, Mapping) and isinstance(value, dict):
            # A mapping of models: the keys are the caller's own, not fields,
            # so the sub-model is asked about each *value*. Walked as the
            # dict itself, every key would be reported dropped and the field
            # would come back empty.
            return {key: _walk(nested[-1], item, f"{path}{key}.") for key, item in value.items()}
        return _walk(nested[0], value, path)

    return _walk(model, payload, ""), dropped


def schema_violations(model: Any, payload: Any, *, code: str) -> list[Violation]:
    """Pydantic's complaints about ``payload``, in words the model can act on.

    The narrative and the report composer answer against a schema with real
    constraints — at least two key findings, an executive summary of at
    least 120 characters, six required fields per recommendation —
    and the constraints are exactly the things a model gets wrong. Before this
    the whole answer was discarded on the first one and the report shipped the
    deterministic template instead, with nothing telling anyone which rule was
    broken. Each pydantic error becomes one violation naming the field and the
    rule, which is what the retry turn shows the model.
    """
    if payload is None:
        return [Violation(code=code, message="the answer was not JSON at all.")]
    try:
        model.model_validate(payload)
    except ValidationError as exc:
        return [
            Violation(
                code=code,
                message=_schema_message(model, error),
                path=".".join(str(part) for part in error.get("loc") or ()),
            )
            for error in exc.errors()
        ][:MAX_SCHEMA_VIOLATIONS]
    except Exception as exc:  # noqa: BLE001 — a coercion failure is still a finding
        return [Violation(code=code, message=safe_finding_value(exc))]
    return []


# ---------------------------------------------------------------------------
# The report's prose
# ---------------------------------------------------------------------------

UNGROUNDED_CAPABILITY_CODE = "narrative.ungrounded_capability"

# The capability each term claims, and what in a run would establish it: an
# ATT&CK technique (matched on the base id, so a sub-technique counts), or an
# evidence section / typed block whose presence means the run looked at that
# behaviour and found something.
#
# The list is fixed rather than derived, and short rather than exhaustive.
# These are the words that turn a thin run into a confident-sounding report:
# run 3's executive summary asserted "active command-and-control
# communication", "data exfiltration" and "persistent backdoor access" for a
# sample whose whole analysis was one technique (T1027) and no network or
# sandbox data at all. A term nobody over-claims does not need to be here.
CAPABILITY_TERMS: tuple[tuple[str, str, tuple[str, ...], tuple[str, ...]], ...] = (
    (
        "command and control",
        r"command[\s-]and[\s-]control|\bc2\b|\bc&c\b|\bcnc\b",
        ("T1071", "T1090", "T1095", "T1102", "T1104", "T1105", "T1132", "T1571", "T1573"),
        ("network", "c2", "connections", "http", "dns"),
    ),
    (
        "exfiltration",
        r"exfiltrat\w*",
        ("T1020", "T1029", "T1041", "T1048", "T1030", "T1567"),
        ("network", "exfiltration", "connections"),
    ),
    (
        "backdoor",
        r"backdoor\w*",
        ("T1071", "T1219", "T1505", "T1546", "T1543", "T1547"),
        ("network", "persistence", "services"),
    ),
    (
        "keylogging",
        r"keylog\w*|keystroke\w*",
        ("T1056",),
        ("dynamic", "hooks", "input"),
    ),
    (
        "ransomware",
        r"ransom\w*",
        ("T1486", "T1490", "T1491", "T1485"),
        ("ransom_note", "encryption_scheme"),
    ),
    (
        "encryption",
        r"encrypt\w*|cryptograph\w*",
        ("T1027", "T1022", "T1486", "T1573", "T1140"),
        ("encryption_scheme", "crypto", "strings"),
    ),
    (
        "persistence",
        r"persist\w*",
        ("T1053", "T1136", "T1197", "T1505", "T1543", "T1546", "T1547", "T1574"),
        ("persistence", "registry", "services", "scheduled_tasks"),
    ),
    (
        "process injection",
        r"inject\w*",
        ("T1055", "T1620", "T1106"),
        ("dynamic", "processes", "imports"),
    ),
    (
        "lateral movement",
        r"lateral[\s-]movement",
        ("T1021", "T1080", "T1210", "T1534", "T1570"),
        ("network", "smb", "connections"),
    ),
    (
        "credential theft",
        r"credential\w*|password[\s-]steal\w*|\bstealer\b",
        ("T1003", "T1552", "T1555", "T1056", "T1539"),
        ("credentials", "browser", "files_read"),
    ),
    (
        "downloader or dropper",
        r"\bdownloader\b|\bdropper\b|\bloader\b",
        ("T1105", "T1204", "T1608", "T1027"),
        ("network", "dropped_files", "files_written"),
    ),
    (
        "rootkit",
        r"rootkit\w*",
        ("T1014", "T1215", "T1542", "T1564"),
        ("drivers", "kernel"),
    ),
    (
        "spyware",
        r"spyware|surveillance",
        ("T1056", "T1113", "T1123", "T1125"),
        ("dynamic", "screenshots"),
    ),
    (
        # Evading detection or analysis and packing are claims of the same
        # kind: a benign control's report wrote "attempts to evade detection
        # and debuggers" and "may indicate a repacked legitimate binary", and
        # neither word was read.
        "anti-analysis",
        r"anti[\s-]?(?:analysis|debug\w*|disassembl\w*|emulation|sandbox|vm)\b"
        r"|(?:sandbox|virtuali[sz]ation|debugger|detection|analysis)[\s-]+evasion"
        r"|\bevasion\s+techniques?\b"
        r"|\bevad\w*\s+(?:\w+\s+){0,2}?(?:detection|analysis|analysts?|debuggers?|sandbox\w*"
        r"|antivirus|security\s+products?)\b"
        r"|\bre-?pack\w*|\bpack(?:ed|er|ers|ing)\b",
        ("T1562", "T1564", "T1497", "T1622", "T1027", "T1140", "T1480"),
        ("anti_analysis",),
    ),
    (
        "anti-forensics",
        r"anti[\s-]?forensic\w*|indicator[\s-]+removal"
        r"|(?:clear|wip|eras|delet)\w*\s+(?:the\s+|its\s+)?(?:\w+\s+)?(?:event\s+)?logs?\b",
        ("T1070",),
        ("anti_forensics",),
    ),
)

_COMPILED_CAPABILITY_TERMS = tuple(
    (label, re.compile(pattern, re.IGNORECASE), techniques, keys)
    for label, pattern, techniques, keys in CAPABILITY_TERMS
)


# The report sections that are reference lookups rather than observations of
# the sample. The API capability table says which catalogue categories an
# imported API is listed under (``evidence_summary.catalogue_associations``:
# reference, not evidence), so what it names is nothing the sample was found
# to do.
_REFERENCE_SECTION_SOURCES: frozenset[str] = frozenset({"tool:api_capability"})

# The report sections that list values the sample holds — its printable
# strings, the indicators read out of them and the strings emulation decoded.
# Their words are the sample's bytes, not anybody's statement about behaviour.
_SAMPLE_VALUE_SECTION_SOURCES: frozenset[str] = frozenset(
    {"tool:strings", "tool:iocs_from_file", "tool:floss"}
)

# The report sections that list what a rule matcher matched. A rule's name is
# the rule author's word for a pattern of bytes or instructions, not a
# statement that the sample does it: capa's "log keystrokes via polling" and
# "check for time delay via GetTickCount" grounded a benign client's
# "performs keylogging" and "attempts to evade detection and debuggers". The
# section still counts by its key.
_RULE_MATCH_SECTION_SOURCES: frozenset[str] = frozenset(
    {"tool:capa", "tool:yara_scan", "tool:yara"}
)


@dataclass(frozen=True)
class CapabilityGrounding:
    """What a run established, in the three shapes the terms are checked against.

    Built once per report and handed to the validator, so the narrative round
    and each of the composer's sections ask the same question of the same run.
    """

    technique_ids: frozenset[str] = frozenset()
    evidence_keys: frozenset[str] = frozenset()
    evidence_text: str = ""
    # The published techniques only a rule match stands behind:
    # ``(technique id, catalogue name, note)``, the note as the ATT&CK table
    # prints it (``corroboration.rule_match_only``).
    rule_only: tuple[tuple[str, str, str], ...] = ()

    def grounds(
        self, techniques: Sequence[str], keys: Sequence[str], pattern: re.Pattern[str]
    ) -> bool:
        """Whether the run supports a term by technique, by section, or by word.

        The third is not a loophole. An analyst that wrote "the sample resolves
        a hard-coded C2 host from its strings" has grounded the phrase whether
        or not anybody mapped it to T1071, and a report is allowed to repeat
        what its own evidence says. What is forbidden is the report being the
        first place the word appears.

        The word has to be said there, not denied: the same reader that spares
        the report's own "no persistence was observed" is asked of the
        evidence, so an analyst's "does not exhibit obvious persistence
        mechanisms" grounds no "establishes persistence".
        """
        if any(base in self.technique_ids for base in techniques):
            return True
        if any(key in self.evidence_keys for key in keys):
            return True
        return bool(self.evidence_text and _claimed(pattern, self.evidence_text))

    def summary(self) -> str:
        """What the run does have, for the feedback turn to offer instead."""
        techniques = ", ".join(sorted(self.technique_ids)) or "no ATT&CK techniques"
        keys = ", ".join(sorted(self.evidence_keys)) or "no evidence sections"
        return f"This run established {techniques}, and has {keys}."

    @classmethod
    def from_report(cls, report: Any, isr_reports: Any = None) -> CapabilityGrounding:
        """Read a ``MalwareReport`` (and optionally the analysts' ISRs).

        Never raises: a grounding that cannot be read is an empty one, and an
        empty one grounds nothing — which would fail every term — so a read
        that finds nothing at all returns a grounding that checks nothing. A
        report the validator cannot understand must not become a report full of
        violations.
        """
        techniques: set[str] = set()
        keys: set[str] = set()
        words: list[str] = []
        rule_rows: list[tuple[str, str, str]] = []
        try:
            # A technique only a rule match stands behind — one string of a
            # YARA rule in a large file, with no analyst claiming it — grounds
            # no capability word: "credential dumping" was waved through by the
            # very match in question. Neither its id, its name nor its rule's
            # row in the evidence counts.
            from maljan.analysis.corroboration import rule_match_only

            rule_notes = rule_match_only(report)
            rule_only = set(rule_notes)
            names = {
                str(getattr(m, "technique_id", "") or ""): str(
                    getattr(m, "technique_name", "") or ""
                )
                for m in getattr(report, "ttp_mappings", None) or []
            }
            rule_rows = [(tid, names.get(tid, ""), note) for tid, note in rule_notes.items()]
            rule_only_rules = {
                str(hit.get("rule") or "").lower()
                for tid in rule_only
                for hit in (getattr(report, "rule_match_strings", None) or {}).get(tid, [])
                if isinstance(hit, dict)
            } - {""}
            for row in list(getattr(report, "ttp_mappings", None) or []) + list(
                getattr(report, "capability_matrix", None) or []
            ):
                if str(getattr(row, "technique_id", "") or "") in rule_only:
                    continue
                # A matrix row this run did not publish — an id the catalogue
                # lacks, one only a claim of absence named, one a rule matched
                # and nobody claimed — is not something the run found.
                if str(getattr(row, "not_published", "") or ""):
                    continue
                base = _base_technique(getattr(row, "technique_id", ""))
                if base:
                    techniques.add(base)
                words.append(str(getattr(row, "technique_name", "") or ""))
            for block in ("static", "dynamic"):
                if getattr(report, block, None) is not None:
                    keys.add(block)
            # The network block exists whenever the string sweep found a run of
            # bytes shaped like a host, and its presence grounded "lateral
            # movement", "command and control" and "exfiltration" in a run
            # that observed no traffic at all. It grounds them when something
            # other than the sweep recorded a row of it.
            if _network_observed(getattr(report, "network", None)):
                keys.add("network")
            if list(getattr(report, "persistence", None) or []):
                keys.add("persistence")
            for section in getattr(report, "sections", None) or []:
                # A reference table's rows say what a catalogue lists an API
                # under, not what the sample does: "CreateMutexA | persistence"
                # grounded a report's "likely uses these registry APIs to
                # establish persistence". Its words and its key ground nothing.
                if str(getattr(section, "source", "") or "").strip().lower() in (
                    _REFERENCE_SECTION_SOURCES
                ):
                    continue
                key = str(getattr(section, "key", "") or "").strip().lower()
                if key:
                    keys.add(key)
                # The sample's own strings are values it holds, not statements
                # about what it does: a benign client's settings path
                # "/SSH/Auth/Credentials" grounded "credential harvesting".
                # The section still counts by its key.
                if str(getattr(section, "source", "") or "").strip().lower() in (
                    _SAMPLE_VALUE_SECTION_SOURCES | _RULE_MATCH_SECTION_SOURCES
                ):
                    continue
                words.append(str(getattr(section, "title", "") or ""))
                for row in getattr(section, "rows", None) or []:
                    if row and str(row[0]).strip().lower() in rule_only_rules:
                        continue
                    words.extend(str(cell) for cell in row)
                words.append(str(getattr(section, "text", "") or ""))
            values = isr_reports.values() if hasattr(isr_reports, "values") else ()
            for isr in values:
                for claim in getattr(isr, "claims", None) or []:
                    words.append(str(getattr(claim, "claim", "") or ""))
                    base = _base_technique(str(getattr(claim, "technique_id", "") or ""))
                    if base:
                        techniques.add(base)
                for finding in getattr(isr, "findings", None) or []:
                    words.append(str(getattr(finding, "title", "") or ""))
        except Exception as exc:  # noqa: BLE001 — an unreadable run grounds nothing
            logger.debug("validation: the capability grounding could not be read (%s).", exc)
        return cls(
            technique_ids=frozenset(techniques),
            evidence_keys=frozenset(keys),
            # One item a line: a line break ends a clause for the negation
            # reader, so a cue in one cell never reaches a word in the next.
            evidence_text="\n".join(w for w in words if w).lower(),
            rule_only=tuple(rule_rows),
        )


def _network_observed(network: Any) -> bool:
    """Whether a network block holds anything but the string sweep's own rows.

    A sandbox's or an analyst's row, or a fingerprint a capture recorded. A
    row that records no source is read as the sweep's, the reading the export
    gives it.
    """
    if network is None:
        return False
    for kind in ("domains", "ips", "urls"):
        for row in getattr(network, kind, None) or []:
            if str(getattr(row, "source", "") or "").strip().lower() not in ("", "strings"):
                return True
    return any(
        getattr(network, recorded, None)
        for recorded in ("user_agents", "ja3_fingerprints", "ja3s_fingerprints")
    )


# What ends the clause a term was written in. A capability word after one of
# these is a new statement, so a negation before it does not reach it.
#
# A comma is deliberately not one of them. "The loader does not, in any
# sandbox run, establish command-and-control" is one clause with a
# parenthetical in it, and treating the commas as boundaries threw the cue
# away and re-flagged the honest negative. The window below is the limiter.
_CLAUSE_BREAK_RE = re.compile(r"[.;:!?\n]|\bbut\b|\bhowever\b|\bwhereas\b", re.IGNORECASE)

# The cues that turn a capability word into a report of its absence.
#
# ``free`` is not among them. "free of" is the only construction it would have
# earned, and it cost a real claim: "a free dynamic-DNS host for command and
# control" is an over-claim the validator exists to catch.
#
# "rather than", "instead of" and "prevents confirmation of" set what follows
# them aside as well: "standard for a client application rather than a C2
# agent" and "the absence of a sandbox run prevents confirmation of runtime C2
# behaviour" claim nothing.
_NEGATION_RE = re.compile(
    r"\b(?:no|not|never|without|lack(?:s|ed|ing)?|absence|none)\b|n't\b|\bfailed to\b"
    r"|\brather\s+than\b|\binstead\s+of\b"
    r"|\b(?:prevents?|precludes?)\s+(?:any\s+)?(?:confirmation|observation)\s+of\b",
    re.IGNORECASE,
)

# The phrases that open with a cue and assert the opposite of one. "There is no
# doubt that the sample exfiltrates data" is a claim, and "not only does it
# persist" is two. Checked at the cue's own position, so a real cue elsewhere
# in the window still counts.
_NOT_A_NEGATION = ("no doubt", "not only")

# How far back a cue is allowed to reach. A negation governs the words next to
# it, not the whole paragraph: "no persistence was observed and the sample
# injects code into explorer.exe" is one honest negative and one real claim,
# and a window this size keeps the second one.
#
# Two known limits, both of them the price of the two rules above, and both
# erring toward the answer that costs a feedback turn rather than the one that
# clears a real over-claim:
#
#   * a comma splice — "No persistence was observed, the sample injects code"
#     — leaves the second claim unflagged, because the comma is not a clause
#     break and the window still reaches the cue;
#   * the last item of a long negative list — "no evidence of keylogging,
#     credential theft, or exfiltration" — is flagged, because the cue is
#     further back than this.
#
# ``TestTheKnownLimitsOfTheWindow`` pins both, so a later change to the break
# set or the window is measured against them rather than discovering them.
_NEGATION_WINDOW = 40


# What ends a negation's reach inside one clause: a relative clause or a new
# statement joined on with its own subject. "No indication of a check was
# found, as the sample harvests credentials" negates the check, not the
# harvesting.
_NEGATION_REACH_END_RE = re.compile(
    r"\b(?:which|that|as|while|whereas)\b|\band\s+(?:the|it|this|its|then)\b|,\s*then\b",
    re.IGNORECASE,
)
# Words inside a negation that the reach-end words would otherwise read as its
# end: the complement of "no evidence that …" and the "such as" of a list the
# negation names. "There is no evidence that the sample exfiltrates data" and
# "no network activity such as exfiltration" are statements of absence.
_INSIDE_A_NEGATION_RE = re.compile(
    r"^\s*(?:evidence|indications?|signs?|traces?)\s+that\b|\bsuch\s+as\b", re.IGNORECASE
)
# A noun negation: "no evidence of", "without any sign of". Its reach runs
# through a ", such as …" list it names, however long, to the end of its clause.
_NOUN_NEGATION_RE = re.compile(
    r"\b(?:no|without(?:\s+any)?)\s+(?:evidence|indications?|signs?|traces?)\s+of\b",
    re.IGNORECASE,
)


# Where a ", such as …" list ends: a comma that no "or"/"and" follows, a
# coordinating break, or "and" opening a new subject ("and credentials are
# stolen").
_LIST_END_RE = re.compile(
    r",(?!\s*(?:or|and)\b)|\b(?:yet|although|though|so|but)\b"
    r"|\band\s+\w+\s+(?:is|are|was|were|has|have|had)\b",
    re.IGNORECASE,
)


def _reach_ends(after_cue: str) -> bool:
    """Whether a relative clause or a new statement stands after a cue."""
    return _NEGATION_REACH_END_RE.search(_INSIDE_A_NEGATION_RE.sub(" ", after_cue)) is not None


def _in_a_named_list(text: str, start: int) -> bool:
    """Whether the term at ``start`` is in the ", such as …" list a noun negation names."""
    head = text[:start]
    breaks = list(_CLAUSE_BREAK_RE.finditer(head))
    clause = head[breaks[-1].end() :] if breaks else head
    cues = list(_NOUN_NEGATION_RE.finditer(clause))
    if not cues:
        return False
    after = clause[cues[-1].end() :]
    named = re.search(r",\s*such\s+as\b", after, re.IGNORECASE)
    if named is None or _reach_ends(after):
        return False
    # The list ends at its first comma not followed by "or"/"and", or at a
    # coordinating break; a term past that point is outside the negation.
    listed = after[named.end() :]
    if _LIST_END_RE.search(listed):
        return False
    # "…, and credentials are stolen": the term itself opens the new subject.
    return not (
        re.search(r"\band\s*$", listed, re.IGNORECASE)
        and re.match(r"\w+(?:\s+\w+)?\s+(?:is|are|was|were|has|have|had)\b", text[start:], re.I)
    )


# A purpose that names the term as its object: "to prevent lateral movement".
# Only the term right after the verb (a determiner allowed) is negated; another
# verb of the same sentence is not ("deletes shadow copies to prevent recovery
# and encrypts every document" still claims encryption).
_PURPOSE_OBJECT_RE = re.compile(
    r"\bto\s+(?:prevent|avoid|stop|block)\s+(?:(?:any|the|a|an|further|its|their)\s+)?$",
    re.IGNORECASE,
)
# An absence said of the term as the subject: "Lateral movement is absent from
# the evidence". "Persistence is missing a cleanup routine" is not one.
# A category noun may stand between the term and its verb: "Persistence
# mechanisms were not observed".
_SUBJECT_ABSENT_RE = re.compile(
    r"^(?:\s+(?:mechanisms?|techniques?|capabilit(?:y|ies)|behaviou?rs?|activit(?:y|ies)"
    r"|functionality|methods?|patterns?))?"
    r"\s+(?:is|was|are|were|remains?)\s+"
    r"(?:absent\b|missing\s+from\b"
    r"|not\s+(?:present|observed|seen|found|detected|supported|established|confirmed)\b)",
    re.IGNORECASE,
)


def _is_negated(text: str, start: int, end: int | None = None) -> bool:
    """Whether the term at ``start`` sits inside a statement of absence.

    Read backwards from the match through at most ``_NEGATION_WINDOW``
    characters, stopping at whatever ended the previous clause. A cue in what
    is left governs this term unless a relative clause or a new statement
    stands between them: "contains no keylogging or credential theft" negates
    both words, while "no persistence was observed; it injects code" negates
    only the first, because the semicolon ends the clause the cue was in. "No
    evidence that …" and "such as" do not end it. A noun negation ("no evidence
    of") also reaches through a ", such as …" list it names to the end of its
    clause. Two more statements of absence: the term as the object of a
    purpose ("to prevent lateral movement"), and the absence question's own
    readings (:func:`_absent_by_its_own_statement`): the term in the subject of
    "is absent" or "is missing from", an item of a negated noun list, and the
    end of a negated verb's object.
    """
    if _PURPOSE_OBJECT_RE.search(text[max(0, start - _NEGATION_WINDOW) : start]):
        return True
    if end is not None and _absent_by_its_own_statement(text, start, end):
        return True
    if _in_a_named_list(text, start):
        return True
    window = text[max(0, start - _NEGATION_WINDOW) : start]
    breaks = list(_CLAUSE_BREAK_RE.finditer(window))
    if breaks:
        window = window[breaks[-1].end() :]
    lowered = window.lower()
    return any(
        not lowered.startswith(_NOT_A_NEGATION, cue.start())
        and not _NEED_VERB_RE.match(window[cue.end() :])
        and not _reach_ends(window[cue.end() :])
        for cue in _NEGATION_RE.finditer(window)
    )


def _starts_its_clause(text: str, start: int) -> bool:
    """Whether the term at ``start`` opens its clause, a determiner or adjective allowed."""
    head = text[:start]
    breaks = list(_CLAUSE_BREAK_RE.finditer(head))
    clause = head[breaks[-1].end() :] if breaks else head
    return len(clause.split()) <= 2


# Where one sentence of checked text ends: a stop, a bang or a question mark
# before a space, or a line break.
_STATEMENT_END_RE = re.compile(r"(?<=[.!?])\s+|\n+")


def _sentence_around(text: str, position: int) -> str:
    """The sentence of ``text`` that holds ``position``, as written."""
    begin = 0
    for end in _STATEMENT_END_RE.finditer(text):
        if end.start() >= position:
            return text[begin : end.start()].strip()
        begin = end.end()
    return text[begin:].strip()


# A value written in running text: a run with no space in it holding two path
# or key separators ("/SSH/Auth/Credentials", "HKCU\Software\...\Run",
# "C:\Users\..."). A slash-joined list of words ("injection/hollowing/
# persistence") has that too, so a run is a value only in a path's shape
# (:func:`_path_shaped`).
_PATH_VALUE_RE = re.compile(r"[^\s\"'`“”]*[\\/][^\s\"'`“”]*[\\/][^\s\"'`“”]*")
# A path's shape: opened by a separator, a drive, a hive or a share, or with a
# component that holds a dot or begins with a capital letter.
_PATH_OPENING_RE = re.compile(r"^(?:[\\/]|[A-Za-z]:[\\/]|HK[A-Z_]+\\)")
_PATH_COMPONENT_RE = re.compile(r"(?:^|[\\/])(?:[^\\/\s]*\.[^\\/\s]+|[A-Z][^\\/\s]*)")


def _path_shaped(run: str) -> bool:
    """Whether a run with two separators reads as a path or key, not a list of words."""
    return bool(_PATH_OPENING_RE.match(run) or _PATH_COMPONENT_RE.search(run))


def masked_values(text: str, own_words: Iterable[str] = ()) -> str:
    """``text`` with every value it writes blanked, each character a space.

    A value is a code span, a quoted string, a path or a registry key, and in a
    record, the words of the record's own value (``own_words``) its other
    fields restate: "Configuration path for SSH authentication credentials" is
    the purpose of the value "/SSH/Auth/Credentials", not a statement that the
    sample steals credentials. Positions are kept, so a sentence found in the
    masked text is quoted from ``text`` as written. The capability check reads
    no word a value holds.
    """
    if not text:
        return text
    chars = list(text)
    spans = [
        match.span() for regex in (_CODE_SPAN_RE, _QUOTED_SPAN_RE) for match in regex.finditer(text)
    ]
    spans.extend(
        match.span() for match in _PATH_VALUE_RE.finditer(text) if _path_shaped(match.group(0))
    )
    words = {w.lower() for w in own_words if len(w) >= 4}
    if words:
        spans.extend(
            match.span()
            for match in re.finditer(r"[A-Za-z]{4,}", text)
            if match.group(0).lower() in words
        )
    for begin, end in spans:
        for index in range(begin, end):
            if chars[index] != "\n":
                chars[index] = " "
    return "".join(chars)


def _claiming_sentences(
    pattern: re.Pattern[str], text: str, masked: str | None = None
) -> list[str]:
    """The sentences in which ``pattern`` is claimed rather than reported absent, once each.

    ``masked`` is ``text`` with the words to leave unread blanked
    (:func:`masked_values`); the sentences are quoted from ``text``.
    """
    read = text if masked is None or len(masked) != len(text) else masked
    found: list[str] = []
    for match in pattern.finditer(read):
        if _is_negated(read, match.start(), match.end()):
            continue
        sentence = _sentence_around(text, match.start())
        if sentence and sentence not in found:
            found.append(sentence)
    return found


def _claimed(pattern: re.Pattern[str], text: str) -> bool:
    """Whether ``text`` claims the capability rather than reporting its absence.

    One surviving match is enough: a report that says the sample does not
    exfiltrate data in one sentence and does exfiltrate it in another has made
    the claim, and it is the claim that has to be grounded.
    """
    return any(
        not _is_negated(text, match.start(), match.end()) for match in pattern.finditer(text)
    )


def _base_technique(technique_id: Any) -> str:
    """``T1055.012`` as ``T1055``; anything else as ""."""
    value = str(technique_id or "").strip().upper()
    return value.split(".")[0] if TECHNIQUE_ID_EXACT_RE.match(value) else ""


# How many of a term's technique ids its question names, as examples of what
# would ground it. Two: every term leads with the ids that describe it most
# generally, and a longer list only puts more technique ids in front of a report
# model that has not established any of them.
_TERM_IDS_SHOWN = 2


# A sentence whose assertion is that a rule matched: the matcher, a rule or a
# signature is its subject, the verb says it matched or reported the rule, and
# nothing is concluded about the sample. "YARA rule X matched" and "capa
# reports the rule Y" report the matcher; "Based on YARA results, the sample
# steals credentials" and "capa confirms that the sample performs keylogging"
# claim what the sample does and are read like any other sentence. The
# capability check's own advice for a rule-only technique is to write the first
# kind.
_RULE_MATCH_ASSERTION_RE = re.compile(
    r"(?:\b(?:yara|capa)\b(?:\s+(?:rules?|signatures?))?|\brules?\b|\bsignatures?\b)"
    r"(?:\s+\S+){0,6}?\s+(?:matched|matches|match|flagged|flags|hit|hits|fired|fires|reports|"
    r"reported|lists|listed)\b",
    re.IGNORECASE,
)
_CONCLUDES_ABOUT_THE_SAMPLE_RE = re.compile(
    r"\b(?:so|therefore|thus|hence|because|since|based|indicat\w*|suggest\w*|show\w*|"
    r"mean\w*|confirm\w*|prov\w*|reveal\w*|demonstrat\w*|consistent)\b"
    r"|\b(?:the|this|it)\s+(?:sample|binary|malware|file|executable)\s+(?!\.)"
    r"(?:is|was|has|can|will|may|does|\w+s)\b",
    re.IGNORECASE,
)


def _says_only_that_a_rule_matched(sentence: str) -> bool:
    """Whether the sentence's assertion is a rule match and nothing about the sample."""
    return bool(_RULE_MATCH_ASSERTION_RE.search(sentence)) and not (
        _CONCLUDES_ABOUT_THE_SAMPLE_RE.search(sentence)
    )


def ungrounded_capabilities(
    text: str,
    grounding: CapabilityGrounding,
    *,
    code: str = UNGROUNDED_CAPABILITY_CODE,
    masked: str | None = None,
) -> list[Violation]:
    """Capability claims in ``text`` that this run's evidence does not support.

    One violation per term, so the feedback turn names each one and the run
    summary counts them. The prose itself is never edited: what an unresolved
    term buys is a reader who can see that the sentence outran the evidence,
    which is worth more than a summary quietly rewritten by a regular
    expression into something no model wrote.

    No word inside a value is read (:func:`masked_values`; ``masked`` is the
    caller's own masking of ``text``, positions kept), and a sentence whose
    assertion is only that a rule matched is not a claim that the sample does
    what the rule names (:func:`_says_only_that_a_rule_matched`).
    """
    if not text or not text.strip():
        return []
    if not grounding.technique_ids and not grounding.evidence_keys and not grounding.evidence_text:
        # Nothing was read, so nothing can be judged ungrounded. See
        # ``CapabilityGrounding.from_report``.
        return []
    if masked is None or len(masked) != len(text):
        masked = masked_values(text)
    violations: list[Violation] = []
    for label, pattern, techniques, keys in _COMPILED_CAPABILITY_TERMS:
        # A report of absence is not a claim. Saying "no command-and-control
        # communication was observed" is the prose a thin run should produce,
        # and flagging it spends the one retry arguing against the honest
        # sentence this validator exists to encourage.
        sentences = [
            sentence
            for sentence in _claiming_sentences(pattern, text, masked)
            if not _says_only_that_a_rule_matched(sentence)
        ]
        if not sentences:
            continue
        if grounding.grounds(techniques, keys, pattern):
            continue
        rule_matched = [
            f"{safe_finding_value(tid)} {safe_finding_value(name)} is published on a "
            f"{safe_finding_value(note)}"
            for tid, name, note in grounding.rule_only
            if _base_technique(tid) in techniques
        ]
        rule_line = (
            f" {'; '.join(rule_matched)}: say that a rule matched, not that the sample does it."
            if rule_matched
            else ""
        )
        violations.append(
            Violation(
                code=code,
                message=(
                    f"the text claims {label}, which nothing in this run establishes — "
                    f"no {', '.join(techniques[:_TERM_IDS_SHOWN])} technique, no matching evidence "
                    f"section, and no analyst said it"
                    f" (in: {safe_finding_value(sentences[0])!r}).{rule_line} "
                    f"{grounding.summary()} Describe what was found, or drop the claim."
                ),
                path=label.replace(" ", "_"),
                quoted=tuple(sentences),
            )
        )
    return violations


RULE_MATCH_AS_ACTION_CODE = "report.rule_match_as_action"

# The words that make a sentence about a rule match, or an estimate, rather
# than a statement that the sample does something.
_RULE_OR_ESTIMATE_RE = re.compile(
    r"\b(?:rules?|yara|capa|signatures?|match(?:es|ed|ing)?|may|might|could|possibl[ey]|"
    r"potential(?:ly)?|likely|suggests?|consistent\s+with|indicat\w*|associated\s+with)\b",
    re.IGNORECASE,
)
# The words of a sentence about the report or about defending against a
# technique, which name it without saying the sample does it.
_ABOUT_NOT_ACTION_RE = re.compile(
    r"\b(?:hunt\w*|monitor\w*|detect\w*|defenders?|should|table|appears?|listed|"
    r"published|without\s+analyst)\b",
    re.IGNORECASE,
)


def rule_match_statement_violations(text: str, grounding: CapabilityGrounding) -> list[Violation]:
    """Sentences that state a technique only a rule match stands behind as an action.

    A technique published on one matched string of a YARA rule, with no
    analyst claiming it, is a rule match: a benchmark report wrote "The sample
    dumps credentials from the target system" for one. A sentence that names
    such a technique — its id or its catalogue name — and says nothing of a
    rule or an estimate is asked about once. The publish rule is unchanged,
    and the sentence is never edited. A capability word behind the same
    technique is the capability check's (:func:`ungrounded_capabilities`).
    """
    if not text or not text.strip() or not grounding.rule_only:
        return []
    violations: list[Violation] = []
    for tid, name, note in grounding.rule_only:
        spellings = [re.escape(tid)]
        if len(name.strip()) >= 4:
            spellings.append(r"\s+".join(re.escape(word) for word in name.split()))
        pattern = re.compile(r"(?<![\w.])(?:" + "|".join(spellings) + r")(?![\w])", re.I)
        sentences = [
            sentence
            for sentence in _claiming_sentences(pattern, text)
            if not _RULE_OR_ESTIMATE_RE.search(sentence)
            and not _ABOUT_NOT_ACTION_RE.search(sentence)
            # A field holding the id or the name alone states nothing.
            and sentence.strip(" .").lower() not in {tid.lower(), name.strip().lower()}
        ]
        if not sentences:
            continue
        violations.append(
            Violation(
                code=RULE_MATCH_AS_ACTION_CODE,
                message=(
                    f"{safe_finding_value(sentences[0])!r} states {safe_finding_value(tid)} "
                    f"{safe_finding_value(name)} as something the sample does; this run "
                    f"publishes it on a {safe_finding_value(note)}. Say that a rule matched "
                    "and what it matched, or drop the sentence."
                ),
                path=tid,
                quoted=tuple(sentences),
            )
        )
    return violations


def record_flagged_statements(
    report: Any, violations: Sequence[Violation], *, asked: bool = True
) -> None:
    """Put the sentences of the surviving marked-in-place findings on the report. Never raises.

    What a renderer marks where the sentence stands (``MARKED_IN_PLACE``). The
    sentence is kept as written; the label is the finding's path, the term or
    the technique the check was about.
    """
    rows = getattr(report, "flagged_statements", None)
    if not isinstance(rows, list):
        return
    try:
        from maljan.reporting.models import FlaggedStatement

        seen = {(row.sentence, row.code, row.label, row.asked) for row in rows}
        for violation in violations:
            if violation.code not in MARKED_IN_PLACE:
                continue
            label = violation.path.replace("_", " ")
            for sentence in violation.quoted:
                key = (sentence, violation.code, label, asked)
                if key not in seen:
                    seen.add(key)
                    rows.append(
                        FlaggedStatement(
                            sentence=sentence, code=violation.code, label=label, asked=asked
                        )
                    )
    except Exception as exc:  # noqa: BLE001 — a mark is never worth a report
        logger.debug("validation: flagged sentences were not recorded (%s).", exc)


def prose_of(payload: Any) -> str:
    """Every string an answer carries, one per line, for the checks that read prose."""
    parts: list[str] = []

    def _walk(value: Any, depth: int = 0) -> None:
        if depth > 4:
            return
        if isinstance(value, str):
            parts.append(value)
        elif isinstance(value, dict):
            for item in value.values():
                _walk(item, depth + 1)
        elif isinstance(value, list | tuple):
            for item in value:
                _walk(item, depth + 1)

    _walk(payload)
    return "\n".join(parts)


def narrative_capability_violations(
    payload: Any, grounding: CapabilityGrounding
) -> list[Violation]:
    """:func:`ungrounded_capabilities` over a narrative answer's prose fields."""
    if payload is None:
        return []
    data = payload if isinstance(payload, dict) else getattr(payload, "__dict__", {}) or {}
    parts: list[str] = [str(data.get("executive_summary") or "")]
    for item in data.get("key_findings") or []:
        parts.append(str(item.get("text") or "") if isinstance(item, dict) else str(item))
    text = "\n".join(parts)
    return [
        *ungrounded_capabilities(text, grounding),
        *rule_match_statement_violations(text, grounding),
    ]


# The fields of a section answer that name its topic rather than state a finding.
_TOPIC_FIELDS = frozenset({"title", "heading"})


def _prose_and_masked(payload: Any) -> tuple[str, str]:
    """:func:`prose_of` and the same text with every value blanked, line for line.

    A record's verbatim field (``value``, ``endpoints``) is a value the sample
    holds and is blanked whole; its other fields are blanked where they restate
    that value's words (:func:`masked_values`).
    """
    texts: list[str] = []
    masked: list[str] = []

    def _add(value: str, own: Sequence[str]) -> None:
        texts.append(value)
        masked.append(masked_values(value, own))

    def _walk(value: Any, depth: int = 0) -> None:
        if depth > 4:
            return
        if isinstance(value, str):
            _add(value, ())
        elif isinstance(value, dict):
            verbatim = [
                s for key in _VERBATIM_FIELDS if key in value for s in _strings_of(value[key])
            ]
            own = [word for s in verbatim for word in re.findall(r"[A-Za-z]{4,}", s)]
            for key, item in value.items():
                if key in _TOPIC_FIELDS and isinstance(item, str):
                    # A heading names a topic ("Persistence") and says nothing
                    # the sample does.
                    texts.append(item)
                    masked.append(re.sub(r"[^\n]", " ", item))
                elif key in _VERBATIM_FIELDS:
                    for s in _strings_of(item):
                        texts.append(s)
                        masked.append(re.sub(r"[^\n]", " ", s))
                elif isinstance(item, str) and own:
                    _add(item, own)
                else:
                    _walk(item, depth + 1)
        elif isinstance(value, list | tuple):
            for item in value:
                _walk(item, depth + 1)

    _walk(payload)
    return "\n".join(texts), "\n".join(masked)


def section_capability_violations(payload: Any, grounding: CapabilityGrounding) -> list[Violation]:
    """:func:`ungrounded_capabilities` and the rule-match check over a section answer's strings."""
    if payload is None:
        return []
    text, masked = _prose_and_masked(payload)
    return [
        *ungrounded_capabilities(text, grounding, code=UNGROUNDED_CAPABILITY_CODE, masked=masked),
        *rule_match_statement_violations(text, grounding),
    ]


CITATION_NOT_EVIDENCE_CODE = "report.citation_not_evidence"

# A run of one or more adjacent bracketed groups in prose. Not the index of an
# expression (``key[i]``), not the text of a markdown link (its target follows
# in parentheses), and not part of a token: a part name such as
# ``[Content_Types].xml``, a type accelerator such as
# ``[System.Convert]::FromBase64String``.
_BRACKET_RUN_RE = re.compile(r"(?<![\w\]])(?:\[[^\[\]\n]{1,200}\])+(?![(\w]|\.\w|::)")
_BRACKET_GROUP_RE = re.compile(r"\[([^\[\]\n]{1,200})\]")
# Code, which the check does not read: a fenced block, then an inline span.
_CODE_SPAN_RE = re.compile(r"```.*?```|`[^`\n]*`", re.DOTALL)
# An IPv6 literal in brackets is the host of a URL or a socket address.
_IPV6_RE = re.compile(r"[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}", re.IGNORECASE)
_EVIDENCE_ID_RE = re.compile(r"ev_\d{3,}", re.IGNORECASE)
# An ATT&CK technique or an MBC behaviour in brackets is an identifier, the
# way the report's own tables print one, not a claim about where a fact came
# from; so is a CVE.
_IDENTIFIER_RE = re.compile(r"[A-Z]\d{4}(?:\.[A-Z]?\d{3})?|CVE-\d{4}-\d{4,}", re.IGNORECASE)
# How many ids the sentence names before it says how many more there are.
_CITABLE_SHOWN = 12


# A pack line's own id: the ``[ev_NNNN]`` that begins a line of the block.
# Only the pack writes a line's start; a quoted string inside a line, whatever
# it carries, cannot begin one, because its line breaks are written out.
_PACK_LINE_ID_RE = re.compile(r"^\[(ev_\d{3,})\] ", re.IGNORECASE | re.MULTILINE)


def pack_line_ids(block: str) -> list[str]:
    """The ids the triage pack issued, read off the start of its lines, once each, in order.

    For a caller that has the pack's block and not the run's ledger. The ids
    that merely appear in a line — a decoded string the sample wrote, a model's
    claim — are not ids anything issued, and are not read.
    """
    return list(dict.fromkeys(found.lower() for found in _PACK_LINE_ID_RE.findall(block or "")))


def _strings_of(value: Any, depth: int = 0) -> list[str]:
    if depth > 4:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for item in value.values() for s in _strings_of(item, depth + 1)]
    if isinstance(value, list | tuple):
        return [s for item in value for s in _strings_of(item, depth + 1)]
    return []


def _cited_groups(text: str) -> list[str]:
    """The bracketed groups of ``text`` that read as citations, each on its own.

    A lone group is one. A run of adjacent groups — ``[ev_0004][ev_0005]``, the
    way a model often writes two citations — is split and every group judged,
    when any group of the run holds an evidence id; a run with none, such as a
    layout written ``[len][payload]``, is notation and is not read.
    """
    found: list[str] = []
    for run in _BRACKET_RUN_RE.finditer(text):
        groups = _BRACKET_GROUP_RE.findall(run.group(0))
        cites = any(
            _EVIDENCE_ID_RE.fullmatch(item.strip())
            for group in groups
            for item in re.split(r"[,;]", group)
        )
        if len(groups) == 1 or cites:
            found.extend(groups)
    return found


def citation_violations(
    payload: Any, citable: Sequence[str], *, prose: Sequence[str] | None = None
) -> list[Violation]:
    """Each bracketed citation item in ``payload``'s prose that is not an id it may cite.

    ``prose`` names the fields that are prose — a section's ``body`` or
    ``text``, the narrative's summary and key findings; only those are read, so a
    record field (a C2 channel's packet layout, a command-line flag) is never
    asked about its notation. ``None`` reads every string. Code spans, fenced
    or inline, are not read either.

    ``citable`` is the evidence ids the run's ledger issued — never ids read out
    of the prompt's text, where a sample's own string can carry any. An item that is an
    ATT&CK or MBC identifier is left alone; any other item — a prompt block's
    heading, a source's name, an id the producer was not shown — is one
    violation, once however often it appears, with a sentence naming the ids
    it may cite. The prose is never edited: a citation the retry does not fix
    prints as written, and the unresolved row is what tells a reader.
    """
    if payload is None:
        return []
    if prose is not None:
        data = payload if isinstance(payload, dict) else getattr(payload, "__dict__", {}) or {}
        payload = {key: data.get(key) for key in prose if key in data}
    known = list(
        dict.fromkeys(
            str(i).strip().lower() for i in citable if _EVIDENCE_ID_RE.fullmatch(str(i).strip())
        )
    )
    allowed = set(known)
    offered = ", ".join(known[:_CITABLE_SHOWN])
    if len(known) > _CITABLE_SHOWN:
        offered += f" and {len(known) - _CITABLE_SHOWN} more"
    remedy = (
        f"Cite an entry by its evidence id in brackets — this answer may cite {offered} — "
        "or write the sentence without a bracketed citation."
        if known
        else "This answer was shown no evidence ids, so write the sentence without a "
        "bracketed citation."
    )
    seen: set[str] = set()
    violations: list[Violation] = []
    for text in _strings_of(payload):
        for group in _cited_groups(_CODE_SPAN_RE.sub(" ", text)):
            for raw in re.split(r"[,;]", group):
                item = raw.strip()
                if not item or item.lower() in seen:
                    continue
                if _EVIDENCE_ID_RE.fullmatch(item):
                    if item.lower() in allowed:
                        continue
                    why = f"[{safe_finding_value(item)}] is not an entry this answer was shown."
                elif _IDENTIFIER_RE.fullmatch(item) or _IPV6_RE.fullmatch(item):
                    continue
                else:
                    why = f"[{safe_finding_value(item)}] is cited, and it is not an evidence id."
                seen.add(item.lower())
                violations.append(
                    Violation(
                        code=CITATION_NOT_EVIDENCE_CODE,
                        message=f"{why} {remedy}",
                        path="citation",
                    )
                )
    return violations


# The report's own citations. Each of these is shown to the model once and,
# if it survives, recorded beside the value it is about; none of them removes
# or rewrites what the model wrote.
UNGROUNDED_FINDING_CODE = "narrative.ungrounded_finding"
FLOW_VOICE_CODE = "report.flow_voice"
UNCITED_CONFIGURATION_CODE = "report.configuration_uncited"
# A report section answer the output cap ended. Its JSON is cut before it
# closes, so the schema check could only say "not JSON at all" — and a model
# told that writes the same long answer again, into the same cap. Both answers
# of a benchmark report's host-identifier section ran to exactly 8,192 tokens.
SECTION_CUT_CODE = "composer.cut_at_output_cap"

# An analyst's answer the output cap ended. The judge and the composer were
# asked about theirs; an analyst whose answer stopped at the cap — 42 claims,
# the last one cut — was asked its other questions over the cut answer, spent
# the retry's whole cap again, and returned no claim at all.
ANALYST_CUT_CODE = "isr.cut_at_output_cap"

# A claim begun in an analyst's answer: the label every claim block opens with.
_CLAIM_BEGUN_RE = re.compile(r"^\s*CLAIM:", re.MULTILINE)


def analyst_cut_violation(cap: int, text: str = "") -> Violation:
    """What an analyst the cap cut is told: the cap, what was begun, and the bound.

    The cut answer is not sent back (``retry_with_feedback_sync``'s
    ``drop_answer_for``): it is described — its characters and the claims it
    began — and the length it was cut at is the bound the next answer stays
    under. It asks once for a whole shorter answer, never for fewer findings
    than the evidence holds, and the cap it names is the one in force: nothing
    here raises it.
    """
    begun = len(_CLAIM_BEGUN_RE.findall(text))
    size = (
        f" It ran to {len(text):,} characters"
        + (f" and began {begun} CLAIM block(s)" if begun else "")
        + ", and it is not shown to you again. The whole answer has to be shorter than "
        f"those {len(text):,} characters, the length at which the limit cut it."
        if text
        else ""
    )
    return Violation(
        code=ANALYST_CUT_CODE,
        message=(
            f"Your previous answer stopped at the output limit of {int(cap)} tokens before "
            f"it ended, so its last claim was cut off.{size} Any reasoning you write counts "
            f"against the same limit. Write the whole answer again so that it ends well inside "
            f"{int(cap)} tokens: the claims the evidence supports best, each written once, "
            "each one sentence with its EVIDENCE, CONFIDENCE and TECHNIQUE lines, and nothing "
            "between the blocks."
        ),
    )


# How much of a cut answer its question shows, as a sample of its shape.
SECTION_CUT_HEAD_CHARS = 160


def section_cut_violation(
    cap: int, *, chars: int = 0, begun: int = 0, head: str = "", distinct: int = 0
) -> Violation:
    """What a section the cap cut is told: the cap, the answer's size, and how it opened.

    The cut answer itself is not sent back (``retry_with_feedback``'s
    ``drop_answer_for``): it is about a cap's worth of tokens nobody can read,
    and a retry that carried it had less room to answer in than the first call.
    ``distinct`` is the most different values any one string field of those
    items holds. Items can still differ in combination or in a list field, so
    it says nothing certain about how many items repeat; what it does say is
    that every string field repeats a value an earlier item carried in at least
    ``begun - distinct`` of them, and the question says that.
    """
    repeated = int(begun) - int(distinct) if 0 < int(distinct) < int(begun) else 0
    size = (
        f" It ran to {int(chars):,} characters with {int(begun)} item(s) begun"
        + (
            f"; in each of its text fields, at least {repeated} of them repeat a value an "
            "earlier item already carried"
            if repeated
            else ""
        )
        + (
            f", and opened with {safe_finding_value(head[:SECTION_CUT_HEAD_CHARS])!r}."
            if head
            else "."
        )
        if chars
        else ""
    )
    return Violation(
        code=SECTION_CUT_CODE,
        message=(
            f"Your previous answer reached the output limit of {int(cap)} tokens and was "
            f"cut off before its JSON closed, so none of it could be read.{size} Any "
            "reasoning you write counts against the same limit. Answer again with an object "
            f"that closes well inside {int(cap)} tokens: only the items the evidence supports "
            "best, each written once, every text a short phrase, the JSON on one line "
            "without indentation."
        ),
    )


# A report section answer that writes one item again. Every list section's
# contract says each item is written once; a host-identifier answer began 161
# items of which at most 19 differed. The answer is kept as written with the
# finding beside it: the platform removes no item the model wrote.
REPEATED_ITEMS_CODE = "composer.repeated_items"


def repeated_item_violations(
    payload: Any, identity: Mapping[str, Sequence[str]]
) -> list[Violation]:
    """Lists in a section answer that write an item already written, one question per list.

    ``identity`` names, per list key, every field the report prints an item
    by — ``{"identifiers": ("kind", "value")}``; no fields means the whole
    item. Two rows alike in all of them are counted as written again. The
    question says how many rows are alike and which, and asks the model to say
    whether they are repeats: it never tells the model to remove a row, since
    two alike rows can still be two items the fields do not tell apart.
    """
    data = payload if isinstance(payload, dict) else {}
    found: list[Violation] = []
    for list_key, fields in identity.items():
        rows = data.get(list_key)
        if not isinstance(rows, list) or len(rows) < 2:
            continue
        counts: dict[str, int] = {}
        for row in rows:
            if isinstance(row, dict) and fields:
                key = " | ".join(
                    json.dumps(row.get(name), sort_keys=True, default=str) for name in fields
                )
            else:
                key = json.dumps(row, sort_keys=True, default=str)
            counts[key] = counts.get(key, 0) + 1
        repeats = len(rows) - len(counts)
        if not repeats:
            continue
        named = _named_ids(
            f"{value} {count} times"
            for value, count in sorted(counts.items(), key=lambda item: -item[1])
            if count > 1
        )
        what = ", ".join(fields) if fields else "every field"
        found.append(
            Violation(
                code=REPEATED_ITEMS_CODE,
                message=(
                    f"{int(repeats)} of the {len(rows)} rows in {safe_finding_value(list_key)!r} "
                    f"are alike in {safe_finding_value(what)} to a row written before them; "
                    f"{len(counts)} differ. Alike: {named}. The contract writes each item once. "
                    "Confirm whether these rows are repeats: answer again with the list as you "
                    "intend it, and where alike rows are different items, write what tells them "
                    "apart."
                ),
                path=list_key,
            )
        )
    return found


CITATION_WRONG_ENTRY_CODE = "report.citation_wrong_entry"
ENTRY_CONTENTS_MISSTATED_CODE = "report.entry_contents_misstated"
UNCITED_IDENTIFIER_CODE = "report.identifier_uncited"
TECHNIQUE_NAME_CODE = "report.technique_name"

# The codes a report round's answer is kept with. A broken shape leaves nothing
# to print; each of these leaves a printable answer with a finding beside it.
# The findings whose sentences survive marked where they stand in the report.
MARKED_IN_PLACE: frozenset[str] = frozenset({UNGROUNDED_CAPABILITY_CODE, RULE_MATCH_AS_ACTION_CODE})

KEPT_WITH_A_FINDING: frozenset[str] = frozenset(
    {
        UNGROUNDED_CAPABILITY_CODE,
        UNGROUNDED_FINDING_CODE,
        FLOW_VOICE_CODE,
        UNCITED_CONFIGURATION_CODE,
        CITATION_NOT_EVIDENCE_CODE,
        CITATION_WRONG_ENTRY_CODE,
        ENTRY_CONTENTS_MISSTATED_CODE,
        UNCITED_IDENTIFIER_CODE,
        TECHNIQUE_NAME_CODE,
        RULE_MATCH_AS_ACTION_CODE,
        REPEATED_ITEMS_CODE,
    }
)

# How many ids one finding names. A model that cites forty entries is not
# helped by forty names in its feedback.
_MAX_NAMED_IDS = 6


def _named_ids(ids: Iterable[str]) -> str:
    listed = [safe_finding_value(value) for value in ids]
    shown = ", ".join(listed[:_MAX_NAMED_IDS])
    if len(listed) > _MAX_NAMED_IDS:
        shown += f" and {len(listed) - _MAX_NAMED_IDS} more"
    return shown


def _rows_of(payload: Any, key: str) -> list[dict[str, Any]]:
    data = payload if isinstance(payload, dict) else {}
    return [row for row in (data.get(key) or []) if isinstance(row, dict)]


def _cited(row: dict[str, Any], key: str) -> list[str]:
    return [str(value).strip() for value in (row.get(key) or []) if str(value).strip()]


def key_finding_citation_violations(payload: Any, known_ids: Iterable[str]) -> list[Violation]:
    """Key findings that cite an evidence id this run's ledger does not carry.

    A bullet with no ids is not a finding here: the report prints it with "no
    evidence cited" beside it and the reader decides. A bullet that names an
    id nobody issued is pointing a reader at nothing, and that is the one
    worth one question. With no ledger to compare against, nothing is judged.
    """
    known = {str(value) for value in known_ids}
    if not known:
        return []
    out: list[Violation] = []
    for index, row in enumerate(_rows_of(payload, "key_findings")):
        unknown = [value for value in _cited(row, "evidence_ids") if value not in known]
        if unknown:
            out.append(
                Violation(
                    code=UNGROUNDED_FINDING_CODE,
                    message=(
                        f"key finding {safe_finding_value(index + 1)} cites "
                        f"{safe_finding_value(_named_ids(unknown))}, which no entry in "
                        "this run's evidence carries. Cite the ev_ ids of the entries the "
                        "finding stands on, or leave evidence_ids empty."
                    ),
                    path=f"key_findings.{index}.evidence_ids",
                )
            )
    return out


def flow_voice_violations(payload: Any, sandbox_ids: Iterable[str]) -> list[Violation]:
    """Execution-flow steps marked ``observed`` that cite no sandbox entry.

    ``observed`` tells a reader a sandbox watched the step happen. A step read
    from the code is ``assessed``, and the mark is the model's to choose; this
    only asks, once, when the mark and the citations disagree.
    """
    sandbox = {str(value) for value in sandbox_ids}
    out: list[Violation] = []
    for index, row in enumerate(_rows_of(payload, "steps")):
        if str(row.get("voice") or "").strip().lower() != "observed":
            continue
        if any(value in sandbox for value in _cited(row, "evidence_refs")):
            continue
        where = (
            f"the sandbox answers that recorded something are {_named_ids(sorted(sandbox))}"
            if sandbox
            else "no sandbox answer in this run recorded anything"
        )
        out.append(
            Violation(
                code=FLOW_VOICE_CODE,
                message=(
                    f"step {safe_finding_value(row.get('order', index + 1))} is marked observed "
                    f"but cites no sandbox entry ({safe_finding_value(where)}). Cite the sandbox "
                    "entry that shows "
                    "it, or mark the step assessed."
                ),
                path=f"steps.{index}.voice",
            )
        )
    return out


def configuration_citation_violations(payload: Any, known_ids: Iterable[str]) -> list[Violation]:
    """Configuration values said to be decrypted or observed that cite no entry.

    A value read off the wire or out of a decryption routine was read from a
    tool's answer, and that answer is what makes it checkable. Inferred and
    static-string values are left to their own mark.
    """
    known = {str(value) for value in known_ids}
    out: list[Violation] = []
    for index, row in enumerate(_rows_of(payload, "items")):
        how = str(row.get("how_obtained") or "").strip().lower()
        if how not in ("decrypted", "observed"):
            continue
        cited = _cited(row, "evidence_refs")
        if cited and (not known or any(value in known for value in cited)):
            continue
        out.append(
            Violation(
                code=UNCITED_CONFIGURATION_CODE,
                message=(
                    f"configuration item {safe_finding_value(index + 1)} "
                    f"({safe_finding_value(row.get('key'))}) is marked {safe_finding_value(how)} "
                    "but cites no entry in this run's evidence. Cite the entry "
                    "the value was read from, or mark how it was obtained as inferred."
                ),
                path=f"items.{index}.evidence_refs",
            )
        )
    return out


def identifier_citation_violations(payload: Any, known_ids: Iterable[str]) -> list[Violation]:
    """Host identifiers that cite no entry of this run's evidence.

    An identifier is a value the report model says it read, and the entry it
    was read in is what lets a reader check it. One with no entry the run
    issued is asked about once; the model decides whether to cite the entry or
    leave the identifier out. With no ledger to compare against, only an empty
    citation list is judged.
    """
    known = {str(value).strip().lower() for value in known_ids}
    out: list[Violation] = []
    for index, row in enumerate(_rows_of(payload, "identifiers")):
        cited = [value.lower() for value in _cited(row, "evidence_refs")]
        if cited and (not known or any(value in known for value in cited)):
            continue
        out.append(
            Violation(
                code=UNCITED_IDENTIFIER_CODE,
                message=(
                    f"identifier {safe_finding_value(index + 1)} "
                    f"({safe_finding_value(row.get('value'))}) cites no entry in this run's "
                    "evidence. Cite the ev_ id of the entry the value was read in, or leave "
                    "the identifier out."
                ),
                path=f"identifiers.{index}.evidence_refs",
            )
        )
    return out


# A technique id with a name written after it in brackets, the way a report
# writes one: "T1027 (Obfuscated Files or Information)". The name is words; a
# bracket holding an id, a count or a list is not a name and is not read.
_ID_THEN_NAME_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\s*\(([A-Za-z][A-Za-z0-9 ,:/&'\-]{2,80})\)")


def technique_name_violations(payload: Any) -> list[Violation]:
    """Technique ids written with a name the ATT&CK catalogue gives another technique.

    "T1027 (Binary Padding)" names T1027.001, and "T1027 (Indicator Removal from
    Host)" names a technique T1027 is not. A reader acts on the id and reads the
    name, and the two disagree. Asked once per id and name, with the
    catalogue's name for the id and the id the written name belongs to, from
    the vendored table; kept as written if the model keeps it. A name the
    catalogue gives the id — alone, or after its parent's name for a
    sub-technique — stands, and an id the table does not have is the
    catalogue check's question, not this one.
    """
    if payload is None:
        return []
    from maljan.memory.attck_loader import technique_entry, technique_ids_named

    def _fold(name: str) -> str:
        return " ".join(re.sub(r"[^a-z0-9]+", " ", str(name or "").lower()).split())

    seen: set[tuple[str, str]] = set()
    out: list[Violation] = []
    for text in _strings_of(payload):
        for match in _ID_THEN_NAME_RE.finditer(text):
            tid, written = match.group(1).upper(), match.group(2).strip()
            entry = technique_entry(tid)
            if entry is None or (tid, _fold(written)) in seen:
                continue
            accepted = {_fold(entry.name)}
            if "." in tid:
                parent = technique_entry(tid.split(".")[0])
                if parent is not None:
                    accepted.add(_fold(f"{parent.name} {entry.name}"))
            if _fold(written) in accepted:
                continue
            seen.add((tid, _fold(written)))
            owners = [owner for owner in technique_ids_named(written) if owner != tid]
            belongs = (
                f" The name {safe_finding_value(written)!r} is "
                f"{safe_finding_value(', '.join(owners))}'s."
                if owners
                else ""
            )
            out.append(
                Violation(
                    code=TECHNIQUE_NAME_CODE,
                    message=(
                        f"{safe_finding_value(tid)} is {safe_finding_value(entry.name)!r} in the "
                        f"ATT&CK catalogue, not {safe_finding_value(written)!r}.{belongs} Write "
                        "the catalogue's name beside the id, or the id the name belongs to."
                    ),
                    path="technique_name",
                )
            )
    return out


# What a sentence states verbatim: a span in backticks, in double quotes, in
# typographic quotes, or in single quotes that stand apart from the words
# around them (an apostrophe inside a word opens nothing). A span of any length
# is matched, so its closing mark is consumed with it; only a value of three
# characters or more is kept (``quoted_values``), so a format specifier or a
# one-letter value, which half the run's answers carry, is never the thing a
# citation is judged by.
_QUOTED_SPAN_RE = re.compile(
    r"`([^`\n]{1,300})`"
    r'|"([^"\n]{1,300})"'
    r"|“([^”\n]{1,300})”"
    r"|(?<![\w'])'([^'\n]{1,300})'(?![\w'])"
)
# Where one sentence ends and the next begins, for reading which citation a
# quoted value sits under. A new line always ends one.
_SENTENCE_END_RE = re.compile(r"(?<=[.!?])\s+(?=[A-Z(`\"“'])|\n+")
# The fields of a record whose whole value is a value the sample carries, read
# as written rather than for quotes inside it.
_VERBATIM_FIELDS = frozenset({"value", "endpoints"})
# The fields a record cites its entries in.
_CITING_FIELDS = ("evidence_refs", "evidence_ids", "evidence_ref")


@dataclass(frozen=True)
class EntryTexts:
    """Each ledger entry's text as this run holds it, lower-cased, and the tool behind it.

    The text a check reads for "is this value in that entry": the answer as
    the model received it where the run's corpus kept it, and the stored
    output where it did not. Read-only, built once per report.
    """

    texts: Mapping[str, str] = field(default_factory=dict)
    tools: Mapping[str, str] = field(default_factory=dict)
    # The entries whose text is known not to be the whole answer — shortened
    # for the model or trimmed by the byte budget. A value absent from one of
    # them may be in the part that is not here, so no absence is read off it.
    partial: frozenset[str] = frozenset()

    @classmethod
    def from_ledger(cls, ledger: Iterable[Any], corpus: Any = None) -> EntryTexts:
        """One text per entry: the corpus's copy first, the stored output after it."""
        texts: dict[str, str] = {}
        tools: dict[str, str] = {}
        partial: set[str] = set()
        for entry in ledger or ():
            written = str(getattr(entry, "id", "") or "").strip()
            entry_id = written.lower()
            if not entry_id:
                continue
            text = ""
            if corpus is not None:
                try:
                    text = str(corpus.text_for(written) or "")
                except Exception:  # noqa: BLE001 — a missing copy falls back to the stored one
                    text = ""
            text = text or str(getattr(entry, "output", "") or "").lower()
            if getattr(entry, "truncated", False):
                partial.add(entry_id)
            if text:
                texts[entry_id] = text
                tools[entry_id] = str(getattr(entry, "tool", "") or "")
        return cls(texts=texts, tools=tools, partial=frozenset(partial))

    def holds(self, entry_id: str, value: str) -> bool:
        """Whether this entry's text holds ``value`` as a value of its own, however spelt.

        A whole value, never a slice of a longer run: ``443`` is not held by an
        answer whose only ``443`` is inside a timestamp. See :func:`decidable`
        for the values no text can answer for at all.
        """
        from maljan.agents._indicator_denylists import whole_value_in

        text = self.texts.get(str(entry_id).strip().lower(), "")
        return bool(text) and any(
            whole_value_in(form, text) for form in written_forms(value.lower())
        )

    def holding(self, value: str) -> list[str]:
        """Every entry whose text holds ``value``, in ledger order; none for an undecidable one."""
        if not decidable(value):
            return []
        return [entry_id for entry_id in self.texts if self.holds(entry_id, value)]

    def named(self, entry_id: str) -> str:
        """``ev_0012 (floss)``: an id with the tool that answered it."""
        tool = self.tools.get(entry_id, "")
        return f"{entry_id} ({tool})" if tool else entry_id


# A value that is only a number — decimal, hex, dotted — is one no text can be
# said to hold or lack: an answer may write it another way (``0x12c`` for
# ``300``), and a reputation report or a strings dump holds almost every short
# number inside some longer run. Such a value raises no question and no note.
# A number: ``0x``-prefixed hex, a hex run with a digit in it (a word spelled
# only with a–f, ``added``, is a word), or digits with separators.
_ONLY_A_NUMBER_RE = re.compile(
    r"0x[0-9a-f]+|(?=[a-f]*[0-9])[0-9a-f]+|[0-9][0-9.,:]*", re.IGNORECASE
)
_WHOLE_DIGEST_RE = re.compile(
    r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}|[0-9a-f]{128}", re.IGNORECASE
)


def decidable(value: str) -> bool:
    """Whether a text can be said to hold or to lack ``value``.

    A short number is not (``443`` sits in many entries by chance); a whole
    digest is, whatever its letters.
    """
    text = str(value or "").strip()
    if _WHOLE_DIGEST_RE.fullmatch(text):
        return True
    return len(text) >= 3 and _ONLY_A_NUMBER_RE.fullmatch(text) is None


def quoted_values(text: str) -> list[str]:
    """What ``text`` states verbatim, in the order written, once each."""
    found: list[str] = []
    for match in _QUOTED_SPAN_RE.finditer(str(text or "")):
        value = next(group for group in match.groups() if group is not None).strip()
        if len(value) >= 3 and value not in found:
            found.append(value)
    return found


# One unquoted token of running text: a run of characters no space, bracket,
# comma, semicolon or quote mark ends.
_LITERAL_TOKEN_RE = re.compile(r"[^\s\[\]()<>{},;\"“”`]+")
# What a token loses at its ends before its shape is read: a sentence's
# punctuation, and the asterisks and underscores of Markdown emphasis.
_LITERAL_EDGE = ".,:;!?'*_"
# A file name: a name, a dot, and an extension a file on a host carries.
_FILE_NAME_RE = re.compile(r"[a-z0-9][\w.$~-]*\.([a-z0-9]{2,5})", re.I)
_FILE_EXTENSIONS = frozenset(
    {
        "exe",
        "dll",
        "sys",
        "scr",
        "cpl",
        "ocx",
        "drv",
        "bat",
        "cmd",
        "ps1",
        "psm1",
        "vbs",
        "vbe",
        "js",
        "jse",
        "wsf",
        "hta",
        "lnk",
        "msi",
        "dat",
        "bin",
        "tmp",
        "log",
        "txt",
        "ini",
        "cfg",
        "conf",
        "db",
        "sqlite",
        "zip",
        "rar",
        "7z",
        "cab",
        "iso",
        "img",
        "doc",
        "docx",
        "docm",
        "xls",
        "xlsx",
        "xlsm",
        "pdf",
        "rtf",
        "so",
        "elf",
        "sh",
        "py",
        "jar",
        "apk",
        "dex",
        "plist",
        "dylib",
    }
)
# The executables every Windows host carries, named bare. A sentence naming one
# ("runs cmd.exe") states how the sample works, not a value to look for, and the
# entry it cites often states the same fact without the name.
_COMMON_EXECUTABLES = frozenset(
    {
        "cmd.exe",
        "powershell.exe",
        "pwsh.exe",
        "explorer.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "svchost.exe",
        "mshta.exe",
        "wscript.exe",
        "cscript.exe",
        "conhost.exe",
        "schtasks.exe",
        "reg.exe",
        "net.exe",
        "net1.exe",
        "whoami.exe",
        "ipconfig.exe",
        "nltest.exe",
        "systeminfo.exe",
        "tasklist.exe",
        "taskkill.exe",
        "wmic.exe",
        "msiexec.exe",
        "certutil.exe",
        "bitsadmin.exe",
        "vssadmin.exe",
        "notepad.exe",
        "lsass.exe",
        "winlogon.exe",
        "services.exe",
        "csrss.exe",
        "dllhost.exe",
        "taskhostw.exe",
        "sc.exe",
        "at.exe",
        "curl.exe",
        "wget.exe",
    }
)


# Names of software written like a host or a file: a library, not a value.
_SOFTWARE_NAMES = frozenset(
    {"node.js", "vue.js", "react.js", "next.js", "express.js", "d3.js", "three.js", "socket.io"}
)


def _host_shaped(token: str) -> bool:
    """A host name under a real top-level domain, by the strings reader's own test."""
    from maljan.tools.strings import _looks_like_domain

    return bool(re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+", token, re.I)) and _looks_like_domain(
        token
    )


def _literal_shape(token: str) -> bool:
    """Whether an unquoted token is an indicator by its shape alone.

    A whole digest, a URL, a backslash path or registry key, a mailbox, a host
    under a real top-level domain, or a file name with a file's extension other
    than an executable every Windows host carries. Never technical vocabulary:
    an algorithm, an encoding, an architecture, an API constant or a tool name
    is written many ways in the entries that state it, and whether one sentence
    restates an entry is a paraphrase this check cannot judge. When in doubt
    the token is not a value and nothing is asked.
    """
    if token.lower() in _SOFTWARE_NAMES:
        return False
    if _WHOLE_DIGEST_RE.fullmatch(token):
        return True
    if "://" in token:
        return True
    if "\\" in token:
        return len(token) >= 4 and re.search(r"[a-z]", token, re.I) is not None
    if "@" in token:
        local, _, host = token.partition("@")
        return bool(local) and _host_shaped(host)
    if _host_shaped(token):
        return True
    named = _FILE_NAME_RE.fullmatch(token)
    return bool(
        named
        and named.group(1).lower() in _FILE_EXTENSIONS
        and token.lower() not in _COMMON_EXECUTABLES
    )


def literal_values(text: str) -> list[str]:
    """What ``text`` states as a literal value without quoting it, once each, in order.

    The quoted spans are :func:`quoted_values`' and the bracketed citations
    are not values; both are taken out first. Only a token whose shape makes
    it a value (:func:`_literal_shape`) and that a text can be said to hold
    (:func:`decidable`) is kept.
    """
    plain = _QUOTED_SPAN_RE.sub(" ", _CODE_SPAN_RE.sub(" ", str(text or "")))
    plain = re.sub(r"\[[^\]\n]*\]", " ", plain)
    found: list[str] = []
    for match in _LITERAL_TOKEN_RE.finditer(plain):
        token = match.group(0).strip(_LITERAL_EDGE)
        if (
            len(token) < 3
            or _EVIDENCE_ID_RE.fullmatch(token)
            or _IDENTIFIER_RE.fullmatch(token)
            or not _literal_shape(token)
            or not decidable(token)
        ):
            continue
        if token not in found:
            found.append(token)
    return found


def _ids_in(value: Any) -> list[str]:
    """The evidence ids a citing field carries, lower-cased, in order."""
    items = value if isinstance(value, list | tuple) else [value]
    ids: list[str] = []
    for item in items:
        for found in _EVIDENCE_ID_RE.findall(str(item or "")):
            if found.lower() not in ids:
                ids.append(found.lower())
    return ids


def _sentences_with_citations(text: str) -> list[tuple[str, list[str]]]:
    """Each sentence of ``text`` with the evidence ids it cites in brackets."""
    out: list[tuple[str, list[str]]] = []
    for sentence in _SENTENCE_END_RE.split(str(text or "")):
        cited: list[str] = []
        for group in _cited_groups(_CODE_SPAN_RE.sub(" ", sentence)):
            for raw in re.split(r"[,;]", group):
                item = raw.strip().lower()
                if _EVIDENCE_ID_RE.fullmatch(item) and item not in cited:
                    cited.append(item)
        if cited:
            out.append((sentence, cited))
    return out


def wrong_entry_citations(
    payload: Any, entries: EntryTexts | None, *, prose: Sequence[str] = ()
) -> list[Violation]:
    """Values a text quotes that the entry it cites does not hold, and another entry does.

    Decided only where it can be: a value the text states verbatim — in quotes
    or backticks, unquoted where its shape makes it an indicator (a digest, a
    URL, a path, a host, a file name; :func:`literal_values`), or the
    whole of a record's value — is looked for in the text of each entry cited
    for it. Found in one of them, the citation stands.
    Found in none of them but in another entry of the run, the citation points
    a reader at the wrong answer, and the model is asked once, with the entry
    that holds it offered. Found nowhere, nothing is said: a value the run's
    texts do not spell as the sentence does is a paraphrase or a composition
    this check cannot judge. The id is never rewritten.

    ``prose`` names the fields that are running text, read sentence by
    sentence under the brackets each sentence carries. Every other string is
    read under its own brackets when it has any, and otherwise under the
    citations of the record it belongs to (``evidence_refs``,
    ``evidence_ids``, ``evidence_ref``); a string with neither is not judged.
    """
    if payload is None or entries is None or not entries.texts:
        return []
    data = payload if isinstance(payload, dict) else getattr(payload, "__dict__", {}) or {}
    wrong: dict[tuple[tuple[str, ...], tuple[str, ...]], list[str]] = {}

    def _ask(value: str, cited: Sequence[str]) -> None:
        value = str(value or "").strip()
        known = [entry_id for entry_id in cited if entry_id in entries.texts]
        if not decidable(value) or not known:
            return
        if any(entries.holds(entry_id, value) for entry_id in known):
            return
        if any(entry_id in entries.partial for entry_id in known):
            # A cited entry that is not the whole answer may hold it in the
            # part that is missing; no "is not in" is said of it.
            return
        holders = entries.holding(value)
        if not holders:
            return
        values = wrong.setdefault((tuple(known), tuple(holders)), [])
        if value not in values:
            values.append(value)

    def _read_prose(text: Any) -> None:
        for sentence, cited in _sentences_with_citations(str(text or "")):
            for value in [*quoted_values(sentence), *literal_values(sentence)]:
                _ask(value, cited)

    def _walk(node: Any, depth: int = 0) -> None:
        if depth > 4:
            return
        if isinstance(node, list | tuple):
            for item in node:
                _walk(item, depth + 1)
            return
        if not isinstance(node, dict):
            return
        refs: list[str] = []
        for key in _CITING_FIELDS:
            refs.extend(ref for ref in _ids_in(node.get(key)) if ref not in refs)
        for key, value in node.items():
            if key in _CITING_FIELDS:
                continue
            if isinstance(value, str):
                if _sentences_with_citations(value):
                    _read_prose(value)
                elif refs:
                    if key in _VERBATIM_FIELDS:
                        _ask(value, refs)
                    for stated in [*quoted_values(value), *literal_values(value)]:
                        _ask(stated, refs)
            elif key in _VERBATIM_FIELDS and isinstance(value, list | tuple) and refs:
                for item in value:
                    if isinstance(item, str):
                        _ask(item, refs)
            else:
                _walk(value, depth + 1)

    for key in prose:
        if isinstance(data.get(key), str):
            _read_prose(data.get(key))
    _walk({key: value for key, value in data.items() if key not in prose})
    for key in prose:
        if not isinstance(data.get(key), str):
            _walk(data.get(key))

    violations: list[Violation] = []
    for (cited, holders), values in wrong.items():
        quoted = safe_finding_value(", ".join(repr(value) for value in values[:_MAX_NAMED_IDS]))
        more = len(values) - _MAX_NAMED_IDS
        named = safe_finding_value(", ".join(entries.named(i) for i in cited))
        holding = safe_finding_value(", ".join(entries.named(i) for i in holders[:_MAX_NAMED_IDS]))
        message = (
            f"{quoted} is not in {named}, which the text cites for it; this run's evidence "
            f"holds it in {holding}. Cite the entry that holds the value the text states."
            if len(values) == 1
            else f"{quoted} are not in {named}, which the text cites for them; this run's "
            f"evidence holds them in {holding}"
            f"{' (with ' + safe_finding_value(more) + ' more)' if more > 0 else ''}. "
            "Cite the entry that holds the value the text states."
        )
        violations.append(
            Violation(code=CITATION_WRONG_ENTRY_CODE, message=message, path="citation")
        )
    return violations


# A statement that an entry holds nothing, or one line and no more. Asked of
# the entry itself: one live report's key finding said the capture entry
# "holds only a header line with no parsed flows" about an entry listing its
# packet count, its protocols and fifteen conversations.
_HOLDING_VERBS = r"(?:holds|held|contains|contained|carries|carried|has|had|records|recorded|returned|returns|shows|showed|lists|listed)"  # noqa: E501
_HOLDS_NOTHING_RE = re.compile(
    rf"\b{_HOLDING_VERBS}\s+(?:nothing|no\s+(?:data|content|contents|output|entries|rows|"
    r"records|values|lines))\b|\b(?:is|was|came\s+back)\s+empty\b",
    re.IGNORECASE,
)
_HOLDS_ONE_LINE_RE = re.compile(
    rf"\b{_HOLDING_VERBS}\s+(?:only|just|nothing\s+but|no\s+more\s+than)\s+"
    r"(?:a|an|one|the|its)?\s*(?:single\s+)?(?:header(?:\s+line)?|heading|line|row|record|"
    r"value|field)\b",
    re.IGNORECASE,
)
# How many words before the verb name what the statement is about.
_SUBJECT_WORDS = 6
# Words a statement uses for an entry that its tool's own name does not carry.
_TOOL_WORDS: dict[str, tuple[str, ...]] = {
    "pcap": ("capture", "packet", "packets", "pcap"),
    "floss": ("decoded", "emulation", "floss"),
    "sigma": ("sigma", "rule", "rules"),
    "yara": ("yara", "rule", "rules"),
}


def _held_values(text: str) -> int:
    """How many values an entry's text holds: its non-empty lines, read through its JSON.

    A zero, an empty string and an empty list hold nothing, so an answer that
    records an absence (``{"registry": [], "total": 0}``) holds none.
    """
    import json as _json

    try:
        parsed: Any = _json.loads(text)
    except (ValueError, TypeError):
        return sum(1 for line in str(text).splitlines() if line.strip())

    def _count(node: Any) -> int:
        if isinstance(node, dict):
            return sum(_count(value) for value in node.values())
        if isinstance(node, list | tuple):
            return sum(_count(item) for item in node)
        if isinstance(node, bool) or node is None:
            return 0
        if isinstance(node, int | float):
            return 1 if node else 0
        return sum(1 for line in str(node).splitlines() if line.strip())

    return _count(parsed)


def _tool_words(tool: str) -> set[str]:
    words = {part for part in re.split(r"[_\W]+", tool.lower()) if len(part) >= 3}
    for part in list(words):
        words.update(_TOOL_WORDS.get(part, ()))
    return words


def _statement_subject(
    entries: EntryTexts, sentence: str, verb_at: int, cited: list[str]
) -> list[str]:
    """The cited entries the statement's subject names, and none when it names none.

    Named by its id written in the subject, or by a word for a recorded answer
    (``entry``, ``output``, ``result``, ``summary``, ``view``, ``answer``)
    beside a word of the entry's tool. A sentence about the sample — "the
    config buffer was empty until the routine ran" — names no entry, whatever
    it cites, and is not judged.
    """
    window = sentence[:verb_at].lower()
    before = re.split(r"[^\w-]+", window)
    subject = {w for word in before[-_SUBJECT_WORDS:] for w in word.split("-") if w}
    by_id = [entry_id for entry_id in cited if entry_id.lower() in subject]
    if by_id:
        return by_id
    if not subject & _ENTRY_NOUNS:
        return []
    return [
        entry_id for entry_id in cited if subject & _tool_words(entries.tools.get(entry_id, ""))
    ]


# The words a sentence names a recorded answer by, rather than something the
# sample holds or does.
_ENTRY_NOUNS = frozenset({"entry", "output", "result", "summary", "view", "answer", "capture"})


def misstated_entry_contents(
    payload: Any, entries: EntryTexts | None, *, prose: Sequence[str] = ()
) -> list[Violation]:
    """Statements that an entry holds nothing, or one line, where the entry holds more.

    Read sentence by sentence under the brackets each sentence cites. The
    statement is about the cited entry its subject names (``the capture
    entry`` names the capture summary's, as does its id), and about no other. It is
    checked against that entry's own text: a statement that it holds nothing is
    false when the entry holds a value, one that it holds one line when it
    holds more. An entry whose text is not the whole answer is not judged. The
    model is asked once; the statement is never rewritten.
    """
    if payload is None or entries is None or not entries.texts:
        return []
    found: list[tuple[str, str, int, str]] = []

    def _read(text: Any) -> None:
        for sentence, cited in _sentences_with_citations(str(text or "")):
            for pattern, most, said in (
                (_HOLDS_NOTHING_RE, 0, "holds nothing"),
                (_HOLDS_ONE_LINE_RE, 1, "holds one line and no more"),
            ):
                match = pattern.search(sentence)
                if match is None:
                    continue
                known = [i for i in cited if i in entries.texts]
                for entry_id in _statement_subject(entries, sentence, match.start(), known):
                    if entry_id in entries.partial:
                        continue
                    held = _held_values(entries.texts[entry_id])
                    if held > most:
                        found.append((entry_id, said, held, sentence.strip()))
                break

    def _walk(node: Any, depth: int = 0) -> None:
        if depth > 4:
            return
        if isinstance(node, str):
            _read(node)
        elif isinstance(node, list | tuple):
            for item in node:
                _walk(item, depth + 1)
        elif isinstance(node, dict):
            for value in node.values():
                _walk(value, depth + 1)

    data = payload if isinstance(payload, dict) else getattr(payload, "__dict__", {}) or {}
    _walk(data)
    del prose  # every string is read under the brackets it carries

    violations: list[Violation] = []
    seen: set[str] = set()
    for entry_id, said, held, sentence in found:
        if entry_id in seen:
            continue
        seen.add(entry_id)
        named = safe_finding_value(entries.named(entry_id))
        violations.append(
            Violation(
                code=ENTRY_CONTENTS_MISSTATED_CODE,
                message=(
                    f"The text says {named} {safe_finding_value(said)} "
                    f"({safe_finding_value(sentence[:200])!r}); {named} holds "
                    f"{safe_finding_value(held)} values in "
                    "this run. State what the entry holds, or cite the entry the statement is "
                    "about."
                ),
                path="citation",
            )
        )
    return violations


# ---------------------------------------------------------------------------
# The judge's bundle
# ---------------------------------------------------------------------------


# The identity fields whose values count as grounded without a ledger entry.
_IDENTITY_INDICATOR_KEYS = ("sha256", "sha1", "md5", "file_name")


def sample_identity_values(sample: Any) -> set[str]:
    """The sample's own identity values, as grounded as anything a tool saw.

    They come from the router rather than from a tool the model chose, and the
    judge is shown them in its identity block. A run that never called
    ``hashes`` has no ledger entry carrying the sha256 the job was queued
    under, and an indicator naming that hash was flagged as invented.
    """
    data = sample if isinstance(sample, dict) else {}
    values = {str(data.get(key) or "").strip() for key in _IDENTITY_INDICATOR_KEYS}
    return {value for value in values if value}


INDICATOR_TYPE_CONTRADICTS_VERDICT_CODE = "stix.indicator_type_contradicts_verdict"

# The word this export will not let a Benign verdict publish unasked, and the
# rest of the STIX indicator-type vocabulary the judge may reach for instead.
_MALICIOUS_ACTIVITY = "malicious-activity"
_MILDER_INDICATOR_TYPES = ("benign", "anomalous-activity", "unknown")


def _is_the_samples_own_indicator(pattern: str, identity: set[str]) -> bool:
    """Whether this indicator names the sample rather than something it touched.

    The export mints one indicator for the sample's own hash and types it with
    the verdict, so an indicator quoting an identity value is that statement
    and not a claim about a third party.
    """
    return any(literal.lower() in identity for _path, literal in _comparisons(pattern))


def indicator_type_contradicts_verdict(
    obj: Any, *, verdict: str | None, identity: set[str], path: str
) -> list[Violation]:
    """A judge-written indicator that says the opposite of the judge's verdict.

    The type is the judge's to give: nothing rewrites it and nothing drops the
    object. On a Benign verdict an indicator typed ``malicious-activity``
    publishes the sample's own vendor domain to a blocklist as malicious
    activity, so the judge is asked about it once, with the vocabulary's milder
    words named and its own answer published whichever way it goes.

    One direction only. A Malware verdict beside an indicator typed ``benign``
    is not the same statement: an indicator is a claim about the value it
    names, and a malicious sample may well touch something harmless.
    """
    if verdict != BENIGN_VERDICT:
        return []
    types = [str(t).strip().lower() for t in (getattr(obj, "indicator_types", None) or [])]
    if _MALICIOUS_ACTIVITY not in types:
        return []
    pattern = str(getattr(obj, "pattern", "") or "")
    if _is_the_samples_own_indicator(pattern, identity):
        return []
    named = str(getattr(obj, "name", "") or "").strip() or pattern
    return [
        Violation(
            code=INDICATOR_TYPE_CONTRADICTS_VERDICT_CODE,
            message=(
                f"the indicator {safe_finding_value(named)!r} is typed "
                f"{_MALICIOUS_ACTIVITY!r} while the verdict you stated is {BENIGN_VERDICT}, "
                "so this bundle publishes the value as malicious activity to whoever reads it. "
                f"The indicator-type vocabulary also has {', '.join(_MILDER_INDICATOR_TYPES)}. "
                "Retype it, or restate the verdict, or keep the type as it is — whichever "
                "you answer is what this run publishes, and a type you keep is recorded "
                "beside the bundle as raised and kept."
            ),
            path=path,
        )
    ]


UNKNOWN_OBSERVABLE_TYPE_CODE = "stix.unknown_observable_type"
IS_FAMILY_MISSING_CODE = "stix.is_family_missing"
FILE_UNIDENTIFIED_CODE = "stix.file_unidentified"
UNKNOWN_OBJECT_PATH_CODE = "stix.unknown_object_path"
STRAY_BACKSLASH_CODE = "stix.unescaped_backslash"
PATTERN_REFUSED_CODE = "stix.pattern_refused"
INDICATOR_TYPE_VOCABULARY_CODE = "stix.indicator_type_vocabulary"

# STIX 2.1's indicator-type vocabulary. Open, so a value outside it is legal
# and published as written; it is asked about because a value outside it is
# almost always the kind of the value (``ip-addr``, ``file``) written where the
# vocabulary says what the value indicates.
INDICATOR_TYPES = (
    "malicious-activity",
    "anomalous-activity",
    "benign",
    "compromised",
    "anonymization",
    "attribution",
    "unknown",
)


def unknown_observable_type_violations(obj: Any, *, path: str) -> list[Violation]:
    """A judge indicator whose pattern the grammar refuses: its type, its path, its escapes.

    Asked, never rewritten: the sentence says which type the value is when the
    value or the spelling answers that, and lists the types when neither does.
    A path the type does not have and a value with a backslash the grammar
    cannot read are asked the same way. An indicator that keeps any of them is
    left out of the export, which records why
    (``reporting.renderers.stix_renderer``).
    """
    from maljan.schemas.stix_pattern import (
        CYBER_OBSERVABLE_TYPES,
        is_observable_type,
        object_path_problems,
        observable_type_for,
        pattern_refusal,
        stray_backslash_values,
    )

    pattern = str(getattr(obj, "pattern", "") or "")
    named = str(getattr(obj, "name", "") or "").strip() or pattern
    out: list[Violation] = []
    seen: set[str] = set()
    for comparison in read_comparisons(pattern):
        written = comparison.written_type or comparison.object_type
        if not written or written in seen or is_observable_type(written):
            continue
        seen.add(written)
        meant = observable_type_for(written, comparison.literal)
        if meant:
            answer = (
                f"{safe_finding_value(comparison.literal)!r} is an {meant}: write the "
                f"comparison over {meant}:{comparison.prop}, or drop the indicator."
            )
        else:
            answer = (
                "The types a pattern can name are "
                f"{', '.join(sorted(CYBER_OBSERVABLE_TYPES))}, or a custom type whose name "
                "starts with x-: write the comparison over the one the value is, or drop "
                "the indicator."
            )
        out.append(
            Violation(
                code=UNKNOWN_OBSERVABLE_TYPE_CODE,
                message=(
                    f"the indicator {safe_finding_value(named)!r} compares "
                    f"{safe_finding_value(written)!r}, which is not a STIX Cyber-observable "
                    "type, so no consumer holds an object this pattern could match. "
                    f"{answer} An indicator that keeps it is not exported."
                ),
                path=path,
            )
        )
    for problem in object_path_problems(pattern):
        out.append(
            Violation(
                code=UNKNOWN_OBJECT_PATH_CODE,
                message=(
                    f"the indicator {safe_finding_value(named)!r} compares a path its type does "
                    f"not have: {safe_finding_value(problem)}. A pattern over it matches nothing "
                    "a consumer holds. Write the comparison over a property the type defines, "
                    "or drop the indicator; an indicator that keeps it is not exported."
                ),
                path=path,
            )
        )
    stray = stray_backslash_values(pattern)
    if stray:
        out.append(
            Violation(
                code=STRAY_BACKSLASH_CODE,
                message=(
                    f"the indicator {safe_finding_value(named)!r} quotes "
                    f"{len(stray)} value(s) with a "
                    "backslash the pattern grammar cannot read: inside a quoted value a STIX "
                    "pattern "
                    "escapes the quote and the backslash and nothing else, so every backslash "
                    "of the value is written twice in the pattern (four times in the JSON "
                    "string that carries it). Write it so, or drop the indicator; an indicator "
                    "that keeps it is not exported."
                ),
                path=path,
            )
        )
    # Anything else the grammar refuses, asked in the grammar's own words when
    # none of the questions above named it: a comparison with nothing to
    # compare, a value written in double quotes, text after the expression
    # closed. A digest the wrong length is the grounding check's question.
    from maljan.agents._indicator_denylists import malformed_hash_in

    refusal = (
        "" if out or not pattern.strip() or malformed_hash_in(pattern) else pattern_refusal(pattern)
    )
    if refusal:
        out.append(
            Violation(
                code=PATTERN_REFUSED_CODE,
                message=(
                    f"the indicator {safe_finding_value(named)!r} is not a pattern the STIX "
                    f"grammar reads: {safe_finding_value(refusal)}. A consumer's parser refuses "
                    "it whole. Write the comparison whole — an object path, an operator and a "
                    "quoted value, in brackets — or drop the indicator; an indicator that keeps "
                    "it is not exported."
                ),
                path=path,
            )
        )
    return out


SHAPE_NAMES_A_VALUE_CODE = "stix.shape_names_a_value"

# The shortest fixed text of a shape that says anything about which value the
# evidence holds: shorter runs are found in any evidence at all.
_SHAPE_TEXT_MIN = 4


def shape_names_a_value_violations(
    obj: Any, haystack: Haystack, stated_values: set[str], *, path: str
) -> list[Violation]:
    """A ``LIKE`` or ``MATCHES`` whose fixed text is a value this run holds: asked about ``=``.

    A ``LIKE`` names every value that fits it, and the export publishes values:
    the one publish rule answers for a value, so a shape over an endpoint or a
    kind the rule answers for is declined. When the text between its wildcards
    is one run that the evidence holds as a value of its own, or that another
    of the judge's indicators compares with ``=``, the judge most likely read
    that value and wrote a shape of it — the reference run wrote every decoded
    host as ``LIKE '%host%'``. It is asked once whether it means the value; what
    it keeps is its decision, and a shape it keeps is declined as before.
    """
    from maljan.reporting.renderers.stix_renderer import shape_is_asked_the_rule
    from maljan.schemas.stix_pattern import like_fixed_text, matches_fixed_text

    pattern = str(getattr(obj, "pattern", "") or "")
    named = str(getattr(obj, "name", "") or "").strip() or pattern
    out: list[Violation] = []
    for comparison in read_comparisons(pattern):
        if comparison.operator not in ("like", "matches") or not comparison.readable:
            continue
        if not shape_is_asked_the_rule(comparison):
            continue
        fixed = (
            like_fixed_text(comparison.literal)
            if comparison.operator == "like"
            else matches_fixed_text(comparison.literal)
        )
        if len(fixed) != 1:
            continue
        value = fixed[0].strip()
        operator = safe_finding_value(comparison.operator.upper())
        if len(value) < _SHAPE_TEXT_MIN or not (
            value.lower() in stated_values or haystack.holds_value(value)
        ):
            continue
        written_as = _path_for_the_value(comparison.path, value)
        # A URL is scrubbed to its scheme and host in any stored sentence, so
        # the whole URL is named by what it is rather than quoted cut short.
        suggestion = (
            "url:value = the whole URL, exactly as the LIKE writes it between its wildcards"
            if written_as == "url:value"
            else f"{safe_finding_value(written_as)} = {safe_finding_value(value)!r}"
        )
        out.append(
            Violation(
                code=SHAPE_NAMES_A_VALUE_CODE,
                message=(
                    f"the indicator {safe_finding_value(named)!r} compares "
                    f"{safe_finding_value(comparison.path)} with {operator} "
                    f"{safe_finding_value(comparison.literal)!r}, which names every value that "
                    "fits it; the export publishes values, so it is not exported as written. "
                    f"This run holds {safe_finding_value(value)!r} as a value of its own: if you "
                    f"mean that value, write {suggestion}; or keep the {operator}, and it is not "
                    "exported."
                ),
                path=path,
            )
        )
    return out


def _path_for_the_value(path: str, value: str) -> str:
    """The object path a value is written under so the one publish rule can answer for it.

    A host a ``url`` shape was written around is a host, not a URL: written as
    ``url:value = 'host'`` it is declined as a URL with no host, and the rule is
    never asked. It is suggested as the type it is — ``domain-name:value``, or
    the address family an address belongs to — and a whole URL, scheme and all,
    stays ``url:value``. Every other path is suggested as the shape wrote it.
    """
    if path not in ("url:value", "domain-name:value"):
        return path
    text = str(value).strip()
    if "://" in text:
        return "url:value"
    try:
        return f"ipv{ipaddress.ip_address(text.strip('[]')).version}-addr:value"
    except ValueError:
        pass
    from maljan.extractors.network_extractor import host_is_public

    return "domain-name:value" if "/" not in text and host_is_public(text) else path


def indicator_type_vocabulary_violations(obj: Any, *, path: str) -> list[Violation]:
    """A judge indicator typed with a word outside STIX's indicator-type vocabulary.

    Asked once and published as answered: the vocabulary is open, and a value
    the judge keeps is a legal one.
    """
    written = [str(t).strip() for t in (getattr(obj, "indicator_types", None) or [])]
    outside = [t for t in written if t.lower() not in INDICATOR_TYPES]
    if not outside:
        return []
    named = str(getattr(obj, "name", "") or "").strip() or str(getattr(obj, "pattern", ""))
    return [
        Violation(
            code=INDICATOR_TYPE_VOCABULARY_CODE,
            message=(
                f"the indicator {safe_finding_value(named)!r} is typed "
                f"{', '.join(repr(safe_finding_value(t)) for t in outside)}; indicator_types "
                "says what the value indicates, not what kind of value it is, and STIX's "
                f"vocabulary for it is {', '.join(INDICATOR_TYPES)}. Use one of those, or "
                "keep the type — whichever you answer is what this run publishes."
            ),
            path=path,
        )
    ]


ANNOTATION_OUT_OF_SCHEMA_CODE = "stix.annotation_out_of_schema"


def annotation_out_of_schema_violations(
    bundle: Any, origins: Sequence[tuple[int | None, str]] | None = None
) -> list[Violation]:
    """A relationship annotation the schema does not describe, asked about as written.

    A confidence that is not a number from 0.0 to 1.0, a basis outside the
    list, credited agents written as something other than a list of names.
    The values are kept: a reader takes a confidence only when it is one
    (``schemas.stix_models.stated_confidence``), and the judge is told what
    the property holds.
    """
    from maljan.schemas.stix_models import EvidenceBasis, stated_confidence

    bases = get_args(EvidenceBasis)
    out: list[Violation] = []
    for index, obj in enumerate(list(getattr(bundle, "objects", None) or [])):
        where = _object_path(index, origins)
        if str(getattr(obj, "type", "") or "") != "relationship":
            continue
        problems: list[str] = []
        confidence = getattr(obj, "x_maljan_confidence", None)
        if confidence is not None and stated_confidence(confidence) is None:
            problems.append(
                f"x_maljan_confidence is {safe_finding_value(confidence)!r}, and it is a number "
                "from 0.0 to 1.0"
            )
        basis = getattr(obj, "x_maljan_evidence_basis", None)
        if basis is not None and basis not in bases:
            problems.append(
                f"x_maljan_evidence_basis is {safe_finding_value(basis)!r}, and it is one of "
                f"{', '.join(bases)}"
            )
        agents = getattr(obj, "x_maljan_contributing_agents", None)
        if agents is not None and not isinstance(agents, list):
            problems.append(
                f"x_maljan_contributing_agents is {safe_finding_value(agents)!r}, and it is a "
                "list of source names"
            )
        if problems:
            out.append(
                Violation(
                    code=ANNOTATION_OUT_OF_SCHEMA_CODE,
                    message=(
                        f"the relationship at {where}: {'; '.join(problems)}. Write "
                        "it that way, or leave the property out; a value you keep is published "
                        "as written and read as no number."
                    ),
                    path=where,
                )
            )
    return out


CREDIT_WITHOUT_CLAIM_CODE = "stix.credit_without_claim"


def credited_agents(obj: Any) -> list[str]:
    """The names a relationship credits, whether written as a list or as one name."""
    agents = getattr(obj, "x_maljan_contributing_agents", None)
    if isinstance(agents, str):
        return [agents] if agents.strip() else []
    return [str(a) for a in (agents or []) if str(a).strip()]


# The words a model adds to an agent's name when it writes one down. The
# evidence summary names a source ``static`` and the judge credits
# ``STATIC ANALYST``, ``static_analyst`` or ``Static-Analyst``: one source.
_NAME_FILLER = frozenset({"analyst", "agent", "the"})


def _source_key(name: Any) -> str:
    """A source name reduced to what identifies it, for comparing two spellings."""
    words = re.split(r"[^a-z0-9]+", str(name or "").lower())
    return "".join(word for word in words if word and word not in _NAME_FILLER)


def _same_source(credited: str, named: str) -> bool:
    """Whether a credited name and a summary's source name are one source.

    Equal once reduced, or one the start of the other with three characters at
    least, so ``yara`` is the ``yara_scan`` tool and ``s`` is nobody.
    """
    if not credited or not named:
        return False
    if credited == named:
        return True
    short, long_ = sorted((credited, named), key=len)
    return len(short) >= 3 and long_.startswith(short)


def _related_ids(tid: str) -> set[str]:
    """The id itself, and its parent when it is a sub-technique."""
    return {tid, tid.split(".", 1)[0]}


@dataclass(frozen=True)
class UnconfirmedCredit:
    """A relationship crediting agents with a technique none of them named."""

    index: int
    technique: str
    uncredited: tuple[str, ...]
    sources: tuple[str, ...]


def unconfirmed_credits(
    bundle: Any, technique_sources: Mapping[str, Sequence[str]] | None
) -> list[UnconfirmedCredit]:
    """Per relationship, the credited names no source of that name stands behind.

    ``technique_sources`` is who named which technique in this run — the
    evidence summary the judge was shown, as ``{technique id: [source]}``.
    ``None`` answers nothing: with no record of the sources, no credit can be
    weighed against one. A technique counts as named by a source that named it,
    its parent technique or one of its sub-techniques: refining an analyst's
    T1071 to T1071.004 is the judge's reading, not a misattribution. The same
    answer serves the question the judge is asked and the export's decision
    about a credit the judge kept.
    """
    if technique_sources is None:
        return []
    named_by: dict[str, list[str]] = {}
    for raw_tid, sources in technique_sources.items():
        tid = str(raw_tid or "").strip().upper()
        for related in _related_ids(tid):
            bucket = named_by.setdefault(related, [])
            bucket.extend(str(s) for s in sources if str(s) not in bucket)
    objects = list(getattr(bundle, "objects", None) or [])
    technique_of: dict[str, str] = {}
    for obj in objects:
        if str(getattr(obj, "type", "") or "") == "attack-pattern":
            declared = _attack_pattern_technique_id(obj)
            if declared:
                technique_of[str(getattr(obj, "id", "") or "")] = declared.upper()
    out: list[UnconfirmedCredit] = []
    for index, obj in enumerate(objects):
        if str(getattr(obj, "type", "") or "") != "relationship":
            continue
        credited = credited_agents(obj)
        if not credited:
            continue
        written = str(getattr(obj, "x_maljan_technique_id", "") or "").strip().upper()
        tid = str(
            written
            or technique_of.get(str(getattr(obj, "target_ref", "") or ""))
            or technique_of.get(str(getattr(obj, "source_ref", "") or ""))
            or ""
        )
        if not tid:
            continue
        sources = list(
            dict.fromkeys(s for related in _related_ids(tid) for s in named_by.get(related, []))
        )
        keys = [_source_key(s) for s in sources]
        uncredited = tuple(
            name for name in credited if not any(_same_source(_source_key(name), k) for k in keys)
        )
        if uncredited:
            out.append(UnconfirmedCredit(index, tid, uncredited, tuple(sources)))
    return out


def credit_without_claim_violations(
    bundle: Any,
    technique_sources: Mapping[str, Sequence[str]] | None,
    origins: Sequence[tuple[int | None, str]] | None = None,
) -> list[Violation]:
    """A judge relationship crediting an agent with a technique it never named.

    Asked, and never rewritten in the judge's own bundle. A credit the judge
    keeps is not published: the export leaves the names no source stands
    behind off its copy of the relationship and records it
    (``stix.unpublishable_credit``).
    """
    out: list[Violation] = []
    for credit in unconfirmed_credits(bundle, technique_sources):
        where = _object_path(credit.index, origins)
        tid = safe_finding_value(credit.technique)
        who = (
            f"the sources that named {tid} are "
            f"{', '.join(safe_finding_value(s) for s in credit.sources)}"
            if credit.sources
            else f"no source in this run named {tid}"
        )
        out.append(
            Violation(
                code=CREDIT_WITHOUT_CLAIM_CODE,
                message=(
                    f"the relationship at {where} credits "
                    f"{', '.join(repr(safe_finding_value(n)) for n in credit.uncredited)} with "
                    f"{tid}, and {who} — the evidence summary lists who named each technique. "
                    "Credit only sources that named it, by the names the summary gives them, "
                    "or leave x_maljan_contributing_agents empty. A credit you keep that names "
                    "no source is not published."
                ),
                path=where,
                subject=str(credit.technique).strip().upper(),
            )
        )
    return out


def validate_verdict_bundle(
    bundle: Any,
    evidence_corpus: set[str] | None = None,
    *,
    attck: Any = None,
    sample: Any = None,
    shortened_tools: Iterable[str] = (),
    searched: Iterable[str] = (),
    corpus_state: CorpusState | None = None,
    technique_sources: Mapping[str, Sequence[str]] | None = None,
    origins: Sequence[tuple[int | None, str]] | None = None,
) -> list[Violation]:
    """What is wrong with the judge's answer, in the judge's own terms.

    ``technique_sources`` is who named which technique in this run, the
    evidence summary as data; a relationship crediting an agent with a
    technique that agent never named is asked about against it. ``None`` asks
    nothing, which is what a caller with no such record passes.

    ``attck`` is the same knowledge module the analyst loop consults, and it is
    the same check: an id is unresolvable when the catalogue does not have it,
    not when it fails a regex. ``T7777`` is well-formed and imaginary, which is
    exactly the case this violation exists for. Passing ``None`` skips the
    catalogue question rather than answering it wrongly.

    ``sample`` is the identity block's dict; a quoted value equal to one of
    its hashes or its file name counts as found, the way a corpus hit does.
    They are kept out of the corpus haystack, which is searched by substring:
    the file name is whatever the submitter typed, and a name carrying an
    address would otherwise ground an indicator for it. A pattern is grounded
    when one of its quoted values is found, in the corpus or in the identity,
    as it always was for the corpus alone; the denylists run first either way.

    ``shortened_tools`` names the tools whose answers reached the corpus with
    rows missing. It changes no verdict: it is one sentence added to an
    absence, so a judge reading one knows which call to narrow.

    ``searched`` is what the run's own tools answered, each answer as itself
    and already lower-cased by the corpus that kept it. It is passed beside
    ``evidence_corpus`` rather than inside it because joining the run's whole
    record into one token copied it twice more for nothing.

    ``corpus_state`` says whether the evidence searched is this run's whole
    record. When it is not — the in-memory corpus hit its ceiling, or there is
    no corpus and the stored entries fell back on had been blanked by the byte
    budget — an absence is written as an **advisory** row: the judge is told
    once, in a sentence that says what was searched and what was not, and
    nothing drops its object for it. Passing ``None`` means the caller knows
    the corpus was whole, which is the default every existing caller had.
    """
    violations: list[Violation] = []
    objects = list(getattr(bundle, "objects", None) or [])
    scope = expected_technique_scope(sample)

    # The token corpus and the run's own answers, each as itself. The tokens
    # are short and are joined once; the answers are searched where they are.
    haystack = Haystack(
        [
            " ".join(sorted(evidence_corpus)).lower() if evidence_corpus else "",
            *(str(part) for part in searched),
        ]
    )
    identity = {value.lower() for value in sample_identity_values(sample)}
    # The verdict as the judge stated it, read the one way every reader of a
    # verdict reads it, so an indicator is weighed against the word that will
    # be published rather than against the object set.
    from maljan.pipeline.outcome import read_stated_verdict

    stated_verdict = read_stated_verdict(bundle).recognised
    runtime_paths = _runtime_paths(evidence_corpus)
    partial = shortened_evidence_note(shortened_tools)
    how_whole = corpus_state or CorpusState()
    # Neither source. The token corpus holds the sandbox report's network
    # entries and the run's own answers travel beside it, so a run with no
    # sandbox block and no answers searched nothing at all — and a check that
    # searched nothing may not conclude from it. It says so instead: the row is
    # written, it is advisory, and the judge keeps its object. Gating the whole
    # branch on the token corpus alone skipped the check outright on mock mode,
    # a static-only team, a failed submission and any sample that made no
    # network call, and an invented indicator was exported with nothing said.
    if not haystack:
        how_whole = both_searched(how_whole, NOTHING_SEARCHED)
    not_searched = partial_evidence_note(how_whole)
    # Every value the bundle's own indicators compare with ``=``: a shape whose
    # fixed text is one of them names a value the judge already wrote whole.
    stated_values = {
        comparison.literal.strip().lower()
        for obj in objects
        if str(getattr(obj, "type", "") or "") == "indicator"
        for comparison in read_comparisons(str(getattr(obj, "pattern", "") or ""))
        if comparison.operator == "=" and comparison.literal.strip()
    }
    for index, obj in enumerate(objects):
        where = _object_path(index, origins)
        kind = str(getattr(obj, "type", "") or "")
        if kind == "indicator":
            pattern = str(getattr(obj, "pattern", "") or "")
            violations.extend(
                shape_names_a_value_violations(obj, haystack, stated_values, path=where)
            )
            violations.extend(
                indicator_type_contradicts_verdict(
                    obj,
                    verdict=stated_verdict,
                    identity=identity,
                    path=where,
                )
            )
            violations.extend(unknown_observable_type_violations(obj, path=where))
            violations.extend(indicator_type_vocabulary_violations(obj, path=where))
            problem = _indicator_problem(pattern, haystack, runtime_paths, identity)
            if problem:
                absent = _is_an_absence(problem)
                caveat = f"{partial}{not_searched}" if absent else ""
                violations.append(
                    Violation(
                        code="stix.ungrounded_indicator",
                        message=(
                            f"{safe_finding_value(problem)} Emit indicators only for values a "
                            "tool in this run actually saw, and prefer zero indicators to an "
                            f"invented one.{caveat}"
                        ),
                        path=where,
                        # Only an absence goes advisory, and only when the
                        # evidence searched was partial. A denylisted host or a
                        # malformed digest is refused on its own account and no
                        # amount of evidence would change it.
                        advisory=absent and how_whole.partial,
                    )
                )
        elif kind == "file" and not getattr(obj, "hashes", None) and not getattr(obj, "name", None):
            violations.append(
                Violation(
                    code=FILE_UNIDENTIFIED_CODE,
                    message=(
                        f"the file at {where} has neither hashes nor name, and STIX needs at "
                        "least one of them to say which file it is. Give it the hashes or the "
                        "name a tool in this run reported, or leave it out; a file kept with "
                        "neither is not exported."
                    ),
                    path=where,
                )
            )
        elif kind == "malware" and getattr(obj, "is_family", None) is None:
            named = str(getattr(obj, "name", "") or "").strip()
            violations.append(
                Violation(
                    code=IS_FAMILY_MISSING_CODE,
                    message=(
                        f"the malware object {safe_finding_value(named)!r} does not say "
                        "is_family, which STIX requires: false when the object stands for "
                        "this one sample, true when it stands for a family. Nothing is "
                        "filled in for you."
                    ),
                    path=where,
                    subject=named or str(getattr(obj, "id", "") or ""),
                )
            )
        elif kind == "attack-pattern":
            tid = _attack_pattern_technique_id(obj)
            if not tid:
                # A technique with a name and no id used to skip every check
                # below, because all of them key on the id — which is how an
                # Android sample's attack-patterns reached a report with the
                # Mobile-domain check never having run on them, and how three
                # of them were published as ATT&CK techniques with an empty
                # `technique_id`. It is asked for once here; if it survives,
                # the report carries it as an unmapped behaviour.
                name = str(getattr(obj, "name", "") or "").strip()
                violations.append(
                    Violation(
                        code=MISSING_ID_CODE,
                        message=(
                            f"the attack-pattern {safe_finding_value(name)!r} names no MITRE "
                            "ATT&CK technique id. "
                            "Give its external_references a mitre-attack entry with the "
                            "external_id (T#### or T####.###), or drop the object and say "
                            "what was observed in the assessment: a behaviour with no "
                            "technique id is reported as a behaviour, not as a technique."
                        ),
                        path=where,
                    )
                )
                continue
            if not TECHNIQUE_ID_EXACT_RE.match(tid):
                violations.append(
                    Violation(
                        code="stix.unknown_technique",
                        message=(
                            f"the attack-pattern names {safe_finding_value(tid)}, which is "
                            "not shaped like a MITRE ATT&CK technique id (T#### or T####.###)."
                        ),
                        path=where,
                    )
                )
            elif attck is not None and not _technique_is_known(tid, attck):
                violations.append(
                    Violation(
                        code="stix.unknown_technique",
                        message=(
                            f"the attack-pattern names {safe_finding_value(tid)}, which the "
                            "MITRE ATT&CK catalogue has no entry for in any domain"
                            f"{_retired_note(tid, attck)}. Use a real technique id or "
                            "drop the attack-pattern."
                        ),
                        path=where,
                    )
                )
            elif attck is not None:
                mismatch = platform_mismatch_message(tid, attck, scope)
                if mismatch:
                    violations.append(
                        Violation(
                            code=PLATFORM_MISMATCH_CODE,
                            message=mismatch,
                            path=where,
                        )
                    )

    assessment = getattr(bundle, "x_maljan_assessment", None)
    severity = getattr(assessment, "severity", None) if assessment is not None else None
    rating = str(getattr(severity, "rating", "") or "") if severity is not None else ""
    if rating and rating not in SEVERITY_RATINGS:
        violations.append(
            Violation(
                code="verdict.severity_enum",
                message=(
                    f"severity.rating is {safe_finding_value(rating)!r}; it must be one of "
                    f"{', '.join(SEVERITY_RATINGS)}."
                ),
                path="severity.rating",
            )
        )

    family = getattr(assessment, "family", None) if assessment is not None else None
    if family is not None and str(getattr(family, "name", "") or "").strip():
        if not list(getattr(family, "evidence_ids", None) or []):
            violations.append(
                Violation(
                    code="attribution.ungrounded_family",
                    message=(
                        f"family {safe_finding_value(family.name)!r} cites no evidence ids; list "
                        "the ledger entries the name came from, or drop the attribution."
                    ),
                    path="family.evidence_ids",
                )
            )

    violations.extend(annotation_out_of_schema_violations(bundle, origins))
    violations.extend(credit_without_claim_violations(bundle, technique_sources, origins))
    return violations


def _model_at(model: Any, loc: Sequence[Any]) -> Any:
    """The model that owns the field ``loc`` points at, or ``model`` itself.

    Walks the named steps of a pydantic error location, stepping through list
    and optional annotations on the way. Anything it cannot follow — a union
    with two model members, a dict of models — ends the walk at the last model
    it was sure about, which is a less specific answer rather than a wrong one.
    """
    import typing

    current = model
    for step in loc[:-1] if loc else ():
        if not isinstance(step, str):
            continue
        field = (getattr(current, "model_fields", {}) or {}).get(step)
        if field is None:
            return current
        annotation = field.annotation
        for _ in range(3):
            args = [a for a in typing.get_args(annotation) if a is not type(None)]
            if len(args) != 1:
                break
            annotation = args[0]
        if isinstance(annotation, type) and hasattr(annotation, "model_fields"):
            current = annotation
        else:
            return current
    return current


def _schema_message(model: Any, error: Mapping[str, Any]) -> str:
    """Pydantic's complaint, with the schema's keys added when it is about a key.

    ``extra="forbid"`` answers "Extra inputs are not permitted", which names
    neither the key that was rejected nor the ones that would have been
    accepted; "Field required" names the one that is absent and nothing else.
    A live report composer spent both of its turns on the first sentence and
    the ``conclusion`` section was dropped from the delivered report. The field
    list is short, it is exactly what the model needs to answer again, and it
    costs one line of the feedback turn.
    """
    # Pydantic's own sentence about the field. It does not normally echo the
    # value, and a finding row is not the place to find out that it sometimes
    # does.
    message = safe_finding_value(error.get("msg") or "is not valid")
    kind = str(error.get("type") or "")
    if kind not in ("extra_forbidden", "missing"):
        return message
    # The keys of the object that rejected the field, which for a nested error
    # is not the answer's own: a bad key inside
    # ``defensive_recommendations[0]`` was answered with the narrative's three
    # top-level keys, none of which belong there.
    owner = _model_at(model, error.get("loc") or ())
    keys = ", ".join(sorted(getattr(owner, "model_fields", {}) or {}))
    if not keys:
        return message
    if kind == "extra_forbidden":
        return (
            f"{message}: this object accepts only these keys and rejects every other one — {keys}."
        )
    return f"{message}: this object's keys are {keys}."


ASSESSMENT_MISSING_CODE = "verdict.assessment_missing"

# What the judge is told to add, in the shape the bundle reads it in.
ASSESSMENT_MISSING_MESSAGE = (
    'Add x_maljan_assessment at the top level of the bundle, as a sibling of "objects" '
    "and not inside it, with verdict, severity {rating, rationale}, malware_category, "
    "family {name, confidence, evidence_ids} and confidence. "
    "Omit only a field the evidence cannot support."
)

# The fields whose presence means the block said something. A block carrying
# only the verdict has still answered the question the report leads with, and a
# judge that abstained on the other four has answered too.
_ASSESSMENT_FIELDS: tuple[str, ...] = (
    "verdict",
    "severity",
    "malware_category",
    "family",
    "confidence",
)


def assessment_violations(bundle: Any) -> list[Violation]:
    """Whether the judge said what it thinks, beyond the STIX objects.

    The message names the top level of the bundle because that is where
    ``Bundle.x_maljan_assessment`` is read from. A block the judge placed
    inside ``objects`` instead is lifted to the top level before validation
    (``agents.judge_postprocess.lift_misplaced_extensions``) and the lift is
    recorded; this check then sees the block where the bundle keeps it. Only a
    bundle that carries no assessment at all reaches the violation below.

    Severity, category, family and the judge's own confidence are the judge's
    to decide and nothing downstream computes them, so a bundle without them
    produces a report that reads "not assessed" from top to bottom. That used
    to happen in silence. It is one feedback turn now, and an unresolved
    finding when the retry omits the block as well.

    A judge that abstains on one field has answered; a block with nothing in it
    has not, and counts as absent.
    """
    assessment = getattr(bundle, "x_maljan_assessment", None)
    if assessment is not None and any(
        getattr(assessment, field, None) is not None for field in _ASSESSMENT_FIELDS
    ):
        return []
    return [
        Violation(
            code=ASSESSMENT_MISSING_CODE,
            message=ASSESSMENT_MISSING_MESSAGE,
            path="x_maljan_assessment",
        )
    ]


UNSTATED_VERDICT_CODE = "verdict.unstated"
UNRECOGNISED_VERDICT_CODE = "verdict.unrecognised"


def stated_verdict_violations(bundle: Any) -> list[Violation]:
    """Whether the judge stated a verdict, and whether it can be read.

    Two different faults with two different consequences, so two codes.

    The field is **absent**: the object set decides, because there is nothing
    else to go on. A ``malware`` object written "strictly as a container for
    the object type in STIX" then becomes a Malware verdict, which is the
    fail-safe and not an answer — so `verdict.unstated` records that it was
    used. The fallback stays for stored runs and for a model that omitted the
    field.

    The field **says something this pipeline cannot read**: the objects decide
    nothing. The run publishes the inconclusive verdict, the judge's own word
    travels to the report beside it, and `verdict.unrecognised` asks once for a
    word from the vocabulary — quoting what the judge wrote, because a
    correction that does not repeat the mistake is one the model cannot locate.

    A bundle this pipeline built out of text states its own verdict in
    ``x_maljan_fallback_verdict`` and is not asked for a second one.
    """
    if getattr(bundle, "x_maljan_fallback_verdict", None) is not None:
        return []
    from maljan.pipeline.outcome import INCONCLUSIVE_VERDICT, read_stated_verdict

    stated = read_stated_verdict(bundle)
    if stated.recognised is not None:
        return []
    listed = ", ".join(VERDICT_VALUES)
    if stated.unrecognised:
        return [
            Violation(
                code=UNRECOGNISED_VERDICT_CODE,
                message=(
                    f"x_maljan_assessment.verdict says {safe_finding_value(stated.written)!r}, "
                    f"which is not one of {listed}. Answer with exactly one of those three words "
                    "and nothing else — no qualifier, no parenthesis, no sentence; put anything "
                    "you want to qualify it with in severity.rationale. Until it is one of them "
                    f"this run publishes {INCONCLUSIVE_VERDICT} and no confidence, and your own "
                    "answer is printed beside it."
                ),
                path="x_maljan_assessment.verdict",
            )
        ]
    return [
        Violation(
            code=UNSTATED_VERDICT_CODE,
            message=(
                "x_maljan_assessment states no verdict. State it: set "
                f"x_maljan_assessment.verdict to one of {listed}, and set "
                "x_maljan_assessment.confidence to how sure you are of it. Write a malware "
                "object only for a sample you conclude is malware; without the field the "
                "verdict is read off the objects, which is a guess at what you meant."
            ),
            path="x_maljan_assessment.verdict",
        )
    ]


ASSESSMENT_CONFLICT_CODE = "verdict.assessment_conflict"

# The pairs that cannot both be meant. A malicious verdict whose severity is
# Informational, and a clean verdict rated High or Critical, are two answers to
# one question: a live run said Malware at 0.6 while its own rationale read
# "there is no evidence of malicious functionality", and the report printed
# both without a word about the contradiction.
_CONFLICTING_RATINGS: dict[str, frozenset[str]] = {
    "Malware": frozenset({"Informational"}),
    "Benign": frozenset({"High", "Critical"}),
}

# The words a category uses to say the sample is not malware. Checked against a
# Malware verdict only, and against this short list only: a category is free
# text, and the mirrored rule — deciding that some word in it means malicious —
# would be this module classifying the sample. PuTTY's was
# ``legitimate-utility`` beside a Malware verdict and an Informational rating.
_BENIGN_CATEGORY_WORDS: tuple[str, ...] = (
    "legitimate",
    "benign",
    "clean",
    "harmless",
    "not malware",
    "no malware",
    "non malicious",
    "not malicious",
)


def _category_says_benign(category: str) -> bool:
    """Whether a free-text category asserts the sample is not malware."""
    words = re.sub(r"[^a-z0-9]+", " ", category.lower()).strip()
    return any(word in words for word in _BENIGN_CATEGORY_WORDS)


def assessment_conflict_violations(bundle: Any) -> list[Violation]:
    """Whether the judge's stated verdict and the rest of its answer agree.

    Three comparisons, all of them against the verdict the judge stated: the
    severity rating, the malware category, and whether a ``malware`` object is
    in the bundle. Every field is the judge's and none is touched here — what
    the judge gets is one turn in which both sides are named and it is asked
    which it meant. A contradiction that survives the turn is recorded rather
    than resolved, because picking one of the two for the judge would be
    exactly the silent override this module exists to replace. The verdict is
    then published as stated, and the STIX export declines to carry a malware
    object under a Benign one.

    One row per disagreeing fact, each with its own path, so the console folds
    them apart and the judge reads what each one is about.
    """
    from maljan.pipeline.outcome import decide_from_bundle

    verdict = decide_from_bundle(bundle)
    assessment = getattr(bundle, "x_maljan_assessment", None)
    found: list[Violation] = []

    rating = str(getattr(getattr(assessment, "severity", None), "rating", "") or "").strip()
    if rating and rating in _CONFLICTING_RATINGS.get(verdict, frozenset()):
        found.append(
            Violation(
                code=ASSESSMENT_CONFLICT_CODE,
                message=(
                    f"This bundle's verdict is {verdict} and "
                    f"x_maljan_assessment.severity.rating says {rating}; those are two "
                    "different answers about the same sample. Reconcile them: either the "
                    "verdict or the rating is what you meant, and the rationale should "
                    "support whichever it is."
                ),
                path="x_maljan_assessment.severity.rating",
            )
        )

    category = str(getattr(assessment, "malware_category", "") or "").strip()
    if verdict == "Malware" and category and _category_says_benign(category):
        found.append(
            Violation(
                code=ASSESSMENT_CONFLICT_CODE,
                message=(
                    f"This bundle's verdict is Malware and x_maljan_assessment."
                    f"malware_category says {safe_finding_value(category)!r}, which says it is "
                    "not. Reconcile them: give the verdict the category describes, or a category "
                    "that describes the verdict."
                ),
                path="x_maljan_assessment.malware_category",
            )
        )

    if verdict == "Benign" and _malware_object_index(bundle) is not None:
        found.append(
            Violation(
                code=ASSESSMENT_CONFLICT_CODE,
                message=(
                    "This bundle's verdict is Benign and it carries a malware object. A "
                    "malware object is written for a sample you conclude is malware; under "
                    "a Benign verdict it is not published and the report says so. Drop the "
                    "object, or state the verdict it belongs to."
                ),
                path="objects",
            )
        )
    return found


def _malware_object_index(bundle: Any) -> int | None:
    """Where the bundle's first ``malware`` object sits, or ``None``."""
    for index, obj in enumerate(getattr(bundle, "objects", None) or []):
        if str(getattr(obj, "type", "") or "") == "malware":
            return index
    return None


UNSUPPORTED_BENIGN_CODE = "verdict.unsupported_benign"


def unsupported_benign_violations(
    bundle: Any, *, analyst_claims: int, ledger_ids: Sequence[str] | None = None
) -> list[Violation]:
    """Whether a Benign verdict on a run with no analysis cites anything.

    A live sample that 31 of 75 engines called malicious ended Benign at 0.1
    after every analyst reported no claims: the judge had seven tool results in
    front of it and no analysis of them, and "nothing was said about this
    sample" became "this sample is clean".

    Benign is a finding, so it needs something behind it. Either the bundle
    cites an entry from this run — a valid Authenticode signature out of
    ``signing_info`` is the usual one, which is how a signed PuTTY still ends
    Benign — or the verdict gives way to Suspicious with a rationale that says
    the run was inconclusive. Which of the two it is stays the judge's
    decision: this asks once and records what survives.

    Any cited entry clears it, not only a signature. The validator's business
    is whether the verdict points at the run's own evidence; grading that
    evidence is the judge's, and a validator that ranked it would be making the
    call it is here to ask for.
    """
    from maljan.pipeline.outcome import decide_from_bundle

    if analyst_claims > 0 or decide_from_bundle(bundle) != "Benign":
        return []
    known = {str(entry).strip().lower() for entry in (ledger_ids or []) if str(entry).strip()}
    # A run with nothing recorded has nothing to cite, and ``verdict_for_run``
    # already calls it inconclusive: the retry could not be satisfied and could
    # not change the reported verdict.
    if not known:
        return []
    try:
        text = json.dumps(bundle.model_dump(mode="json"), default=str)
    except Exception as exc:  # noqa: BLE001 — an unreadable bundle cites nothing
        logger.debug("validation: the bundle could not be read for citations (%s).", exc)
        text = ""
    if entry_ids_in(text) & known:
        return []
    listed = ", ".join(sorted(known)[:3])
    return [
        Violation(
            code=UNSUPPORTED_BENIGN_CODE,
            message=(
                "This verdict is Benign and no analyst made a single claim about the "
                "sample, so nothing examined it. Benign is a finding and needs evidence: "
                "cite the ledger entry that establishes it — a valid signature from "
                "signing_info is the usual one — or return Suspicious and say in the "
                f"rationale that the run was inconclusive. The entries this run recorded "
                f"include {listed}."
            ),
            path="objects",
        )
    ]


def _runtime_paths(evidence_corpus: set[str] | None) -> set[str]:
    """The corpus entries that look like a path something really touched."""
    from maljan.agents._indicator_denylists import IOC_OS_RESOURCE_PREFIXES

    found: set[str] = set()
    for token in evidence_corpus or ():
        value = str(token).strip()
        if any(value.startswith(prefix.lower()) for prefix in IOC_OS_RESOURCE_PREFIXES):
            found.add(value)
    return found


# The root a path on this machine is written from: a POSIX slash, a drive with
# either separator, a UNC share, an environment variable, a home tilde, or a
# registry hive — which ``directory:path`` carries about as often as the
# registry's own object type does.
_DIRECTORY_ROOT_RE = re.compile(
    r"^(?:/"
    # The separator after a drive is required. ``C:Windows`` is drive-relative
    # — it names whatever directory that drive is currently in, which is not a
    # place on the analysed machine that anything could be checked against.
    r"|[A-Za-z]:[\\/]"
    # One backslash or two. Two are a UNC share; one is what a UNC share
    # written the way a judge writes it becomes, because a STIX literal
    # ``'\\server\share'`` is unescaped by the reader to ``\server\share``
    # before any of this sees it. Refusing it told the judge its own valid
    # path could not be a place.
    r"|\\\\?"
    r"|%[A-Za-z_][A-Za-z0-9_]*%[\\/]?"
    r"|\$(?:\{[A-Za-z_][A-Za-z0-9_]*\}|[A-Za-z_][A-Za-z0-9_]*)[\\/]?"
    r"|~[\\/]?"
    r"|(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_[A-Z_]+)[\\/]"
    r")",
    re.IGNORECASE,
)

# A step that is a placeholder rather than a name. A strings table is full of
# them — a format string the sample was compiled with, read out of the bytes as
# though it were a path somebody visited. A step opening with ``#`` or ``?`` is
# the last one too: it is a URL's fragment or query, and ``/#frag`` read as a
# directory is a URL cut at its path.
_PLACEHOLDER_STEP_RE = re.compile(r"^(?:%[-+ #0-9.]*[a-zA-Z]|%\d+|\{[^}]*\}|<[^>]*>|\$\d+|[#?].*)$")

# What a step must carry to read as a name rather than as punctuation: two
# characters somebody could have typed as part of one.
_NAME_RUN_RE = re.compile(r"[A-Za-z0-9]{2}")

# A character no path on any of these filesystems carries.
_CONTROL_CHARACTERS = frozenset(chr(code) for code in range(0x20)) | {chr(0x7F)}

# A run of hexadecimal on its own, and the lengths a digest this project can
# name comes in. Anything else quoted in a pattern is asked the corpus question
# as it always was.
_HEX_TOKEN_RE = re.compile(r"^[0-9a-fA-F]+$")
_DIGEST_LENGTHS = frozenset({32, 40, 56, 64, 96, 128})

# What separates one token from the next in the evidence corpus. A digest is
# found when it stands alone between two of them, never when it is the first
# half of a longer one.
_TOKEN_BOUNDARY_RE = re.compile(r"[0-9a-f]", re.IGNORECASE)


def _comparisons(pattern: str) -> list[tuple[str, str]]:
    """Every ``(object path, quoted literal)`` the pattern compares, in order.

    :func:`~maljan.schemas.stix_pattern.read_comparisons` is the one reader of
    a pattern this repository has; the STIX renderer asks it the same question
    about the same syntax, and two readers of one pattern is how one of them
    publishes what the other vetoes. What is kept here is this caller's own
    filter: a value that is only whitespace is not a value to ask about.
    """
    return [
        (comparison.path, comparison.literal.strip())
        for comparison in read_comparisons(pattern)
        if comparison.literal.strip()
    ]


def reads_as_a_place(value: str) -> bool:
    """Whether this literal is written the way a directory on a machine is.

    The validity half of the directory question, and only that: it removes what
    could not be a place, and says nothing about whether this run saw one. A
    place has a root and at least one named step under it — ``/tmp`` is a
    directory, ``/`` and ``C:\\`` are roots and nothing under them — and every
    step is written the way a name is: not empty, not whitespace, no control
    character, not a format specifier a sample was compiled with, and at least
    one of them carrying two characters running that somebody could have typed.
    A strings table produces ``/%s/%s`` and ``/ /`` by the dozen.
    """
    text = str(value or "")
    root = _DIRECTORY_ROOT_RE.match(text)
    if root is None:
        return False
    steps = [step for step in re.split(r"[\\/]", text[root.end() :]) if step != ""]
    if not steps or text[root.end() :].startswith(("/", "\\")):
        return False
    for step in steps:
        if not step.strip() or _PLACEHOLDER_STEP_RE.match(step):
            return False
        if any(character in _CONTROL_CHARACTERS for character in step):
            return False
    return any(_NAME_RUN_RE.search(step) for step in steps)


def _place_in_the_evidence(
    literal: str, haystack: Haystack, runtime_paths: set[str], own: set[str]
) -> bool:
    """Whether the run recorded this place, however either side spelled it.

    The grounding half. A path is written with whichever separator the writer's
    platform uses and with a trailing one as often as without, so the literal is
    asked under the spellings that mean the same location — the normalisation
    the report's own path rows go through — and each is asked as a whole value
    rather than as a substring.
    """
    from maljan.reporting.dedupe import canonical_path

    lowered = literal.lower()
    spellings = {
        lowered,
        canonical_path(literal).lower(),
        lowered.replace("\\", "/"),
        lowered.replace("/", "\\"),
    }
    spellings |= {spelling.rstrip("/\\") for spelling in spellings if len(spelling) > 1}
    return any(
        spelling in own or spelling in runtime_paths or haystack.holds_value(spelling)
        for spelling in spellings
        if spelling
    )


class Haystack:
    """The evidence a grounding check searches, as the parts it came in.

    Never one joined string. A value never spans two tool answers — joining
    them put a space between them and a space bounds a value — so asking each
    part is exactly the search the joined string performed. Joining was not
    free: on 400 answers of 6 000 characters the run's record was copied on the
    way into the corpus's cache, again as an element of the token set, and a
    third time into the string that was finally searched.

    Everything here is compared lower-cased, which is the corpus's own rule and
    is why the run's answers are folded once, at the moment they are recorded.
    """

    __slots__ = ("parts",)

    def __init__(self, parts: Iterable[str]) -> None:
        self.parts: tuple[str, ...] = tuple(part for part in parts if part)

    def __contains__(self, needle: str) -> bool:
        # Every spelling the value takes in a tool's answer: the answers are
        # JSON, so a quote in a value is stored ``\"`` and a backslash ``\\``,
        # and the plain value a model writes back is in none of them as
        # written. ``utils.written_forms`` names the spellings; the question
        # asked of each is the one that was asked of the plain value.
        forms = written_forms(needle)
        return any(form in part for part in self.parts for form in forms)

    def __bool__(self) -> bool:
        return bool(self.parts)

    def holds_value(self, value: str) -> bool:
        """Whether the evidence holds ``value`` as a value of its own, however spelt."""
        from maljan.agents._indicator_denylists import whole_value_in

        forms = written_forms(value)
        return any(whole_value_in(form, part) for part in self.parts for form in forms)

    def holds_token(self, value: str) -> bool:
        """Whether ``value`` stands between two boundaries rather than inside a run."""
        forms = written_forms(value)
        return any(_token_in(form, part) for part in self.parts for form in forms)


def _token_in(lowered: str, part: str) -> bool:
    """Whether ``lowered`` is a whole token of ``part``."""
    start = part.find(lowered)
    while start != -1:
        before = part[start - 1] if start else ""
        after = part[start + len(lowered) : start + len(lowered) + 1]
        if not _TOKEN_BOUNDARY_RE.match(before or " ") and not _TOKEN_BOUNDARY_RE.match(
            after or " "
        ):
            return True
        start = part.find(lowered, start + 1)
    return False


def _whole_token_in(literal: str, haystack: Haystack, own: set[str]) -> bool:
    """Whether ``literal`` appears in the corpus as a value rather than a prefix."""
    lowered = literal.lower()
    if lowered in own:
        return True
    return haystack.holds_token(lowered)


# What a check that had nothing to search says about what it searched. Not the
# same as a corpus that lost answers — there were none to lose — but the same
# conclusion: an absence measured over nothing is a note, never a reason to
# remove a model's object.
NOTHING_SEARCHED = CorpusState(complete=False, why="no evidence was searched")

# The words every corpus-miss sentence in :func:`_indicator_problem` shares.
# Kept for readers grepping for the phrase; nothing decides anything by it.
ABSENT_FROM_THE_EVIDENCE = "appears nowhere"


class _Problem(str):
    """A refusal sentence, and whether the refusal is an absence.

    A ``str``, so the sentence is still just the sentence everywhere it is
    read. The flag rides on the object rather than in its text because what
    the caveat and the advisory rule key on is *what the check concluded*, and
    keying on the words would let a model-written indicator value carrying the
    phrase attract a caveat it did not earn.
    """

    absent: bool = False


def _an_absence(sentence: str) -> _Problem:
    """A refusal whose whole content is that the evidence does not hold it."""
    found = _Problem(sentence)
    found.absent = True
    return found


def _is_an_absence(problem: str) -> bool:
    """Whether this refusal is "the evidence does not hold it" and nothing else."""
    return bool(getattr(problem, "absent", False))


def shortened_evidence_note(tools: Iterable[str]) -> str:
    """What to add to an absence when part of the evidence searched was shortened.

    A shortened answer is still the answer the model read — the shortener hands
    one string to both the model and the ledger — so "this value is in no tool
    output" stays true and the grounding rule is unchanged. What is not true is
    that the search was over everything the tool found: a shortened document
    handed over fewer rows than the call produced. Naming the tools lets the
    judge ask one of them again with a narrower argument instead of guessing
    whether its value was in the part that did not fit.

    Empty when nothing was shortened, so a clean run's feedback is unchanged.
    """
    named = sorted({str(tool).strip() for tool in tools if str(tool).strip()})
    if not named:
        return ""
    return (
        " The evidence searched includes shortened answers from "
        f"{safe_finding_value(', '.join(named))}: those calls did not fit and were "
        "handed over with rows missing. Narrow one of them and ask again before "
        "withdrawing a value on this."
    )


def partial_evidence_note(state: CorpusState) -> str:
    """What an absence may say when the evidence searched was not the whole run.

    The platform does not assert an absence over evidence it knows is partial.
    When the run's in-memory corpus hit its ceiling, or there is no corpus and
    the stored entries fell back on had been blanked by the byte budget, the
    row says how much was not searched and whose it was — counts and tool
    names only, because a sentence naming a value would put a tool's output
    back into the row the value was withheld from — and says that nothing is
    dropped for it.

    Empty when the corpus was whole, so an ordinary absence reads as it did.
    """
    if state.complete:
        return ""
    if not state.missing_tools:
        # No tool to name — the corpus is gone, or there was never anything to
        # search — so the reason is what the sentence carries instead. One of
        # this module's own words either way, never a producer's.
        return (
            f" The evidence searched is not this run's whole record ({state.why}), so this is a "
            "note rather than a finding and nothing is dropped for it."
        )
    named = safe_finding_value(", ".join(state.missing_tools))
    answers = "answer" if state.missing_answers == 1 else "answers"
    return (
        f" The evidence searched is not this run's whole record: {state.missing_answers} "
        f"{answers} from {named} were not kept. This is a note rather than a finding, and "
        "nothing is dropped for it."
    )


def partial_grounding_reason(state: CorpusState) -> str:
    """One sentence saying grounding was advisory in this run, or ``""``.

    A degradation reason rather than a finding: it is a fact about the run's
    record, not about the sample. It names the remedy — which of the three
    reasons it is — because an operator who set the ceiling and an operator
    whose run was resumed have different things to do about it.
    """
    if state.complete:
        return ""
    reason = state.why or "the evidence searched was not this run's whole record"
    named = f" ({', '.join(state.missing_tools)})" if state.missing_tools else ""
    return (
        f"grounding searched less than this run produced — {reason}: "
        f"{state.missing_answers} answer(s) not kept{named}. "
        "An absence measured against it is recorded as a note and drops nothing."
    )


def _indicator_problem(
    pattern: str, haystack: Haystack, runtime_paths: set[str], identity: Iterable[str] = ()
) -> str:
    """Why this indicator is not grounded, in words the judge can act on, or "".

    The rules are the ones the post-processor used to apply silently, said out
    loud instead: the denylists in ``agents._indicator_denylists`` are what a
    URL host, a compile artefact and a foreign class reference are checked
    against, and here they become the sentence the judge reads rather than a
    log line nobody sees.

    ``identity`` is the sample's own lowercased hashes and file name. A literal
    equal to one of them counts as found wherever the haystack is consulted; a
    literal merely contained in one does not, so neither a slice of the sha256
    nor a value written inside the submitted name passes.
    """
    from maljan.agents._indicator_denylists import (
        COMPILE_ARTIFACT_RE,
        FOREIGN_CLASS_REF_RE,
        HASH_HEX_LENGTHS,
        IOC_FILE_EXTENSIONS,
        IOC_OS_RESOURCE_PREFIXES,
        URL_DENY_HOSTS,
        malformed_hash_in,
    )

    if not pattern.strip():
        return "the indicator has an empty pattern."
    # Raw here, deliberately: these are what the denylists and the corpus are
    # matched against, and a scrubbed path would answer a different question
    # from the one this check asks. The sentence they end up in is what the
    # caller wraps, because that is what is stored and shown.
    comparisons = _comparisons(pattern)
    literals = [literal for _path, literal in comparisons]
    if not literals:
        return "the indicator pattern quotes no value."
    own = set(identity)

    def _found(literal: str) -> bool:
        return literal.lower() in haystack or literal.lower() in own

    # A hash literal answers to its algorithm before it answers to the corpus.
    # Sixteen of the thirty-two characters of an MD5 are a prefix of one, and a
    # substring search over the evidence finds a prefix every time — one run
    # exported ``32066ff6369a7bd7`` as an indicator no consumer matching on MD5
    # can ever match. The length question is asked first because a truncated
    # digest is not "present in the evidence" whatever the haystack says.
    malformed = malformed_hash_in(pattern)
    if malformed is not None:
        algorithm, literal = malformed
        named = safe_finding_value(algorithm)
        expected = HASH_HEX_LENGTHS.get(algorithm)
        return (
            f"{safe_finding_value(literal)!r} is not a {named} digest: "
            f"{named} is {expected} hexadecimal characters."
        )

    # Every comparison in the pattern, asked in turn, and each check below is a
    # veto rather than an acceptance. A pattern is not one comparison —
    # ``[a] AND [b]``, an ``IN`` list, a compound the judge writes — and these
    # branches used to key on what the *pattern* started with, so a URL beside
    # a hash was never asked the denylist question and a grounded digest
    # answered for the whole expression. What one comparison establishes is
    # that *it* raised no problem; the others are still asked.
    grounded = False
    # A ``LIKE`` value is a shape, not a value: ``'%host.example%'`` matches
    # whatever contains the text between its wildcards. That text is what the
    # evidence is asked for, each run of it; the wildcards themselves appear in
    # no tool's answer, and asking for them told the judge that a host it read
    # in the decoded strings was nowhere in the evidence.
    from maljan.schemas.stix_pattern import like_fixed_text, matches_fixed_text

    shapes = {
        (comparison.path, comparison.literal.strip()): comparison.operator
        for comparison in read_comparisons(pattern)
        if comparison.operator in ("like", "matches")
    }
    for path, literal in comparisons:
        if shapes.get((path, literal)) == "matches":
            # A regular expression is not a value. One that is only its text is
            # asked for that text; any other says nothing about which value
            # the evidence holds, and neither grounds nor refuses the pattern.
            fixed = matches_fixed_text(literal)
            if fixed and not _found(fixed[0]):
                return _an_absence(
                    f"the text {safe_finding_value(fixed[0])!r}, which the pattern's MATCHES "
                    f"{safe_finding_value(literal)!r} is written for, appears nowhere in this "
                    "run's evidence."
                )
            grounded = grounded or bool(fixed)
            continue
        if (path, literal) in shapes:
            fixed = like_fixed_text(literal)
            missing = next((part for part in fixed if not _found(part)), None)
            if missing is not None:
                return _an_absence(
                    f"the text {safe_finding_value(missing)!r}, which the pattern's LIKE "
                    f"{safe_finding_value(literal)!r} requires of every value it matches, "
                    "appears nowhere in this run's evidence."
                )
            # A run of a character or three is found in any evidence at all, so
            # it says nothing about which value this run saw.
            if fixed and not any(len(part.strip()) >= _SHAPE_TEXT_MIN for part in fixed):
                return (
                    f"the pattern's LIKE {safe_finding_value(literal)!r} fixes no text of "
                    f"{_SHAPE_TEXT_MIN} or more characters, so nothing in this run's evidence "
                    "says which value it names; it matches values this run never saw."
                )
            grounded = grounded or bool(fixed)
            continue
        if path.startswith("file:hashes") or path.endswith("imphash"):
            if _HEX_TOKEN_RE.match(literal) and len(literal) in _DIGEST_LENGTHS:
                if not _whole_token_in(literal, haystack, own):
                    return _an_absence(
                        f"the indicator pattern names {safe_finding_value(literal)}, which "
                        "appears nowhere in the evidence this run collected as a value of its "
                        "own."
                    )
                grounded = True
                continue
            # A fuzzy hash is not a run of hex and has no length this code
            # knows — an ssdeep carries block sizes and slashes, a TLSH opens
            # with its version — so the prefix question the whole-token rule
            # answers does not arise for it. It is asked the corpus question
            # every other value is asked, and skipping it told a judge that the
            # ssdeep the ``hashes`` tool had just reported "appears nowhere in
            # the evidence", spent the one retry on that and dropped the
            # object.
            grounded = grounded or _found(literal)
            continue
        if path.startswith("url:"):
            host = _url_host(literal)
            if host and any(host.endswith(d) or d in host for d in URL_DENY_HOSTS):
                return (
                    f"the URL host in {safe_finding_value(literal)!r} is documentation or "
                    "vendor infrastructure."
                )
            if not _found(literal):
                return _an_absence(
                    f"the URL {safe_finding_value(literal)!r} appears nowhere in this run's "
                    "evidence."
                )
            grounded = True
            continue
        if path.startswith("file:name") or path.startswith("directory:path"):
            if COMPILE_ARTIFACT_RE.search(literal):
                return (
                    f"{safe_finding_value(literal)!r} is a compiler or toolchain artefact, "
                    "not an indicator."
                )
            if FOREIGN_CLASS_REF_RE.match(literal):
                return (
                    f"{safe_finding_value(literal)!r} is a class reference from a library, "
                    "not a file on disk."
                )
            lowered = literal.lower()
            anchored = (
                any(literal.startswith(prefix) for prefix in IOC_OS_RESOURCE_PREFIXES)
                or lowered in runtime_paths
                or lowered in own
            )
            if path.startswith("directory:path"):
                # Two questions, and a directory is asked both. A directory has
                # no extension to answer the first with, and telling the judge
                # its own row "has no file extension … so nothing says it is a
                # real path" was untrue of the thing it had written.
                if not reads_as_a_place(literal):
                    return (
                        f"{safe_finding_value(literal)!r} is not written as a directory: a "
                        "path on this machine has a root — a drive, a share, a POSIX slash, "
                        "an environment variable or a registry hive — and at least one named "
                        "step under it."
                    )
                if not _place_in_the_evidence(literal, haystack, runtime_paths, own):
                    return _an_absence(
                        f"{safe_finding_value(literal)!r} appears nowhere in the evidence "
                        "this run collected as a value of its own."
                    )
                grounded = True
                continue
            if not (anchored or any(lowered.endswith(ext) for ext in IOC_FILE_EXTENSIONS)):
                return (
                    f"{safe_finding_value(literal)!r} has no file extension, no filesystem "
                    "anchor and was not "
                    "observed at runtime, so nothing says it is a real path."
                )
            grounded = True
            continue
        # A digest-shaped literal under a path this does not model is still a
        # digest: it is asked as a whole token wherever it is written.
        if _HEX_TOKEN_RE.match(literal) and len(literal) in _DIGEST_LENGTHS:
            if not _whole_token_in(literal, haystack, own):
                return (
                    f"the indicator pattern names {safe_finding_value(literal)}, which appears "
                    "nowhere in the evidence this run collected as a value of its own."
                )
            grounded = True
            continue
        grounded = grounded or _found(literal)

    # One comparison is enough to ground the pattern. ``[file:hashes.'SHA-256'
    # = '<hex>']`` quotes the hash algorithm as well as the hash, and requiring
    # every quoted string to appear in the corpus would reject the digest for
    # the company it keeps.
    if grounded:
        return ""
    return _an_absence(
        f"the indicator pattern names {safe_finding_value(', '.join(literals))}, which "
        "appears nowhere "
        "in the evidence this run collected."
    )


def _url_host(raw_url: str) -> str | None:
    """Best-effort host extraction without a full URL parser."""
    from urllib.parse import urlparse

    try:
        return (urlparse(raw_url).hostname or "").lower() or None
    except (ValueError, TypeError):
        return None


# The ``source_name`` values that mean "this external_id is an ATT&CK id".
# Only these are read: an attack-pattern may legitimately carry a Sigma rule id
# or a CVE first in its reference list, and holding the judge to the ATT&CK
# vocabulary for one of those would burn the single retry on nothing.
_MITRE_SOURCES = MITRE_ATTACK_SOURCES


def _attack_pattern_technique_id(obj: Any) -> str:
    """The ATT&CK id an attack-pattern declares, from its MITRE ref or its name."""
    for ref in getattr(obj, "external_references", None) or []:
        if not isinstance(ref, dict):
            continue
        if str(ref.get("source_name") or "").strip().lower() not in _MITRE_SOURCES:
            continue
        external_id = ref.get("external_id")
        if external_id:
            return str(external_id).strip().upper()
    name = str(getattr(obj, "name", "") or "").strip().upper()
    first = name.split()[0].rstrip(":") if name else ""
    return first if first.startswith("T") else ""


def drop_ungrounded_indicators(
    bundle: Any,
    violations: Sequence[Violation],
    *,
    origins: Sequence[tuple[int | None, str]] | None = None,
) -> int:
    """Remove the indicators still ungrounded after the retry; return how many.

    An unresolved technique id can stay on a claim and be labelled; an
    unresolved indicator cannot stay in a STIX bundle, because a bundle is
    consumed by detection tooling that has no way to read a label. It is
    dropped here and recorded in ``run_summary.validation.unresolved``, so the
    false positive is visible as a run fact rather than as a blocking rule.

    An **advisory** row drops nothing. The platform states an absence only over
    evidence it searched whole; when it could not, the judge is told so and
    keeps its object.
    """
    indices = {
        index
        for index in (
            _object_index(v.path)
            for v in violations
            # Never on an advisory row. An advisory absence is one the platform
            # measured against evidence it knows is partial, and dropping the
            # judge's object over it is exactly the wrong statement made
            # expensive: the value may well be in the part that was not kept.
            if v.code == "stix.ungrounded_indicator" and not v.advisory
        )
        if index is not None
    }
    if not indices:
        return 0
    if origins:
        # The paths name the judge's own positions; the drop is over the
        # checked bundle's.
        written_at = {
            written: here for here, (written, _label) in enumerate(origins) if written is not None
        }
        indices = {written_at[i] for i in indices if i in written_at}
    objects = list(getattr(bundle, "objects", None) or [])
    kept = [obj for index, obj in enumerate(objects) if index not in indices]
    dropped = len(objects) - len(kept)
    if dropped:
        bundle.objects = kept
        logger.warning("validation: dropped %d ungrounded indicator(s) from the bundle.", dropped)
    return dropped


# Where a finding names the object it is about. Two answers of one judge
# write the same object at different positions and under different labels, so
# a finding about it is the same question whichever answer raised it.
_OBJECT_PLACE_RE = re.compile(r"objects\[\d+\](?: '[^']*')?")


def not_asked(violations: Sequence[Violation], shown: Sequence[Violation]) -> list[Violation]:
    """``violations``, each one the producer was never shown marked ``asked=False``.

    A finding counts as shown when one of the same code was about the same
    thing: its ``subject`` where the check names one — the technique a credit
    is for, whatever source the answer credits it to now — and otherwise the
    same words, whatever position and label its object had in the answer that
    raised it. The answer to a retry numbers its objects afresh and renames
    what the question told it to; the question is still the one it was asked.
    """

    def _about(v: Violation) -> tuple[str, str]:
        return (v.code, v.subject or _OBJECT_PLACE_RE.sub("objects[]", v.message))

    said = {_about(v) for v in shown}
    return [v if _about(v) in said else replace(v, asked=False) for v in violations]


def _object_index(path: str) -> int | None:
    match = re.search(r"objects\[(\d+)\]", path or "")
    return int(match.group(1)) if match else None


def _object_path(index: int, origins: Sequence[tuple[int | None, str]] | None) -> str:
    """Where an object sits in the answer as the judge wrote it, and its label.

    The bundle a check reads has lost what the post-processor set aside and
    folded, so its own positions name other objects than the judge's list
    holds at the same place. ``origins`` carries, per object checked, the
    judge's position and the id the judge wrote; without it the checked
    bundle's position is all there is.
    """
    if origins is not None and index < len(origins):
        written, label = origins[index]
        if written is not None:
            return (
                f"objects[{written}] {safe_finding_value(label)!r}"
                if label
                else f"objects[{written}]"
            )
    return f"objects[{index}]"


# ---------------------------------------------------------------------------
# The retry loop
# ---------------------------------------------------------------------------


def _collect(parsed: Any, validators: Sequence[Validator]) -> list[Violation]:
    found: list[Violation] = []
    for validator in validators:
        try:
            found.extend(validator(parsed) or [])
        except Exception as exc:  # noqa: BLE001 — a broken validator must not fail a run
            logger.warning("validation: a validator raised (%s); its findings are skipped.", exc)
    return found


def _with_feedback(
    messages: list[Any],
    answer: Any,
    violations: Sequence[Violation],
    *,
    keep_answer: bool = True,
    closing: str = FEEDBACK_CLOSING,
) -> list[Any]:
    """The conversation plus the model's answer plus the correction turn.

    ``keep_answer=False`` leaves the answer out: the correction describes it
    instead (a cut section answer, see ``section_cut_violation``), and with
    no answer between them the correction is asked at the end of the user
    turn before it (``with_question``).
    """
    from langchain_core.messages import AIMessage

    from maljan.pipeline.turns import with_question

    content = getattr(answer, "content", None)
    turns = list(messages)
    if keep_answer:
        turns.append(AIMessage(content=str(content if content is not None else answer)))
    return with_question(turns, feedback_text(violations, closing=closing))


def _announce_feedback(
    violations: Sequence[Violation],
    on_feedback: Callable[[Sequence[Violation]], None] | None,
    feed: _FeedbackFeed | None = None,
    retry_index: int = 0,
) -> None:
    """Log the correction turn, publish it, and hand it to the run's tally."""
    logger.info(
        "validation: retrying after %d violation(s): %s.",
        len(violations),
        ", ".join(sorted({v.code for v in violations})),
    )
    if feed is not None:
        feed.announce(violations, retry_index)
    if on_feedback is None:
        return
    try:
        on_feedback(violations)
    except Exception as exc:  # noqa: BLE001 — a metric is never worth a lost run
        logger.debug("validation: the feedback tally was not updated (%s).", exc)


class _FeedbackFeed:
    """Who is being corrected and where to say so, for one retry loop.

    A tuple of three arguments repeated across two nearly identical loops and
    their four call sites is a tuple somebody eventually passes in the wrong
    order. The producer names itself once and the loops carry one object.
    """

    def __init__(self, sink: EventSink | None, agent: str, stage: str) -> None:
        self.sink = sink
        self.agent = str(agent)
        self.stage = str(stage)

    def announce(self, violations: Sequence[Violation], retry_index: int) -> None:
        for violation in violations:
            self._emit(violation, retry_index, VALIDATION_RETRIED)

    def outcome(
        self,
        shown: Sequence[Violation],
        remaining: Sequence[Violation],
        retry_index: int,
    ) -> None:
        """What became of every violation this loop saw.

        One line per violation, and the ones that were never fed back are here
        too: a retry introduces violations of its own, and a reader of the
        conversation used to see only the batch that triggered the retry —
        two lines beside a run whose summary recorded ten unresolved findings.
        """
        left = {(v.code, v.path) for v in remaining}
        seen: set[tuple[str, str]] = set()
        for violation in shown:
            key = (violation.code, violation.path)
            if key in left or key in seen:
                continue
            seen.add(key)
            self._emit(violation, retry_index, VALIDATION_RESOLVED)
        for violation in remaining:
            self._emit(violation, retry_index, VALIDATION_SURVIVED)

    def _emit(self, violation: Violation, retry_index: int, state: str) -> None:
        emit_validation_feedback(
            self.sink,
            stage=self.stage,
            agent=self.agent,
            code=str(violation.code),
            message=str(violation.message),
            retry_index=retry_index,
            state=state,
            # The producer's own locator, so the two lines about one violation
            # fold together and two violations of one code on different claims
            # do not.
            path=str(violation.path),
        )


def announce_unresolved(
    sink: EventSink | None,
    *,
    agent: str,
    stage: str,
    violations: Sequence[Violation],
    retry_index: int = 0,
) -> None:
    """Publish findings nobody was shown, as findings that survived.

    For a producer that records a violation outside the retry loop — the judge
    appends the timeout, the fallback and its two verdict checks after it —
    where the run summary carried a row the conversation never showed.
    """
    feed = _feed(sink, agent, stage)
    if feed is not None and violations:
        feed.outcome([], violations, retry_index)


def announce_resolved(
    sink: EventSink | None,
    *,
    agent: str,
    stage: str,
    violations: Sequence[Violation],
    retry_index: int = 0,
) -> None:
    """Publish findings the pipeline settled itself, as findings that are settled.

    For an act this pipeline is allowed to perform without asking — moving the
    judge's own assessment block to the property the schema reads it from,
    unchanged. Nobody is corrected and no turn is spent, and the line says so
    rather than leaving a reader to find out from a bundle that parsed.
    """
    feed = _feed(sink, agent, stage)
    if feed is not None and violations:
        feed.outcome(violations, [], retry_index)


def _feed(sink: EventSink | None, agent: str, stage: str) -> _FeedbackFeed | None:
    """The feed for a caller that named a sink, or nothing for one that did not.

    A loop run from the CLI, a test or the report composer has nobody to tell,
    and an object that emits into ``None`` on every violation is cheaper to
    skip than to build.
    """
    return _FeedbackFeed(sink, agent, stage) if sink is not None else None


async def retry_with_feedback[T](
    run: Callable[[list[Any]], Awaitable[Any]],
    messages: list[Any],
    validators: Sequence[Validator],
    *,
    max_retries: int = 1,
    parse: Callable[[Any], T],
    on_feedback: Callable[[Sequence[Violation]], None] | None = None,
    sink: EventSink | None = None,
    agent: str = "",
    stage: str = "",
    drop_answer_for: frozenset[str] = frozenset(),
    can_retry: Callable[[list[Any]], bool] | None = None,
) -> tuple[T, list[Violation], int]:
    """Run, validate, and give the model one chance to fix what it got wrong.

    Returns the last answer, whatever is still wrong with it, and how many
    retries were spent. Remaining violations are returned rather than raised:
    the caller decides whether an unresolved finding is a label on a claim or a
    dropped object, and neither of those is this function's call to make.

    ``on_feedback`` is handed every violation the producer is shown, before it
    is shown. A violation the retry fixes leaves no other trace, and a run
    summary that counts only the leftovers cannot say what the retry was for
    — :class:`ValidationTally` is what the callers pass.

    ``sink``, ``agent`` and ``stage`` put the same correction into the live
    conversation, as one ``validation_feedback`` per violation — ``retried``
    where the producer is shown it, then ``resolved`` or ``survived`` once this
    loop knows which, including for the violations the retry itself introduced.
    A caller with nobody to tell — the CLI, a test, the report composer —
    passes no sink and nothing is emitted.

    ``drop_answer_for`` names the codes whose correction replaces the answer
    rather than following it, and ``can_retry`` is asked about the retry's
    whole conversation before it is sent: answered no, the loop ends there
    with what it has, and the caller records why.
    """
    feed = _feed(sink, agent, stage)
    turns = list(messages)
    answer = await run(turns)
    parsed = parse(answer)
    violations = _collect(parsed, validators)
    retries = 0
    shown: list[Violation] = []
    while violations and retries < max_retries:
        keep = not any(v.code in drop_answer_for for v in violations)
        following = _with_feedback(turns, answer, violations, keep_answer=keep)
        if can_retry is not None and not can_retry(following):
            break
        _announce_feedback(violations, on_feedback, feed, retries + 1)
        shown.extend(violations)
        turns = following
        retries += 1
        answer = await run(turns)
        parsed = parse(answer)
        violations = _collect(parsed, validators)
    if feed is not None:
        feed.outcome(shown, violations, retries)
    return parsed, violations, retries


def retry_with_feedback_sync[T](
    run: Callable[[list[Any]], Any],
    messages: list[Any],
    validators: Sequence[Validator],
    *,
    max_retries: int = 1,
    parse: Callable[[Any], T],
    on_feedback: Callable[[Sequence[Violation]], None] | None = None,
    sink: EventSink | None = None,
    agent: str = "",
    stage: str = "",
    keep: Callable[[T, T], T] | None = None,
    drop_answer_for: frozenset[str] = frozenset(),
    closing: str = FEEDBACK_CLOSING,
) -> tuple[T, list[Violation], int]:
    """:func:`retry_with_feedback` for the analysts, whose loop is synchronous.

    The analyst tool loop is sync all the way down (``execute_tool_loop`` bridges
    to the shared agent loop itself), so an async-only helper would force every
    analyst call site through a second bridge for no gain. The two functions
    share the feedback turn and the collection rule and differ only in the await.

    ``keep`` is the caller's choice between the first answer and the last,
    made here, before anything is published: an analyst keeps its first answer
    when the retry lost claims. The violations returned and the outcome every
    one of them is published with are then the kept answer's. Chosen after the
    outcome, the conversation said "resolved" for four findings the run kept
    and recorded unresolved.

    ``drop_answer_for`` is :func:`retry_with_feedback`'s: the codes whose
    correction describes the answer instead of following it. ``closing`` is
    the retry turn's last line; the analysts' names the block format their
    parser reads (``ANALYST_FEEDBACK_CLOSING``).
    """
    feed = _feed(sink, agent, stage)
    turns = list(messages)
    answer = run(turns)
    parsed = parse(answer)
    first = parsed
    violations = _collect(parsed, validators)
    retries = 0
    shown: list[Violation] = []
    while violations and retries < max_retries:
        _announce_feedback(violations, on_feedback, feed, retries + 1)
        shown.extend(violations)
        keep_answer = not any(v.code in drop_answer_for for v in violations)
        turns = _with_feedback(turns, answer, violations, keep_answer=keep_answer, closing=closing)
        retries += 1
        answer = run(turns)
        parsed = parse(answer)
        violations = _collect(parsed, validators)
    if retries and keep is not None:
        kept = keep(first, parsed)
        if kept is not parsed:
            parsed = kept
            violations = _collect(parsed, validators)
    if feed is not None:
        feed.outcome(shown, violations, retries)
    return parsed, violations, retries


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


def validation_metrics(
    retries: int,
    unresolved: Sequence[tuple[str, Violation]],
    fed_back: Mapping[str, int] | None = None,
    not_run: Sequence[str] | None = None,
) -> dict[str, Any]:
    """``run_summary.validation`` from the run's retries, corrections and leftovers.

    ``fed_back`` is what the producers were told, by code (see
    :class:`ValidationTally`). It is added to the leftovers rather than
    replacing them: a code that was fed back once and never fixed is two
    facts about the run, and ``by_code`` is the count of both. ``not_run``
    names the checks that could not run at all — the validity check on a box
    with no catalogue — which is a different fact from a check that ran and
    found nothing.
    """
    by_code: dict[str, int] = {code: int(count) for code, count in (fed_back or {}).items()}
    rows: list[dict[str, str]] = []
    for agent, violation in unresolved:
        by_code[violation.code] = by_code.get(violation.code, 0) + 1
        rows.append(
            {
                "agent": agent,
                "code": violation.code,
                "message": violation.message,
                # The second place a row is rebuilt for the record. A row the
                # platform declined to act on, stored without the flag, reads
                # downstream as a producer's own unfixed finding.
                **({"advisory": "true"} if violation.advisory else {}),
                # And whether the producer was ever shown it: a finding the
                # answer to the last retry raised first was never a question.
                **({} if violation.asked else {"asked": "false"}),
                **({"subject": violation.subject} if violation.subject else {}),
            }
        )
    return {
        "retries": int(retries),
        "by_code": dict(sorted(by_code.items())),
        "unresolved": rows,
        "not_run": sorted({str(code) for code in (not_run or []) if str(code).strip()}),
    }


def corroboration(
    isrs: dict[str, Any] | None, ledger: Sequence[Any] | None
) -> dict[str, dict[str, Any]]:
    """Per technique id, who asserted it and who claimed it, by name.

    ``asserted_by`` is the deterministic sources that assert a technique from
    this sample — a rule that fired on it names its technique; the tools are
    ``evidence_summary.ASSERTING_SOURCES``, and a reference lookup is never one
    — and ``claimed_by`` is the agents. Two flat lists, no weights, no score:
    the number that used to live here was a weighted sum over layer weights and cross-layer
    multipliers, and its inputs were constants nobody could derive from
    anything. Two agents and a capa rule naming ``T1055`` is a fact; 0.87 was
    an opinion with a decimal point. A technique nothing asserted is not
    penalised anywhere; the reader sees the empty list.

    The same collection feeds the judge's evidence-summary block, so the metric
    the report carries and the block the judge read cannot disagree.
    """
    from maljan.pipeline.evidence_summary import (
        ASSERTING_SOURCES,
        catalogue_associations,
        collect,
    )

    agents = {str(getattr(isr, "agent_id", "") or name) for name, isr in (isrs or {}).items()}
    associations = catalogue_associations(ledger)
    out: dict[str, dict[str, list[str]]] = {}
    collected = collect(isrs, ledger)
    for tid in associations:
        collected.setdefault(tid, [])
    for tid, sources in sorted(collected.items()):
        asserted: list[str] = []
        claimed: list[str] = []
        for source, _confidence in sources:
            if source in agents:
                if source not in claimed:
                    claimed.append(source)
            else:
                # ``collect`` hands back only the asserting tools' own names.
                label = ASSERTING_SOURCES.get(source, source)
                if label not in asserted:
                    asserted.append(label)
        row: dict[str, Any] = {"asserted_by": sorted(asserted), "claimed_by": sorted(claimed)}
        if tid in associations:
            row["associated_by"] = list(associations[tid])
        # Upstream Sigma rules and the case corpus still name ids the
        # catalogue retired; the row says so, the way the validity message does.
        retired = _retired_release(tid)
        if retired:
            row["retired_in"] = retired
        out[tid] = row
    return out


def _retired_release(technique_id: str) -> str | None:
    try:
        from maljan.memory.attck_loader import retired_in

        return retired_in(technique_id)
    except Exception:  # noqa: BLE001 — a note, not a check
        return None


UNSUPPORTED_MALWARE_CODE = "verdict.unsupported_malware"


def unsupported_malware_violations(
    bundle: Any, *, analyst_claims: int, ledger_ids: Sequence[str] | None = None
) -> list[Violation]:
    """Whether a Malware verdict on a run with no analysis cites anything.

    The mirror of ``unsupported_benign_violations``, and for the same reason:
    a verdict is a finding. Malware over zero analyst claims can stand on the
    run's own record — a reputation entry, a rule hit, a signature the pack
    established — and the bundle then cites that entry; or it gives way to
    Suspicious with a rationale that says the run was inconclusive. Which of
    the two stays the judge's call. This asks once and records what survives,
    and it grades nothing: any cited entry from this run clears it.
    """
    from maljan.pipeline.outcome import decide_from_bundle

    if analyst_claims > 0 or decide_from_bundle(bundle) != "Malware":
        return []
    known = {str(entry).strip().lower() for entry in (ledger_ids or []) if str(entry).strip()}
    if not known:
        return []
    try:
        text = json.dumps(bundle.model_dump(mode="json"), default=str)
    except Exception as exc:  # noqa: BLE001 — an unreadable bundle cites nothing
        logger.debug("validation: the bundle could not be read for citations (%s).", exc)
        text = ""
    if entry_ids_in(text) & known:
        return []
    listed = ", ".join(sorted(known)[:3])
    return [
        Violation(
            code=UNSUPPORTED_MALWARE_CODE,
            message=(
                "This verdict is Malware and no analyst made a single claim about the "
                "sample, so nothing examined it. Malware is a finding and needs evidence: "
                "cite the ledger entries that establish it — a reputation entry, a YARA or "
                "capa hit, a Sigma match — or return Suspicious and say in the rationale "
                f"that the run was inconclusive. The entries this run recorded include {listed}."
            ),
            path="objects",
        )
    ]

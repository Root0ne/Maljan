"""The questions an analyst asked of a run, answered in a fixed vocabulary.

A job may be submitted with questions (``config.questions``): "what is the
C2?", "how does it persist?". After the narrative round, the report model is
asked once to answer each from the run's own evidence, with one outcome word
of ``reporting.models.QUESTION_OUTCOMES``: established, partial, limited
negative, not determinable from this run, out of scope. The model picks the
word and cites the entries; code checks what it cites:

- every id it cites is one the run issued (an unknown id is named, never
  counted);
- "established" needs at least one answered entry (or sandbox item) among its
  ``evidence_ids``;
- "limited negative" needs a coverage record, ``looked_at``: the entries of
  calls that ran and answered, which is what was looked at;
- an answer that names an analyst's open question (``AgentISR.open_questions``)
  is never a limited negative: an open question is an unknown, not an absence.

The model is told what is wrong and asked once more, as every report round is
(``validation.retry_with_feedback``). What is still refused after that is
printed as "not determinable from this run", with the model's own word and
the reason beside it, never silently replaced. A question the model did not
answer, or a round that did not run, is "not determinable from this run" with
the reason said.

A job asked no question runs no round, and its report carries no answers.
Every step is one pass over the questions, the answers and the ledger.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage
from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator

from maljan.agents.tool_fence import QUOTED_VALUE_STATEMENT, quoted_value
from maljan.core.logger import logger
from maljan.core.spend import SpendCeilingStop
from maljan.pipeline.events import safe_finding_value
from maljan.pipeline.validation import (
    EntryTexts,
    ValidationTally,
    Violation,
    citation_violations,
    misstated_entry_contents,
    retry_with_feedback,
    schema_violations,
    wrong_entry_citations,
)
from maljan.reporting.models import (
    QUESTION_OUTCOMES,
    MalwareReport,
    QuestionAnswer,
    QuestionOutcome,
    outcome_words,
)
from maljan.schemas.evidence import answer_not_shown, is_guard_answer
from maljan.schemas.isr_models import OpenQuestion, open_question_line

# The producer the round's unresolved findings are recorded under.
QUESTION_PRODUCER = "questions"
# The token ledger's name for the round's calls.
QUESTION_CALL = "questions"

# The round's answer, or one reply of it, does not fit the object asked for.
SCHEMA_CODE = "question.schema"

# A question asked of the run got no reply.
UNANSWERED_CODE = "question.unanswered"
# A reply is for a question number that was not asked.
UNKNOWN_NUMBER_CODE = "question.unknown_number"
# A question got more than one reply; the first is kept.
ANSWERED_TWICE_CODE = "question.answered_twice"
# A reply cites an id the run did not issue; it counts for nothing.
UNISSUED_ID_CODE = "question.unissued_id"
# A reply names an open question the analysts did not leave.
UNKNOWN_OPEN_QUESTION_CODE = "question.unknown_open_question"
# "established" with no entry of a call that answered among the ids cited;
# printed as not determinable if it stands.
ESTABLISHED_UNGROUNDED_CODE = "question.established_ungrounded"
# "limited negative" with no coverage record (no call that answered in
# looked_at); printed as not determinable if it stands.
NEGATIVE_WITHOUT_COVERAGE_CODE = "question.negative_without_coverage"
# "limited negative" resting on an open question, which is an unknown, not an
# absence; printed as not determinable if it stands.
NEGATIVE_ON_OPEN_QUESTION_CODE = "question.negative_on_open_question"

# An outcome as a model may spell it, folded to the word the set holds.
_OUTCOME_SPELLINGS: dict[str, str] = {
    **{word: word for word in QUESTION_OUTCOMES},
    "not_determinable_from_this_run": "not_determinable",
}


def asked_questions(raw: Any) -> list[str]:
    """The questions a job was submitted with, each on one line, blanks left out.

    ``config.questions`` as the submit route accepted it: a list of strings.
    Anything else is no question, which is a job that renders as it always did.
    """
    if not isinstance(raw, list | tuple):
        return []
    questions = [" ".join(str(item).split()) for item in raw if isinstance(item, str)]
    return [question for question in questions if question]


class QuestionReply(BaseModel):
    """One answer as the report model writes it."""

    model_config = ConfigDict(extra="ignore")

    # Strict: ``true`` is no question number, though Python reads it as 1.
    question: StrictInt = Field(ge=1)
    outcome: QuestionOutcome
    answer: str = Field(min_length=1)
    evidence_ids: list[str] = Field(default_factory=list)
    looked_at: list[str] = Field(default_factory=list)
    open_questions: list[str] = Field(default_factory=list)

    @field_validator("outcome", mode="before")
    @classmethod
    def _an_outcome_as_spelt(cls, value: Any) -> Any:
        """``"limited negative"`` and ``"Not determinable from this run"`` are the set's words.

        Shape only: a word outside the set stays as written and fails.
        """
        if not isinstance(value, str):
            return value
        folded = re.sub(r"[\s-]+", "_", value.strip().lower())
        return _OUTCOME_SPELLINGS.get(folded, value)


class QuestionRoundOutput(BaseModel):
    """The round's answer: one reply per question."""

    model_config = ConfigDict(extra="ignore")

    answers: list[QuestionReply] = Field(min_length=1)


@dataclass
class QuestionEvidence:
    """What the checks read: the ids the run issued, the calls that answered, the open questions.

    ``issued`` is every id the report may cite; ``answered`` the entries of
    calls that ran and answered with a result the model was shown (a failed
    call, a guard's answer and an answer the conversation had no room for
    are not); ``items`` the run's sandbox section index, whose items stand
    as answered evidence. ``open_questions`` are labelled ``OQ1``, ``OQ2``…
    in the order the analysts left them.
    """

    issued: set[str] = field(default_factory=set)
    answered: set[str] = field(default_factory=set)
    items: Any = None
    open_questions: list[tuple[str, str, OpenQuestion]] = field(default_factory=list)

    @classmethod
    def of(
        cls,
        ledger: Iterable[Any],
        citable: Iterable[str] = (),
        items: Any = None,
        isr_reports: Any = None,
    ) -> QuestionEvidence:
        issued = {_form(value) for value in citable}
        answered: set[str] = set()
        for entry in ledger or ():
            own = _form(getattr(entry, "id", ""))
            if not own:
                continue
            issued.add(own)
            if getattr(entry, "ok", False) and not is_guard_answer(entry):
                if not answer_not_shown(entry):
                    answered.add(own)
        issued.discard("")
        labelled: list[tuple[str, str, OpenQuestion]] = []
        for agent, isr in dict(isr_reports or {}).items():
            for question in list(getattr(isr, "open_questions", None) or []):
                if isinstance(question, OpenQuestion):
                    label = f"OQ{len(labelled) + 1}"
                    labelled.append((label, str(question.source or agent), question))
        return cls(issued=issued, answered=answered, items=items, open_questions=labelled)

    def item(self, value: str) -> bool:
        """Whether ``value`` is a sandbox item the run's report holds, its text read."""
        read = getattr(self.items, "text", None)
        return callable(read) and read(value.strip().strip("[]").strip()) is not None

    def is_issued(self, value: str) -> bool:
        return _form(value) in self.issued or self.item(value)

    def is_answered(self, value: str) -> bool:
        return _form(value) in self.answered or self.item(value)

    def open_question(self, label: str) -> tuple[str, str, OpenQuestion] | None:
        wanted = str(label or "").strip().strip("[]").strip().upper()
        return next((row for row in self.open_questions if row[0] == wanted), None)


def _form(value: Any) -> str:
    """A cited id as it is compared: without brackets or space round it, lower case."""
    return str(value or "").strip().strip("[]").strip().lower()


def _cited(values: Iterable[Any]) -> list[str]:
    return [str(value).strip() for value in values or () if str(value).strip()]


def _shown(values: Sequence[str]) -> str:
    return safe_finding_value(", ".join(values))


@dataclass
class _Judged:
    """One reply as the checks read it: the outcome they stand by and what they found.

    ``notes`` and ``refused`` are what the report prints; ``violations`` are
    the same findings as the retry turn shows them, each with its remedy.
    """

    outcome: str
    refused: str = ""
    notes: list[str] = field(default_factory=list)
    open_questions: list[str] = field(default_factory=list)
    violations: list[Violation] = field(default_factory=list)


def _judge(reply: QuestionReply, evidence: QuestionEvidence, path: str = "") -> _Judged:
    """The checks on one reply: its citations, and the outcome it may stand by.

    Refused: "established" with no answered entry among its ``evidence_ids``,
    "limited negative" with no answered entry in ``looked_at`` or naming an
    open question. Every other word stands as the model wrote it.
    """
    judged = _Judged(outcome=reply.outcome)
    number = safe_finding_value(reply.question)
    cited = _cited(reply.evidence_ids)
    looked = _cited(reply.looked_at)
    unissued = [
        value for value in dict.fromkeys([*cited, *looked]) if not evidence.is_issued(value)
    ]
    if unissued:
        said = f"cites {_shown(unissued)}, which this run did not issue"
        judged.notes.append(said)
        judged.violations.append(
            Violation(
                code=UNISSUED_ID_CODE,
                message=(
                    f"the answer to question {number} {safe_finding_value(said)}. "
                    "Cite only the ids listed in the run's evidence."
                ),
            )
        )
    named: list[str] = []
    unknown: list[str] = []
    for label in _cited(reply.open_questions):
        row = evidence.open_question(label)
        if row is None:
            unknown.append(label)
        else:
            named.append(f"{row[1]}: {row[2].question}")
    judged.open_questions = list(dict.fromkeys(named))
    if unknown:
        said = f"names open question {_shown(unknown)}, which the analysts did not leave"
        judged.notes.append(said)
        judged.violations.append(
            Violation(
                code=UNKNOWN_OPEN_QUESTION_CODE,
                message=(
                    f"the answer to question {number} {safe_finding_value(said)}. "
                    "Name an open question by its label (OQ1), or none."
                ),
            )
        )
    remedy = "Cite the entries that settle it, or choose the outcome the evidence supports."
    if reply.outcome == "established" and not any(evidence.is_answered(v) for v in cited):
        judged.refused = (
            "answered established, but no entry it cites answered: established needs at "
            "least one evidence id of a call that answered"
        )
        judged.violations.append(
            Violation(
                code=ESTABLISHED_UNGROUNDED_CODE,
                message=(
                    f"the answer to question {number} "
                    f"{safe_finding_value(judged.refused)}. {remedy}"
                ),
                path=f"{path}.outcome",
            )
        )
    elif reply.outcome == "limited_negative" and judged.open_questions:
        judged.refused = (
            "answered limited negative while naming an open question: an open question "
            "is an unknown, not an absence"
        )
        judged.violations.append(
            Violation(
                code=NEGATIVE_ON_OPEN_QUESTION_CODE,
                message=(
                    f"the answer to question {number} "
                    f"{safe_finding_value(judged.refused)}. {remedy}"
                ),
                path=f"{path}.outcome",
            )
        )
    elif reply.outcome == "limited_negative" and not any(
        _form(v) in evidence.answered for v in looked
    ):
        judged.refused = (
            "answered limited negative with no coverage record: looked_at names no call "
            "of this run that answered"
        )
        judged.violations.append(
            Violation(
                code=NEGATIVE_WITHOUT_COVERAGE_CODE,
                message=(
                    f"the answer to question {number} "
                    f"{safe_finding_value(judged.refused)}. {remedy}"
                ),
                path=f"{path}.outcome",
            )
        )
    if judged.refused:
        judged.outcome = "not_determinable"
    return judged


def _replies(payload: Any) -> tuple[list[QuestionReply], set[int]] | None:
    """The payload's replies that fit the schema, and the questions of those that do not.

    ``None`` when the payload holds no list of answers at all. One reply that
    does not fit costs its own question, never the others'.
    """
    rows = payload.get("answers") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        return None
    kept: list[QuestionReply] = []
    broken: set[int] = set()
    for row in rows:
        try:
            kept.append(QuestionReply.model_validate(row))
        except Exception:  # noqa: BLE001 — the schema check says why
            number = row.get("question") if isinstance(row, dict) else None
            if isinstance(number, int) and not isinstance(number, bool):
                broken.add(number)
    return kept, broken


def _by_question(replies: list[QuestionReply], count: int) -> dict[int, QuestionReply]:
    """Each question's first reply, by its number; a number outside the list is not one."""
    kept: dict[int, QuestionReply] = {}
    for reply in replies:
        if 1 <= reply.question <= count and reply.question not in kept:
            kept[reply.question] = reply
    return kept


def question_violations(
    payload: Any, questions: Sequence[str], evidence: QuestionEvidence
) -> list[Violation]:
    """What the checks find in the round's answer, as the retry turn shows it.

    Nothing for an answer that does not fit the schema: the schema check
    speaks for it.
    """
    read = _replies(payload)
    if read is None:
        return []
    replies = read[0]
    out: list[Violation] = []
    seen: set[int] = set()
    for index, reply in enumerate(replies):
        path = f"answers.{index}"
        if not 1 <= reply.question <= len(questions):
            out.append(
                Violation(
                    code=UNKNOWN_NUMBER_CODE,
                    message=(
                        f"answer {safe_finding_value(index + 1)} is for question "
                        f"{safe_finding_value(reply.question)}, but only "
                        f"questions 1 to {len(questions)} were asked."
                    ),
                    path=f"{path}.question",
                )
            )
            continue
        if reply.question in seen:
            out.append(
                Violation(
                    code=ANSWERED_TWICE_CODE,
                    message=(
                        f"question {safe_finding_value(reply.question)} is answered more "
                        "than once; the first "
                        "answer is kept. Give each question one answer."
                    ),
                    path=f"{path}.question",
                )
            )
            continue
        seen.add(reply.question)
        out.extend(_judge(reply, evidence, path).violations)
    missing = [str(number) for number in range(1, len(questions) + 1) if number not in seen]
    if missing:
        out.append(
            Violation(
                code=UNANSWERED_CODE,
                message=(
                    f"question(s) {safe_finding_value(', '.join(missing))} "
                    "got no answer. Answer every question, not_determinable where this run "
                    "cannot settle it."
                ),
            )
        )
    return out


# An open question's label as a model may write it, in or out of brackets.
_OPEN_QUESTION_LABEL = re.compile(r"(?i)\bOQ\d+\b")


def _answer_prose(payload: Any) -> dict[str, Any]:
    """Each reply's answer text with the ids it cites, and nothing else, for the prose checks.

    An open question's label (``[OQ1]``) is taken out of the text: it is no
    evidence citation. The other fields are read by :func:`question_violations`.
    """
    rows = payload.get("answers") if isinstance(payload, dict) else None
    out: list[dict[str, Any]] = []
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        text = row.get("answer")
        ids = row.get("evidence_ids")
        out.append(
            {
                "answer": _OPEN_QUESTION_LABEL.sub("", text) if isinstance(text, str) else "",
                "evidence_ids": [str(i) for i in ids] if isinstance(ids, list) else [],
            }
        )
    return {"answers": out}


def unanswered(questions: Sequence[str], why: str) -> list[QuestionAnswer]:
    """Every question as "not determinable from this run", with why no answer was written."""
    return [
        QuestionAnswer(question=question, outcome="not_determinable", checks=[why])
        for question in questions
    ]


def settle(
    payload: Any, questions: Sequence[str], evidence: QuestionEvidence, why_unread: str = ""
) -> list[QuestionAnswer]:
    """The answers the report prints, one per question, in the order asked.

    The model's words and citations are kept as written; an outcome the
    checks refuse is printed as "not determinable from this run" with the
    model's word in ``answered`` and the reason in ``checks``. A question with
    no reply, or a payload that does not fit the schema, is "not determinable
    from this run" with the reason said.
    """
    read = _replies(payload)
    if read is None:
        return unanswered(
            questions, why_unread or "the report model's answer could not be read after its retry"
        )
    replies, broken = read
    kept = _by_question(replies, len(questions))
    out: list[QuestionAnswer] = []
    for number, question in enumerate(questions, 1):
        reply = kept.get(number)
        if reply is None:
            why = (
                "the report model's answer to this question did not fit its schema after its retry"
                if number in broken
                else "the report model wrote no answer to this question"
            )
            out.append(QuestionAnswer(question=question, outcome="not_determinable", checks=[why]))
            continue
        judged = _judge(reply, evidence)
        checks = list(judged.notes)
        if judged.refused:
            checks.append(f"refused: {judged.refused}")
        out.append(
            QuestionAnswer(
                question=question,
                outcome=judged.outcome,  # type: ignore[arg-type]  # a word of the set
                answer=" ".join(reply.answer.split()),
                evidence_ids=_cited(reply.evidence_ids),
                looked_at=_cited(reply.looked_at),
                open_questions=judged.open_questions,
                answered=reply.outcome if judged.refused else None,
                checks=checks,
            )
        )
    return out


# ---------------------------------------------------------------------------
# Prompt
# ---------------------------------------------------------------------------

EXPECTED_OBJECT = """{
  "answers": [
    {
      "question": 1,
      "outcome": "established",
      "answer": "One or more sentences answering the question from the evidence.",
      "evidence_ids": ["ev_0007"],
      "looked_at": [],
      "open_questions": []
    }
  ]
}"""

SYSTEM_PROMPT = (
    "You are a senior malware reverse engineer answering the questions an analyst asked "
    "of this analysis run, from the run's evidence below and nothing else. "
    + QUOTED_VALUE_STATEMENT
    + "\n"
    "Answer every question with exactly one outcome from this fixed set:\n"
    "  - established: the evidence answers it. Cite in evidence_ids the ev_ ids of the "
    "tool results that show it.\n"
    "  - partial: the evidence answers part of it. Say which part, cite what stands "
    "behind that part, and say what is still unknown.\n"
    "  - limited_negative: the run looked and found nothing. List in looked_at the ev_ "
    "ids of the calls that looked; the negative reaches only as far as those calls, so "
    "say what they did not cover.\n"
    "  - not_determinable: this run cannot settle it: nothing looked, the calls that "
    "would have answered failed, or an analyst left it open.\n"
    "  - out_of_scope: no analysis of a sample could answer it, whatever ran.\n"
    "An open question the analysts left is an unknown, not an absence: a question it "
    "bears on is not_determinable (or partial for the part the evidence establishes), "
    "never limited_negative. Name the open questions an answer rests on by their labels "
    "(OQ1) in open_questions.\n"
    "Cite only ev_ ids listed in the evidence above; leave a list empty rather than "
    "invent an id. State facts plainly and write inferences with estimative words "
    "('likely', 'we assess').\n"
    "Answer with exactly this JSON object, one entry of answers per question, numbered "
    "as the questions are:\n" + EXPECTED_OBJECT
)


def _call_line(entry: Any) -> str:
    """One call of the run as the coverage list shows it: id, agent, tool, target, what it gave."""
    if not getattr(entry, "ok", False):
        state = "failed"
    elif is_guard_answer(entry):
        state = "answered by a guard; no tool ran"
    elif answer_not_shown(entry):
        state = "answered; its answer was not shown"
    else:
        state = "answered"
    symbol = str(getattr(entry, "symbol", "") or "").strip()
    target = f" {quoted_value(symbol)}" if symbol else ""
    agent = " ".join(str(getattr(entry, "agent", "") or "").split()) or "pipeline"
    tool = " ".join(str(getattr(entry, "tool", "") or "").split())
    return f"  - {getattr(entry, 'id', '')} [{agent}] {tool}{target}: {state}"


def question_prompt_text(
    report: MalwareReport,
    questions: Sequence[str],
    evidence: QuestionEvidence,
    ledger: Iterable[Any] = (),
    isr_reports: Any = None,
) -> str:
    """The round's human turn after the standing blocks: the findings, the calls, the questions."""
    from maljan.reporting.narrative_agent import findings_lines

    lines = findings_lines(report, isr_reports)
    lines.append("Calls this run made (the ids a coverage record may name):")
    calls = [_call_line(entry) for entry in ledger or ()]
    lines.extend(calls or ["  (none)"])
    lines.append("")
    if evidence.open_questions:
        lines.append("Open questions the analysts left (unknowns, not absences):")
        for label, agent, left in evidence.open_questions:
            # The label unbracketed: a bracket is where an evidence id is cited.
            lines.append(f"  - {label} {agent}: {quoted_value(open_question_line(left))}")
        lines.append("")
    lines.append("QUESTIONS")
    lines.append("---------")
    for number, question in enumerate(questions, 1):
        lines.append(f"{number}. {quoted_value(question)}")
    lines.extend(
        [
            "",
            "TASK",
            "----",
            "Answer each question above with one outcome from the system prompt's set. "
            "Return ONLY the JSON object shown there.",
        ]
    )
    return "\n".join(lines)


def build_messages(
    report: MalwareReport,
    questions: Sequence[str],
    evidence: QuestionEvidence,
    ledger: Iterable[Any] = (),
    isr_reports: Any = None,
    facts_block: str = "",
    run_state: str = "",
) -> list[BaseMessage]:
    """The system turn and the human turn, the standing blocks leading the human turn as the
    narrative round's do."""
    from maljan.pipeline.run_state import with_run_state

    body = question_prompt_text(report, questions, evidence, ledger, isr_reports)
    if facts_block:
        body = f"{facts_block}\n\n{body}"
    if run_state:
        body = f"{with_run_state('', run_state)}\n\n{body}"
    return [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=body)]


# ---------------------------------------------------------------------------
# The round
# ---------------------------------------------------------------------------


@dataclass
class QuestionRound:
    """What the round produced: the answers, what it was told, and what it could not do."""

    answers: list[QuestionAnswer]
    tally: ValidationTally = field(default_factory=ValidationTally)
    degradations: list[str] = field(default_factory=list)


async def answer_questions(
    reporter: Any,
    report: MalwareReport,
    questions: Sequence[str],
    *,
    ledger: Sequence[Any] = (),
    citable_ids: Iterable[str] = (),
    items: Any = None,
    isr_reports: Any = None,
    facts_block: str = "",
    run_state: str = "",
    evidence_texts: EntryTexts | None = None,
    call: str = QUESTION_CALL,
    what: str = "question round's",
) -> QuestionRound:
    """Ask the reporter's model the job's questions once, check the answers, settle them.

    ``reporter`` is the narrative round's agent, whose model, ledger and
    limits the round's calls use (``NarrativeAgent.ask``), recorded on its
    token ledger under ``call`` and its prompt named ``what`` where the
    window cannot hold it: a follow-up question asked of a finished run
    (``reporting.follow_up``) passes its own. No reporter (a
    mock run, one whose report model was unavailable) and a round that fails
    leave every question "not determinable from this run", with the reason.
    Never raises.
    """
    from maljan.llm.answer_text import structured_answer_text
    from maljan.reporting.narrative_agent import _message_text
    from maljan.utils.json_cleaner import safe_parse_json

    tally = ValidationTally()
    if not questions:
        return QuestionRound([], tally)
    evidence = QuestionEvidence.of(ledger, citable_ids, items, isr_reports)
    if reporter is None:
        return QuestionRound(unanswered(questions, "no report model ran in this run"), tally)
    messages = build_messages(
        report, questions, evidence, ledger, isr_reports, facts_block, run_state
    )
    answer_read = [""]

    def _parse(answer: Any) -> Any:
        answer_read[0] = structured_answer_text(answer, _message_text)
        parsed = safe_parse_json(answer_read[0])
        # Shape only: a bare list of answers, or one answer where a list is
        # asked for, is the object the schema names.
        if isinstance(parsed, list):
            parsed = {"answers": parsed}
        if isinstance(parsed, dict) and isinstance(parsed.get("answers"), dict):
            parsed = {**parsed, "answers": [parsed["answers"]]}
        return parsed if isinstance(parsed, dict) else None

    citable = sorted(evidence.issued)
    # What the reporter records of this round's prompt (one its window cannot
    # hold) lands on its own list, read past this mark.
    mark = len(list(getattr(reporter, "degradations", None) or []))

    def _said() -> list[str]:
        return [str(r) for r in list(getattr(reporter, "degradations", None) or [])[mark:]]

    try:
        payload, violations, retries = await retry_with_feedback(
            lambda turns: reporter.ask(turns, call=call, what=what),
            list(messages),
            [
                lambda p: schema_violations(
                    QuestionRoundOutput, p, code=SCHEMA_CODE, answer=answer_read[0]
                ),
                lambda p: question_violations(p, questions, evidence),
                # The answers' prose is read as the narrative's is: its
                # bracketed citations, a value quoted beside an entry that
                # does not hold it, an entry said to hold nothing.
                lambda p: citation_violations(
                    _answer_prose(p), citable, prose=("answers",), items=items
                ),
                lambda p: wrong_entry_citations(_answer_prose(p), evidence_texts),
                lambda p: misstated_entry_contents(
                    _answer_prose(p), evidence_texts, prose=("answers",)
                ),
            ],
            parse=_parse,
            on_feedback=tally.count,
        )
    except SpendCeilingStop as stop:
        said = f"The question round was not written: {stop}."
        logger.warning("question round: %s", said)
        return QuestionRound(
            unanswered(questions, f"the question round was not written: {stop}"),
            tally,
            [*_said(), said],
        )
    except Exception as exc:  # noqa: BLE001 — a failed round leaves the questions unsettled
        logger.error("question round: the round failed (%s).", exc)
        return QuestionRound(
            unanswered(questions, f"the question round failed ({type(exc).__name__})"),
            tally,
            _said(),
        )
    tally.retries += retries
    tally.count(violations)
    if violations:
        tally.record_unresolved(QUESTION_PRODUCER, violations)
    answers = settle(payload, questions, evidence)
    logger.info(
        "question round: %d question(s) answered: %s.",
        len(answers),
        ", ".join(outcome_words(answer.outcome) for answer in answers),
    )
    return QuestionRound(answers, tally, _said())

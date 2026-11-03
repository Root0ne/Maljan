"""What the limitations paragraph rests on, read off the run for the agreement round.

The composer writes section 11's paragraph from the run's recorded limitations
and its open questions (``composer_pro.analyst_bundle("limitations")``), and
nothing held it to the ledger: haiku8's said the reversing tools failed, "so
control flow was read from the function index", while every decompile and
disassembly that failed had been answered by a later call (T-526). Read here,
from the ledger and the report alone:

* **The failed calls**: each call that ran and failed (a repeat answered from
  an earlier entry is not one), with the addresses it was asked for. Whether a
  later call redid it is read by the one rule the run summary reads
  (``redone_calls.redone_failures``, T-494 D6: the same question asked again
  and answered whole); a call asked for no address has nothing to be matched
  by, and stays a failure. A call no later call redid keeps the later calls
  that answered for some of its addresses (``agreement_facts.answered_later``,
  T-396), so the fact can say which ones.
* **The tools not run**: each ``server.<key>.<tool>_unavailable(<reason>)`` the
  run recorded as a limitation or an operator choice, and how many of a
  server's tools the job withheld from the agents.
* **The recorded limitations**: every other reason the run recorded, but the
  note on how an analyst's answer was read (its claims begun and read), which
  says how the platform read the answer, not what the run could not establish.
* **The open questions**: each one the analysts filed, by why it was left open;
  one filed on a failed call or a missing tool names the addresses it is
  about, and a question a later call answered is marked so, never dropped.

Each is a value read once; the text it carries (a tool's message, a reason, a
model's question) is shown quoted by the caller, a tool's message and a reason
scrubbed first as an event payload is (paths to their last segment) and every
URL left out. Linear in the ledger and the report.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from maljan.agents.function_map import one_spelling
from maljan.pipeline.events import scrub
from maljan.reporting.agreement_facts import AnsweredLater, asked_addresses
from maljan.schemas.evidence import entry_ids_in

__all__ = [
    "FailedCall",
    "LimitationFacts",
    "NotRun",
    "OpenQuestion",
    "limitation_facts",
]

# The reasons an open question is filed under that say a tool could not answer:
# the questions the limitations paragraph's failure sentences rest on.
FAILURE_REASONS = ("tool_failed", "no_capable_tool")
# What a reason code may be: the platform's own snake-case word.
_REASON_WORD = re.compile(r"\s*([a-z][a-z_]{0,39})\b")
# A tool the run could not offer, as ``ToolUnavailable.degradation_reason`` writes it.
_UNAVAILABLE = re.compile(r"server\.[\w-]+\.([\w.-]+?)_unavailable\(")
# A tool a server offers that the job withheld from the agents, as the server's
# registry writes it among the operator choices.
_WITHHELD = re.compile(r"\bis withheld:")
# A URL as it stands in a message, which the scrub leaves as its scheme and host.
_URL = re.compile(r"\b[a-zA-Z][\w+.-]*://[^\s,;()]*")


# A digest or an identifier as long as one, which a message repeats in full.
_DIGEST = re.compile(r"\b[0-9a-fA-F]{32,}\b")
# The note the analyst answer's reader records when it could not read every
# claim (``base_agent.claims_unread_sentence``): how the platform read an
# answer, not what the run could not establish.
_ANSWER_READ_NOTE = re.compile(r"^The \S+ analyst's answer\b[^.]*? began \d+ claim\(s\)")


def _plain(text: str) -> str:
    """A tool's message or a reason as a fact quotes it: scrubbed as an event payload is
    (a path to its last segment, a credential masked), and every URL left out."""
    return _URL.sub("a URL", scrub(text))


def _first_clause(text: str) -> str:
    """A tool's message as a fact quotes it: its first clause, a digest in it named so."""
    return _DIGEST.sub("a digest", _plain(text).split(";", 1)[0].strip())


@dataclass(frozen=True)
class FailedCall:
    """A call that failed, the addresses it was asked for, and the later calls that redid it."""

    entry: str
    tool: str
    error: str
    asked: tuple[int, ...] = ()
    # Each address a later call answered for, with that call's id, by the
    # agreement round's address rule: what a call no later call redid says.
    answered: tuple[tuple[int, str], ...] = ()
    # The later calls that redid it (``redone_calls.redone_failures``).
    redone_by: tuple[str, ...] = ()
    # Whether the call lists code (decompiled or disassembled).
    lists_code: bool = False
    # The kind its entry stored (``tool_kinds.kind_of``), else the kind its code
    # is read as (``tool_kinds.code_family_kind``); ``""`` for neither.
    kind: str = ""

    @property
    def redone(self) -> bool:
        """Whether later calls redid it for every address it was asked for."""
        return bool(self.redone_by)


@dataclass(frozen=True)
class NotRun:
    """A tool the run could not offer, and why."""

    tool: str
    reason: str


@dataclass(frozen=True)
class OpenQuestion:
    """A question an analyst left open: why, the entries it cites, the addresses it names."""

    question: str
    reason: str
    cites: tuple[str, ...] = ()
    addresses: tuple[int, ...] = ()


@dataclass(frozen=True)
class LimitationFacts:
    """Everything the limitations paragraph is held to."""

    failed: tuple[FailedCall, ...] = ()
    not_run: tuple[NotRun, ...] = ()
    withheld: int = 0
    recorded: tuple[str, ...] = ()
    questions: tuple[OpenQuestion, ...] = ()


def _error(entry: Any) -> str:
    """A failed call's message: its error, else the message its answer carries."""
    said = str(getattr(entry, "error", None) or "").strip()
    if said:
        return said
    output = str(getattr(entry, "output", None) or "").strip()
    try:
        parsed = json.loads(output)
    except ValueError:
        return output
    found = parsed.get("error") if isinstance(parsed, dict) else None
    if isinstance(found, dict):
        found = found.get("message") or found.get("code")
    return str(found).strip() if found else output


def failed_calls(
    entries: Iterable[Any], answered: Sequence[AnsweredLater], bases: Sequence[int]
) -> list[FailedCall]:
    """Each call that ran and failed, in ledger order, with the later calls that redid it."""
    from maljan.core.undeclared_tools import entry_lists_any_code
    from maljan.reporting.redone_calls import redone_failures
    from maljan.reporting.tool_kinds import code_family_kind, kind_of

    entries = list(entries)
    redid = {
        str(row["entry_id"]): tuple(str(i) for i in row["answered_by"])
        for row in redone_failures(entries)
    }
    by_failed: dict[str, dict[int, str]] = {}
    for link in answered:
        by_failed.setdefault(link.failed, {}).setdefault(link.address, link.answered)
    out: list[FailedCall] = []
    for entry in entries:
        if getattr(entry, "ok", True) or getattr(entry, "repeated_of", None):
            continue
        entry_id = str(getattr(entry, "id", "") or "")
        asked = tuple(dict.fromkeys(one_spelling(a, bases) for a in asked_addresses(entry)))
        linked = by_failed.get(entry_id, {})
        out.append(
            FailedCall(
                entry=entry_id,
                tool=str(getattr(entry, "tool", "") or ""),
                error=_first_clause(_error(entry)),
                asked=asked,
                answered=tuple((a, linked[a]) for a in asked if a in linked),
                redone_by=redid.get(entry_id, ()),
                lists_code=entry_lists_any_code(entry),
                kind=kind_of(entry) or code_family_kind(entry),
            )
        )
    return out


def _parenthesised(text: str, start: int) -> str:
    """The text from ``start`` up to the bracket that closes the one opened before it."""
    depth = 1
    for at in range(start, len(text)):
        if text[at] == "(":
            depth += 1
        elif text[at] == ")":
            depth -= 1
            if not depth:
                return text[start:at]
    return text[start:]


def _not_run(lines: Iterable[str]) -> tuple[list[NotRun], int, list[str]]:
    """The tools not run, the count withheld, and every other line, in order."""
    not_run: list[NotRun] = []
    withheld = 0
    rest: list[str] = []
    for line in lines:
        found = _UNAVAILABLE.match(line.strip())
        if found:
            reason = _parenthesised(line.strip(), found.end())
            not_run.append(NotRun(tool=found.group(1), reason=_plain(reason)))
        elif _WITHHELD.search(line):
            withheld += 1
        else:
            rest.append(line)
    return not_run, withheld, rest


def _cell(columns: Sequence[str], row: Sequence[Any], name: str) -> str:
    """A table row's cell under the column ``name``, or empty."""
    at = columns.index(name) if name in columns else -1
    return str(row[at]).strip() if 0 <= at < len(row) else ""


def open_questions(report: Any, bases: Sequence[int]) -> list[OpenQuestion]:
    """The questions the run left open, as its own table lists them, each once."""
    for section in getattr(report, "sections", None) or []:
        from maljan.reporting.section_agreement import _addresses_named

        columns = list(getattr(section, "columns", None) or [])
        if getattr(section, "key", "") != "open_questions" or "Question" not in columns:
            continue
        out: dict[tuple[str, str], OpenQuestion] = {}
        for row in getattr(section, "rows", None) or []:
            question = _cell(columns, row, "Question")
            if not question:
                continue
            code = _REASON_WORD.match(_cell(columns, row, "Why open"))
            reason = code.group(1) if code else "other"
            named = f"{question} {_cell(columns, row, 'What would answer it')}"
            out.setdefault(
                (question, reason),
                OpenQuestion(
                    question=question,
                    reason=reason,
                    cites=tuple(sorted(entry_ids_in(_cell(columns, row, "Evidence")))),
                    addresses=tuple(
                        dict.fromkeys(one_spelling(a, bases) for a in _addresses_named(named))
                    ),
                ),
            )
        return list(out.values())
    return []


def limitation_facts(
    report: Any, entries: Iterable[Any], answered: Sequence[AnsweredLater], bases: Sequence[int]
) -> LimitationFacts:
    """The facts the limitations paragraph is held to, read off the report and its ledger."""
    reasons = [str(r) for r in getattr(report, "degradation_reasons", None) or [] if str(r).strip()]
    choices = [str(c) for c in getattr(report, "operator_choices", None) or [] if str(c).strip()]
    not_run, withheld, rest = _not_run(dict.fromkeys([*reasons, *choices]))
    # An operator choice that is no tool left out is the operator's, not the run's limitation.
    held = set(reasons)
    recorded = [_plain(line) for line in rest if line in held and not _ANSWER_READ_NOTE.match(line)]
    return LimitationFacts(
        failed=tuple(failed_calls(entries, answered, bases)),
        not_run=tuple(not_run),
        withheld=withheld,
        recorded=tuple(recorded),
        questions=tuple(open_questions(report, bases)),
    )

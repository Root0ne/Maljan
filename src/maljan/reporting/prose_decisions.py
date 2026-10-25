"""The report model's sentences that doubt what the run decided, marked with the decision.

A run publishes a technique by its own rule: corroborated by the analysts'
statements, and kept or dropped by the judge when asked. The report model
writes its prose afterwards and may still call a published technique a
candidate: a stored run published T1053.005 while its persistence prose said
the entry "should therefore be read as a candidate", and published T1497.001
with the judge's note citing the gate's thresholds while a key finding said
the thresholds were not confirmed. Nothing on the report said the two
disagree.

The publication is the decision, and it is printed where the sentence stands:
a sentence of the report model's prose whose clause names a technique this
run publishes and calls it a candidate or not confirmed is returned as a
:class:`FlaggedStatement` labelled with what the run published (the id,
whether it is corroborated, and the judge's kept note where there is one).
The renderers mark it in place like any other flagged sentence and the
console is served it beside the stored ones; the words are never changed and
the stored report is not edited. The model was not asked, as the check reads
the finished report, and the mark says so.

The export's malware object is the judge's and is published as written, so it
can type the sample by a word the report's category does not use: a stored
run's category was ``loader`` (the vocabulary's ``downloader``) and its
judge's object said ``trojan``. The object is not edited; the report's
category line says which types the category names that the object lacks
(:func:`category_types_unstated`), and the console is served the same row.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from maljan.analysis.technique_ids import ID_BODY
from maljan.core.logger import logger
from maljan.reporting.judge_reasons import judge_reasons_shown
from maljan.reporting.models import FlaggedStatement, MalwareReport, TechnicalSubsection

# A sentence of the report model's prose that calls a technique this run
# publishes a candidate or not confirmed; marked in place with the publication.
PUBLISHED_TECHNIQUE_DOUBTED_CODE = "report.published_technique_doubted"
# The report's category names a STIX malware type the judge's malware object,
# published as written, does not carry; marked beside the category line.
CATEGORY_TYPE_UNSTATED_CODE = "report.category_type_unstated"

# A technique id as prose writes it, never part of a longer id or word.
_TECHNIQUE_RE = re.compile(rf"(?<![\w.]){ID_BODY}(?![\w]|\.\d)")
# A doubt bound to the id it follows: only linking words stand between them
# ("T1053.005 should therefore be read as a candidate", "(T1497.001
# candidate)"), so a noun ("T1071.001 traffic went to an unconfirmed host"),
# another id or a negation ("is no longer a candidate", "is not a candidate")
# breaks the binding. The doubt is not itself a modifier: a noun right after
# it ("a candidate host") makes it about that noun.
_LINK = (
    r"(?:is|are|was|were|be|been|being|remains?|stays?|should|would|must|may|might|"
    r"can|could|therefore|thus|so|still|only|merely|read|treated|considered|"
    r"regarded|seen|listed|as|a|an|the|entry|technique|mapping|here|now|yet)"
)
_DOUBT = r"(?:candidates?|unconfirmed|not\s+(?:yet\s+)?confirmed)"
_AFTER_DOUBT = (
    r"(?=\s*(?:$|[^\w\s]|(?:and|or|but|not|only|until|because|since|for|in|on|at|of|"
    r"pending|that|which|rather|here|now|yet|so|as|by|with|without)\b))"
)
_BOUND_DOUBT_RE = re.compile(
    rf"^[\s)\]]*(?:,\s*)?(?:{_LINK}\W+){{0,6}}?{_DOUBT}\b{_AFTER_DOUBT}", re.I
)
# Where a clause ends inside a sentence: a doubt in another clause is about
# what that clause names, not the technique.
_CLAUSE_RE = re.compile(r"[;:]|\s[—–-]\s|,\s*(?:and|but|while|whereas|although|though|yet)\b", re.I)
# A code span or a quotation: words about a text, not a statement of the report.
_QUOTED_RE = re.compile(r"`[^`]*`|\"[^\"]*\"|“[^”]*”")
# Where one sentence of a paragraph ends and the next begins.
_SENTENCE_RE = re.compile(r"(?<=[.!?])[\"')\]]?\s+(?=[A-Z\"'(\[])")


def _sentences(text: str) -> list[str]:
    return [part.strip() for part in _SENTENCE_RE.split(text) if part.strip()]


def _prose(report: MalwareReport) -> Iterator[str]:
    """Each unit of the report model's prose a mark can follow without cutting a text in two.

    A key finding and a flow step are one unit each, as the report prints
    each whole and on one line; the summary and a subsection are read
    sentence by sentence.
    """
    for finding in report.key_findings:
        yield finding.text.strip()
    yield from _sentences(report.executive_summary)
    technical = report.technical_analysis
    if technical is None:
        return
    for step in technical.execution_flow:
        yield step.action.strip()
    for name in type(technical).model_fields:
        part = getattr(technical, name, None)
        if isinstance(part, TechnicalSubsection):
            yield from _sentences(part.body)


def _doubted(sentence: str, published: set[str]) -> list[str]:
    """The published ids ``sentence`` calls a candidate or not confirmed.

    Read clause by clause, with code spans and quotations blanked: the doubt
    must follow the id with only linking words between them
    (:data:`_BOUND_DOUBT_RE`). A false mark reaches every surface, so a
    sentence the rule cannot bind is left unmarked.
    """
    found: list[str] = []
    for clause in _CLAUSE_RE.split(_QUOTED_RE.sub(lambda m: " " * len(m.group(0)), sentence)):
        for match in _TECHNIQUE_RE.finditer(clause):
            tid = match.group(0).upper()
            if (
                tid in published
                and tid not in found
                and _BOUND_DOUBT_RE.match(clause[match.end() :])
            ):
                found.append(tid)
    return found


def statements_against_publication(report: MalwareReport) -> list[FlaggedStatement]:
    """The report model's sentences that call a published technique a candidate. Never raises."""
    try:
        mappings = {m.technique_id.strip().upper(): m for m in report.ttp_mappings}
        if not mappings:
            return []
        notes = {
            cell.technique_id.strip().upper(): cell.note
            for cell in report.capability_matrix
            if cell.note and not cell.not_published
        }
        rows: list[FlaggedStatement] = []
        seen: set[tuple[str, str]] = set()
        for sentence in _prose(report):
            for tid in _doubted(sentence, set(mappings)):
                label = tid + (", corroborated" if mappings[tid].is_corroborated else "")
                if notes.get(tid):
                    label += f"; {judge_reasons_shown(notes[tid])[0]}"
                if (sentence, label) not in seen:
                    seen.add((sentence, label))
                    rows.append(
                        FlaggedStatement(
                            sentence=sentence,
                            code=PUBLISHED_TECHNIQUE_DOUBTED_CODE,
                            label=label,
                            asked=False,
                        )
                    )
        return rows
    except Exception as exc:  # noqa: BLE001 — a mark is never worth a report
        logger.debug("prose_decisions: the published techniques were not read (%s).", exc)
        return []


# A category word another type also answers: a loader that installs what it
# carries is the vocabulary's dropper.
_ALSO_SATISFIES = {"loader": {"dropper"}}


def category_types_unstated(report: MalwareReport) -> FlaggedStatement | None:
    """The category, labelled with the types it names that the export's malware object lacks.

    The object is the first malware object of the export the run stored
    (``stix_bundle_extended``): the judge's, published as written, or the
    export's own, which carries the category's types already. ``None`` when
    the category names no type, when there is no such object or it has no
    type, or when it carries every one, read as the category is read. Never
    raises.
    """
    try:
        from maljan.reporting.renderers.stix_renderer import category_type_words

        category = " ".join(str(report.malware_category or "").split())
        named = category_type_words(category)
        objects = (report.stix_bundle_extended or {}).get("objects") or []
        malware = next(
            (o for o in objects if isinstance(o, dict) and o.get("type") == "malware"), None
        )
        written = [str(t) for t in (malware or {}).get("malware_types") or [] if str(t).strip()]
        # An object with no type decided nothing to disagree with.
        if not named or not written:
            return None
        # The written types read the way the category is read, so a judge that
        # wrote the category's own word (``loader``) wrote its type.
        held = {kind for t in written for _word, kind in category_type_words(t)}
        held |= {t.strip().casefold() for t in written}
        missing = [
            kind
            for word, kind in named
            if kind not in held and not (_ALSO_SATISFIES.get(word, set()) & held)
        ]
        missing = list(dict.fromkeys(missing))
        if not missing:
            return None
        said = ", ".join(written)
        return FlaggedStatement(
            sentence=category,
            code=CATEGORY_TYPE_UNSTATED_CODE,
            label=(
                f"the category names {', '.join(missing)}; the STIX export's malware object, "
                f"as the judge wrote it, is typed {said}"
            ),
            asked=False,
        )
    except Exception as exc:  # noqa: BLE001 — a mark is never worth a report
        logger.debug("prose_decisions: the export's malware types were not read (%s).", exc)
        return None


def with_decided_statements(
    rows: list[FlaggedStatement], report: MalwareReport
) -> list[FlaggedStatement]:
    """``rows`` and, after them, each statement against a decision they do not hold.

    The category row (:func:`category_types_unstated`) is among them: its
    sentence is the category, which a renderer marks on its category line
    rather than wherever the word stands in prose.
    """
    held = {(row.sentence, row.code, row.label) for row in rows}
    category = category_types_unstated(report)
    decided = [*statements_against_publication(report), *([category] if category else [])]
    return [
        *rows,
        *(row for row in decided if (row.sentence, row.code, row.label) not in held),
    ]

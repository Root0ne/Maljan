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
The doubt may follow the id, stand right before it ("possible T1620,") or open
the next clause pointing back at it ("(T1070.004); this is a code-path
candidate"). The renderers mark it in place like any other flagged sentence and the
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
# Matched at the id's end (``Pattern.match(clause, pos)``), so a clause with
# many ids is read once, not copied from each.
_BOUND_DOUBT_RE = re.compile(
    rf"[\s)\]]*(?:,\s*)?(?:{_LINK}\W+){{0,6}}?{_DOUBT}\b{_AFTER_DOUBT}", re.I
)
# A doubt that lasts "until" something: still a doubt ("remains a candidate
# until the sandbox runs it"), unless the sentence says the thing came
# ("a candidate until the sandbox confirmed it", :data:`_AFFIRMED_RE`).
_UNTIL_RE = re.compile(r"\s*until\b", re.I)
# A sentence that says something is confirmed: a doubt word before an id or
# a clause pointing back is then about what was weighed before it ("the likely
# T1071 traffic was confirmed by PCAP", "it was a candidate until the sandbox
# confirmed it"), so neither binds anywhere in it. "not (yet) confirmed" is the
# doubt itself; "observed" is not a word of this kind, as prose says a
# capability was not observed beside a technique it publishes.
_AFFIRMED_RE = re.compile(
    r"(?<!\bnot\s)(?<!\bnot\syet\s)\b(?:confirm(?:s|ed|ing)?|verified|proven|corroborated)\b",
    re.I,
)
# A doubt that modifies the id it stands right before ("(possible T1620, not
# remote injection)"): a closed set of words that say the writer is not sure,
# never a word that names a behaviour. It binds only when the id is followed
# by a closer, a comma or the clause's end, so a noun after the id ("the
# possible T1071 path") keeps the doubt about that noun.
_DOUBT_WORDS = frozenset(
    {
        "possible", "possibly", "potential", "potentially", "probable", "probably", "likely",
        "suspected", "presumed", "presumably", "putative", "tentative", "hypothetical",
        "candidate", "unconfirmed", "unverified",
    }
)  # fmt: skip
# Words anywhere in the clause before the id that deny or rule the doubt out
# ("no evidence of a possible T1620", "hardly a possible", "rather than a
# possible", "the run disproves the possible", "the sandbox ruled it out"); a
# previous clause that holds one and ends in a colon ("Ruled out: possible
# T1620") cuts the doubt too. A clause pointing back does not bind to an id a
# denial or a contrast stands before ("Unlike earlier builds, it skips
# T1564.004; this is a candidate for the next version").
_DENIAL_RE = re.compile(
    r"\b(?:no|not|never|nor|without|hardly|neither|any|unlike|skip(?:s|ped|ping)?|"
    r"disprove[sd]?|eliminat(?:e|ed|es)|"
    r"exclud(?:e|ed|es)|rather\s+than|instead\s+of|rul(?:e|es|ed)\s+(?:\S+\s+){0,2}?out)\b",
    re.I,
)
# How many whitespace-separated tokens before the id must be read: the doubt
# word and the three before it, however much whitespace stands between them.
_TOKENS_BEFORE = 4
_ID_ENDS_PHRASE_RE = re.compile(r"\s*+(?:[)\],]|[.!?]?\s*+\Z)")
# A clause that opens by pointing back at what the previous clause stated and
# calls it a candidate or not confirmed ("(T1070.004); this is a code-path
# candidate and was not observed"). Only a closed set of words may qualify the
# doubt, never a negation, a degree ("hardly") or a selection ("our best
# candidate", "another candidate for persistence"); a noun after it still makes
# it about that noun (:data:`_AFTER_DOUBT`). The present only: "it was a
# candidate" tells what it was before.
_POINTER_DOUBT_RE = re.compile(
    r"\s*(?:this|that|it|which)\s+(?:is|remains|stays)\s+"
    r"(?:(?:still|only|merely|therefore|thus|so|here|now|yet)\s+){0,3}"
    r"(?:an?\s+)?(?:(?:code-path|static|weak|plausible)\s+){0,2}"
    rf"{_DOUBT}\b{_AFTER_DOUBT}",
    re.I,
)
# What may follow the id that a pointing clause binds to, up to the clause's
# end: closing brackets and evidence references, so the id is the last thing
# the previous clause stated ("delete-on-close (T1070.004) [ev_0020]").
# Possessive, with one owner of each whitespace, so a long run is read once.
_CLAUSE_TAIL_RE = re.compile(r"(?:[\s)\]]|\[[\w\s,.-]*\])*+(?:[.,]\s*)?")
# Any bracket between two ids puts them in different groups.
_BRACKET_RE = re.compile(r"[()\[\]]")
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


def _tokens_before(text: str, end: int, floor: int) -> list[str] | None:
    """The :data:`_TOKENS_BEFORE` whitespace-separated tokens ending at ``end``, nearest first.

    Walked back by hand, never past ``floor`` (the previous id's end, or the
    clause's start), so a run of whitespace of any length cannot push a
    negation out of reach and no character is walked for two ids. ``None``
    when the walk reaches the floor before it has read them all.
    """
    tokens: list[str] = []
    i = end
    while len(tokens) < _TOKENS_BEFORE:
        while i > floor and text[i - 1].isspace():
            i -= 1
        j = i
        while j > floor and not text[j - 1].isspace():
            j -= 1
        if j == i:
            return None
        tokens.append(text[j:i])
        i = j
        if j <= floor and len(tokens) < _TOKENS_BEFORE:
            return None
    return tokens


def _doubt_before(clause: str, match: re.Match[str], floor: int) -> bool:
    """Whether a doubt word stands right before the id ``match`` holds and binds to it.

    The caller has read the clause before the id for a denial
    (:data:`_DENIAL_RE`).
    """
    if not _ID_ENDS_PHRASE_RE.match(clause, match.end()):
        return False
    start = match.start()
    # An opening bracket right before the id is not a word ("possible (T1620)").
    while start > floor and clause[start - 1] in "([":
        start -= 1
    tokens = _tokens_before(clause, start, floor)
    return tokens is not None and tokens[0].strip("([,").casefold() in _DOUBT_WORDS


def _ends_clause(clause: str, ids: list[re.Match[str]]) -> re.Match[str] | None:
    """The clause's last id when it is the last thing the clause states, alone in its group.

    Nothing but closers and evidence references may follow it, and no other
    id may share its bracket group ("(T1053.005, T1070.004); this is a
    candidate" does not say which one).
    """
    if not ids or not _CLAUSE_TAIL_RE.fullmatch(clause, ids[-1].end()):
        return None
    last = ids[-1]
    if len(ids) > 1 and not _BRACKET_RE.search(clause, ids[-2].end(), last.start()):
        return None
    return last


def _clauses(text: str) -> Iterator[tuple[str, str]]:
    """Each clause of ``text`` (:data:`_CLAUSE_RE`) with the separator that ends it."""
    start = 0
    for end in _CLAUSE_RE.finditer(text):
        yield text[start : end.start()], end.group(0)
        start = end.end()
    yield text[start:], ""


def _doubted(sentence: str, published: set[str]) -> list[str]:
    """The published ids ``sentence`` calls a candidate or not confirmed.

    Read clause by clause, with code spans and quotations blanked. The doubt
    must follow the id with only linking words between them
    (:data:`_BOUND_DOUBT_RE`), stand right before it (:func:`_doubt_before`),
    or open the next clause by pointing back at it when the id ends its
    clause (:data:`_POINTER_DOUBT_RE`). The last two, and a doubt that
    lasts "until" something, do not bind in a sentence that says something
    is confirmed (:data:`_AFFIRMED_RE`); a doubt word, or a clause pointing
    back, does not bind after a denial (:data:`_DENIAL_RE`). A false mark
    reaches every surface, so a sentence the rule cannot bind is left
    unmarked.
    """
    found: list[str] = []
    blanked = _QUOTED_RE.sub(lambda m: " " * len(m.group(0)), sentence)
    affirmed = _AFFIRMED_RE.search(blanked) is not None
    last: re.Match[str] | None = None
    cut_by_colon = False
    for clause, separator in _clauses(blanked):
        # The previous clause's last id, when nothing but its closers follows it.
        pointed = last.group(0).upper() if last is not None else ""
        if (
            pointed in published
            and pointed not in found
            and not affirmed
            and _POINTER_DOUBT_RE.match(clause)
        ):
            found.append(pointed)
        ids = list(_TECHNIQUE_RE.finditer(clause))
        # Each stretch of the clause is read for a denial once, as the ids
        # are reached in order, so a denial anywhere before an id is held.
        denied, read_to, floor = cut_by_colon, 0, 0
        for match in ids:
            if not denied and _DENIAL_RE.search(clause, read_to, match.start()):
                denied = True
            read_to = match.start()
            tid = match.group(0).upper()
            bound = _BOUND_DOUBT_RE.match(clause, match.end())
            if (
                tid in published
                and tid not in found
                and (
                    (bound and not (affirmed and _UNTIL_RE.match(clause, bound.end())))
                    or (not affirmed and not denied and _doubt_before(clause, match, floor))
                )
            ):
                found.append(tid)
            floor = match.end()
        # A denial before the clause's last id keeps a clause pointing back
        # from binding to it ("The sandbox ruled out T1564.004; it is
        # unconfirmed").
        last = None if denied else _ends_clause(clause, ids)
        cut_by_colon = separator == ":" and _DENIAL_RE.search(clause) is not None
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

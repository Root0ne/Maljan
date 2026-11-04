"""The analyst report: what the sample is and does, in the order a reader acts on it.

The single-file report prints every measured table, every tool's answer, the
run's own bookkeeping and the model's prose side by side, and a reader looking
for what the sample does reads past all of it. This layout prints the same
report's findings in a fixed order — title block, executive summary,
introduction and scope, sample metadata, execution flow, functionality,
command and control, conclusion, detection, recommendations, the ATT&CK
table, limitations, and an appendix — and leaves the rest to the evidence
bundle (``renderers/bundle.py``), which prints every section of the
single-file report and links each citation to its entry.

What decides where a block goes is its kind, never a tool or a family: the
report model's prose, its configuration, command and channel tables, the
persistence and payload rows and the published techniques are findings and
print here; a tool's own table, a rule's hits, the process tree, the static
properties, the run's validation and coverage records, claims set aside and
every number a model put on its confidence print in the bundle.

A citation is not printed in the prose. Each group of evidence ids becomes a
numbered note (``[3]``) linking to the bundle's note of that number, which
lists the ids, each linked to its entry in the bundle's evidence index; each
section ends with a link to the bundle's sections behind it. The words of the
prose are printed as written, defanged, with only the citations moved.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from maljan.pipeline.validation import NUMERIC_CONFIDENCE_CODE, UNPUBLISHED_VALUE_CODE
from maljan.reporting.composer_pro import (
    _NUMERIC_CONFIDENCE,
    ValueReader,
    carrying_form,
    sentences,
    values_not_carried,
)
from maljan.reporting.defang import defang
from maljan.reporting.detection_signatures import analyst_print_gate, rule_standing
from maljan.reporting.judge_reasons import judge_reasons_shown
from maljan.reporting.models import MalwareReport, TechnicalSubsection, outcome_words
from maljan.reporting.renderers.layout import BUNDLE_HTML, BUNDLE_JSON
from maljan.reporting.renderers.markdown import (
    _EV_RE,
    _NETWORK_KINDS,
    _PIPE,
    ANALYST_LIMITATIONS_TITLE,
    _code_span,
    _degraded_sentence,
    _divider,
    _encryption_table,
    _encrypts_files,
    _endpoint,
    _escape_block,
    _fenced,
    _finding_text,
    _header_facts,
    _inline_safe,
    _item,
    _left_out,
    _one_line,
    _paragraph_line,
    _ransomware_block,
    _reputation_line,
    _resolved_only,
    _row,
    _sample_check_line,
    _states_ransomware,
    _step,
    _title_heading,
    _whole,
    confidence_word,
    is_carve_note,
    not_started_by_the_sample_line,
    report_title,
    started_by_the_sample,
)
from maljan.schemas.isr_models import judge_kept_note
from maljan.utils.sentence_cut import left_out_span

if TYPE_CHECKING:
    from maljan.reporting.renderers.markdown import MarkdownRenderer, _Context

# A run of citations written into prose: ``[ev_0004]``, ``[ev_0024][ev_0008]``,
# ``(ev_0021; ev_0025)``, each group with the space before it.
_CITATION_RUN = re.compile(
    r"(?:\s*[\[(]\s*ev_\d+(?:\s*[,;]\s*ev_\d+)*\s*[\])])+",
)
# A list of ids written bare beside other words: ``get_file_report, ev_0018, ev_0030``.
_BARE_IDS = re.compile(r"\bev_\d+(?:\s*,\s*ev_\d+)*\b")
# The numbering a model writes in front of a claim it quotes ("5. Routine …").
_CLAIM_NUMBER = re.compile(r"^\s*\d{1,3}\.\s+")
# Where a procedure's first sentence ends.
_SENTENCE_END = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9(\"'])")

# A value a statement names: an address, or a name with a capital, a digit or an
# underscore inside it (an API, a symbol, a token the sample compares). An
# evidence id is a citation, not a value.
_VALUE = re.compile(
    r"\b0x[0-9a-fA-F]+\b" + _PIPE + r"\b(?!ev_\d)[A-Za-z_][A-Za-z0-9_]*[A-Z0-9_][A-Za-z0-9_]*\b"
)
# The recorders of an indicator row that only observed it (``ConsolidatedIOC.source``):
# a capture or a strings pass. An unexported row of theirs, bound to no code and
# named by no model, is the bundle's; every other row stays in the table.
_OBSERVED_ONLY = frozenset({"sandbox", "strings"})
# Why a value only the report model's identifier table holds is not exported.
_IDENTIFIER_NOT_EXPORTED = (
    "not exported: the report model's identifier table publishes nothing itself"
)
# Where a reader of this report finds every process the sandbox recorded.
_BUNDLE_TREE = "the evidence bundle's process tree"
# The entropy above which the single-file report flags a section [HIGH].
_HIGH_ENTROPY = 7.0
# Up to how many imports the metadata names one by one.
_IMPORTS_NAMED = 10
# How many values a statement must name that the report prints nowhere else.
_NEW_VALUES = 1
# The analyst layer a statement is labelled with ("static: …").
_LAYER_LABEL = re.compile(r"^\s*[\w.-]+:\s+")

# The anchor of a heading in the evidence bundle's HTML: its title without its
# number and voice tag, as the HTML renderer slugs it.
_SLUG = re.compile(r"[^a-z0-9]+")


def bundle_anchor(title: str) -> str:
    """The id the evidence bundle's HTML gives the heading titled ``title``."""
    slug = _SLUG.sub("-", title.lower()).strip("-")
    return f"sec-{slug or 'section'}"


def unique_anchor(anchor: str, taken: set[str]) -> str:
    """``anchor``, or the first of ``anchor-2``, ``anchor-3``… not in ``taken``; then taken.

    The one counter the bundle's HTML and its JSON number a repeated title by,
    so a section's anchor is the same in both.
    """
    unique, n = anchor, 2
    while unique in taken:
        unique, n = f"{anchor}-{n}", n + 1
    taken.add(unique)
    return unique


# Each section of this report, the sections of the evidence bundle that hold
# what it rests on, by the bundle heading's title.
_BEHIND: dict[str, tuple[str, ...]] = {
    "summary": ("Key findings", "Questions asked of this run"),
    "scope": ("Methodology", "Background"),
    "metadata": ("Sample overview", "Static properties"),
    "flow": ("Execution flow", "Observed behaviour"),
    "functionality": ("Technical analysis",),
    "c2": ("Command and control", "Configuration", "Commands and capabilities"),
    "conclusion": ("Verdict and assessment", "Attribution and related activity"),
    "detection": ("Indicators of compromise", "Detection"),
    "recommendations": ("Recommendations",),
    "attack": ("MITRE ATT&CK mapping",),
    "limitations": ("Limitations and analysis notes", "Run summary"),
    "appendix": ("Evidence index", "References"),
}

# The figures whose section this report prints; every other figure is drawn
# in the bundle, beside the section it illustrates there.
FIGURE_KINDS: frozenset[str] = frozenset(
    {"execution_flow", "infection_chain", "network_graph", "attack_matrix"}
)


@dataclass(frozen=True)
class CitationNote:
    """One numbered note: the evidence ids a passage of the analyst report rests on."""

    number: int
    evidence_ids: tuple[str, ...]
    section: str


@dataclass
class CitationNotes:
    """The notes of one render, numbered in the order the report cites them.

    The same set of ids cited twice is one note, cited twice.
    """

    ctx: _Context
    section: str = ""
    notes: list[CitationNote] = field(default_factory=list)
    _by_ids: dict[tuple[str, ...], CitationNote] = field(default_factory=dict)

    def marker(self, ids: Iterable[Any]) -> str:
        """The note marker for ``ids`` (``[3]``, linked), or ``""`` when there are none."""
        note = self._note(ids)
        if note is None:
            return ""
        # Set aside from the closing pass: a file name is no host to defang.
        return self.ctx.keep(f"[[{note.number}]]({BUNDLE_HTML}#cite-{note.number})")

    def linked(self, evidence_id: str) -> str:
        """One id the prose names as a word, kept, as a link to its note in the bundle."""
        note = self._note([evidence_id])
        if note is None:
            return evidence_id
        return self.ctx.keep(f"[{evidence_id}]({BUNDLE_HTML}#cite-{note.number})")

    def _note(self, ids: Iterable[Any]) -> CitationNote | None:
        key = tuple(dict.fromkeys(_one_line(i).strip() for i in ids if str(i).strip()))
        if not key:
            return None
        note = self._by_ids.get(key)
        if note is None:
            note = CitationNote(len(self.notes) + 1, key, self.section)
            self.notes.append(note)
            self._by_ids[key] = note
        return note

    def moved(self, text: str, ids: Iterable[Any] = ()) -> str:
        """``text`` with each citation written into it a note marker, and ``ids`` it does not
        cite as one more marker at its end."""
        cited: list[str] = []

        def note(found: re.Match[str]) -> str:
            group = _EV_RE.findall(found.group(0))
            cited.extend(group)
            return self.marker(group)

        text = _CITATION_RUN.sub(note, str(text or ""))

        def bare(found: re.Match[str]) -> str:
            group = _EV_RE.findall(found.group(0))
            cited.extend(group)
            if len(group) == 1:
                return self.linked(group[0])
            return self.marker(group)

        text = _BARE_IDS.sub(bare, text)
        rest = [i for i in ids if str(i).strip() and _one_line(i).strip() not in cited]
        if rest:
            text = text.rstrip() + self.marker(rest)
        return text


def analyst_sections(
    renderer: MarkdownRenderer, report: MalwareReport, ctx: _Context
) -> tuple[list[str], list[CitationNote]]:
    """The analyst report's sections in their fixed order, and the notes they cite."""
    layout = _Analyst(report, ctx)
    plan: list[tuple[str, Callable[[], str]]] = [
        ("title", layout.title),
        ("summary", layout.summary),
        ("scope", layout.scope),
        ("metadata", layout.metadata),
        ("flow", layout.flow),
        ("functionality", layout.functionality),
        ("c2", layout.c2),
        ("conclusion", layout.conclusion),
        ("detection", layout.detection),
        ("recommendations", layout.recommendations),
        ("attack", layout.attack),
        ("limitations", layout.limitations),
        ("appendix", layout.appendix),
    ]
    sections: list[str] = []
    for key, build in plan:
        layout.notes.section = key
        sections.append(layout.counted(key, renderer._safe_section(f"analyst_{key}", build)))
        layout.written.append(sections[-1])
    if layout.composed():
        # The sections where composed prose replaces the platform's text are
        # written again, now that the whole report is known: the replaced text
        # that names a value printed nowhere else in it stays (``_keeps``). A
        # value only a sentence the analyst report leaves out names is printed
        # in the bundle beside it, so it brings no replaced text back.
        flagged = "\n".join(sentence for sentence, _mark in ctx.flagged)
        layout.elsewhere = carrying_form("\n".join([*sections, flagged]))
        for index, (key, build) in enumerate(plan):
            if key in _REPLACING:
                layout.notes.section = key
                sections[index] = layout.counted(
                    key, renderer._safe_section(f"analyst_{key}", build)
                )
    return sections, list(layout.notes.notes)


# What a closing section says when every sentence the report model wrote of it
# was left out (T-555).
_LEFT_OUT_WHOLE = (
    "The {what} the report model wrote {verb} left out; the bundle lists each of its "
    "sentences with the reason."
)
# The sections in which a composed section replaces the platform's own text.
_REPLACING = frozenset({"summary", "conclusion", "attack"})


def _heading(number: int, title: str) -> str:
    return f"## {number}. {_one_line(title)}"


def _subheading(number: str, title: str) -> str:
    return f"### {number} {_one_line(title)}"


def _behind(key: str, *, absent: tuple[str, ...] = ()) -> str:
    """The line a section ends with: the bundle's sections behind it, linked.

    Each title is one the bundle always prints (a numbered section or
    subsection prints a line when it has nothing); ``absent`` names one it
    does not print for this report.
    """
    links = ", ".join(
        f"[{title}]({BUNDLE_HTML}#{bundle_anchor(title)})"
        for title in _BEHIND.get(key, ())
        if title not in absent
    )
    return f"_In the evidence bundle: {links}._" if links else ""


def _first_sentence(text: str) -> str:
    """A claim's first sentence, without the number a model wrote in front of it."""
    body = _CLAIM_NUMBER.sub("", _one_line(text).strip())
    return _SENTENCE_END.split(body, maxsplit=1)[0].strip()


def _confidence_words(value: float | None) -> str:
    return confidence_word(value) if value is not None else ""


# How long a step's label in the execution-flow diagram may be, and from how
# many steps the diagram is drawn: one step is no flow.
_LABEL_CHARS = 72
_DIAGRAM_STEPS = 2


def flow_steps(report: MalwareReport) -> list[tuple[str, str, str]]:
    """Each execution-flow step as the diagram draws it: its label, its mark, its sentence.

    The label is the step's first sentence, its citations out, shortened at
    the last word that fits :data:`_LABEL_CHARS` with a mark (never inside a
    word); the sentence is the whole first sentence, which the HTML figure
    carries as each box's title and the numbered steps under the diagram
    print whole. ``observed`` or ``assessed`` as the step is marked. Read by
    the Markdown's diagram and by the HTML's figure
    (``figures.build_execution_flow``), so both draw the same boxes.
    """
    ta = report.technical_analysis
    steps = sorted(ta.execution_flow, key=lambda s: s.order) if ta is not None else []
    out: list[tuple[str, str, str]] = []
    for index, step in enumerate(steps, start=1):
        sentence = _first_sentence(_CITATION_RUN.sub("", str(step.action or "")))
        mark = "observed" if step.voice == "observed" else "assessed"
        out.append((f"{index}. {_word_cut(sentence, _LABEL_CHARS)}", mark, f"{index}. {sentence}"))
    return out if len(out) >= _DIAGRAM_STEPS else []


def flow_step_labels(report: MalwareReport) -> list[tuple[str, str]]:
    """Each execution-flow step's label and mark (:func:`flow_steps`)."""
    return [(label, mark) for label, mark, _sentence in flow_steps(report)]


def _word_cut(text: str, limit: int) -> str:
    """``text`` whole when it fits ``limit``, else cut after its last whole word that fits,
    with a mark; a first word longer than the limit is cut where the limit falls."""
    if len(text) <= limit:
        return text
    head = text[: limit - 1]
    after, beyond = text[limit - 1], text[limit : limit + 1]
    # A mark ends the word only where a space or the text's end follows it: the
    # dot in "a.example" is inside a token.
    ends = after in _WORD_ENDS and (not beyond or beyond.isspace())
    if not (after.isspace() or (_word_char(head[-1]) and ends)):
        # The cut falls inside a word or a token: back to the space before it.
        # A cut before a space, or before a mark that ends a whole word, keeps
        # the word.
        space = head.rfind(" ")
        if space > 0:
            head = head[:space]
    return head.rstrip(" ,;:([{") + "\u2026"


# The marks that end a whole word in a sentence.
_WORD_ENDS = frozenset(",;:.!?)")


def _word_char(char: str) -> bool:
    return char.isalnum() or char == "_"


def _mermaid_label(text: str) -> str:
    """A label inside a Mermaid node's quotes: its quotes and entity marks written as entities."""
    return text.replace("#", "#35;").replace('"', "#quot;")


# The words a C2 message layout's field is annotated with, by the conversion
# its recorded format string gives the field's value.
_FORMAT_WORDS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"%[-+ 0#]*\d*[hlLqjztI0-9]*[xX]"), "a hexadecimal number"),
    (re.compile(r"%[-+ 0#]*\d*[hlLqjztI0-9]*[diu]"), "a decimal number"),
    (re.compile(r"%[-+ 0#]*\d*l?[sS]"), "a text"),
    (re.compile(r"%[-+ 0#]*\d*c"), "a character"),
    (re.compile(r"%[-+ 0#]*\d*(?:\.\d+)?[fg]"), "a decimal fraction"),
)
# A recorded message format: ``name=value`` fields joined by ``&``, at least two.
_QUERY_FORMAT = re.compile(r"^[\w.\[\]-]+=[^&\s]*(?:&[\w.\[\]-]+=[^&\s]*)+$")


def message_fields(fmt: str) -> list[tuple[str, str, str]]:
    """The fields of a recorded ``name=value&...`` message format: name, value, annotation.

    The annotation is the conversion's own meaning (``%d`` a decimal number,
    ``%s`` a text); a value with no conversion is the value as recorded. A
    format of any other shape has no fields here.
    """
    text = _CITATION_RUN.sub("", str(fmt or "")).strip()
    if not _QUERY_FORMAT.match(text):
        return []
    out: list[tuple[str, str, str]] = []
    for part in text.split("&"):
        name, _, value = part.partition("=")
        out.append((name, value, _value_words(value)))
    return out


# One conversion of a format string, any of :data:`_FORMAT_WORDS`.
_CONVERSION = re.compile(_PIPE.join(f"(?:{pattern.pattern})" for pattern, _ in _FORMAT_WORDS))


def _value_words(value: str) -> str:
    """What a field's recorded value holds: each conversion in words, each literal quoted."""
    if not value:
        return "empty"
    if not _CONVERSION.search(value):
        return "the value as recorded" if "%" not in value else "as recorded"
    said: list[str] = []
    at = 0
    for match in _CONVERSION.finditer(value):
        if match.start() > at:
            said.append(f'"{value[at : match.start()]}"')
        said.append(next(w for pattern, w in _FORMAT_WORDS if pattern.fullmatch(match.group(0))))
        at = match.end()
    if at < len(value):
        said.append(f'"{value[at:]}"')
    return ", then ".join(said)


def _left_out_rows(count: int, what: str) -> str:
    """The line under a table some of whose rows only the bundle prints (T-555)."""
    one = count == 1
    return (
        f"{count} further {what}{'' if one else 's'} {'is' if one else 'are'} not printed "
        f"here: a check left a finding on {'it' if one else 'each'}; the bundle lists "
        f"{'it' if one else 'each'} with the reason."
    )


def _left_out_sentences(count: int) -> str:
    """The line a section ends with where sentences of it only the bundle prints (T-555)."""
    one = count == 1
    return (
        f"_{count} sentence{'' if one else 's'} of this section {'was' if one else 'were'} "
        "left out; the bundle lists each with the reason._"
    )


# The number a written confidence holds, a percentage read as its fraction.
_CONFIDENCE_NUMBER = re.compile(
    r"(\d{1,3}(?:\.\d+)?)\s?%" + _PIPE + r"(\d?\.\d{1,3}" + _PIPE + r"1\.0{1,3})"
)


# The state the analyst report writes after a value the run does not publish, in
# its own fixed words: never the model's, never the table's reason (T-555).
UNPUBLISHED_STATE = "not a published indicator"
# A bracket that speaks of publication: what the model wrote of a value's publish
# state, which the platform's own state replaces. Any other bracket ("(UDP 53)")
# is the model's description of the value, and stays.
_ABOUT_PUBLICATION = re.compile(
    r"publish" + _PIPE + r"indicator" + _PIPE + r"\bIOCs?\b" + _PIPE + r"export" + _PIPE + r"STIX",
    re.IGNORECASE,
)


def _whole_value(value: str) -> re.Pattern[str]:
    """``value`` as a whole token, in any case: never part of a longer address, host, path
    or URL ("8.8.8.8" in "18.8.8.81", "evil.example.com" in "notevil.example.com" or in
    "https://evil.example.com/gate.php")."""
    return re.compile(
        r"(?<![\w.\-/:@])" + re.escape(value) + r"(?![\w\-]" + _PIPE + r"\.\w" + _PIPE + r"/)",
        re.IGNORECASE,
    )


def _url_host(value: str) -> re.Pattern[str]:
    """``value`` as the host of a URL or a path, in any case: after ``://`` or at the start
    of its token, and before ``/``, ``:`` or the end of its token
    ("https://evil.example.com/gate.php", "evil.example.com/gate"); never part of a longer
    host."""
    return re.compile(
        r"(?:(?<=://)"
        + _PIPE
        + r"(?<![^\s`'\"(\[<\u2018\u201c]))"
        + re.escape(value)
        + r"(?![\w\-]"
        + _PIPE
        + r"\.\w)",
        re.IGNORECASE,
    )


def _past_open_span(sentence: str, start: int, end: int) -> int:
    """``end``, or just past the closing mark where ``start`` stands inside an open code
    span (an odd count of backticks before it) or an open double quotation, straight or
    curly: the state is never written inside one."""
    before = sentence[:start]
    for closer, inside in (
        ("`", before.count("`") % 2 == 1),
        ('"', before.count('"') % 2 == 1),
        ("\u201d", before.rfind("\u201c") > before.rfind("\u201d")),
    ):
        if inside:
            close = sentence.find(closer, start)
            if close != -1:
                return max(end, close + 1)
    return end


# What a token ends with that the state is written before: a sentence's or a
# clause's punctuation, and a closing bracket.
_TOKEN_TAIL = ".,;:)"


def _token_end(sentence: str, end: int) -> int:
    """Where the token a value ends at ``end`` ends: up to the next space, then back over
    trailing punctuation, so the state lands past a closing backtick or quote and never
    inside a code span, a quotation or a URL."""
    stop = end
    while stop < len(sentence) and not sentence[stop].isspace():
        stop += 1
    while stop > end and sentence[stop - 1] in _TOKEN_TAIL:
        stop -= 1
    return stop


def _with_unpublished_state(sentence: str, values: Iterable[str]) -> str | None:
    """``sentence`` with the platform's state written after the first place each value
    stands as a whole token (:func:`_whole_value`) that no earlier value's place
    overlaps, or else as a URL's or a path's host (:func:`_url_host`), at the end of
    its token and past a code span or a quotation it stands in: a bracket right after
    it that speaks of publication is replaced, any other is kept with the state after
    it. Deterministic: the words are fixed, whatever the model wrote. ``None`` where a
    value stands nowhere: the sentence is then left out."""
    edits: list[tuple[int, int, str]] = []
    claimed: list[tuple[int, int]] = []
    for value in dict.fromkeys(v for v in values if v):
        found = None
        # A value standing alone first; else as a URL's or a path's host, the
        # state after the whole URL.
        for pattern in (_whole_value(value), _url_host(value)):
            for match in pattern.finditer(sentence):
                stop = _past_open_span(sentence, match.start(), _token_end(sentence, match.end()))
                if not any(a < stop and match.start() < b for a, b in claimed):
                    found = (match.start(), stop)
                    break
            if found is not None:
                break
        if found is None:
            return None
        begin, end = found
        bracket = re.match(r"\s*\(", sentence[end:])
        if bracket is not None:
            depth, close = 1, end + bracket.end()
            while close < len(sentence) and depth:
                depth += {"(": 1, ")": -1}.get(sentence[close], 0)
                close += 1
            claimed.append((begin, close))
            if _ABOUT_PUBLICATION.search(sentence[end + bracket.end() : close]):
                edits.append((end, close, f" ({UNPUBLISHED_STATE})"))
                continue
            end = close
        else:
            claimed.append((begin, end))
        edits.append((end, end, f" ({UNPUBLISHED_STATE})"))
    for begin, stop, said in sorted(edits, reverse=True):
        sentence = sentence[:begin] + said + sentence[stop:]
    return sentence


def _worded_confidence(sentence: str) -> str:
    """``sentence`` with each confidence written as a number written as its word
    (``composer_pro._NUMERIC_CONFIDENCE``, ``confidence_word``)."""

    def _word(match: re.Match[str]) -> str:
        said = match.group(0)
        found = _CONFIDENCE_NUMBER.search(said)
        if found is None:
            return said
        value = float(found.group(1)) / 100 if found.group(1) else float(found.group(2))
        return confidence_word(min(max(value, 0.0), 1.0))

    out: list[str] = []
    at = 0
    for match in _NUMERIC_CONFIDENCE.finditer(sentence):
        end = match.end()
        # An opening bracket the match took is closed by the one after it.
        if "(" in match.group(0) and sentence[end : end + 1] == ")":
            end += 1
        start = match.start()
        out.extend([sentence[at:start], _word(match)])
        at = end
    out.append(sentence[at:])
    return "".join(out)


class _Analyst:
    """The sections of one analyst report, over one render's context."""

    def __init__(self, report: MalwareReport, ctx: _Context) -> None:
        self.report = report
        self.ctx = ctx
        self.notes = CitationNotes(ctx)
        self.ta = report.technical_analysis
        # The composer's procedure of each published technique, by id (``attack``).
        self._procedures: dict[str, Any] = {}
        # Every section as first written, once known and in ``carrying_form``:
        # what a replaced text's values are looked for in (``_keeps``). ``None``
        # on the first writing.
        self.elsewhere: str | None = None
        # What counts as a value of the sample's own here (``composer_pro.ValueReader``).
        self.values = ValueReader.of(report)
        # What the sections before the one being written printed.
        self.written: list[str] = []
        # How many sentences the section being written left out (``counted``).
        self.left = 0

    # -- shared writing ---------------------------------------------------

    def _unflagged(self, text: str, *, count: bool = True) -> str:
        """``text`` as the analyst report prints each sentence a check left standing (T-555).

        The single-file report, which the bundle prints whole, prints each
        such sentence with its mark (``_Context.marked``); the analyst report
        prints no mark. A sentence flagged only for a value the run does not
        publish stands with the platform's fixed state after each such value,
        in place of any bracket of the model's on publication, and is left out
        where such a value stands nowhere as a whole token; one flagged only
        for a confidence written as
        a number stands with the confidence in words; any other is left out,
        with the spaces ``left_out_span`` takes, and counted where ``count``.
        A sentence is found as written and with its citations taken out, as
        a procedure's first sentence is printed. One pass over the flagged
        sentences, the longest first.
        """
        edits: list[tuple[int, int, str | None]] = []
        for sentence, _mark in self.ctx.flagged:
            if not sentence:
                continue
            codes = self.ctx.flag_codes.get(sentence, [])
            for form in dict.fromkeys((sentence, _CITATION_RUN.sub("", sentence).strip())):
                start = text.find(form) if form else -1
                while start != -1:
                    end = start + len(form)
                    if not any(a < end and start < b for a, b, _ in edits):
                        edits.append((start, end, self._flag_rewrite(form, codes)))
                    start = text.find(form, start + 1)
        for start, end, rewrite in sorted(edits, reverse=True):
            if rewrite is None:
                start, end = left_out_span(text, start, end)
                rewrite = ""
                if count:
                    self.left += 1
            text = text[:start] + rewrite + text[end:]
        return text

    def _flag_rewrite(self, sentence: str, codes: list[str]) -> str | None:
        """What the analyst report prints for one flagged sentence, or ``None`` to leave
        it out (:meth:`_unflagged`): a value the run does not publish given the
        platform's own state, a confidence written as a number worded."""
        if codes == [UNPUBLISHED_VALUE_CODE]:
            # The sentence stands with the platform's own state after each value
            # the run does not publish, in place of what the model wrote of it;
            # the mark, with the table's reason, is the bundle's.
            try:
                unstated = self.ctx._unstated(sentence)
            except Exception:  # noqa: BLE001 — a sentence not read is left out
                return None
            return _with_unpublished_state(sentence, (value for _kind, value, _ in unstated))
        if codes == [NUMERIC_CONFIDENCE_CODE]:
            return _worded_confidence(sentence)
        return None

    def counted(self, key: str, section: str) -> str:
        """``section`` with the line saying how many of its sentences were left out, before
        the line linking the bundle; the count starts over for the next section.

        The conclusion and the limitations also count the sentences the agreement
        question left out of them (``section_agreement.DROPPED_CODE``).
        """
        from maljan.reporting.section_agreement import DROPPED_CODE

        left = self.left + sum(
            1
            for row in self.ctx.unresolved
            if row.get("code") == DROPPED_CODE and row.get("subject") == key
        )
        self.left = 0
        if not left:
            return section
        said = _left_out_sentences(left)
        head, sep, tail = section.rpartition("\n_In the evidence bundle: ")
        if sep:
            return f"{head}\n{said}\n{sep.lstrip(chr(10))}{tail}"
        return f"{section}\n\n{said}"

    def composed(self) -> bool:
        """Whether the composer wrote any section that replaces the platform's text."""
        ta = self.ta
        return ta is not None and bool(
            ta.capability_summary or ta.analyst_conclusion or ta.technique_procedures
        )

    def _keeps(self, text: str) -> bool:
        """Whether replaced text stays: it names a value printed nowhere else in the
        report (``composer_pro.carried_values``)."""
        if self.elsewhere is None or not str(text or "").strip():
            return False
        return bool(values_not_carried(self.values(text), self.elsewhere, formed=True))

    def _kept_sentences(self, text: str) -> list[str]:
        """The sentences of replaced text that stay (:meth:`_keeps`), as written, in order."""
        return [sentence for sentence in sentences(text) if self._keeps(sentence)]

    def _flagged_whole(self, text: Any) -> bool:
        """Whether nothing of ``text`` is left once its flagged sentences are left out."""
        return (
            bool(str(text or "").strip())
            and not self._unflagged(_one_line(text), count=False).strip()
        )

    def _prose(self, text: str, ids: Iterable[Any] = ()) -> str:
        """Model prose as a paragraph: its flagged sentences left out, defanged, its
        citations moved to note markers."""
        kept = self._unflagged(str(text or "").strip())
        return _escape_block(self.notes.moved(self.ctx.plain(kept), ids))

    def _line(self, text: Any, ids: Iterable[Any] = ()) -> str:
        """Model prose on one line, for an item, a step or a cell; ``-`` where every
        sentence of it was flagged."""
        kept = self._unflagged(_one_line(text))
        if not kept.strip():
            return "-"
        return _one_line(self.notes.moved(self.ctx.plain(kept), ids))

    def _findings(self, rows: list[dict[str, str]]) -> list[str]:
        """The platform's unresolved findings on a section, one item each."""
        return [
            _item(f"_Unresolved:_ {_code_span(row['code'])}: {_finding_text(row, self.ctx.plain)}")
            for row in rows
        ]

    def _cell(self, text: Any) -> str:
        return self._line(text) if str(text or "").strip() else "-"

    def _verdict(self) -> str:
        report = self.report
        if report.verdict_not_assessed:
            return f"not assessed ({_one_line(report.verdict_not_assessed)})"
        said = _confidence_words(report.overall_confidence)
        return f"{_one_line(report.verdict)}" + (f" ({said})" if said else "")

    def _family(self) -> str:
        attr = self.report.attribution
        family = _one_line(attr.family)
        if not family or family.lower() == "unknown":
            return "none attributed"
        if attr.family_source == "sandbox":
            return f"{family} (named by the sandbox's classification)"
        said = _confidence_words(attr.family_confidence)
        family += f" ({said})" if said else ""
        # Grounded as the single-file report grounds it (``_family_words``):
        # the entries the judge cited, or that it cited none.
        if attr.family_evidence_ids:
            family += self.notes.marker(attr.family_evidence_ids)
        elif not attr.family_grounded:
            family += " (no evidence cited)"
        return family

    def _category(self) -> str:
        category = _one_line(self.report.malware_category).strip()
        return category if category and category.lower() != "unknown" else ""

    def _subsection(
        self, number: str, title: str, prose: list[TechnicalSubsection | None], body: list[str]
    ) -> list[str]:
        parts = [sub for sub in prose if sub is not None and sub.body.strip()]
        if not parts and not body:
            return []
        lines = [_subheading(number, title), ""]
        for sub in parts:
            lines.extend([self._prose(sub.body, sub.evidence_refs), ""])
        lines.extend(body)
        return [*lines, ""]

    # -- title block ------------------------------------------------------

    def title(self) -> str:
        report, ctx = self.report, self.ctx
        lines = [_title_heading(report_title(report)), ""]
        fm = report.front_matter
        if fm is not None:
            parts = [f"**TLP:{fm.tlp}**"]
            if fm.report_number:
                parts.append(f"Report {fm.report_number}")
            parts.append(fm.report_date or report.generated_at.date().isoformat())
            parts.append(f"{fm.publisher} {fm.product_type}")
            lines.append(" · ".join(parts) + "  ")
        else:
            lines.append(f"{report.generated_at.date().isoformat()}  ")
        severity = report.severity.rating if report.severity else "not assessed"
        facts = [f"**Verdict:** {self._verdict()}", f"**Severity:** {_one_line(severity)}"]
        facts.append(f"**Family:** {self._family()}")
        if self._category():
            facts.append(f"**Category:** {self._category()}{ctx.category_mark}")
        lines.append(" · ".join(facts) + "  ")
        ident = report.identity
        lines.append(
            f"**Sample:** {_code_span(ident.hashes.sha256 or 'unknown')} "
            f"({_inline_safe(ident.file_type, plain=ctx.plain)}, "
            f"{ident.file_size_bytes:,} bytes)"
        )
        for row in ctx.verdict_findings:
            lines.append(
                f"  \n_Unresolved on the verdict: {_code_span(row['code'])}: "
                f"{_one_line(_finding_text(row, ctx.plain))}_"
            )
        if report.verdict_not_assessed:
            lines.append(
                "\n> **[NO VERDICT]** No verdict was assessed: "
                f"{_one_line(report.verdict_not_assessed)}, so no judge ran."
            )
        elif report.overall_confidence is None:
            lines.append(
                "\n> **[NO CONFIDENCE ASSESSED]** The judge assessed no confidence for this "
                "verdict, and none is substituted for one."
            )
        if report.degraded_mode:
            lines.append("\n> **[DEGRADED RUN]** " + _degraded_sentence(report, ctx))
        return "\n".join(lines)

    # -- 1. executive summary ----------------------------------------------

    def summary(self) -> str:
        report = self.report
        lines = [_heading(1, "Executive summary"), ""]
        bullets = list(self.ta.capability_summary) if self.ta is not None else []
        # The composer's capability bullets where it wrote them; the key
        # findings and the summary paragraph are then the bundle's, but for a
        # finding naming a value printed nowhere else. A bullet or finding a
        # check flagged whole is the bundle's alone (T-555).
        findings = [f for f in report.key_findings if not self._flagged_whole(f.text)]
        if bullets:
            findings = [f for f in findings if self._keeps(f.text)]
        else:
            self.left += len(report.key_findings) - len(findings)
        for bullet in bullets:
            if self._flagged_whole(bullet.text):
                self.left += 1
            else:
                lines.append(_item(self._line(bullet.text, bullet.evidence_refs)))
        for finding in findings:
            lines.append(_item(self._line(finding.text, finding.evidence_ids)))
        summary = report.executive_summary.strip()
        if bullets:
            summary = " ".join(self._kept_sentences(summary))
        if summary:
            if findings or bullets:
                lines.append("")
            lines.append(self._prose(summary))
        if not summary and not findings and not bullets:
            lines.append(
                "No summary was written in this run; the findings below are the platform's "
                "own record of what the run established."
            )
        if self.ctx.narrative_findings:
            lines.extend(["", *self._findings(self.ctx.narrative_findings)])
        verdict = [f"the verdict is {self._verdict()}"]
        family = self._family()
        verdict.append(
            f"the family is {family}" if family != "none attributed" else "no family is attributed"
        )
        if report.severity is not None:
            verdict.append(f"the severity is {_one_line(report.severity.rating).lower()}")
        lines.extend(["", f"**Assessment:** {'; '.join(verdict)}."])
        answers = list(getattr(report, "question_answers", None) or [])
        if answers:
            lines.extend(["", "### Questions asked of this run", ""])
            for number, answer in enumerate(answers, 1):
                asked = re.sub(r"(?=#)", "\\\\", self.ctx.inline(answer.question))
                said = f"**Q{number}. {asked}** — {outcome_words(answer.outcome)}"
                if answer.answer.strip():
                    said += ": " + self._line(answer.answer, answer.evidence_ids)
                lines.append(_item(said))
        # The questions section is printed only for a run asked some.
        absent = () if answers else ("Questions asked of this run",)
        return "\n".join([*lines, "", _behind("summary", absent=absent)])

    # -- 2. introduction and scope -----------------------------------------

    def scope(self) -> str:
        report, ctx = self.report, self.ctx
        ident = report.identity
        name = _code_span(ctx.plain(ident.file_name or ident.hashes.sha256 or "unknown"))
        summary = report.run_summary or {}
        profile = summary.get("profile") or {}
        analysts = [str(a) for a in profile.get("analysts") or []]
        team = f" ({len(analysts)} analyst{'s' if len(analysts) != 1 else ''})" if analysts else ""
        kind = _inline_safe(ident.file_type, plain=ctx.plain)
        said = (
            f"This report covers one file, {name} ({kind}, {ident.file_size_bytes:,} bytes), "
            "submitted for analysis and examined by an automated team of language-model "
            f"analysts{team} working over tool servers; a judge stated the "
            "verdict and a report model wrote the assessed prose. "
            + ctx.sandbox_sentence()
            + " A step or finding read from the code is marked assessed; one a sandbox watched "
            "is marked observed."
        )
        lines = [_heading(2, "Introduction and scope"), "", _paragraph_line(said)]
        background = report.intro_background.strip()
        if background:
            lines.extend(["", "### Context", "", self._prose(background)])
        return "\n".join([*lines, "", _behind("scope")])

    # -- 3. sample metadata ------------------------------------------------

    def metadata(self) -> str:
        report, ctx = self.report, self.ctx
        ident = report.identity
        header = _header_facts(report)
        lines = [_heading(3, "Sample metadata"), "", _row("Field", "Value"), _divider(2)]
        lines.append(_row("File name", _code_span(ctx.plain(ident.file_name or "unknown"))))
        lines.append(_row("Size", f"{ident.file_size_bytes:,} bytes"))
        kind = ident.file_type
        if header["architecture"]:
            kind += f", {header['architecture']}"
        if header["is_dll"] is not None:
            kind += ", DLL" if header["is_dll"] else ", executable"
        lines.append(_row("Type", kind))
        if header["is_dll"] and (ident.file_name or "").lower().endswith(".exe"):
            lines.append(_row("Name and type", "a DLL submitted under an .exe name"))
        if header["compile_timestamp"]:
            lines.append(_row("Compile timestamp", f"{header['compile_timestamp']} (header value)"))
        if header["export_name"]:
            lines.append(_row("Export name", _code_span(ctx.plain(str(header["export_name"])))))
        if ident.internal_name:
            lines.append(_row("Internal name", _code_span(ctx.plain(str(ident.internal_name)))))
        signing = ident.signing
        signed = "yes" if signing.is_signed else "no"
        if signing.signer_subject:
            signed += f", {signing.signer_subject}"
        lines.append(_row("Signed", signed + self.notes.marker([signing.evidence_id or ""])))
        reputation = _reputation_line(report)
        if reputation:
            lines.append(_row("Reputation", self.notes.moved(ctx.plain(reputation))))
        static = report.static
        if static is not None and (static.packer_matches or static.packer_hint):
            names = ", ".join(str(m.get("name") or "not recorded") for m in static.packer_matches)
            lines.append(_row("Packer signatures", names or static.packer_hint))
        for algo, value in (
            ("MD5", ident.hashes.md5),
            ("SHA-1", ident.hashes.sha1),
            ("SHA-256", ident.hashes.sha256),
            ("imphash", ident.hashes.imphash),
            ("ssdeep", ident.hashes.ssdeep),
            ("TLSH", ident.hashes.tlsh),
        ):
            if value:
                lines.append(_row(algo, _code_span(str(value))))
        listed = [*self._sections(), *self._imports(), *self._exports()]
        if listed:
            lines.extend(["", *listed])
        return "\n".join([*lines, "", _behind("metadata")])

    def _sections(self) -> list[str]:
        """The file's sections on one line, each with its entropy; the table is the bundle's."""
        static = self.report.static
        if static is None or not static.sections:
            return []
        rows = list(
            dict.fromkeys(
                (s.name, s.virtual_address, s.raw_offset, s.entropy) for s in static.sections
            )
        )
        shown = ", ".join(
            f"{_code_span(self.ctx.plain(_one_line(name)))} {entropy:.2f}"
            + (" (high entropy)" if entropy > _HIGH_ENTROPY else "")
            for name, _, _, entropy in rows
        )
        return [f"Sections ({len(rows)}), with entropy: {shown}."]

    def _imports(self) -> list[str]:
        """How many functions the file imports from how many libraries; their names when few."""
        static = self.report.static
        if static is None or not static.imports:
            return []
        rows = list(dict.fromkeys((row.dll, row.function) for row in static.imports))
        libraries = {str(dll).lower() for dll, _ in rows if dll}
        said = (
            f"Imports: {len(rows)} function{'s' if len(rows) != 1 else ''} from "
            f"{len(libraries)} librar{'y' if len(libraries) == 1 else 'ies'}"
        )
        if len(rows) <= _IMPORTS_NAMED:
            said += ": " + ", ".join(
                _code_span(self.ctx.plain(f"{dll}!{function}" if dll else str(function)))
                for dll, function in rows
            )
        return [said + "."]

    def _exports(self) -> list[str]:
        static = self.report.static
        if static is None:
            return []
        rows = list(dict.fromkeys((e.name, e.ordinal, e.rva) for e in static.export_rows))
        names = [str(name or "(unnamed)") for name, _, _ in rows] or list(
            dict.fromkeys(str(n) for n in static.exports)
        )
        if not names:
            return []
        shown = ", ".join(_code_span(self.ctx.plain(n)) for n in names[:12])
        more = f" and {len(names) - 12} more" if len(names) > 12 else ""
        said = f"Exports ({len(names)}): {shown}{more}."
        rvas = [rva for _, _, rva in rows if rva]
        if len(rvas) > 1 and len(set(rvas)) == 1:
            said += f" All {len(rvas)} exports share one address, {_one_line(rvas[0])}."
        return [said]

    # -- 4. execution flow -------------------------------------------------

    def flow(self) -> str:
        steps = list(self.ta.execution_flow) if self.ta is not None else []
        lines = [_heading(4, "Execution flow"), ""]
        if not steps:
            lines.append("The report model wrote no execution flow in this run.")
        labels = flow_step_labels(self.report)
        if labels:
            # A label cut at a word stands for its step, printed whole in the
            # numbered list under the diagram.
            # The steps as a diagram (the HTML draws it as a figure); its words
            # are defanged as the steps' are.
            nodes = [
                f'    s{n}["{_mermaid_label(self.ctx.plain(label))} ({mark})"]'
                for n, (label, mark) in enumerate(labels, 1)
            ]
            edges = [f"    s{n} --> s{n + 1}" for n in range(1, len(labels))]
            lines.extend([*_fenced("\n".join(["flowchart TD", *nodes, *edges]), "mermaid"), ""])
        for index, step in enumerate(sorted(steps, key=lambda s: s.order), start=1):
            # A step called observed that the voice check left standing, or that
            # no sandbox observation stands behind, is printed as assessed; the
            # single-file report, which the bundle prints, keeps the finding (T-555).
            observed = (
                step.voice == "observed"
                and str(step.order) not in self.ctx.flow_findings
                and self.ctx.sandbox_observed
            )
            mark = "observed" if observed else "assessed"
            said = f"{self._line(step.action, step.evidence_refs)} _({mark})_"
            lines.append(_step(index, said))
        return "\n".join([*lines, "", _behind("flow")])

    # -- 5. functionality --------------------------------------------------

    def functionality(self) -> str:
        report, ctx, ta = self.report, self.ctx, self.ta
        blocks: list[str] = []
        number = iter(range(1, 100))

        def numbered() -> str:
            return f"5.{next(number)}"

        if report.capabilities_narrative:
            body = [self._prose(p) + "\n" for p in report.capabilities_narrative if p.strip()]
            blocks.extend(self._subsection(numbered(), "Overview", [], body))
        cipher: list[str] = []
        enc = ta.encryption_scheme if ta is not None else None
        if enc is not None and not _encrypts_files(enc):
            cipher = self._encryption(enc)
        prose = [ta.packing_obfuscation, ta.evasion_antiforensics] if ta else []
        if any(sub is not None and sub.body.strip() for sub in prose) or cipher:
            blocks.extend(
                self._subsection(
                    numbered(), "Packing, obfuscation and anti-analysis", prose, cipher
                )
            )
        if ta is not None and ta.string_resolution is not None:
            blocks.extend(
                self._subsection(
                    numbered(), "API and string resolution", [ta.string_resolution], []
                )
            )
        persistence = self._persistence()
        prose = [ta.persistence_detail] if ta else []
        if any(sub is not None and sub.body.strip() for sub in prose) or persistence:
            blocks.extend(self._subsection(numbered(), "Persistence", prose, persistence))
        commands = self._commands_started()
        prose = [ta.discovery] if ta else []
        if any(sub is not None and sub.body.strip() for sub in prose) or commands:
            blocks.extend(self._subsection(numbered(), "Discovery", prose, commands))
        payloads = self._payloads()
        prose = [ta.payloads] if ta else []
        if any(sub is not None and sub.body.strip() for sub in prose) or payloads:
            blocks.extend(
                self._subsection(numbered(), "Payloads and dropped files", prose, payloads)
            )
        if ta is not None:
            family = _ransomware_block(ta, ctx, ransomware=_states_ransomware(report))
            if family:
                head, _, rest = family.partition("\n")
                title = head.split(" · ", 1)[0].removeprefix("### 5.9 ")
                blocks.extend([_subheading(numbered(), title), self.notes.moved(rest), ""])
        lines = [_heading(5, "Functionality"), ""]
        lines.extend(blocks or ["The report model described no capability in this run.", ""])
        return "\n".join([*lines, _behind("functionality")])

    def _encryption(self, enc: Any) -> list[str]:
        table = _encryption_table(enc, self.ctx)
        if not table:
            return []
        # The table's own evidence row is its last; the citation is the note.
        rows = table[2:-1]
        cited = self.notes.marker([enc.evidence_ref or ""])
        return ["Encryption scheme" + cited + ":", "", *rows, ""]

    def _persistence(self) -> list[str]:
        report, ctx = self.report, self.ctx
        if not report.persistence:
            return []
        lines = [_row("Kind", "Target", "Payload", "Technique"), _divider(4)]
        for mech in report.persistence[:40]:
            lines.append(
                _row(
                    mech.kind,
                    _code_span(_whole(ctx.plain(mech.target)))
                    + self.notes.marker([mech.evidence_ref or ""]),
                    _code_span(_whole(ctx.plain(mech.payload))) if mech.payload else "-",
                    mech.technique_id or "-",
                )
            )
        lines.extend(_left_out(len(report.persistence), 40, "persistence mechanisms"))
        return [*lines, ""]

    def _commands_started(self) -> list[str]:
        # Only the sample's own processes, by the export's lineage rule; the ones
        # left out are said under a table that has rows.
        commands, others = started_by_the_sample(self.report)
        if not commands:
            return []
        lines = ["Commands the sample started _(observed)_:", "", _row("PID", "Command line")]
        lines.append(_divider(2))
        for node in commands[:20]:
            lines.append(_row(node.pid, _code_span(_whole(self.ctx.plain(node.command_line)))))
        lines.extend(_left_out(len(commands), 20, "commands"))
        lines.extend(not_started_by_the_sample_line(others, _BUNDLE_TREE))
        return [*lines, ""]

    def _payloads(self) -> list[str]:
        report, ctx = self.report, self.ctx
        static, dynamic = report.static, report.dynamic
        carved = [r for r in (static.embedded_resources if static else []) if r.get("carved")]
        dropped = [
            op
            for op in (dynamic.file_operations if dynamic else [])
            if isinstance(op, dict) and op.get("operation") == "write"
        ]
        if not carved and not dropped:
            return []
        lines = [_row("Name/offset", "Size", "SHA-256", "How found"), _divider(4)]
        for res in carved[:10]:
            size = res.get("size")
            lines.append(
                _row(
                    _code_span(ctx.plain(str(res.get("id") or "not recorded"))),
                    f"{size} bytes" if isinstance(size, int) and size > 0 else "not recorded",
                    _code_span(str(res.get("sha256")).lower()) if res.get("sha256") else "-",
                    "carved from the file",
                )
            )
        for op in dropped[:20]:
            named = str(op.get("path") or op.get("name") or "not recorded")
            lines.append(
                _row(
                    _code_span(_whole(ctx.plain(named))),
                    f"{op['size']} bytes" if op.get("size") else "not recorded",
                    _code_span(str(op.get("sha256")).lower()) if op.get("sha256") else "-",
                    "dropped while a sandbox watched",
                )
            )
        lines.extend(_left_out(len(carved), 10, "carved payloads"))
        lines.extend(_left_out(len(dropped), 20, "dropped files"))
        notes = [r for r in (static.embedded_resources if static else []) if is_carve_note(r)]
        if notes:
            lines.extend(
                ["", *(_item(_inline_safe(str(r["type"]), plain=ctx.plain)) for r in notes)]
            )
        return [*lines, ""]

    # -- 6. command and control --------------------------------------------

    def c2(self) -> str:
        ctx, ta = self.ctx, self.ta
        blocks: list[str] = []
        prose = [ta.command_and_control, ta.message_packet_structure] if ta else []
        protocol = self._channels() + self._message_examples() + self._requests()
        if any(sub is not None and sub.body.strip() for sub in prose) or protocol:
            blocks.extend(self._subsection("6.1", "Protocol and endpoints", prose, protocol))
        if ta is not None and ta.configuration:
            body = [_row("Key", "Value", "How obtained"), _divider(3)]
            left = 0
            for index, item in enumerate(ta.configuration, start=1):
                # A row that cites nothing, or whose value none of its cited
                # entries holds whole, is the bundle's, which prints it with the
                # finding (T-555); the IOC table's state of each value stays.
                if (
                    index in ctx.config_findings
                    or index in ctx.config_unheld
                    or self._flagged_whole(item.key)
                    or self._flagged_whole(item.value)
                ):
                    left += 1
                    continue
                body.append(
                    _row(
                        self._cell(item.key),
                        self._line(item.value, item.evidence_refs) + ctx.publish_state(item.value),
                        item.how_obtained,
                    )
                )
            if left:
                said = _left_out_rows(left, "configuration row")
                # Every row the bundle's: the line alone, with no empty table.
                body = [*body, "", said] if len(body) > 2 else [said]
            blocks.extend([_subheading("6.2", "Configuration"), "", *body, ""])
        if ta is not None and (ta.commands or ta.cli_flags):
            body = []
            # A row whose value a check left standing whole is the bundle's,
            # counted under its table (T-555).
            commands = [
                cmd
                for cmd in ta.commands
                if not (self._flagged_whole(cmd.id) or self._flagged_whole(cmd.name))
            ]
            if commands:
                body.extend([_row("ID", "Command", "Description"), _divider(3)])
                for cmd in commands:
                    body.append(
                        _row(
                            self._cell(cmd.id or "-"),
                            self._cell(cmd.name),
                            self._line(cmd.description or "-", cmd.evidence_refs),
                        )
                    )
                body.append("")
            if len(commands) < len(ta.commands):
                body.extend([_left_out_rows(len(ta.commands) - len(commands), "command row"), ""])
            flags = [flag for flag in ta.cli_flags if not self._flagged_whole(flag.flag)]
            if flags:
                body.extend(["Command-line flags:", "", _row("Flag", "Meaning"), _divider(2)])
                for flag in flags:
                    body.append(
                        _row(
                            _code_span(ctx.plain(flag.flag)),
                            self._line(flag.description or "-", [flag.evidence_ref or ""]),
                        )
                    )
                body.append("")
            if len(flags) < len(ta.cli_flags):
                body.extend([_left_out_rows(len(ta.cli_flags) - len(flags), "flag row"), ""])
            blocks.extend([_subheading("6.3", "Commands"), "", *body])
        lines = [_heading(6, "Command and control"), ""]
        lines.extend(
            blocks
            or [
                "No command-and-control channel was described or observed in this run.",
                "",
            ]
        )
        return "\n".join([*lines, _behind("c2")])

    def _channels(self) -> list[str]:
        channels = self.report.c2_channels
        if not channels:
            return []
        lines = [
            _row("Channel", "Protocol", "Endpoint(s)", "Encryption", "Message format"),
            _divider(5),
        ]
        for ch in channels:
            fmt = " / ".join(part for part in (ch.beacon_format, ch.packet_layout) if part)
            refs = list(ch.evidence_refs) + ([ch.evidence_ref] if ch.evidence_ref else [])
            lines.append(
                _row(
                    self._cell(ch.name) + self.notes.marker(refs),
                    self._cell(ch.protocol),
                    "; ".join(_endpoint(e) for e in ch.endpoints) or "-",
                    self._cell(ch.encryption),
                    self._cell(fmt),
                )
            )
        return [*lines, ""]

    def _message_examples(self) -> list[str]:
        """An annotated example of each message the recorded protocol facts lay out.

        A channel whose recorded message format is ``name=value`` fields gets
        each field on its line with what its conversion holds, and the value of
        a configuration item of the same name. Nothing is added that the record
        does not hold; with no such format there is no example. An observed
        request is the requests table's row, printed once.
        """
        ctx = self.ctx
        config = {
            str(item.key).strip().lower(): item
            for item in (self.ta.configuration if self.ta is not None else [])
            if str(item.key).strip()
        }
        lines: list[str] = []
        for ch in self.report.c2_channels:
            for source in (ch.beacon_format, ch.packet_layout):
                fields = message_fields(source or "")
                if not fields:
                    continue
                width = max(len(f"{name}={value}") for name, value, _ in fields)
                rows = []
                for name, value, words in fields:
                    said = words
                    item = config.get(name.lower())
                    if item is not None:
                        said += (
                            f"; a configuration item of the same name holds {_one_line(item.value)}"
                        )
                    rows.append(f"{name}={value}".ljust(width + 2) + said)
                lines.extend(
                    [
                        f"Message example, {self._line(ch.name)}, as its recorded format lays it "
                        "out:",
                        "",
                        *_fenced(ctx.plain("\n".join(rows)), "text"),
                        "",
                    ]
                )
                break
        return lines

    def _requests(self) -> list[str]:
        net, ctx = self.report.network, self.ctx
        observed = [u for u in (net.urls if net else []) if u.source == "sandbox"]
        lines: list[str] = []
        if observed:
            lines.extend(["Requests _(observed)_:", "", _row("Method", "URL", "User-Agent")])
            lines.append(_divider(3))
            for u in observed[:20]:
                lines.append(
                    _row(
                        _inline_safe(u.method or "-", pipes=False, plain=ctx.plain),
                        _code_span(defang(_whole(u.url), "url")),
                        _inline_safe(_whole(u.user_agent or "-"), pipes=False, plain=ctx.plain),
                    )
                )
            lines.extend(_left_out(len(observed), 20, "requests"))
            lines.append("")
        if net is not None and (net.ja3_fingerprints or net.ja3s_fingerprints):
            prints = [f"JA3 {_code_span(_one_line(j))}" for j in net.ja3_fingerprints]
            prints += [f"JA3S {_code_span(_one_line(j))}" for j in net.ja3s_fingerprints]
            lines.extend(["TLS fingerprints _(observed)_: " + ", ".join(prints) + ".", ""])
        return lines

    # -- 7. conclusion -----------------------------------------------------

    def conclusion(self) -> str:
        report = self.report
        lines = [_heading(7, "Conclusion"), ""]
        said = f"The sample is assessed as {self._verdict()}"
        if self._category():
            said += f", a {self._category()}"
        family = self._family()
        said += (
            f", attributed to the family {family}"
            if family != "none attributed"
            else ", with no family attributed"
        )
        severity = report.severity
        if severity is not None:
            said += f", at {_one_line(severity.rating).lower()} severity"
        lines.append(_paragraph_line(said + "."))
        composed = self.ta.analyst_conclusion if self.ta is not None else None
        if composed is not None:
            # The platform's verdict sentence, then the composer's paragraphs in
            # place of the judge's words, which are the bundle's; the platform's
            # findings on the verdict stay. A conclusion every sentence of which
            # was left out says so, and the judge's words stay the bundle's (T-555).
            lines.append("")
            paragraphs = [p for p in re.split(r"\n\s*\n", composed.body.strip()) if p.strip()]
            written = [
                self._prose(
                    paragraph, composed.evidence_refs if index == len(paragraphs) - 1 else ()
                )
                for index, paragraph in enumerate(paragraphs)
            ]
            written = [paragraph for paragraph in written if paragraph.strip()]
            if not written:
                written = [_LEFT_OUT_WHOLE.format(what="conclusion", verb="was")]
            for paragraph in written:
                lines.extend([paragraph, ""])
            # A sentence of the words it replaces that a check left a mark on, or
            # that names a value printed nowhere else.
            severity, stored = report.severity, report.conclusion
            replaced = " ".join(
                text
                for text in (
                    severity.business_impact if severity is not None else "",
                    stored.text if stored is not None else "",
                )
                if text and text.strip()
            )
            kept = self._kept_sentences(replaced)
            if kept:
                lines.extend([self._prose(" ".join(kept)), ""])
            # The platform's own fields stay beside them.
            if severity is not None and severity.likely_targets:
                targets = ", ".join(_one_line(t) for t in severity.likely_targets)
                lines.extend([f"Likely targets: {targets}.", ""])
            if stored is not None and stored.sophistication_rating:
                lines.extend([f"Sophistication: {_one_line(stored.sophistication_rating)}.", ""])
            if self.ctx.verdict_findings:
                lines.extend([*self._findings(self.ctx.verdict_findings), ""])
            return "\n".join([*lines, _behind("conclusion")])
        if severity is not None and severity.business_impact.strip():
            lines.extend(["", self._prose(severity.business_impact)])
        if severity is not None and severity.likely_targets:
            targets = ", ".join(_one_line(t) for t in severity.likely_targets)
            lines.extend(["", f"Likely targets: {targets}."])
        stored = report.conclusion
        if stored is not None and stored.sophistication_rating:
            lines.extend(["", f"Sophistication: {_one_line(stored.sophistication_rating)}."])
        if stored is not None and stored.text.strip():
            lines.extend(["", self._prose(stored.text)])
        if self.ctx.verdict_findings:
            lines.extend(["", *self._findings(self.ctx.verdict_findings)])
        return "\n".join([*lines, "", _behind("conclusion")])

    # -- 8. detection ------------------------------------------------------

    def detection(self) -> str:
        lines = [_heading(8, "Detection"), ""]
        lines.extend(self._indicators())
        lines.extend(self._rules())
        from maljan.reporting.detection_signatures import hunting_query

        hunting = [rec for rec in self.report.defensive_recommendations if rec.detection]
        query = hunting_query(self.report)
        if hunting or query:
            lines.extend(["### 8.3 Hunting guidance", ""])
            lines.extend(
                _item(
                    self._line(rec.detection)
                    + (f" ({_one_line(rec.technique_id)})" if rec.technique_id else "")
                )
                for rec in hunting
            )
            if hunting:
                lines.append("")
        if query:
            lines.extend(
                [
                    "Hunting query: the requests the sample's code sends, to any host but the "
                    "ones published above; a match is a candidate for more of its "
                    "infrastructure. Built from the published user agents and URL paths, in "
                    "neutral field names to map to a web proxy's log, and not run against any "
                    "log.",
                    "",
                ]
            )
            fenced = _fenced("\n".join(query), "text")
            fenced[1] = self.ctx.keep(fenced[1])
            lines.extend([*fenced, ""])
        return "\n".join([*lines, _behind("detection")])

    def _indicators(self) -> list[str]:
        """The indicator table: every row of the IOC table but an unexported observation.

        A value the run does not export that only an observation pass recorded
        — a name or an address a capture or a strings pass saw, bound to no
        code and named by no model — is counted here and listed in the
        bundle's indicator section with the reason. Every other row is printed,
        with what recovered it and the publish rule's answer where it does not
        export the value.
        """
        from maljan.reporting.renderers.stix_renderer import publishes

        report, ctx = self.report, self.ctx
        rows: list[tuple[str, str, str]] = []
        seen: set[str] = set()
        recorded = 0
        for ioc in ctx.iocs:
            exported = publishes(ioc.published)
            if not exported and str(ioc.source or "") in _OBSERVED_ONLY:
                recorded += 1
                continue
            seen.add(ioc.value.strip().lower())
            value = (
                defang(ioc.value, ioc.kind or "")
                if ioc.kind in _NETWORK_KINDS
                else ctx.plain(ioc.value)
            )
            # A value the code passes to an API argument: where the code
            # decoded and loaded it, which its context (the call) does not say.
            # The whole chain is the bundle's.
            origin = self._bound_origin(ioc) if exported else ""
            role = "; ".join(
                part
                for part in (
                    ctx.inline(ioc.context) if ioc.context else "",
                    origin,
                    f"recovered by {ctx.inline(ioc.recovered_by)}" if ioc.recovered_by else "",
                )
                if part
            )
            if not exported:
                answer = ctx.plain(_one_line(ioc.published or "")).strip() or "not exported"
                role += f" _({_inline_safe(answer, pipes=False, plain=ctx.plain)})_"
            rows.append((ioc.type, value, role or "-"))
        identifiers = list(self.ta.host_identifiers) if self.ta is not None else []
        left = 0
        for index, item in enumerate(identifiers, start=1):
            if item.value.strip().lower() in seen:
                continue
            # A row that cites nothing, or whose value none of its cited entries
            # holds whole, is the bundle's, which prints it with the finding (T-555).
            if (
                index in ctx.identifier_findings
                or index in ctx.identifier_unheld
                or self._flagged_whole(item.value)
            ):
                left += 1
                continue
            seen.add(item.value.strip().lower())
            role = self._line(item.purpose, item.evidence_refs) if item.purpose.strip() else "-"
            state = ctx.publish_state(item.value).strip()
            role += f" _({_IDENTIFIER_NOT_EXPORTED}" + (f"; {state[1:-1]}" if state else "") + ")_"
            rows.append((self._cell(item.kind), ctx.plain(_one_line(item.value)), role))
        lines = ["### 8.1 Indicators of compromise", ""]
        if not rows:
            lines.extend(["No indicator was extracted in this run.", ""])
        else:
            lines.extend([_row("Type", "Value", "Role"), _divider(3)])
            for kind, value, role in rows:
                lines.append(_row(kind, _code_span(value), role))
            lines.append("")
        if left:
            lines.extend([_left_out_rows(left, "host identifier row"), ""])
        if recorded:
            lines.extend(
                [
                    f"{recorded} further value{'s' if recorded != 1 else ''} only a capture or a "
                    f"strings pass recorded {'are' if recorded != 1 else 'is'} not exported; the "
                    "bundle lists each with the reason.",
                    "",
                ]
            )
        rid = _one_line((report.run_summary or {}).get("report_id") or "{report_id}")
        lines.extend(
            [
                "Network values are defanged for reading. A value with the publish rule's answer "
                "beside it is not in the machine-readable outputs, which carry the exported "
                "values live: the STIX 2.1 "
                f"bundle ({_code_span(f'/reports/{rid}/stix')}), the indicator list "
                f"({_code_span(f'/reports/{rid}/iocs')}) and the MISP attributes of the JSON "
                f"report ({_code_span(f'/reports/{rid}/full')}).",
                "",
            ]
        )
        return lines

    def _rules(self) -> list[str]:
        """Each drafted rule by name and what checking it against the sample found.

        A rule a file engine ran against the sample prints its body in the
        appendix only where its strings matched it; one no engine runs on a
        file (a behaviour or traffic rule) prints its body there too. Each
        printed rule carries a Precision line (``precision_line``). A rule that
        matched by its hash alone, was not checked, did not match or did not
        compile is named here with the reason (``analyst_print_gate``) and
        printed in the bundle. Either sentence is the one the rule's record
        carries (``rule_standing``).
        """
        from maljan.reporting.renderers.markdown import _RULE_SECTIONS

        matched = [s for s in self.report.sections if s.key in _RULE_SECTIONS]
        rules = self.report.detection_signatures
        if not rules and not matched:
            return []
        lines = ["### 8.2 Detection rules", ""]
        # The rules that matched the sample, by name, as the single-file report
        # names them; their rows are the bundle's.
        for section in matched:
            at = section.columns.index("Rule") if "Rule" in section.columns else 0
            every = [_one_line(row[at]) for row in section.rows if len(row) > at]
            names = ", ".join(_code_span(self.ctx.plain(n)) for n in every[:20]) or "none"
            more = f" and {len(every) - 20} more (in the bundle)" if len(every) > 20 else ""
            title = _one_line(section.title)
            lines.append(
                _item(
                    f"Matched the sample, {title}: {names}{more}"
                    + self.notes.marker(section.evidence_ids)
                )
            )
        if matched and rules:
            lines.append("")
        for rule in rules:
            kind = _one_line(rule.kind).upper()
            status = "does not compile" if rule.compile_error else "compiles"
            said = f"**{kind}** {_code_span(_one_line(rule.name))} — {status}."
            checked = _sample_check_line(rule, self.ctx)
            if checked:
                said += f" {checked}"
            # A body printed here carries what it was measured on; one that is
            # not says why, and the bundle prints it. The sentence is the one
            # the rule's record carries (``rule_standing``).
            said += f" {rule_standing(rule)[1]}"
            if rule.kind == "yara":
                said += _stored_left_out(self.report)
            lines.append(_item(said))
        if any(self._printed(rule) for rule in rules):
            lines.extend(
                ["", "The rule bodies are in the appendix. Test a rule before deploying it."]
            )
        return [*lines, ""]

    def _bound_origin(self, ioc: Any) -> str:
        """Where the code decoded and loaded a value it passes to an API argument, or ``""``.

        Read from the report's binding record (``reporting.call_bindings``) on
        a row of the call-binding source: the blob's file offset, the place
        that loads it, the function it is in, the routine it is given to and
        the import or slot the call is made through, with a note for the
        decoder's entry. Any other row gives ``""``.
        """
        from maljan.reporting.call_bindings import BOUND_SOURCE, bound_value

        if str(getattr(ioc, "source", "") or "") != BOUND_SOURCE:
            return ""
        bound = bound_value(self.report, str(ioc.kind or ""), ioc.value)
        if bound is None or not bound.site:
            return ""
        said = "decoded" + (f" from the blob at file offset {bound.offset}" if bound.offset else "")
        said += f", loaded at {bound.site}"
        said += f" in the function at {bound.function}" if bound.function else ""
        said += (
            f" and given to the routine called at {bound.decoder_call}"
            if bound.decoder_call
            else ""
        )
        # How the call is named, which the context's API name does not say.
        if bound.imported_as:
            said += f", the call made through the import {bound.imported_as}"
        elif bound.slot:
            said += f", the call made through the slot {bound.slot}"
        return self.ctx.inline(said) + self.notes.marker([bound.entry] if bound.entry else [])

    @staticmethod
    def _printed(rule: Any) -> bool:
        return analyst_print_gate(rule) is None

    # -- 9. recommendations ------------------------------------------------

    def recommendations(self) -> str:
        recs = self.report.defensive_recommendations
        lines = [_heading(9, "Recommendations"), ""]
        if not recs:
            lines.append("The report model gave no recommendation in this run.")
        else:
            lines.extend([_row("Priority", "Category", "Action", "Rationale", "Technique")])
            lines.append(_divider(5))
            order = {"P0": 0, "P1": 1, "P2": 2}
            for rec in sorted(recs, key=lambda r: order.get(r.priority, 9)):
                lines.append(
                    _row(
                        rec.priority,
                        rec.category.replace("_", " "),
                        self._line(rec.action),
                        self._line(rec.rationale),
                        rec.technique_id or "-",
                    )
                )
        return "\n".join([*lines, "", _behind("recommendations")])

    # -- 10. ATT&CK --------------------------------------------------------

    def attack(self) -> str:
        from maljan.reporting.renderers.markdown import _is_mbc_id, _tactic_key

        report = self.report
        lines = [_heading(10, "MITRE ATT&CK mapping"), ""]
        mappings = {m.technique_id: m for m in report.ttp_mappings}
        # The composer's one sentence per technique, where it wrote one.
        self._procedures = {
            p.technique_id.strip().upper(): p
            for p in (self.ta.technique_procedures if self.ta is not None else [])
            if p.procedure.strip()
        }
        rows: list[str] = []
        seen: set[str] = set()
        held: list[str] = []
        for cell in sorted(report.capability_matrix, key=_tactic_key):
            if _is_mbc_id(cell.technique_id) or cell.technique_id in seen:
                continue
            seen.add(cell.technique_id)
            if cell.not_published or not cell.technique_id_valid:
                held.append(self._held(cell))
                continue
            claim = str(cell.evidence[0]) if cell.evidence else ""
            tactic = cell.tactic_name or cell.tactic or "-"
            rows.append(
                _row(
                    _one_line(tactic),
                    cell.technique_id,
                    _one_line(cell.technique_name),
                    self._procedure(
                        claim,
                        _EV_RE.findall(" ".join(map(str, cell.evidence))),
                        cell.technique_id,
                    )
                    + self._status(cell.technique_id, cell.note),
                )
            )
        for tid, mapping in mappings.items():
            if tid in seen:
                continue
            seen.add(tid)
            claim = str(mapping.evidence_quotes[0]) if mapping.evidence_quotes else ""
            rows.append(
                _row(
                    _one_line(mapping.tactic_name or mapping.tactic or "-"),
                    tid,
                    _one_line(mapping.technique_name),
                    self._procedure(claim, _EV_RE.findall(" ".join(mapping.evidence_quotes)), tid)
                    + self._status(tid, ""),
                )
            )
        if rows:
            lines.extend([_row("Tactic", "ID", "Technique", "Procedure"), _divider(4), *rows])
        else:
            lines.append("No ATT&CK technique is published in this run.")
        if held:
            lines.extend(
                [
                    "",
                    f"{len(held)} further technique{'s were' if len(held) != 1 else ' was'} named "
                    "and not published, each with the reason (the claims behind each are in the "
                    "bundle):",
                    "",
                    *held,
                ]
            )
        return "\n".join([*lines, "", _behind("attack")])

    def _held(self, cell: Any) -> str:
        """A technique named and not published, with the status the single-file report gives it."""
        from maljan.reporting.judge_reasons import JUDGE_REASON_WIDTH, status_shown
        from maljan.schemas.isr_models import UNVERIFIED_TECHNIQUE_MARKER

        if not cell.technique_id_valid:
            status = f"unverified id ({UNVERIFIED_TECHNIQUE_MARKER})"
        else:
            status = "claimed, not published: " + status_shown(
                cell.not_published, JUDGE_REASON_WIDTH, self.ctx.plain
            )
        return _item(
            f"{cell.technique_id} {_one_line(cell.technique_name)}: {status}"
            + self._status(cell.technique_id, "")
        )

    def _status(self, technique_id: str, note: str) -> str:
        """What the single-file report says beside a published row's status, or ``""``.

        How little a rule match stands behind a technique only a rule matched,
        and the row's own note. The platform's unresolved findings about it are
        the bundle's, which prints the single-file report's status whole (T-555).
        """
        said: list[str] = []
        rule_only = self.ctx.rule_only.get(technique_id)
        if rule_only:
            said.append(self.ctx.plain(_one_line(rule_only)))
        # The judge's answer when asked is how the row was decided, the
        # bundle's (T-555).
        if note and not note.lower().startswith(judge_kept_note("").lower()):
            said.append(self.ctx.plain(judge_reasons_shown(note)[0]))
        return f" _({'; '.join(said)})_" if said else ""

    def _procedure(self, claim: str, ids: list[str], technique_id: str = "") -> str:
        """The composer's procedure for the technique, else its first claim's first sentence."""
        written = self._procedures.get(technique_id.strip().upper())
        sentence = _first_sentence(_CITATION_RUN.sub("", claim))
        # A first sentence a check left standing is the bundle's: the written
        # procedure stands, or nothing (T-555).
        if self._flagged_whole(_first_sentence(claim)) or self._flagged_whole(sentence):
            if written is not None:
                return self._line(written.procedure, written.evidence_refs)
            return "-"
        # A first sentence naming a value printed nowhere else stays in place
        # of the written procedure.
        if written is not None and not self._keeps(sentence):
            return self._line(written.procedure, written.evidence_refs)
        if not sentence:
            return "-" + self.notes.marker(ids)
        return self._line(sentence, ids)

    # -- 11. limitations ---------------------------------------------------

    def limitations(self) -> str:
        report, ctx = self.report, self.ctx
        said: list[str] = []
        if report.verdict_not_assessed:
            said.append(f"No verdict was assessed: {_one_line(report.verdict_not_assessed)}.")
        if report.degraded_mode:
            said.append(_degraded_sentence(report, ctx))
        partial = ctx.partial_sentence().strip()
        if partial:
            said.append(partial)
        count = len(report.degradation_reasons)
        if count:
            said.append(
                f"The run recorded {count} limitation{'s' if count != 1 else ''}, each with its "
                "reason and remedy in the bundle."
            )
        if not ctx.sandbox_observed:
            said.append(
                "Without a sandbox observation, what the sample does is read from its code and "
                "was not watched running."
            )
        undiscussed = len(getattr(report, "claims_not_discussed", None) or [])
        if undiscussed:
            said.append(
                f"{undiscussed} analyst claim{'s' if undiscussed != 1 else ''} in force "
                f"{'are' if undiscussed != 1 else 'is'} not discussed in this report and "
                f"{'are' if undiscussed != 1 else 'is'} printed whole in the bundle."
            )
        composed = self.ta.analyst_limitations if self.ta is not None else None
        if composed is not None:
            # The composer's scoped paragraph, then every sentence of the
            # platform's own: its caveats, its counts and what the report leaves
            # to the bundle. A paragraph every sentence of which was left out
            # says so (T-555).
            kept = said
            paragraph = self._prose(" ".join(composed.body.split()), composed.evidence_refs)
            if not paragraph.strip():
                paragraph = _LEFT_OUT_WHOLE.format(what="limitations", verb="were")
            if kept:
                paragraph += " " + _paragraph_line(" ".join(kept))
            lines = [_heading(11, ANALYST_LIMITATIONS_TITLE), "", paragraph]
            return "\n".join([*lines, "", _behind("limitations")])
        if not said:
            said.append("The run recorded no limitation.")
        lines = [_heading(11, ANALYST_LIMITATIONS_TITLE), "", _paragraph_line(" ".join(said))]
        return "\n".join([*lines, "", _behind("limitations")])

    # -- appendix ----------------------------------------------------------

    def _statements(self) -> list[str]:
        """The analysts' statements of the ATT&CK section's rule-matched techniques that add a
        value: each fact once, so one whose values the report already prints is left out."""
        from maljan.reporting.renderers.markdown import _is_mbc_id, _tactic_key

        report = self.report
        hits = list(report.static.api_technique_hits) if report.static else []
        by_tid: dict[str, list[dict[str, Any]]] = {}
        for hit in hits:
            by_tid.setdefault(str(hit.get("technique_id") or ""), []).append(hit)
        have = set(_VALUE.findall("\n".join(self.written)))
        out: list[str] = []
        for cell in sorted(report.capability_matrix, key=_tactic_key):
            rules = by_tid.get(cell.technique_id) or []
            if _is_mbc_id(cell.technique_id) or not rules:
                continue
            # The statements the single-file report prints are these techniques'
            # only (``_resolved_only_lines``); every other cell's statements are
            # stored and printed nowhere, so the report gains no text here that
            # the single-file report did not print.
            if not all(_resolved_only(hit) for hit in rules):
                continue
            for statement in cell.statements:
                text = _LAYER_LABEL.sub("", str(statement), count=1)
                new = [v for v in dict.fromkeys(_VALUE.findall(text)) if v not in have]
                if len(new) < _NEW_VALUES:
                    continue
                have.update(new)
                out.append(
                    _item(
                        f"{cell.technique_id} {_one_line(cell.technique_name)}: {self._line(text)}"
                    )
                )
        return out

    def appendix(self) -> str:
        report = self.report
        lines = ["## Appendix", ""]
        printed = [rule for rule in report.detection_signatures if self._printed(rule)]
        if printed:
            lines.extend(["### Detection rules", ""])
            lines.append(
                "_Drafted from templates over this report's own values and not reviewed by an "
                "analyst. Each body is printed as written, its network values not defanged, so "
                "it compiles as deployed._"
            )
            lines.append("")
            for rule in printed:
                kind = _one_line(rule.kind).upper()
                lines.extend([f"**{kind}** {_code_span(_one_line(rule.name))}", ""])
                fence = rule.kind if rule.kind in {"yara", "sigma"} else ""
                fenced = _fenced(rule.body.rstrip(), fence)
                fenced[1] = self.ctx.keep(fenced[1])
                lines.extend([*fenced, ""])
        statements = self._statements()
        if statements:
            lines.extend(["### Analyst statements that add detail", ""])
            lines.append(
                "_What the analysts wrote naming a technique a rule matched only on names "
                "resolved at runtime, where a statement names a value this report prints "
                "nowhere else. Every statement is in the bundle._"
            )
            lines.extend(["", *statements, ""])
        if report.references:
            lines.extend(["### References", ""])
            for ref in report.references:
                note = f" — {ref.note}" if ref.note else ""
                lines.append(_item(f"[{ref.source}]({ref.url}){note}"))
            lines.append("")
        bundle = self.ctx.keep(f"[{BUNDLE_HTML}]({BUNDLE_HTML}) and [{BUNDLE_JSON}]({BUNDLE_JSON})")
        lines.extend(
            [
                "### Evidence bundle",
                "",
                _paragraph_line(
                    "What this report does not print is in the evidence bundle beside it ("
                    + bundle
                    + "): the observed behaviour and the static properties, the full ATT&CK and "
                    "indicator tables, the analysts' statements, every tool call with its output, "
                    "the run's limitations and its summary. Each numbered note above links to the "
                    "evidence entries it rests on there."
                ),
            ]
        )
        return "\n".join(lines)


def _stored_left_out(report: MalwareReport) -> str:
    """`` N stored values … left out …``: the stored values the YARA draft does not match on."""
    from maljan.reporting.detection_signatures import stored_selection

    chosen = stored_selection(report)
    rest = chosen.left_out
    if not rest:
        return ""
    why = f" ({chosen.why})" if chosen.why else ""
    return (
        f" {rest} stored value{'s' if rest != 1 else ''} the run read "
        f"{'are' if rest != 1 else 'is'} left out of the draft{why}; the report's JSON lists "
        "every one."
    )

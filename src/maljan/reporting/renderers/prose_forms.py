"""What the Markdown renderer does to the whole of one render, once every section is written.

Three readings of the rendered text, each read off what the render itself
holds, never off a number or a value written into this module:

* **Section references.** A sentence that sends the reader to another section
  names it by its title (:func:`section_reference`); once every section is
  written, the title is looked up among the headings the render printed and
  the reference becomes that heading's number (``§13``, ``§5.4``, ``Appendix
  A``). A title the render does not print is linked in the evidence bundle
  where the bundle is beside the report, and named in words elsewhere, so a
  reference never points at a section that is not there. The analyst report
  printed "See §13" after its sections were renumbered to eleven.
* **A decoded text in the pack's spelling.** The triage pack writes a
  backslash that would end a quoted string as ``\\x5c``
  (``utils.written_forms.pack_escaped``); a model that copies the value from
  the pack writes ``\\Registry\\Machine\\x5c`` for the decoded
  ``\\Registry\\Machine\\``. Each such spelling of a value the run recorded is
  printed as the value (:func:`pack_spellings`), in prose, cells and code
  spans; a fenced block (a rule's body, a diagram) is left as written.
* **The platform's unread-callee clause.** The agreement round appends to a
  section 5 sentence the clause "the routine at …, called by the read routines
  at …, has no listed code" with every caller's offset; nineteen offsets ran
  inside one sentence. A clause naming more than :data:`CALLERS_IN_PROSE`
  callers names that many in the analyst report, with the count and the
  bundle as the place of the rest; the single-file report and the bundle
  print the callers as a list after the paragraph. Every offset stays printed
  in one of the two files.

Each reading is one pass over the render's lines.
"""

from __future__ import annotations

import re
import secrets
from collections.abc import Iterable, Sequence
from contextvars import ContextVar
from typing import Any

from maljan.utils.written_forms import pack_escaped

# ---------------------------------------------------------------------------
# Section references
# ---------------------------------------------------------------------------

# The references one render wrote, set for that render (``MarkdownRenderer``).
_REFERENCES: ContextVar[SectionReferences | None] = ContextVar(
    "markdown_section_references", default=None
)

# A numbered heading as the renderers print one: "## 13. Title · _Voice_",
# "### 5.4 Title · _Voice_", "## Appendix A. Title · _Voice_", "## 11. Title".
_HEADING = re.compile(
    r"^(?P<level>#{2,3}) (?:(?P<appendix>Appendix [A-Z])\.|(?P<number>\d+(?:\.\d+)*)\.?) "
    r"(?P<title>.+?)(?: · _[^_]*_)?\s*$"
)


# The brackets a reference's token stands between: printable, so no escaping
# pass of a section touches them, and no character Markdown reads.
_OPEN, _CLOSE = "⟦", "⟧"


class SectionReferences:
    """The references one render wrote, each a token until every heading is known.

    The token carries a value drawn for the one render, so no text a sample or
    a model wrote can stand for a reference.
    """

    def __init__(self) -> None:
        self._mark = secrets.token_hex(8)
        self._wanted: list[tuple[str, ...]] = []
        self._token = re.compile(_OPEN + self._mark + r":(\d+)" + _CLOSE)

    def token(self, titles: tuple[str, ...]) -> str:
        self._wanted.append(titles)
        return f"{_OPEN}{self._mark}:{len(self._wanted) - 1}{_CLOSE}"

    def resolved(self, sections: list[str], *, bundle_beside: bool) -> list[str]:
        """The sections with each reference written as the heading it names.

        A reference names the first of its titles the render prints as a
        heading other than the one it stands under; with none, the first title
        is linked in the evidence bundle (``bundle_beside``) or named in words.
        """
        if not self._wanted or not any(self._token.search(text) for text in sections):
            return sections
        printed: dict[str, str] = {}
        for text in sections:
            for line, _under in _text_lines(text):
                found = _HEADING.match(line.rstrip("\r\n"))
                if found is not None:
                    printed.setdefault(_folded(found.group("title")), _label(found))
        out: list[str] = []
        for text in sections:
            lines: list[str] = []
            for line, under in _text_lines(text, all_lines=True):
                if _OPEN in line:

                    def words(found: re.Match[str], under: frozenset[str] = under) -> str:
                        return self._words(int(found.group(1)), printed, under, bundle_beside)

                    line = self._token.sub(words, line)
                lines.append(line)
            out.append("".join(lines))
        return out

    def _words(
        self, index: int, printed: dict[str, str], under: frozenset[str], bundle_beside: bool
    ) -> str:
        titles = self._wanted[index]
        for title in titles:
            key = _folded(title)
            if key in printed and key not in under:
                return printed[key]
        first = titles[0]
        if bundle_beside:
            from maljan.reporting.renderers.analyst import bundle_anchor
            from maljan.reporting.renderers.layout import BUNDLE_HTML

            return f"[{first}]({BUNDLE_HTML}#{bundle_anchor(first)}) in the evidence bundle"
        return f"the section “{first}”"


def section_reference(*titles: str) -> str:
    """A reference to the section titled ``titles[0]`` (or the first of the others printed).

    Written as the heading's number once the render knows its headings
    (:meth:`SectionReferences.resolved`). The first title is the single-file
    report's, which the evidence bundle prints too. Outside a render the
    title itself, in words.
    """
    references = _REFERENCES.get()
    if references is None:
        return f"the section “{titles[0]}”"
    return references.token(titles)


def references_for_render() -> Any:
    """Start a fresh set of references for one render; the token :func:`end_references` takes."""
    return _REFERENCES.set(SectionReferences())


def end_references(token: Any) -> None:
    _REFERENCES.reset(token)


def _folded(title: str) -> str:
    return " ".join(title.split()).casefold()


def _label(found: re.Match[str]) -> str:
    return found.group("appendix") or f"§{found.group('number')}"


def _text_lines(text: str, *, all_lines: bool = False) -> Iterable[tuple[str, frozenset[str]]]:
    """Each line outside a fenced block (every line with ``all_lines``), with the titles of
    the headings it stands under in its section (folded)."""
    from maljan.reporting.renderers.markdown import _TEXT, _ReferenceScan

    section = subsection = ""
    for line, kind in _ReferenceScan().lines(text):
        if kind == _TEXT:
            found = _HEADING.match(line.rstrip("\r\n"))
            if found is not None:
                if len(found.group("level")) == 2:
                    section, subsection = _folded(found.group("title")), ""
                else:
                    subsection = _folded(found.group("title"))
        elif not all_lines:
            continue
        yield line, frozenset(t for t in (section, subsection) if t)


# ---------------------------------------------------------------------------
# A decoded text in the pack's spelling
# ---------------------------------------------------------------------------

# How many characters other than backslashes a value must hold to be printed
# in place of its pack spelling: a shorter one is part of too many texts.
_VALUE_FLOOR = 3


def pack_spellings(report: Any) -> dict[str, str]:
    """Each pack spelling of a recorded text that differs from it, to the text.

    A recorded text is a tool table's cell, a value a recovering tool decoded
    (``emulated_strings.spelled``) or a decoded text the code passes to an API
    (``bound_values``). Only a text whose pack spelling differs by its closing
    backslash (``\\x5c``) is read: one printable line holding no quote, so the
    text printed in its place starts no line and closes no quote. A spelling
    a tool table's cell holds, whole or inside a longer cell, is left out: a
    tool wrote those characters, and a model quoting the tool is not corrected.

    The limit: only the run's recorded texts are read, so a model's own words
    that happen to spell a recorded text with ``\\x5c`` are printed as that
    text, and a spelling a tool wrote in an answer the report holds no table
    of is not known here.
    """
    values: set[str] = set()
    cells: list[str] = []
    for section in getattr(report, "sections", None) or ():
        for row in getattr(section, "rows", None) or ():
            held = [cell for cell in row if isinstance(cell, str) and "\\" in cell]
            values.update(held)
            cells.extend(cell for cell in held if "\\x5c" in cell)
    recovered = getattr(report, "emulated_strings", None)
    if recovered is not None:
        values.update(v for v in recovered.spelled.values() if "\\" in v)
    for bound in getattr(report, "bound_values", None) or ():
        value = str(getattr(bound, "value", "") or "")
        if "\\" in value:
            values.add(value)
    out: dict[str, str] = {}
    for value in values:
        if (
            not value.endswith("\\")
            or '"' in value
            or not value.isprintable()
            or len(value.replace("\\", "").strip()) < _VALUE_FLOOR
        ):
            continue
        spelling = pack_escaped(value)
        if spelling == value[:-1] + "\\x5c" and not any(spelling in cell for cell in cells):
            out[spelling] = value
    return out


# How a spelling stands in the rendered text: as written, or with each
# backslash escaped (a value a section escaped as inline text); either one may
# have its table separators escaped too (a value in a table cell).
_RAW, _ESCAPED = "raw", "escaped"


def _forms(spellings: dict[str, str]) -> dict[str, tuple[str, str, bool]]:
    """Each form a spelling stands in, to its text, how it was escaped and whether its
    table separators were."""
    out: dict[str, tuple[str, str, bool]] = {}
    for spelling, text in spellings.items():
        for form, how in ((spelling, _RAW), (_escaped(spelling), _ESCAPED)):
            out.setdefault(form, (text, how, False))
            if _PIPE in form:
                out.setdefault(_piped(form), (text, how, True))
    return out


def _spelling_pattern(forms: dict[str, tuple[str, str, bool]]) -> re.Pattern[str] | None:
    """Every form, longest first."""
    if not forms:
        return None
    alternatives = "|".join(re.escape(form) for form in sorted(forms, key=len, reverse=True))
    return re.compile(r"(?<![\w\\])(?:" + alternatives + r")(?![0-9A-Za-z])")


# The table separator, named as the Markdown renderer names it.
_PIPE = chr(124)


def _escaped(text: str) -> str:
    return text.replace("\\", "\\\\")


def _piped(text: str) -> str:
    return text.replace(_PIPE, "\\" + _PIPE)


def _code_spans(line: str) -> list[tuple[int, int]]:
    """The code spans of one line: a backtick run outside a span, closed by the next run of
    its length. An unclosed run opens none. A backslash outside a span escapes the next
    character."""
    spans: list[tuple[int, int]] = []
    index = 0
    while index < len(line):
        char = line[index]
        if char == "\\":
            index += 2
            continue
        if char != "`":
            index += 1
            continue
        end = index
        while end < len(line) and line[end] == "`":
            end += 1
        run = line[index:end]
        close = end
        while True:
            close = line.find(run, close)
            if close < 0:
                break
            after = close + len(run)
            if after < len(line) and line[after] == "`":
                while after < len(line) and line[after] == "`":
                    after += 1
                close = after
                continue
            break
        if close < 0:
            index = end
            continue
        spans.append((index, close + len(run)))
        index = close + len(run)
    return spans


def _unspelled_line(
    line: str, pattern: re.Pattern[str], forms: dict[str, tuple[str, str, bool]]
) -> str:
    if "\\x5c" not in line:
        return line
    spans: list[tuple[int, int]] | None = None

    def value(found: re.Match[str]) -> str:
        nonlocal spans
        text, how, piped = forms[found.group(0)]
        if how == _ESCAPED:
            # Among escaped text, escaped as its neighbours are.
            out = _escaped(text)
        else:
            if spans is None:
                spans = _code_spans(line)
            if any(start < found.start() < end for start, end in spans):
                # Inside a code span a backslash is printed as written.
                out = text
            else:
                out = _prose_escaped(text, line[found.end() : found.end() + 1])
        return _piped(out) if piped else out

    return pattern.sub(value, line)


def _prose_escaped(text: str, following: str) -> str:
    """``text`` among prose, printed as written.

    A backslash a viewer would read as an escape (before ASCII punctuation) or
    as a line break (ending the line) is escaped; a punctuation mark after a
    backslash in the value, which was inert behind it, is escaped too where
    Markdown reads it (``HKCR\\*\\shell\\`` would otherwise open emphasis). A
    dot and a colon are never escaped, so no domain or URL is hidden from the
    defanger. The text's closing backslash escapes only itself: the character
    after it is the surrounding text's.
    """
    out: list[str] = []
    for index, char in enumerate(text):
        if char == "\\":
            after = text[index + 1] if index + 1 < len(text) else following
            if not after or after in _ASCII_PUNCTUATION:
                out.append("\\")
        elif index and text[index - 1] == "\\" and char in _MARKDOWN_ACTIVE:
            out.append("\\")
        out.append(char)
    return "".join(out)


_ASCII_PUNCTUATION = frozenset("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~")
# The punctuation Markdown may read as markup, which an escape keeps literal.
_MARKDOWN_ACTIVE = _ASCII_PUNCTUATION - frozenset(".:\\")


# ---------------------------------------------------------------------------
# The platform's unread-callee clause
# ---------------------------------------------------------------------------

# How many callers a clause names in the analyst report's prose.
CALLERS_IN_PROSE = 3

# The clause as ``section_agreement.unread_callee_clause`` writes it for more
# callers than the prose names.
_UNREAD_CLAUSE = re.compile(
    r"(?P<lead>\b[Tt]he routine at (?P<routine>(?:offset )?0x[0-9a-fA-F]+)), called by the read "
    r"routines at (?P<word>offsets )?(?P<callers>0x[0-9a-fA-F]+(?:, 0x[0-9a-fA-F]+){"
    + str(CALLERS_IN_PROSE)
    + r",})(?P<tail>, has no listed code \(decompiled or disassembled\))"
)
# A line that is not a paragraph's: a table row, a list item, a quote, a
# heading, an indented code line. The table separator is named, as the
# Markdown renderer names it.
_NOT_PROSE = re.compile(r"^(?: {4}|\t|\s*(?:[>#" + chr(124) + r"]|[-*+] |\d+[.)] ))")


def _compact_callers(
    line: str, *, analyst: bool, printed_whole: frozenset[tuple[str, str]]
) -> tuple[str, list[str]]:
    """The line with each long caller list compacted, and the list lines to print after it.

    In the analyst report the clause names :data:`CALLERS_IN_PROSE` callers,
    the count and the bundle, only where the clause stands in a section 5 body
    (``printed_whole``: its routine and callers), which the single-file
    report and the bundle print; elsewhere a paragraph's clause names the
    count and its callers follow the paragraph as a list. A clause in a table
    row or a list item outside the analyst report is left whole.
    """
    if "has no listed code" not in line:
        return line, []
    prose = not _NOT_PROSE.match(line)
    if not analyst and not prose:
        return line, []
    listed: list[str] = []

    def compact(found: re.Match[str]) -> str:
        callers = found.group("callers").split(", ")
        word = found.group("word") or ""
        if analyst:
            if (found.group("routine"), found.group("callers")) not in printed_whole:
                return found.group(0)
            more = len(callers) - CALLERS_IN_PROSE
            named = ", ".join(callers[:CALLERS_IN_PROSE])
            where = f"{word}{named} and {more} more, every one listed in the evidence bundle"
        else:
            from maljan.reporting.renderers.markdown import _item

            listed.append(
                _item(f"Read routines that call {found.group('routine')}: {', '.join(callers)}")
            )
            where = "listed below"
        return (
            f"{found.group('lead')}, called by {len(callers)} read routines ({where})"
            f"{found.group('tail')}"
        )

    return _UNREAD_CLAUSE.sub(compact, line), listed


def _section_5_clauses(report: Any) -> frozenset[tuple[str, str]]:
    """The routine and callers of each long clause a section 5 prose body holds: the bodies
    the single-file report and the bundle print (``markdown.SECTION_5_PROSE``)."""
    from maljan.reporting.models import TechnicalSubsection
    from maljan.reporting.renderers.markdown import SECTION_5_PROSE

    ta = getattr(report, "technical_analysis", None)
    found: set[tuple[str, str]] = set()
    for names in SECTION_5_PROSE.values() if ta is not None else ():
        for name in names:
            sub = getattr(ta, name, None)
            if isinstance(sub, TechnicalSubsection) and "has no listed code" in sub.body:
                found.update(
                    (m.group("routine"), m.group("callers"))
                    for m in _UNREAD_CLAUSE.finditer(sub.body)
                )
    return frozenset(found)


def finished(sections: list[str], report: Any, *, analyst: bool) -> list[str]:
    """The sections with their references resolved and their text tidied (module docstring).

    ``analyst`` is whether the render is the analyst report, beside which the
    evidence bundle is served.
    """
    references = _REFERENCES.get()
    if references is not None:
        sections = references.resolved(sections, bundle_beside=analyst)
    return tidied(sections, report, analyst=analyst)


def tidied(sections: Sequence[str], report: Any, *, analyst: bool) -> list[str]:
    """The sections with each pack spelling printed as its text and each long caller list
    compacted (module docstring). One pass over each section's lines outside fences."""
    from maljan.reporting.renderers.markdown import _TEXT, _ReferenceScan

    forms = _forms(pack_spellings(report))
    pattern = _spelling_pattern(forms)
    printed_whole = _section_5_clauses(report) if analyst else frozenset()
    out: list[str] = []
    for text in sections:
        if pattern is None and "has no listed code" not in text:
            out.append(text)
            continue
        lines: list[str] = []
        pending: list[str] = []
        for line, kind in _ReferenceScan().lines(text):
            if pending and (kind != _TEXT or not line.strip() or _NOT_PROSE.match(line)):
                # The paragraph ended: its callers follow it as a list, apart
                # from whatever block starts next.
                lines.extend(["\n", *(item + "\n" for item in pending)])
                if line.strip():
                    lines.append("\n")
                pending = []
            if kind != _TEXT:
                lines.append(line)
                continue
            if pattern is not None:
                ending = line[len(line.rstrip("\r\n")) :]
                line = _unspelled_line(line.rstrip("\r\n"), pattern, forms) + ending
            line, listed = _compact_callers(line, analyst=analyst, printed_whole=printed_whole)
            pending.extend(listed)
            lines.append(line)
        if pending:
            if lines and not lines[-1].endswith("\n"):
                lines[-1] += "\n"
            lines.extend(["\n", *(item + "\n" for item in pending)])
            lines[-1] = lines[-1].rstrip("\n")
        out.append("".join(lines))
    return out

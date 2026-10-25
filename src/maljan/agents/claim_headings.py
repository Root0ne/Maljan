"""Where a claim begins in an analyst's answer: the one heading rule every reader uses.

The claim parser (``base_agent.read_claim_blocks``) splits an answer into
blocks at these headings, and the count of headings is what the parse is
checked against: a claim the model began and the parser did not read is
recorded, never dropped in silence. The validation turn's cut-answer question
and the loop's question whether an answer is a report count claims by the same
rule. A leaf module, so both sides can import it.
"""

from __future__ import annotations

import re

# What may stand before a label at the start of a line: quote and emphasis
# marks, and one list marker (``-``, ``+``, ``1.``, ``2)``; ``*`` is an
# emphasis mark already).
LINE_PREFIX = r"[ \t>*_#]*+(?:(?:[-+]|\d++[.)])[ \t]++)?[ \t>*_#]*+"

# A claim's heading at the start of a line, as models number and mark it:
# ``CLAIM:``, ``CLAIM 3:``, ``CLAIM R3:`` (a label of letters before its
# number, after a space or ``#``), ``CLAIM 3 —``, ``**CLAIM 4 (REVISED):**``,
# ``CLAIM 2 [REVISED — retracts claim 5]:``, ``- CLAIM:``, ``1. CLAIM:``, and a
# heading whose note is all its line holds (``CLAIM 1 (REVISED — not
# observed)``, fields on the lines after it). Each one opens a block of its
# own, so claims written one after another with no ``---`` between them are
# read as the claims they are, not as the first one. The note, in round or
# square brackets, is the model's own words: before a delimiter it is kept
# beside the claim (``heading_note``) and the sentence is what follows the
# delimiter; a heading that is its note alone has that note as its sentence. A
# bracket is closed on its own line or the line is no heading, and a bracket
# that never closes is given up once, and every run of spaces and marks is read
# possessively, so a line costs time linear in its length.
CLAIM_HEAD_RE = re.compile(
    r"^" + LINE_PREFIX + r"CLAIM(?:(?:[ \t]++#?(?P<label>[A-Za-z]++)|[ \t]*+#?)(?P<number>\d++))?"
    r"(?:[ \t]*+(?P<note>\([^)\n]*+\)|\[[^\]\n]*+\]))?[ \t]*+(?:\*\*)?[ \t]*+"
    r"(?:(?P<delim>:|—|–|-(?=\s))[ \t]*+(?:\*\*)?[ \t]*+|(?(note)$|(?!)))"
)


def heading_sentence(line: str, heading: re.Match[str]) -> str:
    """The claim sentence a heading's line starts: what follows its delimiter, or its note alone."""
    if heading.group("delim") is None:
        return heading.group("note") or ""
    return line[heading.end() :]


def heading_number(heading: re.Match[str]) -> str | None:
    """The number a heading writes after ``CLAIM`` (``CLAIM 7:``), leading zeros aside, or ``None``.

    Kept as the digits written, never converted: the number names a claim, it
    is not a quantity, and digits of any length compare as written. A label
    written before the digits stays in front of them (``CLAIM R7:`` is
    ``"R7"``): it is part of the name, so ``R7`` is never read as claim 7.
    """
    groups = heading.groupdict()
    digits = groups.get("number")
    if digits is None:
        return None
    return f"{groups.get('label') or ''}{digits.lstrip('0') or '0'}"


def heading_note(heading: re.Match[str]) -> str | None:
    """The note a heading writes before its delimiter, as written, or ``None``.

    A heading that is its note alone has no note beside its sentence: the
    note is the sentence.
    """
    if heading.group("delim") is None:
        return None
    return heading.group("note") or None


# The DISPUTES section's label: ``DISPUTES:`` (marks and a list marker
# allowed before it, ``**`` before the colon), or a Markdown heading naming
# it. Case-sensitive, and with its colon or its heading marks, so a claim's
# own sentence beginning "Disputes the static analyst's reading" is prose.
_DISPUTES_LABEL_RE = re.compile(
    r"^" + LINE_PREFIX + r"DISPUTES[ \t]*(?:\*\*)?[ \t]*:(?P<rest>.*)$"
    r"|^#+[ \t]*\**[ \t]*DISPUTES\b(?P<heading_rest>.*)$"
)
# What a label says on its own line to state that there is no dispute. Such a
# line closes itself: it opens no section, and what follows it is read.
_NO_DISPUTE = frozenset({"NONE", "N/A", "—", "–", "-"})


def _opens_disputes(line: str) -> bool:
    """Whether ``line`` opens the DISPUTES section: its label, not one that says there is none."""
    match = _DISPUTES_LABEL_RE.match(line)
    if match is None:
        return False
    rest = match.group("rest")
    if rest is None:
        rest = match.group("heading_rest") or ""
    rest = rest.strip().lstrip(":").strip("*_` ").rstrip(".").strip()
    # A label with nothing after it opens the section its items follow.
    return not rest or rest.upper() not in _NO_DISPUTE


def _split_at_disputes(text: str) -> tuple[list[str], list[str]]:
    lines = (text or "").splitlines()
    for index, line in enumerate(lines):
        if _opens_disputes(line):
            return lines[:index], lines[index:]
    return lines, []


# What ends the DISPUTES section: a label of a section an answer writes after
# it, at the start of a line, its emphasis and heading marks aside
# (``SUMMARY:``, ``**FINAL VERDICT:**``, ``## CONCLUSION:``). Only these, and
# case-sensitive: a dispute written as prose that names an analyst or a
# domain before a colon (``NETWORK: I disagree ...``, ``Network analyst:
# ...``) is a dispute, not the end of the section.
SECTION_END_LABELS = (
    "SUMMARY",
    "CONCLUSION",
    "CONCLUSIONS",
    "FINAL VERDICT",
    "VERDICT",
    "FINAL ASSESSMENT",
    "ASSESSMENT",
    "RECOMMENDATIONS",
    "NOTES",
    "REVISED CLAIMS",
)
_SECTION_END_RE = re.compile(
    r"^[ \t>*_#]*+(?:"
    + "|".join(re.escape(label) for label in SECTION_END_LABELS)
    + r")[ \t]*+(?:\*\*|__)?[ \t]*+:"
)


def disputes_section(text: str) -> str | None:
    """What ``text`` writes under its DISPUTES label, up to the next section; ``None`` without one.

    The section opens only at the label (:func:`_opens_disputes`): the word
    in a sentence, in any case, opens nothing, and a label saying there is no
    dispute opens no section. What the label's own line holds after it is the
    section's first line; the section ends at a known section label or at a
    claim block written after it (an unbulleted ``CLAIM_HEAD_RE`` heading
    followed by its EVIDENCE or CONFIDENCE line). Linear in ``text``.
    """
    _, section = _split_at_disputes(text)
    if not section:
        return None
    match = _DISPUTES_LABEL_RE.match(section[0])
    rest = "" if match is None else (match.group("rest") or match.group("heading_rest") or "")
    body = [rest.strip().lstrip(":").lstrip("*_` ")]
    lines = section[1:]
    for index, line in enumerate(lines):
        # A known section label ends it, and so does a claim block written
        # after it: an unbulleted claim heading (the claim reader's own test)
        # whose next line is its EVIDENCE or CONFIDENCE. A bulleted heading is
        # a dispute quoting a peer's claim, and stays one.
        if _SECTION_END_RE.match(line) or _opens_a_claim_block(lines, index):
            break
        body.append(line)
    return "\n".join(body)


# A list marker at the start of a line, after any quote or emphasis marks.
_BULLETED_RE = re.compile(r"[ \t>*_#]*+(?:[-+•]|\d++[.)])[ \t]")
# A claim block's first field line under its heading.
_CLAIM_FIELD_RE = re.compile(r"^" + LINE_PREFIX + r"(?:EVIDENCE|CONFIDENCE)\b", re.IGNORECASE)


def _opens_a_claim_block(lines: list[str], index: int) -> bool:
    """Whether ``lines[index]`` is an unbulleted claim heading whose next written line is a field.

    The blank lines between are read once more at most, so a section costs
    time linear in its length.
    """
    line = lines[index]
    if _BULLETED_RE.match(line) or not CLAIM_HEAD_RE.match(line):
        return False
    for after in lines[index + 1 :]:
        if after.strip():
            return bool(_CLAIM_FIELD_RE.match(after))
    return False


def before_disputes(text: str) -> str:
    """``text`` up to its DISPUTES section: what is the analyst's own.

    A peer's claim quoted under DISPUTES, with or without a ``---`` line before
    it, is not this analyst's claim, and the reader does not read past the
    section's label. A label that says there is no dispute (``DISPUTES:
    NONE``) opens no section, wherever it stands.
    """
    return "\n".join(_split_at_disputes(text)[0])


def count_claims_after_disputes(text: str) -> int:
    """How many claim headings ``text`` writes under its DISPUTES section.

    Not the analyst's own claims, so neither read nor counted as begun; the
    reader says when there are some and none of the analyst's own was read,
    which is the one case they could be the answer's only claims.
    """
    return _headings_in(_split_at_disputes(text)[1])


def claims_headed(text: str) -> str:
    """``text`` with every claim heading turned into a ``---``-separated ``CLAIM:`` block.

    Every heading opens a block, so no claim's CONFIDENCE, TECHNIQUE or
    EVIDENCE line is ever read as another's: a claim written without its
    CONFIDENCE line is a claim that states none, and the one after it keeps
    its own. Nothing under the DISPUTES section is read.
    """
    return claims_headed_with_notes(text)[0]


def _is_bare_heading(line: str, heading: re.Match[str]) -> bool:
    """Whether ``heading`` writes a delimiter and nothing after it (``CLAIM 7:``, ``**CLAIM 7:**``)."""
    return heading.groupdict().get("delim") is not None and not heading_sentence(
        line, heading
    ).strip(" \t*_`")


def _sentence_lines(lines: list[str]) -> dict[int, int]:
    """``{bare heading's index: index of the CLAIM: line that writes its sentence}``.

    A heading that writes only its number (``CLAIM 7:``), with a plain
    ``CLAIM: <sentence>`` as its next written line, is one claim: claim 7, its
    sentence on the line after. The retry that fixes claims by number asks for
    each one "under its number (CLAIM 7:) as its own block of CLAIM, EVIDENCE:
    ..." lines, and read as two headings it was an empty claim begun and not
    read, and a claim with no number. Each line is read once.
    """
    pairs: dict[int, int] = {}
    bare: int | None = None
    for index, line in enumerate(lines):
        if not line.strip():
            continue
        heading = CLAIM_HEAD_RE.match(line)
        groups = heading.groupdict() if heading is not None else {}
        if (
            bare is not None
            and heading is not None
            and groups.get("number") is None
            and groups.get("note") is None
            and groups.get("delim") == ":"
            and not _is_bare_heading(line, heading)
        ):
            pairs[bare] = index
            bare = None
            continue
        bare = index if heading is not None and _is_bare_heading(line, heading) else None
    return pairs


def claims_headed_with_notes(
    text: str,
) -> tuple[str, list[tuple[int, str | None, str | None]]]:
    """:func:`claims_headed`, and where each heading's ``CLAIM:`` line starts with its note.

    One ``(offset, note, number)`` per heading, in order: ``offset`` is where
    its ``CLAIM:`` line starts in the text returned, ``note`` is
    :func:`heading_note` and ``number`` is :func:`heading_number`. A heading
    that writes only its number, its ``CLAIM:`` line next, is one heading with
    that line's sentence (:func:`_sentence_lines`).
    """
    out: list[str] = []
    notes: list[tuple[int, str | None, str | None]] = []
    at = 0
    lines = before_disputes(text).splitlines()
    sentence_at = _sentence_lines(lines)
    skip_to = -1
    for index, line in enumerate(lines):
        if index <= skip_to:
            continue
        heading = CLAIM_HEAD_RE.match(line)
        if heading is not None:
            sentence_line, sentence_heading = line, heading
            if index in sentence_at:
                skip_to = sentence_at[index]
                sentence_line = lines[skip_to]
                sentence_heading = CLAIM_HEAD_RE.match(sentence_line) or heading
            written = "CLAIM: " + heading_sentence(sentence_line, sentence_heading)
            notes.append((at + len("---\n"), heading_note(heading), heading_number(heading)))
            out.extend(["---", written])
            at += len("---\n") + len(written) + 1
            continue
        out.append(line)
        at += len(line) + 1
    return "\n".join(out), notes


def _headings_in(lines: list[str]) -> int:
    """How many claim headings ``lines`` write, a bare heading and its ``CLAIM:`` line once."""
    return sum(1 for line in lines if CLAIM_HEAD_RE.match(line)) - len(_sentence_lines(lines))


def count_claims_begun(text: str) -> int:
    """How many claims ``text`` begins: every claim heading before its DISPUTES section."""
    return _headings_in(before_disputes(text).splitlines())


# A line that ends a claim's block: a ``---`` separator.
_SEPARATOR_RE = re.compile(r"^[ \t]*-{3,}[ \t]*$")
# The field lines a claim block writes under its heading.
_FIELD_LABEL_RE = re.compile(
    r"^" + LINE_PREFIX + r"(?:EVIDENCE|CONFIDENCE|TECHNIQUE|DISSENT)\b", re.IGNORECASE
)


def _block_key(lines: list[str]) -> str:
    """A claim's block as compared: marks, case and spacing aside, blank lines left out."""
    words = re.sub(r"[*_`#>]", " ", " ".join(lines)).lower().split()
    return " ".join(words).rstrip(" .;:")


def claim_blocks(text: str) -> list[tuple[int, str]]:
    """``(offset, key)`` of each claim ``text`` begins, before its DISPUTES section.

    A claim is its whole block: the sentence on its heading line and every
    line after it up to the next heading, a ``---`` separator, or the first
    line that is not a field once its field lines have begun (the prose after
    the last claim is not part of it), blank lines aside; the claim's number
    and the note a heading writes before its delimiter are not part of it,
    while a heading that is its note alone starts its block with that note. Two claims under one label
    with different sentences or evidence are different claims, and a heading
    that holds only its label is told apart by what follows it. ``offset`` is
    where the heading line starts in ``text``.
    """
    body = before_disputes(text)
    blocks: list[tuple[int, list[str]]] = []
    current: list[str] | None = None
    fields = False
    offset = 0
    for line in body.splitlines(keepends=True):
        bare = line.rstrip("\r\n")
        heading = CLAIM_HEAD_RE.match(bare)
        if heading is not None:
            # A heading that is its note alone starts its block with the
            # note, the only sentence it writes.
            current = [heading_sentence(bare, heading)]
            fields = False
            blocks.append((offset, current))
        elif _SEPARATOR_RE.match(bare):
            current = None
        elif current is not None and bare.strip():
            if _FIELD_LABEL_RE.match(bare):
                fields = True
                current.append(bare)
            elif fields:
                current = None
            else:
                current.append(bare)
        offset += len(line)
    return [(start, _block_key(lines)) for start, lines in blocks]

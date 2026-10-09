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
LINE_PREFIX = r"[ \t>*_#]*(?:(?:[-+]|\d+[.)])[ \t]+)?[ \t>*_#]*"

# A claim's heading at the start of a line, as models number and mark it:
# ``CLAIM:``, ``CLAIM 3:``, ``CLAIM 3 —``, ``**CLAIM 4 (REVISED):**``,
# ``CLAIM 2 [REVISED — retracts claim 5]:``, ``- CLAIM:``, ``1. CLAIM:``, and a
# heading whose note is all its line holds (``CLAIM 1 (REVISED — not
# observed)``, fields on the lines after it). Each one opens a block of its
# own, so claims written one after another with no ``---`` between them are
# read as the claims they are, not as the first one. The note, in round or
# square brackets, is the model's own words and is kept (``heading_text``); a
# bracket is closed on its own line or the line is no heading, and a bracket
# that never closes is given up once, so a line costs time linear in its length.
CLAIM_HEAD_RE = re.compile(
    r"^" + LINE_PREFIX + r"CLAIM(?:[ \t]*#?\d+)?"
    r"(?:[ \t]*(?P<note>\([^)\n]*\)|\[[^\]\n]*\]))?[ \t]*(?:\*\*)?[ \t]*"
    r"(?:(?::|—|–|-(?=\s))[ \t]*(?:\*\*)?[ \t]*|(?(note)$|(?!)))"
)


def heading_text(line: str, heading: re.Match[str]) -> str:
    """What a claim heading's line says after its label: the note, then the sentence.

    The note before the delimiter (a revision, a retraction) is the model's
    own words, kept as written, brackets and all, ahead of the sentence it
    qualifies; a heading without one reads as it always did.
    """
    rest = line[heading.end() :]
    note = heading.group("note")
    if not note:
        return rest
    return f"{note} {rest}" if rest else note


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
    return sum(1 for line in _split_at_disputes(text)[1] if CLAIM_HEAD_RE.match(line))


def claims_headed(text: str) -> str:
    """``text`` with every claim heading turned into a ``---``-separated ``CLAIM:`` block.

    Every heading opens a block, so no claim's CONFIDENCE, TECHNIQUE or
    EVIDENCE line is ever read as another's: a claim written without its
    CONFIDENCE line is a claim that states none, and the one after it keeps
    its own. Nothing under the DISPUTES section is read.
    """
    out: list[str] = []
    for line in before_disputes(text).splitlines():
        heading = CLAIM_HEAD_RE.match(line)
        if heading is not None:
            out.extend(["---", "CLAIM: " + heading_text(line, heading)])
            continue
        out.append(line)
    return "\n".join(out)


def count_claims_begun(text: str) -> int:
    """How many claims ``text`` begins: every claim heading before its DISPUTES section."""
    return sum(1 for line in before_disputes(text).splitlines() if CLAIM_HEAD_RE.match(line))


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
    and its heading's note are not part of it. Two claims under one label
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
            current = [bare[heading.end() :]]
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


def claim_heading_counts(text: str) -> tuple[int, int]:
    """``(claims begun, distinct claims)`` of an answer, each claim keyed by its block."""
    blocks = claim_blocks(text)
    return len(blocks), len({key for _start, key in blocks})

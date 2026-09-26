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
# ``- CLAIM:``, ``1. CLAIM:``. Each one opens a block of its own, so claims
# written one after another with no ``---`` between them are read as the
# claims they are, not as the first one.
CLAIM_HEAD_RE = re.compile(
    r"^" + LINE_PREFIX + r"CLAIM(?:[ \t]*#?\d+)?(?:[ \t]*\([^)\n]*\))?[ \t]*(?:\*\*)?[ \t]*"
    r"(?::|—|–|-(?=\s))[ \t]*(?:\*\*)?[ \t]*"
)
_DISPUTES_LINE_RE = re.compile(r"^[ \t>*_#]*DISPUTES\b", flags=re.IGNORECASE)


def before_disputes(text: str) -> str:
    """``text`` up to its DISPUTES section: what is the analyst's own.

    A peer's claim quoted under DISPUTES, with or without a ``---`` line before
    it, is not this analyst's claim, and neither the reader nor the count
    reads past the section's line.
    """
    lines = (text or "").splitlines()
    for index, line in enumerate(lines):
        if _DISPUTES_LINE_RE.match(line):
            return "\n".join(lines[:index])
    return "\n".join(lines)


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
            out.extend(["---", "CLAIM: " + line[heading.end() :]])
            continue
        out.append(line)
    return "\n".join(out)


def count_claims_begun(text: str) -> int:
    """How many claims ``text`` begins: every claim heading before its DISPUTES section."""
    return sum(1 for line in before_disputes(text).splitlines() if CLAIM_HEAD_RE.match(line))

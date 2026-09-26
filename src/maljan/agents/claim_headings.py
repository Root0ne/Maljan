"""Where a claim begins in an analyst's answer: the one heading rule every reader uses.

The claim parser (``base_agent.read_claim_blocks``) splits an answer into
blocks at these headings, and the count of headings is what the parse is
checked against: a claim the model began and the parser did not read is
recorded, never dropped in silence. The validation turn's cut-answer question
counts claims by the same rule. A leaf module, so both sides can import it.
"""

from __future__ import annotations

import re

# A claim's heading at the start of a line, as models number and mark it:
# ``CLAIM:``, ``CLAIM 3:``, ``CLAIM 3 —``, ``**CLAIM 4 (REVISED):**``. Each one
# opens a block of its own, so claims written one after another with no
# ``---`` between them are read as the claims they are, not as the first one.
CLAIM_HEAD_RE = re.compile(
    r"^[ \t>*_#]*CLAIM(?:[ \t]*#?\d+)?(?:[ \t]*\([^)\n]*\))?[ \t]*(?:\*\*)?[ \t]*"
    r"(?::|—|–|-(?=\s))[ \t]*(?:\*\*)?[ \t]*"
)
_CONFIDENCE_LINE_RE = re.compile(r"^[ \t>*_#]*CONFIDENCE:")
_DISPUTES_LINE_RE = re.compile(r"^[ \t>*_#]*DISPUTES\b", flags=re.IGNORECASE)


def claims_headed(text: str) -> str:
    """``text`` with each claim heading turned into a ``---``-separated ``CLAIM:`` block.

    A heading opens a new block only where one can begin: the first one, or
    one after the open block has its CONFIDENCE line. A line inside a block's
    EVIDENCE that happens to start with "CLAIM 2 -" is part of that block, and
    nothing under the DISPUTES section — a peer's claim quoted there — is
    read as this analyst's claim.
    """
    out: list[str] = []
    open_block = False
    confident = False
    disputes = False
    for line in text.splitlines():
        if _DISPUTES_LINE_RE.match(line):
            disputes = True
        heading = None if disputes else CLAIM_HEAD_RE.match(line)
        if heading is not None and (not open_block or confident):
            out.extend(["---", "CLAIM: " + line[heading.end() :]])
            open_block, confident = True, False
            continue
        if _CONFIDENCE_LINE_RE.match(line):
            confident = True
        elif line.strip() and not line.strip().strip("-"):
            # The model's own separator line closes the block.
            open_block = False
        out.append(line)
    return "\n".join(out)


def count_claims_begun(text: str) -> int:
    """How many claims ``text`` begins: every claim heading before its DISPUTES section.

    Every heading counts, including one the block reader took into the block
    before it (a heading written where the open block had no CONFIDENCE line
    yet). That is the case a count has to catch: the model began a claim
    there, and the reader did not read it as one.
    """
    begun = 0
    for line in (text or "").splitlines():
        if _DISPUTES_LINE_RE.match(line):
            break
        if CLAIM_HEAD_RE.match(line):
            begun += 1
    return begun

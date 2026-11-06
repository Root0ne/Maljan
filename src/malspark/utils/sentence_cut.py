"""What leaving one sentence out of a text takes away with it.

The report leaves a sentence out of its prose in two places: the agreement
round, where no rewrite of a closing sentence a source says otherwise of
passes (``reporting.section_agreement``), and the analyst report, which prints
no sentence a check left standing (``reporting.renderers.analyst``). Both
take the same span, so a paragraph reads the same whichever left it out.
"""

from __future__ import annotations

# The spaces taken with a sentence: never a line break, which ends a paragraph
# or an item.
_SPACES = " \t"


def left_out_span(text: str, start: int, end: int) -> tuple[int, int]:
    """The span of ``text[start:end]`` with the spaces after it, or, where a line break
    or the text's end follows it, the spaces before it."""
    after = end
    while after < len(text) and text[after] in _SPACES:
        after += 1
    if after > end:
        return start, after
    while start > 0 and text[start - 1] in _SPACES:
        start -= 1
    return start, end

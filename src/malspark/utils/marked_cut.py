"""A text cut to a width, with the cut shown where it is shown.

A claim's evidence stored at a fixed width ended mid-sentence — "… This
suggests", "… like PowerShell di" — and a report printed it as the model's own
sentence. A text that is shortened anywhere it is shown carries the mark of the
cut, so a reader, and a model reading it back, can tell a cut from an ending.
"""

from __future__ import annotations

# The mark a cut text ends with.
CUT_MARK = "…"


def marked_cut(text: str, width: int) -> str:
    """``text`` whole when it fits ``width``, else cut and ending in :data:`CUT_MARK`.

    The mark is inside the width, so the result is never longer than it. A
    width of zero or less keeps the text whole: no width is no cut.
    """
    value = str(text or "")
    if width <= 0 or len(value) <= width:
        return value
    return value[: max(0, width - len(CUT_MARK))].rstrip() + CUT_MARK

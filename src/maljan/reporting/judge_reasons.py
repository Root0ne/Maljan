"""A judge's reason as the report's ATT&CK table prints it, under one rule.

The judge answers each technique question with a reason, and the record keeps
it whole. The table prints whole sentences of it, up to the first that opens
the model's own working ("Wait, …") and as many as fit one width, marked where
anything is left out.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from maljan.utils.marked_cut import CUT_MARK

# The words a judge's reason is printed after in the ATT&CK table, and the
# width its printed reason keeps to.
_JUDGE_REASON_OPENERS = ("the judge dropped it (", "kept by the judge when asked (")
JUDGE_REASON_WIDTH = 200
# Where one sentence ends and the next begins.
_SENTENCE_BREAK_RE = re.compile(r"(?<=[.!?])[\"')\]]?\s+(?=[A-Z\"'(\[])")
# A sentence that is the model's own working rather than its reason: one that
# opens with words only working opens with. "Actually", "okay" and "oh" open
# reasons as often, and are not among them.
_SELF_TALK_RE = re.compile(
    r"^\W*(?:wait\b|hmm+\b|hold on\b|let me\b|let's\b|but wait\b|on second thought\b"
    r"|re-?reading\b|looking again\b)",
    re.IGNORECASE,
)


def judge_reason_shown(reason: str, width: int = JUDGE_REASON_WIDTH) -> str:
    """A judge's reason as the ATT&CK table prints it, under one rule.

    The sentences that are the model's own working ("Wait, …", "Let me …")
    are left out wherever they stand; the others are printed in order, as
    many as fit ``width``, so a conclusion written after the working is
    printed. A reason that is all working prints its last sentence, its
    conclusion. A first sentence longer than the width is cut at a word.
    Anything left out is marked with the cut mark. The record keeps the
    reason whole.
    """
    text = " ".join(str(reason or "").split())
    if not text:
        return ""
    sentences = _SENTENCE_BREAK_RE.split(text)
    kept = [sentence for sentence in sentences if not _SELF_TALK_RE.match(sentence)]
    if not kept:
        kept = sentences[-1:]
    shown: list[str] = []
    for sentence in kept:
        if len(" ".join([*shown, sentence])) > width:
            break
        shown.append(sentence)
    if not shown:
        return word_cut(kept[0], width)
    said = " ".join(shown)
    return said if len(shown) == len(sentences) else f"{said} {CUT_MARK}"


def status_shown(text: str, width: int, plain: Callable[[str], str] = str) -> str:
    """A status that may carry a judge's reason, as the report prints it in ``width``.

    Each judge's reason is printed by :func:`judge_reason_shown` and never cut
    into; what follows the last reason is cut at a word to what the width
    leaves. A status with no judge's reason is cut to the width as before.
    ``plain`` is the report's defanger, applied before anything is cut.
    """
    said, through = judge_reasons_shown(str(text or ""))
    if not through:
        whole = plain(said)
        return whole if len(whole) <= width else whole[: width - 1] + CUT_MARK
    head, tail = plain(said[:through]), plain(said[through:])
    return head + word_cut(tail, max(0, width - len(head))) if tail else head


def word_cut(text: str, width: int) -> str:
    """``text`` whole when it fits ``width``, else cut at the last word that fits and marked."""
    if len(text) <= width:
        return text
    cut = text[: max(0, width - len(CUT_MARK))]
    if " " in cut:
        cut = cut[: cut.rfind(" ")]
    cut = cut.rstrip(" ,;:")
    return f"{cut}{CUT_MARK}" if cut else CUT_MARK


def judge_reasons_shown(text: str) -> tuple[str, int]:
    """``text`` with each judge's reason in it printed by :func:`judge_reason_shown`.

    The reason is the bracket after "the judge dropped it" or "kept by the
    judge when asked", to its matching close (to the end, where the bracket is
    never closed). The second value is where the last reason printed ends in
    the returned text, ``0`` when there is none.
    """
    out: list[str] = []
    at = 0
    through = 0
    lowered = text.lower()
    while True:
        starts = [
            (lowered.find(opener, at), opener)
            for opener in _JUDGE_REASON_OPENERS
            if lowered.find(opener, at) >= 0
        ]
        if not starts:
            break
        start, opener = min(starts)
        open_at = start + len(opener)
        depth = 1
        end = open_at
        while end < len(text) and depth:
            if text[end] == "(":
                depth += 1
            elif text[end] == ")":
                depth -= 1
            end += 1
        closed = depth == 0
        inner = text[open_at : end - 1] if closed else text[open_at:]
        out.append(text[at:open_at] + judge_reason_shown(inner) + (")" if closed else ""))
        at = end
        through = len("".join(out))
    out.append(text[at:])
    return "".join(out), through

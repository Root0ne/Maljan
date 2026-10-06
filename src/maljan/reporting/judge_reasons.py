"""A judge's reason as the report's ATT&CK table prints it, under one rule.

The judge answers each technique question with a reason, and the record keeps
it whole. The table prints whole sentences of it, up to the first that opens
the model's own working ("Wait, …") and as many as fit one width, marked where
anything is left out.
"""

from __future__ import annotations

import re

from maljan.utils.marked_cut import CUT_MARK

# The words a judge's reason is printed after in the ATT&CK table, and the
# width its printed reason keeps to.
_JUDGE_REASON_OPENERS = ("the judge dropped it (", "kept by the judge when asked (")
JUDGE_REASON_WIDTH = 200
# Where one sentence ends and the next begins.
_SENTENCE_BREAK_RE = re.compile(r"(?<=[.!?])[\"')\]]?\s+(?=[A-Z\"'(\[])")
# A sentence that opens the model's own working rather than its reason.
_SELF_TALK_RE = re.compile(
    r"^\W*(?:wait|hmm+|hold on|let me|let's|actually|okay|ok|oh|but wait"
    r"|on second thought|re-?reading)\b",
    re.IGNORECASE,
)
JUDGE_WORKING_ONLY = "its reason is its working, kept whole in the report record"


def judge_reason_shown(reason: str, width: int = JUDGE_REASON_WIDTH) -> str:
    """A judge's reason as the ATT&CK table prints it, under one rule.

    Whole sentences, in order, up to the first that opens the model's own
    working ("Wait, …", "Let me …"), and as many as fit ``width``; a first
    sentence longer than the width is cut at a word and marked. Anything left
    out is marked with the cut mark. The record keeps the reason whole.
    """
    text = " ".join(str(reason or "").split())
    if not text:
        return ""
    sentences = _SENTENCE_BREAK_RE.split(text)
    kept: list[str] = []
    for sentence in sentences:
        if _SELF_TALK_RE.match(sentence):
            break
        kept.append(sentence)
    if not kept:
        return JUDGE_WORKING_ONLY
    shown: list[str] = []
    for sentence in kept:
        if len(" ".join([*shown, sentence])) > width:
            break
        shown.append(sentence)
    if not shown:
        return word_cut(kept[0], width)
    said = " ".join(shown)
    return said if len(shown) == len(sentences) else f"{said} {CUT_MARK}"


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

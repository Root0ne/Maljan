"""The same indicator or finding said twice, written once.

Two analysts that both read the same C2 endpoint out of the same sample give
the report two rows that mean one thing, and a reader counting rows counts it
twice. The same happens to a finding a static analyst and a reverser both
reach. What is wanted is one row, and what must not happen is a merge that
invents anything: severity, confidence, a verdict, a category, a family, a
technique id and every sentence a model wrote belong to the model that wrote
them, and a merge that raised a confidence because two agents agreed would be
this codebase inventing agreement.

So a merge here only ever grows a set. The first occurrence's text is what the
row keeps — its notes, its title, its confidence — and what the second
occurrence contributes is the ids, the sources, the agents and the stages it
brings with it. A merge that had nothing set-shaped to contribute leaves the
row exactly as it was and is still counted, because the count is what tells a
reader the two rows were the same thing rather than two.

Fingerprinting is deliberately shy. An indicator is ``(kind, canonical
value)`` where canonicalising is lower-casing, trimming and undoing the two
ways an analyst writes an address it does not want a reader to click; a
finding is ``(first technique id, normalised title)``. Anything cleverer —
substring matching, edit distance, a URL parser's idea of equivalence — can
merge two indicators that are not the same one, and a wrongly merged indicator
is a fact removed from a report with nothing saying it happened.
"""

from __future__ import annotations

import re
from typing import Any

# The two ways an analyst writes an address it does not want a reader to open,
# undone so the defanged spelling and the plain one fingerprint alike. Only
# these: a substitution table that guessed would merge indicators that differ.
_DEFANGED = (
    ("[.]", "."),
    ("(.)", "."),
    ("[:]", ":"),
    ("[://]", "://"),
    ("[at]", "@"),
    ("(at)", "@"),
    ("hxxps", "https"),
    ("hxxp", "http"),
)

_WHITESPACE = re.compile(r"\s+")
# Trailing punctuation a title picks up from the sentence it was written in.
_TITLE_TAIL = ".,;:!-–— "


def canonical_value(value: Any) -> str:
    """One indicator value in the spelling two copies of it share."""
    text = str(value or "").strip().lower()
    for defanged, plain in _DEFANGED:
        text = text.replace(defanged, plain)
    return text


def indicator_fingerprint(kind: Any, value: Any) -> tuple[str, str]:
    """What makes two indicator rows the same indicator."""
    return (str(kind or "").strip().lower(), canonical_value(value))


def normalised_title(title: Any) -> str:
    """A finding's title with the spelling two writers of it would share."""
    text = _WHITESPACE.sub(" ", str(title or "")).strip().lower()
    return text.strip(_TITLE_TAIL)


def finding_fingerprint(technique_ids: Any, title: Any) -> tuple[str, str]:
    """What makes two findings the same finding: its technique and what it says.

    The first technique id, because that is the one the finding is filed
    under; a finding with none is fingerprinted on its title alone, which is
    why the title is normalised rather than compared as written.
    """
    ids = [str(tid).strip().upper() for tid in (technique_ids or []) if str(tid).strip()]
    return (ids[0] if ids else "", normalised_title(title))


def merge_cell(kept: str, arriving: str, *, separator: str = ", ") -> str:
    """Two set-shaped cells as one, in the order they were first seen.

    A cell that holds a list of ledger ids or agent names is a set written
    down; merging it is a union. Nothing else in a row is merged this way,
    because nothing else in a row is a set.
    """
    seen: list[str] = []
    for part in (*kept.split(separator.strip()), *arriving.split(separator.strip())):
        item = part.strip()
        if item and item not in seen:
            seen.append(item)
    return separator.join(seen)


class MergeTally:
    """How many rows were merged away, for the run summary to state.

    A number, not a list: the report shows the merged rows themselves, and
    what a reader needs from the summary is whether merging happened at all
    and how much of the run's output it accounts for.
    """

    def __init__(self) -> None:
        self.indicators_merged = 0
        self.findings_merged = 0

    def indicator(self) -> None:
        self.indicators_merged += 1

    def finding(self) -> None:
        self.findings_merged += 1

    def as_dict(self, *, extra_indicators: int = 0) -> dict[str, int]:
        """``run_summary.dedupe``, with merges counted elsewhere added in.

        ``extra_indicators`` is the STIX bundle's own indicator merge, counted
        by the integrity pass in the judge long before a report is assembled.
        Both are the same act on the same run, so the summary states one
        number for it.
        """
        return {
            "indicators_merged": self.indicators_merged + max(0, int(extra_indicators)),
            "findings_merged": self.findings_merged,
        }

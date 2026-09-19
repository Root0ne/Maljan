"""Making a tool answer fit the prompt without stopping it being an answer.

A tool result wider than ``max_tool_output_chars`` used to be cut as text: the
first N characters and a marker. For prose that is the right thing. For the
JSON every tool server actually answers with, it is the end of the document —
the model gets a prefix ending mid-array, and the ledger gets a string that
will not parse, so ``structured`` is ``None`` and every reader of the record
(the ledger projection, the ledger report, the triage pack) skips the entry.
The effect was backwards: an analyst's *largest* answers, the ones that found
the most, were exactly the ones that contributed nothing to the report, and
nothing anywhere said so.

What is shortened here is the document. Elements come off the end of its
largest lists until it fits; no key is ever dropped, so whatever the answer
says about itself — which file it read, how many rows exist, where the next
page starts — survives however long its list was. The document then says what
it handed over, in its own vocabulary, so a reader can reconcile the count.

One document, one reader. The string this returns is what the model reads and
what the recorder stores, with no second shortening in between: a model that
was told a hundred rows exist and a ledger that holds forty would be two
answers to one call.
"""

from __future__ import annotations

import json
from typing import Any

__all__ = ["shorten_json_document"]

# The key a sidecar already sets when it paged an answer itself. Reused rather
# than invented: an answer that was shortened twice — once by the tool's own
# page limit and once here — is still one truncated answer.
_TRUNCATED = "truncated"


def _dump(document: Any) -> str:
    return json.dumps(document)


def _lists(document: Any) -> list[tuple[dict[str, Any], str, list[Any]]]:
    """Every list in the document, with the object and key that hold it.

    Depth-first in declaration order, so the walk is deterministic and a
    caller's idea of "the first list" does not depend on anything but the
    document. A list not held under a key of some object is not returned:
    there is nowhere to write down how much of it was left out, and a
    shortening nobody can see is the defect this module exists to remove.
    """
    found: list[tuple[dict[str, Any], str, list[Any]]] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in list(node.items()):
                if isinstance(value, list):
                    found.append((node, str(key), value))
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(document)
    return found


def _longest_prefix_that_fits(
    document: Any, holder: dict[str, Any], key: str, rows: list[Any], limit: int
) -> int:
    """How many of ``rows`` may stay, given everything else as it now stands.

    Binary search rather than one element at a time: an answer with a hundred
    and fifty thousand rows would otherwise cost a hundred and fifty thousand
    serialisations of a five-megabyte document. Dropping from the end only
    ever shrinks the result, so the predicate is monotonic and the search is
    exact — it keeps every row the limit allows, where halving would throw
    away rows nobody had to lose.
    """
    low, high = 0, len(rows)
    best = 0
    while low <= high:
        middle = (low + high) // 2
        holder[key] = rows[:middle]
        if len(_dump(document)) <= limit:
            best = middle
            low = middle + 1
        else:
            high = middle - 1
    holder[key] = rows[:best]
    return best


def _count_key(holder: dict[str, Any], key: str) -> str:
    """What this object will call the number of rows it handed over.

    Beside a ``total`` the tool already emits, the useful number is how many
    rows are here: the reader has the denominator. Without one, the useful
    number is how many are missing, because otherwise nothing in the answer
    distinguishes "forty rows" from "forty of three thousand".
    """
    if "total" in holder or "total_matched" in holder:
        return f"{key}_returned"
    return f"{key}_omitted"


def shorten_json_document(text: str, limit: int) -> tuple[str, bool]:
    """``(text, whether it was shortened)`` for one tool answer.

    Returns the text unchanged, and ``False``, for anything this cannot
    shorten while leaving a document a reader can still parse and reconcile:
    text that is not JSON, a JSON scalar, a bare list (nothing in one can say
    how many elements are missing, so the caller's character cut is the honest
    outcome), an answer already inside the limit, and a document whose keys
    alone are over it.

    Otherwise the largest list gives up as many trailing elements as it must,
    then the next largest, and so on. ``truncated`` and each shortened list's
    count go in *before* that list is measured, at the widest value they can
    take, so the room they need is room the search has already paid for and
    the finished document is inside the limit rather than a few characters
    past it.
    """
    if limit <= 0 or len(text) <= limit:
        return text, False
    try:
        document = json.loads(text)
    except (ValueError, TypeError):
        return text, False
    if not isinstance(document, dict):
        return text, False

    lists = _lists(document)
    if not lists:
        return text, False
    # Largest first, so the rows that come off are the ones there are most of;
    # ties keep the walk's order, which makes the result deterministic.
    ordered = sorted(range(len(lists)), key=lambda index: -len(lists[index][2]))

    document[_TRUNCATED] = True
    shortened = False
    for index in ordered:
        holder, key, rows = lists[index]
        if len(_dump(document)) <= limit:
            break
        if not rows:
            continue
        counted = _count_key(holder, key)
        had_count = counted in holder
        # The widest the number can be, so the search measures the document
        # this will end up being rather than a shorter one.
        holder[counted] = len(rows)
        kept = _longest_prefix_that_fits(document, holder, key, rows, limit)
        if kept == len(rows):
            if not had_count:
                holder.pop(counted, None)
            continue
        holder[counted] = kept if counted.endswith("_returned") else len(rows) - kept
        shortened = True

    if not shortened or len(_dump(document)) > limit:
        # Either nothing needed to give, or even with every list emptied the
        # document is over the limit because its keys alone are. Nothing here
        # can help; the caller's character cut is what is left.
        return text, False
    return _dump(document), True

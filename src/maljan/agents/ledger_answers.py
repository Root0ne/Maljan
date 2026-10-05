"""Answers the ledger already holds: a listing asked again, a function decompiled again.

Failed reversing loops repeat themselves; successful ones move on. The repeat
guard (``evidence_recorder.RepeatGuard``) counts identical calls. What it cannot
see are the other spellings of the same call:

* a list or search tool asked again for the same scope, or a wider one, after
  an answer that already held every item of it — ``limit`` 100 after a
  ``limit`` 50 answer that held 11 items;
* a function decompiled again with no new argument — the address with ``0x``
  after it without, one function of an earlier batch asked alone.

Such a call is not run. It is answered with the recorded text under the id of
the entry that holds it, and a sentence says so; nothing is written to the
ledger, because no tool ran. What counts as covered is read off the run and
the call: an answer is whole when it held fewer items than it asked for, and
a call that adds an argument the earlier one did not have is run. The first
decompile answered this way in a loop also says, once, how the loop can move
on instead of reading again.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any

from maljan.pipeline.validation import (
    _ADDRESS_ARGUMENTS,
    _ADDRESS_LIST_ARGUMENTS,
    _NAME_ARGUMENTS,
    _batch_listings,
    _entry_functions,
    _one_function,
    image_bases_in,
)

__all__ = [
    "DECOMPILED_AGAIN",
    "LISTED_AGAIN",
    "LedgerAnswer",
    "LedgerAnswers",
    "decoding_tools",
    "pivot_sentence",
]

# The two kinds of answer, as the loop's budget record counts them.
LISTED_AGAIN = "listing"
DECOMPILED_AGAIN = "decompile"

# The arguments that bound how many items a page holds, and the ones that say
# where the page starts. Every other argument names the scope and must match.
_SIZE_NAMES = frozenset({"limit", "k", "page_size", "count_limit"})
_POSITION_NAMES = frozenset({"offset", "cursor", "page"})
_FUNCTION_ARGUMENTS = frozenset([*_ADDRESS_ARGUMENTS, *_ADDRESS_LIST_ARGUMENTS, *_NAME_ARGUMENTS])


def _is_size(name: str) -> bool:
    lowered = name.lower()
    return (
        lowered in _SIZE_NAMES
        or lowered.startswith("max_")
        or lowered.endswith("_limit")
        or (lowered.endswith("_size") and lowered.startswith(("page_", "max_")))
    )


def _is_position(name: str) -> bool:
    lowered = name.lower()
    return lowered in _POSITION_NAMES or lowered.endswith(("_offset", "_page"))


def _words(tool: str) -> list[str]:
    return [w for w in re.split(r"[^a-z0-9]+", str(tool or "").lower()) if w]


def _lists_or_searches(tool: str) -> bool:
    words = _words(tool)
    return "list" in words or "search" in words


def _decompiles(tool: str) -> bool:
    return "decompil" in str(tool or "").lower()


def decoding_tools(names: Iterable[str]) -> tuple[str, ...]:
    """The tool names among ``names`` that say they decode, decrypt or emulate."""
    return tuple(
        dict.fromkeys(
            str(name)
            for name in names
            if re.search(r"decod|decrypt|emulat", str(name or ""), re.IGNORECASE)
        )
    )


def pivot_sentence(decoders: Sequence[str]) -> str:
    """How a loop that reads the same code again can move on, said once per loop.

    Names the loop's own decoding tools when it has any, and otherwise asks for
    the decoder in a claim, where the analysis can use it.
    """
    decoder = (
        f"run a decoder over what it decodes ({', '.join(decoders)})"
        if decoders
        else "name the decoder it uses, with its scheme and its key, in a claim"
    )
    return (
        "Reading it again adds nothing new; you can move on instead: "
        f"{decoder}, state the constraint its code imposes, or give your answer."
    )


def _absent(value: Any) -> bool:
    return value is None or value == "" or value == [] or value == {}


def _normal(args: Mapping[str, Any]) -> dict[str, Any]:
    return {str(k): v for k, v in (args or {}).items() if not _absent(v)}


def _key(args: Mapping[str, Any]) -> str:
    try:
        return json.dumps(args, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return repr(sorted(args.items()))


def _split(args: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """``(scope, size, position)`` of normalised arguments."""
    scope: dict[str, Any] = {}
    size: dict[str, Any] = {}
    position: dict[str, Any] = {}
    for name, value in _normal(args).items():
        if _is_size(name):
            size[name] = value
        elif _is_position(name):
            # A page that starts at the start is the page with no position.
            if str(value).strip() not in ("0", "0.0"):
                position[name] = value
        else:
            scope[name] = value
    return scope, size, position


def _at_start(position: Mapping[str, Any]) -> bool:
    return all(str(value).strip() in ("0", "0.0") for value in position.values())


def _one_number(size: Mapping[str, Any]) -> int | None:
    if len(size) != 1:
        return None
    value = next(iter(size.values()))
    if isinstance(value, bool):
        return None
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


def _items(output: str) -> int:
    """How many items an answer holds: a list's length, the longest list of an object, or lines."""
    try:
        parsed = json.loads(output)
    except (ValueError, TypeError, RecursionError):
        parsed = None
    if isinstance(parsed, list):
        return len(parsed)
    if isinstance(parsed, dict):
        lists = [len(v) for v in parsed.values() if isinstance(v, list)]
        if lists:
            return max(lists)
    return sum(1 for line in str(output).splitlines() if line.strip())


def _kept_whole(entry: Any) -> bool:
    """Whether an entry answered and holds its answer as the model read it, unshortened."""
    from maljan.agents.output_shortening import BOOKKEEPING_KEY, our_key_in

    if not getattr(entry, "ok", True) or getattr(entry, "truncated", False):
        return False
    output = str(getattr(entry, "output", "") or "")
    if not output:
        return False
    if BOOKKEEPING_KEY in output:
        try:
            if our_key_in(json.loads(output)):
                return False
        except (ValueError, TypeError, RecursionError):
            pass
    return True


@dataclass(frozen=True)
class LedgerAnswer:
    """What a call is answered with instead of running.

    ``repeat`` is an ask the ledger already answered in this loop: the caller
    counts it as a repeat and says so briefly, without the text again.
    """

    kind: str
    text: str
    entry_id: str
    repeat: bool = False


class LedgerAnswers:
    """One loop's reader of the answers its ledger already holds.

    ``entries`` returns the entries to read, as of now: the analyst's earlier
    loops in this job and this loop's own calls. ``decoders`` are the loop's
    decoding tools, named by the pivot sentence.
    """

    def __init__(
        self,
        entries: Callable[[], Sequence[Any]],
        *,
        decoders: Sequence[str] = (),
        image_bases: Sequence[int] = (),
    ) -> None:
        self._entries = entries
        self._decoders = tuple(decoders)
        self._bases = tuple(image_bases)
        self._told: set[str] = set()
        self._pivot_said = False
        self.counts: dict[str, int] = {}

    def answer(
        self, tool: str, server: str | None, kwargs: Mapping[str, Any]
    ) -> LedgerAnswer | None:
        """The answer for this call from the ledger, or ``None`` when it must run. Never raises."""
        try:
            if _lists_or_searches(tool):
                return self._listing(tool, server, kwargs)
            if _decompiles(tool):
                return self._decompile(tool, server, kwargs)
        except Exception:  # noqa: BLE001 — a reader never costs a call
            return None
        return None

    def _rows(self, server: str | None) -> list[Any]:
        return [
            e
            for e in (self._entries() or [])
            if str(getattr(e, "server", "") or "") == str(server or "")
        ]

    def _told_before(self, key: str) -> bool:
        if key in self._told:
            return True
        self._told.add(key)
        return False

    def _count(self, kind: str) -> None:
        self.counts[kind] = self.counts.get(kind, 0) + 1

    # -- listings -----------------------------------------------------------

    def _listing(
        self, tool: str, server: str | None, kwargs: Mapping[str, Any]
    ) -> LedgerAnswer | None:
        scope, size, position = _split(kwargs)
        asked = _one_number(size)
        for entry in reversed(self._rows(server)):
            if str(getattr(entry, "tool", "") or "") != tool or not _kept_whole(entry):
                continue
            e_scope, e_size, e_position = _split(getattr(entry, "args", None) or {})
            if e_scope != scope:
                continue
            output = str(entry.output)
            entry_id = str(entry.id)
            if e_size == size and e_position == position:
                why = (
                    f"{tool} was not run: this call asks for the same scope as the call "
                    f"recorded in [{entry_id}], so the text above is the answer recorded there."
                )
            else:
                limit = _one_number(e_size)
                held = _items(output)
                whole = limit is not None and held < limit
                if not (whole and _at_start(e_position) and _at_start(position)):
                    continue
                if asked is not None and asked < held:
                    continue
                why = (
                    f"{tool} was not run: the call recorded in [{entry_id}] asked for up to "
                    f"{limit} items and its answer held {held}, so it is the whole listing for "
                    "this scope, and the text above is the answer recorded there."
                )
            key = f"{LISTED_AGAIN}:{tool}:{_key(_normal(kwargs))}"
            if self._told_before(key):
                return LedgerAnswer(LISTED_AGAIN, "", entry_id, repeat=True)
            self._count(LISTED_AGAIN)
            return LedgerAnswer(LISTED_AGAIN, f"[{entry_id}]\n{output}\n\n{why}", entry_id)
        return None

    # -- decompiles ---------------------------------------------------------

    def _decompile(
        self, tool: str, server: str | None, kwargs: Mapping[str, Any]
    ) -> LedgerAnswer | None:
        asked = _entry_functions(SimpleNamespace(args=dict(kwargs), output=""))
        asked = [(address, names) for address, names in asked if address is not None or names]
        if not asked:
            return None
        extras = {k: v for k, v in _normal(kwargs).items() if k not in _FUNCTION_ARGUMENTS}
        rows = [e for e in self._rows(server) if _decompiles(getattr(e, "tool", ""))]
        bases = tuple(dict.fromkeys([*self._bases, *image_bases_in(self._entries() or [])]))
        found: list[tuple[str, str, str]] = []
        for address, names in asked:
            hit = self._recorded_listing(rows, address, names, extras, bases)
            if hit is None:
                return None
            found.append(hit)
        ids = list(dict.fromkeys(entry_id for entry_id, _, _ in found))
        key = f"{DECOMPILED_AGAIN}:" + ",".join(sorted(where for _, where, _ in found))
        if self._told_before(key):
            return LedgerAnswer(DECOMPILED_AGAIN, "", ids[0], repeat=True)
        self._count(DECOMPILED_AGAIN)
        bodies = "\n\n".join(f"[{entry_id}]\n{listing}" for entry_id, _, listing in found)
        cited = ", ".join(f"[{i}]" for i in ids)
        what = f"{found[0][1]} was" if len(found) == 1 else f"these {len(found)} functions were"
        why = (
            f"{tool} was not run: {what} already decompiled in {cited}, and this call gives no "
            "argument the recorded one did not, so the listing above is the one recorded there. "
            "The function map in the run state says what it reaches."
        )
        if not self._pivot_said:
            self._pivot_said = True
            why = f"{why} {pivot_sentence(self._decoders)}"
        return LedgerAnswer(DECOMPILED_AGAIN, f"{bodies}\n\n{why}", ids[0])

    def _recorded_listing(
        self,
        rows: Sequence[Any],
        address: int | None,
        names: Sequence[str],
        extras: Mapping[str, Any],
        bases: Sequence[int],
    ) -> tuple[str, str, str] | None:
        """``(entry id, where, listing)`` of the latest whole listing of this function, or ``None``."""
        for entry in reversed(list(rows)):
            if not _kept_whole(entry):
                continue
            given = _normal(getattr(entry, "args", None) or {})
            if any(given.get(k) != v for k, v in extras.items()):
                continue
            output = str(entry.output)
            held = _entry_functions(entry)
            for e_address, e_names in held:
                same = (
                    address is not None
                    and e_address is not None
                    and _one_function(address, e_address, bases)
                ) or bool(set(names) & set(e_names))
                if not same:
                    continue
                listing = self._listing_of(output, e_address, alone=len(held) == 1)
                if listing is None:
                    break
                where = hex(e_address) if e_address is not None else (names or e_names)[0]
                return str(entry.id), where, listing
        return None

    @staticmethod
    def _listing_of(output: str, address: int | None, *, alone: bool) -> str | None:
        """One function's listing out of an entry: its batch key's text, or the whole answer.

        An answer that is no batch holds one function's listing only when the
        call asked for one function (``alone``).
        """
        shown, listings = _batch_listings(output)
        if not shown:
            if not alone or output.lstrip().lower().startswith("error"):
                return None
            return output
        if address is None or address not in listings:
            return None
        return listings[address]

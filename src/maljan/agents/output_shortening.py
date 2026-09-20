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

What is shortened here is the document. In order: elements come off the end of
its largest lists, largest first; then, if that was not enough, characters come
off the end of its largest long strings, largest first. Lists before strings
because a list has natural units and a string does not, and largest first
because that is where the characters are. No key is ever dropped, so whatever
the answer says about itself — which file it read, how many rows exist, where
the next page starts — survives however long its list was.

**Nothing is written into the tool's vocabulary** but the ``truncated`` flag it
already has. Everything else goes under one reserved key this module owns,
mapping each shortened value's path to what was kept and what was left out, so
a count can be reconciled without guessing which of the answer's own numbers it
should be read against and without a tool's own key being overwritten.

**Cost.** Deciding what to drop is arithmetic: one walk measures every element
and every string, and prefix sums say what a given cut saves. The document is
serialised once at the start, once at the end, and at most twice more to
correct an estimate. A document the shortening cannot help — its keys alone
over the limit — is recognised by one subtraction before any of that work, so
the hopeless case costs a parse rather than minutes of re-serialising.

Two things bound the whole: a size ceiling, because the deadline below cannot
pre-empt the one ``json.loads`` everything depends on and an answer large
enough makes that parse the cost; and, past the parse, a monotonic deadline
checked at every phase and inside the cut loop. The deadline bounds the
deciding, the ceiling bounds the reading.

One document, one reader. The string this returns is what the model reads and
what the recorder stores, with no second shortening in between: a model that
was told a hundred rows exist and a ledger that holds forty would be two
answers to one call.
"""

from __future__ import annotations

import json
import math
import re
import time
import unicodedata
from typing import Any, NamedTuple

__all__ = [
    "BOOKKEEPING_KEY",
    "MAX_SHORTENABLE_CHARS",
    "SHORTENING_BUDGET_SECONDS",
    "Shortening",
    "MAX_NARROWING_NAMES",
    "MAX_SENTENCE_ROOM",
    "narrowing_arguments",
    "our_key_in",
    "shorten_json_document",
    "shorten_target",
    "shortening_sentence",
    "shortening_sentence_room",
]

# The key a sidecar already sets when it paged an answer itself. Reused rather
# than invented: an answer that was shortened twice — once by the tool's own
# page limit and once here — is still one truncated answer.
_TRUNCATED = "truncated"

# Where everything this module has to say about its own work goes. One key, at
# the top level, holding a path for each value it shortened. A tool that
# happens to use the name keeps it and this moves aside (see ``_our_key``).
BOOKKEEPING_KEY = "shortened"

# At most this many paths are named, then one ``others`` row with the totals.
# The bookkeeping must not be the thing that stops a document fitting, and a
# reader who needs more than the thirty-two largest contributors is reading the
# ledger rather than the answer.
_MAX_BOOKKEEPING_ROWS = 32
_OTHERS = "others"

# A string is a payload worth trimming only when it is large enough to be one.
# Below this a string is a path, a label, an id or a message — metadata the
# whole exercise exists to preserve — and cutting it would lose the answer's
# own account of itself to save a few dozen characters.
_MIN_SHORTENABLE_STRING = 512

# The wall this work may not run past. It is CPU-bound, so the ceiling is what
# keeps an input nobody has thought of from costing an analyst its stage
# budget; past it the caller's character cut is the answer and the ledger says
# the clock is why. A second rather than a quarter of one because the largest
# answer measured — a seven-megabyte list of a hundred and fifty thousand rows
# — costs 0.3 s, most of it the one parse nothing can avoid, and a wall that
# refuses the largest legitimate answers would turn this into the regression it
# was written to remove. It runs on a thread, not the event loop.
SHORTENING_BUDGET_SECONDS = 1.0

# Above this an answer is handed straight back. The wall above cannot pre-empt
# the one ``json.loads`` everything else depends on, so what bounds the parse is
# the size of what is parsed: eighteen megabytes of JSON is a second before the
# clock is consulted at all. Well above every answer measured — the largest was
# under eight megabytes — and far enough below the shapes that cost a second
# that the two together are a real bound rather than a stated one.
MAX_SHORTENABLE_CHARS = 12_000_000

# A subtree under this key is never touched. A returned error is the one answer
# whose every field is load-bearing — the code a caller branches on, the
# remediation the model acts on — and it is small, so there is nothing to gain
# and a contract to lose.
_NEVER_TOUCHED = "error"


class Shortening(NamedTuple):
    """What became of one answer: the text, and why it is that text."""

    text: str
    shortened: bool
    timed_out: bool = False


# How many leading units of one value are measured one by one. Beyond it a cut
# is not offered: a list this long against a limit of a few thousand characters
# keeps a small prefix or nothing, and measuring a hundred and fifty thousand
# elements individually is the cost this module exists to avoid. Keeping the
# cap rather than the exact optimum drops a few units more than strictly
# necessary in the one case where the cap binds, which is a case that was
# keeping four thousand of them.
_MEASURED_UNITS = 4096


class _Candidate:
    """One value that could give, and what each unit of it costs.

    ``whole`` is measured for every candidate, because the floor probe needs
    it and it is one serialisation each. The per-unit breakdown is measured
    only for a candidate that is actually going to be cut, which is normally
    one of them: the walk over a document with twenty thousand lists must not
    pay for twenty thousand breakdowns to discover it can help none of them.
    """

    __slots__ = ("holder", "key", "path", "is_list", "value", "whole", "units", "_cumulative")

    def __init__(
        self,
        holder: dict[str, Any],
        key: str,
        path: str,
        *,
        is_list: bool,
        value: Any,
        whole: int,
    ) -> None:
        self.holder = holder
        self.key = key
        self.path = path
        self.is_list = is_list
        self.value = value
        self.whole = whole
        self.units = len(value)
        self._cumulative: list[int] | None = None

    def cumulative(self, separators: tuple[str, str] | None) -> list[int]:
        """Serialised cost of each of the first ``_MEASURED_UNITS`` units."""
        if self._cumulative is None:
            head = self.value[:_MEASURED_UNITS]
            if self.is_list:
                costs = [_cost_of(item, separators) + 1 for item in head]
            else:
                costs = _string_unit_costs(head)
            self._cumulative = _cumulative(costs)
        return self._cumulative

    def cut_points(self, separators: tuple[str, str] | None) -> int:
        """The largest prefix this candidate offers to keep."""
        return min(self.units, len(self.cumulative(separators)) - 1)

    def saving_from(self, kept: int, separators: tuple[str, str] | None) -> int:
        """What keeping ``kept`` units instead of all of them saves."""
        if kept >= self.units:
            return 0
        return self.whole - self.cumulative(separators)[kept]


def _parsed(text: str) -> tuple[Any, bool]:
    """``(document, whether re-serialising it would still mean the same)``.

    One parse, not two: the same pass that reads the document answers the two
    things ``json`` reads but cannot write back — a duplicate key, of which
    only the last survives a round trip, and ``NaN``/``Infinity``, which are
    not JSON at all and which a strict reader downstream would refuse. Either
    one and this module declines, because a shortening is not allowed to be
    how a fact disappears. Everything else round-trips: key order is preserved
    by ``dict``, and a float is re-rendered by ``repr`` from the same double.
    """
    faithful = True

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        nonlocal faithful
        out: dict[str, Any] = {}
        for key, value in items:
            if key in out:
                faithful = False
            out[key] = value
        return out

    def constant(_name: str) -> Any:
        nonlocal faithful
        faithful = False
        return None

    try:
        document = json.loads(text, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, TypeError):
        return None, False
    except RecursionError:
        # A deeply nested answer. Raising here would reach the tool wrapper\'s
        # own catch-all and the model would get a failure marker instead of
        # the prefix the character cut gives it, which is a worse answer than
        # the one this module was written to stop producing.
        return None, False
    return document, faithful


# Above this the separators the tool used are not probed. The probe is a whole
# extra serialisation and what it buys is form rather than meaning; on an
# answer this size the form is the least of what the shortening is deciding.
_SEPARATOR_PROBE_LIMIT = 1_000_000


def _separators(text: str, document: Any) -> tuple[str, str] | None:
    """The separators the tool used, as far as that can be known cheaply.

    A compact answer comes back compact rather than gaining a space per
    element, which on a paged list is hundreds of characters of somebody
    else\'s budget. Anything the two candidates do not explain — an indented
    answer, most often — takes the library default.
    """
    if len(text) > _SEPARATOR_PROBE_LIMIT:
        return None
    compact = (",", ":")
    if len(json.dumps(document, ensure_ascii=False, separators=compact)) == len(text):
        return compact
    return None


def _cost_of(value: Any, separators: tuple[str, str] | None) -> int:
    return len(json.dumps(value, ensure_ascii=False, separators=separators))


def _cumulative(costs: list[int]) -> list[int]:
    out = [0]
    for cost in costs:
        out.append(out[-1] + cost)
    return out


def _string_unit_costs(value: str) -> list[int]:
    """The serialised width of each character of ``value``, in order.

    A character is one to six characters of JSON depending on what it is, so a
    prefix of ``n`` characters is not ``n`` characters of budget. Measured once
    here; every later question about a cut is a lookup.
    """
    encoder = json.JSONEncoder(ensure_ascii=False).encode
    return [len(encoder(char)) - 2 for char in value]


def _walk(document: dict[str, Any], separators: tuple[str, str] | None) -> list[_Candidate]:
    """Every value that could give, with its whole cost, in one pass.

    Depth-first in declaration order, so the result is deterministic. A value
    under ``error`` is skipped whole, and so is anything that is neither a list
    nor a string long enough to be a payload rather than a label.
    """
    found: list[_Candidate] = []

    def visit(node: Any, path: str) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                name = str(key)
                if name == _NEVER_TOUCHED:
                    continue
                here = f"{path}/{_escaped(name)}"
                if isinstance(value, list) and value:
                    found.append(
                        _Candidate(
                            node,
                            name,
                            here,
                            is_list=True,
                            value=value,
                            whole=_cost_of(value, separators) - 2,
                        )
                    )
                elif isinstance(value, str) and len(value) >= _MIN_SHORTENABLE_STRING:
                    found.append(
                        _Candidate(
                            node,
                            name,
                            here,
                            is_list=False,
                            value=value,
                            whole=_cost_of(value, separators) - 2,
                        )
                    )
                visit(value, here)
        elif isinstance(node, list):
            for index, item in enumerate(node):
                visit(item, f"{path}/{index}")

    visit(document, "")
    return found


def _topmost(candidates: list[_Candidate]) -> list[_Candidate]:
    """The candidates no other candidate contains.

    Giving a list entirely gives everything under it, so a floor computed by
    summing every candidate counts a nested list twice — once inside its
    ancestor and once on its own — and reads as though the document could
    shrink further than it can. The walk is depth-first in declaration order,
    so a candidate is nested exactly when another candidate\'s path is a
    prefix of its own.
    """
    out: list[_Candidate] = []
    covered = ""
    for candidate in sorted(candidates, key=lambda c: c.path):
        if covered and candidate.path.startswith(covered):
            continue
        out.append(candidate)
        covered = f"{candidate.path}/"
    return out


def _still_there(document: Any, path: str) -> Any:
    """What ``path`` names in ``document`` now, or ``None``.

    Asked after the cutting, because an ancestor that gave everything took its
    descendants with it: a row describing a value the answer no longer holds
    is a row a reader cannot check, and the whole point of the reserved key is
    that its numbers account for the difference between what came in and what
    goes out.
    """
    node = document
    for raw in path.split("/")[1:]:
        segment = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(node, list):
            if not segment.isdigit() or int(segment) >= len(node):
                return None
            node = node[int(segment)]
        elif isinstance(node, dict):
            if segment not in node:
                return None
            node = node[segment]
        else:
            return None
    return node


def _escaped(name: str) -> str:
    """A path segment in the JSON-pointer spelling, so a key with a slash reads."""
    return name.replace("~", "~0").replace("/", "~1")


def our_key_in(document: Any) -> str:
    """The key this module\'s bookkeeping is under in ``document``, or ``""``.

    The reserved name, or the one it moved aside to when a tool already owned
    it. Everything that has to introduce the map — the sentence the model
    reads, the sentence the report draws, the fields a report must not print
    as facts — asks here, so a fallback name is explained wherever the first
    one is rather than sitting in the answer unannounced.
    """
    if not isinstance(document, dict):
        return ""
    for key, value in document.items():
        if not isinstance(key, str):
            continue
        if key != BOOKKEEPING_KEY and not key.startswith(f"{BOOKKEEPING_KEY}_"):
            continue
        if _is_our_map(value):
            return key
    return ""


# The shape of one row, which is how a map this module wrote is told from a
# tool's own key of the same name: the name can collide, the vocabulary does
# not.
_ROW_WORDS = frozenset({"kept", "omitted", "kept_chars", "omitted_chars", "paths"})


def _is_our_map(value: Any) -> bool:
    if not isinstance(value, dict) or not value:
        return False
    return all(isinstance(row, dict) and row and set(row) <= _ROW_WORDS for row in value.values())


def _our_key(document: dict[str, Any]) -> str:
    """``BOOKKEEPING_KEY``, or the first free name beside it.

    A tool that already uses the name keeps it: this module never overwrites a
    word the tool said. The fallback is deterministic, so two runs of the same
    answer put the bookkeeping under the same name.
    """
    if BOOKKEEPING_KEY not in document:
        return BOOKKEEPING_KEY
    for suffix in range(2, 100):
        candidate = f"{BOOKKEEPING_KEY}_{suffix}"
        if candidate not in document:
            return candidate
    return f"{BOOKKEEPING_KEY}_x"


# The argument names that narrow or page an answer, read off the schema the
# tool offered rather than guessed per tool. Kept as one list because it is one
# question — which of this tool's own arguments reach the part that was left
# out — and because the two places that ask it, the guardrail that reserves
# room for the sentence and the recorder that writes it, must get one answer.
# The built-in sidecars between them offer every name here: ``strings`` pages
# with ``limit``/``offset`` and filters with ``pattern``/``start``/``end``, the
# network tools bound with ``packet_limit``, the knowledge tools with ``k``,
# and ``archive_list``/``apk_info`` with ``limit``.
_NARROWING_NAMES = frozenset(
    {
        "end",
        "filter",
        "k",
        "limit",
        "offset",
        "page",
        "pattern",
        "query",
        "start",
    }
)

# The same question for a name nobody listed: ``packet_limit``, ``max_rows``,
# ``page_size``. A prefix or a suffix is enough, because these name the bound
# rather than the subject. ``_size`` alone is not: ``buffer_size`` and
# ``block_size`` name a machine detail and narrow nothing, so it counts only
# under a name that already reads as a bound.
_NARROWING_PREFIXES = ("max_",)
_NARROWING_SUFFIXES = ("_limit", "_offset", "_page")
_SIZE_SUFFIX = "_size"
_SIZE_PREFIXES = ("page_", "max_")

# A parameter name is a tool server's text, and this sentence goes into the
# model's context. Only a plain identifier is named, and the rest are left out
# rather than escaped or cut: a name this refuses is a name the model cannot
# pass anyway, and a repaired one would be a parameter nobody offers. The
# length is the same bound under another name — an identifier longer than this
# is not one a schema writes.
_PLAIN_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,39}$")
MAX_NARROWING_NAME_CHARS = 40

# How many are named. The sentence is a hint, not a manual: past a handful the
# model is reading a list instead of narrowing a call, and the cap is what
# bounds what a server can spend of the answer's own budget.
MAX_NARROWING_NAMES = 6


def narrowing_arguments(names: Any) -> tuple[str, ...]:
    """The arguments of one tool's schema that narrow or page its answer.

    In the order the schema declared them, so the sentence reads the way the
    tool's own documentation does, and at most :data:`MAX_NARROWING_NAMES` of
    them. A name that is not a plain identifier is not named at all. An empty
    result means the tool offers no way to ask for a smaller answer, which is
    itself worth telling the model.
    """
    found: list[str] = []
    for raw in names or ():
        name = str(raw)
        if not _PLAIN_NAME_RE.match(name):
            continue
        lowered = name.lower()
        sized = lowered.endswith(_SIZE_SUFFIX) and lowered.startswith(_SIZE_PREFIXES)
        if (
            lowered in _NARROWING_NAMES
            or lowered.startswith(_NARROWING_PREFIXES)
            or lowered.endswith(_NARROWING_SUFFIXES)
            or sized
        ):
            found.append(name)
        if len(found) == MAX_NARROWING_NAMES:
            break
    return tuple(found)


def shortening_sentence(narrowing: Any = (), *, key: str = BOOKKEEPING_KEY) -> str:
    """What the model is told about an answer that had to be shortened.

    It names the key the arithmetic is under, says that asking again the same
    way returns the same answer, and names this tool's own arguments that
    reach what was left out. A tool that offers none says so and stops there:
    a hint to "try different arguments" on a tool with nothing to vary is how
    a loop spends its steps re-issuing one call.

    Whatever is passed is filtered again here, so the one place that writes the
    sentence is also the one place that decides what a name may look like.
    """
    named = ", ".join(f"`{name}`" for name in narrowing_arguments(narrowing))
    head = (
        f"\n\nThis answer did not fit and was shortened; `{key}` says which parts were cut "
        "and how much of each is missing. An identical call returns the identical "
        "shortened answer"
    )
    if not named:
        return f"{head}, and this tool takes no argument that narrows or pages it."
    return f"{head}; narrow it with {named}, or call another tool."


# How much longer the sentence can be than the one written with the ordinary
# key: the fallback name a tool that owns ``shortened`` pushes it to is at most
# ``shortened_99``.
_KEY_FALLBACK_ROOM = 3

# The most the sentence can ever cost, and therefore the most a schema can take
# out of the budget its own answer is shortened into. Six names of forty
# characters each is what :func:`narrowing_arguments` will pass at its widest,
# so the sentence written over those, plus the fallback key, is an exact
# ceiling rather than an estimate — about four hundred characters, against a
# limit in the thousands. Without it a server declaring two hundred long
# parameters shrank the target to nothing and every answer it returned was cut
# as text instead of shortened as a document.
_WIDEST_NAME = "max_" + "n" * (MAX_NARROWING_NAME_CHARS - len("max_"))
MAX_SENTENCE_ROOM = (
    len(shortening_sentence((_WIDEST_NAME,) * MAX_NARROWING_NAMES)) + _KEY_FALLBACK_ROOM
)


def shortening_sentence_room(narrowing: Any = ()) -> int:
    """What to keep back so the sentence fits inside the same limit.

    The guardrail shortens to the limit and the recorder appends the sentence
    afterwards, so the room the sentence needs is room the shortening has to
    have already given up. An upper bound: the key it will actually name is
    the ordinary one on every answer but the few that own the name. Never more
    than :data:`MAX_SENTENCE_ROOM`, which the sentence itself cannot exceed.
    """
    return min(len(shortening_sentence(narrowing)) + _KEY_FALLBACK_ROOM, MAX_SENTENCE_ROOM)


def shorten_target(limit: int, narrowing: Any = ()) -> int:
    """The size to shorten an answer to so its notice still fits ``limit``.

    One function for both guardrails — the MCP toolkit's and the HTTP client's
    — because the claim they support is one claim: what the model reads, the
    answer and the sentence appended to it, is inside the limit the operator
    set.
    """
    return max(1, int(limit) - shortening_sentence_room(narrowing))


def _row(candidate: _Candidate, kept: int) -> dict[str, int]:
    dropped = candidate.units - kept
    if candidate.is_list:
        return {"kept": kept, "omitted": dropped}
    return {"kept_chars": kept, "omitted_chars": dropped}


def _bookkeeping(rows: list[tuple[_Candidate, int]]) -> dict[str, Any]:
    """The map, bounded, largest contributor first.

    Bounded because a document with ten thousand shortened lists would
    otherwise answer with ten thousand rows of bookkeeping, which is the
    budget spent on saying what happened to the budget.
    """
    ordered = sorted(rows, key=lambda pair: -(pair[0].units - pair[1]))
    out: dict[str, Any] = {}
    for candidate, kept in ordered[:_MAX_BOOKKEEPING_ROWS]:
        out[candidate.path] = _row(candidate, kept)
    rest = ordered[_MAX_BOOKKEEPING_ROWS:]
    if rest:
        out[_OTHERS] = {
            "paths": len(rest),
            "omitted": sum(c.units - k for c, k in rest if c.is_list),
            "omitted_chars": sum(c.units - k for c, k in rest if not c.is_list),
        }
    return out


def _room_for_bookkeeping(candidates: list[_Candidate], separators: tuple[str, str] | None) -> int:
    """What the bookkeeping and the flag are expected to cost, as an estimate.

    Priced before anything is decided, so the room they need is room the
    arithmetic has already accounted for, and priced over the top-most
    candidates because those are the ones a cut reaches first and the ones a
    descendant\'s row is folded into when its ancestor gives everything.
    Normally an over-estimate — every number is at its widest — and sometimes a
    small under-estimate, when a partial cut of an ancestor leaves room for
    descendants to be recorded as well. Either way the three correction passes
    below absorb it: this decides how much to cut, and the dump decides whether
    that was enough.
    """
    rows = [(candidate, candidate.units) for candidate in _topmost(candidates)]
    block = _bookkeeping(rows)
    # The map, its key, the quotes and separators around it, and the flag.
    return _cost_of(block, separators) + len(BOOKKEEPING_KEY) + 8 + len(_TRUNCATED) + 10


def _keep_for(candidate: _Candidate, must_save: int, separators: tuple[str, str] | None) -> int:
    """The largest prefix of ``candidate`` that saves at least ``must_save``.

    Arithmetic over the prefix sums measured for this one candidate, so it
    costs a binary search over a list of integers rather than a serialisation
    of the whole document per step. Keeping more would not save enough;
    keeping fewer would throw away units nobody had to lose.
    """
    sums = candidate.cumulative(separators)
    low, high = 0, candidate.cut_points(separators)
    best = 0
    while low <= high:
        middle = (low + high) // 2
        if candidate.whole - sums[middle] >= must_save:
            best = middle
            low = middle + 1
        else:
            high = middle - 1
    return best


def _safe_string_cut(value: str, kept: int) -> int:
    """``kept``, backed off so the cut is not between a mark and what it marks.

    A Python string is code points, so a slice cannot split a surrogate pair.
    What it can split is a combining sequence — a letter and its accent — and
    that is cheap to see: step back while the next character is a combining
    mark.
    """
    while 0 < kept < len(value) and unicodedata.combining(value[kept]):
        kept -= 1
    return kept


def shorten_json_document(
    text: str, limit: int, *, budget_seconds: float | None = None
) -> Shortening:
    """One tool answer, made to fit, or handed back for the caller to cut.

    ``shortened`` is false, with the text unchanged, for everything this cannot
    shorten into a document a reader can still parse and reconcile: text that
    is not JSON, a JSON scalar, a bare list (nothing in one can say how many
    elements are missing, so the caller\'s character cut is the honest
    outcome), an answer already inside the limit, a document whose meaning
    would not survive re-serialising, and a document whose keys alone are over
    the limit. ``timed_out`` says the deadline, not the shape, is why.
    """
    deadline = time.monotonic() + (
        SHORTENING_BUDGET_SECONDS if budget_seconds is None else budget_seconds
    )
    if limit <= 0 or len(text) <= limit or len(text) > MAX_SHORTENABLE_CHARS:
        return Shortening(text, False)
    if time.monotonic() >= deadline:
        return Shortening(text, False, True)

    document, faithful = _parsed(text)
    if not faithful or not isinstance(document, dict):
        return Shortening(text, False)
    # An answer this module has already shortened is left alone: a second map
    # would count against a baseline the first one already moved, so the two
    # would be two accounts of one answer and neither would reconcile. Not
    # reachable through a guardrail, which runs once per call, and cheap to be
    # sure of.
    if our_key_in(document):
        return Shortening(text, False)

    separators = _separators(text, document)
    candidates = _walk(document, separators)
    if not candidates:
        return Shortening(text, False)
    if time.monotonic() >= deadline:
        return Shortening(text, False, True)

    # The tool's own text when its form is the one this will write back, which
    # is the common case and saves a serialisation of the whole document.
    base = (
        len(text)
        if separators is not None
        else len(json.dumps(document, ensure_ascii=False, separators=separators))
    )
    room = _room_for_bookkeeping(candidates, separators)
    # Everything that could give, given entirely, against what the document
    # would still weigh: one subtraction, before a single unit is measured.
    # This is the shape that used to run to the end of every list. Only the
    # top-most candidates are summed — a nested list\'s cost is already inside
    # its ancestor\'s, and counting it twice says the document can shrink
    # further than it can.
    if base - sum(candidate.whole for candidate in _topmost(candidates)) + room > limit:
        return Shortening(text, False)

    # Lists before strings, largest first inside each: a list has units the
    # tool chose and a string has only characters, so the one that loses less
    # meaning per character saved goes first.
    order = sorted(candidates, key=lambda c: (not c.is_list, -c.whole, c.path))
    must_save = base + room - limit
    cut: list[tuple[_Candidate, int]] = []
    for candidate in order:
        if must_save <= 0:
            break
        if time.monotonic() >= deadline:
            return Shortening(text, False, True)
        kept = _keep_for(candidate, must_save, separators)
        if not candidate.is_list:
            kept = _safe_string_cut(candidate.value, kept)
        if kept >= candidate.units:
            continue
        candidate.holder[candidate.key] = candidate.value[:kept]
        must_save -= candidate.saving_from(kept, separators)
        cut.append((candidate, kept))

    # A candidate an ancestor\'s cut removed is not something this answer can
    # be asked about, so it is not something the answer claims to have.
    cut = [
        (candidate, kept)
        for candidate, kept in cut
        if _still_there(document, candidate.path) is not None
    ]
    if not cut:
        return Shortening(text, False)

    ours = _our_key(document)
    document[ours] = _bookkeeping(cut)
    if document.get(_TRUNCATED) is not True:
        document[_TRUNCATED] = True

    # One dump, then at most two corrections: ``room`` is an upper bound and
    # the per-unit costs are exact, so the result is normally inside the limit
    # on the first try and never far outside it.
    for _ in range(3):
        result = json.dumps(document, ensure_ascii=False, separators=separators)
        if len(result) <= limit:
            return Shortening(result, True)
        if time.monotonic() >= deadline:
            return Shortening(text, False, True)
        over = len(result) - limit
        shaved = False
        for index, (candidate, kept) in enumerate(cut):
            if kept == 0:
                continue
            fewer = _keep_for(candidate, candidate.saving_from(kept, separators) + over, separators)
            if not candidate.is_list:
                fewer = _safe_string_cut(candidate.value, fewer)
            if fewer >= kept:
                fewer = max(0, kept - max(1, math.ceil(kept / 8)))
            candidate.holder[candidate.key] = candidate.value[:fewer]
            cut[index] = (candidate, fewer)
            shaved = True
            break
        if not shaved:
            return Shortening(text, False)
        document[ours] = _bookkeeping(cut)
    return Shortening(text, False)

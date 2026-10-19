"""How complete one tool answer is, read from the answer itself.

A page of rows read as the whole is how an empty or short page becomes "none":
the agent asked, saw three strings, and wrote that the sample holds three. This
module reads, deterministically, whether an answer is known to be partial, and
the recorder turns that into one line of fixed platform wording under the
answer (:func:`completeness_line`). The run's coverage record
(``analysis.coverage``) takes the same reading of every call
(:attr:`AnswerReading.capped`): an answer the line calls partial or of unknown
extent is never read as whole there, and an answer the line stays silent about
is not capped there either. The governing rule is the coverage record's: never
say "partial" about a complete answer. Where the structure cannot bind a number
to a list, nothing is said.

**Where paging words are read.** In the *paged mappings*: the answer's top
level, and any mapping that holds a list and is not itself inside a list (a
row is data, never a page). Each paged mapping is read together with its
list-free mapping children, which is where an answer keeps its paging block
(``meta``, ``links``, ``pageInfo``, ``pagination`` or any other name: the
shape decides, never the name). A flag is read in any mapping at any depth.

* *Explicit words.* A flag, matched ignoring case and underscores:
  ``truncated``, ``more``, ``has_more``, ``hasNextPage``, ``IsTruncated``. A
  next field: ``next``, ``cursor``, a ``<part>_next_offset``, or a name that
  starts with ``next`` and ends with ``offset``, ``cursor``, ``page``,
  ``token``, ``url``, ``link`` or ``marker`` (``nextCursor``,
  ``next_page_token``, ``NextContinuationToken``). A true flag or a given next
  field says more exists. A paged mapping carrying any of these has said
  whether it is complete, and its counts and pages are not read against it: a
  ``total`` of runs scanned beside the page of runs a filter matched is not a
  missing page.
* *Counts, only where bound.* A count is compared with a list only when the
  structure binds the two: ``total`` (``total_count``, ``totalCount``) when
  the mapping holds exactly one list; ``total_<name>`` or ``<name>_total``
  for the list ``<name>``; a ``totals`` entry for the list of its name. With
  several lists and no binding a count says nothing. A bound count is partial
  only when no way of placing the page makes it the last one: the page starts
  at the mapping's own ``offset`` (``page_offset``, ``skip``, ``start_index``),
  else at the call's ``offset`` argument for the top level, else at page N
  times its size counted from 0 or from 1, else at 0 when no page field is
  given. A last page (offset plus rows shown reaching the count) is complete.
* *Pages.* A page number with a page count is partial only when it is before
  the last whichever way pages are counted (page 0 of 1 is complete). A page
  number with no count, no bound count and no explicit word is a known paged
  shape with a field missing, the one case the line says "unknown".
* *A full page.* A call that passed a bounding argument its tool declares
  (``limit``, ``k``, ``max_…``, ``…_limit``, ``page_size``:
  ``output_shortening.bounding_arguments``) and got back a primary list (the
  answer itself, or the top level's only list) exactly that long, with no
  explicit word, bound count or page field at the top level, has a full page.
* *The platform's cut.* The characters the tool-output guardrail left out of
  the answer (``chars_dropped``, the one number ``analysis.coverage`` reads a
  call as cut by: :func:`platform_cut`), whether it cut the text, summarised it
  or had to leave it out. A JSON answer the platform shortened as a document
  carries its own sentence (``output_shortening.shortening_sentence``): the cut
  is not stated twice, and its counts and top-level ``truncated`` are not read,
  since the shortening may have made them. Where the job keeps a store the
  whole answer is kept beside the entry (``schemas.evidence_spill``); the line
  does not say so, because what the model reads never depends on whether the
  job has a store.

**Malformed numbers.** A count, page, offset or size whose digit count exceeds
the answer's own text length cannot have come from that text: the shape reads
as unknown, the line says nothing of it and the coverage record reads the
answer as of no readable shape.

**Ceiling.** The line is fixed wording, at most a handful of field names of at
most forty characters each (a name that is not a plain identifier is written
``a field``) and its numbers, whose digits never exceed the answer's own length.

Every reading is one pass over the answer.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "AnswerReading",
    "COMPLETENESS_PREFIX",
    "completeness_line",
    "cut_line_room",
    "platform_cut",
    "read_answer",
    "shortened_line_room",
]

# The flags an answer says it holds part of its rows by, lowercase and without
# underscores, so ``has_more``, ``hasMore``, ``IsTruncated`` and
# ``has_next_page`` are one word each.
_FLAG_WORDS = frozenset({"truncated", "more", "hasmore", "hasnextpage", "istruncated"})

# The fields that name where the next page starts: these two, a
# ``<part>_next_offset``, and a ``next…`` name with one of the endings.
_NEXT_WORDS = frozenset({"next", "cursor"})
_NEXT_ENDINGS = ("offset", "cursor", "page", "token", "url", "link", "marker")

# A count of the rows of a mapping's only list.
_TOTAL_WORDS = ("total", "total_count", "totalCount")
_TOTALS = "totals"

# A page number, a page count, where a page starts and how many rows it holds.
_PAGE_WORDS = ("page", "page_number", "current_page", "pageNumber", "currentPage")
_PAGES_WORDS = ("pages", "page_count", "total_pages", "num_pages", "pageCount", "totalPages")
_OFFSET_WORDS = ("offset", "page_offset", "skip", "start_index")
_SIZE_WORDS = ("per_page", "page_size", "pageSize", "perPage", "page_limit", "limit")

# The call argument a page of the top level starts at.
_OFFSET_ARGUMENT = "offset"

# The fixed words every line starts with.
COMPLETENESS_PREFIX = "Completeness: "


def _norm(name: str) -> str:
    return name.lower().replace("_", "")


def _given(value: Any) -> bool:
    """Whether a next field names somewhere to go on from."""
    return value is not None and value is not False and value != "" and value != {} and value != []


def _names_next(name: str) -> bool:
    """Whether ``name`` is a field naming where the next page starts."""
    if name.endswith("_next_offset"):
        return True
    lowered = name.lower()
    if lowered in _NEXT_WORDS:
        return True
    return lowered.startswith("next") and len(lowered) > 4 and lowered.endswith(_NEXT_ENDINGS)


@dataclass
class AnswerReading:
    """What one answer says about how much of its rows it holds.

    Each marker carries whether it stands at the top level (``top``), which is
    what the tool's own paging arguments reach.
    """

    shortened: bool = False
    malformed: bool = False
    flags: list[tuple[str, bool]] = field(default_factory=list)
    nexts: list[tuple[str, bool]] = field(default_factory=list)
    counts: list[tuple[str, int, int, bool]] = field(default_factory=list)
    pages: list[tuple[int, int, bool]] = field(default_factory=list)
    page_unknown: tuple[int, bool] | None = None
    top_rows: int | None = None
    top_said: bool = False

    @property
    def partial(self) -> bool:
        """Whether a marker shows the answer holds part of its rows."""
        return bool(self.flags or self.nexts or self.counts or self.pages)

    @property
    def capped(self) -> bool:
        """The coverage record's question: is the answer known partial or of unknown extent.

        True exactly where the line speaks of the answer's structure, and for a
        document the platform shortened (its own sentence speaks). A malformed
        answer is read by the record as of no readable shape instead.
        """
        if self.malformed:
            return False
        return self.shortened or self.partial or self.page_unknown is not None


class _Reader:
    """One pass over one answer, filling an :class:`AnswerReading`."""

    def __init__(
        self, reading: AnswerReading, args: Mapping[str, Any] | None, text_chars: int | None
    ) -> None:
        self.reading = reading
        self.args = args or {}
        self.text_chars = text_chars

    def count(self, value: Any) -> int | None:
        """``value`` as a count, or ``None``; a count too long for the answer marks it malformed."""
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            return None
        if self.text_chars is not None:
            try:
                digits = len(str(value))
            except ValueError:
                digits = self.text_chars + 1
            if digits > self.text_chars:
                self.reading.malformed = True
                return None
        return value

    def first(self, held: Mapping[str, Any], words: Sequence[str]) -> int | None:
        for word in words:
            if word in held:
                found = self.count(held[word])
                if found is not None:
                    return found
        return None

    def flags(self, node: Mapping[Any, Any], top_scope: bool) -> None:
        from maljan.agents.output_shortening import BOOKKEEPING_KEY

        for key, value in node.items():
            name = str(key)
            if top_scope and name == BOOKKEEPING_KEY:
                self.reading.shortened = True
            elif value is True and _norm(name) in _FLAG_WORDS:
                self.reading.flags.append((name, top_scope))

    def page(self, node: Mapping[Any, Any], top: bool) -> None:
        """One paged mapping, read with its list-free mapping children."""
        from maljan.agents.output_shortening import BOOKKEEPING_KEY

        reading = self.reading
        # Beside the shortening bookkeeping a top-level ``truncated`` may be
        # the platform's own, so it is read neither way, whoever wrote it: the
        # original and the shortened document then read alike.
        ignored = {BOOKKEEPING_KEY}
        if top and reading.shortened:
            ignored.add("truncated")
        lists: dict[str, int] = {}
        scope: dict[str, Any] = {}
        explicit = False
        nexts: list[str] = []
        blocks: list[Mapping[Any, Any]] = [node]
        for key, value in node.items():
            if str(key) in ignored:
                continue
            if isinstance(value, list):
                lists[str(key)] = len(value)
            elif isinstance(value, Mapping) and not any(
                isinstance(inner, list) for inner in value.values()
            ):
                blocks.append(value)
        for block in blocks:
            for key, value in block.items():
                name = str(key)
                if block is node and name in ignored:
                    continue
                if _norm(name) in _FLAG_WORDS and isinstance(value, bool):
                    explicit = True
                elif _names_next(name):
                    explicit = True
                    if _given(value):
                        nexts.append(name)
                else:
                    scope.setdefault(name, value)
        if explicit:
            reading.nexts.extend((name, top) for name in nexts)
            if top:
                reading.top_said = True
            return
        bound: list[tuple[str, int]] = []
        total = self.first(scope, _TOTAL_WORDS)
        if total is not None and len(lists) == 1:
            bound.append((next(iter(lists)), total))
        for key, value in node.items():
            name = str(key)
            if name.startswith("total_"):
                named = name[len("total_") :]
            elif name.endswith("_total"):
                named = name[: -len("_total")]
            else:
                continue
            if named in lists:
                held = self.count(value)
                if held is not None:
                    bound.append((named, held))
        totals = node.get(_TOTALS)
        if isinstance(totals, Mapping):
            for name, raw in totals.items():
                held = self.count(raw)
                if held is not None and str(name) in lists:
                    bound.append((str(name), held))
        page = self.first(scope, _PAGE_WORDS)
        pages = self.first(scope, _PAGES_WORDS)
        offset = self.first(scope, _OFFSET_WORDS)
        if offset is None and top:
            offset = self.count(self.args.get(_OFFSET_ARGUMENT))
        size = self.first(scope, _SIZE_WORDS)
        starts: list[int] | None
        if offset is not None:
            starts = [offset]
        elif page is not None and size is not None:
            starts = [start for start in ((page - 1) * size, page * size) if start >= 0]
        elif page is not None:
            starts = None
        else:
            starts = [0]
        for name, held in dict.fromkeys(bound):
            shown = lists[name]
            last = held <= shown if starts is None else any(s + shown >= held for s in starts)
            if not last:
                reading.counts.append((name, shown, held, top))
        if page is not None:
            if pages is not None:
                if page + 1 < pages:
                    reading.pages.append((page, pages, top))
            elif not bound and reading.page_unknown is None:
                reading.page_unknown = (page, top)
        if top:
            reading.top_rows = next(iter(lists.values())) if len(lists) == 1 else None
            reading.top_said = bool(bound) or page is not None or pages is not None


def read_answer(
    structure: Any,
    *,
    args: Mapping[str, Any] | None = None,
    text_chars: int | None = None,
    platform_shortened: bool = False,
) -> AnswerReading:
    """Every completeness marker in one answer's structure. One pass.

    ``structure`` is the parsed answer (``schemas.evidence.parse_structured``)
    or ``None``; ``args`` the call's arguments (its ``offset`` places a page of
    the top level); ``text_chars`` the length of the answer's text, which no
    number in it can exceed in digits; ``platform_shortened`` says the platform
    shortened the document, for an original read before it was.
    """
    reading = AnswerReading(shortened=platform_shortened)
    reader = _Reader(reading, args, text_chars)
    if isinstance(structure, list | tuple):
        reading.top_rows = len(structure)
    # (node, top, top scope's parent, inside a list)
    stack: list[tuple[Any, bool, bool, bool]] = [(structure, True, False, False)]
    while stack:
        node, top, parent_top, in_list = stack.pop()
        if isinstance(node, Mapping):
            holds_list = any(isinstance(value, list) for value in node.values())
            reader.flags(node, top or (parent_top and not holds_list))
            if top or (holds_list and not in_list):
                reader.page(node, top)
            for value in node.values():
                if isinstance(value, Mapping):
                    stack.append((value, False, top, in_list))
                elif isinstance(value, list | tuple):
                    stack.append((value, False, False, True))
        elif isinstance(node, list | tuple):
            stack.extend(
                (value, False, False, True)
                for value in node
                if isinstance(value, Mapping | list | tuple)
            )
    return reading


def platform_cut(entry: Any) -> int:
    """The characters the platform's guardrail left out of an entry's answer; ``0`` for none.

    The one number both readers take a call to be cut by: the coverage record
    (``analysis.coverage``) and the line under the answer (:func:`completeness_line`).
    """
    raw = (
        entry.get("chars_dropped")
        if isinstance(entry, Mapping)
        else getattr(entry, "chars_dropped", 0)
    )
    try:
        return max(0, int(raw or 0))
    except (TypeError, ValueError):
        return 0


def _quoted(name: str) -> str:
    """A field name an answer used, as the line quotes it, or ``a field``.

    Only a plain identifier is named (``output_shortening.is_plain_name``), and
    it is written escaped (``utils.written_forms.pack_escaped``).
    """
    from maljan.agents.output_shortening import is_plain_name
    from maljan.utils.written_forms import pack_escaped

    if not is_plain_name(name):
        return "a field"
    return f'"{pack_escaped(name, delimiters=True)}"'


def _named(names: Sequence[str]) -> str:
    """The distinct names, the first quoted and the rest counted."""
    distinct = list(dict.fromkeys(names))
    said = _quoted(distinct[0])
    if len(distinct) > 1:
        said += f" and {len(distinct) - 1:,} more"
    return said


def _bounded(
    reading: AnswerReading, args: Mapping[str, Any] | None, bounds: Sequence[str]
) -> tuple[str, int] | None:
    """The bounding argument a call passed whose limit the primary list filled, if any."""
    if (
        not args
        or not bounds
        or reading.shortened
        or reading.top_said
        or reading.partial
        or reading.page_unknown is not None
        or not reading.top_rows
    ):
        return None
    for name in bounds:
        value = args.get(name)
        if isinstance(value, int) and not isinstance(value, bool) and value == reading.top_rows:
            return name, value
    return None


def _parts(
    reading: AnswerReading, bounded: tuple[str, int] | None, cut: int
) -> tuple[list[str], bool]:
    """The fixed-wording clauses of one line, in order, and whether the top level is meant."""
    parts: list[str] = []
    top = False
    if cut and not reading.shortened:
        parts.append(
            f"the platform left out {cut:,} characters of this answer to fit the room for "
            "a tool answer"
        )
        top = True
    if reading.malformed:
        return parts, top
    # Beside the shortening bookkeeping, the top-level ``truncated`` and the
    # counts may be the platform's own (``output_shortening``), and its
    # sentence already says what was cut.
    flags = [
        (name, at)
        for name, at in reading.flags
        if not (reading.shortened and at and name == "truncated")
    ]
    if flags:
        parts.append(f"the answer says it holds part of its rows ({_named([n for n, _ in flags])})")
        top = top or any(at for _, at in flags)
    if reading.nexts:
        names = [name for name, _ in reading.nexts]
        parts.append(f"the answer names where the next page starts ({_named(names)})")
        top = top or any(at for _, at in reading.nexts)
    counts = [] if reading.shortened else reading.counts
    if counts:
        name, shown, total, _ = counts[0]
        said = f"{_quoted(name)} shows {shown:,} of {total:,}"
        if len(counts) > 1:
            said += f" (and {len(counts) - 1:,} more lists cut the same way)"
        parts.append(said)
        top = top or any(row[3] for row in counts)
    if reading.pages:
        page, pages, _ = reading.pages[0]
        parts.append(f"this is page {page:,} of {pages:,}")
        top = top or any(row[2] for row in reading.pages)
    if reading.page_unknown is not None:
        page, at = reading.page_unknown
        parts.append(f"this is page {page:,} and the answer does not say how many pages exist")
        top = top or at
    if bounded is not None:
        name, value = bounded
        parts.append(
            f"it holds as many rows as `{name}` allowed ({value:,}) and does not say whether "
            "more exist"
        )
        top = True
    return parts, top


def completeness_line(
    structure: Any,
    *,
    narrowing: Sequence[str] = (),
    bounds: Sequence[str] = (),
    args: Mapping[str, Any] | None = None,
    cut: int = 0,
    text_chars: int | None = None,
    platform_shortened: bool = False,
) -> str:
    """The one line an agent reads under an answer known to be partial, or ``""``.

    ``structure`` is the answer as the model reads it, parsed (or the original
    a shortened document was cut from, with ``platform_shortened``);
    ``narrowing`` the narrowing arguments of the tool that made the answer, of
    which only those that page it are named (``output_shortening.paging_arguments``),
    and only where the partial part is the top level they page; ``bounds``
    those that bound how many rows come back; ``args`` the call's arguments;
    ``cut`` the characters the platform left out (:func:`platform_cut`);
    ``text_chars`` the answer's text length. The wording is the platform's; a
    field name the answer used is quoted escaped.
    """
    from maljan.agents.output_shortening import paging_arguments

    reading = read_answer(
        structure, args=args, text_chars=text_chars, platform_shortened=platform_shortened
    )
    parts, top = _parts(reading, _bounded(reading, args, bounds), int(cut or 0))
    if not parts:
        return ""
    paging = paging_arguments(narrowing)
    named = ", ".join(f"`{name}`" for name in paging)
    if not paging:
        how = "this tool takes no argument that pages it"
    elif top:
        how = f"read further with {named}"
    else:
        how = "no argument of this tool pages that part"
    return (
        f"\n\n{COMPLETENESS_PREFIX}" + "; ".join(parts) + ". Anything not shown here is unknown, "
        f"not absent; {how}."
    )


def cut_line_room(chars_in: int, narrowing: Sequence[str] = ()) -> int:
    """The room the line under a text-cut or summarised answer of ``chars_in`` characters takes.

    Both guardrails (the MCP toolkit's and the Ghidra HTTP client's) keep it
    back when they cut an answer as text, and charge it beside a summary, so
    the answer and the line the recorder appends together are inside the limit
    in force. A cut never exceeds the answer, so the line written over
    ``chars_in`` is an upper bound; a text cut or a summary has no structure,
    so the cut is all the line says of it.
    """
    return len(completeness_line(None, narrowing=narrowing, cut=max(1, int(chars_in))))


def shortened_line_room(output: str, narrowing: Sequence[str] = ()) -> int:
    """The room the line under ``output`` takes once the platform shortens it as a document.

    Read off the original: shortening drops no key and keeps every scalar a
    paging word holds, and under a shortened document the line reads neither
    the cut, nor the counts, nor the top-level ``truncated``, so the line over
    the original is the line over what the shortening leaves. Both guardrails
    keep it back from the shortening's target. ``0`` for an answer that does
    not parse, or one too large to be shortened at all
    (``output_shortening.MAX_SHORTENABLE_CHARS``).
    """
    from maljan.agents.output_shortening import MAX_SHORTENABLE_CHARS
    from maljan.schemas.evidence import parse_structured

    if len(output) > MAX_SHORTENABLE_CHARS:
        return 0
    try:
        structure = parse_structured(output)
    except (RecursionError, ValueError):
        return 0
    if structure is None:
        return 0
    return len(
        completeness_line(
            structure, narrowing=narrowing, text_chars=len(output), platform_shortened=True
        )
    )

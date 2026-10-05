"""The repeated-claims check read as an answer streams: the same verdict, a flat cost, bounded state.

The check on a finished answer is ``pipeline.validation.claims_repeated`` over
the answer without its tool-call scaffolding
(``base_agent.strip_tool_call_scaffolding``). Reading it again over the whole
answer at every line costs the square of the answer's length: about 13 s of
CPU for a 130,000-character answer and about 40 minutes for 1.57 million, on
the loop every analyst shares. :class:`ClaimRepeatReader` keeps what that check
would compute as the answer arrives and gives the same verdict for every prefix
of it, at a cost per line that does not grow with what came before.

Nothing it keeps grows with the text it has read, except what the verdict
itself needs: one 16-byte hash per distinct claim.

* **Claims** (``claim_headings.claim_blocks``). A claim's key — its block's
  words with marks, case and spacing set aside and its trailing ``.``, ``;``
  and ``:`` trimmed (``claim_headings._block_key``) — is never held as text: it
  is hashed as its characters arrive (:class:`_Key`), and a closed claim is
  kept as its hash in a set. What decides the verdict is the number of claims
  begun and the number of distinct hashes.
* **Lines.** A line's part in a block — a claim's heading, a field line, a
  ``---`` separator, a DISPUTES label, prose or blank — is read by automata
  built from the heading patterns themselves (:data:`_HEAD` and the rest),
  one character at a time while it is undecided, and its text goes straight
  into the hashes. No line is buffered, however long. The check trims the
  text's ends once the strip removed anything; that changes only how the first
  and the last line that hold anything are read, so each line keeps the
  automata states that answer for its trimmed reading too, and the last such
  line is applied once the next one begins.
* **Scaffolding.** A tool-call block or a fenced JSON block that has begun and
  not resolved is held back; everything before the earliest such opening is
  final, because no later text can make a match that reaches back over it. A
  tool-call block that has opened is dropped as it arrives; only the few
  characters that may begin its closing tag are kept. A fenced JSON object
  whose fence has not closed, and a tool-call tag still waiting for its ``>``,
  are held until they resolve, because whether the check removes them depends
  on their whole text.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from functools import lru_cache
from typing import Any

__all__ = ["ClaimRepeatReader", "RepeatCount"]

# ---------------------------------------------------------------------------
# Characters, read exactly as the check's patterns and string methods read them
# ---------------------------------------------------------------------------

_LINE_END = re.compile("\r\n|[\n\r\x0b\x0c\x1c\x1d\x1e\x85  ]")
_LINE_END_CHARS = frozenset("\n\r\x0b\x0c\x1c\x1d\x1e\x85  ")
_MARKS = re.compile(r"[*_`#>]")
_TOKENS = re.compile(r"\s+|\S+")
_TRIMMED = " .;:"
# A run of the characters a key's end is trimmed of goes into the hash as its
# own characters while it is short, and as its hash once it is longer than this:
# fixed by the encoding, so one key always hashes the same way, and it keeps
# what a run holds bounded however long the run.
_SHORT_RUN = 32
_LONG_RUN = re.compile(f"[ .;:]{{{_SHORT_RUN + 1},}}")
_TRIM_RUNS = re.compile(r"[ .;:]+|[^ .;:]+")


def _escaped(text: str) -> bytes:
    return text.encode("utf-8", "surrogatepass").replace(b"\x00", b"\x00\x00")


def _char_test(pattern: str, flags: int = 0) -> Callable[[str], bool]:
    compiled = re.compile(pattern, flags)

    @lru_cache(maxsize=4096)
    def _test(ch: str) -> bool:
        return compiled.fullmatch(ch) is not None

    return _test


_SPACE = _char_test(r"\s")
_WORD = _char_test(r"\w")
_DIGIT = _char_test(r"\d")


@lru_cache(maxsize=4096)
def _cased(ch: str) -> bool:
    """Whether ``ch`` is cased and not case-ignorable, as ``str.lower`` reads it for a sigma."""
    return ("AΣ" + ch).lower()[1] == "σ"


@lru_cache(maxsize=4096)
def _case_ignorable(ch: str) -> bool:
    """Whether ``str.lower`` skips ``ch`` when it decides a capital sigma is final."""
    return ("AΣ" + ch + "B").lower()[1] == "σ" and not _cased(ch)


# ---------------------------------------------------------------------------
# A claim's key, hashed as it arrives
# ---------------------------------------------------------------------------


class _Key:
    """One claim block's key (``claim_headings._block_key``), kept as a running hash.

    The key is the block's text with marks turned into spaces, lowercased,
    split into words, joined by single spaces, and trimmed of trailing spaces,
    dots, semicolons and colons. It is hashed as it is produced. A run of those
    four characters is held back until a character after it says it does not
    end the key; it goes in as its own characters while it is short and as its
    hash, after a mark, once it is longer than ``_SHORT_RUN``, so what is held
    stays bounded. Everything else goes in as its UTF-8 bytes, a NUL doubled so
    the mark is never ambiguous.
    Lowercasing is ``str.lower``'s own, character by character; the one
    character whose lowercase depends on what follows it, a capital sigma at
    the end of a word, is resolved by keeping both readings until the next
    character that is not case-ignorable says which one holds.
    """

    __slots__ = ("_cased", "_final", "_main", "_run", "_run_hash", "_space", "_started")

    def __init__(self) -> None:
        self._main = hashlib.blake2b(digest_size=16)
        # The run held back: its characters while short, its hash once long.
        self._run = ""
        self._run_hash: Any = None
        self._started = False
        self._space = False
        self._cased = False
        # The reading with the pending capital sigma as final, while it waits.
        self._final: _Key | None = None

    def copy(self) -> _Key:
        twin = _Key.__new__(_Key)
        twin._main = self._main.copy()
        twin._run = self._run
        twin._run_hash = None if self._run_hash is None else self._run_hash.copy()
        twin._started = self._started
        twin._space = self._space
        twin._cased = self._cased
        twin._final = None if self._final is None else self._final.copy()
        return twin

    def _adopt(self, other: _Key) -> None:
        self._main, self._run, self._run_hash = other._main, other._run, other._run_hash
        self._started, self._space, self._cased = other._started, other._space, other._cased

    def _extend_run(self, run: str) -> None:
        if not run:
            return
        if self._run_hash is not None:
            self._run_hash.update(run.encode("ascii"))
            return
        self._run += run
        if len(self._run) > _SHORT_RUN:
            self._run_hash = hashlib.blake2b(self._run.encode("ascii"), digest_size=16)
            self._run = ""

    def _flush_run(self) -> None:
        if self._run_hash is not None:
            self._main.update(b"\x00\x01" + self._run_hash.digest())
            self._run_hash = None
        elif self._run:
            self._main.update(self._run.encode("ascii"))
            self._run = ""

    def _put(self, text: str) -> None:
        """Add a stretch of the key's own text: words and the single spaces between them."""
        body = text.rstrip(_TRIMMED)
        tail = text[len(body) :]
        if body:
            lead = len(body) - len(body.lstrip(_TRIMMED))
            self._extend_run(body[:lead])
            body = body[lead:]
            self._flush_run()
            if _LONG_RUN.search(body) is None:
                self._main.update(_escaped(body))
            else:
                for match in _TRIM_RUNS.finditer(body):
                    piece = match.group()
                    if piece[0] in _TRIMMED:
                        self._extend_run(piece)
                    else:
                        self._flush_run()
                        self._main.update(_escaped(piece))
        self._extend_run(tail)

    def _word(self, text: str) -> None:
        if self._space:
            self._put(" ")
            self._space = False
        self._put(text)
        self._started = True

    def feed(self, text: str) -> None:
        """Add ``text`` to the block, as the block's own text (marks still in it)."""
        if not text:
            return
        text = _MARKS.sub(" ", text)
        if self._final is None and "Σ" not in text:
            lowered = text.lower()
            words = lowered.split()
            if words:
                joined = " ".join(words)
                if self._started and (self._space or lowered[0].isspace()):
                    joined = " " + joined
                self._space = lowered[-1].isspace()
                self._started = True
                self._put(joined)
            elif self._started:
                self._space = True
            for ch in reversed(text):
                if not _case_ignorable(ch):
                    self._cased = _cased(ch)
                    break
            return
        for ch in text:
            self._char(ch)

    def _char(self, ch: str) -> None:
        final = self._final
        if final is not None:
            if _case_ignorable(ch):
                final._plain(ch)
                self._plain(ch)
                return
            if not _cased(ch):
                self._adopt(final)
            self._final = None
        self._plain(ch)

    def _plain(self, ch: str) -> None:
        if ch.isspace():
            if self._started:
                self._space = True
            self._cased = False
            return
        if ch == "Σ" and self._cased:
            final = self.copy()
            final._word("ς")
            self._word("σ")
            self._final = final
            return
        self._word(ch.lower())
        if not _case_ignorable(ch):
            self._cased = _cased(ch)

    def digest(self) -> bytes:
        if self._final is not None:
            return self._final.digest()
        return self._main.copy().digest()


# ---------------------------------------------------------------------------
# The heading patterns as automata
# ---------------------------------------------------------------------------


class _Automaton:
    """A pattern compiled to states, read one character at a time; a state set is immutable."""

    def __init__(self, tree: Any) -> None:
        self.edges: list[list[tuple[Callable[[str], bool], int]]] = []
        self.empty: list[list[int]] = []
        start, self.accept = self._build(tree)
        self.start = self._closure({start})

    def _state(self) -> int:
        self.edges.append([])
        self.empty.append([])
        return len(self.edges) - 1

    def _build(self, tree: Any) -> tuple[int, int]:
        kind = tree[0]
        if kind == "char":
            begin, end = self._state(), self._state()
            self.edges[begin].append((tree[1], end))
            return begin, end
        if kind in ("seq", "alt"):
            parts = [self._build(part) for part in tree[1]]
            if kind == "seq":
                for (_b, end), (begin, _e) in zip(parts, parts[1:], strict=False):
                    self.empty[end].append(begin)
                return parts[0][0], parts[-1][1]
            begin, end = self._state(), self._state()
            for part_begin, part_end in parts:
                self.empty[begin].append(part_begin)
                self.empty[part_end].append(end)
            return begin, end
        inner_begin, inner_end = self._build(tree[1])
        begin, end = self._state(), self._state()
        self.empty[begin].append(inner_begin)
        self.empty[inner_end].append(end)
        if kind in ("star", "opt"):
            self.empty[begin].append(end)
        if kind in ("star", "plus"):
            self.empty[inner_end].append(inner_begin)
        return begin, end

    def _closure(self, states: set[int]) -> frozenset[int]:
        stack = list(states)
        seen = set(states)
        while stack:
            for target in self.empty[stack.pop()]:
                if target not in seen:
                    seen.add(target)
                    stack.append(target)
        return frozenset(seen)

    def step(self, states: frozenset[int], ch: str) -> frozenset[int]:
        moved = {target for state in states for test, target in self.edges[state] if test(ch)}
        return self._closure(moved) if moved else frozenset()


def _one(ch: str, flags: int = 0) -> tuple[str, Callable[[str], bool]]:
    if flags:
        return ("char", _char_test(re.escape(ch), flags))
    return ("char", lambda c, want=ch: c == want)


def _word(text: str, flags: int = 0) -> tuple[str, list[Any]]:
    return ("seq", [_one(ch, flags) for ch in text])


def _among(chars: str) -> tuple[str, Callable[[str], bool]]:
    allowed = frozenset(chars)
    return ("char", lambda c: c in allowed)


def _seq(*parts: Any) -> tuple[str, list[Any]]:
    return ("seq", list(parts))


def _star(part: Any) -> tuple[str, Any]:
    return ("star", part)


def _opt(part: Any) -> tuple[str, Any]:
    return ("opt", part)


_SPACE_OR_TAB = _among(" \t")
_LINE_PREFIX = _seq(
    _star(_among(" \t>*_#")),
    _opt(
        _seq(
            ("alt", [_among("-+"), _seq(("plus", ("char", _DIGIT)), _among(".)"))]),
            ("plus", _SPACE_OR_TAB),
        )
    ),
    _star(_among(" \t>*_#")),
)
_STARS = _opt(_seq(_one("*"), _one("*")))

# ``claim_headings.CLAIM_HEAD_RE`` up to its delimiter. ``-(?=\s)`` reads the
# whitespace after the dash too: the heading's text after the delimiter is
# read as words, and that whitespace adds none.
_HEAD = _Automaton(
    _seq(
        _LINE_PREFIX,
        _word("CLAIM"),
        _opt(_seq(_star(_SPACE_OR_TAB), _opt(_one("#")), ("plus", ("char", _DIGIT)))),
        _opt(
            _seq(
                _star(_SPACE_OR_TAB),
                _one("("),
                _star(("char", lambda c: c not in ")\n")),
                _one(")"),
            )
        ),
        _star(_SPACE_OR_TAB),
        _STARS,
        _star(_SPACE_OR_TAB),
        ("alt", [_one(":"), _one("—"), _one("–"), _seq(_one("-"), ("char", _SPACE))]),
    )
)
# ``claim_headings._SEPARATOR_RE``, read to the end of the line.
_SEPARATOR = _Automaton(
    _seq(_star(_SPACE_OR_TAB), _one("-"), _one("-"), ("plus", _one("-")), _star(_SPACE_OR_TAB))
)
# ``claim_headings._FIELD_LABEL_RE`` up to its ``\b``.
_FIELD = _Automaton(
    _seq(
        _LINE_PREFIX,
        (
            "alt",
            [
                _word(name, re.IGNORECASE)
                for name in ("EVIDENCE", "CONFIDENCE", "TECHNIQUE", "DISSENT")
            ],
        ),
    )
)
# The two forms of ``claim_headings._DISPUTES_LABEL_RE``, up to where their rest begins.
_DISPUTES_LABEL = _Automaton(
    _seq(
        _LINE_PREFIX,
        _word("DISPUTES"),
        _star(_SPACE_OR_TAB),
        _STARS,
        _star(_SPACE_OR_TAB),
        _one(":"),
    )
)
_DISPUTES_HEADING = _Automaton(
    _seq(
        ("plus", _one("#")),
        _star(_SPACE_OR_TAB),
        _star(_one("*")),
        _star(_SPACE_OR_TAB),
        _word("DISPUTES"),
    )
)
# The rests ``claim_headings._opens_disputes`` reads as saying there is no
# dispute: what its strips leave of the rest is ``NONE``, ``N/A`` or a dash,
# in any case. Its strips, in order: whitespace from both ends, colons from the
# start, ``*``, ``_``, backtick and space from both ends, dots from the end,
# whitespace from both ends; so what they remove is whitespace, colons, those
# marks and whitespace before what is left, and whitespace, dots, those marks
# and whitespace after it.
_SPACES = _star(("char", _SPACE))
_STRIPPED_MARKS = _star(_among("*_` "))
_NO_DISPUTE = _Automaton(
    _seq(
        _SPACES,
        _star(_one(":")),
        _STRIPPED_MARKS,
        _SPACES,
        (
            "alt",
            [
                _seq(_among("nN"), _among("oO"), _among("nN"), _among("eE")),
                _seq(_among("nN"), _one("/"), _among("aA")),
                _one("—"),
                _one("–"),
                _one("-"),
            ],
        ),
        _SPACES,
        _star(_one(".")),
        _STRIPPED_MARKS,
        _SPACES,
    )
)


class _Reading:
    """How one line reads so far, under every heading pattern; immutable, so a state can be kept."""

    __slots__ = (
        "_field",
        "_field_open",
        "_field_wait",
        "_head",
        "_label",
        "_label_rest",
        "_section",
        "_section_rest",
        "_section_wait",
        "_separator",
        "heading_at_delimiter",
        "heading",
    )

    def __init__(self) -> None:
        self._head: frozenset[int] = _HEAD.start
        self.heading = False
        # Set on the character that completed the heading's delimiter only.
        self.heading_at_delimiter = False
        self._separator: frozenset[int] = _SEPARATOR.start
        self._field: frozenset[int] = _FIELD.start
        self._field_wait = False
        self._field_open: bool | None = None
        self._label: frozenset[int] = _DISPUTES_LABEL.start
        self._label_rest: frozenset[int] | None = None
        self._section: frozenset[int] = _DISPUTES_HEADING.start
        self._section_wait = False
        self._section_rest: frozenset[int] | None = None

    def _copy(self) -> _Reading:
        twin = _Reading.__new__(_Reading)
        twin._head, twin.heading = self._head, self.heading
        twin.heading_at_delimiter = self.heading_at_delimiter
        twin._separator = self._separator
        twin._field, twin._field_wait = self._field, self._field_wait
        twin._field_open = self._field_open
        twin._label, twin._label_rest = self._label, self._label_rest
        twin._section, twin._section_wait = self._section, self._section_wait
        twin._section_rest = self._section_rest
        return twin

    @property
    def decided(self) -> bool:
        """Whether no further character of the line can change how it reads."""
        # A DISPUTES label first: its form with the colon wins over the other.
        if self._label_rest is not None:
            # Its rest can no longer say "none": the section opens.
            return not self._label_rest
        if self._label or self._section_wait:
            return False
        if self._section_rest is not None:
            return not self._section_rest
        if self._section:
            return False
        return (
            (self.heading or not self._head)
            and not self._separator
            and not self._field_wait
            and (self._field_open is not None or not self._field)
        )

    def step(self, ch: str) -> _Reading:
        new = self._copy()
        new.heading_at_delimiter = False
        if not new.heading and new._head:
            new._head = _HEAD.step(new._head, ch)
            if _HEAD.accept in new._head:
                new.heading = True
                new.heading_at_delimiter = True
                new._head = frozenset()
        if new._separator:
            new._separator = _SEPARATOR.step(new._separator, ch)
        if new._field_wait:
            new._field_wait = False
            new._field_open = not _WORD(ch)
        elif new._field_open is None and new._field:
            new._field = _FIELD.step(new._field, ch)
            if _FIELD.accept in new._field:
                new._field_wait = True
                new._field = frozenset()
        if new._label_rest is not None:
            if new._label_rest:
                new._label_rest = _NO_DISPUTE.step(new._label_rest, ch)
        elif new._label:
            new._label = _DISPUTES_LABEL.step(new._label, ch)
            if _DISPUTES_LABEL.accept in new._label:
                new._label = frozenset()
                new._label_rest = _NO_DISPUTE.start
        if new._section_wait:
            new._section_wait = False
            if not _WORD(ch):
                new._section_rest = _NO_DISPUTE.step(_NO_DISPUTE.start, ch)
        elif new._section_rest is not None:
            if new._section_rest:
                new._section_rest = _NO_DISPUTE.step(new._section_rest, ch)
        elif new._section:
            new._section = _DISPUTES_HEADING.step(new._section, ch)
            if _DISPUTES_HEADING.accept in new._section:
                new._section = frozenset()
                new._section_wait = True
        return new

    def role(self, nonblank: bool) -> str:
        """What the line is, had it ended here; ``nonblank`` is whether it holds anything."""
        if self._label_rest is not None:
            opens = _NO_DISPUTE.accept not in self._label_rest
        elif self._section_wait:
            opens = True
        elif self._section_rest is not None:
            opens = _NO_DISPUTE.accept not in self._section_rest
        else:
            opens = False
        if opens:
            return "disputes"
        if self.heading:
            return "heading"
        if _SEPARATOR.accept in self._separator:
            return "separator"
        if self._field_open or self._field_wait:
            return "field"
        return "other" if nonblank else "blank"


# ---------------------------------------------------------------------------
# The claims of the lines applied so far
# ---------------------------------------------------------------------------


class _Seen:
    """The hashes of the closed claims; a peek adds its own over its base's, which it never changes."""

    __slots__ = ("_base", "_own")

    def __init__(self, base: _Seen | None = None) -> None:
        self._base = base
        self._own: set[bytes] = set()

    def __contains__(self, digest: bytes) -> bool:
        return digest in self._own or (self._base is not None and digest in self._base)

    def add(self, digest: bytes) -> None:
        if digest not in self:
            self._own.add(digest)

    def __len__(self) -> int:
        return len(self._own) + (len(self._base) if self._base is not None else 0)


class _Claims:
    """``claim_blocks`` over the lines applied so far: claims begun, closed hashes, the open block."""

    __slots__ = ("begun", "disputes", "fields", "open", "seen")

    def __init__(self, seen: _Seen | None = None) -> None:
        self.seen = seen if seen is not None else _Seen()
        self.begun = 0
        self.open: _Key | None = None
        self.fields = False
        self.disputes = False

    def peek(self) -> _Claims:
        view = _Claims(_Seen(self.seen))
        view.begun, view.fields, view.disputes = self.begun, self.fields, self.disputes
        view.open = None if self.open is None else self.open.copy()
        return view

    def fork(self) -> _Claims:
        twin = _Claims()
        twin.seen._own = set(self.seen._own)
        twin.begun, twin.fields, twin.disputes = self.begun, self.fields, self.disputes
        twin.open = None if self.open is None else self.open.copy()
        return twin

    def _close(self) -> None:
        if self.open is not None:
            self.seen.add(self.open.digest())
            self.begun += 1
            self.open = None

    def apply(self, role: str, continued: _Key | None, heading: _Key | None) -> None:
        if self.disputes:
            return
        if role == "disputes":
            self.disputes = True
        elif role == "heading":
            self._close()
            self.open = heading if heading is not None else _Key()
            self.fields = False
        elif role == "separator":
            self._close()
        elif self.open is None or role == "blank":
            return
        elif role == "field":
            self.fields = True
            self.open = continued
        elif self.fields:
            self._close()
        else:
            self.open = continued

    def count(self, margin: int | None) -> RepeatCount:
        begun = self.begun
        distinct = len(self.seen)
        if self.open is not None:
            begun += 1
            if self.open.digest() not in self.seen:
                distinct += 1
        allowed = distinct if margin is None else max(0, int(margin))
        return RepeatCount(begun, distinct, allowed)


class RepeatCount:
    """What the claims of an answer say: begun, distinct, and the margin they are held to."""

    __slots__ = ("begun", "distinct", "margin")

    def __init__(self, begun: int, distinct: int, margin: int) -> None:
        self.begun = begun
        self.distinct = distinct
        self.margin = margin

    @property
    def repeated(self) -> int:
        return self.begun - self.distinct

    @property
    def crossed(self) -> bool:
        return self.repeated > self.margin


# ---------------------------------------------------------------------------
# One line, read as it arrives
# ---------------------------------------------------------------------------

# The readings a line keeps: as written, and with its leading whitespace
# trimmed (only while it may be the first line that holds anything).
_PLAIN, _TRIMMED_START = "plain", "start"


class _Line:
    """One line: its readings, its readings as they stood at its last non-space character,
    and the hashes of its text as each reading would take it."""

    __slots__ = ("continued", "decided_late", "headings", "last", "readings", "started")

    def __init__(self, first: bool) -> None:
        self.readings: dict[str, _Reading] = {_PLAIN: _Reading()}
        if first:
            self.readings[_TRIMMED_START] = _Reading()
        # Each reading as it stood after the line's last non-space character.
        self.last: dict[str, _Reading] = dict(self.readings)
        # Whether a non-space character came after the reading was decided:
        # trimming the line's end then cannot change it.
        self.decided_late: dict[str, bool] = dict.fromkeys(self.readings, False)
        self.headings: dict[str, _Key] = {}
        # The open block of each claims machine with this line added, from its
        # first non-space character on.
        self.continued: list[_Key | None] | None = None
        self.started = False

    def copy(self) -> _Line:
        twin = _Line.__new__(_Line)
        twin.readings = dict(self.readings)
        twin.last = dict(self.last)
        twin.decided_late = dict(self.decided_late)
        twin.headings = {name: key.copy() for name, key in self.headings.items()}
        twin.continued = (
            None
            if self.continued is None
            else [None if key is None else key.copy() for key in self.continued]
        )
        twin.started = self.started
        return twin

    @property
    def decided(self) -> bool:
        return all(
            reading.decided and (self.decided_late[name] or self.last[name] is reading)
            for name, reading in self.readings.items()
        )

    def roles(self, trim_end: bool) -> dict[str, str]:
        out = {}
        for name, reading in self.readings.items():
            if trim_end and not self.decided_late[name]:
                out[name] = self.last[name].role(self.started)
            else:
                out[name] = reading.role(self.started)
        return out


# ---------------------------------------------------------------------------
# The reader
# ---------------------------------------------------------------------------


def _scaffolding() -> tuple[Any, Any, Any, tuple[str, ...]]:
    """The strip's own patterns, from ``base_agent``, which imports this module."""
    if not _SCAFFOLDING:
        from maljan.agents.base_agent import (
            _FENCED_JSON_RE,
            _SCAFFOLD_BLOCK_RE,
            _SCAFFOLD_TAGS,
            _is_tool_invocation,
        )

        _SCAFFOLDING.append(
            (_SCAFFOLD_BLOCK_RE, _FENCED_JSON_RE, _is_tool_invocation, _SCAFFOLD_TAGS)
        )
    return _SCAFFOLDING[0]


_SCAFFOLDING: list[tuple[Any, Any, Any, tuple[str, ...]]] = []
_OPENINGS: dict[str, Any] = {}


def _openings() -> dict[str, Any]:
    if not _OPENINGS:
        _block, _fenced, _is_inv, tags = _scaffolding()
        names = "|".join(tags)
        _OPENINGS.update(
            {
                "tag": re.compile(r"<(?:" + names + r")\b[^>]*\Z", re.IGNORECASE),
                "tag_part": re.compile(r"<([A-Za-z_]*)\Z"),
                "tags": tuple(tags),
                "fence": re.compile(r"```(?:json|tool_code)?\s*\{"),
                "fence_part": re.compile(
                    r"(?:```(?:json|tool_code|j|js|jso|t|to|too|tool|tool_|tool_c|tool_co"
                    r"|tool_cod)?\s*|``|`)\Z"
                ),
            }
        )
    return _OPENINGS


def _strip_core(text: str) -> str:
    """``strip_tool_call_scaffolding`` without its last step, the trim of the text's ends."""
    block_re, fenced_re, is_invocation, _tags = _scaffolding()
    cleaned = block_re.sub("", text)
    return str(fenced_re.sub(lambda m: "" if is_invocation(m.group(1)) else m.group(0), cleaned))


def _closed_block(match: Any) -> bool:
    tag = re.escape(match.group("tag"))
    return re.search(r"</" + tag + r"\s*>\Z", match.group(0), re.IGNORECASE) is not None


def _tag_opening(text: str, start: int) -> int | None:
    found = _openings()
    whole = found["tag"].search(text, start)
    if whole is not None:
        return int(whole.start())
    part = found["tag_part"].search(text, max(start, len(text) - 16))
    if part is not None:
        begun = part.group(1).lower()
        if any(tag.startswith(begun) and tag != begun for tag in found["tags"]):
            return int(part.start())
    return None


def _fence_opening(text: str, start: int) -> int | None:
    found = _openings()
    places = [
        m.start()
        for m in (found["fence"].search(text, start), found["fence_part"].search(text, start))
        if m is not None
    ]
    return min(places) if places else None


def _settle(tail: str) -> tuple[int, str, bool, tuple[str, int] | None]:
    """``(cut, stripped, removed, opened)`` of the unresolved ``tail``.

    ``tail[:cut]`` stripped is the check's strip of that part whatever text
    follows. ``opened`` is ``(tag, at)`` when the cut stops at a tool-call block
    that has opened (its ``>`` arrived) and not closed, and nothing before it
    is unresolved: its text from ``at`` on is never part of the answer.
    """
    block_re, fenced_re, is_invocation, _tags = _scaffolding()
    kept: list[str] = []
    spans: list[tuple[int, int, int]] = []
    length = 0
    last = 0
    pending: int | None = None
    opened: tuple[str, int] | None = None
    for match in block_re.finditer(tail):
        if not _closed_block(match):
            pending = match.start()
            opened = (match.group("tag"), match.start() + match.group(0).index(">") + 1)
            break
        piece = tail[last : match.start()]
        spans.append((length, last, len(piece)))
        kept.append(piece)
        length += len(piece)
        last = match.end()
    if pending is None:
        pending = _tag_opening(tail, last)
    end = pending if pending is not None else len(tail)
    piece = tail[last:end]
    spans.append((length, last, len(piece)))
    kept.append(piece)
    scaffold_free = "".join(kept)

    out: list[str] = []
    fence_end = 0
    for match in fenced_re.finditer(scaffold_free):
        out.append(scaffold_free[fence_end : match.start()])
        out.append("" if is_invocation(match.group(1)) else match.group(0))
        fence_end = match.end()
    fence_pending = _fence_opening(scaffold_free, fence_end)
    stop = fence_pending if fence_pending is not None else len(scaffold_free)
    out.append(scaffold_free[fence_end:stop])
    if stop == len(scaffold_free):
        cut = end
    else:
        cut = end
        opened = None
        for begins, at, size in spans:
            if begins <= stop < begins + size:
                cut = at + (stop - begins)
                break
    stripped = "".join(out)
    return cut, stripped, stripped != tail[:cut], opened


def _distinct(keys: Any) -> list[_Key]:
    """Each hash once, where two readings share one."""
    out: list[_Key] = []
    for key in keys:
        if all(key is not seen for seen in out):
            out.append(key)
    return out


class _Pipeline:
    """The stripped text, line by line, into one claims machine, or two until the first line's
    leading whitespace is known to be trimmed or not."""

    __slots__ = ("held", "line", "machines", "trimmed_first")

    def __init__(self) -> None:
        # ``machines[0]`` reads the first line as written; ``machines[1]``,
        # when there is one, reads it with its leading whitespace trimmed.
        self.machines: list[_Claims] = [_Claims()]
        # Whether the first line that holds anything has been applied.
        self.trimmed_first = False
        self.line = _Line(first=True)
        # The last complete line that holds anything, not yet applied.
        self.held: _Line | None = None

    def peek(self) -> _Pipeline:
        twin = _Pipeline.__new__(_Pipeline)
        twin.machines = [machine.peek() for machine in self.machines]
        twin.trimmed_first = self.trimmed_first
        twin.line = self.line.copy()
        twin.held = None if self.held is None else self.held.copy()
        return twin

    def _apply(self, line: _Line, trim_end: bool) -> None:
        roles = line.roles(trim_end)
        plain = roles[_PLAIN]
        if not self.trimmed_first:
            # The first line that holds anything; nothing is open before it.
            self.trimmed_first = True
            trimmed = roles.get(_TRIMMED_START, plain)
            if trimmed != plain:
                self.machines.append(self.machines[0].fork())
                self.machines[1].apply(trimmed, None, line.headings.get(_TRIMMED_START))
            self.machines[0].apply(plain, None, line.headings.get(_PLAIN))
            return
        continued = line.continued or []
        heading = line.headings.get(_PLAIN)
        for index, machine in enumerate(self.machines):
            machine.apply(
                plain,
                continued[index] if index < len(continued) else None,
                heading.copy() if heading is not None and index else heading,
            )

    def _start(self) -> None:
        """The current line's first non-space character: the held line is applied first."""
        if self.held is not None:
            self._apply(self.held, trim_end=False)
            self.held = None
        self.line.started = True
        continued: list[_Key | None] = []
        for machine in self.machines:
            if machine.open is None:
                continued.append(None)
            else:
                key = machine.open.copy()
                key.feed(" ")
                continued.append(key)
        self.line.continued = continued

    def _feed_line(self, text: str) -> None:
        line = self.line
        at = 0
        while at < len(text) and not (line.started and line.decided):
            ch = text[at]
            at += 1
            if not line.started and not ch.isspace():
                self._start()
            for key in _distinct(line.headings.values()):
                key.feed(ch)
            # Readings whose heading ends on the same character share its hash.
            opened: _Key | None = None
            for name, reading in list(line.readings.items()):
                if name == _TRIMMED_START and not line.started:
                    continue
                if reading.decided:
                    if not ch.isspace():
                        line.decided_late[name] = True
                    continue
                stepped = reading.step(ch)
                line.readings[name] = stepped
                if not ch.isspace():
                    line.last[name] = stepped
                    if stepped.decided:
                        line.decided_late[name] = True
                if stepped.heading_at_delimiter:
                    opened = opened or _Key()
                    line.headings[name] = opened
            if line.continued is not None:
                for continuing in line.continued:
                    if continuing is not None:
                        continuing.feed(ch)
        if line.started and line.decided:
            # How the line reads is settled: the hashes it can no longer use go.
            roles = {reading.role(True) for reading in line.readings.values()}
            if line.continued is not None and not roles & {"field", "other"}:
                line.continued = None
            if "heading" not in roles:
                line.headings.clear()
        rest = text[at:]
        if not rest:
            return
        if not rest.isspace():
            for name in line.readings:
                line.decided_late[name] = True
        for key in _distinct(line.headings.values()):
            key.feed(rest)
        if line.continued is not None:
            for continuing in line.continued:
                if continuing is not None:
                    continuing.feed(rest)

    def _end_line(self) -> None:
        line = self.line
        if line.started:
            self.held = line
        self.line = _Line(first=not self.trimmed_first and self.held is None)

    def feed(self, text: str) -> None:
        at = 0
        for match in _LINE_END.finditer(text):
            self._feed_line(text[at : match.start()])
            self._end_line()
            at = match.end()
        self._feed_line(text[at:])

    def count(self, removed: bool, margin: int | None) -> RepeatCount:
        """The count had the text ended here; this pipeline is a peek and is used up.

        The last line that holds anything is read with its end trimmed when the
        strip removed something, and the first with its start trimmed.
        """
        last = self.line if self.line.started else self.held
        if last is not None:
            self._apply(last, trim_end=removed)
        machine = self.machines[1] if removed and len(self.machines) > 1 else self.machines[0]
        return machine.count(margin)


class ClaimRepeatReader:
    """``claims_repeated(strip_tool_call_scaffolding(text), margin)`` for each prefix, read as it grows.

    :meth:`feed` takes the next piece of the answer; :meth:`count` is what the
    check on a finished answer would count had the answer ended there.
    """

    def __init__(self, margin: int | None = None) -> None:
        self.margin = margin
        self._tail = ""
        self._removed = False
        self._pipeline = _Pipeline()
        # Inside a tool-call block that opened and has not closed: its tag and
        # the characters that may begin its closing tag.
        self._inside: tuple[str, str] | None = None

    def feed(self, piece: str) -> None:
        if not piece:
            return
        if self._inside is not None:
            piece = self._inside_block(piece)
            if not piece:
                return
        if not self._tail and "<" not in piece and "`" not in piece:
            # Nothing unresolved, and nothing here can open a block: final as it is.
            self._pipeline.feed(piece)
            return
        self._tail += piece
        cut, stripped, removed, opened = _settle(self._tail)
        if removed:
            self._removed = True
        if stripped:
            self._pipeline.feed(stripped)
        if opened is not None:
            # Everything from the block's opening on is removed: only the
            # characters that may begin its closing tag are kept.
            tag, at = opened
            rest = self._tail[at:]
            self._tail = ""
            self._removed = True
            self._inside = (tag, "")
            if rest:
                self.feed(rest)
            return
        self._tail = self._tail[cut:]

    def _inside_block(self, piece: str) -> str:
        """``piece`` read inside an opened tool-call block: what follows its closing tag, if any."""
        assert self._inside is not None
        tag, carry = self._inside
        text = carry + piece
        close = re.search(r"</" + re.escape(tag) + r"\s*>", text, re.IGNORECASE)
        if close is not None:
            self._inside = None
            return text[close.end() :]
        start = text.rfind("<")
        keep = ""
        if start >= 0:
            candidate = text[start:]
            wanted = "</" + tag.lower()
            lowered = candidate.lower()
            if lowered.startswith(wanted):
                after = candidate[len(wanted) :]
                if not after or after.isspace():
                    keep = candidate[: len(wanted)] + (" " if after else "")
            elif wanted.startswith(lowered):
                keep = candidate
        self._inside = (tag, keep)
        return ""

    def count(self) -> RepeatCount:
        peek = self._pipeline.peek()
        removed = self._removed or self._inside is not None
        if self._tail:
            rest = _strip_core(self._tail)
            removed = removed or rest != self._tail
            peek.feed(rest)
        return peek.count(removed, self.margin)

"""The repeated-claims check read line by line while an answer streams, at a flat cost per line.

The check on a finished answer is ``pipeline.validation.claims_repeated`` over
the answer without its tool-call scaffolding
(``base_agent.strip_tool_call_scaffolding``). Reading it again over the whole
answer at every line costs the square of the answer's length: about 13 s of
CPU for a 130,000-character answer and about 40 minutes for 1.57 million, on
the loop every analyst shares. :class:`ClaimRepeatReader` keeps what that check
would compute as the lines arrive and gives the same verdict, for every prefix
of the answer, at a cost that does not grow with what came before.

What it keeps:

* the scaffolding, stripped as it resolves. A tool-call block, or a fenced
  JSON block, that has begun and not yet resolved is held back as an
  unresolved tail; everything before the earliest such opening is final,
  because no later text can make a match that reaches back over it. The tail
  is stripped as the check strips it, each time it is read. The one global
  step of the strip, trimming the text's ends once anything was removed,
  touches only the first and the last line that hold anything: the reader
  keeps the last such line back, and keeps both readings of the first
  (``ClaimRepeatReader._lstripped``) until it is known which one applies;
* the claims (``claim_headings.claim_blocks``): the keys of the closed blocks
  and their count, the open block's words with a running fingerprint of them
  (so whether the open block repeats a closed one is a lookup, its key built
  only to confirm a match), whether its field lines have begun, and whether a
  DISPUTES section has opened.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any

from maljan.agents.claim_headings import (
    _FIELD_LABEL_RE,
    _SEPARATOR_RE,
    CLAIM_HEAD_RE,
    _opens_disputes,
)

__all__ = ["ClaimRepeatReader", "RepeatCount"]

# Where a line ends, as ``str.splitlines`` reads it.
_LINE_END = re.compile("\r\n|[\n\r\x0b\x0c\x1c\x1d\x1e\x85  ]")
_LINE_END_CHARS = frozenset("\n\r\x0b\x0c\x1c\x1d\x1e\x85  ")

# The marks a claim's key sets aside (``claim_headings._block_key``).
_MARKS = re.compile(r"[*_`#>]")

# The running fingerprint of a block's words: a polynomial over the words'
# hashes, modulo a Mersenne prime.
_BASE = 1_000_003
_MODULUS = (1 << 61) - 1


_SCAFFOLDING: list[tuple[Any, Any, Any, tuple[str, ...]]] = []


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


def _strip_core(text: str) -> str:
    """``strip_tool_call_scaffolding`` without its last step, the trim of the text's ends."""
    block_re, fenced_re, is_invocation, _tags = _scaffolding()
    cleaned = block_re.sub("", text)
    return str(fenced_re.sub(lambda m: "" if is_invocation(m.group(1)) else m.group(0), cleaned))


_OPENING_CACHE: dict[str, Any] = {}


def _openings() -> dict[str, Any]:
    """The patterns of an opening that has begun and may still resolve."""
    if not _OPENING_CACHE:
        _block_re, _fenced_re, _is_inv, tags = _scaffolding()
        names = "|".join(tags)
        _OPENING_CACHE.update(
            {
                # A tool-call tag with no ``>`` after it yet.
                "tag": re.compile(r"<(?:" + names + r")\b[^>]*\Z", re.IGNORECASE),
                "tag_part": re.compile(r"<([A-Za-z_]*)\Z"),
                "tags": tuple(tags),
                # A fence whose JSON object has begun and not closed.
                "fence": re.compile(r"```(?:json|tool_code)?\s*\{"),
                # A fence still being opened at the end of the text.
                "fence_part": re.compile(
                    r"(?:```(?:json|tool_code|j|js|jso|t|to|too|tool|tool_|tool_c|tool_co"
                    r"|tool_cod)?\s*|``|`)\Z"
                ),
            }
        )
    return _OPENING_CACHE


def _closed_block(match: Any) -> bool:
    """Whether a tool-call block ended at its closing tag rather than at the end of the text."""
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


def _settle(tail: str) -> tuple[int, str, bool]:
    """``(cut, stripped, removed)``: how much of ``tail`` is final, it stripped, and whether
    stripping removed anything from it.

    ``tail[:cut]`` stripped is the check's strip of that part whatever text
    follows: it ends before the earliest opening that has not resolved.
    """
    block_re, fenced_re, is_invocation, _tags = _scaffolding()
    kept: list[str] = []
    spans: list[tuple[int, int, int]] = []
    length = 0
    last = 0
    pending: int | None = None
    for match in block_re.finditer(tail):
        if not _closed_block(match):
            pending = match.start()
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
        for begins, at, size in spans:
            if begins <= stop < begins + size:
                cut = at + (stop - begins)
                break
    stripped = "".join(out)
    return cut, stripped, stripped != tail[:cut]


def _words(text: str) -> list[str]:
    return _MARKS.sub(" ", text).lower().split()


class _Block:
    """One open claim block: its words, their running fingerprint, and its field state."""

    __slots__ = ("fields", "last_real", "prefix", "words")

    def __init__(self) -> None:
        self.words: list[str] = []
        self.prefix: list[int] = [0]
        self.fields = False
        # The index of the last word the key's trim (``rstrip(" .;:")``) keeps.
        self.last_real = -1

    def add(self, text: str) -> None:
        for word in _words(text):
            self.words.append(word)
            self.prefix.append((self.prefix[-1] * _BASE + hash(word)) % _MODULUS)
            if word.rstrip(".;:"):
                self.last_real = len(self.words) - 1

    def state(self) -> tuple[int, bool, int]:
        return len(self.words), self.fields, self.last_real

    def restore(self, state: tuple[int, bool, int]) -> None:
        size, self.fields, self.last_real = state
        del self.words[size:]
        del self.prefix[size + 1 :]

    def fingerprint(self) -> tuple[int, int]:
        count = self.last_real + 1
        if count == 0:
            return 0, 0
        last = self.words[count - 1].rstrip(".;:")
        return count, (self.prefix[count - 1] * _BASE + hash(last)) % _MODULUS

    def key(self) -> str:
        count = self.last_real + 1
        if count == 0:
            return ""
        return " ".join([*self.words[: count - 1], self.words[count - 1].rstrip(".;:")])


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


class _Claims:
    """The claim blocks of the lines read so far (``claim_headings.claim_blocks``)."""

    def __init__(self) -> None:
        self.closed: dict[str, int] = {}
        self.by_fingerprint: dict[tuple[int, int], set[str]] = {}
        self.begun = 0
        self.open: _Block | None = None
        self.disputes = False
        self._log: list[tuple[str, tuple[int, int]]] | None = None

    def _close(self) -> None:
        block = self.open
        if block is None:
            return
        key = block.key()
        fingerprint = block.fingerprint()
        self.closed[key] = self.closed.get(key, 0) + 1
        self.by_fingerprint.setdefault(fingerprint, set()).add(key)
        self.begun += 1
        self.open = None
        if self._log is not None:
            self._log.append((key, fingerprint))

    def read(self, line: str) -> None:
        if self.disputes:
            return
        if _opens_disputes(line):
            self.disputes = True
            return
        heading = CLAIM_HEAD_RE.match(line)
        if heading is not None:
            self._close()
            opened = _Block()
            opened.add(line[heading.end() :])
            self.open = opened
            return
        if _SEPARATOR_RE.match(line):
            self._close()
            return
        block = self.open
        if block is None or not line.strip():
            return
        if _FIELD_LABEL_RE.match(line):
            block.fields = True
            block.add(line)
        elif block.fields:
            self._close()
        else:
            block.add(line)

    def _repeats_a_closed_one(self, block: _Block) -> bool:
        keys = self.by_fingerprint.get(block.fingerprint())
        return bool(keys) and block.key() in keys  # type: ignore[operator]

    def count(self, margin: int | None) -> RepeatCount:
        begun = self.begun
        distinct = len(self.closed)
        if self.open is not None:
            begun += 1
            if not self._repeats_a_closed_one(self.open):
                distinct += 1
        allowed = distinct if margin is None else max(0, int(margin))
        return RepeatCount(begun, distinct, allowed)

    def peek(self, lines: Sequence[str], margin: int | None) -> RepeatCount:
        """The count had ``lines`` been read too; nothing read so far changes."""
        opened = self.open
        opened_state = opened.state() if opened is not None else None
        disputes, begun = self.disputes, self.begun
        self._log = []
        try:
            for line in lines:
                self.read(line)
            return self.count(margin)
        finally:
            for key, fingerprint in self._log:
                left = self.closed[key] - 1
                if left:
                    self.closed[key] = left
                else:
                    del self.closed[key]
                    keys = self.by_fingerprint[fingerprint]
                    keys.discard(key)
                    if not keys:
                        del self.by_fingerprint[fingerprint]
            self._log = None
            self.open = opened
            if opened is not None and opened_state is not None:
                opened.restore(opened_state)
            self.disputes, self.begun = disputes, begun


class ClaimRepeatReader:
    """``claims_repeated(strip_tool_call_scaffolding(text), margin)`` for each prefix, read as it grows.

    :meth:`feed` takes the next piece of the answer; :meth:`count` is what the
    check on a finished answer would count had the answer ended there.
    """

    def __init__(self, margin: int | None = None) -> None:
        self.margin = margin
        self._tail = ""
        self._removed = False
        self._plain = _Claims()
        # The first line holding anything, read with its leading whitespace
        # trimmed: the check trims the text's ends once anything was removed.
        self._lstripped: _Claims | None = None
        self._first_read = False
        self._partial: list[str] = []
        self._held: str | None = None

    def feed(self, piece: str) -> None:
        if not piece:
            return
        self._tail += piece
        cut, stripped, removed = _settle(self._tail)
        if removed:
            self._removed = True
        self._tail = self._tail[cut:]
        if stripped:
            self._take(stripped)

    def _take(self, text: str) -> None:
        if not any(ch in _LINE_END_CHARS for ch in text):
            self._partial.append(text)
            return
        joined = "".join(self._partial) + text
        lines = _LINE_END.split(joined)
        rest = lines.pop()
        self._partial = [rest] if rest else []
        for line in lines:
            if line.strip():
                if self._held is not None:
                    self._read(self._held)
                self._held = line

    def _read(self, line: str) -> None:
        if not self._first_read:
            self._first_read = True
            trimmed = line.lstrip()
            if trimmed != line:
                self._lstripped = _Claims()
                self._lstripped.read(trimmed)
            self._plain.read(line)
            return
        self._plain.read(line)
        if self._lstripped is not None:
            self._lstripped.read(line)

    def count(self) -> RepeatCount:
        rest = _strip_core(self._tail)
        removed = self._removed or rest != self._tail
        if removed and self._lstripped is not None and self._removed:
            # Settled: the trimmed reading is the one that applies from here on.
            self._plain, self._lstripped = self._lstripped, None
        machine = self._lstripped if removed and self._lstripped is not None else self._plain
        held = f"{self._held}\n" if self._held is not None else ""
        text = held + "".join(self._partial) + rest
        if removed:
            text = text.rstrip()
            if not self._first_read:
                text = text.lstrip()
        return machine.peek(text.splitlines(), self.margin)

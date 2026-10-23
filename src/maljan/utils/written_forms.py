"""The spellings one value takes in the texts a run records.

A tool answers in JSON, so the string ``/c query "Example Operators" /all`` reaches
the ledger and the corpus as ``/c query \\"Example Operators\\" /all``, and a path
``C:\\Windows\\x.exe`` as ``C:\\\\Windows\\\\x.exe``. The triage pack quotes a
decoded string on one line, so a quote in it is written ``\\"``, a control
character as an escape and a backslash that would end the string as ``\\x5c``.
A model reads either text and writes the value back plainly. A search for the
plain value in the escaped text finds nothing, and a check built on that search
told a judge that two strings the pack had shown it appear nowhere in the
evidence.

This module answers one question, for every search that compares a value a
model wrote with a text a tool wrote: which spellings mean this value. It does
not decide anything, and it never rewrites the value; a caller asks each
spelling the question it was already asking of one.
"""

from __future__ import annotations

import functools
import json
import re
import sys
import unicodedata

# How the triage pack writes a character that would break its line or its
# quoting. One table, read by the pack when it writes a string and by every
# search that has to find the string again.
PACK_ESCAPES: dict[str, str] = {'"': '\\"', "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _escape(ch: str) -> str:
    return PACK_ESCAPES.get(ch, ch if ch.isprintable() else f"\\x{ord(ch):02x}")


# Every escape below U+00A0, where control characters run long in practice,
# as one translate table: a run of them is written in C, one output string.
_LOW_ESCAPES = {code: _escape(chr(code)) for code in range(0xA0)}


@functools.lru_cache(maxsize=1)
def _unprintable() -> re.Pattern[str]:
    """Runs of the characters ``pack_escaped`` writes out: the quote and every
    character that is not printable. Built once, from ``str.isprintable``
    itself, so the two can never disagree."""
    ranges: list[tuple[int, int]] = []
    for code in range(sys.maxunicode + 1):
        ch = chr(code)
        if ch == '"' or not ch.isprintable():
            if ranges and ranges[-1][1] == code - 1:
                ranges[-1] = (ranges[-1][0], code)
            else:
                ranges.append((code, code))
    members = "".join(
        re.escape(chr(a)) if a == b else f"{re.escape(chr(a))}-{re.escape(chr(b))}"
        for a, b in ranges
    )
    return re.compile(f"[{members}]+")


def _escaped_run(match: re.Match[str]) -> str:
    run = match.group()
    if max(run) < "\xa0":
        return run.translate(_LOW_ESCAPES)
    return "".join(_escape(ch) for ch in run)


# The characters a model's chat template builds its control tokens from
# (``<|im_start|>``, ``[INST]``, ``<s>``), written out the way a control
# character is when ``pack_escaped`` is asked to defang them: a tokenizer that
# parses special tokens inside message text then finds none in the value.
TOKEN_DELIMITERS: dict[str, str] = {ch: f"\\x{ord(ch):02x}" for ch in "<>|[]"}
_TOKEN_DELIMITERS = str.maketrans(TOKEN_DELIMITERS)


def controls_written_out(text: str) -> str:
    """``text`` with only its unprintable characters written out, as ``pack_escaped`` writes them.

    The quote and every printable character are left as they are, so a text
    with no control character comes back unchanged. A line built of it can
    never break into two.
    """
    if text.isprintable():  # the common case, decided in one pass in C
        return text
    return "".join(ch if ch.isprintable() else _escape(ch) for ch in text)


# How ``ids_written_out`` writes the underscore it takes out of an id, in the
# form a control character takes.
ENTRY_ID_JOIN_ESCAPE = f"\\x{ord('_'):02x}"


def ids_written_out(text: str) -> str:
    """``text`` with the underscore of every ledger id in it written ``\\x5f``.

    The id shape is ``schemas.evidence.ENTRY_ID_JOIN_RE``: only where
    ``ENTRY_ID_RE`` would begin one, or right after an escape. Run it after the
    control characters are written out (``controls_written_out``), never
    before: a control character between ``e`` and ``v`` is an escape whose
    last digit can read as the ``e``. Afterwards the text holds no citation
    ``ENTRY_ID_RE`` or a reader would take for the platform's. Linear.
    """
    from maljan.schemas.evidence import ENTRY_ID_JOIN_RE

    return ENTRY_ID_JOIN_RE.sub(lambda m: m.group()[:-1] + ENTRY_ID_JOIN_ESCAPE, text)


# The platform's run-state markers (``pipeline.run_state.RUN_STATE_BEGIN`` /
# ``RUN_STATE_END``): a rule of three or more equals signs, the words, and the
# rule that closes the line, wherever a text carries one, in any case and spacing.
_RUN_STATE_MARKER_RE = re.compile(
    r"(?<!=)(={3,}+)(\s*+(?:end\s+)?run\s+state\b[^=\n]*+)(=*+)", re.IGNORECASE
)


def _dashed(match: re.Match[str]) -> str:
    return "-" * len(match.group(1)) + match.group(2) + "-" * len(match.group(3))


def hint_escaped(text: str) -> str:
    """A name in a prompt hint: control characters, quotes and chat-template tokens written out.

    Only what could end the line, close a quote or pose as a control token
    (``<|...|>``) is written out; ``<``, ``>``, ``|`` and brackets stay as
    they are, so ``std::vector<int>::push_back`` and ``operator<<`` read and
    copy as the names they are.
    """
    return pack_escaped(text).replace("<|", "\\x3c|").replace("|>", "|\\x3e")


def markers_written_out(text: str) -> str:
    """``text`` with every run-state marker in it written with dashes for its equals signs.

    The platform's block is recognised by its markers; a sample or a tool that
    writes one would otherwise open a block the model reads as derived from
    the ledger, or end a text on one the platform takes back off. Each ``=``
    of the rule becomes ``-``, one character for one, so a text's length and
    every offset in it are unchanged; text with no marker comes back as it
    was. Idempotent.
    """
    if "=" not in text:
        return text
    return _RUN_STATE_MARKER_RE.sub(_dashed, text)


def sample_written_out(text: str) -> str:
    """Bare text a sample wrote, as a line holds it: its controls, then its ids, written out."""
    return markers_written_out(ids_written_out(controls_written_out(text)))


def quoted_backslashes_written_out(text: str) -> str:
    """``text`` with every backslash that stands right before a quote written ``\\x5c``.

    A backslash before a quote would read as escaping it, and so close the
    quote the value sits in. Run before the quote itself is written out; a
    text with no quote, or no backslash, comes back as it was. Linear.
    """
    if '"' not in text or "\\" not in text:
        return text
    pieces = text.split('"')
    # Every piece but the last ends where a quote stood; its trailing run of
    # backslashes is the one before that quote. No pattern: one pass.
    for at, piece in enumerate(pieces[:-1]):
        kept = piece.rstrip("\\")
        pieces[at] = kept + "\\x5c" * (len(piece) - len(kept))
    return '"'.join(pieces)


def pack_escaped(text: str, *, delimiters: bool = False, ids: bool = False) -> str:
    """``text`` as the pack writes it between its quotes, without the quotes.

    The quote and the control characters are written out and every other
    character is left as it is, backslashes included, so a Windows path reads
    as a path; a backslash that would end the string is written ``\\x5c``,
    where it would otherwise read as escaping the closing quote; so is every
    backslash that stands right before a quote in the value, so no text can
    close the quote it sits in. A path with no quote in it is unchanged. With
    ``delimiters`` the characters of a chat template's control tokens
    (``TOKEN_DELIMITERS``) are written out too, for a value that may carry
    one. With ``ids`` every ledger id in it is written out
    (``ids_written_out``), for a value the sample controls. Without either,
    the output is as it always was, except that a run-state marker in it is
    always written out (``markers_written_out``).
    """
    text = quoted_backslashes_written_out(text)
    if text.isprintable():  # the common case, decided in one pass in C
        out = text.replace('"', PACK_ESCAPES['"'])
    else:
        out = _unprintable().sub(_escaped_run, text)
    if delimiters:
        out = out.translate(_TOKEN_DELIMITERS)
    if ids:
        # After every escape is written: an id may stand right after one.
        out = ids_written_out(out)
    # A run-state marker is the platform's alone, whoever wrote the value.
    out = markers_written_out(out)
    if out.endswith("\\"):
        out = out[:-1] + "\\x5c"
    return out


def _json_body(text: str, *, ascii_only: bool) -> str:
    """``text`` as a JSON string carries it, without the surrounding quotes."""
    return json.dumps(text, ensure_ascii=ascii_only)[1:-1]


def _json_read(text: str) -> str | None:
    """``text`` read as the inside of a JSON string, or ``None`` when it is not one.

    A model that copied a value out of a tool's JSON sometimes keeps the
    escapes; read back, it is the value the tool meant.
    """
    if "\\" not in text:
        return None
    try:
        value = json.loads(f'"{text}"')
    except (ValueError, TypeError):
        return None
    return value if isinstance(value, str) and value != text else None


# The escapes the pack writes, read back: ``\x`` with as many hex digits as the
# widest code point takes, and the short forms of ``PACK_ESCAPES``.
_PACK_READS = {escaped: plain for plain, escaped in PACK_ESCAPES.items()}
_HEX_DIGITS = len(f"{sys.maxunicode:x}")
_PACK_ESCAPE_RE = re.compile(rf"\\(?:x([0-9a-fA-F]{{2,{_HEX_DIGITS}}})|[ntr\"])")
# The printable characters the pack writes as a ``\x`` escape: a token
# delimiter, an id's underscore and a final backslash (and the quote, by any
# spelling).
_ESCAPED_PRINTABLE = frozenset(TOKEN_DELIMITERS) | {"_", "\\", '"'}


def _written_as_escape(code: int) -> bool:
    """Whether the pack writes the character ``code`` as a ``\\x`` escape.

    A printable character only when it is one of ``_ESCAPED_PRINTABLE``. An
    unprintable one only when it is assigned, so the digits after a narrow
    escape (``\\x5f`` then ``0003``) are not read as an unassigned code point.
    """
    if code > sys.maxunicode:
        return False
    ch = chr(code)
    if ch.isprintable():
        return ch in _ESCAPED_PRINTABLE
    return unicodedata.category(ch) != "Cn"


def pack_reads(text: str) -> tuple[str, ...]:
    """``text`` with the escapes the pack writes read back: each distinct reading, or none.

    A model that copied a value out of a pack line in its written-out form
    (``prev\\x5f2024.doc``, ``invoice\\x202efdp.exe``, ``a\\nb``) is citing
    the value the sample wrote. The pack writes a character in as few hex
    digits as it takes, so the digits after an escape may be text. Each ``\\x``
    run is read at the widest width, from six digits down to two, whose
    character the pack would have written as an escape. The reading at two
    digits throughout is asked too. Linear: each escape tries at most six
    widths.
    """
    if "\\" not in text:
        return ()

    def widest(match: re.Match[str]) -> str:
        digits = match.group(1)
        if digits is None:
            return _PACK_READS[match.group()]
        for width in range(len(digits), 1, -1):
            code = int(digits[:width], 16)
            if _written_as_escape(code):
                return chr(code) + digits[width:]
        return match.group()

    def narrow(match: re.Match[str]) -> str:
        digits = match.group(1)
        if digits is None:
            return _PACK_READS[match.group()]
        return chr(int(digits[:2], 16)) + digits[2:]

    readings: list[str] = []
    for read in (widest, narrow):
        value = _PACK_ESCAPE_RE.sub(read, text)
        if value != text and value not in readings:
            readings.append(value)
    return tuple(readings)


def written_forms(value: str) -> tuple[str, ...]:
    """Every spelling of ``value`` a run's texts may hold it in, the value first.

    The value as written; as a JSON string carries it, with and without
    non-ASCII characters escaped; as the triage pack quotes it; and, when the
    value itself carries JSON escapes, the value they spell and that value's
    own spellings. Distinct and in that order, so a caller that stops at the
    first hit asks the plain question first.
    """
    text = str(value or "")
    if not text:
        return ()
    bases = [text]
    for read in (_json_read(text), *pack_reads(text)):
        if read and read not in bases:
            bases.append(read)
    forms: list[str] = []
    for base in bases:
        # A text escaped before it was lower-cased — the run's corpus is — keeps
        # the case of a non-ASCII capital in its escape (``Ú`` is ``\\u00da``,
        # ``ú`` is ``\\u00fa``), while a caller folds the value first. The
        # escape of the capitals is asked too, folded as the corpus folds it.
        # A value mixing capital and small non-ASCII letters is the case this
        # does not cover.
        capitals = (
            _json_body(base.upper(), ascii_only=True).lower()
            if any(ord(ch) > 127 for ch in base)
            else ""
        )
        for form in (
            base,
            _json_body(base, ascii_only=False),
            _json_body(base, ascii_only=True),
            capitals,
            pack_escaped(base),
            pack_escaped(base, delimiters=True),
            pack_escaped(base, ids=True),
            pack_escaped(base, delimiters=True, ids=True),
            sample_written_out(base),
        ):
            if form and form not in forms:
                forms.append(form)
    return tuple(forms)

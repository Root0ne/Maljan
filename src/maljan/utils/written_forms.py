"""The spellings one value takes in the texts a run records.

A tool answers in JSON, so the string ``/c net group "Admins" /domain`` reaches
the ledger and the corpus as ``/c net group \\"Admins\\" /domain``, and a path
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

import json

# How the triage pack writes a character that would break its line or its
# quoting. One table, read by the pack when it writes a string and by every
# search that has to find the string again.
PACK_ESCAPES: dict[str, str] = {'"': '\\"', "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def pack_escaped(text: str) -> str:
    """``text`` as the pack writes it between its quotes, without the quotes.

    The quote and the control characters are written out and every other
    character is left as it is, backslashes included, so a Windows path reads
    as a path; a backslash that would end the string is written ``\\x5c``,
    where it would otherwise read as escaping the closing quote.
    """
    out = "".join(
        PACK_ESCAPES.get(ch, ch if ch.isprintable() else f"\\x{ord(ch):02x}") for ch in text
    )
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
    unescaped = _json_read(text)
    if unescaped:
        bases.append(unescaped)
    forms: list[str] = []
    for base in bases:
        for form in (
            base,
            _json_body(base, ascii_only=False),
            _json_body(base, ascii_only=True),
            pack_escaped(base),
        ):
            if form and form not in forms:
                forms.append(form)
    return tuple(forms)

"""One-line, bounded rendering of request-derived values for log messages.

A value that reaches a log line from a path segment, a query string, a request
body or an exception message can carry newlines, and a newline inside a log
record lets its sender forge further records: everything after the newline
reads as a fresh line to whatever parses the log. Control characters can also
drive a terminal that tails the log. Length matters for the same reason a
single unbounded field can push a whole record out of a collector's line
buffer. Every such value goes through :func:`log_safe` before it is
interpolated.
"""

from __future__ import annotations

# The three whitespace characters that occur in real input get their familiar
# spelling; everything else in C0 (and DEL) falls back to the hex form.
_NAMED_ESCAPES = {"\r": "\\r", "\n": "\\n", "\t": "\\t"}

TRUNCATION_MARKER = "…"


def log_safe(value: object, limit: int = 256) -> str:
    """A request-derived value made safe for a log line: one line, bounded length."""
    text = value if isinstance(value, str) else str(value)

    rendered: list[str] = []
    for char in text:
        named = _NAMED_ESCAPES.get(char)
        if named is not None:
            rendered.append(named)
        elif ord(char) < 0x20 or ord(char) == 0x7F:
            rendered.append(f"\\x{ord(char):02x}")
        else:
            rendered.append(char)

    out = "".join(rendered)
    if len(out) > limit:
        # The marker is appended, not counted: a reader has to be able to tell
        # a value that was cut from one that happened to end there.
        out = out[:limit] + TRUNCATION_MARKER
    return out

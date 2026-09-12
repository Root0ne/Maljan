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

import re

# Everything in C0 except the three whitespace characters handled by name,
# plus DEL: rendered in the hex form so a value can never drive a terminal
# that tails the log.
_OTHER_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
TRUNCATION_MARKER = "…"


def _hex_escape(match: re.Match[str]) -> str:
    return f"\\x{ord(match.group()):02x}"


def log_safe(value: object, limit: int = 256) -> str:
    """A request-derived value made safe for a log line: one line, bounded length."""
    text = value if isinstance(value, str) else str(value)
    # Line breaks first, and through str.replace on purpose: this is the
    # construction static analysis recognises as the end of a log-injection
    # flow, so the call sites stop being flagged for the value they log.
    text = text.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
    out = _OTHER_CONTROL.sub(_hex_escape, text)
    if len(out) > limit:
        # The marker is appended, not counted: a reader has to be able to tell
        # a value that was cut from one that happened to end there.
        out = out[:limit] + TRUNCATION_MARKER
    return out

"""JSON cleanup utilities for LLM structured output.

LLMs often return markdown-wrapped JSON, trailing commas, or single-quoted
strings. This module provides best-effort repair before Pydantic/STIX
validation.

Design notes — ReDoS hardening:
    The previous implementation used greedy ``.*`` with ``DOTALL`` to locate
    JSON blocks, which is catastrophically slow on long mismatched input.
    The current implementation walks the string once with a bracket counter
    so worst-case behaviour is O(n) regardless of pathological input.
"""

from __future__ import annotations

import json
import re
from typing import Any

# Hard limit on the input size we'll attempt to repair. Anything larger
# almost certainly is a logging artefact, not a JSON payload.
MAX_INPUT_CHARS: int = 2 * 1024 * 1024  # 2 MB


_OPEN_CLOSE = {"{": "}", "[": "]"}


def _find_balanced(text: str, start: int) -> int | None:
    """Return the index of the matching closer for ``text[start]`` or ``None``.

    Walks the string respecting double-quoted JSON strings, so braces inside
    a string literal do not affect nesting. The quote scan starts at ``start``,
    so a stray quote in prose before the payload hides nothing. This is
    intentionally a single forward scan, no regex, to guarantee linear time.
    """
    opener = text[start]
    closer = _OPEN_CLOSE.get(opener)
    if closer is None:
        return None
    depth = 0
    in_string = False
    escape = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
            continue
        if ch == opener:
            depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0:
                return i
    return None


def extract_json(text: str) -> str:
    """Return the JSON object/array substring in ``text`` that is the payload.

    The function strips Markdown fences first, then locates the first
    ``{`` or ``[`` and walks forward until the matching closer. That span is
    the payload unless it is the prose's own bracket, which is skipped for the
    next one: a span that is not JSON and looks like prose (no ``"`` and no
    ``:``: ``{placeholder}``, ``[see below]``), or one that reads as JSON but
    is a list of numbers only (``[1]``, ``[0, 1]``) inside a line of prose, in which case a later
    object or list of structures wins. A payload that begins the answer or a
    line (or follows a fence), broken or not, is always the answer, so the
    repair and the decode error read it. Each candidate is scanned from its own
    opener, and a skipped span is passed whole, so the walk is linear.
    """
    if len(text) > MAX_INPUT_CHARS:
        text = text[:MAX_INPUT_CHARS]

    # Strip ```json fences if present — uses non-greedy with limited search.
    fence_match = re.match(r"\s*```(?:json)?\s*", text, flags=re.IGNORECASE)
    if fence_match:
        text = text[fence_match.end() :]
        if text.endswith("```"):
            text = text[:-3]

    first: str | None = None
    weak: str | None = None
    at = 0
    # Whether the current line holds text other than blanks before ``at``, kept
    # as ``at`` advances rather than read off a slice of the prefix.
    line_text = False
    while at < len(text):
        ch = text[at]
        if ch not in _OPEN_CLOSE:
            if ch == "\n":
                line_text = False
            elif not ch.isspace():
                line_text = True
            at += 1
            continue
        end = _find_balanced(text, at)
        if end is None:
            break
        span = text[at : end + 1].strip()
        if first is None:
            first = span
        # Inside a line of prose (a citation, a range); a span that begins its
        # own line is an answer, whatever it holds.
        after_prose = line_text
        parsed = _parsed(span)
        if parsed is _UNREAD:
            if '"' in span or ":" in span:
                # A payload that does not read: the repair and the error read it.
                return span
            line_text = _line_text_after(text, at, end)
            at = end + 1
            continue
        if not (after_prose and _is_marker(parsed)):
            return span
        if weak is None:
            weak = span
        line_text = _line_text_after(text, at, end)
        at = end + 1
    if weak is not None:
        return weak
    if first is not None:
        return first
    return text.strip()


def _line_text_after(text: str, at: int, end: int) -> bool:
    """Whether the line holds text other than blanks after the span ``text[at:end + 1]``."""
    newline = text.rfind("\n", at, end + 1)
    if newline < 0:
        return True  # the span itself is text on the line
    return bool(text[newline + 1 : end + 1].strip())


_UNREAD = object()


def _parsed(span: str) -> Any:
    for candidate in (span, repair_json(span)):
        try:
            return json.loads(candidate)
        except (json.JSONDecodeError, RecursionError):
            continue
    return _UNREAD


def _is_marker(value: Any) -> bool:
    """Whether a parsed span is only numbers in a list, a citation or range: ``[1]``, ``[0, 1]``."""
    return (
        isinstance(value, list)
        and bool(value)
        and all(isinstance(v, int | float) and not isinstance(v, bool) for v in value)
    )


# Trailing-comma and single-quote repairs use bounded, non-greedy patterns
# anchored to small contexts — safe against ReDoS.
_TRAILING_COMMA_RE = re.compile(r",(\s*[}\]])")
_LINE_COMMENT_RE = re.compile(r"//[^\n]*")
_BLOCK_COMMENT_RE = re.compile(r"/\*[^*]*\*+(?:[^/*][^*]*\*+)*/")
_SINGLE_QUOTED_RE = re.compile(r"'([^'\\\n]{0,500}(?:\\.[^'\\\n]{0,500})*)'")


def _replace_single_quotes(match: re.Match[str]) -> str:
    inner = match.group(1).replace('"', '\\"')
    return f'"{inner}"'


def repair_json(text: str) -> str:
    """Apply bounded LLM JSON repair heuristics."""
    if len(text) > MAX_INPUT_CHARS:
        text = text[:MAX_INPUT_CHARS]

    text = _LINE_COMMENT_RE.sub("", text)
    text = _BLOCK_COMMENT_RE.sub("", text)
    text = _TRAILING_COMMA_RE.sub(r"\1", text)
    text = _SINGLE_QUOTED_RE.sub(_replace_single_quotes, text)
    return text.strip()


def safe_parse_json(text: str) -> Any:
    """Best-effort parse of LLM output into a Python value.

    Returns ``None`` when neither the cleaned nor the repaired text parses.
    """
    if not text:
        return None
    cleaned = extract_json(text)
    repaired = repair_json(cleaned)

    try:
        return json.loads(repaired)
    except (json.JSONDecodeError, RecursionError):
        pass

    try:
        return json.loads(cleaned)
    except (json.JSONDecodeError, RecursionError):
        return None


def json_decode_error(text: str) -> tuple[str, int, str] | None:
    """Why :func:`safe_parse_json` reads nothing from ``text``: ``(complaint, position, json)``.

    The decoder's own complaint about the JSON this reader found in ``text``
    (fence and surrounding words taken off by :func:`extract_json`, as the
    reader takes them off), the 0-based position it stopped at in that JSON,
    and the JSON itself, before the repair pass, which is what the writer
    wrote. ``None`` when the reader reads ``text``, or when the JSON it found
    decodes and only the reader's own rules took nothing from it. Linear in
    ``text``.
    """
    if safe_parse_json(text) is not None:
        return None
    cleaned = extract_json(text)
    try:
        json.loads(cleaned)
    except json.JSONDecodeError as exc:
        return exc.msg, exc.pos, cleaned
    except RecursionError:
        return None
    return None

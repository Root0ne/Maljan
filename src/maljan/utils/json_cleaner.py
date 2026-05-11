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
    a string literal do not affect nesting. This is intentionally a single
    forward scan — no regex — to guarantee linear time.
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
    """Return the first JSON object/array substring in ``text``.

    The function strips Markdown fences first, then locates the first
    ``{`` or ``[`` and walks forward until the matching closer.
    """
    if len(text) > MAX_INPUT_CHARS:
        text = text[:MAX_INPUT_CHARS]

    # Strip ```json fences if present — uses non-greedy with limited search.
    fence_match = re.match(r"\s*```(?:json)?\s*", text, flags=re.IGNORECASE)
    if fence_match:
        text = text[fence_match.end() :]
        if text.endswith("```"):
            text = text[:-3]

    # Find the first opening bracket and walk forward.
    for start, ch in enumerate(text):
        if ch in _OPEN_CLOSE:
            end = _find_balanced(text, start)
            if end is not None:
                return text[start : end + 1].strip()
            break
    return text.strip()


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
    except json.JSONDecodeError:
        pass

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        return None

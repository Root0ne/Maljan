"""What names an arm, read from the arm's stored run, and the redaction of it.

An arm is named by its directory, by the model and provider its settings
snapshot holds, by the job and report ids, by the profile and paths it ran
with, and by every date a report prints. :func:`identifiers` collects the
strings, :func:`redact` removes them (and every date) from a text, and
:func:`leaks` is the self-check's question: what is still there.
"""

from __future__ import annotations

import html
import json
import re
from pathlib import Path
from typing import Any

REDACTED = "[redacted]"
DATE = "[date]"

# A date, with its time of day when it has one.
_DATE = re.compile(
    r"\d{4}-\d{2}-\d{2}"
    r"(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?"
)
# The report number carries the day: ``MJN20261008-6091f2``.
_REPORT_NUMBER = re.compile(r"(?<=MJN)\d{8}")

# The settings that name an arm: the LLM section's model, provider and
# endpoint leaves (the model and provider also name a vendor, whose first word
# is stripped as well), and the team profile. Nothing else in a snapshot: it
# holds every tool's settings and role names too, and stripping those would
# strip the report's own words.
_VENDOR = re.compile(r"^llm\.(?:.*[._])?(?:model|provider)$", re.IGNORECASE)
_LEAF = re.compile(
    r"^llm\.(?:.*[._])?(?:model|provider|base_url|endpoint)$|^agents\.profile$|^profile$",
    re.IGNORECASE,
)
_MIN = 4


def _worth(value: Any) -> bool:
    return isinstance(value, str) and len(value.strip()) >= _MIN and not value.strip().isdigit()


def _vendor(text: str) -> str | None:
    """The first word of a model id (``deepseek-flash`` becomes ``deepseek``)."""
    head = re.match(r"[A-Za-z][A-Za-z0-9]{3,}", text.strip())
    return head.group(0) if head else None


def _add(out: set[str], value: str, *, vendor: bool) -> None:
    out.add(value.strip())
    first = _vendor(value) if vendor else None
    if first:
        out.add(first)


def _walk(node: Any, out: set[str], path: str = "") -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            here = f"{path}.{key}" if path else str(key)
            if isinstance(value, str) and _LEAF.search(here) and _worth(value):
                _add(out, value, vendor=bool(_VENDOR.search(here)))
            else:
                _walk(value, out, here)


def _read(root: Path, name: str) -> Any:
    try:
        return json.loads((root / name).read_bytes())
    except (OSError, ValueError):
        return None


def identifiers(root: Path, name: str, extra: tuple[str, ...] = ()) -> set[str]:
    """Every string of the run in ``root`` that tells which arm it is."""
    found: set[str] = {name, root.name, str(root), *extra}
    meta = _read(root, "meta.json")
    if isinstance(meta, dict):
        for key in ("job_id", "report_id"):
            if _worth(meta.get(key)):
                found.add(str(meta[key]).strip())
        for key in ("model", "provider"):
            if _worth(meta.get(key)):
                _add(found, str(meta[key]), vendor=True)
    job = _read(root, "job.json")
    if isinstance(job, dict):
        for key in ("id", "report_id"):
            if _worth(job.get(key)):
                found.add(str(job[key]).strip())
        _walk(job.get("config"), found)
    summary = _read(root, "run-summary.json")
    if isinstance(summary, dict):
        _walk(summary.get("settings_snapshot"), found)
    return {s for s in found if _worth(s)}


def _forms(value: str) -> set[str]:
    """The ways a string is written in a JSON or HTML copy."""
    return {value, json.dumps(value)[1:-1], html.escape(value), html.escape(value, quote=False)}


def _pattern(strings: set[str]) -> re.Pattern[str] | None:
    forms = sorted({f for s in strings for f in _forms(s) if f}, key=len, reverse=True)
    if not forms:
        return None
    return re.compile("|".join(re.escape(f) for f in forms), re.IGNORECASE)


def redact(text: str, strings: set[str]) -> str:
    """``text`` without any of ``strings`` (any case) and without a date."""
    pattern = _pattern(strings)
    if pattern is not None:
        text = pattern.sub(REDACTED, text)
    text = _DATE.sub(DATE, text)
    return _REPORT_NUMBER.sub(DATE, text)


def leaks(text: str, strings: set[str]) -> list[str]:
    """The strings of ``strings`` still in ``text`` (lowercased), and ``a date`` when one is."""
    left: list[str] = []
    pattern = _pattern(strings)
    if pattern is not None:
        left.extend(sorted({m.group(0).lower() for m in pattern.finditer(text)}))
    if _DATE.search(text) or _REPORT_NUMBER.search(text):
        left.append("a date")
    return left

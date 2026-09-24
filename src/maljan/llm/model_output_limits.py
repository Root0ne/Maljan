"""The maximum output a model's provider declares, where it declares one.

A derived output cap is a quarter of the model's learned window
(``context_window.derived_reply``), and no fixed figure bounds it from above:
the one bound besides an operator's own cap is the model's own maximum output,
where its provider states it. Two places state it: an OpenAI-compatible model
list entry, read from the same answer the window probe reads, and the vendored
table's ``max_output`` rows. Nothing here asks a model to produce anything.
Zero is always "not declared", never a limit.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from maljan.core.logger import logger

_lock = threading.Lock()
# Learned from model list answers, keyed by the model id as asked, lower-cased.
_learned: dict[str, int] = {}
_table: dict[str, int] | None = None

# The fields a model list entry states its own maximum output under: on the
# entry itself, or under OpenRouter's ``top_provider``.
OUTPUT_LIMIT_KEYS = ("max_output_tokens", "max_completion_tokens", "max_output_length")


def output_limit_from_model_list(payload: Any, model: str = "") -> int:
    """The maximum output a model list entry declares for ``model``, or zero.

    The entry is chosen as the window's is: the one named ``model``, or the only
    one. Refused past the window this platform believes, as a window is.
    """
    from maljan.llm.context_window import believable

    if not isinstance(payload, dict):
        return 0
    entries = [row for row in (payload.get("data") or []) if isinstance(row, dict)]
    wanted = str(model or "").strip().lower()
    named = [row for row in entries if str(row.get("id") or "").strip().lower() == wanted]
    for row in named or (entries if len(entries) == 1 else []):
        for holder in (row, row.get("top_provider")):
            if not isinstance(holder, dict):
                continue
            for key in OUTPUT_LIMIT_KEYS:
                value = believable(holder.get(key))
                if value > 0:
                    return value
    return 0


def note_from_model_list(payload: Any, model: str = "") -> None:
    """Remember the maximum output a model list answer declares for ``model``."""
    tokens = output_limit_from_model_list(payload, model)
    if tokens > 0 and str(model or "").strip():
        with _lock:
            _learned[str(model).strip().lower()] = int(tokens)


def forget_learned() -> None:
    """Drop what was learned — for a test, or a changed endpoint."""
    with _lock:
        _learned.clear()


def declared_output_limit(model: object) -> int:
    """The maximum output ``model``'s provider declares, in tokens, or zero when none does.

    What a probe learned from the model list first, then the vendored table's
    ``max_output`` rows, keyed as its windows are (``context_window.model_family``).
    """
    from maljan.llm.context_window import model_family

    name = str(model or "").strip().lower()
    if not name:
        return 0
    with _lock:
        learned = _learned.get(name, 0)
    if learned > 0:
        return learned
    rows = _table_rows()
    family = model_family(name)
    for key in sorted(rows, key=len, reverse=True):
        if family.startswith(key):
            return rows[key]
    return 0


def _table_rows() -> dict[str, int]:
    """The vendored table's ``max_output`` rows, read once. Unreadable is empty."""
    global _table
    from maljan.core.paths import resolve_data
    from maljan.llm.context_window import TABLE_PATH

    with _lock:
        if _table is not None:
            return _table
        rows: dict[str, int] = {}
        try:
            raw = json.loads(Path(resolve_data(TABLE_PATH)).read_text(encoding="utf-8"))
            for key, value in (raw.get("max_output") or {}).items():
                if isinstance(value, int) and value > 0:
                    rows[str(key).lower()] = value
        except Exception as exc:  # noqa: BLE001 — a fallback table never fails a run
            logger.debug("the vendored output-limit table could not be read: %s", exc)
        _table = rows
        return _table

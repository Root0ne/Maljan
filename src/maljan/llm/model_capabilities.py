"""What a vendor's own model description says a model takes, kept from the window probe.

The Anthropic Models API (``GET /v1/models/{model_id}``) answers three facts
about a model in one free request, and the window probe
(``context_window.probe_window``) is the one place that asks it:

* ``max_input_tokens``, the window, which the probe reads itself;
* ``max_tokens``, the largest output cap a request may name, which is handed
  to :mod:`maljan.llm.model_output_limits` as the model's declared maximum;
* ``capabilities``, kept here: which effort levels the model takes and which
  thinking configurations it accepts.

A fact is what the description said, or absent. Nothing here is a default:
a model never described answers ``None`` to every question, and its caller
then sends what the operator configured and lets the API answer.
"""

from __future__ import annotations

import threading
from typing import Any

from maljan.core.logger import logger

_lock = threading.Lock()
# The ``capabilities`` object of each model described, keyed by the id asked
# about, lower-cased.
_capabilities: dict[str, dict[str, Any]] = {}


def _key(model: object) -> str:
    return str(model or "").strip().lower()


def note_model_description(payload: Any, model: str, where: str) -> None:
    """Keep what one Models API answer says about ``model``.

    Its output limit goes to :mod:`maljan.llm.model_output_limits` with the
    place it was read from; its capabilities are kept here.
    """
    if not isinstance(payload, dict) or not _key(model):
        return
    from maljan.llm.context_window import believable
    from maljan.llm.model_output_limits import note_declared

    limit = believable(payload.get("max_tokens"))
    if limit > 0:
        note_declared(model, limit, where)
    capabilities = payload.get("capabilities")
    if isinstance(capabilities, dict):
        with _lock:
            _capabilities[_key(model)] = dict(capabilities)
        logger.debug("model capabilities: %s described %s", where, model)


def forget_capabilities() -> None:
    """Drop what was kept — for a test, or a changed key."""
    with _lock:
        _capabilities.clear()


def _supported(holder: Any) -> bool | None:
    if not isinstance(holder, dict):
        return None
    value = holder.get("supported")
    return value if isinstance(value, bool) else None


def capabilities_of(model: object) -> dict[str, Any] | None:
    """The ``capabilities`` object the Models API answered for ``model``, or ``None``."""
    with _lock:
        held = _capabilities.get(_key(model))
    return dict(held) if held is not None else None


def takes_effort(model: object, level: str) -> bool | None:
    """Whether ``model`` takes ``output_config.effort`` at ``level``; ``None`` undescribed."""
    held = capabilities_of(model)
    if held is None:
        return None
    effort = held.get("effort")
    if _supported(effort) is False:
        return False
    if not isinstance(effort, dict):
        return None
    return _supported(effort.get(str(level)))

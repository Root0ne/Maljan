"""Whether the model calls of this process are traced, and the one place the platform switches it.

The tracing library decides from the process environment alone: the first
non-empty of ``LANGSMITH_TRACING_V2`` and ``LANGCHAIN_TRACING_V2``, else of
``LANGSMITH_TRACING`` and ``LANGCHAIN_TRACING``, and tracing is on when that
value is ``true`` (:func:`tracing_in_environment` reads it the same way). The
setting ``langchain_tracing_v2`` is the platform's switch, and a job turns it
into the environment through :func:`apply_tracing_setting`.

The environment is the process's, shared by every job the process runs, so
the switch is undone as well as made: a job with the setting off puts every
variable the platform set back to what the environment held before the
platform first set it, unsetting what the platform added and never clearing
what the operator's own environment holds. An environment that traces with
the setting off is said in a warning, and the run's disclosure block reads
the effective state (``analysis.disclosure``), not the setting alone.
"""

from __future__ import annotations

import os
import threading
from collections.abc import Mapping, MutableMapping

from maljan.core.logger import logger

# The variables the tracing library reads, in the order it reads them.
TRACING_V2_NAMES: tuple[str, ...] = ("LANGSMITH_TRACING_V2", "LANGCHAIN_TRACING_V2")
TRACING_NAMES: tuple[str, ...] = ("LANGSMITH_TRACING", "LANGCHAIN_TRACING")
# What the platform writes when the setting is on.
PLATFORM_NAMES: tuple[str, ...] = ("LANGCHAIN_TRACING_V2", "LANGCHAIN_PROJECT", "LANGCHAIN_API_KEY")

_LOCK = threading.Lock()
# What the environment held for each of ``PLATFORM_NAMES`` before the platform
# first set them; ``None`` while the platform has set nothing.
_BEFORE: dict[str, str | None] | None = None


def _first(environ: Mapping[str, str], names: tuple[str, ...]) -> str:
    for name in names:
        value = environ.get(name)
        if value is not None and value.strip() != "":
            return value
    return ""


def tracing_in_environment(environ: Mapping[str, str] | None = None) -> bool:
    """Whether ``environ`` (the process's by default) turns tracing on, as the library reads it."""
    held = os.environ if environ is None else environ
    return (_first(held, TRACING_V2_NAMES) or _first(held, TRACING_NAMES)) == "true"


def _forget_the_library_reading() -> None:
    """Make the tracing library read the environment again. Never raises.

    It caches each variable it reads, so a variable changed after its first
    read would otherwise go unseen for the life of the process.
    """
    try:
        from langsmith import utils as library

        clear = getattr(getattr(library, "get_env_var", None), "cache_clear", None)
        if callable(clear):
            clear()
    except Exception as exc:  # noqa: BLE001 — a library that is absent traces nothing
        logger.debug("tracing: the library's reading was not refreshed (%s).", type(exc).__name__)


def apply_tracing_setting(
    enabled: bool,
    *,
    project: str = "",
    api_key: str = "",
    environ: MutableMapping[str, str] | None = None,
) -> bool:
    """Turn the setting into the environment, or undo what the platform set. Answer the effect.

    On: the variables are saved, once, as the environment held them, and set.
    Off: each variable the platform set is put back as it was before, unset
    where it was absent. The answer is whether tracing is on afterwards, as
    the library reads the environment; with the setting off and tracing still
    on, the environment's own variables turned it on, which is said in a
    warning.
    """
    global _BEFORE
    held = os.environ if environ is None else environ
    with _LOCK:
        if enabled:
            if _BEFORE is None:
                _BEFORE = {name: held.get(name) for name in PLATFORM_NAMES}
            held["LANGCHAIN_TRACING_V2"] = "true"
            if project:
                held["LANGCHAIN_PROJECT"] = project
            if api_key:
                held["LANGCHAIN_API_KEY"] = api_key
        elif _BEFORE is not None:
            for name, value in _BEFORE.items():
                if value is None:
                    held.pop(name, None)
                else:
                    held[name] = value
            _BEFORE = None
        _forget_the_library_reading()
        traced = tracing_in_environment(held)
    if not enabled and traced:
        logger.warning(
            "LangSmith tracing is on through the process environment while "
            "langchain_tracing_v2 is off: every prompt and answer of this job is sent to the "
            "tracing service, and the run's disclosure block says so."
        )
    return traced


def forget_saved_environment() -> None:
    """Drop what was saved of the environment. For a test that sets the variables itself."""
    global _BEFORE
    with _LOCK:
        _BEFORE = None

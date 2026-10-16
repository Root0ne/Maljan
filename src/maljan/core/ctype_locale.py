"""One locale for the C library's character classes in the platform's own processes.

C code folds case with the C library's ``tolower``, by the process's
``LC_CTYPE``. Under a Turkish or Azerbaijani one a capital I does not fold, since
the dotless ı has no single byte: the YARA engine's ``nocase`` table, built by
the ``LC_CTYPE`` in force when the engine loads, then never matches an I
against an i, and its ``pe.imphash()`` over an import name holding one differs.

Each of the platform's own processes therefore pins ``LC_CTYPE``, and nothing
else, at its start (:func:`pin_character_classification`): messages, times,
collation and numbers stay the operator's. An operator's tool server is its own
process and keeps the environment it was started with.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import locale
import logging
import sys
from collections.abc import Callable
from typing import Any

from maljan.core.logger import logger

# The C library's UTF-8 C locale, in the two spellings C libraries give it.
CANDIDATES: tuple[str, ...] = ("C.UTF-8", "C.utf8")

# The first call's answer, kept for every later call in the process.
_pinned: list[str | None] = []


def _libc() -> Any:
    """The C library this process runs with."""
    try:
        return ctypes.CDLL(None)
    except OSError:  # a platform where the running program exports no libc symbols
        return ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6")


def libc_folds_ascii() -> bool:
    """Whether the C library's ``tolower`` folds ``I`` to ``i`` under the current ``LC_CTYPE``."""
    return int(_libc().tolower(ord("I"))) == ord("i")


def _log(level: int, text: str) -> None:
    logger.log(level, text)


def say_on_stderr(level: int, text: str) -> None:
    """Write the pin's one line to standard error.

    For a process whose standard output is a protocol channel, such as a stdio
    tool server, where a log line on standard output would be read as a
    message.
    """
    print(f"{logging.getLevelName(level)} {text}", file=sys.stderr, flush=True)


def pin_character_classification(say: Callable[[int, str], None] = _log) -> str | None:
    """Pin ``LC_CTYPE`` to the first candidate under which the C library folds ASCII.

    Called at the start of each of the platform's own processes, before any
    thread starts and before anything loads a C library that builds a case
    table as it loads. Only ``LC_CTYPE`` changes, set by name and never from
    the environment. It acts once per process: a later call answers the first
    call's result and changes nothing.

    Answers the ``LC_CTYPE`` in force afterwards: the candidate set, or, when
    no candidate can be set, the process's own locale if it already folds
    ASCII. Answers ``None`` when no locale in reach folds ASCII; the process's
    own is then kept, with a warning. ``say`` writes the one line this states
    (a level and a text), the platform's logger by default.
    """
    if _pinned:
        return _pinned[0]
    before = locale.setlocale(locale.LC_CTYPE)
    chosen: str | None = None
    for name in CANDIDATES:
        try:
            locale.setlocale(locale.LC_CTYPE, name)
        except locale.Error:
            continue
        if libc_folds_ascii():
            chosen = name
            break
    if chosen is not None:
        say(
            logging.INFO,
            f"LC_CTYPE set to {chosen} (it was {before}): C code in this process folds case "
            "as ASCII does.",
        )
    else:
        locale.setlocale(locale.LC_CTYPE, before)
        if libc_folds_ascii():
            chosen = before
            say(
                logging.INFO,
                f"LC_CTYPE stays {before}, which folds case as ASCII does; no candidate "
                f"({', '.join(CANDIDATES)}) could be set.",
            )
        else:
            say(
                logging.WARNING,
                f"LC_CTYPE stays {before}: no candidate ({', '.join(CANDIDATES)}) folds case as "
                "ASCII does here, so C code in this process folds a capital I by this locale.",
            )
    _pinned.append(chosen)
    return chosen

"""One locale for the C library's character classes in the platform's own processes.

C code folds case with the C library's ``tolower``, by the process's
``LC_CTYPE``. Under a Turkish or Azerbaijani one a capital I does not fold, since
the dotless ı has no single byte: the YARA engine's ``nocase`` table, built by
the ``LC_CTYPE`` in force when the engine loads, then never matches an I
against an i, and its ``pe.imphash()`` over an import name holding one differs.

Each of the platform's own processes therefore pins ``LC_CTYPE``, and nothing
else, at its start (:func:`pin_character_classification`): messages, times,
collation and numbers stay the operator's. An operator's tool server is its own
process and keeps the environment it was started with. A YARA pass asks the
engine itself whether its case folding holds (:func:`yara_case_folding_problem`)
before it trusts a ``nocase`` answer.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import functools
import locale
import logging
import sys
from collections.abc import Callable
from typing import Any

from maljan.core.logger import logger

# The C library's UTF-8 C locale, in the two spellings C libraries give it.
CANDIDATES: tuple[str, ...] = ("C.UTF-8", "C.utf8")

# Said by a YARA pass whose engine fails the case-folding self-test.
YARA_FOLDING_BROKEN = (
    "the YARA engine's case folding is broken in this process's locale "
    "(LC_CTYPE={ctype}), so nocase strings and the import-hash clause cannot be checked"
)
# Said by a YARA pass whose engine raised instead of answering the self-test.
YARA_SELF_TEST_FAILED = (
    "the YARA engine's case-folding self-test failed ({why}), so nocase strings and "
    "the import-hash clause cannot be checked"
)
# The self-test's string, far longer than the engine's longest atom (four bytes
# in this build, and a build may set a longer one). A string that fits in one
# atom is matched through the atom's case variants, which the engine builds as
# ASCII whatever the locale, so a test with ``"i"`` passes even where every
# longer string fails; a longer string is verified through the case table the
# engine built by the locale.
_SELF_TEST_TEXT = "i" * 32

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
    encoding = locale.getpreferredencoding(False)
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
        # The candidates are UTF-8 locales: from a host locale that is not, the
        # switch also makes UTF-8 Python's preferred encoding, as in the image.
        now = locale.getpreferredencoding(False)
        changed = (
            f" Python's preferred encoding changes with it, from {encoding} to {now}, "
            "as in the image."
            if now != encoding
            else ""
        )
        say(
            logging.INFO,
            f"LC_CTYPE set to {chosen} (it was {before}): C code in this process folds case "
            f"as ASCII does.{changed}",
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


@functools.cache
def yara_case_folding_problem() -> str | None:
    """Why the YARA engine's ``nocase`` cannot be trusted in this process, or ``None``.

    The engine is asked once per process: a ``nocase`` rule for a run of
    ``i`` (``_SELF_TEST_TEXT``), compiled with includes refused, is matched
    against the same run of ``I``, and the answer is kept, since the engine
    builds its case table once, when it loads. The one place a YARA pass asks
    before it trusts a ``nocase`` answer. ``None`` also when the engine is not
    installed: nothing of its is then trusted. An engine that raises instead of
    answering is not trusted either, and the reason quotes its message rather
    than blaming the locale; the test compiles text and matches bytes, so no
    path can be in it.
    """
    try:
        import yara  # type: ignore[import-untyped]
    except ImportError:
        return None
    try:
        rules = yara.compile(
            source=f'rule t {{ strings: $a = "{_SELF_TEST_TEXT}" nocase condition: $a }}',
            includes=False,
        )
        folds = bool(rules.match(data=_SELF_TEST_TEXT.upper().encode("ascii")))
    except Exception as exc:  # noqa: BLE001 - an engine that cannot run the test is not trusted
        problem = YARA_SELF_TEST_FAILED.format(why=f"{type(exc).__name__}: {exc}")
    else:
        if folds:
            return None
        problem = YARA_FOLDING_BROKEN.format(ctype=locale.setlocale(locale.LC_CTYPE))
    logger.warning("ctype_locale: %s.", problem)
    return problem

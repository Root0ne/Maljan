"""Leave a context variable the way ``ContextVar.reset`` would, in whatever context runs it.

For a ``with`` block whose whole life is inside one task or call. Such a block
sets a context variable and resets it from its ``finally``. When the coroutine
holding the block is closed from another context (a task dropped with its loop,
a generator finalised by the garbage collector), that ``finally`` runs where
the token was not made and ``ContextVar.reset`` raises ``ValueError``, which
Python prints as an unraisable exception. Nothing is left set by it: a task
runs in a copy of its creator's context, so the value the block set lived in a
context that has already ended. This helper says so in a warning and ends the
block; in the context that set the variable it is exactly ``reset``.

It is not for a variable that one context sets and a different one is meant to
reset on purpose: there the failure to reset is the fault, and it is hidden.
"""

from __future__ import annotations

import logging
from contextvars import ContextVar, Token
from typing import Any

_log = logging.getLogger("maljan.core.context_reset")


def reset_in_own_context(var: ContextVar[Any], token: Token[Any]) -> None:
    """``var.reset(token)``, or a warning when this is not the context that made ``token``."""
    try:
        var.reset(token)
    except ValueError:
        _log.warning(
            "context variable %r was not reset: its block ended in another context than the "
            "one that set it (a task closed with its loop); the value died with that context.",
            var.name,
        )

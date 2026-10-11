"""The one argument of a recorded API call a reader asks for, chosen by name priority.

A sandbox files a call's arguments in one of three shapes: a dict of name to
value, a list of such dicts, or a list of ``{"name": ..., "value": ...}`` rows.
A reader that wants "the" registry key, mutex name or written value names
several argument names that can hold it, and the order it names them in is the
order it prefers them in. Taking the first one the call happens to list instead
let a call that lists a handle before the path it opened (``Registry`` before
``FullName``) report the handle as the key.

Each argument is read once into a table, so a call costs the length of its
arguments plus the length of the names asked for.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any


def _present(value: Any) -> bool:
    """Whether an argument carries a value: neither absent nor blank text."""
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    return True


def argument_table(arguments: Any, accept: Callable[[Any], bool] = _present) -> dict[str, Any]:
    """Every argument name a call carries, mapped to the first accepted value filed under it."""
    if isinstance(arguments, dict):
        pools: Iterable[Any] = (arguments,)
    elif isinstance(arguments, list):
        pools = arguments
    else:
        return {}
    table: dict[str, Any] = {}
    for pool in pools:
        if not isinstance(pool, dict):
            continue
        name = pool.get("name")
        if isinstance(name, str) and "value" in pool:
            if name not in table and accept(pool["value"]):
                table[name] = pool["value"]
            continue
        for key, value in pool.items():
            if isinstance(key, str) and key not in table and accept(value):
                table[key] = value
    return table


def pick_argument(
    arguments: Any, names: tuple[str, ...], accept: Callable[[Any], bool] = _present
) -> Any | None:
    """The value of the first of ``names``, in that order, the call holds an accepted value for."""
    table = argument_table(arguments, accept)
    for name in names:
        if name in table:
            return table[name]
    return None

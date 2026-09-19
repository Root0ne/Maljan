"""What one module can reach a symbol by, read out of its own source.

Two guards in this directory walk the tree looking for a call: one for the
helper that puts an exception's text on the live feed, one for the constructor
of a stored finding row. Both used to compare against a single spelling, and
both were told the same thing by a review — an ``import ... as`` renames the
symbol and the walk goes quiet. One resolution, imported by both, because two
answers to "what is this called here" is how one of them keeps a hole the other
closed.
"""

from __future__ import annotations

import ast


def names_reaching(tree: ast.AST, symbol: str) -> set[str]:
    """Every plain name this module can reach ``symbol`` by.

    Its own spelling, and every alias an import gives it. Attribute access
    through a module alias — ``validation.Violation(...)`` — is not a plain
    name and is matched by the attribute of the call instead, which is what the
    callers already do.
    """
    found = {symbol}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Import | ast.ImportFrom):
            continue
        for alias in node.names:
            if alias.asname and alias.name.rsplit(".", 1)[-1] == symbol:
                found.add(alias.asname)
    return found


def called_name(node: ast.AST) -> str:
    """The name a call calls, however it is spelled."""
    func = getattr(node, "func", None)
    return getattr(func, "id", "") or getattr(func, "attr", "")


def names_bound_to(tree: ast.AST, value: str) -> set[str]:
    """Every module-level name this module binds to the string ``value``.

    A code written as a constant is this repository's own idiom —
    ``UNPUBLISHABLE_ENDPOINT_CODE``, ``MALFORMED_HASH_CODE``,
    ``UNGROUNDED_TECHNIQUE_CODE`` are all written that way — so a guard that
    looks for the bare literal is invisible to the next consumer written in
    house style. Module level only: a local of the same value is inside the
    function the guard is already reading.
    """
    found: set[str] = set()
    for node in getattr(tree, "body", []):
        target_names: list[str] = []
        if isinstance(node, ast.Assign):
            target_names = [t.id for t in node.targets if isinstance(t, ast.Name)]
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            target_names = [node.target.id]
        else:
            continue
        if isinstance(node.value, ast.Constant) and node.value.value == value:
            found.update(target_names)
    return found


def names_imported_from(tree: ast.AST, wanted: set[str]) -> set[str]:
    """Every plain name this module can reach one of ``wanted`` by.

    An import renames as freely as it re-exports, so the alias is what the
    reading module actually writes.
    """
    found: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom):
            continue
        for alias in node.names:
            if alias.name in wanted:
                found.add(alias.asname or alias.name)
    return found

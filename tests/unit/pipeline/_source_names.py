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

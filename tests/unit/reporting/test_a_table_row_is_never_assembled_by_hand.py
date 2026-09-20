"""A row in the report's Markdown is built by one helper or it is not built.

Escaping each cell at each call site was tried first and it did not hold. The
sweep was careful, it had a test behind it, and it still left the PE Sections
table assembling its own row — whose first cell is eight raw bytes out of the
section header, `errors="replace"`-decoded and stripped only of NULs and
spaces. A sample named `a|b` shifted every value one column right and dropped
the Notes column; a newline split one section into two rows. A rule that a
reader has to remember is a rule that is eventually forgotten, in a table a
human reads to make a call.

So the rule is structural now. `_row(*cells)` composes the separators and
escapes each cell on the way past, `_divider(n)` writes the rule under a
header, and this test fails the build when anything else in the renderer writes
a `|` into a string. There is nothing to remember: a row a caller cannot write
by hand cannot be written wrong.

Scope is the Markdown renderer alone. The HTML renderer derives from it, the
PDF from the HTML, and the console renders from structured JSON rather than
from Markdown at all, so this one file is where a table is made.
"""

from __future__ import annotations

import ast
from pathlib import Path

RENDERER = (
    Path(__file__).resolve().parents[3]
    / "src"
    / "maljan"
    / "reporting"
    / "renderers"
    / "markdown.py"
)

# The three functions that may name the separator, each because composing it is
# their whole job. Nothing else in the file has a reason to write one.
ALLOWED: dict[str, str] = {
    "_row": "composes a row out of its cells, which is what everything else calls",
    "_divider": "writes the rule under a header row",
    "_cell": "escapes the separator out of one cell, and has to name it to do that",
}


def _enclosing_functions(tree: ast.AST) -> dict[int, str]:
    """Line number → the name of the innermost function that line sits in."""
    owner: dict[int, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        end = node.end_lineno or node.lineno
        for line in range(node.lineno, end + 1):
            # Innermost wins: a nested definition is walked after its parent
            # only by accident of order, so prefer the shorter span.
            previous = owner.get(line)
            if previous is None or _span(tree, node.name) <= _span(tree, previous):
                owner[line] = node.name
    return owner


def _span(tree: ast.AST, name: str) -> int:
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name == name:
            return (node.end_lineno or node.lineno) - node.lineno
    return 10**6


def _string_constants(tree: ast.AST) -> list[tuple[int, str]]:
    """Every string literal in the module, with the line it starts on.

    An f-string's literal halves are ``Constant`` nodes inside a ``JoinedStr``
    and are reached by the same walk, so ``f"| {x} |"`` is caught as surely as
    ``"| a |"``.
    """
    return [
        (node.lineno, node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    ]


class TestTheRendererCannotWriteARowByHand:
    def test_no_string_outside_the_helpers_carries_a_table_separator(self) -> None:
        source = RENDERER.read_text(encoding="utf-8")
        tree = ast.parse(source)
        owner = _enclosing_functions(tree)

        offenders = [
            (lineno, owner.get(lineno, "<module>"), text)
            for lineno, text in _string_constants(tree)
            if "|" in text and owner.get(lineno, "<module>") not in ALLOWED
        ]
        assert not offenders, "\n".join(
            f"markdown.py:{lineno} in {where}: {text!r} — build the row with _row()"
            for lineno, where, text in offenders
        )

    def test_the_allow_list_is_short_and_every_entry_is_still_there(self) -> None:
        """An allow-list nobody reads is an allow-list that grows."""
        tree = ast.parse(RENDERER.read_text(encoding="utf-8"))
        defined = {
            node.name
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
        }
        assert set(ALLOWED) <= defined, sorted(set(ALLOWED) - defined)
        assert len(ALLOWED) <= 3
        assert all(reason.strip() for reason in ALLOWED.values())

    def test_the_guard_catches_a_row_written_the_old_way(self) -> None:
        """The check itself, on a module shaped like the mistake it is for."""
        tree = ast.parse('def _section_x():\n    return f"| {a} | {b} |"\n')
        owner = _enclosing_functions(tree)
        found = [
            (lineno, owner.get(lineno, "<module>"))
            for lineno, text in _string_constants(tree)
            if "|" in text and owner.get(lineno, "<module>") not in ALLOWED
        ]
        assert found and found[0][1] == "_section_x"

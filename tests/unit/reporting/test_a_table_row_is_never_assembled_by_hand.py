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

Scope is the Markdown renderer alone, and that is where the report's tables
are made: the HTML renderer derives from it, the PDF from the HTML, and the
console renders from structured JSON rather than from Markdown at all. Two
other modules also emit Markdown tables and are outside this check --
``analysis/run_summary.py`` and ``parsers/base_parser.py``. Neither renders a
report and neither puts a sample-written or model-written value in a cell, so
the exposure this guard exists for is not theirs; if either ever grows one,
it needs a guard of its own rather than a mention here.
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
# their whole job. Nothing else in the file has a reason to write one, and the
# names are matched against a qualified owner, so a method or a nested function
# cannot take one of them and write a row under its cover.
#
# The rule the check applies is broader than it sounds: no string literal
# outside these three may contain a ``|`` at all. A regular expression with an
# alternation and a sentence of prose that happens to use the character both
# trip it. Nothing in the renderer needs either today; the next edit that does
# has to restructure or widen this list on purpose rather than work around it.
ALLOWED: dict[str, str] = {
    "_row": "composes a row out of its cells, which is what everything else calls",
    "_divider": "writes the rule under a header row",
    "_cell": "escapes the separator out of one cell, and has to name it to do that",
}


def _enclosing_functions(tree: ast.AST) -> dict[int, str]:
    """Line number → the qualified name of the innermost function holding it.

    Qualified, because the allow-list is a list of three module-level
    functions and nothing else may borrow one of their names. A method or a
    nested definition called ``_row`` reads as ``R._row`` or ``outer._row``
    here, neither of which the allow-list holds, so the only way to write a
    separator is to be the helper itself.
    """
    owner: dict[int, str] = {}

    def descend(node: ast.AST, path: tuple[str, ...]) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                here = (*path, child.name)
                if not isinstance(child, ast.ClassDef):
                    end = child.end_lineno or child.lineno
                    for line in range(child.lineno, end + 1):
                        owner[line] = ".".join(here)
                # After its own span, so an inner definition overwrites the
                # outer one and the innermost owner is the one that stands.
                descend(child, here)
            else:
                descend(child, path)

    descend(tree, ())
    return owner


def _module_level_functions(tree: ast.AST) -> set[str]:
    return {
        node.name
        for node in ast.iter_child_nodes(tree)
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
    }


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
        defined = _module_level_functions(tree)
        assert set(ALLOWED) <= defined, sorted(set(ALLOWED) - defined)
        assert len(ALLOWED) <= 3
        assert all(reason.strip() for reason in ALLOWED.values())

    def test_a_borrowed_name_does_not_buy_the_separator(self) -> None:
        """A method or a nested function may not write a row by taking a name."""
        borrowed = (
            "class R:\n"
            "    def _row(self):\n"
            '        return "| hand | written |"\n'
            "\n\n"
            "def outer():\n"
            "    def _cell():\n"
            '        return "| also | hand |"\n'
            "    return _cell\n"
        )
        tree = ast.parse(borrowed)
        owner = _enclosing_functions(tree)
        caught = {
            owner.get(lineno, "<module>")
            for lineno, text in _string_constants(tree)
            if "|" in text and owner.get(lineno, "<module>") not in ALLOWED
        }
        assert caught == {"R._row", "outer._cell"}

    def test_the_helpers_themselves_are_still_allowed(self) -> None:
        """The qualified owner of a module-level helper is its bare name."""
        tree = ast.parse('def _row(*cells):\n    return "| " + " | ".join(cells) + " |"\n')
        owner = _enclosing_functions(tree)
        assert set(owner.values()) == {"_row"}
        assert not [
            lineno
            for lineno, text in _string_constants(tree)
            if "|" in text and owner.get(lineno, "<module>") not in ALLOWED
        ]

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

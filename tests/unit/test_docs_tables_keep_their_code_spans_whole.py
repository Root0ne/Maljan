"""A docs table cell never splits a code span.

GitHub-flavoured Markdown splits a table row at every unescaped ``|`` before it
reads code spans, so a ``|`` inside backticks in a table ends the cell, the
code span is left open, and MDX then reads a brace after it as an expression:
the docs site fails to build. A ``|`` in a table's code span is written ``\\|``.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "apps" / "docs" / "content"
_CELL_BREAK = re.compile(r"(?<!\\)\|")


def test_no_table_cell_leaves_a_code_span_open() -> None:
    broken = [
        f"{page.relative_to(ROOT)}:{number}"
        for page in sorted(DOCS.rglob("*.mdx"))
        for number, line in enumerate(page.read_text(encoding="utf-8").splitlines(), 1)
        if line.lstrip().startswith("|")
        and any(cell.count("`") % 2 for cell in _CELL_BREAK.split(line))
    ]
    assert not broken, f"a table cell splits a code span (write `\\|` inside it): {broken}"

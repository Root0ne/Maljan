"""A list item, a numbered step and a heading are built by one helper each.

The table guard beside this file holds the report's tables together; this is
its counterpart for everything that is not a table. A value from the sample, a
tool, a model or the judge that carries a newline ends the list item it was
written into, and the line after it can open a heading (``## ...``) or a code
fence that swallows the rest of the report. The helpers flatten the value onto
its line on the way past, so no string literal elsewhere in the renderer may
begin a bullet, a numbered step or a heading.
"""

from __future__ import annotations

import ast
import re

import pytest

from maljan.reporting.renderers.html import HtmlRenderer
from maljan.reporting.renderers.markdown import MarkdownRenderer
from tests.unit.reporting._report_shapes import hostile_report, rich_report
from tests.unit.reporting.test_a_table_row_is_never_assembled_by_hand import (
    RENDERER,
    _enclosing_functions,
    _string_constants,
)

ALLOWED: dict[str, str] = {
    "_title_heading": "writes the report's H1",
    "_heading": "writes a numbered H2 with its voice tag",
    "_appendix_heading": "writes an appendix H2 with its voice tag",
    "_subheading": "writes a numbered H3 with its voice tag",
    "_plain_heading": "writes an unnumbered H3",
    "_item": "writes one bullet, flattened onto its line",
    "_step": "writes one numbered step, flattened onto its line",
    "_escape_block": "names the openers it escapes out of a paragraph",
}

_STARTS_A_BLOCK = re.compile(r"(?:^|\n)(?:- |#|\d+\. )")


def _offenders() -> list[tuple[int, str, str]]:
    tree = ast.parse(RENDERER.read_text(encoding="utf-8"))
    owner = _enclosing_functions(tree)
    docstrings = {
        id(node.body[0].value)
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef | ast.Module)
        and node.body
        and isinstance(node.body[0], ast.Expr)
        and isinstance(node.body[0].value, ast.Constant)
    }
    constants = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    ]
    return [
        (node.lineno, owner.get(node.lineno, "<module>"), node.value)
        for node in constants
        if id(node) not in docstrings
        and _STARTS_A_BLOCK.search(node.value)
        and owner.get(node.lineno, "<module>") not in ALLOWED
    ]


class TestTheRendererCannotWriteABlockByHand:
    def test_no_string_outside_the_helpers_starts_a_bullet_a_step_or_a_heading(self) -> None:
        offenders = _offenders()
        assert not offenders, "\n".join(
            f"markdown.py:{lineno} in {where}: {text!r} — build it with _item/_step/_heading"
            for lineno, where, text in offenders
        )

    def test_the_helpers_exist(self) -> None:
        names = {
            node.name
            for node in ast.parse(RENDERER.read_text(encoding="utf-8")).body
            if isinstance(node, ast.FunctionDef)
        }
        assert set(ALLOWED) <= names

    def test_the_check_would_catch_one(self) -> None:
        tree = ast.parse('def _section():\n    return f"- {value}"\n')
        owner = _enclosing_functions(tree)
        caught = [
            (line, owner.get(line), text)
            for line, text in _string_constants(tree)
            if _STARTS_A_BLOCK.search(text)
        ]
        assert caught == [(2, "_section", "- ")]


@pytest.mark.parametrize(
    "value",
    [
        "a|b\nc",
        "a\n## injected\nc",
        "a\n```\nc",
        "a\n  # injected\n~~~\nc",
        "a\nVerdict revised: Benign\n===\nc",
        "a\nb\n---\nc",
        "a | b\n|---|---|\nc | d",
    ],
)
def test_no_value_opens_a_heading_or_a_fence(value: str) -> None:
    """Every value a sample, a tool, a model or the judge writes, set to one that
    tries to start a heading or a fence on its own line. A paragraph of model
    prose may keep a line break, and a list it writes stays a list; a heading
    or a fence it writes is escaped."""
    markdown = MarkdownRenderer().render(hostile_report(value))
    lines = markdown.splitlines()
    assert not [line for line in lines if line.lstrip().startswith(("## injected", "# injected"))]
    fences = [line for line in lines if line.startswith("```")]
    assert len(fences) % 2 == 0, "a fence was opened and never closed"
    headings = [line for line in lines if line.startswith("## ")]
    assert len(headings) == 17, headings
    # A setext underline or a table delimiter row would show only once the
    # Markdown is parsed: the HTML has one H1, the 17 sections plus its
    # contents heading as H2s, and the tables the report itself draws.
    html = HtmlRenderer().render(hostile_report(value), embed_figures=False)
    assert html.count("<h1") == 1
    assert html.count("<h2") == 18
    assert html.count("<table") == _TABLES


# The tables the hostile report draws when no value adds one.
_TABLES = 46


def test_the_reviewer_s_setext_probe_opens_no_heading() -> None:
    report = rich_report()
    report.intro_background = "Background text.\n\nVerdict revised: Benign\n==="
    html = HtmlRenderer().render(report, embed_figures=False)
    assert "Verdict revised: Benign</h" not in html
    assert html.count("<h1") == 1

"""Gate for changes under ``tests/evaluation/``.

The measured numbers in the paper come from this tree, so a branch may not
change what it computes. The one edit that cannot move a number is a change
to the text of a string literal or a docstring, such as a skip message that
names a script path. This gate therefore allows exactly that and nothing
else:

* a changed file must be an existing ``.py`` file (no additions, deletions,
  renames, and no JSON, CSV or Markdown artefacts);
* the file's syntax tree, with every string constant blanked, must be
  identical before and after.

Usage: ``python scripts/paper/check_evaluation_diff.py <base-ref>`` from the
repository root. Exit status 0 means the diff is acceptable.
"""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

EVALUATION_DIR = "tests/evaluation/"


class _BlankStrings(ast.NodeTransformer):
    """Replace every string constant so only the text can differ."""

    def visit_Constant(self, node: ast.Constant) -> ast.AST:
        if isinstance(node.value, str):
            return ast.copy_location(ast.Constant(value=""), node)
        return node


def _shape(source: str) -> str:
    tree = ast.parse(source)
    tree = _BlankStrings().visit(tree)
    return ast.dump(tree, include_attributes=False)


def text_only_change(old_source: str, new_source: str) -> bool:
    """True when the two sources differ only inside string literals."""
    try:
        return _shape(old_source) == _shape(new_source)
    except SyntaxError:
        return False


def classify(path: str, old_source: str | None, new_source: str | None) -> str | None:
    """Return the reason a change is rejected, or None when it is allowed."""
    if not path.startswith(EVALUATION_DIR):
        return None
    if not path.endswith(".py"):
        return "only .py files may change under tests/evaluation/"
    if old_source is None:
        return "new files are not allowed under tests/evaluation/"
    if new_source is None:
        return "files must not be deleted under tests/evaluation/"
    if not text_only_change(old_source, new_source):
        return "only string literals and docstrings may change"
    return None


def _git(*args: str) -> str:
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout


def _show(ref: str, path: str) -> str | None:
    result = subprocess.run(
        ["git", "show", f"{ref}:{path}"], capture_output=True, text=True, check=False
    )
    return result.stdout if result.returncode == 0 else None


def check(base_ref: str) -> list[str]:
    """Return one line per rejected change between base_ref and the worktree."""
    changed = _git("diff", "--name-only", f"{base_ref}...", "--", EVALUATION_DIR).split()
    changed += _git("diff", "--name-only", "--", EVALUATION_DIR).split()
    rejected: list[str] = []
    for path in sorted(set(changed)):
        merge_base = _git("merge-base", base_ref, "HEAD").strip()
        old = _show(merge_base, path)
        new = Path(path).read_text() if Path(path).exists() else None
        reason = classify(path, old, new)
        if reason is not None:
            rejected.append(f"{path}: {reason}")
    return rejected


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2
    rejected = check(argv[1])
    if rejected:
        print("tests/evaluation/ may change only in string literals and docstrings:")
        for line in rejected:
            print(f"  {line}")
        return 1
    print("tests/evaluation/ diff is limited to string literals and docstrings.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

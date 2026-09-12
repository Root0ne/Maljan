"""No component may quietly rewrite what an agent decided.

This is the phase's direction, enforced rather than described. Five attribute
names carry a decision somebody made: a claim's ``technique_id`` and
``confidence``, and a report's ``severity``, ``malware_category`` and
``family``. Every layer that used to write one of them wrote it over an
answer that already existed — the cascade over the analyst's confidence, the
autocorrect over its technique id, the report builder's arithmetic over a
severity the judge was never asked for.

Three places may still write them, because in each the write *is* the answer
rather than a correction of one:

* ``schemas/`` — the models these live on, where a field is constructed.
* ``tools/`` — a tool reporting what it found.
* ``pipeline/validation.py`` — the one place a finding is recorded, and even
  there only as a validity flag or a drop that the run summary carries.

Constructing a fresh object is always fine: ``Claim(technique_id=...)`` is not
an override of anything, and only *assignment to an attribute of an existing
object* is caught. Nothing about this test is a style rule; a failure means a
decision is being replaced somewhere a reader of the report cannot see.
"""

from __future__ import annotations

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src" / "maljan"

# The attribute names that carry a decision.
GUARDED = frozenset({"technique_id", "confidence", "severity", "malware_category", "family"})

# Where a write to one of them is the answer rather than an override of one.
EXEMPT_PATHS = ("schemas/", "tools/", "pipeline/validation.py")

# Empty, and worth keeping empty. It exists for a parser that has to fill one
# of these fields in on an object it is still building — the brief allows that
# — but no parser needs it today, and an exemption added without a reason is
# the hole this test exists to close.
WHITELIST: frozenset[str] = frozenset()


def _relative(path: Path) -> str:
    return path.relative_to(SRC).as_posix()


def _is_exempt(relative: str) -> bool:
    return relative in WHITELIST or any(relative.startswith(prefix) for prefix in EXEMPT_PATHS)


def _guarded_attribute(node: ast.expr) -> str | None:
    """The guarded name this target writes, when it writes one on an object.

    ``obj.severity = x`` counts. ``severity = x`` does not: a bare local is not
    somebody else's decision, and the object it eventually reaches is
    constructed from it, which is a construction rather than an override.
    """
    if isinstance(node, ast.Attribute) and node.attr in GUARDED:
        return node.attr
    return None


def _setattr_target(node: ast.Call) -> str | None:
    """The guarded name a ``setattr(obj, "severity", x)`` call writes."""
    func = node.func
    name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
    if name != "setattr" or len(node.args) < 2:  # noqa: PLR2004 — setattr takes three
        return None
    key = node.args[1]
    if isinstance(key, ast.Constant) and key.value in GUARDED:
        return str(key.value)
    return None


def _constructor_selves(tree: ast.AST) -> set[int]:
    """Line numbers inside an ``__init__``, where ``self.x = x`` is construction.

    Storing a constructor argument on the object being built is not an
    override of anything: nothing has decided the value yet.
    """
    inside: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name == "__init__":
            for child in ast.walk(node):
                if hasattr(child, "lineno"):
                    inside.add(child.lineno)
    return inside


def _offences(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    relative = _relative(path)
    constructor_lines = _constructor_selves(tree)
    found: list[str] = []

    for node in ast.walk(tree):
        targets: list[ast.expr] = []
        if isinstance(node, ast.Assign):
            targets = list(node.targets)
        elif isinstance(node, ast.AugAssign | ast.AnnAssign):
            targets = [node.target]
        elif isinstance(node, ast.Call):
            attribute = _setattr_target(node)
            if attribute:
                found.append(f"{relative}:{node.lineno}: setattr(..., {attribute!r}, ...)")
            continue

        for target in targets:
            attribute = _guarded_attribute(target)
            if attribute is None:
                continue
            written_on = getattr(target, "value", None)
            if (
                isinstance(written_on, ast.Name)
                and written_on.id == "self"
                and node.lineno in constructor_lines
            ):
                continue
            found.append(f"{relative}:{node.lineno}: assignment to .{attribute}")

    return found


def test_nothing_outside_schemas_tools_and_validation_overrides_a_decision():
    offences: list[str] = []
    for path in sorted(SRC.rglob("*.py")):
        relative = _relative(path)
        if _is_exempt(relative):
            continue
        offences.extend(_offences(path))

    assert not offences, (
        "These write a decision an agent already made, where a reader of the "
        "report cannot see it happen. Report it as a "
        "``pipeline.validation.Violation`` and give the producer a turn to fix "
        "it, or construct a fresh object instead of assigning to an existing "
        "one:\n  " + "\n  ".join(offences)
    )


def test_the_guard_would_catch_an_override():
    """The test above passes trivially if the scan is broken, so prove it is not."""
    source = (
        "def f(claim, report):\n    claim.confidence = 0.4\n    setattr(report, 'severity', x)\n"
    )
    path = SRC / "__guard_probe__.py"
    try:
        path.write_text(source, encoding="utf-8")
        offences = _offences(path)
    finally:
        path.unlink(missing_ok=True)

    assert [o.split(": ", 1)[1] for o in offences] == [
        "assignment to .confidence",
        "setattr(..., 'severity', ...)",
    ]


def test_every_exempt_path_and_whitelist_entry_still_exists():
    """A stale exemption is a hole nobody notices."""
    for prefix in EXEMPT_PATHS:
        assert (SRC / prefix).exists(), f"{prefix} no longer exists; drop the exemption"
    for entry in WHITELIST:
        assert (SRC / entry).exists(), f"{entry} no longer exists; drop the whitelist entry"

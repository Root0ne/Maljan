"""No component may quietly rewrite what an agent decided.

This is the phase's direction, enforced rather than described. Five names carry
a decision somebody made: a claim's ``technique_id`` and ``confidence``, and a
report's ``severity``, ``malware_category`` and ``family``. Every layer that
used to write one of them wrote it over an answer that already existed — the
cascade over the analyst's confidence, the autocorrect over its technique id,
the report builder's arithmetic over a severity the judge was never asked for.

Both spellings are scanned, because the judge's bundle is a plain ``dict`` for
the whole of ``agents/judge_postprocess.py`` and an override there would be
``obj["confidence"] = …`` rather than an attribute write.

Three places may still write them, because in each the write *is* the answer
rather than a correction of one:

* ``schemas/`` — the models these live on, where a field is constructed.
* ``tools/`` — a tool reporting what it found.
* ``pipeline/validation.py`` — the one place a finding is recorded, and even
  there only as a validity flag or a drop that the run summary carries.

Constructing a fresh object is always fine: ``Claim(technique_id=...)`` and
``{"confidence": x}`` are not overrides of anything, so only assignment to an
attribute or a key of an object that already exists is caught. Nothing about
this test is a style rule; a failure means a decision is being replaced
somewhere a reader of the report cannot see.
"""

from __future__ import annotations

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src" / "maljan"

# The names that carry a decision.
GUARDED = frozenset({"technique_id", "confidence", "severity", "malware_category", "family"})

# Where a write to one of them is the answer rather than an override of one.
EXEMPT_PATHS = ("schemas/", "tools/", "pipeline/validation.py")

# Empty, and worth keeping empty. It exists for a module that has to fill one
# of these fields in on an object it is still building — the brief allows that
# — but nothing needs it today, and an exemption added without a reason is the
# hole this test exists to close.
WHITELIST: frozenset[str] = frozenset()


def _relative(path: Path) -> str:
    return path.relative_to(SRC).as_posix()


def _is_exempt(relative: str) -> bool:
    return relative in WHITELIST or any(relative.startswith(prefix) for prefix in EXEMPT_PATHS)


def _guarded_target(node: ast.expr) -> str | None:
    """The guarded name this target writes, when it writes one on an object.

    ``obj.severity = x`` and ``obj["severity"] = x`` both count. A bare local
    (``severity = x``) does not: it is not somebody else's decision, and the
    object it eventually reaches is constructed from it. A computed key
    (``obj[name] = x``) does not either — there is nothing to read.
    """
    if isinstance(node, ast.Attribute) and node.attr in GUARDED:
        return node.attr
    if isinstance(node, ast.Subscript):
        key = node.slice
        if isinstance(key, ast.Constant) and key.value in GUARDED:
            return str(key.value)
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


def _constructor_lines(tree: ast.AST) -> set[int]:
    """Line numbers inside an ``__init__``."""
    inside: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name == "__init__":
            for child in ast.walk(node):
                if hasattr(child, "lineno"):
                    inside.add(child.lineno)
    return inside


def _is_constructor_passthrough(
    node: ast.stmt, target: ast.expr, constructor_lines: set[int]
) -> bool:
    """``self.severity = severity`` inside an ``__init__`` — storing an argument.

    Deliberately narrow on both axes. It must be inside a constructor, and the
    value must be a *bare name*: nothing has decided it yet, this is the object
    being built, and the value passes straight through.
    ``self.severity = compute(...)`` in an ``__init__`` is a decision like any
    other and is caught, and so is any write outside one.
    """
    if node.lineno not in constructor_lines:
        return False
    if not (
        isinstance(target, ast.Attribute)
        and isinstance(target.value, ast.Name)
        and target.value.id == "self"
    ):
        return False
    return isinstance(getattr(node, "value", None), ast.Name)


def offences(source: str, label: str) -> list[str]:
    """Every guarded write in ``source``, as ``label:line: description``."""
    tree = ast.parse(source, filename=label)
    constructor_lines = _constructor_lines(tree)
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
                found.append(f"{label}:{node.lineno}: setattr(..., {attribute!r}, ...)")
            continue

        for target in targets:
            name = _guarded_target(target)
            if name is None or _is_constructor_passthrough(node, target, constructor_lines):
                continue
            how = "key" if isinstance(target, ast.Subscript) else "attribute"
            found.append(f"{label}:{node.lineno}: assignment to {how} {name!r}")

    return found


def test_nothing_outside_schemas_tools_and_validation_overrides_a_decision():
    found: list[str] = []
    for path in sorted(SRC.rglob("*.py")):
        relative = _relative(path)
        if _is_exempt(relative):
            continue
        found.extend(offences(path.read_text(encoding="utf-8"), relative))

    assert not found, (
        "These write a decision an agent already made, where a reader of the "
        "report cannot see it happen. Report it as a "
        "``pipeline.validation.Violation`` and give the producer a turn to fix "
        "it, or construct a fresh object instead of writing into an existing "
        "one:\n  " + "\n  ".join(found)
    )


class TestTheScannerWouldActuallyCatchOne:
    """The test above passes trivially if the scan is broken, so prove it is not.

    Every probe is a source *string*. Planting a module in ``src/maljan`` to
    prove the scanner works would leave a stray file in the installed package
    if the run were interrupted, and could be walked by the scanning test above
    while it existed.
    """

    def test_an_attribute_write_is_caught(self):
        assert offences("claim.confidence = 0.4\n", "probe.py") == [
            "probe.py:1: assignment to attribute 'confidence'"
        ]

    def test_a_dict_key_write_is_caught(self):
        assert offences("obj['severity'] = 'High'\n", "probe.py") == [
            "probe.py:1: assignment to key 'severity'"
        ]

    def test_setattr_is_caught(self):
        assert offences("setattr(report, 'family', name)\n", "probe.py") == [
            "probe.py:1: setattr(..., 'family', ...)"
        ]

    def test_an_augmented_assignment_is_caught(self):
        assert offences("claim.confidence += 0.1\n", "probe.py") == [
            "probe.py:1: assignment to attribute 'confidence'"
        ]

    def test_constructing_a_fresh_object_is_not_caught(self):
        assert offences("c = Claim(technique_id='T1055', confidence=0.8)\n", "probe.py") == []

    def test_a_fresh_dict_literal_is_not_caught(self):
        assert offences("row = {'confidence': 0.8, 'severity': 'High'}\n", "probe.py") == []

    def test_a_bare_local_is_not_caught(self):
        assert offences("severity = compute()\n", "probe.py") == []

    def test_a_computed_key_is_not_caught(self):
        assert offences("row[name] = value\n", "probe.py") == []

    def test_a_constructor_passthrough_is_exempt(self):
        source = "class A:\n    def __init__(self, severity):\n        self.severity = severity\n"

        assert offences(source, "probe.py") == []

    def test_a_constructor_that_computes_the_value_is_not_exempt(self):
        source = "class A:\n    def __init__(self, data):\n        self.severity = score(data)\n"

        assert offences(source, "probe.py") == ["probe.py:3: assignment to attribute 'severity'"]

    def test_a_write_outside_a_constructor_is_never_exempt(self):
        source = "class A:\n    def later(self, severity):\n        self.severity = severity\n"

        assert offences(source, "probe.py") == ["probe.py:3: assignment to attribute 'severity'"]


def test_every_exempt_path_and_whitelist_entry_still_exists():
    """A stale exemption is a hole nobody notices."""
    for prefix in EXEMPT_PATHS:
        assert (SRC / prefix).exists(), f"{prefix} no longer exists; drop the exemption"
    for entry in WHITELIST:
        assert (SRC / entry).exists(), f"{entry} no longer exists; drop the whitelist entry"

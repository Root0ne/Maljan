"""Write generated tool declarations with the API's answers, for the console's box.

The console's tool-declaration box and the API must count a field as set the
same way and the box must never refuse what the API accepts. A hand-written
case table (``tool-declaration-cases.json``) holds the cases that drove the
rules; this file holds a generated set beside it: every declaration field
alone or beside another field, at its default, at a valid value and at each of
a list of odd values (falsy words a yes-or-no field is read as, empty values,
wrong types), under every spelling of the kind, plus pairs of kind-dependent
fields. For each, the API's answer: whether an operator's edit is accepted,
whether the no-kind word names no kind, and the fields it counts as set.
``declarationFields.test.ts`` runs the box over the same declarations and
``tests/unit/api/test_the_console_reads_tool_declarations_as_the_api_does.py``
fails when this file no longer matches the API. Run from the repository root:

    PYTHONPATH=src:apps/api python scripts/dev/write_tool_declaration_cases.py
"""

from __future__ import annotations

import itertools
import json
from pathlib import Path
from typing import Any

FIXTURE = Path("apps/web/src/test-fixtures/tool-declaration-generated.json")

# A valid value of each field, written as an operator would.
_GOOD: dict[str, Any] = {
    "display_name": "X",
    "category": "cat",
    "words": ["w"],
    "timeout_seconds": 5,
    "long_running": True,
    "memory_peak_mb": 100,
    "discloses_sample": True,
    "arguments": {"path": "file_path"},
    "asserts_techniques": True,
    "source": "sigma",
    "holds_strings": True,
    "rows": "/m/*",
    "function_starts": "/f",
    "places": {"offset": "/o"},
    "values": {"text": "/t"},
    "techniques": [{"path": "/tags/*"}],
    "reputation": {"service": "svc"},
    "reader": "flow_table",
    "report_sections": ["sec"],
}
# Values that read differently as written and as a model reads them, or not at
# all. JSON numbers are whole, so the console parses them as the API does.
_ODD: tuple[Any, ...] = (
    "",
    [],
    {},
    None,
    0,
    1,
    2,
    False,
    True,
    "false",
    "0",
    "NO",
    "off",
    "yes",
    "x",
    [""],
)
_ABSENT = "<absent>"
_KINDS: tuple[Any, ...] = (_ABSENT, "", "unclassified", "strings")
_BESIDE: tuple[dict[str, Any], ...] = ({}, {"display_name": "X"})


def _declarations() -> list[dict[str, Any]]:
    from maljan.core.tool_declarations import (
        KIND_DEPENDENT_FIELDS,
        KIND_FREE_FIELDS,
        ToolFacts,
    )

    defaults = ToolFacts.model_construct().model_dump(mode="json")
    out: list[dict[str, Any]] = []
    for name in (*KIND_FREE_FIELDS, *KIND_DEPENDENT_FIELDS):
        for value in (defaults[name], _GOOD[name], *_ODD):
            for kind in _KINDS:
                for beside in _BESIDE:
                    if name in beside:
                        continue
                    declaration = dict(beside)
                    if kind != _ABSENT:
                        declaration["kind"] = kind
                    declaration[name] = value
                    out.append(declaration)
    for left, right in itertools.combinations(KIND_DEPENDENT_FIELDS, 2):
        for kind in _KINDS:
            declaration = {left: _GOOD[left], right: _GOOD[right]}
            if kind != _ABSENT:
                declaration["kind"] = kind
            out.append(declaration)
    seen: set[str] = set()
    unique = []
    for declaration in out:
        text = json.dumps(declaration, sort_keys=True)
        if text not in seen:
            seen.add(text)
            unique.append(declaration)
    return unique


def answers(declaration: dict[str, Any]) -> list[Any]:
    """The API's answer for one declaration: accepted, names no kind, the fields set."""
    from maljan.core.tool_declarations import (
        ToolFacts,
        is_set,
        reads_no_kind,
        strict_declarations,
    )

    try:
        with strict_declarations():
            ToolFacts.model_validate(declaration)
        accepted = True
    except ValueError:
        accepted = False
    fields = ToolFacts.model_fields
    named = sorted(
        key
        for key, value in declaration.items()
        if key != "kind" and key in fields and is_set(key, value)
    )
    return [accepted, reads_no_kind(declaration), named]


def rendered() -> str:
    """The generated cases as the fixture holds them: one per line."""
    lines = [
        json.dumps([declaration, *answers(declaration)], sort_keys=True, separators=(",", ":"))
        for declaration in _declarations()
    ]
    about = json.dumps(
        "Generated tool declarations with the API's answers: [declaration, accepted, "
        "reads_no_kind, fields set]. Written by scripts/dev/write_tool_declaration_cases.py."
    )
    return '{"_about": ' + about + ',\n "cases": [\n' + ",\n".join(lines) + "\n]}\n"


if __name__ == "__main__":
    FIXTURE.parent.mkdir(parents=True, exist_ok=True)
    FIXTURE.write_text(rendered(), encoding="utf-8")
    print(f"wrote {FIXTURE}")

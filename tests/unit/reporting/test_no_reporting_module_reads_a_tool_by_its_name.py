"""No module in ``maljan.reporting`` reads an entry's tool by a tool's name.

The report reads a tool by the kind its entry stored (``reporting.tool_kinds``
over ``core.declared_reading``). The detection is the one both guards share
(``tests/tool_name_reads.py``): it follows a tool read through locals, string
methods, f-strings, ``getattr``, subscripts and ``.get``, and fails on a
comparison, membership test, ``match``, name test, ``getattr`` or dictionary
lookup against anything that is not itself a tool read, and on an import of a
legacy table module.

The tables that read an entry with no recorded source by name live in one
module, ``reporting/legacy_tool_names.py``, exempt by its exact path. Only
``reporting/tool_kinds.py`` imports it (the gateway), and there only on a
branch for an entry with no source (``source_of(...) is None``) or in a
``stored_*`` function, which serves records written before sources.

The legacy module's own reads are pinned below, as a multiset with a reason
each: they may only shrink, so no new name table is added there. The
gateway's ``stored_*`` helpers read a tool by name, so a call to one with a
tool's name (a literal name of a shipped tool, or a value read from an
entry's tool) is allowed only inside the gateway, on its branches for an
entry read by name (``read_by_name(...)``, ``source_of(...) is None``) or in
another ``stored_*`` function.
"""

from __future__ import annotations

import ast
from collections import Counter
from pathlib import Path

import pytest

from tests.tool_name_reads import NAME_READ_SNIPPETS, findings, tool_parameters_under, violations

REPORTING = Path(__file__).resolve().parents[3] / "src" / "maljan" / "reporting"
EXEMPT = REPORTING / "legacy_tool_names.py"
GATEWAY = REPORTING / "tool_kinds.py"
# Helpers any module of the product defines, for a literal handed to one imported.
SHARED = tool_parameters_under(REPORTING.parent)


def _modules() -> list[Path]:
    return sorted(p for p in REPORTING.rglob("*.py") if p != EXEMPT)


@pytest.mark.parametrize("path", _modules(), ids=lambda p: str(p.relative_to(REPORTING)))
def test_no_reporting_module_reads_a_tool_by_its_name(path: Path) -> None:
    source = path.read_text(encoding="utf-8")
    assert violations(source, path.name, gateway=path == GATEWAY, shared=SHARED) == []


def test_the_exemption_is_the_one_module_by_its_path() -> None:
    assert EXEMPT.is_file()
    assert [p for p in REPORTING.rglob("*.py") if p.name == EXEMPT.name] == [EXEMPT]


_TABLE = "the old report table, read for an entry with no recorded source"

# (what, code) -> (count, why). The counts may only shrink.
LEGACY_READS: dict[tuple[str, str], tuple[int, str]] = {
    ("compares", "name == tool"): (
        1,
        "a stored recovery's tool to its kind (stored_recovery_kind)",
    ),
    ("compares", "tool in order"): (1, "a consumer's fixed order (rank)"),
    ("compares", "'sandbox' not in tool"): (1, _TABLE + ": the file tools (looked_at_the_file)"),
    ("startswith", "tool.startswith(MARKDOWN_SANDBOX_TOOLS)"): (1, _TABLE + ": the sandbox tools"),
    ("compares", "tool not in REPUTATION_TOOLS"): (1, _TABLE + ": the reputation lookups"),
    ("compares", "hint in tool"): (1, _TABLE + ": the composer's section hints"),
    ("compares", "tool in legacy_names(consumer)"): (1, "a consumer's legacy names, frozen"),
    ("looks", "_builtin_by_name().get(str(tool or ''))"): (1, "a stored tool's frozen facts"),
}


def _legacy_reads() -> Counter[tuple[str, str]]:
    held = findings(EXEMPT.read_text(encoding="utf-8"), EXEMPT.name)
    return Counter((f.what.split()[0], f.text) for f in held)


def test_the_legacy_module_s_reads_are_the_pinned_ones() -> None:
    found = _legacy_reads()
    over = {k: n for k, n in found.items() if n > LEGACY_READS.get(k, (0, ""))[0]}
    assert not over, over


def test_the_legacy_module_s_pinned_reads_only_shrink() -> None:
    found = _legacy_reads()
    stale = {k: n for k, (n, _why) in LEGACY_READS.items() if found[k] < n}
    assert not stale, stale


def _tool_names() -> frozenset[str]:
    from maljan.core.builtin_declarations import CONSUMER_KINDS
    from maljan.core.declared_reading import shipped_by_name

    names = set(shipped_by_name())
    for spec in CONSUMER_KINDS.values():
        names |= set(spec.get("legacy_names", ()))
    return frozenset(names)


def _reads_a_tool(node: ast.AST) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Attribute) and sub.attr in ("tool", "tool_name"):
            return True
        if isinstance(sub, ast.Name) and (
            sub.id in ("tool", "tool_name") or sub.id.endswith("_tool")
        ):
            return True
        if isinstance(sub, ast.Call):
            func = sub.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
            if name in ("tool_of", "section_tool", "declared_name"):
                return True
    return False


def _by_name_branch(test: ast.AST) -> bool:
    text = ast.unparse(test)
    return text.startswith("read_by_name(") or ("source_of(" in text and text.endswith(" is None"))


def stored_calls(source: str, label: str, *, gateway: bool = False) -> list[str]:
    """Calls to a ``stored_*`` helper with a tool's name, outside where the gateway makes them."""
    tree = ast.parse(source)
    names = _tool_names()
    allowed: set[int] = set()
    if gateway:
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name.startswith("stored_"):
                allowed |= {id(n) for n in ast.walk(node)}
            if isinstance(node, ast.If) and _by_name_branch(node.test):
                for stmt in node.body:
                    allowed |= {id(n) for n in ast.walk(stmt)}
    found: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or id(node) in allowed:
            continue
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
        if not name.startswith("stored_"):
            continue
        args = [*node.args, *(k.value for k in node.keywords)]
        literal = any(
            isinstance(sub, ast.Constant) and sub.value in names
            for arg in args
            for sub in ast.walk(arg)
        )
        if literal or any(_reads_a_tool(arg) for arg in args):
            found.append(f"{label}:{node.lineno}: {name} with a tool's name")
    return found


@pytest.mark.parametrize("path", _modules(), ids=lambda p: str(p.relative_to(REPORTING)))
def test_no_module_calls_a_stored_helper_with_a_tool_s_name(path: Path) -> None:
    source = path.read_text(encoding="utf-8")
    assert stored_calls(source, path.name, gateway=path == GATEWAY) == []


@pytest.mark.parametrize(
    "snippet",
    [
        "x = tool_kinds.stored_builder_of(tool_of(entry))\n",
        'x = tool_kinds.stored_section_hint("payloads", entry.tool)\n',
        'x = stored_facts_by_name("capa")\n',
    ],
)
def test_the_guard_sees_a_stored_helper_called_with_a_tool_s_name(snippet: str) -> None:
    assert stored_calls(snippet, "<snippet>")
    assert stored_calls(snippet, "<snippet>", gateway=True)


def test_the_gateway_may_call_a_stored_helper_on_its_by_name_branch() -> None:
    good = (
        "def builder_of(entry):\n"
        "    if read_by_name(entry):\n"
        "        return stored_builder_of(tool_of(entry))\n"
        '    return stored_tool_of_kind("decoded_strings")\n'
    )
    assert stored_calls(good, "<snippet>", gateway=True) == []


@pytest.mark.parametrize("snippet", NAME_READ_SNIPPETS)
def test_the_guard_sees_each_way_a_name_is_read(snippet: str) -> None:
    assert violations(snippet)


def test_the_gateway_reads_legacy_only_on_its_no_source_branch() -> None:
    bad = (
        "from maljan.reporting import legacy_tool_names as legacy\n"
        "def is_of(entry, consumer):\n"
        "    return legacy.in_table(consumer, tool_of(entry))\n"
    )
    good = (
        "from maljan.reporting import legacy_tool_names as legacy\n"
        "def is_of(entry, consumer):\n"
        "    if source_of(entry) is None:\n"
        "        return legacy.in_table(consumer, tool_of(entry))\n"
        "    return False\n"
        "def stored_word(kind):\n"
        "    return legacy.WORDS.get(kind)\n"
    )
    assert violations(bad, gateway=True)
    assert violations(good, gateway=True) == []


def test_the_guard_lets_kinds_section_keys_and_tool_to_tool_be() -> None:
    clean = (
        '_KIND_SHAPE = {"strings": ("/strings/*", "/text")}\n'
        'ok = facts.kind in ("strings", "emulated_strings")\n'
        'section = acc.get("sandbox_processes", "Processes observed", "table")\n'
        'opened = acc.get(f"tool_{entry.tool}", entry.tool.capitalize(), "kv")\n'
        'same = row.source == "strings"\n'
        "def f(rows, section):\n"
        "    ranked = {}\n"
        "    for row in rows:\n"
        "        if str(row.tool) not in ranked:\n"
        "            ranked[str(row.tool)] = 1\n"
        "    return tool_of(rows[0]) == section_tool(section)\n"
    )
    assert violations(clean) == []

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
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.tool_name_reads import NAME_READ_SNIPPETS, violations

REPORTING = Path(__file__).resolve().parents[3] / "src" / "maljan" / "reporting"
EXEMPT = REPORTING / "legacy_tool_names.py"
GATEWAY = REPORTING / "tool_kinds.py"


def _modules() -> list[Path]:
    return sorted(p for p in REPORTING.rglob("*.py") if p != EXEMPT)


@pytest.mark.parametrize("path", _modules(), ids=lambda p: str(p.relative_to(REPORTING)))
def test_no_reporting_module_reads_a_tool_by_its_name(path: Path) -> None:
    source = path.read_text(encoding="utf-8")
    assert violations(source, path.name, gateway=path == GATEWAY) == []


def test_the_exemption_is_the_one_module_by_its_path() -> None:
    assert EXEMPT.is_file()
    assert [p for p in REPORTING.rglob("*.py") if p.name == EXEMPT.name] == [EXEMPT]


def test_the_legacy_module_is_the_one_that_names_tools() -> None:
    assert violations(EXEMPT.read_text(encoding="utf-8"), EXEMPT.name)


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

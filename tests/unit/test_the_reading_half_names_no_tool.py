"""No module of the reading half reads an entry's tool by a tool's name.

The reading half (``pipeline/``, ``analysis/``, ``agents/``) reads what an
entry is from its tool's declared kind (``core.declared_reading``). The
detection is shared with the report's guard (``tests/tool_name_reads.py``): it
follows a tool read through locals, string methods, f-strings, ``getattr``,
subscripts, ``.get`` and dict tables, and fails on a comparison, a membership
test, a ``match`` or a lookup against anything that is not itself a tool read,
and on an import of a legacy table module. The legacy record of the old tables
lives in ``core.legacy_tool_tables``, read only by ``core.declared_reading``,
outside these packages.

``STILL_BY_NAME`` holds, as a multiset, the reads whose own change is another
branch's, each with its reason. The triage pack reads each entry it renders by
the renderer and label its step declared (``core.pack_steps``), and an entry
of a step as shipped by that shipped step. The name-text heuristics for an undeclared tool live in
``core.undeclared_tools``, outside these packages, read only after a tool's
declared kind.
Its counts may only shrink: a new read, a moved one, or one more of the same,
fails.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest

from tests.tool_name_reads import (
    NAME_READ_SNIPPETS,
    findings,
    tool_parameters,
    tool_parameters_under,
)

ROOT = Path(__file__).resolve().parents[2]
PACKAGES = ("pipeline", "analysis", "agents")
# Helpers any module of the product defines, for a literal handed to one imported.
SHARED = tool_parameters_under(ROOT / "src" / "maljan")

_PACK_STEP = (
    "the triage pack reading the answer its own in-process step just produced, by that "
    "step's tool, before the entry is written"
)

# ((module, what, code), count) -> why it is still by name.
STILL_BY_NAME: dict[tuple[str, str, str], tuple[int, str]] = {
    ("pipeline/triage_pack.py", "looks", "_ESTABLISHED.get(tool)"): (1, _PACK_STEP),
    ("agents/evidence_recorder.py", "compares", "name != tool"): (
        1,
        "a repaired call matched to the note the same call left, by the tool name it gave",
    ),
}


def _found() -> Counter[tuple[str, str, str]]:
    held: Counter[tuple[str, str, str]] = Counter()
    for package in PACKAGES:
        for path in sorted((ROOT / "src" / "maljan" / package).rglob("*.py")):
            module = path.relative_to(ROOT / "src" / "maljan").as_posix()
            for finding in findings(path.read_text(encoding="utf-8"), module, shared=SHARED):
                held[(module, finding.what.split()[0], finding.text)] += 1
    return held


def test_no_module_of_the_reading_half_reads_a_tool_by_its_name() -> None:
    found = _found()
    over = {
        key: (count, STILL_BY_NAME.get(key, (0, ""))[0])
        for key, count in found.items()
        if count > STILL_BY_NAME.get(key, (0, ""))[0]
    }
    assert not over, over


def test_the_reads_still_by_name_only_shrink() -> None:
    found = _found()
    stale = {key: allowed for key, (allowed, _) in STILL_BY_NAME.items() if found[key] < allowed}
    assert not stale, stale


@pytest.mark.parametrize("snippet", NAME_READ_SNIPPETS)
def test_the_guard_sees_each_way_a_name_is_read(snippet: str) -> None:
    assert findings(snippet)


def test_the_guard_lets_kinds_and_tool_to_tool_be() -> None:
    clean = (
        'ok = facts.kind in ("strings", "emulated_strings")\n'
        'ok = kind_of(entry) == "sandbox_sections"\n'
        "def f(rows):\n"
        "    ranked = {}\n"
        "    lines = []\n"
        "    for row in rows:\n"
        "        lines.append(f'{row.tool}')\n"
        "        if str(row.tool) not in ranked:\n"
        "            ranked[str(row.tool)] = 1\n"
        "    return 'intro' not in lines\n"
    )
    assert findings(clean) == []


def test_the_guard_lets_a_writer_and_a_tool_to_tool_helper_be() -> None:
    clean = (
        "def find(es, tool):\n"
        "    return [e for e in es if e.tool == tool]\n"
        "def record(tool, args):\n"
        "    return (tool, args)\n"
        "find(es, other)\n"
        'record("capa", {})\n'
        'record(tool="capa", args={})\n'
        "tool, ok = entry.tool, entry.ok\n"
        "same = tool == other.tool\n"
        "tools = [e.tool for e in es]\n"
        "ok = len(tools) == 2\n"
        'words = re.findall("[a-z]+", entry.tool)\n'
    )
    assert findings(clean) == []


def test_the_guard_sees_a_source_held_against_a_registry_key_that_is_built() -> None:
    for built in (
        'ok = entry.source == f"mcp:{key}"\n',
        'ok = entry.source in (f"mcp:{k}", other)\n',
        'ok = entry.source == "mcp:" + key\n',
    ):
        assert findings(built), built
    for near in (
        "ok = entry.source == f'{key}'\n",
        'ok = entry.source == f"x{key}:mcp:"\n',
        'ok = entry.source == "native"\n',
        "ok = entry.source == key\n",
    ):
        assert findings(near) == [], near


def test_the_guard_follows_a_tool_helper_imported_from_another_module() -> None:
    helper = "def find(es, tool):\n    return [e for e in es if e.tool == tool]\n"
    shared = tool_parameters(helper)
    for caller in (
        'from maljan.core.helpers import find\nfind(es, "capa")\n',
        'from maljan.core.helpers import find as look\nlook(es, tool="capa")\n',
        'from maljan.core import helpers\nhelpers.find(es, "capa")\n',
        'import maljan.core.helpers as h\nh.find(es, "capa")\n',
    ):
        assert findings(caller, shared=shared), caller
        assert findings(caller) == [], caller
    for near in (
        "from maljan.core.helpers import find\nfind(es, other)\n",
        'from elsewhere import find\nfind(es, "capa")\n',
        'import re\nre.find(es, "capa")\n',
        'def find(es, label):\n    return label\nfind(es, "capa")\n',
    ):
        assert findings(near, shared=shared) == [], near


def test_the_guard_reads_every_module_under_a_root_for_tool_helpers(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("def find(es, tool):\n    return tool == es.tool\n")
    (tmp_path / "b.py").write_text("def record(tool):\n    return {tool: 1}\n")
    assert tool_parameters_under(tmp_path) == {"find": ([1], {"tool"})}


def test_the_guard_flags_an_entry_s_server_held_against_a_name_only() -> None:
    for read in (
        'ok = entry.server == "radare2"\n',
        'ok = row.server in ("radare2", "ghidra")\n',
        'ok = "radare2" == entry.server_name\n',
    ):
        assert findings(read), read
    for near in (
        'ok = entry.server == ""\n',
        'ok = entry.server in (None, "", PIPELINE)\n',
        'ok = self.server == "radare2"\n',
        "ok = entry.server == other.server\n",
        "ok = entry.server == PIPELINE\n",
    ):
        assert findings(near) == [], near

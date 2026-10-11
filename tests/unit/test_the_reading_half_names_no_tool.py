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
branch's (the triage pack's own steps, which the pack writes itself;
name-text heuristics for an undeclared listing tool), each with its reason.
Its counts may only shrink: a new read, a moved one, or one more of the same,
fails.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest

from tests.tool_name_reads import NAME_READ_SNIPPETS, findings

ROOT = Path(__file__).resolve().parents[2]
PACKAGES = ("pipeline", "analysis", "agents")

_PACK_STEP = (
    "the triage pack reading or rendering the entry its own step just wrote, by that step's "
    "name; the pack as a declared step list replaces it"
)
_LISTING_WORDS = (
    "a name-text heuristic for a tool that lists code (decompile, disassemble, function), "
    "kept for an undeclared tool; the prompts-and-wording group replaces it"
)

# ((module, what, code), count) -> why it is still by name.
STILL_BY_NAME: dict[tuple[str, str, str], tuple[int, str]] = {
    ("pipeline/triage_pack.py", "looks", "_ESTABLISHED.get(tool)"): (1, _PACK_STEP),
    ("pipeline/triage_pack.py", "looks", "_GROUP_LABELS.get(entry.tool, entry.tool)"): (
        2,
        _PACK_STEP,
    ),
    ("pipeline/triage_pack.py", "looks", "_RENDERERS.get(entry.tool)"): (1, _PACK_STEP),
    ("pipeline/triage_pack.py", "looks", "_SHORTER_RENDERERS.get(entry.tool)"): (1, _PACK_STEP),
    ("pipeline/triage_pack.py", "compares", "entry.tool in PASS_TOOLS"): (4, _PACK_STEP),
    ("pipeline/triage_pack.py", "compares", "entry.tool not in PASS_TOOLS"): (1, _PACK_STEP),
    ("pipeline/triage_pack.py", "compares", "entry.tool == 'capa'"): (1, _PACK_STEP),
    ("pipeline/triage_pack.py", "compares", "entry.tool != 'capa'"): (1, _PACK_STEP),
    ("pipeline/triage_pack.py", "compares", "entry.tool == crypto_constants.TOOL"): (1, _PACK_STEP),
    ("pipeline/triage_pack.py", "compares", "entry.tool == ANTI_ANALYSIS_TOOL"): (1, _PACK_STEP),
    ("pipeline/triage_pack.py", "compares", "entry.tool == INDEX_TOOL"): (2, _PACK_STEP),
    ("pipeline/triage_pack.py", "compares", "entry.tool != INDEX_TOOL"): (1, _PACK_STEP),
    ("pipeline/triage_pack.py", "compares", "e.tool == INDEX_TOOL"): (1, _PACK_STEP),
    ("pipeline/triage_pack.py", "compares", "entry.tool != sandbox_sections.SECTIONS_TOOL"): (
        1,
        _PACK_STEP,
    ),
    ("pipeline/triage_pack.py", "compares", "made[-1].tool == artefact_index.TOOL"): (
        1,
        _PACK_STEP,
    ),
    ("pipeline/nodes.py", "looks", "_FORMAT_TOOLS.get(tool)"): (
        1,
        "the pack's own format step chosen for the routed format; the declared step list "
        "replaces it",
    ),
    ("pipeline/function_claims.py", "compares", "'disassembl' not in tool"): (1, _LISTING_WORDS),
    ("pipeline/function_claims.py", "compares", "'function' not in tool"): (1, _LISTING_WORDS),
    ("pipeline/function_claims.py", "compares", "'string' in lowered"): (1, _LISTING_WORDS),
    ("pipeline/function_claims.py", "compares", "'floss' in lowered"): (1, _LISTING_WORDS),
    ("pipeline/validation.py", "compares", "'decompil' not in tool"): (1, _LISTING_WORDS),
    ("agents/function_map.py", "compares", "'decompil' in tool"): (1, _LISTING_WORDS),
    ("agents/function_map.py", "compares", "'disassembl' in tool.lower()"): (1, _LISTING_WORDS),
    ("agents/function_map.py", "compares", "'function' in tool.lower()"): (1, _LISTING_WORDS),
    ("agents/evidence_recorder.py", "compares", "'decompil' in str(tool or '').lower()"): (
        1,
        _LISTING_WORDS,
    ),
    ("agents/evidence_recorder.py", "compares", "name != tool"): (
        1,
        "a repaired call matched to the note the same call left, by the tool name it gave",
    ),
    ("analysis/ghidra_program.py", "looks", "(overrides or {}).get(tool)"): (
        1,
        "the Ghidra REST opener's endpoint overrides, keyed by its caller (the Ghidra adapter)",
    ),
}


def _found() -> Counter[tuple[str, str, str]]:
    held: Counter[tuple[str, str, str]] = Counter()
    for package in PACKAGES:
        for path in sorted((ROOT / "src" / "maljan" / package).rglob("*.py")):
            module = path.relative_to(ROOT / "src" / "maljan").as_posix()
            for finding in findings(path.read_text(encoding="utf-8"), module):
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

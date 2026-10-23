"""Whether a scored item was found by the run's own analysis or by a lookup.

A key score credits an item from the report; the report's sentences cite the
ledger entries they rest on. This pass follows those citations back, read
only from the stored run beside the score file (``evidence.json``,
``report.md`` and ``mitre.json`` in its directory), and never changes a
verdict:

- **the entries that credited an item** are the evidence ids its row names
  (``ev_0014``), the ids cited where a quoted fragment of the row (text between
  double quotes, split at an ellipsis, at least :data:`MIN_FRAGMENT` characters)
  stands in ``report.md`` (on a table row, every id of the row; in prose, the
  ids inside the fragment and the citation that closes its sentence), and, for
  an item whose code is an ATT&CK technique id (``K10 T1027``), the ids the
  run's published technique of that id cites in ``mitre.json``;
- **each entry is classed by the kind its tool declares**
  (``core.declared_reading.kind_of``: the facts the entry stored, or, for an
  entry written before facts were stored, the platform's shipped declaration
  of its tool), never by the tool's name: a kind that asks a service outside
  the deployment what it knows (``builtin_declarations.OUTWARD_KINDS``:
  reputation, indicator reports, submissions to it) is a **lookup**, any other
  declared kind is **analysis**, and a tool that declares no kind is
  **undeclared**, never taken as either. An entry that did not answer (``ok``
  false) credits nothing, nor does an id the ledger does not hold; both are
  named;
- **the item's tag** is :data:`OWN` when only analysis entries credited it,
  :data:`BOTH` when analysis and lookup entries did (stated as both, never
  folded into one), :data:`LOOKUP_ONLY` when only lookups did, :data:`UNTOLD`
  when no analysis entry did and an undeclared tool did (which of the two it
  was cannot be told), and :data:`NO_ENTRY` when no entry that answered did. A
  score with no ledger beside it is :data:`NOT_READ`, and says why.

"Found by analysis" counts :data:`OWN` and :data:`BOTH`; "found only by
lookup" counts :data:`LOOKUP_ONLY`. Locating a fragment is a substring search
of the report, so time is the fragments times the report's length; the rest is
linear in the items and the entries they cite.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from scripts.replay.stored import evidence_rows

from maljan.core.builtin_declarations import OUTWARD_KINDS
from maljan.core.declared_reading import kind_of

LEDGER_FILE, REPORT_FILE, TECHNIQUES_FILE = "evidence.json", "report.md", "mitre.json"
# The kinds whose answer is what a service outside the deployment already holds.
LOOKUP_KINDS: frozenset[str] = frozenset(OUTWARD_KINDS)

# What one cited entry is, by its tool's declared kind.
ANALYSIS, LOOKUP, UNDECLARED = "analysis", "lookup", "undeclared"
# Why a cited id credits nothing.
NO_ANSWER, NOT_IN_LEDGER = "did not answer", "not in the ledger"

# An item's tag, in the order a report lists them.
OWN = "own analysis"
BOTH = "own analysis + lookup"
LOOKUP_ONLY = "lookup only"
UNTOLD = "undeclared tool"
NO_ENTRY = "no cited entry"
NOT_READ = "not read"
# An arm's tag when no one tag is shared by m of the runs that reach its verdict
# and fewer than m of them found it by analysis.
MIXED = "mixed"
TAGS: tuple[str, ...] = (OWN, BOTH, LOOKUP_ONLY, UNTOLD, NO_ENTRY, NOT_READ, MIXED)
BY_ANALYSIS: frozenset[str] = frozenset({OWN, BOTH})
ONLY_BY_LOOKUP: frozenset[str] = frozenset({LOOKUP_ONLY})

MIN_FRAGMENT = 12
EVIDENCE_ID = re.compile(r"\bev_\d+\b")
_QUOTED = re.compile(r'"([^"]+)"|“([^”]+)”')
_ELLIPSIS = re.compile(r"…|\.\.\.")
_CITATION = re.compile(r"(?:\[ev_\d+(?:,\s*ev_\d+)*\])+|\(ev_\d+(?:,\s*ev_\d+)*\)")
_SENTENCE_END = re.compile(r"[.!?]\s")
_CLOSING_STOP = re.compile(r"[.!?]?\s*(?:\([^()]*\)\s*)?$")
_TECHNIQUE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_EMPHASIS = re.compile(r"[*`]")
_SPACE = re.compile(r"\s+")


@dataclass
class ItemProvenance:
    """The entries that credited one item, each with its class, and the item's tag."""

    tag: str
    # evidence id -> ANALYSIS, LOOKUP, UNDECLARED, NO_ANSWER or NOT_IN_LEDGER
    entries: dict[str, str] = field(default_factory=dict)
    # quoted fragments of the row, and how many of them stand in the report
    fragments: int = 0
    located: int = 0


def tag_of(classes: Iterable[str]) -> str:
    """An item's tag from the classes of the entries that credited it."""
    held = set(classes)
    if ANALYSIS in held:
        return BOTH if LOOKUP in held else OWN
    if LOOKUP in held:
        return LOOKUP_ONLY if UNDECLARED not in held else UNTOLD
    return UNTOLD if UNDECLARED in held else NO_ENTRY


def entry_class(entry: Mapping[str, Any]) -> str:
    """One ledger entry as analysis, lookup or undeclared, by its tool's declared kind."""
    if entry.get("ok") is False:
        return NO_ANSWER
    kind = kind_of(entry)
    if not kind:
        return UNDECLARED
    return LOOKUP if kind in LOOKUP_KINDS else ANALYSIS


def _plain(text: str) -> str:
    return _SPACE.sub(" ", _EMPHASIS.sub("", text.replace("\\|", "|"))).strip().casefold()


def fragments(row: str) -> list[str]:
    """The quoted fragments of a row long enough to locate, each folded as the report is."""
    found: list[str] = []
    for quoted in _QUOTED.finditer(row.replace("\\|", "|")):
        for part in _ELLIPSIS.split(quoted.group(1) or quoted.group(2)):
            plain = _plain(part)
            if len(plain) >= MIN_FRAGMENT and plain not in found:
                found.append(plain)
    return found


def closes_sentence(gap: str) -> bool:
    """Whether a citation after ``gap`` (the text since a fragment ended) closes its sentence.

    It does when no sentence ends inside the gap; the one stop just before the
    citation (``… surface. [ev_0004]``), or before a bracketed note that leads
    it (``… is set. (assessed) [ev_0314]``), is the fragment's own sentence
    ending.
    """
    return not _SENTENCE_END.search(_CLOSING_STOP.sub("", gap))


def cited_at(line: str, fragment: str) -> tuple[bool, set[str]]:
    """Whether ``fragment`` stands on ``line``, and the evidence ids it is cited by there."""
    ids: set[str] = set()
    start = line.find(fragment)
    if start < 0:
        return False, ids
    if line.startswith("|"):
        return True, set(EVIDENCE_ID.findall(line))
    while start >= 0:
        end = start + len(fragment)
        ids.update(EVIDENCE_ID.findall(line[start:end]))
        closing = _CITATION.search(line, end)
        if closing and closes_sentence(line[end : closing.start()]):
            ids.update(EVIDENCE_ID.findall(closing.group(0)))
        start = line.find(fragment, end)
    return True, ids


def _technique_ids(path: Path) -> dict[str, set[str]]:
    """``{technique id: evidence ids its published description cites}`` of ``mitre.json``."""
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except ValueError:
        return {}
    cited: dict[str, set[str]] = {}
    for technique in (data.get("techniques") or []) if isinstance(data, dict) else []:
        if isinstance(technique, dict) and technique.get("technique_id"):
            text = json.dumps(technique, default=str)
            cited.setdefault(str(technique["technique_id"]), set()).update(
                EVIDENCE_ID.findall(text)
            )
    return cited


@dataclass
class StoredEvidence:
    """What of the run beside a score file this pass reads."""

    entries: Mapping[str, Mapping[str, Any]]
    report: list[str]
    techniques: dict[str, set[str]]


def read_beside(score: Path) -> tuple[StoredEvidence | None, str]:
    """The stored run in the score file's own directory, or why none was read."""
    root = Path(score).parent
    ledger = root / LEDGER_FILE
    if not ledger.is_file():
        return None, f"not read: no {LEDGER_FILE} beside the score"
    try:
        rows, why = evidence_rows(json.loads(ledger.read_text(encoding="utf-8")))
    except ValueError as exc:
        return None, f"not read: {LEDGER_FILE} is not JSON ({exc})"
    if not rows:
        return None, f"not read: {why}"
    entries = {str(r["entry_id"]): r for r in rows if r.get("entry_id")}
    report_path = root / REPORT_FILE
    report = (
        [_plain(line) for line in report_path.read_text(encoding="utf-8").splitlines()]
        if report_path.is_file()
        else []
    )
    stored = StoredEvidence(entries, report, _technique_ids(root / TECHNIQUES_FILE))
    held = ((REPORT_FILE, report), (TECHNIQUES_FILE, stored.techniques))
    read = [LEDGER_FILE, *(name for name, there in held if there)]
    return stored, f"read from {', '.join(read)} beside the score"


def attribute(key: str, row: str, stored: StoredEvidence) -> ItemProvenance:
    """The entries that credited the item ``key`` scored on ``row``, classed, and its tag."""
    ids = set(EVIDENCE_ID.findall(row))
    quoted = fragments(row)
    located = 0
    for fragment in quoted:
        hit = False
        for line in stored.report:
            stands, cited = cited_at(line, fragment)
            hit = hit or stands
            ids |= cited
        located += hit
    code = key.split(" ", 1)[1] if " " in key else ""
    if _TECHNIQUE.match(code):
        ids |= stored.techniques.get(code, set())
    entries = {
        i: (entry_class(stored.entries[i]) if i in stored.entries else NOT_IN_LEDGER)
        for i in sorted(ids)
    }
    return ItemProvenance(tag_of(entries.values()), entries, len(quoted), located)


def attribute_all(score: Path, rows: Mapping[str, str]) -> tuple[dict[str, ItemProvenance], str]:
    """Every item's provenance, ``rows`` being each item's row as written, and how it was read."""
    stored, note = read_beside(score)
    if stored is None:
        return {key: ItemProvenance(NOT_READ) for key in rows}, note
    return {key: attribute(key, row, stored) for key, row in rows.items()}, note


def split(tags: Iterable[str]) -> dict[str, Any]:
    """The count of each tag, and the two columns: found by analysis, found only by lookup."""
    counts = dict.fromkeys(TAGS, 0)
    for tag in tags:
        counts[tag] += 1
    return {
        "by_tag": counts,
        "by_analysis": sum(counts[t] for t in BY_ANALYSIS),
        "only_by_lookup": sum(counts[t] for t in ONLY_BY_LOOKUP),
    }

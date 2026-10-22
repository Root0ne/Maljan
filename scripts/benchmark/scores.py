"""Scored runs read back as item verdicts, whichever way they were scored.

Three sources are read, never written:

- **a key score** (``score.md``): the table that opens the section headed "Item
  by item", the scored run's verdicts being its first column that holds a
  verdict word (found, partly (body), partly (dump), missed, wrong; a bare
  ``partly`` is ``partly (body)``, as the scoring brief writes a body partly),
  every cell of which must be one (a later column is another run's and is never
  read in its place), and the numbered list of the section headed "Beyond the human reports". The
  file's own sentences are checked against what was counted: the ``**Totals:**``
  line and the "N facts more than the human analyst" line, when it has them. A
  file that disagrees with itself is refused, naming both numbers;
- **a blind score sheet** with its sealed map (``scripts/blind``): one scored
  run per arm, named by the map;
- **a calibration score** (``scripts/calibration/run.py score --json`` or
  ``gate --json``): each case's facts on the fact scale, its traps and absent
  capabilities on the claim scale (a trap is only ever false or not claimed; a
  part the run did not store is unknown). The calibration scorer's ``beyond``
  counts publications no manifest names, not proven facts, so it is not read as
  a beyond-human count.

Every verdict sits on a **scale**, a tuple of words from worst to best, so that
two verdicts of one item can be ordered and nothing else is compared. An item is
keyed by its code (``K3.2``, ``K7 17``, ``K10 T1027``), or, where the label has
no code, by its whole label in one case, without emphasis or backticks, its runs
of spaces read as one and the spaces around a ``/`` dropped, so the same item
spelt ``a / b`` in one file and ``a/b`` in another is one item, while ``task
Updater`` and ``taskUpdater`` stay two. A file with no Totals line is read, and
the output says its totals were unchecked; a Totals line that cannot be read is
refused, naming the line, as is a stated beyond-human count with no list.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

KEY, FACT, CLAIM = "key", "fact", "claim"
# Each scale's words, worst first: a verdict's rank is its index.
SCALES: dict[str, tuple[str, ...]] = {
    KEY: ("wrong", "missed", "partly (dump)", "partly (body)", "found"),
    FACT: ("missed", "mentioned", "partial", "found"),
    CLAIM: ("false", "not claimed"),
}
# The lowest word of a scale that the totals credit ("found + partly"); a scale
# absent here credits nothing.
CREDITED: dict[str, str] = {KEY: "partly (dump)", FACT: "partial"}
KEY_ALIASES: dict[str, str] = {"partly": "partly (body)"}
# A calibration trap's or absence's status, on the claim scale; None: unknown.
CLAIM_STATUSES: dict[str, str | None] = {
    "false": "false",
    "clear": "not claimed",
    "withheld": "not claimed",
    "mentioned": "not claimed",
    "not recorded": None,
}
SCORE_FILE = "score.md"
ITEM_SECTION = re.compile(r"^(#+)\s.*\bitem by item\b", re.IGNORECASE)
BEYOND_SECTION = re.compile(r"^(#+)\s+(?:\d+\.\s+)?beyond the human reports\b", re.IGNORECASE)
_HEADING = re.compile(r"^(#+)\s")
_LISTED = re.compile(r"^(\d+)\.\s")
_STATED_BEYOND = re.compile(
    r"\*\*(\d+) facts? (?:more than the human analyst|beyond the human reports)"
)
_TOTALS_LINE = "**Totals:"
_STATED_TOTALS = re.compile(
    r"\*\*Totals:\s*(\d+) found / (\d+) partly \((\d+) body \+ (\d+) dump\) / "
    r"(\d+) missed / (\d+) wrong"
)
_CELL_SPLIT = re.compile(r"(?<!\\)\|")
_SEPARATOR = re.compile(r"^\|[\s:|-]+\|$")
_DOTTED_CODE = re.compile(r"^K\d+\.\w+$")
_GROUP = re.compile(r"^K\d+$")
_SUB_CODE = re.compile(r"^(\d+|T\d{4}(\.\d{3})?)$")
_EMPHASIS = re.compile(r"[*`]")
_SPACE = re.compile(r"\s+")
_AROUND_SLASH = re.compile(r" ?/ ?")


class ScoreFileError(RuntimeError):
    """A scored run cannot be read; the message names the file and why."""


@dataclass
class ScoredRun:
    """One scored run: each item's scale and verdict, and its beyond-human count."""

    name: str
    source: str
    # item key -> (scale, verdict); a verdict of None is unknown.
    verdicts: dict[str, tuple[str, str | None]]
    labels: dict[str, str] = field(default_factory=dict)
    beyond: int | None = None
    # Why ``beyond`` is None, or where it was read.
    beyond_note: str = ""
    # The table column the verdicts were read from, for a key score.
    column: str | None = None
    # Whether the file's own totals were checked against its table, and how.
    totals_note: str = ""


def rank(scale: str, word: str | None) -> int | None:
    """A verdict's rank on its scale; None for an unknown verdict."""
    return None if word is None else SCALES[scale].index(word)


def _plain(text: str) -> str:
    return _SPACE.sub(" ", _EMPHASIS.sub("", text)).strip()


def item_key(label: str) -> str:
    """The item a label names: its code, or the folded label when it has none."""
    words = _plain(label).split(" ")
    if _DOTTED_CODE.match(words[0]):
        return words[0]
    if _GROUP.match(words[0]) and len(words) > 1 and _SUB_CODE.match(words[1]):
        return f"{words[0]} {words[1]}"
    if len(words) == 1:
        return words[0]
    return words[0] + " " + _AROUND_SLASH.sub("/", " ".join(words[1:]).casefold())


def key_verdict(cell: str) -> str | None:
    """A table cell as a key-scale verdict, or None when it is not one."""
    word = _plain(cell).casefold()
    word = KEY_ALIASES.get(word, word)
    return word if word in SCALES[KEY] else None


def _cells(line: str) -> list[str]:
    return [c.strip() for c in _CELL_SPLIT.split(line.strip().strip("|"))]


def _section(lines: list[str], heading: re.Pattern[str]) -> list[str] | None:
    """The lines under the first heading ``heading`` matches, up to one of its level or above."""
    for start, line in enumerate(lines):
        found = heading.match(line)
        if not found:
            continue
        level = len(found.group(1))
        body: list[str] = []
        for following in lines[start + 1 :]:
            other = _HEADING.match(following)
            if other and len(other.group(1)) <= level:
                break
            body.append(following)
        return body
    return None


def _first_table(body: list[str]) -> list[list[str]]:
    rows: list[list[str]] = []
    for line in body:
        if line.startswith("|"):
            rows.append(_cells(line))
        elif rows:
            break
    return rows


def _name(path: Path) -> str:
    return path.parent.name if path.name == SCORE_FILE else path.stem


def read_key_score(path: Path) -> ScoredRun:
    """A key score file's item verdicts and beyond-human count, checked against its own totals."""
    path = Path(path)
    lines = path.read_text(encoding="utf-8").splitlines()
    body = _section(lines, ITEM_SECTION)
    if body is None:
        raise ScoreFileError(f"{path}: no section headed 'Item by item'")
    table = _first_table(body)
    raw = [line for line in body if line.startswith("|")]
    if len(table) < 3 or not _SEPARATOR.match(raw[1].strip()):
        raise ScoreFileError(f"{path}: the 'Item by item' section opens with no item table")
    header, rows = table[0], table[2:]
    column = next(
        (j for j in range(1, len(header)) if any(len(r) > j and key_verdict(r[j]) for r in rows)),
        None,
    )
    if column is None:
        raise ScoreFileError(f"{path}: no column of the item table holds a verdict")
    for row in rows:
        if len(row) <= column or not key_verdict(row[column]):
            cell = row[column] if len(row) > column else ""
            raise ScoreFileError(
                f"{path}: the scored column {_plain(header[column])!r} is not a verdict "
                f"for {_plain(row[0])!r}: {cell!r}"
            )
    verdicts: dict[str, tuple[str, str | None]] = {}
    labels: dict[str, str] = {}
    for row in rows:
        key = item_key(row[0])
        if key in verdicts:
            raise ScoreFileError(
                f"{path}: item {key} is scored twice ({labels[key]!r}, {row[0]!r})"
            )
        verdicts[key] = (KEY, key_verdict(row[column]))
        labels[key] = _plain(row[0])
    run = ScoredRun(
        name=_name(path),
        source=str(path),
        verdicts=verdicts,
        labels=labels,
        column=_plain(header[column]),
    )
    _check_totals(path, lines, run)
    _read_beyond(path, lines, run)
    return run


def _check_totals(path: Path, lines: list[str], run: ScoredRun) -> None:
    line = next((x for x in lines if _TOTALS_LINE in x), None)
    if line is None:
        run.totals_note = "no Totals line: totals unchecked"
        return
    stated = _STATED_TOTALS.search(line)
    if stated is None:
        raise ScoreFileError(f"{path}: the Totals line cannot be read: {line.strip()!r}")
    words = [v for _, v in run.verdicts.values()]
    counted = {
        "found": words.count("found"),
        "partly": words.count("partly (body)") + words.count("partly (dump)"),
        "body": words.count("partly (body)"),
        "dump": words.count("partly (dump)"),
        "missed": words.count("missed"),
        "wrong": words.count("wrong"),
    }
    said = dict(zip(counted, (int(g) for g in stated.groups()), strict=True))
    differ = [
        f"{k} {said[k]} stated, {counted[k]} in the table" for k in counted if said[k] != counted[k]
    ]
    if differ:
        raise ScoreFileError(
            f"{path}: the Totals line disagrees with the item table: {'; '.join(differ)}"
        )
    run.totals_note = "Totals line checked against the table"


def _read_beyond(path: Path, lines: list[str], run: ScoredRun) -> None:
    stated = next((int(m.group(1)) for m in map(_STATED_BEYOND.search, lines) if m), None)
    body = _section(lines, BEYOND_SECTION)
    if body is None:
        if stated is not None:
            raise ScoreFileError(
                f"{path}: {stated} beyond-human facts stated, and no section headed "
                "'Beyond the human reports' lists them"
            )
        run.beyond_note = "no section headed 'Beyond the human reports'"
        return
    numbers = [int(m.group(1)) for m in map(_LISTED.match, body) if m]
    if numbers != list(range(1, len(numbers) + 1)):
        raise ScoreFileError(
            f"{path}: the beyond-human list is not numbered 1 to {len(numbers)} in order"
        )
    if stated is not None and stated != len(numbers):
        raise ScoreFileError(f"{path}: {stated} beyond-human facts stated, {len(numbers)} listed")
    run.beyond = len(numbers)
    run.beyond_note = f"{len(numbers)} listed" + ("" if stated is None else ", as stated")


def read_blind(sheet: Path, sealed: Path) -> list[ScoredRun]:
    """One scored run per arm of a filled blind score sheet, named by its sealed map."""
    from scripts.blind.prepare import BlindError
    from scripts.blind.reveal import reveal

    try:
        revealed = reveal(sheet, sealed)
    except BlindError as exc:
        raise ScoreFileError(f"{sheet}: {exc}") from exc
    runs: list[ScoredRun] = []
    for arm, given in revealed.verdicts.items():
        verdicts: dict[str, tuple[str, str | None]] = {}
        labels: dict[str, str] = {}
        for item, word in given.items():
            key = item_key(item)
            if key in verdicts:
                raise ScoreFileError(f"{sheet}: items {labels[key]!r} and {item!r} are one item")
            verdicts[key] = (KEY, KEY_ALIASES.get(word, word))
            labels[key] = item
        runs.append(
            ScoredRun(
                name=arm,
                source=f"{sheet} ({arm})",
                verdicts=verdicts,
                labels=labels,
                beyond=revealed.beyond[arm],
                beyond_note="the sheet's beyond_human row",
            )
        )
    return runs


def _calibration_items(score: dict[str, Any], where: Path) -> dict[str, tuple[str, str | None]]:
    case = str(score.get("case") or "")
    if not case:
        raise ScoreFileError(f"{where}: a calibration score names no case")
    items: dict[str, tuple[str, str | None]] = {}
    for fact in score.get("facts") or []:
        status = str(fact.get("status"))
        if status not in SCALES[FACT]:
            raise ScoreFileError(f"{where}: {case}/{fact.get('id')} has the status {status!r}")
        items[f"{case}/{fact['id']}"] = (FACT, status)
    for claim in [*(score.get("traps") or []), *(score.get("absent") or [])]:
        status = str(claim.get("status"))
        if status not in CLAIM_STATUSES:
            raise ScoreFileError(f"{where}: {case}/{claim.get('id')} has the status {status!r}")
        items[f"{case}/{claim['id']}"] = (CLAIM, CLAIM_STATUSES[status])
    if not items:
        raise ScoreFileError(f"{where}: the score of {case} has no fact, trap or absent entry")
    return items


def read_calibration(path: Path) -> ScoredRun:
    """A calibration score, or a calibration gate result (every held-out case it scored)."""
    path = Path(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise ScoreFileError(f"{path}: not JSON ({exc})") from exc
    if not isinstance(data, dict):
        raise ScoreFileError(f"{path}: not a calibration score")
    found = data.get("scores")
    gate_result = isinstance(found, list)
    scores: list[Any] = found if isinstance(found, list) else [data]
    verdicts: dict[str, tuple[str, str | None]] = {}
    for score in scores:
        if not isinstance(score, dict) or "facts" not in score:
            raise ScoreFileError(f"{path}: not a calibration score")
        verdicts.update(_calibration_items(score, path))
    name = path.stem if gate_result else str(data.get("run") or path.stem)
    return ScoredRun(
        name=name,
        source=str(path),
        verdicts=verdicts,
        labels={k: k for k in verdicts},
        beyond_note=(
            "not read: the calibration scorer's beyond counts publications no manifest "
            "names, not proven facts"
        ),
    )


def read_scored(path: Path) -> ScoredRun:
    """A key score (``.md``) or a calibration score (``.json``), by its suffix."""
    path = Path(path)
    if path.suffix.lower() == ".md":
        return read_key_score(path)
    if path.suffix.lower() == ".json":
        return read_calibration(path)
    raise ScoreFileError(f"{path}: neither a key score (.md) nor a calibration score (.json)")

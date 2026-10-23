"""Reveal a blind A/B score: read the scores, unseal the map, print each arm and the differences.

The score file is the CSV that ``prepare`` wrote (``item`` and one column per
anonymous id), or a JSON object ``{id: {item: score}}`` (under ``scores`` or
bare). Each item takes a verdict word and the ``beyond_human`` row a count. An
item left unscored refuses the reveal, naming the item.
"""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from scripts.blind.prepare import BEYOND_ROW, VERDICTS, BlindError


@dataclass
class Revealed:
    items: list[str]
    # arm name -> item -> verdict
    verdicts: dict[str, dict[str, str]]
    beyond: dict[str, int]
    totals: dict[str, dict[str, int]] = field(default_factory=dict)
    # item -> arm name -> verdict, for the items on which the arms differ
    differences: dict[str, dict[str, str]] = field(default_factory=dict)


def _load_scores(path: Path) -> dict[str, dict[str, Any]]:
    path = Path(path)
    if path.suffix.lower() == ".json":
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("scores"), dict):
            data = data["scores"]
        if not isinstance(data, dict) or not all(isinstance(v, dict) for v in data.values()):
            raise BlindError(f"{path} is not an object of one score object per id")
        return {str(k): dict(v) for k, v in data.items()}
    with path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.reader(handle))
    if not rows or not rows[0] or rows[0][0] != "item":
        raise BlindError(f"{path} has no header row starting with 'item'")
    columns = rows[0][1:]
    scores: dict[str, dict[str, Any]] = {anon: {} for anon in columns}
    for row in rows[1:]:
        if not row or not row[0].strip():
            continue
        for anon, cell in zip(columns, row[1:], strict=False):
            scores[anon][row[0].strip()] = cell
        for anon in columns[len(row) - 1 :]:
            scores[anon][row[0].strip()] = ""
    return scores


def reveal(scores_path: Path, sealed_path: Path) -> Revealed:
    """The per-arm scores, named, or a :class:`BlindError` when anything is unscored."""
    sealed = json.loads(Path(sealed_path).read_text(encoding="utf-8"))
    items: list[str] = list(sealed["items"])
    arms = {anon: str(arm["name"]) for anon, arm in sealed["arms"].items()}
    scores = _load_scores(scores_path)
    unknown = sorted(set(scores) - set(arms))
    if unknown:
        raise BlindError(
            f"the score file names ids the sealed map does not hold: {', '.join(unknown)}"
        )
    verdicts: dict[str, dict[str, str]] = {}
    beyond: dict[str, int] = {}
    for anon in sorted(arms):
        if anon not in scores:
            raise BlindError(f"no scores for {anon}")
        given = scores[anon]
        verdicts[arms[anon]] = {}
        for item in (*items, BEYOND_ROW):
            value = str(given.get(item, "")).strip() if given.get(item) is not None else ""
            if not value:
                raise BlindError(f"item {item} is not scored for {anon}")
            if item == BEYOND_ROW:
                if not value.isdigit():
                    raise BlindError(f"{BEYOND_ROW} for {anon} is not a count: {value!r}")
                beyond[arms[anon]] = int(value)
                continue
            word = value.lower()
            if word not in VERDICTS:
                raise BlindError(
                    f"item {item} for {anon} is not one of {', '.join(VERDICTS)}: {value!r}"
                )
            verdicts[arms[anon]][item] = word
    result = Revealed(items=items, verdicts=verdicts, beyond=beyond)
    for name, given in verdicts.items():
        result.totals[name] = {
            word: sum(1 for v in given.values() if v == word) for word in VERDICTS
        }
    for item in items:
        row = {name: verdicts[name][item] for name in verdicts}
        if len(set(row.values())) > 1:
            result.differences[item] = row
    return result


def render(result: Revealed) -> str:
    """The reveal as text: per-arm totals, then each item the arms scored differently."""
    names = list(result.verdicts)
    lines = ["Per arm", ""]
    width = max(len(n) for n in names)
    lines.append(f"{'arm'.ljust(width)}  " + "  ".join(VERDICTS) + "  beyond_human")
    for name in names:
        counts = "  ".join(str(result.totals[name][w]).rjust(len(w)) for w in VERDICTS)
        lines.append(f"{name.ljust(width)}  {counts}  {result.beyond[name]}".rstrip())
    lines += [
        "",
        f"Items scored differently ({len(result.differences)} of {len(result.items)})",
        "",
    ]
    for item, row in result.differences.items():
        lines.append(f"{item}: " + "; ".join(f"{name} {verdict}" for name, verdict in row.items()))
    if not result.differences:
        lines.append("none")
    spread = max(result.beyond.values()) - min(result.beyond.values())
    lines += ["", f"beyond_human spread: {spread}"]
    return "\n".join(lines)

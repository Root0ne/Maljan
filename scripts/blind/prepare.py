"""Prepare a blind A/B scoring set from two or more stored runs.

Each arm's scorer-facing files (the rendered report in Markdown and HTML, the
STIX bundle and the IOC table: what the scoring brief says a scorer reads) are
copied under a shuffled anonymous id, with every string that names the arm
removed. The id-to-arm map is written to a sealed file outside the scorer's
directory, and a template for the scores is written inside it.

The stored runs are only ever opened for reading: every file of each is
digested before and after, and the preparation fails when any digest moved.
"""

from __future__ import annotations

import csv
import json
import random
import secrets
import shutil
import string
from dataclasses import dataclass
from pathlib import Path

from scripts.blind.identity import identifiers, leaks, redact
from scripts.replay.stored import check_unchanged, digests

# What a scorer reads of a run: the report body, STIX and the IOC table.
ARTEFACTS: tuple[str, ...] = ("report.md", "report.html", "stix-bundle.json", "iocs.json")
SCORER_DIR = "scorer"
SEALED_FILE = "sealed-map.json"
TEMPLATE_FILE = "scores.csv"
# The score-sheet rows that are not items of the answer list.
BEYOND_ROW = "beyond_human"
VERDICTS: tuple[str, ...] = ("found", "partly (body)", "partly (dump)", "missed", "wrong")


class BlindError(RuntimeError):
    """The preparation or the reveal cannot go on; the message names why."""


@dataclass
class Prepared:
    scorer_dir: Path
    sealed: Path
    template: Path
    ids: list[str]


def read_items(path: Path) -> list[str]:
    """The answer list's item ids, one per line; blank lines and ``#`` comments are skipped."""
    items: list[str] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        item = line.strip()
        if item and not item.startswith("#") and item not in items:
            items.append(item)
    if not items:
        raise BlindError(f"no item in {path}")
    return items


def _order(count: int, seed: int | None) -> list[int]:
    order = list(range(count))
    if seed is None:
        secrets.SystemRandom().shuffle(order)
    else:
        random.Random(seed).shuffle(order)  # nosec B311 — a repeatable order for tests, never a secret
    return order


def _present(root: Path) -> tuple[str, ...]:
    return tuple(name for name in ARTEFACTS if (root / name).is_file())


def prepare(
    runs: list[Path],
    out: Path,
    items: list[str],
    *,
    seed: int | None = None,
    identify: tuple[str, ...] = (),
) -> Prepared:
    """Write the scorer's directory, the score template and the sealed map under ``out``."""
    if len(runs) < 2:
        raise BlindError("name at least two runs")
    resolved = [Path(run).resolve() for run in runs]
    if len(set(resolved)) != len(resolved):
        raise BlindError("a run is named twice")
    for root in resolved:
        if not root.is_dir():
            raise BlindError(f"no stored run at {root}")
    sets = {root: _present(root) for root in resolved}
    if not all(sets.values()):
        empty = next(str(root) for root, names in sets.items() if not names)
        raise BlindError(f"{empty} holds none of {', '.join(ARTEFACTS)}")
    if len(set(sets.values())) != 1:
        raise BlindError(
            "the arms do not hold the same scorer-facing files; scoring would not be blind"
        )
    out = Path(out).resolve()
    if any(out == root or root in out.parents or out in root.parents for root in resolved):
        raise BlindError("the output directory is inside a stored run, or holds one")
    if out.exists() and any(out.iterdir()):
        raise BlindError(f"{out} is not empty")
    if len(resolved) > len(string.ascii_uppercase):
        raise BlindError("too many arms")

    before = {root: digests(root) for root in resolved}
    ids = [string.ascii_uppercase[i] for i in range(len(resolved))]
    order = _order(len(resolved), seed)
    arms = {ids[slot]: resolved[index] for slot, index in enumerate(order)}
    strings = {anon: identifiers(root, root.name, identify) for anon, root in arms.items()}
    everything = set().union(*strings.values())

    scorer = out / SCORER_DIR
    scorer.mkdir(parents=True, exist_ok=True)
    for anon, root in arms.items():
        target = scorer / anon
        target.mkdir()
        for name in sets[root]:
            text = (root / name).read_text(encoding="utf-8", errors="replace")
            # Every arm's strings go out of every arm's copy, so that a name
            # an arm quotes of another is gone too.
            (target / name).write_text(redact(text, everything), encoding="utf-8")

    template = scorer / TEMPLATE_FILE
    with template.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["item", *sorted(arms)])
        for item in (*items, BEYOND_ROW):
            writer.writerow([item, *[""] * len(arms)])

    problems = self_check(scorer, everything, ids)
    if problems:
        shutil.rmtree(out, ignore_errors=True)
        raise BlindError("the copies still name an arm: " + "; ".join(problems))

    sealed = out / SEALED_FILE
    sealed.write_text(
        json.dumps(
            {
                "version": 1,
                "seed": seed,
                "items": items,
                "arms": {
                    anon: {"name": root.name, "path": str(root)}
                    for anon, root in sorted(arms.items())
                },
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    for root in resolved:
        check_unchanged(before[root], digests(root))
    return Prepared(scorer, sealed, template, sorted(arms))


def self_check(scorer: Path, strings: set[str], ids: list[str]) -> list[str]:
    """What still names an arm anywhere under the scorer's directory, file names included."""
    problems: list[str] = []
    for path in sorted(p for p in scorer.rglob("*") if p.is_file()):
        relative = path.relative_to(scorer).as_posix()
        left = leaks(relative, strings)
        left += leaks(path.read_text(encoding="utf-8", errors="replace"), strings)
        if left:
            problems.append(f"{relative}: {', '.join(sorted(set(left)))}")
    names = {p.name for p in scorer.iterdir()}
    if names != {*ids, TEMPLATE_FILE}:
        problems.append("the scorer's directory holds more than the arms and the template")
    return problems

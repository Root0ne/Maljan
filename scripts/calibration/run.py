"""The calibration set: build it, read a case's answers, score stored runs, check for leaks.

    python scripts/calibration/run.py split
    python scripts/calibration/run.py build [--out DIR] [--mode tuning|heldout]
    python scripts/calibration/run.py manifest CASE [--mode tuning|heldout]
    python scripts/calibration/run.py score RUN [--case CASE] [--mode tuning|heldout] [--json OUT]
    python scripts/calibration/run.py gate RUN [RUN ...] [--json OUT]
    python scripts/calibration/run.py leak-check [--terms FILE] [--private-allow FILE]
                                                [--settings-export FILE] [--allow-entries]

``--mode`` is ``tuning`` unless given. In tuning mode a held-out case's answers
are never printed or written: ``manifest`` and ``score`` refuse it (status 2)
and ``build`` writes its bytes without its manifest. ``gate`` reads the
held-out half only, whatever the mode: it builds no tuning case, names a run
of one as not scored, and prints ids, kinds and verdicts, never a term.
``heldout`` mode lets ``manifest`` and ``score`` read a held-out case; ``score``
still prints no term of it.

No case is ever run: the files are written as ``.bin`` with the process's
default permissions, and nothing here starts them.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from scripts.calibration import cases, leak_check  # noqa: E402
from scripts.calibration import score as scoring  # noqa: E402
from scripts.replay.stored import StoredRunChanged  # noqa: E402

TUNING, HELDOUT = cases.SPLITS
DEFAULT_OUT = _ROOT / "calibration-set"
INDEX_FILE = "index.json"
MANIFESTS_DIR = "manifests"


class HeldOut(cases.CaseError):
    """A held-out case's answers were asked for in tuning mode."""


def _entry(case_id: str, seeds: Path) -> tuple[int, cases.Entry]:
    split_seed, entries = cases.read_seeds(seeds)
    for entry in entries:
        if entry.case_id == case_id:
            return split_seed, entry
    raise cases.CaseError(f"no case {case_id} in {seeds}")


def _refuse_heldout(entry: cases.Entry, mode: str) -> None:
    if entry.split == HELDOUT and mode != HELDOUT:
        raise HeldOut(
            f"{entry.case_id} is in the held-out half; tuning mode does not read its answers"
        )


def manifest(case_id: str, mode: str = TUNING, seeds: Path = cases.SEEDS) -> dict[str, Any]:
    """A case's manifest; a held-out case's only in held-out mode."""
    split_seed, entry = _entry(case_id, seeds)
    _refuse_heldout(entry, mode)
    return cases.build(entry, split_seed).manifest()


def split_table(seeds: Path = cases.SEEDS) -> list[dict[str, Any]]:
    """Each case's id, format and half: no answer."""
    _, entries = cases.read_seeds(seeds)
    return [{"case": e.case_id, "format": e.format, "split": e.split} for e in entries]


def build(out: Path, mode: str = TUNING, seeds: Path = cases.SEEDS) -> list[dict[str, Any]]:
    """Write every case's bytes and the index; the manifests the mode may read."""
    out = Path(out)
    if out.exists() and any(out.iterdir()):
        raise cases.CaseError(f"{out} is not empty; give a new or empty directory")
    built = cases.build_all(seeds)
    (out / MANIFESTS_DIR).mkdir(parents=True, exist_ok=True)
    index: list[dict[str, Any]] = []
    for case in built:
        document = case.manifest()
        (out / document["file"]).write_bytes(case.data)
        written = case.split == TUNING or mode == HELDOUT
        if written:
            scoring.write_json(out / MANIFESTS_DIR / f"{case.case_id}.json", document)
        index.append(
            {key: document[key] for key in ("case", "file", "format", "split", "sha256", "size")}
            | {"manifest": f"{MANIFESTS_DIR}/{case.case_id}.json" if written else None}
        )
    scoring.write_json(out / INDEX_FILE, index)
    return index


def _manifests_by_sha(splits: tuple[str, ...], seeds: Path) -> dict[str, dict[str, Any]]:
    return {m["sha256"]: m for m in (c.manifest() for c in cases.build_all(seeds, splits))}


def score_run(
    run: Path, mode: str = TUNING, case_id: str | None = None, seeds: Path = cases.SEEDS
) -> dict[str, Any]:
    """The score of one stored run against the case its sample is."""
    surfaces = scoring.read_surfaces(run)
    if case_id is not None:
        found = manifest(case_id, mode, seeds)
        if surfaces.sample_sha256 and surfaces.sample_sha256 != found["sha256"]:
            raise cases.CaseError(
                f"{run}: the run's sample is {surfaces.sample_sha256}, not {case_id}'s"
            )
        return scoring.score(found, surfaces)
    if not surfaces.sample_sha256:
        raise cases.CaseError(f"{run}: the run names no sample sha256; give --case")
    split_seed, entries = cases.read_seeds(seeds)
    for entry in entries:
        case = cases.build(entry, split_seed)
        document = case.manifest()
        if document["sha256"] == surfaces.sample_sha256:
            _refuse_heldout(entry, mode)
            return scoring.score(document, surfaces)
    raise cases.CaseError(f"{run}: sample {surfaces.sample_sha256} is no calibration case")


def gate(runs: list[Path], seeds: Path = cases.SEEDS) -> dict[str, Any]:
    """The held-out half's score over ``runs``; a tuning case is never built or read."""
    heldout = _manifests_by_sha((HELDOUT,), seeds)
    scored: list[dict[str, Any]] = []
    not_scored: dict[str, str] = {}
    for run in runs:
        surfaces = scoring.read_surfaces(run)
        document = heldout.get(surfaces.sample_sha256)
        if document is None:
            not_scored[str(run)] = "its sample is no held-out case"
            continue
        scored.append(scoring.redacted(scoring.score(document, surfaces)))
    cases_seen = {s["case"] for s in scored}
    return {
        "split": HELDOUT,
        "scores": scored,
        "not_scored": not_scored,
        "heldout_cases_without_a_run": sorted(
            m["case"] for m in heldout.values() if m["case"] not in cases_seen
        ),
        "totals": scoring.summed(scored),
    }


def _render_gate(result: dict[str, Any]) -> str:
    lines = [scoring.render(s, show_answers=False) for s in result["scores"]]
    for run, why in result["not_scored"].items():
        lines.append(f"{run}: not scored ({why})")
    for case in result["heldout_cases_without_a_run"]:
        lines.append(f"{case}: no run given")
    totals = result["totals"]
    lines.append("held-out total: " + "  ".join(f"{k} {totals[k]}" for k in scoring.TOTAL_KEYS))
    return "\n".join(lines)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scripts/calibration/run.py", description="The synthetic calibration set."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def with_mode(p: argparse.ArgumentParser) -> None:
        p.add_argument("--mode", choices=cases.SPLITS, default=TUNING)

    sub.add_parser("split", help="each case's format and half, no answer")
    b = sub.add_parser("build", help="write the cases, the index and the readable manifests")
    b.add_argument("--out", type=Path, default=DEFAULT_OUT, help="a new or empty directory")
    with_mode(b)
    m = sub.add_parser("manifest", help="print one case's manifest")
    m.add_argument("case")
    with_mode(m)
    s = sub.add_parser("score", help="score one stored run")
    s.add_argument("run", type=Path)
    s.add_argument("--case", default=None, help="the case, when the run names no sample")
    s.add_argument("--json", type=Path, default=None, help="also write the score here")
    with_mode(s)
    g = sub.add_parser("gate", help="score stored runs of the held-out half only")
    g.add_argument("runs", nargs="+", type=Path)
    g.add_argument("--json", type=Path, default=None, help="also write the result here")
    lc = sub.add_parser("leak-check", help="scan shipped files for answer-key terms")
    lc.add_argument(
        "--terms", type=Path, default=None, help="the private term list (an absent one is an error)"
    )
    lc.add_argument(
        "--settings-export",
        type=Path,
        default=None,
        help="also scan every string of a settings export (the prompts the database holds)",
    )
    lc.add_argument(
        "--private-allow",
        type=Path,
        default=None,
        help="the private allow-list (default: answer-key-allow.json; named and absent: an error)",
    )
    lc.add_argument(
        "--allow-entries",
        action="store_true",
        help="print the allow-list entry (digests, no term) for each hit, to review and add",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "split":
            for row in split_table():
                print(f"{row['case']}  {row['format']}  {row['split']}")
        elif args.command == "build":
            index = build(args.out, args.mode)
            readable = sum(1 for row in index if row["manifest"])
            print(f"calibration: {len(index)} cases written to {args.out}, {readable} manifests")
        elif args.command == "manifest":
            print(json.dumps(manifest(args.case, args.mode), indent=1))
        elif args.command == "score":
            result = score_run(args.run, args.mode, args.case)
            answers = result["split"] == TUNING
            print(scoring.render(result, show_answers=answers))
            if args.json:
                scoring.write_json(args.json, result if answers else scoring.redacted(result))
        elif args.command == "gate":
            result = gate(args.runs)
            print(_render_gate(result))
            if args.json:
                scoring.write_json(args.json, result)
        else:
            outcome = leak_check.check(
                private=args.terms,
                settings_export=args.settings_export,
                private_allow=args.private_allow,
            )
            print(leak_check.render(outcome))
            if args.allow_entries:
                entries = [
                    leak_check.allow_entry(h, "WHY THIS IS LEGITIMATE") for h in outcome.hits
                ]
                print(json.dumps(entries, indent=1))
            return 1 if outcome.hits else 0
    except (
        cases.CaseError,
        scoring.ScoreError,
        leak_check.LeakCheckError,
        StoredRunChanged,
        OSError,
        ValueError,
    ) as exc:
        print(f"calibration: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
